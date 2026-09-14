/**
 * JS bundle version-diffing across separate hunts against the same target.
 *
 * A one-shot hunt only ever sees one snapshot of a bundle. A real app ships
 * new JS regularly; a newly-added endpoint, feature flag, or role check
 * often exists in the bundle for days or weeks before it is wired up
 * server-side, which is exactly the window where source-aware discovery
 * (this module) beats waiting for a fresh full crawl to happen to notice.
 * `js-snapshots.jsonl` persists one entry per `(sourceRef)` per workspace
 * (across engagements, mirroring `memory/hunt-memory.ts`'s own
 * once-per-workspace, not per-engagement, persistence) so a later hunt
 * against the same target can diff against what an earlier hunt actually
 * saw, not just within a single run.
 *
 * Deliberately simple: a content hash decides whether anything changed at
 * all (cheap, exact), and a string-literal set diff — reusing nothing more
 * than `String.prototype.match`, no AST — is what actually surfaces *what*
 * changed. This is diff-for-triage, not a full structural diff.
 */

import { createHash } from 'node:crypto';
import { appendFile, mkdir, readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { err, ok, type Result } from '../types.js';

const STRING_LITERAL_PATTERN = /"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`(?:[^`\\]|\\.)*`/g;

/** Every distinct quoted string literal in `content`, deduplicated -- deliberately not filtered to "interesting-looking" ones here; that judgment belongs to `js-intel.ts`'s own patterns, run separately over whichever strings this reports as new. */
export function extractStringLiterals(content: string): readonly string[] {
  const matches = content.match(STRING_LITERAL_PATTERN) ?? [];
  return [...new Set(matches.map((m) => m.slice(1, -1)))];
}

export interface JsBundleSnapshot {
  readonly sourceRef: string;
  readonly assetRef: string;
  readonly contentHash: string;
  readonly stringLiterals: readonly string[];
  readonly capturedAt: string;
}

export function snapshotBundle(sourceRef: string, assetRef: string, content: string): JsBundleSnapshot {
  return {
    sourceRef,
    assetRef,
    contentHash: createHash('sha256').update(content).digest('hex'),
    stringLiterals: extractStringLiterals(content),
    capturedAt: new Date().toISOString(),
  };
}

export interface JsBundleDiff {
  readonly sourceRef: string;
  readonly changed: boolean;
  /** Present now, absent from the prior snapshot -- undefined (not empty) when there was no prior snapshot at all, distinct from "diffed against a prior snapshot and found nothing new." */
  readonly newStringLiterals: readonly string[] | undefined;
  readonly removedStringLiterals: readonly string[] | undefined;
}

/** `previous: undefined` means "never snapshotted before" -- reported as changed (everything in it is new), not silently skipped. */
export function diffBundleSnapshots(previous: JsBundleSnapshot | undefined, current: JsBundleSnapshot): JsBundleDiff {
  if (!previous) {
    return {
      sourceRef: current.sourceRef,
      changed: true,
      newStringLiterals: current.stringLiterals,
      removedStringLiterals: undefined,
    };
  }
  if (previous.contentHash === current.contentHash) {
    return {
      sourceRef: current.sourceRef,
      changed: false,
      newStringLiterals: undefined,
      removedStringLiterals: undefined,
    };
  }
  const previousSet = new Set(previous.stringLiterals);
  const currentSet = new Set(current.stringLiterals);
  return {
    sourceRef: current.sourceRef,
    changed: true,
    newStringLiterals: current.stringLiterals.filter((s) => !previousSet.has(s)),
    removedStringLiterals: previous.stringLiterals.filter((s) => !currentSet.has(s)),
  };
}

export function jsSnapshotsFilePath(workspaceDir: string): string {
  return join(workspaceDir, 'js-snapshots.jsonl');
}

/** Appends a new snapshot record. Append-only, exactly like `hunt-memory.jsonl` -- history is never overwritten, only added to. */
export async function appendSnapshot(workspaceDir: string, snapshot: JsBundleSnapshot): Promise<void> {
  const filePath = jsSnapshotsFilePath(workspaceDir);
  await mkdir(dirname(filePath), { recursive: true });
  await appendFile(filePath, `${JSON.stringify(snapshot)}\n`, 'utf8');
}

/** Every snapshot ever recorded in this workspace, oldest first. Empty (not an error) when nothing has ever been snapshotted. */
export async function loadSnapshots(workspaceDir: string): Promise<Result<readonly JsBundleSnapshot[], string>> {
  const filePath = jsSnapshotsFilePath(workspaceDir);
  let raw: string;
  try {
    raw = await readFile(filePath, 'utf8');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return ok([]);
    }
    return err(`could not read JS snapshot log "${filePath}": ${(error as Error).message}`);
  }
  const lines = raw.split('\n').filter((line) => line.trim().length > 0);
  const snapshots: JsBundleSnapshot[] = [];
  for (const line of lines) {
    try {
      snapshots.push(JSON.parse(line) as JsBundleSnapshot);
    } catch (error) {
      return err(`JS snapshot log "${filePath}" contains an invalid line: ${(error as Error).message}`);
    }
  }
  return ok(snapshots);
}

/** The most recent snapshot recorded for `sourceRef`, or undefined if it has never been snapshotted before. */
export function latestSnapshotFor(
  snapshots: readonly JsBundleSnapshot[],
  sourceRef: string,
): JsBundleSnapshot | undefined {
  let latest: JsBundleSnapshot | undefined;
  for (const snapshot of snapshots) {
    if (snapshot.sourceRef !== sourceRef) continue;
    if (!latest || snapshot.capturedAt > latest.capturedAt) latest = snapshot;
  }
  return latest;
}

/**
 * Snapshots `content`, diffs it against whatever was last recorded for
 * `sourceRef` in this workspace, appends the new snapshot to the durable
 * log either way (so the *next* hunt has this one to diff against), and
 * returns the diff. The one entry point a caller actually needs — wraps
 * load -> diff -> append so no caller has to sequence those three
 * themselves.
 */
export async function diffAndRecordBundle(
  workspaceDir: string,
  sourceRef: string,
  assetRef: string,
  content: string,
): Promise<Result<JsBundleDiff, string>> {
  const existing = await loadSnapshots(workspaceDir);
  if (!existing.ok) return existing;
  const previous = latestSnapshotFor(existing.value, sourceRef);
  const current = snapshotBundle(sourceRef, assetRef, content);
  const diff = diffBundleSnapshots(previous, current);
  await appendSnapshot(workspaceDir, current);
  return ok(diff);
}
