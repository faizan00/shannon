/**
 * Engagement/state persistence.
 *
 * An engagement is the durable record of one authorized hunt: which program,
 * which validated targets, which pipeline phase it has reached, and which
 * observations/findings/hypotheses belong to it. State lives as a single
 * JSON file per engagement under `<workspaceDir>/engagements/<id>/state.json`
 * so it can be inspected, diffed, and resumed without any database.
 */

import { readFile, rename } from 'node:fs/promises';
import { join } from 'node:path';
import {
  type Engagement,
  err,
  ok,
  PIPELINE_PHASES,
  type PipelinePhase,
  type Result,
  type ValidatedTarget,
} from '../types.js';
import { writeFileAtomic } from './atomic-write.js';

export function engagementFilePath(workspaceDir: string, engagementId: string): string {
  return join(workspaceDir, 'engagements', engagementId, 'state.json');
}

/**
 * `'not-found'` (no `state.json` at all -- a genuinely fresh engagement)
 * must never be conflated with `'corrupted'` (a file that exists but
 * failed to read/parse -- real prior progress that needs quarantine, not
 * silent overwrite). Every sibling loader (`loadCheckpoint`, `loadWorldModel`,
 * `loadProvenanceGraph`, `loadStateGraph`) already makes this distinction;
 * `loadEngagement` previously did not, and its caller
 * (`pipeline/adaptive-loop.ts`) silently created and saved a fresh empty
 * engagement over a corrupted one either way -- irreversibly destroying
 * whatever the corrupted file actually contained.
 */
export type EngagementLoadError =
  | { readonly kind: 'not-found' }
  | { readonly kind: 'corrupted'; readonly message: string };

export interface CreateEngagementInput {
  readonly id: string;
  readonly programId: string;
  readonly targets: readonly ValidatedTarget[];
}

export function newEngagement(input: CreateEngagementInput): Engagement {
  const now = new Date().toISOString();
  return {
    id: input.id,
    programId: input.programId,
    createdAt: now,
    updatedAt: now,
    phase: PIPELINE_PHASES[0],
    targets: input.targets,
    observationIds: [],
    findingIds: [],
    hypothesisIds: [],
  };
}

export async function saveEngagement(workspaceDir: string, engagement: Engagement): Promise<void> {
  const filePath = engagementFilePath(workspaceDir, engagement.id);
  await writeFileAtomic(filePath, `${JSON.stringify(engagement, null, 2)}\n`);
}

export async function loadEngagement(
  workspaceDir: string,
  engagementId: string,
): Promise<Result<Engagement, EngagementLoadError>> {
  const filePath = engagementFilePath(workspaceDir, engagementId);
  let raw: string;
  try {
    raw = await readFile(filePath, 'utf8');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return err({ kind: 'not-found' });
    }
    return err({
      kind: 'corrupted',
      message: `could not read engagement state "${filePath}": ${(error as Error).message}`,
    });
  }
  try {
    return ok(JSON.parse(raw) as Engagement);
  } catch (error) {
    return err({
      kind: 'corrupted',
      message: `engagement state "${filePath}" is not valid JSON: ${(error as Error).message}`,
    });
  }
}

/** Moves a corrupted `state.json` aside — never deletes it, so it stays available for forensics — and returns the quarantine path. Mirrors `checkpoint.ts:quarantineCorruptedCheckpoint` exactly. */
export async function quarantineCorruptedEngagementState(
  workspaceDir: string,
  engagementId: string,
): Promise<Result<string | undefined, string>> {
  const filePath = engagementFilePath(workspaceDir, engagementId);
  const quarantinePath = `${filePath}.corrupted-${new Date().toISOString().replace(/[:.]/g, '-')}`;
  try {
    await rename(filePath, quarantinePath);
    return ok(quarantinePath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return ok(undefined);
    }
    return err(`could not quarantine corrupted engagement state "${filePath}": ${(error as Error).message}`);
  }
}

function phaseIndex(phase: PipelinePhase): number {
  return PIPELINE_PHASES.indexOf(phase);
}

/**
 * Advance an engagement to a new phase. Phases are monotonic — an engagement
 * can only move forward (or stay put to re-save the same phase), never
 * backward, matching the fixed workflow order in `PIPELINE_PHASES`.
 */
export function advancePhase(engagement: Engagement, nextPhase: PipelinePhase): Result<Engagement, string> {
  const currentIndex = phaseIndex(engagement.phase);
  const nextIndex = phaseIndex(nextPhase);
  if (nextIndex < currentIndex) {
    return err(`cannot move engagement "${engagement.id}" backward from phase "${engagement.phase}" to "${nextPhase}"`);
  }
  return ok({
    ...engagement,
    phase: nextPhase,
    updatedAt: new Date().toISOString(),
  });
}

function withUniqueIds(existing: readonly string[], added: readonly string[]): readonly string[] {
  return Array.from(new Set([...existing, ...added]));
}

export function withObservations(engagement: Engagement, observationIds: readonly string[]): Engagement {
  return {
    ...engagement,
    observationIds: withUniqueIds(engagement.observationIds, observationIds),
    updatedAt: new Date().toISOString(),
  };
}

export function withFindings(engagement: Engagement, findingIds: readonly string[]): Engagement {
  return {
    ...engagement,
    findingIds: withUniqueIds(engagement.findingIds, findingIds),
    updatedAt: new Date().toISOString(),
  };
}

export function withHypotheses(engagement: Engagement, hypothesisIds: readonly string[]): Engagement {
  return {
    ...engagement,
    hypothesisIds: withUniqueIds(engagement.hypothesisIds, hypothesisIds),
    updatedAt: new Date().toISOString(),
  };
}
