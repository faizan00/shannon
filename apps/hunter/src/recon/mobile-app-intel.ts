/**
 * Mobile app (APK/IPA) static intelligence.
 *
 * A mobile client frequently hardcodes API endpoints, internal hostnames,
 * and (mistakenly) real credentials that never appear anywhere on the web
 * surface at all — the app is the only place they exist. This is a real,
 * common source of findings no web-only recon path can ever reach.
 *
 * Operator-supplied only, exactly like `pipeline/adaptive-loop.ts`'s
 * `jsArtifacts` — this package never fetches an app from an app store
 * itself (a live store fetch raises its own ToS/authorization questions
 * entirely separate from the target program's own scope, and is out of
 * scope for what this function does). Given a real local `.apk`/`.ipa`
 * file (both are ordinary ZIP archives), this unzips it with the real
 * `unzip` binary and extracts printable-string runs from every file inside
 * — `classes.dex` (Android bytecode) and a compiled iOS binary are not
 * text, but both embed their string literals as contiguous printable-ASCII
 * byte runs, which is exactly what a first-pass `strings`-style scan
 * already recovers without decompiling or disassembling anything. This
 * reuses `js-intel.ts`'s own `SECRET_PATTERNS`/`fingerprint` for secret
 * detection — one detection ruleset, not two — and follows the exact same
 * "never retain a full matched secret value" discipline.
 */

import { execFile } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { mkdtemp, readdir, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import type { Observation, RawDiscovery } from '../types.js';
import { fingerprint, SECRET_PATTERNS } from './js-intel.js';

const execFileAsync = promisify(execFile);

const ENDPOINT_URL_PATTERN = /https?:\/\/[A-Za-z0-9.-]+(?::\d+)?(?:\/[A-Za-z0-9_\-./%]*)?/g;
const DEFAULT_MIN_STRING_LENGTH = 6;

/**
 * Dependency-free reimplementation of the standard `strings` utility:
 * extracts runs of printable ASCII characters at least `minLength` long.
 * Binary files (compiled bytecode, native libraries, plists) still embed
 * their string literals this way — this is the first, coarse pass real
 * reverse-engineering tooling (`strings`, then `jadx -d` + grep) also
 * starts with.
 */
export function extractPrintableStrings(buffer: Buffer, minLength: number = DEFAULT_MIN_STRING_LENGTH): string[] {
  const strings: string[] = [];
  let current = '';
  for (const byte of buffer) {
    if (byte >= 0x20 && byte <= 0x7e) {
      current += String.fromCharCode(byte);
    } else {
      if (current.length >= minLength) strings.push(current);
      current = '';
    }
  }
  if (current.length >= minLength) strings.push(current);
  return strings;
}

async function listFilesRecursively(dir: string): Promise<string[]> {
  const entries = await readdir(dir, { withFileTypes: true });
  const files: string[] = [];
  for (const entry of entries) {
    const fullPath = join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...(await listFilesRecursively(fullPath)));
    } else if (entry.isFile()) {
      files.push(fullPath);
    }
  }
  return files;
}

export interface MobileAppAnalysisResult {
  readonly discoveries: readonly RawDiscovery[];
  readonly observations: readonly Observation[];
  readonly filesAnalyzed: number;
  readonly stringsExtracted: number;
}

/**
 * Unzips `filePath` (a real, operator-supplied `.apk`/`.ipa`) and extracts
 * endpoint/URL and secret-shaped strings from every file inside. Requires
 * the real `unzip` binary on PATH, exactly like this package requires
 * `ffuf`/`nuclei`/etc. for other adapters — never invented, never guessed.
 */
export async function analyzeMobileApp(
  filePath: string,
  assetRef: string,
  engagementId: string,
): Promise<MobileAppAnalysisResult> {
  const extractDir = await mkdtemp(join(tmpdir(), 'hunter-mobile-'));
  try {
    await execFileAsync('unzip', ['-o', '-q', filePath, '-d', extractDir], { timeout: 60_000 });
    const filePaths = await listFilesRecursively(extractDir);
    const discoveries: RawDiscovery[] = [];
    const observations: Observation[] = [];
    const seenEndpoints = new Set<string>();
    let stringsExtracted = 0;
    const collectedAt = new Date().toISOString();

    for (const entryPath of filePaths) {
      let buffer: Buffer;
      try {
        buffer = await readFile(entryPath);
      } catch {
        continue;
      }
      const relativePath = entryPath.slice(extractDir.length + 1);
      const strings = extractPrintableStrings(buffer);
      stringsExtracted += strings.length;

      for (const str of strings) {
        for (const match of str.matchAll(ENDPOINT_URL_PATTERN)) {
          const url = match[0];
          if (seenEndpoints.has(url)) continue;
          seenEndpoints.add(url);
          discoveries.push({
            source: 'mobile-app-intel',
            kind: 'endpoint',
            label: url,
            attributes: { foundIn: relativePath },
            confidence: 0.55,
            discoveredAt: collectedAt,
          });
        }
        for (const { name, pattern } of SECRET_PATTERNS) {
          for (const match of str.matchAll(pattern)) {
            observations.push({
              id: `obs-mobile-secret-${randomUUID()}`,
              engagementId,
              source: 'js-intelligence',
              assetRef,
              vulnClass: 'mobile-secret-exposure',
              title: `Possible ${name} exposed in ${relativePath}`,
              description: `A string matching the "${name}" pattern was found inside the supplied app package (${fingerprint(match[0])}). Requires human validation — do not use the credential, and do not log or report it in full.`,
              severityHint: 'high',
              confidenceHint: 'low',
              verified: false,
              tags: ['requires-manual-review', 'mobile'],
              collectedAt,
            });
          }
        }
      }
    }
    return { discoveries, observations, filesAnalyzed: filePaths.length, stringsExtracted };
  } finally {
    await rm(extractDir, { recursive: true, force: true });
  }
}
