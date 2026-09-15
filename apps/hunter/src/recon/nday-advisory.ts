/**
 * N-day / patch-window advisory correlation via OSV.dev.
 *
 * Given a fingerprinted `(name, ecosystem, version)`, this asks OSV.dev
 * (Google's free, no-credential, cross-ecosystem vulnerability database --
 * aggregates GHSA, PyPA, RustSec and more) which advisories affect it, and
 * whether a fix already exists at a version the target has not adopted --
 * the "N-day window" between a patch being published and a target actually
 * upgrading. Request/response shapes below were verified against OSV's own
 * live API documentation (google.github.io/osv.dev), not assumed.
 *
 * Follows `js-version-diff.ts`'s persistence shape exactly: a dedicated,
 * append-only `nday-advisory-cache.jsonl` per workspace (not
 * `memory/hunt-memory.ts` -- that module's entry-kind taxonomy is about
 * hypothesis outcomes, not raw external-lookup caching), `ENOENT` -> `ok([])`,
 * `Result`-wrapped throughout. A cached entry is reused for 24h before being
 * treated as stale and re-queried, since advisories publish continuously.
 *
 * Never throws on a request failure -- a lookup that could not be completed
 * folds into a `Result` err (the batch call) or is silently skipped (a
 * single advisory's detail fetch, so one bad ID never blocks the rest), the
 * same "a failure must never look like a clean result" discipline as
 * `recon/cloud-buckets.ts`.
 *
 * A version match is a lead, never a finding: `isLikelyUnpatched` is only
 * ever `true` when both the introduced and fixed boundaries were confidently
 * comparable version strings, and `undefined` (never guessed) when OSV's fix
 * boundary was a bare commit hash or otherwise not comparable -- see
 * `reasoning/hypothesis.ts`'s `known-vulnerable-dependency` evidence
 * requirements for what still has to be confirmed against the live target
 * before this becomes reportable.
 *
 * HONEST STATUS: the request/response shapes below were checked against
 * two real, live api.osv.dev calls (a `querybatch` for jquery@1.4.2 and a
 * `vulns/{id}` detail fetch) during development -- not just the published
 * docs. That live check is what surfaced two real gaps the docs alone
 * didn't: a GHSA-sourced npm record's severity actually lives at
 * `database_specific.severity` (using GHSA's own "MODERATE", not this
 * codebase's "medium"), and its fix-commit reference is tagged plain "WEB",
 * not the schema's dedicated "FIX" value -- both are handled below. The
 * automated test suite itself still only exercises an injected `fetchImpl`
 * with hand-built fixtures shaped to match what that live check found; it
 * has not made its own real network call to api.osv.dev.
 */

import { randomUUID } from 'node:crypto';
import { appendFile, mkdir, readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import type { Observation } from '../types.js';
import { err, ok, type Result } from '../types.js';
import type { DependencyFingerprint } from './dependency-fingerprint.js';

const OSV_QUERYBATCH_URL = 'https://api.osv.dev/v1/querybatch';
const osvVulnUrl = (id: string): string => `https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`;
const CACHE_TTL_MS = 24 * 60 * 60 * 1000;

export interface AdvisoryMatch {
  readonly dependency: DependencyFingerprint;
  readonly advisoryId: string;
  readonly summary: string;
  readonly severity: string | undefined;
  readonly fixedVersion: string | undefined;
  readonly patchReferenceUrl: string | undefined;
  /** undefined when the fix boundary could not be confidently compared (e.g. a GIT-range commit hash) -- never guessed. */
  readonly isLikelyUnpatched: boolean | undefined;
}

// === OSV wire shapes (only the fields this module reads) ===

interface OsvEvent {
  readonly introduced?: string;
  readonly fixed?: string;
}

interface OsvRange {
  readonly events?: readonly OsvEvent[];
}

interface OsvAffectedPackage {
  readonly name?: string;
  readonly ecosystem?: string;
}

interface OsvAffected {
  readonly package?: OsvAffectedPackage;
  readonly ranges?: readonly OsvRange[];
  readonly ecosystem_specific?: { readonly severity?: string };
}

interface OsvReference {
  readonly type?: string;
  readonly url?: string;
}

interface OsvVulnDetail {
  readonly id: string;
  readonly summary?: string;
  readonly affected?: readonly OsvAffected[];
  readonly references?: readonly OsvReference[];
  /** Where a real GHSA-sourced npm record actually carries its severity label (verified live against api.osv.dev -- `affected[].ecosystem_specific.severity` below is an OSS-Fuzz-style fallback, not the common case). */
  readonly database_specific?: { readonly severity?: string };
}

interface OsvBatchResultVuln {
  readonly id: string;
}

interface OsvBatchResult {
  readonly vulns?: readonly OsvBatchResultVuln[];
}

interface OsvBatchResponse {
  readonly results?: readonly OsvBatchResult[];
}

export interface OsvRequestOptions {
  readonly fetchImpl?: typeof fetch;
  readonly timeoutMs?: number;
}

export interface OsvBatchQueryResult {
  readonly dependency: DependencyFingerprint;
  readonly vulnIds: readonly string[];
}

/** One `querybatch` call for every fingerprint at once -- OSV's own batch endpoint exists precisely so callers don't issue one request per package. Returns IDs only; `fetchVulnDetails` fills in the rest. */
export async function queryOsvBatch(
  fingerprints: readonly DependencyFingerprint[],
  options: OsvRequestOptions = {},
): Promise<Result<readonly OsvBatchQueryResult[], string>> {
  if (fingerprints.length === 0) return ok([]);
  const fetchImpl = options.fetchImpl ?? fetch;
  let response: Response;
  try {
    response = await fetchImpl(OSV_QUERYBATCH_URL, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        queries: fingerprints.map((f) => ({ package: { name: f.name, ecosystem: f.ecosystem }, version: f.version })),
      }),
      signal: AbortSignal.timeout(options.timeoutMs ?? 15_000),
    });
  } catch (error) {
    return err(`OSV querybatch request failed: ${(error as Error).message}`);
  }
  if (!response.ok) {
    return err(`OSV querybatch responded ${response.status}`);
  }
  let body: OsvBatchResponse;
  try {
    body = (await response.json()) as OsvBatchResponse;
  } catch (error) {
    return err(`OSV querybatch returned invalid JSON: ${(error as Error).message}`);
  }
  const results = body.results ?? [];
  return ok(
    fingerprints.map((dependency, index) => ({
      dependency,
      vulnIds: (results[index]?.vulns ?? []).map((v) => v.id),
    })),
  );
}

/** Full advisory detail for one OSV ID. A `Result` err here is always handled by the caller as "could not check this one," never as "clean." */
export async function fetchVulnDetails(
  id: string,
  options: OsvRequestOptions = {},
): Promise<Result<OsvVulnDetail, string>> {
  const fetchImpl = options.fetchImpl ?? fetch;
  let response: Response;
  try {
    response = await fetchImpl(osvVulnUrl(id), { signal: AbortSignal.timeout(options.timeoutMs ?? 15_000) });
  } catch (error) {
    return err(`OSV vuln detail request for "${id}" failed: ${(error as Error).message}`);
  }
  if (!response.ok) {
    return err(`OSV vuln detail for "${id}" responded ${response.status}`);
  }
  try {
    return ok((await response.json()) as OsvVulnDetail);
  } catch (error) {
    return err(`OSV vuln detail for "${id}" returned invalid JSON: ${(error as Error).message}`);
  }
}

const CLEAN_VERSION_PATTERN = /^\d+(\.\d+){0,3}$/;

/** Numeric dot-separated version comparison, `undefined` when either side isn't a clean numeric version (e.g. a git commit hash) -- never guessed. */
function compareVersions(a: string, b: string): number | undefined {
  if (!CLEAN_VERSION_PATTERN.test(a) || !CLEAN_VERSION_PATTERN.test(b)) return undefined;
  const partsA = a.split('.').map(Number);
  const partsB = b.split('.').map(Number);
  const length = Math.max(partsA.length, partsB.length);
  for (let i = 0; i < length; i++) {
    const diff = (partsA[i] ?? 0) - (partsB[i] ?? 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

interface FixEvaluation {
  readonly fixedVersion: string | undefined;
  readonly isLikelyUnpatched: boolean | undefined;
}

/** Walks every range OSV records for the matching package, looking for a window `[introduced, fixed)` that contains the detected version. Only ever asserts `true`/`false` when both boundaries were confidently comparable; otherwise reports `undefined` rather than guessing. */
function evaluateFix(detail: OsvVulnDetail, dependency: DependencyFingerprint): FixEvaluation {
  const matchingAffected = (detail.affected ?? []).filter(
    (a) =>
      a.package?.ecosystem === dependency.ecosystem && a.package?.name?.toLowerCase() === dependency.name.toLowerCase(),
  );

  let fixedVersion: string | undefined;
  let isLikelyUnpatched: boolean | undefined;

  for (const affected of matchingAffected) {
    let introduced = '0';
    for (const range of affected.ranges ?? []) {
      for (const event of range.events ?? []) {
        if (event.introduced !== undefined) introduced = event.introduced;
        if (event.fixed === undefined) continue;

        const fixed = event.fixed;
        fixedVersion = fixedVersion ?? fixed;
        const introducedCmp = compareVersions(dependency.version, introduced);
        const fixedCmp = compareVersions(dependency.version, fixed);
        if (introducedCmp === undefined || fixedCmp === undefined) {
          continue;
        }
        const inWindow = introducedCmp >= 0 && fixedCmp < 0;
        if (inWindow) {
          isLikelyUnpatched = true;
          fixedVersion = fixed;
        } else if (isLikelyUnpatched === undefined) {
          isLikelyUnpatched = false;
        }
      }
    }
  }

  return { fixedVersion, isLikelyUnpatched };
}

// GHSA's own severity vocabulary (LOW/MODERATE/HIGH/CRITICAL) doesn't quite
// match `reasoning/hypothesis.ts`'s SEVERITY_WEIGHT table (critical/high/
// medium/low/informational) -- "moderate" would otherwise silently miss
// that table and fall through to its generic default weight instead of
// "medium"'s real one. Verified against a live api.osv.dev record, not
// assumed.
const GHSA_SEVERITY_ALIASES: Readonly<Record<string, string>> = { moderate: 'medium' };

function severityLabelFrom(detail: OsvVulnDetail): string | undefined {
  const raw =
    detail.database_specific?.severity ??
    detail.affected?.find((a) => a.ecosystem_specific?.severity)?.ecosystem_specific?.severity;
  if (!raw) return undefined;
  const lowered = raw.toLowerCase();
  return GHSA_SEVERITY_ALIASES[lowered] ?? lowered;
}

// A commit-looking URL, not just any WEB-typed reference -- deliberately
// conservative so an unrelated changelog/blog link is never mistaken for
// the actual fix.
const COMMIT_URL_PATTERN = /\/commit\/[0-9a-f]{7,40}(?:$|[/?#])/i;

/**
 * The advisory's own patch/fix commit link, when it has one. `type: "FIX"`
 * is the schema's own dedicated value for this, but a live GHSA-sourced npm
 * record checked against the real API tags its fix commit as a plain "WEB"
 * reference instead -- so a commit-shaped WEB URL is accepted as a
 * (labeled, lower-confidence-by-construction) fallback rather than reported
 * as absent just because the ideal schema value wasn't used in practice.
 */
function patchReferenceUrlFrom(detail: OsvVulnDetail): string | undefined {
  const references = detail.references ?? [];
  const explicit = references.find((r) => r.type === 'FIX')?.url;
  if (explicit) return explicit;
  return references.find((r) => r.url && COMMIT_URL_PATTERN.test(r.url))?.url;
}

// === Per-workspace cache ===

export interface AdvisoryCacheEntry {
  readonly key: string;
  readonly matches: readonly AdvisoryMatch[];
  readonly checkedAt: string;
}

export function dependencyCacheKey(dependency: DependencyFingerprint): string {
  return `${dependency.ecosystem}:${dependency.name.toLowerCase()}:${dependency.version}`;
}

export function ndayAdvisoryCacheFilePath(workspaceDir: string): string {
  return join(workspaceDir, 'nday-advisory-cache.jsonl');
}

/** Appends a new cache record. Append-only, exactly like `js-version-diff.ts`'s snapshot log -- history is never overwritten. */
export async function appendCacheEntry(workspaceDir: string, entry: AdvisoryCacheEntry): Promise<void> {
  const filePath = ndayAdvisoryCacheFilePath(workspaceDir);
  await mkdir(dirname(filePath), { recursive: true });
  await appendFile(filePath, `${JSON.stringify(entry)}\n`, 'utf8');
}

/** Every cache entry ever recorded in this workspace. Empty (not an error) when nothing has ever been cached. */
export async function loadCacheEntries(workspaceDir: string): Promise<Result<readonly AdvisoryCacheEntry[], string>> {
  const filePath = ndayAdvisoryCacheFilePath(workspaceDir);
  let raw: string;
  try {
    raw = await readFile(filePath, 'utf8');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return ok([]);
    }
    return err(`could not read N-day advisory cache "${filePath}": ${(error as Error).message}`);
  }
  const lines = raw.split('\n').filter((line) => line.trim().length > 0);
  const entries: AdvisoryCacheEntry[] = [];
  for (const line of lines) {
    try {
      entries.push(JSON.parse(line) as AdvisoryCacheEntry);
    } catch (error) {
      return err(`N-day advisory cache "${filePath}" contains an invalid line: ${(error as Error).message}`);
    }
  }
  return ok(entries);
}

/** The most recently recorded cache entry for `key`, or undefined if it has never been checked before. */
export function latestCacheEntryFor(
  entries: readonly AdvisoryCacheEntry[],
  key: string,
): AdvisoryCacheEntry | undefined {
  let latest: AdvisoryCacheEntry | undefined;
  for (const entry of entries) {
    if (entry.key !== key) continue;
    if (!latest || entry.checkedAt > latest.checkedAt) latest = entry;
  }
  return latest;
}

export function isCacheEntryFresh(entry: AdvisoryCacheEntry, now: Date = new Date()): boolean {
  return now.getTime() - Date.parse(entry.checkedAt) < CACHE_TTL_MS;
}

/**
 * The one entry point a caller actually needs: checks the workspace cache
 * first, queries OSV only for fingerprints that were never checked or whose
 * cache entry has gone stale, records fresh results either way (so the
 * *next* hunt has them to reuse), and returns every match -- cached and
 * fresh -- together.
 */
export async function correlateAdvisories(
  fingerprints: readonly DependencyFingerprint[],
  workspaceDir: string,
  options: OsvRequestOptions = {},
): Promise<Result<readonly AdvisoryMatch[], string>> {
  if (fingerprints.length === 0) return ok([]);

  const existingCache = await loadCacheEntries(workspaceDir);
  if (!existingCache.ok) return existingCache;

  const now = new Date();
  const cached: AdvisoryMatch[] = [];
  const toQuery: DependencyFingerprint[] = [];
  for (const dependency of fingerprints) {
    const entry = latestCacheEntryFor(existingCache.value, dependencyCacheKey(dependency));
    if (entry && isCacheEntryFresh(entry, now)) {
      cached.push(...entry.matches);
    } else {
      toQuery.push(dependency);
    }
  }

  if (toQuery.length === 0) return ok(cached);

  const batchResult = await queryOsvBatch(toQuery, options);
  if (!batchResult.ok) return batchResult;

  const dependenciesById = new Map<string, DependencyFingerprint[]>();
  for (const { dependency, vulnIds } of batchResult.value) {
    for (const id of vulnIds) {
      const list = dependenciesById.get(id) ?? [];
      list.push(dependency);
      dependenciesById.set(id, list);
    }
  }

  const freshMatchesByDependency = new Map<DependencyFingerprint, AdvisoryMatch[]>(toQuery.map((d) => [d, []]));
  for (const [id, dependencies] of dependenciesById) {
    const detailResult = await fetchVulnDetails(id, options);
    if (!detailResult.ok) continue; // one failed advisory lookup never blocks the rest
    const detail = detailResult.value;
    for (const dependency of dependencies) {
      const { fixedVersion, isLikelyUnpatched } = evaluateFix(detail, dependency);
      freshMatchesByDependency.get(dependency)?.push({
        dependency,
        advisoryId: detail.id,
        summary: detail.summary ?? '',
        severity: severityLabelFrom(detail),
        fixedVersion,
        patchReferenceUrl: patchReferenceUrlFrom(detail),
        isLikelyUnpatched,
      });
    }
  }

  const checkedAt = now.toISOString();
  for (const dependency of toQuery) {
    await appendCacheEntry(workspaceDir, {
      key: dependencyCacheKey(dependency),
      matches: freshMatchesByDependency.get(dependency) ?? [],
      checkedAt,
    });
  }

  return ok([...cached, ...[...freshMatchesByDependency.values()].flat()]);
}

/**
 * Normalizes one match into the shared `Observation` shape so it flows
 * through `reasoning/hypothesis.ts` exactly like any other recon signal. A
 * version match is a lead, not a finding -- `confidenceHint` is only ever
 * `'high'` when the fix boundary was confidently confirmed to sit above the
 * detected version; everything else, including "advisory affects this
 * package but the fix boundary couldn't be compared," is `'low'`.
 */
export function advisoryMatchToObservation(match: AdvisoryMatch, engagementId: string): Observation {
  return {
    id: randomUUID(),
    engagementId,
    source: 'dependency-intelligence',
    assetRef: match.dependency.assetRef,
    vulnClass: 'known-vulnerable-dependency',
    title: `${match.dependency.name}@${match.dependency.version} may be affected by ${match.advisoryId}`,
    description:
      `${match.summary || 'No summary provided by the advisory.'} ` +
      `Fixed in ${match.fixedVersion ?? 'an unspecified version'}. ` +
      'This is a version-match lead only -- it has not been confirmed against the live target.',
    severityHint: match.severity ?? 'medium',
    confidenceHint: match.isLikelyUnpatched === true ? 'high' : 'low',
    verified: false,
    tags: ['nday', 'dependency-advisory', match.dependency.ecosystem],
    collectedAt: new Date().toISOString(),
    raw: {
      advisoryId: match.advisoryId,
      patchReferenceUrl: match.patchReferenceUrl,
      discoveredVia: match.dependency.discoveredVia,
    },
  };
}
