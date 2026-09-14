/**
 * Deterministic, offline `ProgramDiscoveryProvider` over exactly one
 * already-known engagement definition.
 *
 * `discovery/fixture-provider.ts` and `discovery/h1-brain-provider.ts` both
 * assume the caller wants Hunter's own ranking to choose *among* several
 * candidate programs. A real authorized engagement is frequently the
 * opposite case: the target program was already selected by some other
 * means entirely outside this package (a human decision, a prior manual
 * HackerOne review, an operator simply saying "hunt this one") — forcing
 * that through an 8-program synthetic dataset or a live snapshot file just
 * to get back the one program already known would be a pointless detour,
 * and previously the only way to reach `orchestration/lifecycle.ts`'s
 * scope/ROE/authorization/live-recon/live-Shannon machinery at all was
 * through a `ProgramDiscoveryProvider`.
 *
 * `SingleProgramDiscoveryProvider` closes that gap by making "one
 * already-known engagement" itself a (trivial, one-candidate) discovery
 * provider — reusing the exact same validation
 * (`discovery/fixture-provider.ts`'s field checks, duplicated narrowly here
 * rather than exported/shared, since the two providers' error messages are
 * intentionally distinct) and the exact same downstream path
 * (`discovery/normalize.ts:normalizeDiscoveredProgram`,
 * `orchestration/lifecycle.ts:runHuntLifecycle`) as every other provider.
 * No lifecycle/normalization/scope code changes for this to work — HackerOne
 * intake and Hunter's execution engine stay decoupled exactly as they
 * already were: a caller who has an authorized target/scope/ROE, but has
 * never touched `discovery/h1-brain-provider.ts` or any HackerOne-specific
 * code, can still drive the full engine.
 *
 * Ranking a single candidate against nothing is not a meaningful
 * "opportunity" decision — there is nothing to compare it to — but it is
 * never skipped: `discovery/opportunity.ts`'s existing single-program
 * assessment still runs and is still surfaced by `cli.ts lifecycle`,
 * exactly as it would for the winner of a real multi-program ranking, so
 * the printed rationale a human reviews before authorizing is the same
 * either way.
 */

import { readFile } from 'node:fs/promises';
import { err, ok, type Result } from '../types.js';
import type { DiscoveredProgram, ProgramDiscoveryProvider } from './types.js';

const VALID_ASSET_TYPES = new Set(['domain', 'wildcard-domain', 'url', 'repo', 'ip', 'cidr', 'unsupported']);
const VALID_INSTRUCTIONS = new Set(['in-scope', 'out-of-scope', 'unclear']);
const SIGNAL_KEYS = [
  'bountyAttractiveness',
  'competitionPressure',
  'disclosedReportDensity',
  'vulnClassHistory',
  'assetSurfaceBreadth',
  'researchCost',
  'programFreshness',
  'capabilityFit',
] as const;

function isSignal(value: unknown): boolean {
  if (typeof value !== 'object' || value === null) return false;
  const s = value as Record<string, unknown>;
  return (
    typeof s.value === 'number' &&
    typeof s.confidence === 'number' &&
    typeof s.freshnessAt === 'string' &&
    typeof s.detail === 'string'
  );
}

/**
 * Validates a single engagement-definition record. Deliberately less
 * demanding than a HackerOne-shaped record needs to be: `signals` may be
 * `{}` (an operator handing over an already-authorized target rarely has
 * — or needs — Hunter's opportunity-scoring signals at all; ranking a
 * single candidate against nothing does not depend on them), and
 * `offersBounty`/`rateLimitPerMinute` are the only economics fields this
 * provider cares about at all. Everything the safety model actually
 * depends on — `assets`, `rulesOfEngagement`, `disallowedTechniques` — is
 * validated exactly as strictly as `discovery/fixture-provider.ts` does.
 */
function isValidEngagementRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null) return false;
  const p = value as Record<string, unknown>;
  if (typeof p.programId !== 'string' || p.programId.length === 0) return false;
  if (typeof p.programName !== 'string' || p.programName.length === 0) return false;
  if (p.platform !== 'hackerone') return false;
  if (typeof p.offersBounty !== 'boolean') return false;
  if (!Array.isArray(p.assets) || p.assets.length === 0) return false;
  for (const asset of p.assets) {
    if (typeof asset !== 'object' || asset === null) return false;
    const a = asset as Record<string, unknown>;
    if (typeof a.identifier !== 'string' || a.identifier.length === 0) return false;
    if (typeof a.type !== 'string' || !VALID_ASSET_TYPES.has(a.type)) return false;
    if (typeof a.instruction !== 'string' || !VALID_INSTRUCTIONS.has(a.instruction)) return false;
  }
  if (!Array.isArray(p.rulesOfEngagement) || !p.rulesOfEngagement.every((v) => typeof v === 'string')) return false;
  if (!Array.isArray(p.disallowedTechniques) || !p.disallowedTechniques.every((v) => typeof v === 'string')) {
    return false;
  }
  if (p.rateLimitPerMinute !== undefined && typeof p.rateLimitPerMinute !== 'number') return false;
  const signals = p.signals ?? {};
  if (typeof signals !== 'object' || signals === null) return false;
  for (const key of Object.keys(signals as Record<string, unknown>)) {
    if (!(SIGNAL_KEYS as readonly string[]).includes(key)) return false;
    if (!isSignal((signals as Record<string, unknown>)[key])) return false;
  }
  return true;
}

export class SingleProgramDiscoveryProvider implements ProgramDiscoveryProvider {
  readonly name = 'single-program';

  constructor(private readonly filePath: string) {}

  async discoverPrograms(): Promise<Result<readonly DiscoveredProgram[], string>> {
    let raw: string;
    try {
      raw = await readFile(this.filePath, 'utf8');
    } catch (error) {
      return err(`could not read engagement definition "${this.filePath}": ${(error as Error).message}`);
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch (error) {
      return err(`engagement definition "${this.filePath}" is not valid JSON: ${(error as Error).message}`);
    }
    if (!isValidEngagementRecord(parsed)) {
      return err(
        `engagement definition "${this.filePath}" is not a valid single-program record (needs at least programId, programName, platform:"hackerone", offersBounty, one or more assets, rulesOfEngagement, disallowedTechniques)`,
      );
    }
    const record = parsed as Record<string, unknown>;
    return ok([
      {
        ...record,
        signals: record.signals ?? {},
        sourceProvider: this.name,
        discoveredAt: new Date().toISOString(),
      } as unknown as DiscoveredProgram,
    ]);
  }
}
