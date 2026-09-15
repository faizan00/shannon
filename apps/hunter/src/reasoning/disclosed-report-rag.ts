/**
 * Semantic retrieval over historical HackerOne disclosed reports.
 *
 * "A similar bug was found and paid out on a comparable target/tech
 * before" is a real signal bug-bounty hunters already use manually; this
 * lets a matched historical disclosed-report writeup bias hypothesis
 * generation for the current engagement, the same way
 * `recon/nday-advisory.ts`'s matched advisory does for a fingerprinted
 * dependency version.
 *
 * The corpus itself only ever enters this package through the
 * operator-populated `H1BrainSnapshot` (`discovery/h1-brain-provider.ts`) —
 * this module never calls `mcp__h1-brain__*` itself, exactly like every
 * other HackerOne-sourced data path in this package. What's new here is
 * *judging relevance* once that corpus is already loaded, which needs
 * genuine semantic understanding a keyword match can't provide — so this
 * reuses the existing, now cost-tiered `ReasoningRouter` infrastructure
 * (`reasoning/router.ts`) via `ReasoningProvider.findRelevantReports`
 * rather than inventing a new embeddings/vector-search dependency.
 *
 * Called once per hunt (not per round) as a one-time enrichment step, so it
 * always goes through `router.primary` (the cheap tier) directly — this is
 * not a per-round decision `model-tier.ts:chooseModelTier` was built for.
 * Skips entirely, with no call made, when the operator hasn't supplied any
 * disclosed-report content: zero cost when the feature is unused.
 *
 * A version match is a lead, never a finding, and the same is true here:
 * `relevantReportMatchToObservation` always produces `confidenceHint:
 * 'low'` — a matched historical report is a *weaker* signal than a live
 * fingerprint match, since nothing has been observed on the current target
 * yet. It becomes ordinary supporting evidence for whatever real vulnClass
 * the report's own weakness type maps to, not a novel vulnClass of its
 * own -- so it competes and merges with hypotheses discovered through any
 * other source for that same vulnClass, through the existing, unmodified
 * `hypothesesFromObservations` pipeline.
 */

import { randomUUID } from 'node:crypto';
import type { H1BrainDisclosedReportRecord } from '../discovery/h1-brain-provider.js';
import type { Observation } from '../types.js';
import { err, ok, type Result } from '../types.js';
import type { ReasoningRouter } from './router.js';

export interface RelevantReportMatch {
  readonly report: H1BrainDisclosedReportRecord;
  /** One of the current engagement's own observation asset refs — never the historical report's own (foreign, out-of-scope) asset. See `ReasoningProvider.findRelevantReports`'s hallucination guard. */
  readonly relatedAssetRef: string;
  readonly relevanceRationale: string;
  readonly suggestedNextInvestigation: string;
}

/**
 * h1-brain's own free-text weakness vocabulary doesn't match this
 * package's short `vulnClass` keys -- a small, honest lookup table, same
 * spirit as `recon/dependency-fingerprint.ts`'s signature table. An
 * unmapped weakness type is skipped entirely in
 * `relevantReportMatchToObservation`, never guessed at.
 */
const VULN_CLASS_BY_WEAKNESS_KEYWORD: readonly (readonly [string, string])[] = [
  ['cross-site scripting', 'xss'],
  ['xss', 'xss'],
  ['server-side request forgery', 'ssrf'],
  ['ssrf', 'ssrf'],
  ['insecure direct object reference', 'idor'],
  ['idor', 'idor'],
  ['broken access control', 'authz'],
  ['improper access control', 'authz'],
  ['privilege escalation', 'authz'],
];

function vulnClassFromWeakness(weakness: string): string | undefined {
  const normalized = weakness.toLowerCase();
  return VULN_CLASS_BY_WEAKNESS_KEYWORD.find(([keyword]) => normalized.includes(keyword))?.[1];
}

/**
 * The one entry point a caller needs: judges relevance via the router's
 * cheap tier, then filters to only the reports whose weakness type maps to
 * a real vulnClass this package understands. Never throws -- a failed
 * provider call folds into a `Result` err so the caller treats it as
 * "couldn't check," never silently as "no matches" (same discipline as
 * `recon/nday-advisory.ts`).
 */
export async function findRelevantDisclosedReports(
  observations: readonly Observation[],
  disclosedReports: readonly H1BrainDisclosedReportRecord[],
  router: ReasoningRouter,
): Promise<Result<readonly RelevantReportMatch[], string>> {
  if (disclosedReports.length === 0) {
    return ok([]);
  }
  let proposals: Awaited<ReturnType<typeof router.primary.findRelevantReports>>;
  try {
    proposals = await router.primary.findRelevantReports(observations, disclosedReports);
  } catch (error) {
    return err(`relevant-report ranking failed: ${(error as Error).message}`);
  }
  const reportsById = new Map(disclosedReports.map((r) => [r.id, r]));
  const matches: RelevantReportMatch[] = [];
  for (const proposal of proposals) {
    const report = reportsById.get(proposal.reportId);
    if (!report) continue; // already filtered by the provider, but never trust twice
    matches.push({
      report,
      relatedAssetRef: proposal.relatedAssetRef,
      relevanceRationale: proposal.relevanceRationale,
      suggestedNextInvestigation: proposal.suggestedNextInvestigation,
    });
  }
  return ok(matches);
}

export function relevantReportMatchToObservation(
  match: RelevantReportMatch,
  engagementId: string,
): Observation | undefined {
  const vulnClass = vulnClassFromWeakness(match.report.weakness);
  if (!vulnClass) {
    return undefined;
  }
  return {
    id: randomUUID(),
    engagementId,
    source: 'disclosed-report-intelligence',
    assetRef: match.relatedAssetRef,
    vulnClass,
    title: `Historical disclosed report #${match.report.id} ("${match.report.title}") may be relevant here`,
    description: `${match.relevanceRationale} Suggested next investigation: ${match.suggestedNextInvestigation}`,
    severityHint: 'medium',
    confidenceHint: 'low',
    verified: false,
    tags: ['disclosed-report', 'rag', match.report.program],
    collectedAt: new Date().toISOString(),
    raw: {
      reportId: match.report.id,
      program: match.report.program,
      weakness: match.report.weakness,
      bounty: match.report.bounty,
    },
  };
}
