/**
 * Per-round model-tier selection for `reasoning/router.ts`.
 *
 * Hunter's pipeline has exactly one real LLM call site in production —
 * `ReasoningProvider.selectNextBestAction`, invoked once per adaptive-loop
 * round (`pipeline/adaptive-loop.ts`). `ReasoningProvider.generateHypotheses`
 * is implemented by every provider but never actually called there —
 * hypotheses are always derived deterministically by
 * `reasoning/hypothesis.ts:hypothesesFromObservations` instead. So there is
 * no "recon call vs. exploitation call" split to route between; instead,
 * this tiers the single per-round decision by how consequential *that
 * round's* choice actually is, using data already materialized on the
 * snapshot -- no new computation.
 *
 * Also controls how much extended-thinking effort the chosen call spends
 * (`reasoning/router.ts`): a round is "critical" when a `shannon`-kind
 * candidate is present -- the single highest-stakes case in this pipeline,
 * since it actually triggers a real deep Shannon scan -- and gets the
 * deepest thinking effort; "premium" when a high/critical-impact
 * hypothesis is in play without a `shannon` candidate yet, and gets a
 * shallower-but-real thinking effort; "cheap" otherwise, with no thinking
 * at all -- which covers the bulk of ordinary rounds (passive/active-recon,
 * js-intelligence, behavioral-diff, manual-review, low/medium-impact
 * hypotheses).
 */

import type { WorldModelSnapshot } from '../types.js';

export type ModelTier = 'cheap' | 'premium' | 'critical';

const PREMIUM_IMPACT_LEVELS = new Set(['high', 'critical']);

export function chooseModelTier(snapshot: WorldModelSnapshot): ModelTier {
  const candidateHasShannonAction = snapshot.candidateActions.some((action) => action.kind === 'shannon');
  if (candidateHasShannonAction) {
    return 'critical';
  }

  const candidateHypothesisIds = new Set(snapshot.candidateActions.map((action) => action.hypothesisId));
  const candidateHasHighImpactHypothesis = snapshot.hypotheses.some(
    (hypothesis) => candidateHypothesisIds.has(hypothesis.id) && PREMIUM_IMPACT_LEVELS.has(hypothesis.potentialImpact),
  );
  if (candidateHasHighImpactHypothesis) {
    return 'premium';
  }

  return 'cheap';
}
