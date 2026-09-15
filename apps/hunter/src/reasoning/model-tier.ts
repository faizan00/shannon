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
 * A round is "premium" when either signal below is present among the
 * round's real candidates, and "cheap" otherwise -- which covers the bulk
 * of ordinary rounds (passive/active-recon, js-intelligence,
 * behavioral-diff, manual-review, low/medium-impact hypotheses).
 */

import type { WorldModelSnapshot } from '../types.js';

export type ModelTier = 'cheap' | 'premium';

const PREMIUM_IMPACT_LEVELS = new Set(['high', 'critical']);

export function chooseModelTier(snapshot: WorldModelSnapshot): ModelTier {
  const candidateHasShannonAction = snapshot.candidateActions.some((action) => action.kind === 'shannon');
  if (candidateHasShannonAction) {
    return 'premium';
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
