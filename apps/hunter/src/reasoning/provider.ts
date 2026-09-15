/**
 * ReasoningProvider abstraction.
 *
 * A provider only ever *proposes* — it never touches the world model, a
 * tool, or the network on the controller's behalf. `pipeline/adaptive-loop.ts`
 * runs every proposal through `reasoning/policy.ts:evaluateProposal` before
 * anything executes: the proposal must match a real, currently-queued
 * action built from the real world model (never an arbitrary or
 * hallucinated target/hypothesis id) and must fit the configured budget.
 *
 * Three real implementations exist: `HeuristicReasoningProvider` (a
 * deterministic wrapper around `reasoning/hypothesis.ts`/`reasoning/actions.ts` —
 * this is the always-available fallback, not a stub), `ClaudeReasoningProvider`
 * (a real Anthropic Messages API call, used only when `ANTHROPIC_API_KEY`
 * is configured), and `ClaudeCodeReasoningProvider` (shells out to the real
 * `claude` CLI's own OAuth session — for an operator paying via a Claude
 * Pro/Max subscription rather than the API directly — used only when
 * explicitly opted into via `HUNTER_USE_CLAUDE_CODE=1`). `reasoning/router.ts`
 * decides which runs, and falls back to the heuristic provider if the
 * model-backed one errors or returns something that fails schema
 * validation.
 *
 * `findRelevantReports` is a third, genuinely-wired call type (unlike
 * `generateHypotheses`, which no caller in the real pipeline actually
 * invokes today — hypotheses are always derived deterministically instead,
 * see `reasoning/hypothesis.ts`): `reasoning/disclosed-report-rag.ts` calls
 * it once per hunt to judge which, if any, of an operator-supplied set of
 * historical HackerOne disclosed reports are genuinely relevant to the
 * current engagement's observations. `HeuristicReasoningProvider` always
 * returns `[]` for it — an honest "no real semantic judgment available"
 * rather than a fake keyword-matched guess.
 */

import type { H1BrainDisclosedReportRecord } from '../discovery/h1-brain-provider.js';
import type {
  ActionProposal,
  HypothesisProposal,
  Observation,
  ReasoningSource,
  RelevantReportProposal,
  WorldModelSnapshot,
} from '../types.js';

export interface ReasoningProvider {
  readonly source: ReasoningSource;
  /** Proposes the single next-best action given the current world-model snapshot, or undefined if nothing is worth investigating. */
  selectNextBestAction(snapshot: WorldModelSnapshot): Promise<ActionProposal | undefined>;
  /** Proposes hypotheses from a batch of new observations. */
  generateHypotheses(
    observations: readonly Observation[],
    engagementId: string,
  ): Promise<readonly HypothesisProposal[]>;
  /** Judges which candidate disclosed reports (if any) are genuinely relevant to the given observations. */
  findRelevantReports(
    observations: readonly Observation[],
    disclosedReports: readonly H1BrainDisclosedReportRecord[],
  ): Promise<readonly RelevantReportProposal[]>;
}
