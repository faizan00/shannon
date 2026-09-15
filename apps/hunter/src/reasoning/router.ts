/**
 * Reasoning provider selection + cost-tiered + fallback routing.
 *
 * `createReasoningProvider` picks, in order:
 *
 * 1. `ClaudeReasoningProvider` (direct Anthropic API) when
 *    `ANTHROPIC_API_KEY` is configured — unchanged from before.
 * 2. `ClaudeCodeReasoningProvider` (shells out to the `claude` CLI's own
 *    OAuth session — see `claude-code-provider.ts`) when
 *    `HUNTER_USE_CLAUDE_CODE=1` is explicitly set *and* the `claude`
 *    binary is genuinely present. Explicitly opt-in, exactly like
 *    `liveRecon`/`liveShannon`: a machine with Claude Code installed for
 *    unrelated reasons must never silently start spending a Claude
 *    subscription's usage just because the binary exists on PATH. Named
 *    after Shannon's own `SHANNON_USE_PI_AUTH` (root `CLAUDE.md`), the same
 *    "reuse an already-authenticated CLI, opt-in" pattern.
 * 3. The heuristic provider outright, if neither applies.
 *
 * Whichever source is chosen is built as *three* provider instances —
 * `primary` (the cheap tier, no thinking), `premium` (adaptive thinking at
 * effort `'high'`), and `critical` (the *same* premium-tier model, adaptive
 * thinking at effort `'max'`) — always paired with the heuristic provider
 * as `fallback`. Hunter's pipeline has exactly one real LLM call site in
 * production (`selectNextBestAction`, once per adaptive-loop round —
 * `ReasoningProvider.generateHypotheses` exists on every provider but is
 * never actually called there, since hypotheses are always derived
 * deterministically by `reasoning/hypothesis.ts`), so there is no
 * "recon call vs. exploitation call" split to route between; instead
 * `reasoning/model-tier.ts:chooseModelTier` tiers that single per-round
 * decision, three ways, by how consequential *that round's* candidates
 * actually are — which also scales how much extended-thinking effort the
 * call spends, not just which model answers it.
 *
 * `HUNTER_REASONING_MODEL_CHEAP`/`HUNTER_REASONING_MODEL_PREMIUM` configure
 * the cheap and premium/critical model strings independently (`critical`
 * always reuses the premium model — only the thinking effort escalates,
 * never the model). For back-compat, the older, single
 * `HUNTER_REASONING_MODEL` (when the tier-specific variable is unset) is
 * used for both, so an existing single-model config's behavior does not
 * change. `DEFAULT_CHEAP_MODEL_ANTHROPIC`/`DEFAULT_CHEAP_MODEL_CLAUDE_CODE`
 * are the real, verified cheap-tier defaults for each path (the CLI's
 * `haiku` alias was confirmed live, against the real installed `claude`
 * binary, to resolve to `claude-haiku-4-5-20251001` — not assumed from
 * `--help` text alone); the premium tier has no hardcoded default for
 * either path, since leaving `model` unset already gets each provider's own
 * existing default (`claude-sonnet-4-6` direct-API / the CLI's own default
 * model). `PREMIUM_EFFORT`/`CRITICAL_EFFORT` are fixed, hardcoded constants
 * for v1 — not operator-configurable, matching `reasoning/actions.ts`'s own
 * `COST_BY_KIND` hardcoded-constants convention rather than adding new env
 * vars for a first cut.
 *
 * The direct-API `effort` request shape (`ClaudeReasoningProvider`) was
 * checked against the current, authoritative Claude API reference but is
 * **not live-verified** — no `ANTHROPIC_API_KEY` was available in this
 * environment during development. The CLI `--effort` shape
 * (`ClaudeCodeReasoningProvider`) *was* verified live against the real
 * installed `claude` CLI, including forced JSON-schema output.
 *
 * `selectNextBestActionWithFallback` is what the adaptive loop actually
 * calls each round: it tries the tier `chooseModelTier` selects, and on
 * *any* error (network/process failure, non-2xx, schema validation) falls
 * back to the heuristic provider and reports why, rather than stalling the
 * hunt on a model outage.
 */

import { isToolInstalled } from '../recon/sources.js';
import type { ActionProposal, ReasoningSource, WorldModelSnapshot } from '../types.js';
import { ClaudeCodeReasoningProvider } from './claude-code-provider.js';
import { ClaudeReasoningProvider, type ThinkingEffort } from './claude-provider.js';
import { HeuristicReasoningProvider } from './heuristic-provider.js';
import { chooseModelTier } from './model-tier.js';
import type { ReasoningProvider } from './provider.js';

const DEFAULT_CHEAP_MODEL_ANTHROPIC = 'claude-haiku-4-5-20251001';
const DEFAULT_CHEAP_MODEL_CLAUDE_CODE = 'haiku';
const PREMIUM_EFFORT: ThinkingEffort = 'high';
const CRITICAL_EFFORT: ThinkingEffort = 'max';

export interface ReasoningRouter {
  /** The cheap tier's provider instance — kept as `primary` so it doubles as "the model-backed provider" for every pre-existing single-tier caller/test. */
  readonly primary: ReasoningProvider;
  readonly premium: ReasoningProvider;
  /** The premium-tier model at the deepest thinking effort — see this file's module docstring. */
  readonly critical: ReasoningProvider;
  readonly fallback: ReasoningProvider;
  readonly configuredSource: ReasoningSource;
}

/** Exported for direct unit testing of the back-compat precedence — tier-specific var, then the legacy single-model var, then the tier's own hardcoded default. */
export function resolveTierModel(
  env: Readonly<Record<string, string | undefined>>,
  tierVar: 'HUNTER_REASONING_MODEL_CHEAP' | 'HUNTER_REASONING_MODEL_PREMIUM',
  fallbackDefault: string | undefined,
): string | undefined {
  return env[tierVar] ?? env.HUNTER_REASONING_MODEL ?? fallbackDefault;
}

export async function createReasoningProvider(
  env: Readonly<Record<string, string | undefined>> = process.env,
): Promise<ReasoningRouter> {
  const fallback = new HeuristicReasoningProvider();
  const apiKey = env.ANTHROPIC_API_KEY;
  if (apiKey) {
    const cheapModel = resolveTierModel(env, 'HUNTER_REASONING_MODEL_CHEAP', DEFAULT_CHEAP_MODEL_ANTHROPIC);
    const premiumModel = resolveTierModel(env, 'HUNTER_REASONING_MODEL_PREMIUM', undefined);
    const primary = new ClaudeReasoningProvider({
      apiKey,
      ...(cheapModel !== undefined ? { model: cheapModel } : {}),
    });
    const premium = new ClaudeReasoningProvider({
      apiKey,
      ...(premiumModel !== undefined ? { model: premiumModel } : {}),
      effort: PREMIUM_EFFORT,
    });
    const critical = new ClaudeReasoningProvider({
      apiKey,
      ...(premiumModel !== undefined ? { model: premiumModel } : {}),
      effort: CRITICAL_EFFORT,
    });
    return { primary, premium, critical, fallback, configuredSource: 'claude' };
  }
  if (env.HUNTER_USE_CLAUDE_CODE === '1' && (await isToolInstalled(env.HUNTER_CLAUDE_CODE_BINARY ?? 'claude'))) {
    const cheapModel = resolveTierModel(env, 'HUNTER_REASONING_MODEL_CHEAP', DEFAULT_CHEAP_MODEL_CLAUDE_CODE);
    const premiumModel = resolveTierModel(env, 'HUNTER_REASONING_MODEL_PREMIUM', undefined);
    const binaryOptions = env.HUNTER_CLAUDE_CODE_BINARY !== undefined ? { binary: env.HUNTER_CLAUDE_CODE_BINARY } : {};
    const primary = new ClaudeCodeReasoningProvider({
      ...(cheapModel !== undefined ? { model: cheapModel } : {}),
      ...binaryOptions,
    });
    const premium = new ClaudeCodeReasoningProvider({
      ...(premiumModel !== undefined ? { model: premiumModel } : {}),
      ...binaryOptions,
      effort: PREMIUM_EFFORT,
    });
    const critical = new ClaudeCodeReasoningProvider({
      ...(premiumModel !== undefined ? { model: premiumModel } : {}),
      ...binaryOptions,
      effort: CRITICAL_EFFORT,
    });
    return { primary, premium, critical, fallback, configuredSource: 'claude' };
  }
  return { primary: fallback, premium: fallback, critical: fallback, fallback, configuredSource: 'heuristic' };
}

export interface ActionSelectionResult {
  readonly proposal: ActionProposal | undefined;
  readonly source: ReasoningSource;
  readonly fallbackReason: string | undefined;
}

export async function selectNextBestActionWithFallback(
  router: ReasoningRouter,
  snapshot: WorldModelSnapshot,
): Promise<ActionSelectionResult> {
  const tier = chooseModelTier(snapshot);
  const tieredProvider = tier === 'critical' ? router.critical : tier === 'premium' ? router.premium : router.primary;
  if (tieredProvider.source === router.fallback.source) {
    return {
      proposal: await tieredProvider.selectNextBestAction(snapshot),
      source: tieredProvider.source,
      fallbackReason: undefined,
    };
  }
  try {
    const proposal = await tieredProvider.selectNextBestAction(snapshot);
    return { proposal, source: tieredProvider.source, fallbackReason: undefined };
  } catch (error) {
    const proposal = await router.fallback.selectNextBestAction(snapshot);
    return { proposal, source: router.fallback.source, fallbackReason: (error as Error).message };
  }
}
