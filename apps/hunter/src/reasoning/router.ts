/**
 * Reasoning provider selection + fallback routing.
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
 * Whichever primary is chosen is always paired with the heuristic provider
 * as fallback. `selectNextBestActionWithFallback` is what the adaptive loop
 * actually calls each round: it tries the primary, and on *any* error
 * (network/process failure, non-2xx, schema validation) falls back to the
 * heuristic provider and reports why, rather than stalling the hunt on a
 * model outage.
 */

import { isToolInstalled } from '../recon/sources.js';
import type { ActionProposal, ReasoningSource, WorldModelSnapshot } from '../types.js';
import { ClaudeCodeReasoningProvider } from './claude-code-provider.js';
import { ClaudeReasoningProvider } from './claude-provider.js';
import { HeuristicReasoningProvider } from './heuristic-provider.js';
import type { ReasoningProvider } from './provider.js';

export interface ReasoningRouter {
  readonly primary: ReasoningProvider;
  readonly fallback: ReasoningProvider;
  readonly configuredSource: ReasoningSource;
}

export async function createReasoningProvider(
  env: Readonly<Record<string, string | undefined>> = process.env,
): Promise<ReasoningRouter> {
  const fallback = new HeuristicReasoningProvider();
  const apiKey = env.ANTHROPIC_API_KEY;
  if (apiKey) {
    const primary = new ClaudeReasoningProvider({
      apiKey,
      ...(env.HUNTER_REASONING_MODEL !== undefined ? { model: env.HUNTER_REASONING_MODEL } : {}),
    });
    return { primary, fallback, configuredSource: 'claude' };
  }
  if (env.HUNTER_USE_CLAUDE_CODE === '1' && (await isToolInstalled(env.HUNTER_CLAUDE_CODE_BINARY ?? 'claude'))) {
    const primary = new ClaudeCodeReasoningProvider({
      ...(env.HUNTER_REASONING_MODEL !== undefined ? { model: env.HUNTER_REASONING_MODEL } : {}),
      ...(env.HUNTER_CLAUDE_CODE_BINARY !== undefined ? { binary: env.HUNTER_CLAUDE_CODE_BINARY } : {}),
    });
    return { primary, fallback, configuredSource: 'claude' };
  }
  return { primary: fallback, fallback, configuredSource: 'heuristic' };
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
  if (router.primary.source === router.fallback.source) {
    return {
      proposal: await router.primary.selectNextBestAction(snapshot),
      source: router.primary.source,
      fallbackReason: undefined,
    };
  }
  try {
    const proposal = await router.primary.selectNextBestAction(snapshot);
    return { proposal, source: router.primary.source, fallbackReason: undefined };
  } catch (error) {
    const proposal = await router.fallback.selectNextBestAction(snapshot);
    return { proposal, source: router.fallback.source, fallbackReason: (error as Error).message };
  }
}
