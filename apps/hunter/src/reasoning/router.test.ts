import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { ActionProposal, HuntAction, WorldModelSnapshot } from '../types.js';
import { ClaudeCodeReasoningProvider } from './claude-code-provider.js';
import { ClaudeReasoningProvider } from './claude-provider.js';
import { HeuristicReasoningProvider } from './heuristic-provider.js';
import type { ReasoningProvider } from './provider.js';
import { createReasoningProvider, resolveTierModel, selectNextBestActionWithFallback } from './router.js';

const EMPTY_SNAPSHOT: WorldModelSnapshot = {
  programId: 'p1',
  nodes: [],
  edges: [],
  hypotheses: [],
  recentObservations: [],
  completedActions: [],
  candidateActions: [],
  round: 1,
};

function shannonAction(): HuntAction {
  return {
    id: 'action-1',
    engagementId: 'e1',
    kind: 'shannon',
    targetRef: 'https://app.example.com',
    hypothesisId: 'hyp-1',
    rationale: 'test',
    expectedInformationGain: 0.5,
    cost: 0.6,
    status: 'queued',
    createdAt: new Date().toISOString(),
    completedAt: undefined,
    resultSummary: undefined,
  };
}

const PREMIUM_SNAPSHOT: WorldModelSnapshot = { ...EMPTY_SNAPSHOT, candidateActions: [shannonAction()] };

test('createReasoningProvider picks the heuristic provider outright when nothing is configured', async () => {
  const router = await createReasoningProvider({});
  assert.equal(router.configuredSource, 'heuristic');
  assert.ok(router.primary instanceof HeuristicReasoningProvider);
  assert.equal(router.primary, router.fallback);
  assert.equal(router.premium, router.fallback);
});

test('createReasoningProvider picks Claude (direct API) as primary and premium, with heuristic as fallback, when an API key is configured', async () => {
  const router = await createReasoningProvider({ ANTHROPIC_API_KEY: 'fake-key' });
  assert.equal(router.configuredSource, 'claude');
  assert.ok(router.primary instanceof ClaudeReasoningProvider);
  assert.ok(router.premium instanceof ClaudeReasoningProvider);
  assert.notEqual(router.primary, router.premium, 'the cheap and premium tiers must be distinct provider instances');
  assert.ok(router.fallback instanceof HeuristicReasoningProvider);
});

// === Claude Code (OAuth) path — explicit opt-in only, never automatic just
// because the binary exists, and never requiring ANTHROPIC_API_KEY ===

test('createReasoningProvider does NOT select Claude Code merely because HUNTER_USE_CLAUDE_CODE is unset, even if the binary is genuinely on PATH', async () => {
  // Deliberately does not check whether "claude" is installed here -- the
  // point of this test is that presence alone must never be enough.
  const router = await createReasoningProvider({});
  assert.equal(router.configuredSource, 'heuristic');
});

test('createReasoningProvider falls back to heuristic when HUNTER_USE_CLAUDE_CODE=1 but the named binary does not exist', async () => {
  const router = await createReasoningProvider({
    HUNTER_USE_CLAUDE_CODE: '1',
    HUNTER_CLAUDE_CODE_BINARY: 'definitely-not-a-real-binary-xyz-123',
  });
  assert.equal(router.configuredSource, 'heuristic');
});

test('createReasoningProvider selects ClaudeCodeReasoningProvider as both tiers when HUNTER_USE_CLAUDE_CODE=1 and the binary genuinely exists', async () => {
  // Uses "sh" (present on every POSIX box, exactly like other tests in this
  // package use it to stand in for "some real binary") purely to prove the
  // opt-in + presence-check wiring, not to actually invoke Claude Code here.
  const router = await createReasoningProvider({
    HUNTER_USE_CLAUDE_CODE: '1',
    HUNTER_CLAUDE_CODE_BINARY: 'sh',
  });
  assert.equal(router.configuredSource, 'claude');
  assert.ok(router.primary instanceof ClaudeCodeReasoningProvider);
  assert.ok(router.premium instanceof ClaudeCodeReasoningProvider);
  assert.notEqual(router.primary, router.premium, 'the cheap and premium tiers must be distinct provider instances');
  assert.ok(router.fallback instanceof HeuristicReasoningProvider);
});

test('ANTHROPIC_API_KEY still takes precedence over HUNTER_USE_CLAUDE_CODE when both are set', async () => {
  const router = await createReasoningProvider({
    ANTHROPIC_API_KEY: 'fake-key',
    HUNTER_USE_CLAUDE_CODE: '1',
    HUNTER_CLAUDE_CODE_BINARY: 'sh',
  });
  assert.ok(router.primary instanceof ClaudeReasoningProvider);
});

// === Cost-tiered model resolution (resolveTierModel back-compat precedence) ===

test('resolveTierModel prefers the tier-specific env var over everything else', () => {
  const model = resolveTierModel(
    { HUNTER_REASONING_MODEL_CHEAP: 'tier-specific', HUNTER_REASONING_MODEL: 'legacy' },
    'HUNTER_REASONING_MODEL_CHEAP',
    'fallback-default',
  );
  assert.equal(model, 'tier-specific');
});

test('resolveTierModel falls back to the legacy single-model var when the tier-specific one is unset -- both tiers keep an existing single-model config working unchanged', () => {
  const env = { HUNTER_REASONING_MODEL: 'legacy-model' };
  assert.equal(resolveTierModel(env, 'HUNTER_REASONING_MODEL_CHEAP', 'fallback-default'), 'legacy-model');
  assert.equal(resolveTierModel(env, 'HUNTER_REASONING_MODEL_PREMIUM', undefined), 'legacy-model');
});

test('resolveTierModel falls back to the tier default when nothing is configured', () => {
  assert.equal(resolveTierModel({}, 'HUNTER_REASONING_MODEL_CHEAP', 'fallback-default'), 'fallback-default');
  assert.equal(resolveTierModel({}, 'HUNTER_REASONING_MODEL_PREMIUM', undefined), undefined);
});

class FailingProvider implements ReasoningProvider {
  readonly source = 'claude' as const;
  selectNextBestAction(): Promise<ActionProposal | undefined> {
    return Promise.reject(new Error('simulated model outage'));
  }
  generateHypotheses(): Promise<readonly []> {
    return Promise.resolve([]);
  }
  findRelevantReports(): Promise<readonly []> {
    return Promise.resolve([]);
  }
}

test('selectNextBestActionWithFallback falls back to the heuristic provider when the tiered provider throws, and reports why', async () => {
  const result = await selectNextBestActionWithFallback(
    {
      primary: new FailingProvider(),
      premium: new FailingProvider(),
      fallback: new HeuristicReasoningProvider(),
      configuredSource: 'claude',
    },
    EMPTY_SNAPSHOT,
  );
  assert.equal(result.source, 'heuristic');
  assert.match(result.fallbackReason ?? '', /simulated model outage/);
});

test('selectNextBestActionWithFallback uses the primary directly when it succeeds', async () => {
  const heuristic = new HeuristicReasoningProvider();
  const result = await selectNextBestActionWithFallback(
    { primary: heuristic, premium: heuristic, fallback: heuristic, configuredSource: 'heuristic' },
    EMPTY_SNAPSHOT,
  );
  assert.equal(result.source, 'heuristic');
  assert.equal(result.fallbackReason, undefined);
});

// === Cost-tiered dispatch: selectNextBestActionWithFallback picks the tier chooseModelTier selects ===

class StubProvider implements ReasoningProvider {
  readonly source = 'claude' as const;
  constructor(private readonly label: string) {}
  selectNextBestAction(): Promise<ActionProposal | undefined> {
    return Promise.resolve({
      kind: 'manual-review',
      targetRef: this.label,
      hypothesisId: 'hyp-1',
      whyThisAction: this.label,
      hypothesisTested: this.label,
      uncertaintyReduced: this.label,
      confirmingObservation: this.label,
      contradictingObservation: this.label,
      nextStepIfConfirmed: this.label,
      nextStepIfContradicted: this.label,
    });
  }
  generateHypotheses(): Promise<readonly []> {
    return Promise.resolve([]);
  }
  findRelevantReports(): Promise<readonly []> {
    return Promise.resolve([]);
  }
}

test('selectNextBestActionWithFallback dispatches to the cheap tier for an ordinary round', async () => {
  const router = {
    primary: new StubProvider('cheap'),
    premium: new StubProvider('premium'),
    fallback: new HeuristicReasoningProvider(),
    configuredSource: 'claude' as const,
  };
  const result = await selectNextBestActionWithFallback(router, EMPTY_SNAPSHOT);
  assert.equal(result.proposal?.targetRef, 'cheap');
});

test('selectNextBestActionWithFallback dispatches to the premium tier when the round has a shannon-kind candidate', async () => {
  const router = {
    primary: new StubProvider('cheap'),
    premium: new StubProvider('premium'),
    fallback: new HeuristicReasoningProvider(),
    configuredSource: 'claude' as const,
  };
  const result = await selectNextBestActionWithFallback(router, PREMIUM_SNAPSHOT);
  assert.equal(result.proposal?.targetRef, 'premium');
});
