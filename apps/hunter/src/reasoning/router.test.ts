import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { ActionProposal, WorldModelSnapshot } from '../types.js';
import { ClaudeCodeReasoningProvider } from './claude-code-provider.js';
import { ClaudeReasoningProvider } from './claude-provider.js';
import { HeuristicReasoningProvider } from './heuristic-provider.js';
import type { ReasoningProvider } from './provider.js';
import { createReasoningProvider, selectNextBestActionWithFallback } from './router.js';

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

test('createReasoningProvider picks the heuristic provider outright when nothing is configured', async () => {
  const router = await createReasoningProvider({});
  assert.equal(router.configuredSource, 'heuristic');
  assert.ok(router.primary instanceof HeuristicReasoningProvider);
  assert.equal(router.primary, router.fallback);
});

test('createReasoningProvider picks Claude (direct API) as primary, with heuristic as fallback, when an API key is configured', async () => {
  const router = await createReasoningProvider({ ANTHROPIC_API_KEY: 'fake-key' });
  assert.equal(router.configuredSource, 'claude');
  assert.ok(router.primary instanceof ClaudeReasoningProvider);
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

test('createReasoningProvider selects ClaudeCodeReasoningProvider when HUNTER_USE_CLAUDE_CODE=1 and the binary genuinely exists', async () => {
  // Uses "sh" (present on every POSIX box, exactly like other tests in this
  // package use it to stand in for "some real binary") purely to prove the
  // opt-in + presence-check wiring, not to actually invoke Claude Code here.
  const router = await createReasoningProvider({
    HUNTER_USE_CLAUDE_CODE: '1',
    HUNTER_CLAUDE_CODE_BINARY: 'sh',
  });
  assert.equal(router.configuredSource, 'claude');
  assert.ok(router.primary instanceof ClaudeCodeReasoningProvider);
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

class FailingProvider implements ReasoningProvider {
  readonly source = 'claude' as const;
  selectNextBestAction(): Promise<ActionProposal | undefined> {
    return Promise.reject(new Error('simulated model outage'));
  }
  generateHypotheses(): Promise<readonly []> {
    return Promise.resolve([]);
  }
}

test('selectNextBestActionWithFallback falls back to the heuristic provider when the primary throws, and reports why', async () => {
  const result = await selectNextBestActionWithFallback(
    { primary: new FailingProvider(), fallback: new HeuristicReasoningProvider(), configuredSource: 'claude' },
    EMPTY_SNAPSHOT,
  );
  assert.equal(result.source, 'heuristic');
  assert.match(result.fallbackReason ?? '', /simulated model outage/);
});

test('selectNextBestActionWithFallback uses the primary directly when it succeeds', async () => {
  const heuristic = new HeuristicReasoningProvider();
  const result = await selectNextBestActionWithFallback(
    { primary: heuristic, fallback: heuristic, configuredSource: 'heuristic' },
    EMPTY_SNAPSHOT,
  );
  assert.equal(result.source, 'heuristic');
  assert.equal(result.fallbackReason, undefined);
});
