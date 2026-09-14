import assert from 'node:assert/strict';
import type { ChildProcess } from 'node:child_process';
import { EventEmitter } from 'node:events';
import { tmpdir } from 'node:os';
import { test } from 'node:test';
import type { SpawnFn } from '../shannon/execution-adapter.js';
import type { HuntAction, ProgramScope } from '../types.js';
import { executeShannonHuntAction } from './shannon-action.js';

function fakeSpawn(recordedArgs: { args: readonly string[] }[]): SpawnFn {
  return (_command, args) => {
    recordedArgs.push({ args });
    const child = new EventEmitter() as unknown as ChildProcess & { stdout: EventEmitter; stderr: EventEmitter };
    (child as unknown as { stdout: EventEmitter }).stdout = new EventEmitter();
    (child as unknown as { stderr: EventEmitter }).stderr = new EventEmitter();
    setTimeout(() => child.emit('close', 0), 0);
    return child;
  };
}

function action(): HuntAction {
  const now = new Date().toISOString();
  return {
    id: 'action-1',
    engagementId: 'e1',
    kind: 'shannon',
    targetRef: 'https://app.example.com/search',
    hypothesisId: 'hyp-1',
    rationale: 'x',
    expectedInformationGain: 0.5,
    cost: 0.6,
    status: 'queued',
    createdAt: now,
    completedAt: undefined,
    resultSummary: undefined,
  };
}

function program(overrides: Partial<ProgramScope> = {}): ProgramScope {
  return {
    programId: 'p1',
    programName: 'Test Program',
    platform: 'hackerone',
    authorizationConfirmed: true,
    assets: [],
    rulesOfEngagement: [],
    disallowedTechniques: [],
    rateLimitPerMinute: 60,
    ...overrides,
  };
}

test('a program disallowing "shannon" blocks the action before the eligibility check even runs', async () => {
  const result = await executeShannonHuntAction(action(), {
    program: program({ disallowedTechniques: ['shannon'] }),
    repoPath: undefined, // would normally produce an UNAVAILABLE ineligibility reason instead
    engagementId: 'e1',
    workspaceDir: '/tmp/does-not-matter',
    shannonOutputsByAsset: new Map(),
    liveShannon: undefined,
  });
  assert.equal(result.executionStatus, 'BLOCKED_BY_POLICY');
  assert.match(result.resultSummary, /ROE:/);
  assert.equal(result.skipped, true);
});

test('a program disallowing "automated exploitation" (an alias, not the bare kind) also blocks Shannon', async () => {
  const result = await executeShannonHuntAction(action(), {
    program: program({ disallowedTechniques: ['automated exploitation'] }),
    repoPath: undefined,
    engagementId: 'e1',
    workspaceDir: '/tmp/does-not-matter',
    shannonOutputsByAsset: new Map(),
    liveShannon: undefined,
  });
  assert.equal(result.executionStatus, 'BLOCKED_BY_POLICY');
});

test('a program with no disallowed techniques falls through to the ordinary eligibility check', async () => {
  const result = await executeShannonHuntAction(action(), {
    program: program(),
    repoPath: undefined, // no repo -> ineligible for a different, unrelated reason
    engagementId: 'e1',
    workspaceDir: '/tmp/does-not-matter',
    shannonOutputsByAsset: new Map(),
    liveShannon: undefined,
  });
  assert.equal(result.executionStatus, 'UNAVAILABLE');
  assert.match(result.resultSummary, /black-box/);
});

test('an unrelated ROE rule never blocks a shannon action', async () => {
  const result = await executeShannonHuntAction(action(), {
    program: program({ disallowedTechniques: ['no social engineering'] }),
    repoPath: undefined,
    engagementId: 'e1',
    workspaceDir: '/tmp/does-not-matter',
    shannonOutputsByAsset: new Map(),
    liveShannon: undefined,
  });
  // still ineligible, but for the eligibility reason, not ROE.
  assert.equal(result.executionStatus, 'UNAVAILABLE');
  assert.doesNotMatch(result.resultSummary, /ROE:/);
});

// === Regression: concurrent Shannon-kind experiments (research-track
// batches, or a research-track run overlapping the primary loop) must
// never rely on Shannon's own URL+timestamp auto-naming to keep their
// state apart — see `shannonWorkspaceName`'s docstring. ===

test('a live Shannon invocation always carries an explicit, deterministic --workspace name', async () => {
  const recorded: { args: readonly string[] }[] = [];
  const result = await executeShannonHuntAction(action(), {
    program: program(),
    repoPath: tmpdir(),
    engagementId: 'e1',
    workspaceDir: '/tmp/does-not-matter',
    shannonOutputsByAsset: new Map(),
    liveShannon: { confirmed: true, spawnImpl: fakeSpawn(recorded) },
  });
  assert.equal(result.executionStatus, 'EXECUTED_NO_RESULTS');
  assert.equal(recorded.length, 1);
  const args = recorded[0]?.args ?? [];
  const flagIndex = args.indexOf('--workspace');
  assert.ok(flagIndex >= 0, `expected --workspace in ${JSON.stringify(args)}`);
  assert.match(args[flagIndex + 1] ?? '', /^hunter-[0-9a-f]{12}$/);
});

test('two different targets in the same engagement get two different --workspace names', async () => {
  const recordedA: { args: readonly string[] }[] = [];
  const recordedB: { args: readonly string[] }[] = [];
  const targetA = action();
  const targetB = { ...action(), targetRef: 'https://app.example.com/other-endpoint' };

  await executeShannonHuntAction(targetA, {
    program: program(),
    repoPath: tmpdir(),
    engagementId: 'e1',
    workspaceDir: '/tmp/does-not-matter',
    shannonOutputsByAsset: new Map(),
    liveShannon: { confirmed: true, spawnImpl: fakeSpawn(recordedA) },
  });
  await executeShannonHuntAction(targetB, {
    program: program(),
    repoPath: tmpdir(),
    engagementId: 'e1',
    workspaceDir: '/tmp/does-not-matter',
    shannonOutputsByAsset: new Map(),
    liveShannon: { confirmed: true, spawnImpl: fakeSpawn(recordedB) },
  });

  const workspaceOf = (recorded: { args: readonly string[] }[]) => {
    const args = recorded[0]?.args ?? [];
    return args[args.indexOf('--workspace') + 1];
  };
  assert.notEqual(workspaceOf(recordedA), workspaceOf(recordedB));
});

test('the same (engagementId, targetRef) pair always gets the same --workspace name, across separate invocations', async () => {
  const recordedFirst: { args: readonly string[] }[] = [];
  const recordedSecond: { args: readonly string[] }[] = [];

  await executeShannonHuntAction(action(), {
    program: program(),
    repoPath: tmpdir(),
    engagementId: 'e1',
    workspaceDir: '/tmp/does-not-matter',
    shannonOutputsByAsset: new Map(),
    liveShannon: { confirmed: true, spawnImpl: fakeSpawn(recordedFirst) },
  });
  await executeShannonHuntAction(action(), {
    program: program(),
    repoPath: tmpdir(),
    engagementId: 'e1',
    workspaceDir: '/tmp/does-not-matter',
    shannonOutputsByAsset: new Map(),
    liveShannon: { confirmed: true, spawnImpl: fakeSpawn(recordedSecond) },
  });

  const workspaceOf = (recorded: { args: readonly string[] }[]) => {
    const args = recorded[0]?.args ?? [];
    return args[args.indexOf('--workspace') + 1];
  };
  assert.equal(workspaceOf(recordedFirst), workspaceOf(recordedSecond));
});
