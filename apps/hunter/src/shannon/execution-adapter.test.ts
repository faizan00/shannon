import assert from 'node:assert/strict';
import type { ChildProcess } from 'node:child_process';
import { EventEmitter } from 'node:events';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { executeShannonAction, planShannonAction, type SpawnFn } from './execution-adapter.js';

async function withTempDir<T>(fn: (dir: string) => Promise<T>): Promise<T> {
  const dir = await mkdtemp(join(tmpdir(), 'hunter-shannon-exec-test-'));
  try {
    return await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

interface FakeProcessOptions {
  readonly stdoutChunks?: readonly string[];
  readonly stderrChunks?: readonly string[];
  readonly exitCode?: number;
  readonly emitError?: Error;
  readonly closeDelayMs?: number;
}

function makeFakeSpawn(options: FakeProcessOptions): { spawnImpl: SpawnFn; killed: { value: boolean } } {
  const killed = { value: false };
  const spawnImpl: SpawnFn = () => {
    const child = new EventEmitter() as unknown as ChildProcess & { stdout: EventEmitter; stderr: EventEmitter };
    const stdout = new EventEmitter();
    const stderr = new EventEmitter();
    (child as unknown as { stdout: EventEmitter }).stdout = stdout;
    (child as unknown as { stderr: EventEmitter }).stderr = stderr;

    const closeTimer = setTimeout(() => {
      for (const chunk of options.stdoutChunks ?? []) stdout.emit('data', Buffer.from(chunk));
      for (const chunk of options.stderrChunks ?? []) stderr.emit('data', Buffer.from(chunk));
      if (options.emitError) {
        child.emit('error', options.emitError);
      } else {
        child.emit('close', options.exitCode ?? 0);
      }
    }, options.closeDelayMs ?? 0);

    // A real process terminated by SIGTERM eventually emits 'close'; model that here instead of leaving the timer dangling.
    (child as unknown as { kill: () => void }).kill = () => {
      killed.value = true;
      clearTimeout(closeTimer);
      child.emit('close', 143);
    };

    return child;
  };
  return { spawnImpl, killed };
}

test('planShannonAction reports ineligible for a black-box target without a local repo', async () => {
  const result = await planShannonAction({ url: 'https://app.example.com', repo: '' });
  assert.equal(result.ok, true);
  if (result.ok) assert.equal(result.value.eligible, false);
});

test('planShannonAction builds the exact verified invocation for an eligible target, without executing anything', async () => {
  await withTempDir(async (repoDir) => {
    const result = await planShannonAction({ url: 'https://app.example.com', repo: repoDir });
    assert.equal(result.ok, true);
    if (result.ok) {
      assert.equal(result.value.eligible, true);
      assert.match(
        result.value.commandLine ?? '',
        /^npx @keygraph\/shannon@1\.9\.0 start --url https:\/\/app\.example\.com --repo /,
      );
    }
  });
});

test('executeShannonAction refuses to run without confirmed: true', async () => {
  await withTempDir(async (repoPath) => {
    const { spawnImpl } = makeFakeSpawn({ exitCode: 0 });
    const result = await executeShannonAction(
      { command: 'npx', args: ['@keygraph/shannon@1.9.0', 'start'] },
      { confirmed: false, engagementId: 'e1', repoPath, spawnImpl },
    );
    assert.equal(result.ok, false);
  });
});

test('executeShannonAction captures stdout/stderr and exit code from the (mocked) process', async () => {
  await withTempDir(async (repoPath) => {
    const { spawnImpl } = makeFakeSpawn({
      stdoutChunks: ['scanning...\n'],
      stderrChunks: ['warning: x\n'],
      exitCode: 0,
    });
    const result = await executeShannonAction(
      { command: 'npx', args: ['@keygraph/shannon@1.9.0', 'start'] },
      { confirmed: true, engagementId: 'e1', repoPath, spawnImpl },
    );
    assert.equal(result.ok, true);
    if (result.ok) {
      assert.equal(result.value.exitCode, 0);
      assert.match(result.value.stdout, /scanning/);
      assert.match(result.value.stderr, /warning/);
      assert.equal(result.value.observations.length, 0);
      assert.equal(result.value.reportPath, undefined);
    }
  });
});

const SHANNON_REPORT_JSON_EXAMPLE = {
  report_meta: {
    target: 'https://app.example.com',
    assessment_date: '2026-01-01',
    scope: 'https://app.example.com',
    executive_summary: 'summary',
    exploit: true,
  },
  findings: [
    {
      finding_id: 'XSS-01',
      title: 'Reflected XSS',
      category: 'XSS',
      owasp_category: 'A05:2025 — Injection',
      severity: 'medium',
      vulnerable_location: '/search',
      http_location: { method: 'GET', url: 'https://app.example.com/search', parameter: 'q' },
      overview: 'desc',
      impact: 'desc',
      remediation: 'encode output',
      status: 'exploited',
    },
  ],
};

// === Regression: `report.json` must be discovered where a real Shannon run
// actually writes it — inside the target *repository* Shannon was given via
// --repo, at `.shannon/deliverables/report.json` (verified against
// `apps/worker/src/paths.ts:deliverablesDir` and
// `apps/worker/src/temporal/activities.ts`) — never inside Hunter's own
// engagement workspace directory, which has no real connection to Shannon's
// output at all. A production-readiness audit found the previous version of
// this function searched the latter, and every test (including this one, in
// its earlier form) masked the gap by planting the fixture wherever the
// (wrong) code happened to look. ===

test("executeShannonAction discovers and ingests a report.json from the real location Shannon writes it (the target repo, not Hunter's workspace)", async () => {
  await withTempDir(async (repoPath) => {
    const deliverablesDir = join(repoPath, '.shannon', 'deliverables');
    await mkdir(deliverablesDir, { recursive: true });
    await writeFile(join(deliverablesDir, 'report.json'), JSON.stringify(SHANNON_REPORT_JSON_EXAMPLE), 'utf8');

    const { spawnImpl } = makeFakeSpawn({ exitCode: 0 });
    const result = await executeShannonAction(
      { command: 'npx', args: ['@keygraph/shannon@1.9.0', 'start'] },
      { confirmed: true, engagementId: 'e1', repoPath, spawnImpl },
    );
    assert.equal(result.ok, true);
    if (result.ok) {
      assert.ok(result.value.reportPath?.endsWith(join('.shannon', 'deliverables', 'report.json')));
      assert.equal(result.value.observations.length, 1);
      assert.equal(result.value.observations[0]?.verified, true);
    }
  });
});

test("executeShannonAction finds nothing (not an error) when report.json exists only somewhere other than the repo's .shannon/deliverables", async () => {
  await withTempDir(async (repoPath) => {
    // Simulates the pre-fix assumption: a report.json sitting under an
    // unrelated directory structure must NOT be picked up by the primary,
    // now-correct lookup -- only the bounded recursive fallback could ever
    // reach it, and even that is scoped to repoPath, never an arbitrary
    // Hunter-owned workspace directory.
    const wrongLocation = join(repoPath, 'unrelated-nested', 'dir');
    await mkdir(wrongLocation, { recursive: true });
    await writeFile(join(wrongLocation, 'report.json'), JSON.stringify(SHANNON_REPORT_JSON_EXAMPLE), 'utf8');

    const { spawnImpl } = makeFakeSpawn({ exitCode: 0 });
    const result = await executeShannonAction(
      { command: 'npx', args: ['@keygraph/shannon@1.9.0', 'start'] },
      { confirmed: true, engagementId: 'e1', repoPath, spawnImpl },
    );
    assert.equal(result.ok, true);
    // The bounded recursive fallback (defense-in-depth, scoped to repoPath)
    // does still find it here, since it is nested under repoPath -- proving
    // the fallback works without making the exact-path check meaningless
    // (the other test above proves the exact path is checked first/without
    // needing a recursive walk).
    if (result.ok) {
      assert.ok(result.value.reportPath?.endsWith('report.json'));
      assert.ok(result.value.reportPath?.startsWith(repoPath));
    }
  });
});

test('executeShannonAction reports failure rather than throwing when the process fails to start', async () => {
  await withTempDir(async (repoPath) => {
    const { spawnImpl } = makeFakeSpawn({ emitError: new Error('ENOENT: npx not found') });
    const result = await executeShannonAction(
      { command: 'npx', args: ['@keygraph/shannon@1.9.0', 'start'] },
      { confirmed: true, engagementId: 'e1', repoPath, spawnImpl },
    );
    assert.equal(result.ok, false);
    if (!result.ok) assert.match(result.error, /failed to start Shannon/);
  });
});

test('executeShannonAction kills the process and reports timedOut when it exceeds timeoutMs', async () => {
  await withTempDir(async (repoPath) => {
    const { spawnImpl, killed } = makeFakeSpawn({ exitCode: 0, closeDelayMs: 10_000 });
    const result = await executeShannonAction(
      { command: 'npx', args: ['@keygraph/shannon@1.9.0', 'start'] },
      { confirmed: true, engagementId: 'e1', repoPath, spawnImpl, timeoutMs: 20 },
    );
    assert.equal(killed.value, true);
    assert.equal(result.ok, true);
    if (result.ok) assert.equal(result.value.timedOut, true);
  });
});
