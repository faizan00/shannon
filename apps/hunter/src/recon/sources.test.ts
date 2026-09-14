import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { promisify } from 'node:util';
import {
  isToolInstalled,
  LocalFixtureReconSource,
  runReconSources,
  runReconSourcesStreaming,
  verifyToolIdentity,
} from './sources.js';

const execFileAsync = promisify(execFile);

async function withTempFixture<T>(content: unknown, fn: (path: string) => Promise<T>): Promise<T> {
  const dir = await mkdtemp(join(tmpdir(), 'hunter-recon-source-test-'));
  const path = join(dir, 'fixture.json');
  await writeFile(path, JSON.stringify(content), 'utf8');
  try {
    return await fn(path);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

test('isToolInstalled returns true for a binary that certainly exists', async () => {
  assert.equal(await isToolInstalled('sh'), true);
});

test('isToolInstalled returns false for a binary that certainly does not exist, without throwing', async () => {
  assert.equal(await isToolInstalled('definitely-not-a-real-tool-xyz-123'), false);
});

test('LocalFixtureReconSource reports available and parses its fixture', async () => {
  await withTempFixture(
    [{ kind: 'host', label: 'api.example.com', confidence: 0.8, attributes: { via: 'test' } }],
    async (path) => {
      const source = new LocalFixtureReconSource('subfinder', path);
      assert.equal(await source.isAvailable(), true);
      const discoveries = await source.discover();
      assert.equal(discoveries.length, 1);
      assert.equal(discoveries[0]?.source, 'subfinder');
      assert.equal(discoveries[0]?.label, 'api.example.com');
    },
  );
});

test('LocalFixtureReconSource reports unavailable for a missing fixture file', async () => {
  const source = new LocalFixtureReconSource('amass', '/nonexistent/path/fixture.json');
  assert.equal(await source.isAvailable(), false);
});

test('LocalFixtureReconSource rejects a malformed fixture', async () => {
  await withTempFixture([{ notARealField: true }], async (path) => {
    const source = new LocalFixtureReconSource('bad-source', path);
    await assert.rejects(() => source.discover());
  });
});

test('runReconSources skips unavailable sources and concatenates the rest', async () => {
  await withTempFixture([{ kind: 'host', label: 'a.example.com', confidence: 0.5 }], async (path) => {
    const available = new LocalFixtureReconSource('subfinder', path);
    const unavailable = new LocalFixtureReconSource('amass', '/nonexistent/fixture.json');
    const discoveries = await runReconSources([available, unavailable]);
    assert.equal(discoveries.length, 1);
    assert.equal(discoveries[0]?.source, 'subfinder');
  });
});

test('runReconSources runs independent sources concurrently — a slow source never blocks a fast one', async () => {
  let fastResolvedAt = 0;
  let slowStartedAt = 0;
  const slow = {
    name: 'slow-source',
    isAvailable: async () => true,
    discover: async () => {
      slowStartedAt = Date.now();
      await new Promise((resolve) => setTimeout(resolve, 100));
      return [];
    },
  };
  const fast = {
    name: 'fast-source',
    isAvailable: async () => true,
    discover: async () => {
      fastResolvedAt = Date.now();
      return [
        {
          source: 'fast-source',
          kind: 'host' as const,
          label: 'fast.example.com',
          attributes: {},
          confidence: 0.5,
          discoveredAt: '',
        },
      ];
    },
  };

  await runReconSources([slow, fast]);

  assert.ok(slowStartedAt > 0 && fastResolvedAt > 0);
  // The proof is overlap, not total wall-clock (which is bounded by the
  // slowest source either way, concurrent or not): with `[slow, fast]`
  // given in that order, a sequential implementation would only start
  // (and resolve) `fast` *after* `slow`'s own 100ms completes — well over
  // 50ms after `slowStartedAt`. Concurrent execution starts both together,
  // so `fast` resolves almost immediately, still well inside `slow`'s own
  // 100ms window.
  assert.ok(
    fastResolvedAt - slowStartedAt < 50,
    `the fast source must resolve while the slow source is still running, not after it (gap was ${fastResolvedAt - slowStartedAt}ms)`,
  );
});

// === Regression: a production-readiness audit asked for genuinely bounded
// (not merely "concurrent") recon fan-out — `maxConcurrency` (default:
// unbounded, matching every pre-existing caller/test above) is what closes
// that without changing any of the concurrency guarantees those tests
// already prove. ===

test('runReconSources with no maxConcurrency given still runs every source at once, unchanged from before this parameter existed', async () => {
  let concurrent = 0;
  let maxConcurrent = 0;
  const sources = Array.from({ length: 5 }, (_, i) => ({
    name: `source-${i}`,
    isAvailable: async () => true,
    discover: async () => {
      concurrent += 1;
      maxConcurrent = Math.max(maxConcurrent, concurrent);
      await new Promise((resolve) => setTimeout(resolve, 20));
      concurrent -= 1;
      return [];
    },
  }));
  await runReconSources(sources);
  assert.equal(maxConcurrent, 5);
});

test('runReconSources genuinely bounds fan-out to an explicit maxConcurrency', async () => {
  let concurrent = 0;
  let maxConcurrent = 0;
  const sources = Array.from({ length: 6 }, (_, i) => ({
    name: `source-${i}`,
    isAvailable: async () => true,
    discover: async () => {
      concurrent += 1;
      maxConcurrent = Math.max(maxConcurrent, concurrent);
      await new Promise((resolve) => setTimeout(resolve, 15));
      concurrent -= 1;
      return [
        { source: `source`, kind: 'host' as const, label: 'x', attributes: {}, confidence: 0.5, discoveredAt: '' },
      ];
    },
  }));
  const results = await runReconSources(sources, 2);
  assert.equal(maxConcurrent, 2, `expected at most 2 sources running at once, saw ${maxConcurrent}`);
  assert.equal(results.length, 6, 'a bounded run must still eventually execute every source');
});

test('runReconSourcesStreaming genuinely bounds fan-out while still streaming per-source callbacks', async () => {
  let concurrent = 0;
  let maxConcurrent = 0;
  const completedInOrder: string[] = [];
  const sources = Array.from({ length: 4 }, (_, i) => ({
    name: `source-${i}`,
    isAvailable: async () => true,
    discover: async () => {
      concurrent += 1;
      maxConcurrent = Math.max(maxConcurrent, concurrent);
      await new Promise((resolve) => setTimeout(resolve, 10));
      concurrent -= 1;
      return [];
    },
  }));
  await runReconSourcesStreaming(
    sources,
    (event) => {
      completedInOrder.push(event.source);
    },
    2,
  );
  assert.equal(maxConcurrent, 2);
  assert.equal(completedInOrder.length, 4);
});

test("runReconSources preserves every other source's results when one source throws during discover()", async () => {
  const throwing = {
    name: 'broken-source',
    isAvailable: async () => true,
    discover: async () => {
      throw new Error('simulated tool crash');
    },
  };
  const healthy = {
    name: 'healthy-source',
    isAvailable: async () => true,
    discover: async () => [
      {
        source: 'healthy-source',
        kind: 'host' as const,
        label: 'ok.example.com',
        attributes: {},
        confidence: 0.5,
        discoveredAt: '',
      },
    ],
  };
  const discoveries = await runReconSources([throwing, healthy]);
  assert.equal(discoveries.length, 1);
  assert.equal(discoveries[0]?.source, 'healthy-source');
});

test("runReconSourcesStreaming fires a fast source's callback while a slow sibling source is still running", async () => {
  let slowStartedAt = 0;
  let slowStillRunningWhenFastCallbackFired = false;
  let slowCompleted = false;
  const slow = {
    name: 'slow-source',
    isAvailable: async () => true,
    discover: async () => {
      slowStartedAt = Date.now();
      await new Promise((resolve) => setTimeout(resolve, 100));
      slowCompleted = true;
      return [];
    },
  };
  const fast = {
    name: 'fast-source',
    isAvailable: async () => true,
    discover: async () => [
      {
        source: 'fast-source',
        kind: 'host' as const,
        label: 'fast.example.com',
        attributes: {},
        confidence: 0.5,
        discoveredAt: '',
      },
    ],
  };

  const callbackOrder: string[] = [];
  await runReconSourcesStreaming([slow, fast], (event) => {
    callbackOrder.push(event.source);
    if (event.source === 'fast-source') {
      slowStillRunningWhenFastCallbackFired = slowStartedAt > 0 && !slowCompleted;
    }
  });

  assert.deepEqual(
    callbackOrder,
    ['fast-source', 'slow-source'],
    "the fast source's callback must fire before the slow one's, not after both settle",
  );
  assert.ok(
    slowStillRunningWhenFastCallbackFired,
    'the slow source must genuinely still be in flight when the fast callback fires — this is the "stream while siblings still run" property',
  );
});

test('runReconSourcesStreaming still returns the full concatenated discovery list once every source has settled', async () => {
  const a = {
    name: 'a',
    isAvailable: async () => true,
    discover: async () => [
      { source: 'a', kind: 'host' as const, label: 'a.example.com', attributes: {}, confidence: 0.5, discoveredAt: '' },
    ],
  };
  const b = {
    name: 'b',
    isAvailable: async () => true,
    discover: async () => [
      { source: 'b', kind: 'host' as const, label: 'b.example.com', attributes: {}, confidence: 0.5, discoveredAt: '' },
    ],
  };
  const events: string[] = [];
  const discoveries = await runReconSourcesStreaming([a, b], (event) => {
    events.push(`${event.source}:${event.discoveries.length}`);
  });
  assert.equal(discoveries.length, 2);
  assert.equal(events.length, 2);
});

test('runReconSourcesStreaming calls back for an unavailable source too, with an empty discoveries array', async () => {
  const unavailable = { name: 'gone', isAvailable: async () => false, discover: async () => [] };
  const events: string[] = [];
  await runReconSourcesStreaming([unavailable], (event) => {
    events.push(event.source);
    assert.equal(event.discoveries.length, 0);
  });
  assert.deepEqual(events, ['gone']);
});

test('runReconSourcesStreaming calls back for a throwing source with an empty result, and does not lose the other source', async () => {
  const throwing = {
    name: 'broken',
    isAvailable: async () => true,
    discover: async () => {
      throw new Error('simulated crash');
    },
  };
  const healthy = {
    name: 'healthy',
    isAvailable: async () => true,
    discover: async () => [
      {
        source: 'healthy',
        kind: 'host' as const,
        label: 'ok.example.com',
        attributes: {},
        confidence: 0.5,
        discoveredAt: '',
      },
    ],
  };
  const seen = new Set<string>();
  const discoveries = await runReconSourcesStreaming([throwing, healthy], (event) => {
    seen.add(event.source);
  });
  assert.deepEqual(seen, new Set(['broken', 'healthy']));
  assert.equal(discoveries.length, 1);
});

test('verifyToolIdentity reports unavailable for a binary name that does not exist, without throwing', async () => {
  const capability = await verifyToolIdentity({
    binary: 'definitely-not-a-real-tool-xyz-123',
    versionArgs: ['-version'],
    expectedSignature: /anything/,
  });
  assert.equal(capability.available, false);
  assert.match(capability.reason, /not found on PATH/);
});

test('verifyToolIdentity rejects a real binary whose output does not match the expected tool signature', async () => {
  // "sh" exists on every POSIX box but is obviously not any recon tool.
  const capability = await verifyToolIdentity({
    binary: 'sh',
    versionArgs: ['-c', 'echo not-the-right-tool'],
    expectedSignature: /this-signature-will-never-match/,
  });
  assert.equal(capability.available, false);
  assert.match(capability.reason, /unrelated program/);
});

test('verifyToolIdentity confirms a real installed tool when both presence and signature match', async () => {
  // Only assert the positive path when the environment genuinely has the
  // tool, so this test is meaningful without being flaky across machines.
  if (!(await isToolInstalled('ffuf'))) {
    return;
  }
  const capability = await verifyToolIdentity({
    binary: 'ffuf',
    versionArgs: ['-V'],
    expectedSignature: /ffuf/i,
  });
  assert.equal(capability.available, true);
  assert.ok(capability.version);
});

test('verifyToolIdentity catches a same-named-but-different binary (e.g. Python httpx instead of ProjectDiscovery httpx), and confirms the real one when it genuinely resolves first', async () => {
  if (!(await isToolInstalled('httpx'))) {
    return;
  }
  const capability = await verifyToolIdentity({
    binary: 'httpx',
    versionArgs: ['-version'],
    expectedSignature: /projectdiscovery/i,
  });
  // Derived from reality, not hardcoded: whichever "httpx" this machine's
  // PATH resolves to right now, `capability.available` must agree with
  // whether that binary's own -version output actually says
  // "projectdiscovery" -- true when a real ProjectDiscovery install
  // legitimately comes first on PATH, false when an unrelated same-named
  // tool (e.g. Python's httpx client) does. A hardcoded `false` here would
  // itself be exactly the kind of environment-baked assumption this test
  // exists to catch elsewhere.
  const raw = await execFileAsync('httpx', ['-version']).catch((error) => ({
    stdout: (error as { stdout?: string }).stdout ?? '',
    stderr: (error as { stderr?: string }).stderr ?? '',
  }));
  const isRealProjectDiscoveryHttpx = /projectdiscovery/i.test(`${raw.stdout}\n${raw.stderr}`);
  assert.equal(capability.available, isRealProjectDiscoveryHttpx);
});
