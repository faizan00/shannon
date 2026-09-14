import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { RawDiscovery } from '../types.js';
import type { ReconSource } from './sources.js';
import { watchReconSources } from './watch.js';

function makeDiscovery(label: string): RawDiscovery {
  return { source: 'test', kind: 'host', label, attributes: {}, confidence: 0.6, discoveredAt: '' };
}

test('watchReconSources fires immediately on the first tick, not after waiting a full interval', async () => {
  const source: ReconSource = {
    name: 'ct-log',
    isAvailable: async () => true,
    discover: async () => [makeDiscovery('a.example.com')],
  };
  const fired: { at: number; discoveries: readonly RawDiscovery[] }[] = [];
  const start = Date.now();
  const handle = watchReconSources(
    [source],
    (discoveries) => {
      fired.push({ at: Date.now() - start, discoveries });
    },
    { intervalMs: 5000, maxIterations: 1 },
  );
  await handle.done;
  assert.equal(fired.length, 1);
  const firstTick = fired[0];
  assert.ok(firstTick);
  assert.ok(firstTick.at < 1000, `expected the first tick to fire immediately, took ${firstTick.at}ms`);
});

test('watchReconSources only reports genuinely new discoveries across ticks, never repeating an already-seen one', async () => {
  let tickCount = 0;
  const source: ReconSource = {
    name: 'ct-log',
    isAvailable: async () => true,
    discover: async () => {
      tickCount += 1;
      // Tick 1: "a" only. Tick 2: "a" again plus a genuinely new "b". Tick 3: same as tick 2 -- nothing new.
      if (tickCount === 1) return [makeDiscovery('a.example.com')];
      return [makeDiscovery('a.example.com'), makeDiscovery('b.example.com')];
    },
  };
  const rounds: (readonly RawDiscovery[])[] = [];
  const handle = watchReconSources(
    [source],
    (discoveries) => {
      rounds.push(discoveries);
    },
    { intervalMs: 50, maxIterations: 3 },
  );
  await handle.done;
  assert.equal(tickCount, 3);
  // Only 2 rounds actually called the callback: tick 1 ("a" is new) and tick 2 ("b" is new). Tick 3 has nothing new, so onNewDiscoveries is never called for it.
  assert.equal(rounds.length, 2);
  assert.equal(rounds[0]?.length, 1);
  assert.equal(rounds[0]?.[0]?.label, 'a.example.com');
  assert.equal(rounds[1]?.length, 1);
  assert.equal(rounds[1]?.[0]?.label, 'b.example.com');
});

test('stop() halts the loop before maxIterations is reached', async () => {
  let tickCount = 0;
  const source: ReconSource = {
    name: 'ct-log',
    isAvailable: async () => true,
    discover: async () => {
      tickCount += 1;
      return [];
    },
  };
  const handle = watchReconSources([source], () => {}, { intervalMs: 30 });
  await new Promise((resolve) => setTimeout(resolve, 80));
  handle.stop();
  const countAtStop = tickCount;
  await new Promise((resolve) => setTimeout(resolve, 100));
  assert.equal(tickCount, countAtStop, 'no further ticks must fire after stop()');
});

test('a source throwing on a given tick does not stop the watch loop (isolation via runReconSources)', async () => {
  let tickCount = 0;
  const throwing: ReconSource = {
    name: 'broken',
    isAvailable: async () => true,
    discover: async () => {
      throw new Error('simulated failure');
    },
  };
  const healthy: ReconSource = {
    name: 'healthy',
    isAvailable: async () => true,
    discover: async () => {
      tickCount += 1;
      return tickCount === 2 ? [makeDiscovery('only-on-tick-2.example.com')] : [];
    },
  };
  const rounds: (readonly RawDiscovery[])[] = [];
  const handle = watchReconSources(
    [throwing, healthy],
    (d) => {
      rounds.push(d);
    },
    { intervalMs: 30, maxIterations: 2 },
  );
  await handle.done;
  assert.equal(tickCount, 2);
  assert.equal(rounds.length, 1);
  assert.equal(rounds[0]?.[0]?.label, 'only-on-tick-2.example.com');
});
