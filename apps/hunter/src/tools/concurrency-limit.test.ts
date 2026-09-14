import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mapWithConcurrencyLimit } from './concurrency-limit.js';

test('mapWithConcurrencyLimit with no effective cap runs every worker immediately, like Promise.all', async () => {
  let concurrent = 0;
  let maxConcurrent = 0;
  const items = [1, 2, 3, 4];
  const results = await mapWithConcurrencyLimit(items, items.length, async (item) => {
    concurrent += 1;
    maxConcurrent = Math.max(maxConcurrent, concurrent);
    await new Promise((resolve) => setTimeout(resolve, 20));
    concurrent -= 1;
    return item * 2;
  });
  assert.deepEqual(results, [2, 4, 6, 8]);
  assert.equal(maxConcurrent, 4);
});

test('mapWithConcurrencyLimit genuinely bounds concurrency to the given limit', async () => {
  let concurrent = 0;
  let maxConcurrent = 0;
  const items = [1, 2, 3, 4, 5, 6];
  const results = await mapWithConcurrencyLimit(items, 2, async (item) => {
    concurrent += 1;
    maxConcurrent = Math.max(maxConcurrent, concurrent);
    await new Promise((resolve) => setTimeout(resolve, 15));
    concurrent -= 1;
    return item;
  });
  assert.deepEqual(results, items);
  assert.equal(maxConcurrent, 2, `expected at most 2 concurrent workers, saw ${maxConcurrent}`);
});

test('mapWithConcurrencyLimit preserves result order regardless of completion order', async () => {
  const delays = [30, 10, 20];
  const results = await mapWithConcurrencyLimit(delays, 3, async (delay, index) => {
    await new Promise((resolve) => setTimeout(resolve, delay));
    return index;
  });
  assert.deepEqual(results, [0, 1, 2]);
});

test('mapWithConcurrencyLimit with a limit of 1 runs strictly one at a time', async () => {
  const order: number[] = [];
  await mapWithConcurrencyLimit([1, 2, 3], 1, async (item) => {
    order.push(item);
    await new Promise((resolve) => setTimeout(resolve, 5));
    return item;
  });
  assert.deepEqual(order, [1, 2, 3]);
});

test('mapWithConcurrencyLimit is a safe no-op for an empty item list', async () => {
  const results = await mapWithConcurrencyLimit<number, number>([], 3, async (item) => item);
  assert.deepEqual(results, []);
});

test('mapWithConcurrencyLimit rejects if a worker throws (callers must isolate their own failures)', async () => {
  await assert.rejects(
    mapWithConcurrencyLimit([1, 2], 2, async (item) => {
      if (item === 1) throw new Error('boom');
      return item;
    }),
    /boom/,
  );
});
