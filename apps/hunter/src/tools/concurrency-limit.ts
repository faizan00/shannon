/**
 * A small, dependency-free bounded-concurrency runner. `mapWithConcurrencyLimit`
 * is a strict generalization of `Promise.all(items.map(worker))`, not a
 * separate code path for the unbounded case: a `limit` at or above
 * `items.length` (the default, and what every pre-existing caller in this
 * package gets when it does not pass one) fires every worker immediately,
 * identical to today's behavior — only a caller that explicitly passes a
 * smaller `limit` gets real bounding. This is what makes it safe to drop
 * into `recon/sources.ts` without changing any currently-passing real-timing
 * concurrency test.
 *
 * `worker` is responsible for its own failure isolation (catch internally
 * and return a fallback value) — a worker that throws here rejects the
 * whole pool, exactly like a bare `Promise.all` would, unlike
 * `Promise.allSettled`. Callers that need per-item isolation (every current
 * one does) wrap their own worker body in try/catch, the same way they
 * already relied on `Promise.allSettled` to do for them before this change.
 */
export async function mapWithConcurrencyLimit<T, R>(
  items: readonly T[],
  limit: number,
  worker: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const results: R[] = new Array(items.length);
  if (items.length === 0) {
    return results;
  }
  const laneCount = limit > 0 ? Math.min(Math.floor(limit), items.length) : items.length;
  let nextIndex = 0;

  async function runLane(): Promise<void> {
    for (;;) {
      const index = nextIndex;
      nextIndex += 1;
      if (index >= items.length) {
        return;
      }
      results[index] = await worker(items[index] as T, index);
    }
  }

  const lanes = Array.from({ length: laneCount }, () => runLane());
  await Promise.all(lanes);
  return results;
}
