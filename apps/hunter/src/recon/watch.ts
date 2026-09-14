/**
 * Continuous/real-time recon monitoring ("watch mode").
 *
 * Every recon path elsewhere in this package (`runReconSources`,
 * `runReconSourcesStreaming`) is a single snapshot: run once, get whatever
 * is true right now. A real edge experienced hunters have is monitoring —
 * re-checking certificate transparency, passive DNS, and similar low-cost
 * sources on an interval and reacting the moment something *new* appears
 * (a fresh CT log entry for a subdomain that didn't exist yesterday), often
 * minutes after it happens rather than whenever the next one-off scan
 * happens to run.
 *
 * `watchReconSources` is a thin, dependency-free polling loop around the
 * exact same `ReconSource` abstraction and `runReconSources` this package
 * already uses for one-shot recon — no second discovery implementation.
 * It tracks everything it has already reported (by `kind::label`) so the
 * caller's callback only ever fires for genuinely new discoveries, never a
 * repeat of something already seen on a prior tick.
 */

import type { RawDiscovery } from '../types.js';
import { type ReconSource, runReconSources } from './sources.js';

export interface WatchOptions {
  readonly intervalMs: number;
  /** Bounds the loop to this many ticks, then stops on its own -- primarily for deterministic tests; omitted means "run until stop() is called." */
  readonly maxIterations?: number;
  readonly maxConcurrency?: number;
}

export interface WatchHandle {
  /** Stops the loop after its current tick (if one is in flight) finishes; safe to call more than once. */
  stop(): void;
  /** Resolves once the loop has genuinely stopped -- either `stop()` was called, or `maxIterations` was reached. */
  readonly done: Promise<void>;
}

function discoveryKey(discovery: RawDiscovery): string {
  return `${discovery.kind}::${discovery.label}`;
}

/**
 * Polls `sources` every `options.intervalMs`, firing `onNewDiscoveries`
 * with only the discoveries not already reported on a prior tick. Fires
 * immediately on the first tick rather than waiting a full interval first.
 * A source throwing on a given tick is isolated by `runReconSources`
 * itself (partial results preserved) -- this loop never stops because one
 * tick had a bad source.
 */
export function watchReconSources(
  sources: readonly ReconSource[],
  onNewDiscoveries: (discoveries: readonly RawDiscovery[]) => void | Promise<void>,
  options: WatchOptions,
): WatchHandle {
  const seen = new Set<string>();
  let stopped = false;
  let resolveDone: () => void;
  const done = new Promise<void>((resolve) => {
    resolveDone = resolve;
  });

  async function tick(iteration: number): Promise<void> {
    if (stopped) {
      resolveDone();
      return;
    }
    const discoveries = await runReconSources(sources, options.maxConcurrency ?? sources.length);
    const fresh: RawDiscovery[] = [];
    for (const discovery of discoveries) {
      const key = discoveryKey(discovery);
      if (seen.has(key)) continue;
      seen.add(key);
      fresh.push(discovery);
    }
    if (fresh.length > 0) {
      await onNewDiscoveries(fresh);
    }
    if (stopped || (options.maxIterations !== undefined && iteration + 1 >= options.maxIterations)) {
      resolveDone();
      return;
    }
    setTimeout(() => {
      tick(iteration + 1).catch(() => {
        // A tick that throws for a reason outside runReconSources's own
        // isolation (e.g. onNewDiscoveries itself throwing) ends the loop
        // rather than looping forever on a broken callback -- surfaced via
        // `done` never resolving cleanly is not acceptable either, so
        // resolve here too, having done what it safely could.
        resolveDone();
      });
    }, options.intervalMs);
  }

  tick(0).catch(() => resolveDone());

  return {
    stop: () => {
      stopped = true;
    },
    done,
  };
}
