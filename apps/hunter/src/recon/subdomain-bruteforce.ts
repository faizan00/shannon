/**
 * Active subdomain bruteforcing via real DNS resolution.
 *
 * Passive sources (`recon/sources.ts`, `recon/cli-adapters.ts`'s
 * subfinder/amass/chaos/certificate-transparency) only ever surface a
 * subdomain someone else already recorded somewhere public. A real
 * permutation bruteforce — resolve a large, target-vocabulary-informed
 * candidate list and see what actually answers — regularly finds hosts no
 * passive source ever will (an internal-only DNS record, a forgotten
 * staging box, a host that was never certificate-transparency-logged).
 * This is read-only DNS resolution (`node:dns/promises`, no network
 * library) against whatever DNS server this process already uses — no
 * different in kind from a browser resolving a hostname, and standard
 * recon practice on any program that does not explicitly forbid it (see
 * `discovery/roe.ts` — this is wired as its own `ToolAdapter`, so a
 * program declaring "no DNS bruteforcing"/"no active scanning" blocks it
 * exactly like any other active-recon tool).
 *
 * Bounded concurrency (`tools/concurrency-limit.ts`, not the process's own
 * event loop capacity) so a large candidate list cannot itself become a
 * de facto denial-of-service against the target's own DNS infrastructure.
 */

import { resolve4, resolve6 } from 'node:dns/promises';
import { mapWithConcurrencyLimit } from '../tools/concurrency-limit.js';
import type { RawDiscovery } from '../types.js';

export interface BruteforceOptions {
  /** Default 20 -- deliberately conservative; DNS resolution against a real authoritative server is still real load. */
  readonly concurrency?: number;
  readonly timeoutMs?: number;
}

interface ResolutionOutcome {
  readonly candidate: string;
  readonly addresses: readonly string[];
}

async function resolveWithTimeout(candidate: string, timeoutMs: number): Promise<ResolutionOutcome | undefined> {
  const timeout = new Promise<never>((_, reject) => {
    setTimeout(() => reject(new Error('dns resolution timed out')), timeoutMs);
  });
  try {
    const addresses = await Promise.race([resolve4(candidate).catch(async () => resolve6(candidate)), timeout]);
    return { candidate, addresses };
  } catch {
    // NXDOMAIN, timeout, or any other resolution failure -- this candidate simply does not exist. Not an error to surface.
    return undefined;
  }
}

/**
 * Resolves every candidate FQDN and returns a `RawDiscovery` for each one
 * that genuinely answers. Candidates that do not resolve are silently
 * dropped (an NXDOMAIN is the expected, overwhelmingly common outcome for
 * most of a real permutation list, not a failure worth reporting).
 */
export async function bruteforceSubdomains(
  candidates: readonly string[],
  options: BruteforceOptions = {},
): Promise<readonly RawDiscovery[]> {
  const concurrency = options.concurrency ?? 20;
  const timeoutMs = options.timeoutMs ?? 5000;
  const outcomes = await mapWithConcurrencyLimit(candidates, concurrency, (candidate) =>
    resolveWithTimeout(candidate, timeoutMs),
  );
  const discoveredAt = new Date().toISOString();
  const discoveries: RawDiscovery[] = [];
  for (const outcome of outcomes) {
    if (!outcome) continue;
    discoveries.push({
      source: 'subdomain-bruteforce',
      kind: 'host',
      label: outcome.candidate,
      attributes: { addresses: outcome.addresses },
      confidence: 0.7,
      discoveredAt,
    });
  }
  return discoveries;
}
