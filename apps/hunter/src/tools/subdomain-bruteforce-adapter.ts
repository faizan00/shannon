/**
 * `ToolAdapter` wrapper around `recon/subdomain-bruteforce.ts` +
 * `recon/wordlist-generator.ts`, so real DNS-permutation bruteforcing fits
 * the same `ToolRegistry`/`pipeline/tool-bridge.ts` gate chain as every
 * other adapter — scope, ROE, and rate limiting apply to it exactly like
 * `naabu`/`ffuf`. Classified `active-recon`/`active-in-scope` (conservative,
 * matching `naabu`'s classification) even though it never touches the
 * target's web application layer, only DNS: a program's ROE may still
 * reasonably restrict active enumeration techniques, and this package
 * never assumes otherwise.
 */

import { bruteforceSubdomains } from '../recon/subdomain-bruteforce.js';
import { generateSubdomainPermutations } from '../recon/wordlist-generator.js';
import type { ActionKind, ToolCapability, ToolRisk, ToolScopeRequirement } from '../types.js';
import type { ToolAdapter, ToolRunResult } from './registry.js';

export interface SubdomainBruteforceInput {
  readonly baseDomain: string;
  /** Operator-supplied vocabulary specific to this target (company/product names). */
  readonly seedWords?: readonly string[];
  /** Tokens from `wordlist-generator.ts:extractCandidateTokens`, over whatever this engagement has already discovered -- the "amplification" loop. */
  readonly discoveredTokens?: readonly string[];
  readonly includePairs?: boolean;
  readonly concurrency?: number;
}

export class SubdomainBruteforceAdapter implements ToolAdapter<SubdomainBruteforceInput> {
  readonly name = 'subdomain-bruteforce';
  readonly kind: ActionKind = 'active-recon';
  readonly scopeRequirement: ToolScopeRequirement = 'active-in-scope';
  readonly requiresAuthorization = true;
  readonly cost = 0.15;
  readonly risk: ToolRisk = 'low';
  readonly timeoutMs = 60_000;

  capability(): Promise<ToolCapability> {
    return Promise.resolve({
      available: true,
      reason: 'pure DNS resolution (node:dns); no local binary required',
      version: undefined,
    });
  }

  async run(input: SubdomainBruteforceInput): Promise<ToolRunResult> {
    const candidates = generateSubdomainPermutations({
      baseDomain: input.baseDomain,
      ...(input.seedWords !== undefined ? { seedWords: input.seedWords } : {}),
      ...(input.discoveredTokens !== undefined ? { discoveredTokens: input.discoveredTokens } : {}),
      ...(input.includePairs !== undefined ? { includePairs: input.includePairs } : {}),
    });
    try {
      const discoveries = await bruteforceSubdomains(candidates, {
        ...(input.concurrency !== undefined ? { concurrency: input.concurrency } : {}),
        timeoutMs: Math.min(this.timeoutMs, 8000),
      });
      return {
        ok: true,
        summary: `subdomain-bruteforce resolved ${discoveries.length}/${candidates.length} candidate(s)`,
        discoveries,
        observations: [],
        raw: { candidateCount: candidates.length },
      };
    } catch (error) {
      return {
        ok: false,
        summary: `subdomain-bruteforce failed: ${(error as Error).message}`,
        discoveries: [],
        observations: [],
        raw: undefined,
      };
    }
  }
}
