/**
 * `ToolAdapter` wrapper around `recon/github-dork.ts`. Follows the exact
 * same "capability() reports the missing credential; real call only when
 * configured" pattern as `recon/cli-adapters.ts:ChaosAdapter`/`PDCP_API_KEY`.
 * NOT registered in `tools/default-registry.ts` by default — unlike Chaos
 * (a passive-recon source safe to try unconditionally, reporting itself
 * unavailable when unconfigured), enabling this in every hunt would mean
 * an unconfigured `GITHUB_TOKEN` silently no-ops for every single
 * engagement forever; a caller who wants this wires it in explicitly.
 *
 * HONEST STATUS: see `recon/github-dork.ts`'s module docstring — this has
 * never made a real GitHub API call in this codebase's own test suite (no
 * `GITHUB_TOKEN` was available). Unit-tested against an injected `fetch`
 * only.
 */

import { searchGitHubForLeakedSecrets } from '../recon/github-dork.js';
import type { ActionKind, RawDiscovery, ToolCapability, ToolRisk, ToolScopeRequirement } from '../types.js';
import type { ToolAdapter, ToolRunResult } from './registry.js';

export interface GitHubDorkInput {
  readonly domain: string;
}

export class GitHubDorkAdapter implements ToolAdapter<GitHubDorkInput> {
  readonly name = 'github-dork';
  readonly kind: ActionKind = 'passive-recon';
  readonly scopeRequirement: ToolScopeRequirement = 'passive-only';
  readonly requiresAuthorization = false;
  readonly cost = 0.2;
  readonly risk: ToolRisk = 'none';
  readonly timeoutMs = 30_000;

  constructor(private readonly tokenEnvVar: string = 'GITHUB_TOKEN') {}

  capability(): Promise<ToolCapability> {
    const token = process.env[this.tokenEnvVar];
    if (!token) {
      return Promise.resolve({
        available: false,
        reason: `${this.tokenEnvVar} is not configured`,
        version: undefined,
      });
    }
    return Promise.resolve({ available: true, reason: `${this.tokenEnvVar} is configured`, version: undefined });
  }

  async run(input: GitHubDorkInput): Promise<ToolRunResult> {
    const token = process.env[this.tokenEnvVar];
    if (!token) {
      return {
        ok: false,
        summary: `github-dork skipped: ${this.tokenEnvVar} is not configured`,
        discoveries: [],
        observations: [],
        raw: undefined,
      };
    }
    try {
      const matches = await searchGitHubForLeakedSecrets(input.domain, { token });
      const discoveredAt = new Date().toISOString();
      const discoveries: RawDiscovery[] = matches.map((match) => ({
        source: 'github-dork',
        kind: 'integration',
        label: match.htmlUrl,
        attributes: {
          repository: match.repository,
          filePath: match.filePath,
          matchedSecretPatterns: match.matchedSecretPatterns,
          snippetFingerprint: match.snippetFingerprint,
        },
        confidence: 0.5,
        discoveredAt,
      }));
      return {
        ok: true,
        summary: `github-dork found ${matches.length} potential leaked-secret match(es) for "${input.domain}"`,
        discoveries,
        observations: [],
        raw: matches,
      };
    } catch (error) {
      return {
        ok: false,
        summary: `github-dork failed: ${(error as Error).message}`,
        discoveries: [],
        observations: [],
        raw: undefined,
      };
    }
  }
}
