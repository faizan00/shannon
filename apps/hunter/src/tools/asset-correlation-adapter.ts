/**
 * `ToolAdapter` wrapper around `recon/asset-correlation.ts` (Shodan).
 * Same `capability()`-reports-missing-credential discipline as
 * `GitHubDorkAdapter`/`ChaosAdapter`. NOT registered in
 * `tools/default-registry.ts` by default, for the same reason
 * `GitHubDorkAdapter` isn't — an unconfigured `SHODAN_API_KEY` would
 * otherwise silently no-op forever; a caller who wants this wires it in
 * explicitly.
 *
 * HONEST STATUS: see `recon/asset-correlation.ts`'s module docstring —
 * never exercised against the real Shodan API in this codebase's own test
 * suite (no `SHODAN_API_KEY` was available). Unit-tested against an
 * injected `fetch` only.
 */

import { findAssetsByCertificateCommonName, findAssetsByOrg } from '../recon/asset-correlation.js';
import type { ActionKind, RawDiscovery, ToolCapability, ToolRisk, ToolScopeRequirement } from '../types.js';
import type { ToolAdapter, ToolRunResult } from './registry.js';

export interface AssetCorrelationInput {
  readonly orgName?: string;
  readonly certificateCommonName?: string;
}

export class AssetCorrelationAdapter implements ToolAdapter<AssetCorrelationInput> {
  readonly name = 'asset-correlation';
  readonly kind: ActionKind = 'passive-recon';
  readonly scopeRequirement: ToolScopeRequirement = 'passive-only';
  readonly requiresAuthorization = false;
  readonly cost = 0.2;
  readonly risk: ToolRisk = 'none';
  readonly timeoutMs = 30_000;

  constructor(private readonly apiKeyEnvVar: string = 'SHODAN_API_KEY') {}

  capability(): Promise<ToolCapability> {
    const apiKey = process.env[this.apiKeyEnvVar];
    if (!apiKey) {
      return Promise.resolve({
        available: false,
        reason: `${this.apiKeyEnvVar} is not configured`,
        version: undefined,
      });
    }
    return Promise.resolve({ available: true, reason: `${this.apiKeyEnvVar} is configured`, version: undefined });
  }

  async run(input: AssetCorrelationInput): Promise<ToolRunResult> {
    const apiKey = process.env[this.apiKeyEnvVar];
    if (!apiKey) {
      return {
        ok: false,
        summary: `asset-correlation skipped: ${this.apiKeyEnvVar} is not configured`,
        discoveries: [],
        observations: [],
        raw: undefined,
      };
    }
    if (!input.orgName && !input.certificateCommonName) {
      return {
        ok: false,
        summary: 'asset-correlation requires at least one of orgName/certificateCommonName',
        discoveries: [],
        observations: [],
        raw: undefined,
      };
    }
    try {
      const [byOrg, byCert] = await Promise.all([
        input.orgName ? findAssetsByOrg(input.orgName, { apiKey }) : Promise.resolve([]),
        input.certificateCommonName
          ? findAssetsByCertificateCommonName(input.certificateCommonName, { apiKey })
          : Promise.resolve([]),
      ]);
      const assets = [...byOrg, ...byCert];
      const discoveredAt = new Date().toISOString();
      const discoveries: RawDiscovery[] = assets.map((asset) => ({
        source: 'asset-correlation',
        kind: 'host',
        label: asset.hostnames[0] ?? asset.ip,
        attributes: {
          ip: asset.ip,
          port: asset.port,
          hostnames: asset.hostnames,
          org: asset.org,
          matchedOn: asset.matchedOn,
        },
        confidence: 0.5,
        discoveredAt,
      }));
      return {
        ok: true,
        summary: `asset-correlation found ${discoveries.length} related asset(s)`,
        discoveries,
        observations: [],
        raw: assets,
      };
    } catch (error) {
      return {
        ok: false,
        summary: `asset-correlation failed: ${(error as Error).message}`,
        discoveries: [],
        observations: [],
        raw: undefined,
      };
    }
  }
}
