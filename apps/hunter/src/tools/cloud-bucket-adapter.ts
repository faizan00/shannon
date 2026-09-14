/**
 * `ToolAdapter` wrapper around `recon/cloud-buckets.ts`, so real cloud
 * storage bucket discovery fits the same `ToolRegistry`/
 * `pipeline/tool-bridge.ts` gate chain as every other adapter. Classified
 * `active-recon`/`active-in-scope` like `naabu`/`subdomain-bruteforce` —
 * conservative, even though it is read-only HTTP against the cloud
 * provider's own public endpoint, never the target's own infrastructure
 * directly.
 */

import { type CloudProvider, checkBucket, generateBucketNameCandidates } from '../recon/cloud-buckets.js';
import type { ActionKind, RawDiscovery, ToolCapability, ToolRisk, ToolScopeRequirement } from '../types.js';
import { mapWithConcurrencyLimit } from './concurrency-limit.js';
import type { ToolAdapter, ToolRunResult } from './registry.js';

const CHECK_CONCURRENCY = 10;

export interface CloudBucketDiscoveryInput {
  /** Operator/discovery-supplied vocabulary specific to this target -- company/product names, discovered hostname tokens. */
  readonly seedWords: readonly string[];
  readonly providers?: readonly CloudProvider[];
}

const ALL_PROVIDERS: readonly CloudProvider[] = ['s3', 'gcs', 'azure'];

export class CloudBucketAdapter implements ToolAdapter<CloudBucketDiscoveryInput> {
  readonly name = 'cloud-bucket-discovery';
  readonly kind: ActionKind = 'active-recon';
  readonly scopeRequirement: ToolScopeRequirement = 'active-in-scope';
  readonly requiresAuthorization = true;
  readonly cost = 0.2;
  readonly risk: ToolRisk = 'low';
  readonly timeoutMs = 60_000;

  capability(): Promise<ToolCapability> {
    return Promise.resolve({
      available: true,
      reason: "plain HTTP GET against the cloud provider's own public endpoint; no local binary or credential required",
      version: undefined,
    });
  }

  async run(input: CloudBucketDiscoveryInput): Promise<ToolRunResult> {
    const providers = input.providers ?? ALL_PROVIDERS;
    const candidates = generateBucketNameCandidates(input.seedWords);
    const checks = providers.flatMap((provider) => candidates.map((candidate) => ({ provider, candidate })));
    try {
      const results = await mapWithConcurrencyLimit(checks, CHECK_CONCURRENCY, ({ provider, candidate }) =>
        checkBucket(provider, candidate),
      );
      const discoveredAt = new Date().toISOString();
      const discoveries: RawDiscovery[] = results
        .filter((result) => result.exists)
        .map((result) => ({
          source: 'cloud-bucket-discovery',
          kind: 'resource',
          label: result.url,
          attributes: {
            provider: result.provider,
            bucketName: result.bucketName,
            publiclyListable: result.publiclyListable,
            statusCode: result.statusCode,
          },
          confidence: result.publiclyListable ? 0.9 : 0.5,
          discoveredAt,
        }));
      const publicCount = discoveries.filter((d) => d.attributes.publiclyListable === true).length;
      const checkedCount = checks.length;
      return {
        ok: true,
        summary: `cloud-bucket-discovery checked ${checkedCount} candidate(s) across ${providers.length} provider(s): ${discoveries.length} exist, ${publicCount} publicly listable`,
        discoveries,
        observations: [],
        raw: { checkedCount },
      };
    } catch (error) {
      return {
        ok: false,
        summary: `cloud-bucket-discovery failed: ${(error as Error).message}`,
        discoveries: [],
        observations: [],
        raw: undefined,
      };
    }
  }
}
