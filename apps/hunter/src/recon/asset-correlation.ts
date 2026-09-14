/**
 * Cross-asset correlation via Shodan — scoped to the authorized target's
 * own footprint, never internet-wide scanning.
 *
 * "Cross-program asset correlation at scale" done responsibly means: given
 * something already known and specific to *this* target (its own org name
 * in WHOIS/ASN registration, a TLS certificate subject/fingerprint already
 * observed on one of its confirmed hosts), query an already-existing
 * internet-wide scan index — Shodan — for other hosts sharing that same
 * signal. This never scans anything itself; it queries a third-party
 * service that already scanned the public internet under its own
 * authorization, filtered to a signal the target's own infrastructure
 * already produced. Running your own mass internet scan would be a wholly
 * different, unauthorized action this package will not perform.
 *
 * Built against Shodan's public, documented REST API
 * (`GET /shodan/host/search`, https://developer.shodan.io/api) — a stable,
 * public contract. Requires a real `SHODAN_API_KEY`, following the same
 * "capability() reports the missing credential" discipline as
 * `recon/cli-adapters.ts:ChaosAdapter`/`recon/github-dork.ts`.
 *
 * HONEST STATUS: never exercised against the real Shodan API in this
 * codebase's own test suite — no `SHODAN_API_KEY` was available. Unit-
 * tested against an injected `fetchImpl` only; do not read a passing unit
 * test as equivalent to a real, live query having ever happened.
 */

export interface ShodanCorrelationOptions {
  readonly apiKey: string;
  readonly fetchImpl?: typeof fetch;
  readonly timeoutMs?: number;
}

export interface CorrelatedAsset {
  readonly ip: string;
  readonly port: number;
  readonly hostnames: readonly string[];
  readonly org: string | undefined;
  /** The query facet that matched -- "org" or "ssl.cert.subject.cn", so a caller/report can show *why* this asset was correlated, never just "found." */
  readonly matchedOn: string;
}

interface ShodanMatch {
  readonly ip_str?: string;
  readonly port?: number;
  readonly hostnames?: readonly string[];
  readonly org?: string;
}

interface ShodanSearchResponse {
  readonly matches?: readonly ShodanMatch[];
}

async function runShodanQuery(
  query: string,
  matchedOn: string,
  options: ShodanCorrelationOptions,
): Promise<readonly CorrelatedAsset[]> {
  const fetchImpl = options.fetchImpl ?? fetch;
  const url = `https://api.shodan.io/shodan/host/search?key=${encodeURIComponent(options.apiKey)}&query=${encodeURIComponent(query)}`;
  const response = await fetchImpl(url, { signal: AbortSignal.timeout(options.timeoutMs ?? 15_000) });
  if (!response.ok) {
    const bodyText = await response.text();
    throw new Error(`Shodan search responded ${response.status}: ${bodyText.slice(0, 500)}`);
  }
  const body = (await response.json()) as ShodanSearchResponse;
  return (body.matches ?? [])
    .filter((match) => match.ip_str !== undefined && match.port !== undefined)
    .map((match) => ({
      ip: match.ip_str as string,
      port: match.port as number,
      hostnames: match.hostnames ?? [],
      org: match.org,
      matchedOn,
    }));
}

/** Finds other hosts Shodan already indexed under the same organization name as the target's own known registration. */
export function findAssetsByOrg(
  orgName: string,
  options: ShodanCorrelationOptions,
): Promise<readonly CorrelatedAsset[]> {
  return runShodanQuery(`org:"${orgName}"`, 'org', options);
}

/** Finds other hosts serving a TLS certificate with the same subject common name as one already confirmed on the target -- a real, common signal for shared/reused infrastructure the target may not realize is discoverable this way. */
export function findAssetsByCertificateCommonName(
  commonName: string,
  options: ShodanCorrelationOptions,
): Promise<readonly CorrelatedAsset[]> {
  return runShodanQuery(`ssl.cert.subject.cn:"${commonName}"`, 'ssl.cert.subject.cn', options);
}
