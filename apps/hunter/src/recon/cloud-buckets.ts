/**
 * Cloud storage bucket discovery (S3, GCS, Azure Blob).
 *
 * A real, common finding class: an org's own naming conventions (product
 * name, environment tier, "backup"/"assets"/"private") predict its bucket
 * names well enough that permuting them and checking each one — a plain
 * `GET`/`HEAD` against the provider's own public listing endpoint, exactly
 * how these services are designed to be queried, never an exploit or an
 * authentication bypass of any kind — regularly finds a bucket that is
 * both real and, more importantly, misconfigured to allow public listing.
 * `checkBucket` only ever reports what the provider's own HTTP response
 * already says (a 404 for "no such bucket," a 200 with a listing body for
 * "public," a 403 for "exists, but private"); it never attempts to read,
 * list, or download bucket contents beyond the one response body needed to
 * tell those apart.
 */

export type CloudProvider = 's3' | 'gcs' | 'azure';

export interface BucketCheckResult {
  readonly provider: CloudProvider;
  readonly bucketName: string;
  readonly url: string;
  /** false only for a definitive "no such bucket" (e.g. S3/GCS 404) -- a network error is reported separately via `checkedSuccessfully`, never folded into "does not exist". */
  readonly exists: boolean;
  readonly publiclyListable: boolean;
  readonly statusCode: number;
  readonly checkedSuccessfully: boolean;
}

function bucketUrl(provider: CloudProvider, bucketName: string): string {
  switch (provider) {
    case 's3':
      return `https://${bucketName}.s3.amazonaws.com/`;
    case 'gcs':
      return `https://storage.googleapis.com/${bucketName}/`;
    case 'azure':
      return `https://${bucketName}.blob.core.windows.net/?comp=list`;
  }
}

const LISTING_MARKERS = /<ListBucketResult|<EnumerationResults|<Contents>|"items"\s*:\s*\[/;

export async function checkBucket(
  provider: CloudProvider,
  bucketName: string,
  fetchImpl: typeof fetch = fetch,
  timeoutMs = 8000,
): Promise<BucketCheckResult> {
  const url = bucketUrl(provider, bucketName);
  try {
    const response = await fetchImpl(url, { method: 'GET', signal: AbortSignal.timeout(timeoutMs) });
    const bodyText = await response.text();
    return {
      provider,
      bucketName,
      url,
      exists: response.status !== 404,
      publiclyListable: response.status === 200 && LISTING_MARKERS.test(bodyText),
      statusCode: response.status,
      checkedSuccessfully: true,
    };
  } catch {
    return {
      provider,
      bucketName,
      url,
      exists: false,
      publiclyListable: false,
      statusCode: 0,
      checkedSuccessfully: false,
    };
  }
}

const BUCKET_SUFFIXES: readonly string[] = [
  '',
  '-backup',
  '-backups',
  '-dev',
  '-staging',
  '-prod',
  '-production',
  '-assets',
  '-static',
  '-uploads',
  '-upload',
  '-data',
  '-logs',
  '-private',
  '-public',
  '-media',
  '-files',
  '-cdn',
  '-www',
  '-old',
  '-archive',
  '-test',
  '-internal',
  '-storage',
];

/** Generates bucket-name candidates from operator/discovery-supplied vocabulary layered under common suffixes -- reuses the same "seed with real target vocabulary" principle as `wordlist-generator.ts`. */
export function generateBucketNameCandidates(seedWords: readonly string[]): string[] {
  const candidates = new Set<string>();
  for (const word of seedWords) {
    const base = word.toLowerCase().replace(/[^a-z0-9-]/g, '');
    if (base.length === 0) continue;
    for (const suffix of BUCKET_SUFFIXES) {
      const candidate = `${base}${suffix}`;
      if (candidate.length >= 3 && candidate.length <= 63) candidates.add(candidate);
    }
  }
  return [...candidates];
}
