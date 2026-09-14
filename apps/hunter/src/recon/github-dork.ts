/**
 * GitHub code-search "dorking" for the target's own leaked secrets.
 *
 * A real, common finding source: an org's own employee commits a real
 * credential to a public (or since-deleted-but-cached) repository,
 * referencing the target's own domain — searching GitHub's own documented
 * code-search API for the target's domain string and checking hits against
 * `js-intel.ts`'s own `SECRET_PATTERNS` (one detection ruleset, reused, not
 * duplicated) is a standard, accepted bug-bounty recon technique because it
 * only ever surfaces what the target's *own* people already published
 * publicly — never anyone else's code, and never anything requiring
 * bypassing access controls.
 *
 * Built against GitHub's public, documented REST API
 * (`GET /search/code`, https://docs.github.com/en/rest/search/search#search-code)
 * — a stable, public contract, not a guessed or private one. Requires a
 * real `GITHUB_TOKEN` (unauthenticated code search is effectively
 * unusable — heavily rate-limited and often blocked outright), following
 * exactly the same "capability() reports the missing credential, real
 * network call only when configured" discipline as
 * `recon/cli-adapters.ts:ChaosAdapter`/`PDCP_API_KEY`.
 *
 * HONEST STATUS: this module has never been exercised against the real
 * GitHub API in this codebase's own test suite — no `GITHUB_TOKEN` was
 * available in the session that wrote it. Its request construction and
 * response parsing are verified with an injected `fetchImpl` only,
 * exactly the same "unit-tested, not live-tested" status
 * `claude-provider.ts` was in before its own live integration harness
 * existed — do not read a passing unit-test run as equivalent to a real,
 * live search having ever happened.
 */

import { fingerprint, SECRET_PATTERNS } from './js-intel.js';

export interface GitHubDorkOptions {
  readonly token: string;
  readonly fetchImpl?: typeof fetch;
  readonly timeoutMs?: number;
  readonly perPage?: number;
}

export interface GitHubDorkMatch {
  readonly repository: string;
  readonly filePath: string;
  readonly htmlUrl: string;
  /** Names only (e.g. "aws-access-key") -- never the matched value itself. */
  readonly matchedSecretPatterns: readonly string[];
  /** A truncated, non-reversible fingerprint of the matched text fragment -- same discipline as `js-intel.ts`'s own `fingerprint()`. */
  readonly snippetFingerprint: string;
}

interface GitHubCodeSearchItem {
  readonly path?: string;
  readonly html_url?: string;
  readonly repository?: { readonly full_name?: string };
  readonly text_matches?: readonly { readonly fragment?: string }[];
}

interface GitHubCodeSearchResponse {
  readonly items?: readonly GitHubCodeSearchItem[];
}

/**
 * Searches GitHub code for `domain` (quoted, exact-phrase search) and
 * reports only hits whose matched text fragment also matches one of
 * `js-intel.ts`'s `SECRET_PATTERNS` — a plain domain mention with no
 * secret-shaped content nearby is not reported at all, keeping this a
 * leaked-secret finder, not a generic "who mentions us" search.
 */
export async function searchGitHubForLeakedSecrets(
  domain: string,
  options: GitHubDorkOptions,
): Promise<readonly GitHubDorkMatch[]> {
  const fetchImpl = options.fetchImpl ?? fetch;
  const query = encodeURIComponent(`"${domain}"`);
  const perPage = options.perPage ?? 30;
  const response = await fetchImpl(`https://api.github.com/search/code?q=${query}&per_page=${perPage}`, {
    headers: {
      Authorization: `Bearer ${options.token}`,
      Accept: 'application/vnd.github.text-match+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': 'shannon-hunter',
    },
    signal: AbortSignal.timeout(options.timeoutMs ?? 15_000),
  });
  if (!response.ok) {
    const bodyText = await response.text();
    throw new Error(`GitHub code search responded ${response.status}: ${bodyText.slice(0, 500)}`);
  }
  const body = (await response.json()) as GitHubCodeSearchResponse;
  const matches: GitHubDorkMatch[] = [];
  for (const item of body.items ?? []) {
    const fragment = (item.text_matches ?? []).map((t) => t.fragment ?? '').join('\n');
    if (fragment.length === 0) continue;
    // A fresh RegExp per test, not `pattern.test(fragment)` directly:
    // SECRET_PATTERNS carries the global flag (for `matchAll` elsewhere),
    // and a global regex's `.test()` is stateful across calls (it mutates
    // `lastIndex`) -- reusing the shared instance here would make results
    // depend on call order, a real, subtle bug this avoids entirely.
    const matchedPatterns = SECRET_PATTERNS.filter(({ pattern }) =>
      new RegExp(pattern.source, pattern.flags).test(fragment),
    ).map(({ name }) => name);
    if (matchedPatterns.length === 0) continue;
    matches.push({
      repository: item.repository?.full_name ?? 'unknown',
      filePath: item.path ?? 'unknown',
      htmlUrl: item.html_url ?? '',
      matchedSecretPatterns: matchedPatterns,
      snippetFingerprint: fingerprint(fragment),
    });
  }
  return matches;
}
