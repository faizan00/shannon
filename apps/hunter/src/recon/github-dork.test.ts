import assert from 'node:assert/strict';
import { test } from 'node:test';
import { searchGitHubForLeakedSecrets } from './github-dork.js';

function fakeSearchResponse(items: unknown[]): Response {
  return new Response(JSON.stringify({ items }), { status: 200, headers: { 'content-type': 'application/json' } });
}

test('searchGitHubForLeakedSecrets sends the documented request shape (query, auth header, API version)', async () => {
  let capturedUrl: string | undefined;
  let capturedHeaders: RequestInit['headers'];
  const fetchImpl = (async (url: string | URL, init?: RequestInit) => {
    capturedUrl = url.toString();
    capturedHeaders = init?.headers;
    return fakeSearchResponse([]);
  }) as typeof fetch;

  await searchGitHubForLeakedSecrets('acmecorp.com', { token: 'fake-token', fetchImpl });

  assert.ok(capturedUrl?.includes('search/code'));
  assert.ok(capturedUrl?.includes(encodeURIComponent('"acmecorp.com"')));
  const headers = capturedHeaders as Record<string, string>;
  assert.equal(headers.Authorization, 'Bearer fake-token');
  assert.equal(headers['X-GitHub-Api-Version'], '2022-11-28');
});

test('searchGitHubForLeakedSecrets only reports items whose matched fragment contains a real secret pattern', async () => {
  const fetchImpl = (async () =>
    fakeSearchResponse([
      {
        path: 'config/settings.py',
        html_url: 'https://github.com/acme/repo/blob/main/config/settings.py',
        repository: { full_name: 'acme/repo' },
        text_matches: [{ fragment: 'AWS_KEY = "AKIAABCDEFGHIJKLMNOP"' }],
      },
      {
        path: 'README.md',
        html_url: 'https://github.com/acme/repo/blob/main/README.md',
        repository: { full_name: 'acme/repo' },
        text_matches: [{ fragment: 'Visit acmecorp.com for more info' }],
      },
    ])) as typeof fetch;

  const matches = await searchGitHubForLeakedSecrets('acmecorp.com', { token: 'fake-token', fetchImpl });
  assert.equal(matches.length, 1);
  assert.equal(matches[0]?.filePath, 'config/settings.py');
  assert.deepEqual(matches[0]?.matchedSecretPatterns, ['aws-access-key']);
});

test('searchGitHubForLeakedSecrets never retains the full matched secret value -- only a fingerprint', async () => {
  const fetchImpl = (async () =>
    fakeSearchResponse([
      {
        path: 'x.py',
        html_url: 'https://github.com/acme/repo/blob/main/x.py',
        repository: { full_name: 'acme/repo' },
        text_matches: [{ fragment: 'AKIAABCDEFGHIJKLMNOP' }],
      },
    ])) as typeof fetch;

  const matches = await searchGitHubForLeakedSecrets('acmecorp.com', { token: 'fake-token', fetchImpl });
  assert.ok(!matches[0]?.snippetFingerprint.includes('AKIAABCDEFGHIJKLMNOP'));
  assert.match(matches[0]?.snippetFingerprint ?? '', /redacted/);
});

test('the shared, global-flag SECRET_PATTERNS regex is not mutated across repeated calls (no stateful lastIndex bug)', async () => {
  const item = {
    path: 'x.py',
    html_url: 'https://github.com/acme/repo/blob/main/x.py',
    repository: { full_name: 'acme/repo' },
    text_matches: [{ fragment: 'AKIAABCDEFGHIJKLMNOP' }],
  };
  const fetchImpl = (async () => fakeSearchResponse([item])) as typeof fetch;

  const first = await searchGitHubForLeakedSecrets('acmecorp.com', { token: 'fake', fetchImpl });
  const second = await searchGitHubForLeakedSecrets('acmecorp.com', { token: 'fake', fetchImpl });
  assert.equal(first.length, 1);
  assert.equal(second.length, 1, 'a stateful shared regex would cause the second call to miss the match');
});

test('searchGitHubForLeakedSecrets throws on a non-2xx response rather than fabricating results', async () => {
  const fetchImpl = (async () => new Response('rate limited', { status: 403 })) as typeof fetch;
  await assert.rejects(() => searchGitHubForLeakedSecrets('acmecorp.com', { token: 'fake', fetchImpl }), /403/);
});

test('searchGitHubForLeakedSecrets returns an empty list when there are no results at all', async () => {
  const fetchImpl = (async () => fakeSearchResponse([])) as typeof fetch;
  const matches = await searchGitHubForLeakedSecrets('acmecorp.com', { token: 'fake', fetchImpl });
  assert.deepEqual(matches, []);
});
