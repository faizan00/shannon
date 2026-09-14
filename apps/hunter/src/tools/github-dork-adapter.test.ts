import assert from 'node:assert/strict';
import { test } from 'node:test';
import { GitHubDorkAdapter } from './github-dork-adapter.js';

test('capability() reports unavailable when the configured token env var is unset', async () => {
  const adapter = new GitHubDorkAdapter('DEFINITELY_UNSET_GITHUB_TOKEN_VAR');
  const capability = await adapter.capability();
  assert.equal(capability.available, false);
  assert.match(capability.reason, /not configured/);
});

test('run() refuses (does not silently no-op as success) without the token configured', async () => {
  const adapter = new GitHubDorkAdapter('DEFINITELY_UNSET_GITHUB_TOKEN_VAR');
  const result = await adapter.run({ domain: 'acmecorp.com' });
  assert.equal(result.ok, false);
  assert.match(result.summary, /skipped/);
});

test('run() reports the classification metadata a policy layer needs before ever calling it', () => {
  const adapter = new GitHubDorkAdapter();
  assert.equal(adapter.kind, 'passive-recon');
  assert.equal(adapter.scopeRequirement, 'passive-only');
});
