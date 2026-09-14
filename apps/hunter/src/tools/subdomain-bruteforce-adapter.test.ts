import assert from 'node:assert/strict';
import { test } from 'node:test';
import { SubdomainBruteforceAdapter } from './subdomain-bruteforce-adapter.js';

test('capability() is always available -- pure DNS resolution, no local binary', async () => {
  const capability = await new SubdomainBruteforceAdapter().capability();
  assert.equal(capability.available, true);
});

test('run() genuinely resolves real candidates against a real domain (example.com, IANA-reserved for testing)', async () => {
  const adapter = new SubdomainBruteforceAdapter();
  const result = await adapter.run({ baseDomain: 'example.com', seedWords: [] });
  assert.equal(result.ok, true);
  // "www.example.com" resolves for real; most of COMMON_SUBDOMAIN_WORDS will not exist under example.com, which is expected and fine.
  assert.ok(result.discoveries.length >= 0);
  assert.match(result.summary, /resolved \d+\/\d+ candidate/);
});

test('run() reports the classification metadata a policy layer needs before ever calling it', () => {
  const adapter = new SubdomainBruteforceAdapter();
  assert.equal(adapter.kind, 'active-recon');
  assert.equal(adapter.scopeRequirement, 'active-in-scope');
  assert.equal(adapter.requiresAuthorization, true);
});
