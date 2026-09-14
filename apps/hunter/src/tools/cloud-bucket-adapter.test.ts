import assert from 'node:assert/strict';
import { test } from 'node:test';
import { CloudBucketAdapter } from './cloud-bucket-adapter.js';

test('capability() is always available -- plain HTTP, no local binary or credential', async () => {
  const capability = await new CloudBucketAdapter().capability();
  assert.equal(capability.available, true);
});

test('run() reports the classification metadata a policy layer needs before ever calling it', () => {
  const adapter = new CloudBucketAdapter();
  assert.equal(adapter.kind, 'active-recon');
  assert.equal(adapter.scopeRequirement, 'active-in-scope');
  assert.equal(adapter.requiresAuthorization, true);
});

test('run() genuinely checks real candidates against real cloud provider endpoints and returns a coherent summary', async () => {
  const adapter = new CloudBucketAdapter();
  const result = await adapter.run({
    seedWords: [`hunter-adapter-test-${Date.now()}`],
    providers: ['s3'],
  });
  assert.equal(result.ok, true);
  assert.match(result.summary, /checked \d+ candidate\(s\) across 1 provider\(s\)/);
  // An almost-certainly-unique seed word should not resolve to any real, existing bucket.
  assert.equal(result.discoveries.length, 0);
});
