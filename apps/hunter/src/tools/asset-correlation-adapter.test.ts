import assert from 'node:assert/strict';
import { test } from 'node:test';
import { AssetCorrelationAdapter } from './asset-correlation-adapter.js';

test('capability() reports unavailable when the configured API key env var is unset', async () => {
  const adapter = new AssetCorrelationAdapter('DEFINITELY_UNSET_SHODAN_KEY_VAR');
  const capability = await adapter.capability();
  assert.equal(capability.available, false);
  assert.match(capability.reason, /not configured/);
});

test('run() refuses (does not silently no-op as success) without the API key configured', async () => {
  const adapter = new AssetCorrelationAdapter('DEFINITELY_UNSET_SHODAN_KEY_VAR');
  const result = await adapter.run({ orgName: 'Acme Corp' });
  assert.equal(result.ok, false);
  assert.match(result.summary, /skipped/);
});

test('run() refuses when neither orgName nor certificateCommonName is supplied, even with a key configured', async () => {
  process.env.HUNTER_TEST_SHODAN_KEY = 'fake-key-for-this-test-only';
  try {
    const adapter = new AssetCorrelationAdapter('HUNTER_TEST_SHODAN_KEY');
    const result = await adapter.run({});
    assert.equal(result.ok, false);
    assert.match(result.summary, /requires at least one/);
  } finally {
    delete process.env.HUNTER_TEST_SHODAN_KEY;
  }
});

test('run() reports the classification metadata a policy layer needs before ever calling it', () => {
  const adapter = new AssetCorrelationAdapter();
  assert.equal(adapter.kind, 'passive-recon');
  assert.equal(adapter.scopeRequirement, 'passive-only');
});
