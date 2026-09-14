import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { SingleProgramDiscoveryProvider } from './single-program-provider.js';

const EXAMPLE_FIXTURE = fileURLToPath(
  new URL('../../fixtures/discovery/single-engagement-example.json', import.meta.url),
);

test('reads the bundled single-engagement example and returns exactly one program', async () => {
  const provider = new SingleProgramDiscoveryProvider(EXAMPLE_FIXTURE);
  const result = await provider.discoverPrograms();
  assert.ok(result.ok);
  assert.equal(result.value.length, 1);
  assert.equal(result.value[0]?.programId, 'operator-supplied-example');
  assert.equal(result.value[0]?.sourceProvider, 'single-program');
  assert.ok(result.value[0]?.signals.assetSurfaceBreadth);
});

test('rejects a record missing required safety-relevant fields (assets)', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'hunter-single-program-'));
  try {
    const filePath = join(dir, 'bad.json');
    await writeFile(
      filePath,
      JSON.stringify({
        programId: 'x',
        programName: 'X',
        platform: 'hackerone',
        offersBounty: false,
        assets: [],
        rulesOfEngagement: [],
        disallowedTechniques: [],
      }),
    );
    const result = await new SingleProgramDiscoveryProvider(filePath).discoverPrograms();
    assert.equal(result.ok, false);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('rejects malformed JSON rather than throwing', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'hunter-single-program-'));
  try {
    const filePath = join(dir, 'broken.json');
    await writeFile(filePath, '{not json');
    const result = await new SingleProgramDiscoveryProvider(filePath).discoverPrograms();
    assert.equal(result.ok, false);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('rejects a missing file rather than throwing', async () => {
  const result = await new SingleProgramDiscoveryProvider('/nonexistent/engagement.json').discoverPrograms();
  assert.equal(result.ok, false);
});

test('accepts a record with no signals object at all, defaulting to {}', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'hunter-single-program-'));
  try {
    const filePath = join(dir, 'no-signals.json');
    await writeFile(
      filePath,
      JSON.stringify({
        programId: 'no-signals',
        programName: 'No Signals',
        platform: 'hackerone',
        offersBounty: false,
        assets: [{ identifier: '*.nosignals.test', type: 'wildcard-domain', instruction: 'in-scope' }],
        rulesOfEngagement: [],
        disallowedTechniques: [],
      }),
    );
    const result = await new SingleProgramDiscoveryProvider(filePath).discoverPrograms();
    assert.ok(result.ok);
    assert.deepEqual(result.value[0]?.signals, {});
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
