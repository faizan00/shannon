import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import {
  advancePhase,
  engagementFilePath,
  loadEngagement,
  newEngagement,
  quarantineCorruptedEngagementState,
  saveEngagement,
  withFindings,
  withObservations,
} from './engagement-store.js';

async function withTempWorkspace<T>(fn: (dir: string) => Promise<T>): Promise<T> {
  const dir = await mkdtemp(join(tmpdir(), 'hunter-engagement-test-'));
  try {
    return await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

test('newEngagement starts at the first pipeline phase', () => {
  const engagement = newEngagement({ id: 'e1', programId: 'p1', targets: [] });
  assert.equal(engagement.phase, 'scope-validation');
  assert.deepEqual(engagement.findingIds, []);
});

test('save then load round-trips an engagement', async () => {
  await withTempWorkspace(async (dir) => {
    const engagement = newEngagement({ id: 'e1', programId: 'p1', targets: [] });
    await saveEngagement(dir, engagement);
    const loaded = await loadEngagement(dir, 'e1');
    assert.equal(loaded.ok, true);
    if (loaded.ok) {
      assert.equal(loaded.value.id, 'e1');
      assert.equal(loaded.value.phase, 'scope-validation');
    }
  });
});

test('loadEngagement reports "not-found", not "corrupted", when the file does not exist', async () => {
  await withTempWorkspace(async (dir) => {
    const loaded = await loadEngagement(dir, 'missing');
    assert.equal(loaded.ok, false);
    if (!loaded.ok) assert.equal(loaded.error.kind, 'not-found');
  });
});

test('loadEngagement reports "corrupted", not "not-found", for a file that exists but fails to parse', async () => {
  await withTempWorkspace(async (dir) => {
    const filePath = engagementFilePath(dir, 'e1');
    await mkdir(dirname(filePath), { recursive: true });
    await writeFile(filePath, '{not valid json', 'utf8');
    const loaded = await loadEngagement(dir, 'e1');
    assert.equal(loaded.ok, false);
    if (!loaded.ok) assert.equal(loaded.error.kind, 'corrupted');
  });
});

test('quarantineCorruptedEngagementState moves the corrupted file aside — never deletes it — and leaves nothing loadable at the original path', async () => {
  await withTempWorkspace(async (dir) => {
    const filePath = engagementFilePath(dir, 'e1');
    await mkdir(dirname(filePath), { recursive: true });
    await writeFile(filePath, '{not valid json', 'utf8');

    const result = await quarantineCorruptedEngagementState(dir, 'e1');
    assert.equal(result.ok, true);
    if (!result.ok) return;
    assert.ok(result.value?.includes('.corrupted-'));

    const quarantinedContent = await readFile(result.value as string, 'utf8');
    assert.equal(quarantinedContent, '{not valid json');

    const reloaded = await loadEngagement(dir, 'e1');
    assert.equal(reloaded.ok, false);
    if (!reloaded.ok) assert.equal(reloaded.error.kind, 'not-found');
  });
});

test('advancePhase moves forward through the fixed order', () => {
  const engagement = newEngagement({ id: 'e1', programId: 'p1', targets: [] });
  const advanced = advancePhase(engagement, 'recon');
  assert.equal(advanced.ok, true);
  if (advanced.ok) {
    assert.equal(advanced.value.phase, 'recon');
  }
});

test('advancePhase refuses to move backward', () => {
  const engagement = { ...newEngagement({ id: 'e1', programId: 'p1', targets: [] }), phase: 'observations' as const };
  const result = advancePhase(engagement, 'scope-validation');
  assert.equal(result.ok, false);
});

test('withObservations and withFindings de-duplicate ids', () => {
  let engagement = newEngagement({ id: 'e1', programId: 'p1', targets: [] });
  engagement = withObservations(engagement, ['obs-1', 'obs-2']);
  engagement = withObservations(engagement, ['obs-2', 'obs-3']);
  assert.deepEqual(engagement.observationIds, ['obs-1', 'obs-2', 'obs-3']);

  engagement = withFindings(engagement, ['f-1']);
  engagement = withFindings(engagement, ['f-1']);
  assert.deepEqual(engagement.findingIds, ['f-1']);
});
