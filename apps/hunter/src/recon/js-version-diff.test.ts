import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import {
  appendSnapshot,
  diffAndRecordBundle,
  diffBundleSnapshots,
  extractStringLiterals,
  latestSnapshotFor,
  loadSnapshots,
  snapshotBundle,
} from './js-version-diff.js';

async function withTempWorkspace<T>(fn: (dir: string) => Promise<T>): Promise<T> {
  const dir = await mkdtemp(join(tmpdir(), 'hunter-js-diff-test-'));
  try {
    return await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

test('extractStringLiterals pulls every distinct quoted string, deduplicated', () => {
  const literals = extractStringLiterals(`fetch('/a'); fetch('/a'); fetch("/b"); const x = \`/c\`;`);
  assert.deepEqual([...literals].sort(), ['/a', '/b', '/c']);
});

test('snapshotBundle produces a stable content hash for identical content', () => {
  const a = snapshotBundle('bundle.js', 'https://app.example.com/', 'const x = 1;');
  const b = snapshotBundle('bundle.js', 'https://app.example.com/', 'const x = 1;');
  assert.equal(a.contentHash, b.contentHash);
});

test('snapshotBundle produces a different hash for different content', () => {
  const a = snapshotBundle('bundle.js', 'https://app.example.com/', 'const x = 1;');
  const b = snapshotBundle('bundle.js', 'https://app.example.com/', 'const x = 2;');
  assert.notEqual(a.contentHash, b.contentHash);
});

test('diffBundleSnapshots reports everything as new when there is no prior snapshot', () => {
  const current = snapshotBundle('bundle.js', 'https://app.example.com/', `fetch('/api/a');`);
  const diff = diffBundleSnapshots(undefined, current);
  assert.equal(diff.changed, true);
  assert.deepEqual(diff.newStringLiterals, ['/api/a']);
  assert.equal(diff.removedStringLiterals, undefined);
});

test('diffBundleSnapshots reports unchanged when the content hash is identical', () => {
  const previous = snapshotBundle('bundle.js', 'https://app.example.com/', `fetch('/api/a');`);
  const current = snapshotBundle('bundle.js', 'https://app.example.com/', `fetch('/api/a');`);
  const diff = diffBundleSnapshots(previous, current);
  assert.equal(diff.changed, false);
  assert.equal(diff.newStringLiterals, undefined);
});

test('diffBundleSnapshots surfaces genuinely new and removed string literals between two real versions', () => {
  const previous = snapshotBundle('bundle.js', 'https://app.example.com/', `fetch('/api/a'); fetch('/api/old');`);
  const current = snapshotBundle(
    'bundle.js',
    'https://app.example.com/',
    `fetch('/api/a'); fetch('/api/new-feature');`,
  );
  const diff = diffBundleSnapshots(previous, current);
  assert.equal(diff.changed, true);
  assert.deepEqual(diff.newStringLiterals, ['/api/new-feature']);
  assert.deepEqual(diff.removedStringLiterals, ['/api/old']);
});

test('loadSnapshots returns an empty list, not an error, when nothing was ever recorded', async () => {
  await withTempWorkspace(async (dir) => {
    const result = await loadSnapshots(dir);
    assert.ok(result.ok);
    assert.deepEqual(result.value, []);
  });
});

test('appendSnapshot then loadSnapshots round-trips, append-only across multiple calls', async () => {
  await withTempWorkspace(async (dir) => {
    await appendSnapshot(dir, snapshotBundle('bundle.js', 'https://app.example.com/', 'v1'));
    await appendSnapshot(dir, snapshotBundle('bundle.js', 'https://app.example.com/', 'v2'));
    const result = await loadSnapshots(dir);
    assert.ok(result.ok);
    assert.equal(result.value.length, 2);
  });
});

test('latestSnapshotFor picks the most recently captured snapshot for a given sourceRef', async () => {
  const older = { ...snapshotBundle('bundle.js', 'x', 'v1'), capturedAt: '2026-01-01T00:00:00.000Z' };
  const newer = { ...snapshotBundle('bundle.js', 'x', 'v2'), capturedAt: '2026-06-01T00:00:00.000Z' };
  const other = { ...snapshotBundle('other.js', 'x', 'v3'), capturedAt: '2026-12-01T00:00:00.000Z' };
  const latest = latestSnapshotFor([older, newer, other], 'bundle.js');
  assert.equal(latest?.capturedAt, '2026-06-01T00:00:00.000Z');
});

test('latestSnapshotFor returns undefined when the sourceRef was never snapshotted', () => {
  assert.equal(latestSnapshotFor([], 'bundle.js'), undefined);
});

// === End-to-end proof: a real, second "hunt" against the same workspace
// genuinely detects a real JS change from the first one, across separate
// calls, exactly the way two separate hunt runs weeks apart would ===

test('diffAndRecordBundle detects a real bundle change across two separate calls simulating two separate hunts', async () => {
  await withTempWorkspace(async (dir) => {
    const first = await diffAndRecordBundle(dir, 'bundle.js', 'https://app.example.com/', `fetch('/api/v1/search');`);
    assert.ok(first.ok);
    assert.equal(first.value.changed, true, 'first-ever snapshot is always reported as a change');

    // Same content, second call -- simulates a re-run finding nothing new.
    const unchanged = await diffAndRecordBundle(
      dir,
      'bundle.js',
      'https://app.example.com/',
      `fetch('/api/v1/search');`,
    );
    assert.ok(unchanged.ok);
    assert.equal(unchanged.value.changed, false);

    // A genuinely new endpoint shipped -- simulates a hunt weeks later against an updated app.
    const changed = await diffAndRecordBundle(
      dir,
      'bundle.js',
      'https://app.example.com/',
      `fetch('/api/v1/search'); fetch('/api/v2/internal/export');`,
    );
    assert.ok(changed.ok);
    assert.equal(changed.value.changed, true);
    assert.deepEqual(changed.value.newStringLiterals, ['/api/v2/internal/export']);

    const history = await loadSnapshots(dir);
    assert.ok(history.ok);
    assert.equal(history.value.length, 3, 'every diffAndRecordBundle call appends, never overwrites, history');
  });
});
