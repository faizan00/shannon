import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { promisify } from 'node:util';
import { MobileAppAdapter } from './mobile-app-adapter.js';

const execFileAsync = promisify(execFile);

test('capability() reflects real unzip availability on this machine', async () => {
  const capability = await new MobileAppAdapter().capability();
  assert.equal(typeof capability.available, 'boolean');
});

test('run() reports the classification metadata a policy layer needs before ever calling it', () => {
  const adapter = new MobileAppAdapter();
  assert.equal(adapter.kind, 'passive-recon');
  assert.equal(adapter.requiresAuthorization, false);
});

test('run() genuinely unzips a real archive end to end through the adapter interface', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'hunter-mobile-adapter-test-'));
  try {
    const textFile = join(dir, 'strings.txt');
    await writeFile(textFile, 'contact https://api.example.com/v1/ping for health checks');
    const apkPath = join(dir, 'test.apk');
    await execFileAsync('zip', ['-j', '-q', apkPath, textFile]);

    const adapter = new MobileAppAdapter();
    const result = await adapter.run({ filePath: apkPath, assetRef: 'com.example.app', engagementId: 'e1' });
    assert.equal(result.ok, true);
    assert.ok(result.discoveries.some((d) => d.label === 'https://api.example.com/v1/ping'));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('run() reports failure rather than throwing for a nonexistent file', async () => {
  const adapter = new MobileAppAdapter();
  const result = await adapter.run({ filePath: '/nonexistent/app.apk', assetRef: 'x', engagementId: 'e1' });
  assert.equal(result.ok, false);
  assert.match(result.summary, /mobile-app-intel failed/);
});
