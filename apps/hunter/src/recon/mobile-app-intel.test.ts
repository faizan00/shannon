import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { promisify } from 'node:util';
import { analyzeMobileApp, extractPrintableStrings } from './mobile-app-intel.js';

const execFileAsync = promisify(execFile);

async function withTempDir<T>(fn: (dir: string) => Promise<T>): Promise<T> {
  const dir = await mkdtemp(join(tmpdir(), 'hunter-mobile-test-'));
  try {
    return await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

test('extractPrintableStrings pulls readable text out of a buffer with binary noise around it', () => {
  const buffer = Buffer.concat([
    Buffer.from([0x00, 0x01, 0x02]),
    Buffer.from('https://api.internal.acmecorp.com/v1/users', 'ascii'),
    Buffer.from([0x00, 0xff, 0x03]),
    Buffer.from('sixchr', 'ascii'), // exactly at the default min length (6)
    Buffer.from([0x00]),
    Buffer.from('ab', 'ascii'), // below the default min length -- must be dropped
  ]);
  const strings = extractPrintableStrings(buffer);
  assert.ok(strings.includes('https://api.internal.acmecorp.com/v1/users'));
  assert.ok(strings.includes('sixchr'));
  assert.ok(!strings.includes('ab'));
});

test('extractPrintableStrings respects a custom minLength', () => {
  const buffer = Buffer.from('ab\x00cdef', 'ascii');
  assert.deepEqual(extractPrintableStrings(buffer, 2), ['ab', 'cdef']);
  assert.deepEqual(extractPrintableStrings(buffer, 3), ['cdef']);
});

// === End-to-end proof: a real .apk-shaped ZIP file, genuinely unzipped by
// the real `unzip` binary, yields a real hidden endpoint and a real
// (fingerprinted, never fully retained) secret pattern match ===

test('analyzeMobileApp genuinely unzips a real archive and extracts an endpoint and a secret from a binary-shaped file inside it', async () => {
  await withTempDir(async (dir) => {
    // A "classes.dex"-shaped binary blob: real binary noise around embedded, readable strings -- exactly the shape a real compiled Android bytecode file has.
    const fakeDex = Buffer.concat([
      Buffer.from([0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00]), // real dex magic bytes ("dex\n035\0")
      Buffer.from([0x00, 0x01, 0x02, 0x03, 0x04]),
      Buffer.from('https://api.internal-staging.acmecorp.com/v2/admin/export', 'ascii'),
      Buffer.from([0x00, 0xff, 0xfe]),
      Buffer.from('AKIAABCDEFGHIJKLMNOP', 'ascii'), // AWS-access-key-shaped string
      Buffer.from([0x00, 0x01]),
    ]);
    const appDir = join(dir, 'app-contents');
    await mkdir(appDir, { recursive: true });
    await writeFile(join(appDir, 'classes.dex'), fakeDex);

    const apkPath = join(dir, 'test-app.apk');
    await execFileAsync('zip', ['-j', '-q', apkPath, join(appDir, 'classes.dex')]);

    const result = await analyzeMobileApp(apkPath, 'com.acmecorp.app', 'e1');

    assert.equal(result.filesAnalyzed, 1);
    assert.ok(result.stringsExtracted > 0);

    const endpointLabels = result.discoveries.filter((d) => d.kind === 'endpoint').map((d) => d.label);
    assert.ok(
      endpointLabels.includes('https://api.internal-staging.acmecorp.com/v2/admin/export'),
      `expected the hidden mobile-only endpoint among: ${JSON.stringify(endpointLabels)}`,
    );

    assert.ok(result.observations.some((o) => o.vulnClass === 'mobile-secret-exposure'));
    const secretObservation = result.observations.find((o) => o.vulnClass === 'mobile-secret-exposure');
    // The full secret value must never be retained -- only a truncated fingerprint, same discipline as js-intel.ts.
    assert.ok(!secretObservation?.description.includes('AKIAABCDEFGHIJKLMNOP'));
    assert.match(secretObservation?.description ?? '', /redacted/);
  });
});

test('analyzeMobileApp reports zero discoveries for an archive with no interesting strings, without throwing', async () => {
  await withTempDir(async (dir) => {
    const plainFile = join(dir, 'readme.txt');
    await writeFile(plainFile, 'just some ordinary text with nothing interesting in it');
    const apkPath = join(dir, 'boring.apk');
    await execFileAsync('zip', ['-j', '-q', apkPath, plainFile]);

    const result = await analyzeMobileApp(apkPath, 'com.example.boring', 'e1');
    assert.equal(result.discoveries.length, 0);
    assert.equal(result.observations.length, 0);
  });
});
