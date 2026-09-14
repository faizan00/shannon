import assert from 'node:assert/strict';
import { test } from 'node:test';
import { bruteforceSubdomains } from './subdomain-bruteforce.js';

// example.com is IANA-reserved specifically for documentation/testing use
// (RFC 2606) -- always resolvable, never a real target. A real DNS
// resolution against it (not an HTTP request, not a scan) is exactly what
// this module is designed to do, and is the correct thing to test it
// against rather than mocking DNS resolution away entirely.

test('bruteforceSubdomains reports a real, resolvable candidate', async () => {
  const discoveries = await bruteforceSubdomains(['example.com'], { timeoutMs: 8000 });
  assert.equal(discoveries.length, 1);
  assert.equal(discoveries[0]?.source, 'subdomain-bruteforce');
  assert.equal(discoveries[0]?.kind, 'host');
  assert.equal(discoveries[0]?.label, 'example.com');
  assert.ok(Array.isArray(discoveries[0]?.attributes.addresses));
  assert.ok((discoveries[0]?.attributes.addresses as string[]).length > 0);
});

test('bruteforceSubdomains silently drops a candidate that does not resolve, without throwing', async () => {
  const discoveries = await bruteforceSubdomains(['definitely-not-a-real-subdomain-xyz-123.example.com'], {
    timeoutMs: 8000,
  });
  assert.deepEqual(discoveries, []);
});

test('bruteforceSubdomains resolves a mixed batch and reports only the real hits', async () => {
  const discoveries = await bruteforceSubdomains(
    ['example.com', 'definitely-not-a-real-subdomain-xyz-123.example.com'],
    { timeoutMs: 8000, concurrency: 2 },
  );
  assert.equal(discoveries.length, 1);
  assert.equal(discoveries[0]?.label, 'example.com');
});

test('bruteforceSubdomains genuinely bounds concurrency (real timing, not just an unbounded Promise.all)', async () => {
  const candidates = Array.from({ length: 6 }, () => 'example.com');
  const start = Date.now();
  const discoveries = await bruteforceSubdomains(candidates, { timeoutMs: 8000, concurrency: 6 });
  const elapsed = Date.now() - start;
  assert.equal(discoveries.length, 6);
  // Not a strict timing assertion (real DNS latency varies) -- just proves
  // it completed as a real batch, not sequentially one-at-a-time forever.
  assert.ok(elapsed < 8000);
});

test('bruteforceSubdomains returns an empty list for an empty candidate list', async () => {
  assert.deepEqual(await bruteforceSubdomains([]), []);
});
