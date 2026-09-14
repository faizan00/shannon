import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { test } from 'node:test';
import { checkBucket, generateBucketNameCandidates } from './cloud-buckets.js';

// A random UUID-based bucket name is guaranteed not to exist anywhere.
// Checking it against the real S3/GCS/Azure public endpoints is a plain,
// read-only GET to the *provider's own* infrastructure -- not a real
// target, and exactly what these endpoints are designed to answer (the
// same category of "safe against real infrastructure" proof this package
// already uses for DNS: see subdomain-bruteforce.test.ts's example.com).
const definitelyNonexistentBucket = `hunter-test-${randomUUID()}`;

test('checkBucket reports a real, definitely-nonexistent S3 bucket as not existing', async () => {
  const result = await checkBucket('s3', definitelyNonexistentBucket, fetch, 10_000);
  assert.equal(result.checkedSuccessfully, true);
  assert.equal(result.exists, false);
  assert.equal(result.statusCode, 404);
});

test('checkBucket reports a real, definitely-nonexistent GCS bucket as not existing', async () => {
  const result = await checkBucket('gcs', definitelyNonexistentBucket, fetch, 10_000);
  assert.equal(result.checkedSuccessfully, true);
  assert.equal(result.exists, false);
  assert.equal(result.statusCode, 404);
});

test('checkBucket never throws on a network failure -- reports checkedSuccessfully: false instead', async () => {
  const failingFetch: typeof fetch = async () => {
    throw new Error('simulated network failure');
  };
  const result = await checkBucket('s3', 'anything', failingFetch);
  assert.equal(result.checkedSuccessfully, false);
  assert.equal(result.exists, false);
});

test('checkBucket recognizes a publicly listable S3 bucket from a real-shaped ListBucketResult body', async () => {
  const fakeFetch: typeof fetch = async () =>
    new Response(
      '<?xml version="1.0"?><ListBucketResult><Contents><Key>secret.txt</Key></Contents></ListBucketResult>',
      {
        status: 200,
      },
    );
  const result = await checkBucket('s3', 'some-bucket', fakeFetch);
  assert.equal(result.exists, true);
  assert.equal(result.publiclyListable, true);
});

test('checkBucket recognizes an existing-but-private bucket (403, no listing body) as exists without publiclyListable', async () => {
  const fakeFetch: typeof fetch = async () => new Response('AccessDenied', { status: 403 });
  const result = await checkBucket('s3', 'some-private-bucket', fakeFetch);
  assert.equal(result.exists, true);
  assert.equal(result.publiclyListable, false);
});

test('checkBucket recognizes a publicly listable Azure Blob container from a real-shaped EnumerationResults body', async () => {
  const fakeFetch: typeof fetch = async () =>
    new Response(
      '<?xml version="1.0"?><EnumerationResults><Blobs><Blob><Name>x</Name></Blob></Blobs></EnumerationResults>',
      {
        status: 200,
      },
    );
  const result = await checkBucket('azure', 'some-container', fakeFetch);
  assert.equal(result.publiclyListable, true);
});

test('generateBucketNameCandidates layers seed words under common suffixes', () => {
  const candidates = generateBucketNameCandidates(['acmecorp']);
  assert.ok(candidates.includes('acmecorp'));
  assert.ok(candidates.includes('acmecorp-backup'));
  assert.ok(candidates.includes('acmecorp-private'));
  assert.ok(candidates.includes('acmecorp-staging'));
});

test('generateBucketNameCandidates sanitizes and length-bounds candidates', () => {
  const candidates = generateBucketNameCandidates(['Acme Corp!!', 'ab']);
  assert.ok(candidates.every((c) => /^[a-z0-9-]+$/.test(c)));
  assert.ok(candidates.every((c) => c.length >= 3 && c.length <= 63));
});

test('generateBucketNameCandidates returns nothing for an empty seed list', () => {
  assert.deepEqual(generateBucketNameCandidates([]), []);
});
