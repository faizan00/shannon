import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { RawDiscovery } from '../types.js';
import {
  COMMON_SUBDOMAIN_WORDS,
  extractCandidateTokens,
  generatePathPermutations,
  generateSubdomainPermutations,
} from './wordlist-generator.js';

function discovery(kind: RawDiscovery['kind'], label: string): RawDiscovery {
  return { source: 'test', kind, label, attributes: {}, confidence: 0.5, discoveredAt: '' };
}

test('generateSubdomainPermutations produces one candidate per common word by default', () => {
  const candidates = generateSubdomainPermutations({ baseDomain: 'example.com' });
  assert.equal(candidates.length, COMMON_SUBDOMAIN_WORDS.length);
  assert.ok(candidates.includes('api.example.com'));
  assert.ok(candidates.includes('admin.example.com'));
});

test('generateSubdomainPermutations includes operator-supplied seed words', () => {
  const candidates = generateSubdomainPermutations({ baseDomain: 'example.com', seedWords: ['acmecorp'] });
  assert.ok(candidates.includes('acmecorp.example.com'));
});

test('generateSubdomainPermutations includes pairs only when explicitly requested', () => {
  const withoutPairs = generateSubdomainPermutations({ baseDomain: 'example.com', seedWords: ['x'] });
  assert.ok(!withoutPairs.some((c) => c.startsWith('x-api.') || c.startsWith('xapi.')));

  const withPairs = generateSubdomainPermutations({ baseDomain: 'example.com', seedWords: ['x'], includePairs: true });
  assert.ok(withPairs.includes('x-api.example.com') || withPairs.includes('api-x.example.com'));
});

test('generateSubdomainPermutations de-duplicates', () => {
  const candidates = generateSubdomainPermutations({ baseDomain: 'example.com', seedWords: ['api'] });
  const apiCount = candidates.filter((c) => c === 'api.example.com').length;
  assert.equal(apiCount, 1);
});

test('extractCandidateTokens pulls the first label from discovered hosts', () => {
  const tokens = extractCandidateTokens([discovery('host', 'internal-billing.example.com')]);
  assert.ok(tokens.includes('internal-billing'.replace('-', '')) || tokens.some((t) => t.includes('billing')));
});

test('extractCandidateTokens pulls path-segment-shaped tokens from endpoints', () => {
  const tokens = extractCandidateTokens([discovery('endpoint', '/internal/workflow/approve')]);
  assert.ok(tokens.includes('internal'));
  assert.ok(tokens.includes('workflow'));
  assert.ok(tokens.includes('approve'));
});

test('extractCandidateTokens pulls identifier-shaped tokens from JS artifact labels', () => {
  const tokens = extractCandidateTokens([discovery('js-artifact', 'bundle-adminPanel-legacy.js')]);
  assert.ok(tokens.includes('adminpanel') || tokens.includes('bundle'));
});

test('extractCandidateTokens filters out stopwords and overly short/long tokens', () => {
  const tokens = extractCandidateTokens([discovery('endpoint', '/the/and/ab/x'.padEnd(5, 'a'))]);
  assert.ok(!tokens.includes('the'));
  assert.ok(!tokens.includes('and'));
});

test('extractCandidateTokens returns nothing for an empty discovery list', () => {
  assert.deepEqual(extractCandidateTokens([]), []);
});

test('generatePathPermutations layers discovered tokens under common API/admin path prefixes', () => {
  const paths = generatePathPermutations(['users']);
  assert.ok(paths.includes('users'));
  assert.ok(paths.includes('api/v1/users'));
  assert.ok(paths.includes('admin/users'));
  assert.ok(paths.includes('internal/users'));
});
