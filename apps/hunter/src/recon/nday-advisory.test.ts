import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { hypothesesFromObservations } from '../reasoning/hypothesis.js';
import type { DependencyFingerprint } from './dependency-fingerprint.js';
import { extractDependencyFingerprints } from './dependency-fingerprint.js';
import {
  advisoryMatchToObservation,
  appendCacheEntry,
  correlateAdvisories,
  fetchVulnDetails,
  loadCacheEntries,
  queryOsvBatch,
} from './nday-advisory.js';

async function withTempWorkspace<T>(fn: (dir: string) => Promise<T>): Promise<T> {
  const dir = await mkdtemp(join(tmpdir(), 'hunter-nday-test-'));
  try {
    return await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

function fingerprint(overrides: Partial<DependencyFingerprint> = {}): DependencyFingerprint {
  return {
    name: 'jquery',
    ecosystem: 'npm',
    version: '1.4.2',
    assetRef: 'https://app.example.com/vendor.js',
    discoveredVia: 'jquery-dev-banner',
    confidence: 'high',
    ...overrides,
  };
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}

test('queryOsvBatch returns ok([]) without calling fetch when there is nothing to query', async () => {
  let called = false;
  const result = await queryOsvBatch([], {
    fetchImpl: (async () => {
      called = true;
      return jsonResponse({});
    }) as typeof fetch,
  });
  assert.ok(result.ok);
  assert.deepEqual(result.value, []);
  assert.equal(called, false);
});

test('queryOsvBatch sends one query per fingerprint and maps vuln IDs back positionally', async () => {
  let capturedBody: unknown;
  const fetchImpl = (async (_url, init) => {
    capturedBody = JSON.parse(String(init?.body));
    return jsonResponse({ results: [{ vulns: [{ id: 'GHSA-aaaa' }] }, { vulns: [] }] });
  }) as typeof fetch;

  const result = await queryOsvBatch(
    [fingerprint({ version: '1.4.2' }), fingerprint({ name: 'bootstrap', version: '5.0.0' })],
    { fetchImpl },
  );
  assert.ok(result.ok);
  assert.deepEqual(
    { queries: (capturedBody as { queries: unknown[] }).queries },
    {
      queries: [
        { package: { name: 'jquery', ecosystem: 'npm' }, version: '1.4.2' },
        { package: { name: 'bootstrap', ecosystem: 'npm' }, version: '5.0.0' },
      ],
    },
  );
  assert.deepEqual(result.value[0]?.vulnIds, ['GHSA-aaaa']);
  assert.deepEqual(result.value[1]?.vulnIds, []);
});

test('queryOsvBatch reports a Result err, never throws, on a non-2xx response', async () => {
  const result = await queryOsvBatch([fingerprint()], {
    fetchImpl: (async () => new Response('nope', { status: 500 })) as typeof fetch,
  });
  assert.equal(result.ok, false);
});

test('queryOsvBatch reports a Result err, never throws, on a network failure', async () => {
  const result = await queryOsvBatch([fingerprint()], {
    fetchImpl: (async () => {
      throw new Error('ECONNRESET');
    }) as typeof fetch,
  });
  assert.equal(result.ok, false);
});

test('fetchVulnDetails reports a Result err on a non-2xx response', async () => {
  const result = await fetchVulnDetails('GHSA-aaaa', {
    fetchImpl: (async () => new Response('nope', { status: 404 })) as typeof fetch,
  });
  assert.equal(result.ok, false);
});

function fakeOsvFetch(vulnDetail: unknown, vulnId = 'GHSA-aaaa') {
  let calls = 0;
  const fetchImpl = (async (url) => {
    calls += 1;
    const urlString = String(url);
    if (urlString.includes('querybatch')) {
      return jsonResponse({ results: [{ vulns: [{ id: vulnId }] }] });
    }
    return jsonResponse(vulnDetail);
  }) as typeof fetch;
  return { fetchImpl, callCount: () => calls };
}

test('correlateAdvisories marks a version inside the vulnerable window as likely unpatched, with the FIX reference surfaced', async () => {
  await withTempWorkspace(async (dir) => {
    const { fetchImpl } = fakeOsvFetch({
      id: 'GHSA-aaaa',
      summary: 'XSS in jQuery',
      affected: [
        {
          package: { name: 'jquery', ecosystem: 'npm' },
          ranges: [{ events: [{ introduced: '0' }, { fixed: '1.9.0' }] }],
        },
      ],
      references: [{ type: 'FIX', url: 'https://github.com/jquery/jquery/commit/abc123' }],
    });

    const result = await correlateAdvisories([fingerprint({ version: '1.4.2' })], dir, { fetchImpl });
    assert.ok(result.ok);
    assert.equal(result.value.length, 1);
    const match = result.value[0];
    assert.equal(match?.isLikelyUnpatched, true);
    assert.equal(match?.fixedVersion, '1.9.0');
    assert.equal(match?.patchReferenceUrl, 'https://github.com/jquery/jquery/commit/abc123');
  });
});

test('correlateAdvisories marks a version already at or above the fix as not unpatched', async () => {
  await withTempWorkspace(async (dir) => {
    const { fetchImpl } = fakeOsvFetch({
      id: 'GHSA-aaaa',
      summary: 'XSS in jQuery',
      affected: [
        {
          package: { name: 'jquery', ecosystem: 'npm' },
          ranges: [{ events: [{ introduced: '0' }, { fixed: '1.9.0' }] }],
        },
      ],
    });

    const result = await correlateAdvisories([fingerprint({ version: '3.5.1' })], dir, { fetchImpl });
    assert.ok(result.ok);
    assert.equal(result.value[0]?.isLikelyUnpatched, false);
  });
});

test('correlateAdvisories never guesses when the fix boundary is a commit hash, not a version', async () => {
  await withTempWorkspace(async (dir) => {
    const { fetchImpl } = fakeOsvFetch({
      id: 'GHSA-bbbb',
      summary: 'Some Git-range advisory',
      affected: [
        {
          package: { name: 'jquery', ecosystem: 'npm' },
          ranges: [{ events: [{ introduced: '0' }, { fixed: 'e4badf4d745b8e8f9a0a25b6c3cc97fbadbbb499' }] }],
        },
      ],
    });

    const result = await correlateAdvisories([fingerprint()], dir, { fetchImpl });
    assert.ok(result.ok);
    assert.equal(result.value[0]?.isLikelyUnpatched, undefined);
    assert.equal(result.value[0]?.fixedVersion, 'e4badf4d745b8e8f9a0a25b6c3cc97fbadbbb499');
  });
});

test('correlateAdvisories reports a Result err, never throws, when the batch request itself fails', async () => {
  await withTempWorkspace(async (dir) => {
    const result = await correlateAdvisories([fingerprint()], dir, {
      fetchImpl: (async () => {
        throw new Error('network down');
      }) as typeof fetch,
    });
    assert.equal(result.ok, false);
  });
});

test('correlateAdvisories caches a fresh result and does not re-query OSV on a second call', async () => {
  await withTempWorkspace(async (dir) => {
    const { fetchImpl, callCount } = fakeOsvFetch({
      id: 'GHSA-aaaa',
      summary: 'XSS in jQuery',
      affected: [
        {
          package: { name: 'jquery', ecosystem: 'npm' },
          ranges: [{ events: [{ introduced: '0' }, { fixed: '1.9.0' }] }],
        },
      ],
    });

    const first = await correlateAdvisories([fingerprint()], dir, { fetchImpl });
    assert.ok(first.ok);
    const callsAfterFirst = callCount();
    assert.ok(callsAfterFirst > 0);

    const second = await correlateAdvisories([fingerprint()], dir, { fetchImpl });
    assert.ok(second.ok);
    // Compared through a JSON round-trip on both sides: a cache-reloaded match
    // has gone through JSON once already, which drops `undefined`-valued keys
    // entirely -- that's a real, harmless property of the on-disk cache, not
    // a correctness difference this test should care about.
    assert.deepEqual(JSON.parse(JSON.stringify(second.value)), JSON.parse(JSON.stringify(first.value)));
    assert.equal(callCount(), callsAfterFirst, 'second call must be served entirely from cache');
  });
});

test('correlateAdvisories re-queries a stale cache entry rather than trusting it forever', async () => {
  await withTempWorkspace(async (dir) => {
    await appendCacheEntry(dir, {
      key: 'npm:jquery:1.4.2',
      matches: [],
      checkedAt: new Date(Date.now() - 25 * 60 * 60 * 1000).toISOString(),
    });

    const { fetchImpl, callCount } = fakeOsvFetch({
      id: 'GHSA-aaaa',
      summary: 'XSS in jQuery',
      affected: [
        {
          package: { name: 'jquery', ecosystem: 'npm' },
          ranges: [{ events: [{ introduced: '0' }, { fixed: '1.9.0' }] }],
        },
      ],
    });

    const result = await correlateAdvisories([fingerprint()], dir, { fetchImpl });
    assert.ok(result.ok);
    assert.ok(callCount() > 0, 'a stale cache entry must be re-queried, not reused');
    assert.equal(result.value.length, 1);
  });
});

test('correlateAdvisories keeps separate cache entries for different dependencies (no cross-key poisoning)', async () => {
  await withTempWorkspace(async (dir) => {
    const fetchImpl = (async (url, init) => {
      const urlString = String(url);
      if (urlString.includes('querybatch')) {
        const body = JSON.parse(String(init?.body)) as { queries: { package: { name: string } }[] };
        return jsonResponse({
          results: body.queries.map((q) => ({ vulns: q.package.name === 'jquery' ? [{ id: 'GHSA-jquery' }] : [] })),
        });
      }
      return jsonResponse({ id: 'GHSA-jquery', summary: 'jquery advisory', affected: [] });
    }) as typeof fetch;

    const result = await correlateAdvisories(
      [fingerprint({ name: 'jquery' }), fingerprint({ name: 'bootstrap', version: '5.0.0' })],
      dir,
      { fetchImpl },
    );
    assert.ok(result.ok);
    assert.equal(result.value.length, 1);
    assert.equal(result.value[0]?.dependency.name, 'jquery');

    const cache = await loadCacheEntries(dir);
    assert.ok(cache.ok);
    const keys = cache.value.map((entry) => entry.key).sort();
    assert.deepEqual(keys, ['npm:bootstrap:5.0.0', 'npm:jquery:1.4.2']);
  });
});

// === Shapes below are grounded in two real, live api.osv.dev calls made
// during development (GHSA-2pqj-h3vj-pqgw for jquery@1.4.2) -- not just the
// published docs, which don't mention either quirk covered here. ===

test("correlateAdvisories reads severity from database_specific.severity and normalizes GHSA vocabulary to this codebase's own", async () => {
  await withTempWorkspace(async (dir) => {
    const { fetchImpl } = fakeOsvFetch({
      id: 'GHSA-2pqj-h3vj-pqgw',
      summary: 'Cross-Site Scripting in jquery',
      database_specific: { severity: 'MODERATE' },
      affected: [
        {
          package: { name: 'jquery', ecosystem: 'npm' },
          ranges: [{ events: [{ introduced: '0' }, { fixed: '1.9.0' }] }],
        },
      ],
    });

    const result = await correlateAdvisories([fingerprint()], dir, { fetchImpl });
    assert.ok(result.ok);
    assert.equal(result.value[0]?.severity, 'medium');
  });
});

test('correlateAdvisories accepts a commit-shaped WEB reference as the patch link when no reference is tagged FIX', async () => {
  await withTempWorkspace(async (dir) => {
    const { fetchImpl } = fakeOsvFetch({
      id: 'GHSA-2pqj-h3vj-pqgw',
      summary: 'Cross-Site Scripting in jquery',
      affected: [
        {
          package: { name: 'jquery', ecosystem: 'npm' },
          ranges: [{ events: [{ introduced: '0' }, { fixed: '1.9.0' }] }],
        },
      ],
      references: [
        { type: 'ADVISORY', url: 'https://nvd.nist.gov/vuln/detail/CVE-2012-6708' },
        { type: 'WEB', url: 'https://github.com/jquery/jquery/commit/05531fc4080ae24070930d15ae0cea7ae056457d' },
        { type: 'WEB', url: 'https://snyk.io/vuln/npm:jquery:20120206' },
      ],
    });

    const result = await correlateAdvisories([fingerprint()], dir, { fetchImpl });
    assert.ok(result.ok);
    assert.equal(
      result.value[0]?.patchReferenceUrl,
      'https://github.com/jquery/jquery/commit/05531fc4080ae24070930d15ae0cea7ae056457d',
    );
  });
});

test('correlateAdvisories never mistakes an unrelated WEB link for the patch commit', async () => {
  await withTempWorkspace(async (dir) => {
    const { fetchImpl } = fakeOsvFetch({
      id: 'GHSA-2pqj-h3vj-pqgw',
      summary: 'Cross-Site Scripting in jquery',
      affected: [
        {
          package: { name: 'jquery', ecosystem: 'npm' },
          ranges: [{ events: [{ introduced: '0' }, { fixed: '1.9.0' }] }],
        },
      ],
      references: [{ type: 'WEB', url: 'https://snyk.io/vuln/npm:jquery:20120206' }],
    });

    const result = await correlateAdvisories([fingerprint()], dir, { fetchImpl });
    assert.ok(result.ok);
    assert.equal(result.value[0]?.patchReferenceUrl, undefined);
  });
});

test('advisoryMatchToObservation is a low-confidence lead unless the fix boundary was confidently confirmed', () => {
  const match = {
    dependency: fingerprint(),
    advisoryId: 'GHSA-aaaa',
    summary: 'XSS in jQuery',
    severity: undefined,
    fixedVersion: '1.9.0',
    patchReferenceUrl: undefined,
    isLikelyUnpatched: undefined,
  };
  const observation = advisoryMatchToObservation(match, 'engagement-1');
  assert.equal(observation.vulnClass, 'known-vulnerable-dependency');
  assert.equal(observation.source, 'dependency-intelligence');
  assert.equal(observation.confidenceHint, 'low');
  assert.equal(observation.verified, false);

  const confirmed = advisoryMatchToObservation({ ...match, isLikelyUnpatched: true }, 'engagement-1');
  assert.equal(confirmed.confidenceHint, 'high');
});

// === End-to-end proof: a real bundle's version banner survives the whole
// chain -- fingerprint -> OSV correlation -> Observation -> Hypothesis --
// exactly the path pipeline/adaptive-loop.ts wires it into ===

test('a fingerprinted, genuinely outdated jQuery bundle produces a known-vulnerable-dependency hypothesis', async () => {
  await withTempWorkspace(async (dir) => {
    const bundle = `/*! jQuery JavaScript Library v1.4.2 | (c) 2010 John Resig */\nvar x = 1;`;
    const fingerprints = extractDependencyFingerprints(bundle, 'https://app.example.com/vendor.js');
    assert.equal(fingerprints.length, 1);

    const { fetchImpl } = fakeOsvFetch({
      id: 'CVE-2011-4969',
      summary: 'Cross-site scripting in jQuery before 1.6.3',
      affected: [
        {
          package: { name: 'jquery', ecosystem: 'npm' },
          ranges: [{ events: [{ introduced: '0' }, { fixed: '1.6.3' }] }],
        },
      ],
      references: [{ type: 'FIX', url: 'https://github.com/jquery/jquery/commit/deadbeef' }],
    });

    const correlated = await correlateAdvisories(fingerprints, dir, { fetchImpl });
    assert.ok(correlated.ok);
    assert.equal(correlated.value[0]?.isLikelyUnpatched, true);

    const observations = correlated.value.map((match) => advisoryMatchToObservation(match, 'engagement-1'));
    const hypotheses = hypothesesFromObservations(observations, 'engagement-1');
    assert.equal(hypotheses.length, 1);
    assert.equal(hypotheses[0]?.vulnClass, 'known-vulnerable-dependency');
    assert.equal(hypotheses[0]?.assetRef, 'https://app.example.com/vendor.js');
    assert.match(hypotheses[0]?.nextInvestigation ?? '', /confirm the version fingerprint directly/);
    assert.deepEqual(
      [...(hypotheses[0]?.requiredEvidence ?? [])],
      [
        'a confirmed version fingerprint from the live target, not just the bundle/banner match',
        'the advisory ID and its fixed-version boundary',
        'demonstrated triggering of the specific vulnerable behavior -- a version match alone is never sufficient',
      ],
    );
  });
});
