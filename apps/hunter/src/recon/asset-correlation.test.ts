import assert from 'node:assert/strict';
import { test } from 'node:test';
import { findAssetsByCertificateCommonName, findAssetsByOrg } from './asset-correlation.js';

function fakeShodanResponse(matches: unknown[]): Response {
  return new Response(JSON.stringify({ matches }), { status: 200, headers: { 'content-type': 'application/json' } });
}

test('findAssetsByOrg sends the documented request shape (org query, API key)', async () => {
  let capturedUrl: string | undefined;
  const fetchImpl = (async (url: string | URL) => {
    capturedUrl = url.toString();
    return fakeShodanResponse([]);
  }) as typeof fetch;

  await findAssetsByOrg('Acme Corp', { apiKey: 'fake-key', fetchImpl });

  assert.ok(capturedUrl?.includes('shodan/host/search'));
  assert.ok(capturedUrl?.includes('key=fake-key'));
  assert.ok(capturedUrl?.includes(encodeURIComponent('org:"Acme Corp"')));
});

test('findAssetsByOrg parses real-shaped Shodan match records and tags them with matchedOn', async () => {
  const fetchImpl = (async () =>
    fakeShodanResponse([
      { ip_str: '203.0.113.5', port: 443, hostnames: ['forgotten.acmecorp.com'], org: 'Acme Corp' },
    ])) as typeof fetch;

  const assets = await findAssetsByOrg('Acme Corp', { apiKey: 'fake-key', fetchImpl });
  assert.equal(assets.length, 1);
  assert.equal(assets[0]?.ip, '203.0.113.5');
  assert.equal(assets[0]?.port, 443);
  assert.deepEqual(assets[0]?.hostnames, ['forgotten.acmecorp.com']);
  assert.equal(assets[0]?.matchedOn, 'org');
});

test('findAssetsByCertificateCommonName uses the ssl.cert.subject.cn query facet and tags results accordingly', async () => {
  let capturedUrl: string | undefined;
  const fetchImpl = (async (url: string | URL) => {
    capturedUrl = url.toString();
    return fakeShodanResponse([{ ip_str: '198.51.100.9', port: 8443, hostnames: [], org: undefined }]);
  }) as typeof fetch;

  const assets = await findAssetsByCertificateCommonName('*.acmecorp.com', { apiKey: 'fake-key', fetchImpl });
  assert.ok(capturedUrl?.includes(encodeURIComponent('ssl.cert.subject.cn:"*.acmecorp.com"')));
  assert.equal(assets[0]?.matchedOn, 'ssl.cert.subject.cn');
});

test('filters out a malformed match record missing ip_str/port rather than fabricating one', async () => {
  const fetchImpl = (async () => fakeShodanResponse([{ org: 'Acme Corp' }])) as typeof fetch;
  const assets = await findAssetsByOrg('Acme Corp', { apiKey: 'fake-key', fetchImpl });
  assert.deepEqual(assets, []);
});

test('throws on a non-2xx response rather than fabricating results', async () => {
  const fetchImpl = (async () => new Response('invalid key', { status: 401 })) as typeof fetch;
  await assert.rejects(() => findAssetsByOrg('Acme Corp', { apiKey: 'bad-key', fetchImpl }), /401/);
});

test('returns an empty list when Shodan reports no matches at all', async () => {
  const fetchImpl = (async () => fakeShodanResponse([])) as typeof fetch;
  assert.deepEqual(await findAssetsByOrg('Acme Corp', { apiKey: 'fake-key', fetchImpl }), []);
});
