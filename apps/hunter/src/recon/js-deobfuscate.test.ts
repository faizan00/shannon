import assert from 'node:assert/strict';
import { test } from 'node:test';
import { resolveStringArrayObfuscation } from './js-deobfuscate.js';
import { analyzeJavaScript } from './js-intel.js';

test('resolveStringArrayObfuscation inlines direct array-index references back to literal strings', () => {
  const obfuscated = `
    var _0x1a2b = ['/api/internal/debug', '/api/v1/search'];
    fetch(_0x1a2b[0]);
    fetch(_0x1a2b[1]);
  `;
  const result = resolveStringArrayObfuscation(obfuscated);
  assert.equal(result.resolvedArrayCount, 1);
  assert.equal(result.resolvedReferenceCount, 2);
  assert.match(result.code, /fetch\("\/api\/internal\/debug"\)/);
  assert.match(result.code, /fetch\("\/api\/v1\/search"\)/);
});

test('resolveStringArrayObfuscation inlines references made through a one-level decoder function', () => {
  const obfuscated = `
    var _0xdead = ['/internal/admin/users', 'ignored'];
    function _0xbeef(_0xn) { return _0xdead[_0xn]; }
    axios.get(_0xbeef(0));
  `;
  const result = resolveStringArrayObfuscation(obfuscated);
  assert.equal(result.resolvedReferenceCount, 1);
  assert.match(result.code, /axios\.get\("\/internal\/admin\/users"\)/);
});

test('resolveStringArrayObfuscation is a safe no-op on ordinary, unobfuscated code', () => {
  const plain = `fetch('/api/v1/search'); const x = 1 + 2;`;
  const result = resolveStringArrayObfuscation(plain);
  assert.equal(result.resolvedArrayCount, 0);
  assert.equal(result.resolvedReferenceCount, 0);
  assert.equal(result.code, plain);
});

test('resolveStringArrayObfuscation leaves a non-literal (computed) index alone rather than guessing', () => {
  const obfuscated = `
    var _0xarr = ['/api/a', '/api/b'];
    function pick(i) { return i + 1; }
    fetch(_0xarr[pick(0)]);
  `;
  const result = resolveStringArrayObfuscation(obfuscated);
  // pick(0) is not a literal numeric index -- must be left untouched, not misresolved.
  assert.match(result.code, /_0xarr\[pick\(0\)\]/);
});

test('resolveStringArrayObfuscation decodes hex-escaped string-array contents (the shape that actually evades a literal-text scan)', () => {
  // '/internal/admin/debug-console' hex-escaped char by char -- what a real
  // obfuscator emits specifically so the readable path never appears in
  // the source text.
  const hexEscaped = '/internal/admin/debug-console'
    .split('')
    .map((c) => `\\x${c.charCodeAt(0).toString(16).padStart(2, '0')}`)
    .join('');
  const obfuscated = `
    var _0x9f3a = ['${hexEscaped}'];
    fetch(_0x9f3a[0]).then(r => r.json());
  `;
  assert.ok(
    !obfuscated.includes('/internal/admin/debug-console'),
    'the readable path must not appear anywhere in the raw source',
  );

  const { code } = resolveStringArrayObfuscation(obfuscated);
  assert.match(code, /fetch\("\/internal\/admin\/debug-console"\)/);
});

// === End-to-end proof: deobfuscation genuinely changes what js-intel.ts
// can find, not just what this module's own regex matches ===

test('a hex-escaped, string-array-obfuscated endpoint is invisible to analyzeJavaScript directly, but found after deobfuscation', () => {
  const hexEscaped = '/internal/admin/debug-console'
    .split('')
    .map((c) => `\\x${c.charCodeAt(0).toString(16).padStart(2, '0')}`)
    .join('');
  const obfuscated = `
    var _0x9f3a = ['${hexEscaped}'];
    fetch(_0x9f3a[0]).then(r => r.json());
  `;

  const directResult = analyzeJavaScript(obfuscated, 'bundle.js', 'https://app.example.com/', 'e1');
  assert.ok(
    !directResult.discoveries.some((d) => d.kind === 'endpoint' && d.label.includes('debug-console')),
    'analyzeJavaScript must NOT find the hex-escaped endpoint directly -- it genuinely does not appear as readable text',
  );

  const { code: deobfuscated } = resolveStringArrayObfuscation(obfuscated);
  const deobfuscatedResult = analyzeJavaScript(deobfuscated, 'bundle.js', 'https://app.example.com/', 'e1');
  assert.ok(
    deobfuscatedResult.discoveries.some((d) => d.kind === 'endpoint' && d.label.includes('debug-console')),
    'analyzeJavaScript must find the endpoint once the hex-escaped string-array obfuscation is resolved',
  );
});
