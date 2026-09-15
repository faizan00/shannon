import assert from 'node:assert/strict';
import { test } from 'node:test';
import { extractDependencyFingerprints } from './dependency-fingerprint.js';

test('extracts jQuery from its dev-banner comment', () => {
  const content = `/*! jQuery JavaScript Library v3.5.1 | (c) JS Foundation and other contributors */\nvar x = 1;`;
  const fingerprints = extractDependencyFingerprints(content, 'https://app.example.com/vendor.js');
  assert.equal(fingerprints.length, 1);
  assert.equal(fingerprints[0]?.name, 'jquery');
  assert.equal(fingerprints[0]?.ecosystem, 'npm');
  assert.equal(fingerprints[0]?.version, '3.5.1');
  assert.equal(fingerprints[0]?.confidence, 'high');
  assert.equal(fingerprints[0]?.assetRef, 'https://app.example.com/vendor.js');
});

test('extracts jQuery from its minified version-property assignment', () => {
  const content = `n.fn.jquery="1.4.2",n.fn=n.prototype={jquery:"1.4.2"};`;
  const fingerprints = extractDependencyFingerprints(content, 'asset');
  assert.equal(fingerprints.length, 1);
  assert.equal(fingerprints[0]?.version, '1.4.2');
});

test('does not double-report the same library when both signatures match the same version', () => {
  const content = `/*! jQuery JavaScript Library v3.5.1 */\n(n.fn.jquery="3.5.1")`;
  const fingerprints = extractDependencyFingerprints(content, 'asset');
  assert.equal(fingerprints.length, 1);
});

test('extracts Bootstrap from its banner comment', () => {
  const content = `/*!\n * Bootstrap v5.3.2 (https://getbootstrap.com/)\n * Copyright 2011-2023\n */`;
  const fingerprints = extractDependencyFingerprints(content, 'asset');
  assert.equal(fingerprints.length, 1);
  assert.equal(fingerprints[0]?.name, 'bootstrap');
  assert.equal(fingerprints[0]?.version, '5.3.2');
});

test('extracts Moment.js from its banner comment', () => {
  const content = `//! moment.js\n//! version : 2.29.4\n//! authors : ...`;
  const fingerprints = extractDependencyFingerprints(content, 'asset');
  assert.equal(fingerprints.length, 1);
  assert.equal(fingerprints[0]?.name, 'moment');
  assert.equal(fingerprints[0]?.version, '2.29.4');
});

test('extracts Handlebars from its banner comment', () => {
  const content = `/*!\n\nhandlebars v4.7.7\n\nCopyright (C) 2011-2019 by Yehuda Katz\n*/`;
  const fingerprints = extractDependencyFingerprints(content, 'asset');
  assert.equal(fingerprints.length, 1);
  assert.equal(fingerprints[0]?.name, 'handlebars');
  assert.equal(fingerprints[0]?.version, '4.7.7');
});

test('extracts AngularJS from its license banner', () => {
  const content = `/**\n * @license AngularJS v1.8.2\n * (c) 2010-2020 Google, Inc.\n */`;
  const fingerprints = extractDependencyFingerprints(content, 'asset');
  assert.equal(fingerprints.length, 1);
  assert.equal(fingerprints[0]?.name, 'angular');
  assert.equal(fingerprints[0]?.version, '1.8.2');
});

test('reports nothing for content with no known signature', () => {
  const fingerprints = extractDependencyFingerprints(`function add(a, b) { return a + b; }`, 'asset');
  assert.deepEqual(fingerprints, []);
});

test('does not false-positive on an unrelated string that merely contains a version-shaped number', () => {
  const fingerprints = extractDependencyFingerprints(`const releaseTag = "3.5.1";`, 'asset');
  assert.deepEqual(fingerprints, []);
});

test('reports multiple distinct libraries found in the same bundle', () => {
  const content = `/*! jQuery JavaScript Library v3.5.1 */\n/*!\n * Bootstrap v5.3.2 (https://getbootstrap.com/)\n */`;
  const fingerprints = extractDependencyFingerprints(content, 'asset');
  assert.deepEqual(fingerprints.map((f) => f.name).sort(), ['bootstrap', 'jquery']);
});
