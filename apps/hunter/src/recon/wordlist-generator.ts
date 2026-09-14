/**
 * Custom subdomain/content wordlist generation ("amplification").
 *
 * A checklist scanner runs a fixed public wordlist once. A more experienced
 * hunter's real edge here is narrower and self-reinforcing: seed a
 * permutation set with the target's own vocabulary (company/product names,
 * and — critically — tokens already pulled out of what recon has *already*
 * found: hostnames, path segments, JS identifiers), then keep permuting
 * against what comes back. `extractCandidateTokens` closes that loop:
 * every real discovery this package makes becomes raw material for the
 * next round's wordlist, not just an end result.
 *
 * Pure, offline, dependency-free — no network, no binary. What this
 * produces (a candidate list) is only ever a *list*; nothing here resolves
 * or requests anything itself (see `recon/subdomain-bruteforce.ts` for
 * where these candidates actually get looked up, DNS-only and read-only).
 */

import type { RawDiscovery } from '../types.js';

/**
 * Common infrastructure/environment vocabulary real subdomain enumeration
 * wordlists converge on — deliberately not "everything ever seen in a
 * wordlist," which would just be noise; this is a compact, curated set
 * covering the patterns that actually recur across real orgs (environment
 * tiers, common internal tooling, API/auth surface, cloud/ops tooling).
 */
export const COMMON_SUBDOMAIN_WORDS: readonly string[] = [
  'www',
  'api',
  'api-internal',
  'app',
  'app1',
  'app2',
  'admin',
  'dev',
  'dev1',
  'dev2',
  'staging',
  'stage',
  'test',
  'test1',
  'test2',
  'qa',
  'uat',
  'demo',
  'beta',
  'preprod',
  'pre-prod',
  'prod',
  'production',
  'sandbox',
  'local',
  'internal',
  'intranet',
  'vpn',
  'private',
  'secure',
  'mail',
  'smtp',
  'imap',
  'ftp',
  'sftp',
  'ns1',
  'ns2',
  'cdn',
  'static',
  'assets',
  'media',
  'img',
  'images',
  'video',
  'upload',
  'uploads',
  'download',
  'downloads',
  'auth',
  'sso',
  'login',
  'oauth',
  'account',
  'accounts',
  'dashboard',
  'portal',
  'console',
  'manage',
  'admin-panel',
  'monitor',
  'status',
  'health',
  'metrics',
  'grafana',
  'kibana',
  'jenkins',
  'ci',
  'cd',
  'build',
  'git',
  'gitlab',
  'jira',
  'confluence',
  'wiki',
  'docs',
  'api-docs',
  'swagger',
  'graphql',
  'ws',
  'websocket',
  'socket',
  'stream',
  'db',
  'database',
  'redis',
  'cache',
  'search',
  'elastic',
  'es',
  'kafka',
  'queue',
  'mq',
  'v1',
  'v2',
  'v3',
  'old',
  'new',
  'legacy',
  'backup',
  'bak',
  'archive',
  'tmp',
  'temp',
  'partner',
  'partners',
  'vendor',
  'b2b',
  'b2c',
  'mobile',
  'm',
  'payments',
  'payment',
  'billing',
  'checkout',
  'cart',
  'shop',
  'store',
  'support',
  'help',
  'helpdesk',
  'ticket',
  'crm',
  'erp',
  'hr',
  'finance',
  'corp',
  'my',
] as const;

const MIN_TOKEN_LENGTH = 3;
const MAX_TOKEN_LENGTH = 24;
/** Tokens too generic to be worth permuting on their own (would just regenerate COMMON_SUBDOMAIN_WORDS noise). */
const STOPWORDS = new Set([
  'the',
  'and',
  'for',
  'with',
  'from',
  'this',
  'that',
  'com',
  'org',
  'net',
  'http',
  'https',
  'www',
  'html',
  'json',
  'true',
  'false',
  'null',
  'undefined',
  'function',
  'const',
  'var',
  'let',
]);

function isPlausibleToken(token: string): boolean {
  return (
    token.length >= MIN_TOKEN_LENGTH &&
    token.length <= MAX_TOKEN_LENGTH &&
    !STOPWORDS.has(token) &&
    /^[a-z][a-z0-9]*$/.test(token)
  );
}

/**
 * Pulls reusable vocabulary out of what recon has already discovered:
 * the first label of every discovered hostname, path-segment-shaped
 * substrings inside endpoint labels, and short identifier-shaped tokens
 * inside JS-artifact labels/attributes. Deliberately conservative (see
 * `isPlausibleToken`) — this exists to seed the *next* round of
 * permutations, not to dump every substring ever seen.
 */
export function extractCandidateTokens(discoveries: readonly RawDiscovery[]): string[] {
  const tokens = new Set<string>();
  for (const discovery of discoveries) {
    if (discovery.kind === 'host') {
      const firstLabel = discovery.label
        .split('.')[0]
        ?.toLowerCase()
        .replace(/[^a-z0-9]/g, '');
      if (firstLabel && isPlausibleToken(firstLabel)) tokens.add(firstLabel);
    }
    if (discovery.kind === 'endpoint') {
      for (const segment of discovery.label.split(/[/?#]/)) {
        const cleaned = segment.toLowerCase().replace(/[^a-z0-9]/g, '');
        if (isPlausibleToken(cleaned)) tokens.add(cleaned);
      }
    }
    if (discovery.kind === 'js-artifact' || discovery.kind === 'source-location') {
      for (const match of discovery.label.match(/[a-zA-Z][a-zA-Z0-9]{2,23}/g) ?? []) {
        const cleaned = match.toLowerCase();
        if (isPlausibleToken(cleaned)) tokens.add(cleaned);
      }
    }
  }
  return [...tokens];
}

export interface PermutationOptions {
  readonly baseDomain: string;
  /** Operator-supplied vocabulary specific to this target — company name, product names, internal codenames if known. */
  readonly seedWords?: readonly string[];
  /** Tokens pulled from prior discoveries via `extractCandidateTokens` — the "amplification" loop. */
  readonly discoveredTokens?: readonly string[];
  /** Also generate two-word combinations (word-word, wordword) — off by default since it multiplies the list size quadratically. */
  readonly includePairs?: boolean;
}

/**
 * Generates candidate FQDNs for `options.baseDomain` from
 * `COMMON_SUBDOMAIN_WORDS` plus any operator/discovery-supplied vocabulary.
 * Pure list generation — resolving these is `subdomain-bruteforce.ts`'s job.
 */
export function generateSubdomainPermutations(options: PermutationOptions): string[] {
  const words = [
    ...new Set([...COMMON_SUBDOMAIN_WORDS, ...(options.seedWords ?? []), ...(options.discoveredTokens ?? [])]),
  ];
  const candidates = new Set<string>();
  for (const word of words) {
    candidates.add(`${word}.${options.baseDomain}`);
  }
  if (options.includePairs) {
    for (const a of words) {
      for (const b of words) {
        if (a === b) continue;
        candidates.add(`${a}-${b}.${options.baseDomain}`);
        candidates.add(`${a}${b}.${options.baseDomain}`);
      }
    }
  }
  return [...candidates];
}

/**
 * Generates candidate content-discovery paths (for `ffuf`'s wordlist input)
 * from discovered vocabulary, layered under common API/admin path shapes —
 * the same "amplify what's already been found" principle, applied to paths
 * instead of hostnames.
 */
export function generatePathPermutations(discoveredTokens: readonly string[]): string[] {
  const commonPrefixes = ['api/v1', 'api/v2', 'admin', 'internal', '_internal', 'debug', 'test', 'backup'];
  const paths = new Set<string>();
  for (const token of discoveredTokens) {
    paths.add(token);
    for (const prefix of commonPrefixes) {
      paths.add(`${prefix}/${token}`);
    }
  }
  return [...paths];
}
