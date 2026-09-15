/**
 * Client-library version fingerprinting from already-collected JS content.
 *
 * The first half of N-day/variant hunting: before a version can be checked
 * against known advisories (`nday-advisory.ts`), it has to be identified in
 * the first place. Rather than fetching anything new, this regexes the raw
 * JS bundle text `js-intel.ts`/`js-version-diff.ts` already receive, for the
 * distinctive version-banner strings a handful of widely-used front-end
 * libraries reliably ship (their own copyright/license header or an
 * explicit `.version =`-style assignment) — the same kind of signature
 * matching `retire.js`/Wappalyzer rely on, just a small, honestly-scoped
 * table rather than an exhaustive one.
 *
 * Deliberately narrow for now: five libraries with a clean, well-known
 * banner pattern that maps to a real, well-covered OSV npm-ecosystem
 * package name. Lodash was considered and dropped — its shipped banner
 * does not reliably embed a bare, unambiguous version string across
 * builds, and a wrong guess here would be worse than no guess. HTTP-header-
 * based fingerprinting (Server/X-Powered-By) is a natural extension once a
 * header-collection step is wired into the adaptive loop's input — nothing
 * upstream currently supplies headers to this phase, so it is not attempted
 * here rather than added unwired and untested.
 */

export interface DependencyFingerprint {
  readonly name: string;
  readonly ecosystem: string;
  readonly version: string;
  readonly assetRef: string;
  /** Which signature matched -- kept for provenance/audit, e.g. "jquery-dev-banner". */
  readonly discoveredVia: string;
  readonly confidence: 'high' | 'low';
}

interface SignaturePattern {
  readonly id: string;
  readonly name: string;
  readonly ecosystem: string;
  readonly pattern: RegExp;
  readonly confidence: 'high' | 'low';
}

const SIGNATURE_PATTERNS: readonly SignaturePattern[] = [
  {
    id: 'jquery-dev-banner',
    name: 'jquery',
    ecosystem: 'npm',
    pattern: /jQuery JavaScript Library v(\d+\.\d+\.\d+)/i,
    confidence: 'high',
  },
  {
    id: 'jquery-version-assignment',
    name: 'jquery',
    ecosystem: 'npm',
    pattern: /\.jquery\s*=\s*["'](\d+\.\d+\.\d+)["']/,
    confidence: 'high',
  },
  {
    id: 'bootstrap-banner',
    name: 'bootstrap',
    ecosystem: 'npm',
    pattern: /Bootstrap v(\d+\.\d+\.\d+)/i,
    confidence: 'high',
  },
  {
    id: 'momentjs-banner',
    name: 'moment',
    ecosystem: 'npm',
    pattern: /moment\.js[\s\S]{0,80}?version\s*:\s*(\d+\.\d+\.\d+)/i,
    confidence: 'high',
  },
  {
    id: 'handlebars-banner',
    name: 'handlebars',
    ecosystem: 'npm',
    pattern: /handlebars v(\d+\.\d+\.\d+)/i,
    confidence: 'high',
  },
  {
    id: 'angularjs-banner',
    name: 'angular',
    ecosystem: 'npm',
    pattern: /AngularJS v(\d+\.\d+\.\d+)/i,
    confidence: 'high',
  },
];

/**
 * Matches every known signature against `content` once each, deduplicating
 * by (name, version) so a library referenced by more than one signature (or
 * appearing more than once in the same bundle) is reported a single time
 * per asset.
 */
export function extractDependencyFingerprints(content: string, assetRef: string): readonly DependencyFingerprint[] {
  const seen = new Set<string>();
  const fingerprints: DependencyFingerprint[] = [];
  for (const signature of SIGNATURE_PATTERNS) {
    const match = signature.pattern.exec(content);
    const version = match?.[1];
    if (!version) continue;
    const dedupeKey = `${signature.name}@${version}`;
    if (seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);
    fingerprints.push({
      name: signature.name,
      ecosystem: signature.ecosystem,
      version,
      assetRef,
      discoveredVia: signature.id,
      confidence: signature.confidence,
    });
  }
  return fingerprints;
}
