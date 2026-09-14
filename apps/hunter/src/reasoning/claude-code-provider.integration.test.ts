/**
 * Claude Code (OAuth) reasoning provider — live integration harness.
 *
 * `claude-code-provider.test.ts` proves `ClaudeCodeReasoningProvider`'s
 * parsing, validation, and error handling against a scripted
 * `spawnCaptureImpl`; it never spawns a real process. This file is the
 * "clearly separated integration test harness" that actually does: a real
 * invocation of the `claude` CLI's non-interactive print mode, authenticated
 * however that CLI is already authenticated on this machine (a Claude Pro/Max
 * OAuth session in the case this was built for — see `claude-code-provider.ts`'s
 * module docstring) — never `ANTHROPIC_API_KEY`, which this file does not
 * read or require.
 *
 * Skipped unless the `claude` binary is genuinely present on PATH. It does
 * NOT additionally check whether it is authenticated — an unauthenticated
 * `claude` would fail at spawn time and this test would then fail loudly
 * (not silently skip), which is the honest outcome: this harness exists to
 * prove real, working Claude Code reasoning, not to hide the case where it
 * is not actually working. Reasons only over a synthetic, hard-coded
 * `WorldModelSnapshot` — no real program, no real hostname, no network
 * request to anything other than Claude Code's own API traffic.
 */

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { isToolInstalled } from '../recon/sources.js';
import type { WorldModelSnapshot } from '../types.js';
import { ClaudeCodeReasoningProvider } from './claude-code-provider.js';

const claudeInstalled = await isToolInstalled('claude');
const skip = claudeInstalled
  ? false
  : 'the "claude" binary is not on PATH; skipping the live Claude Code integration test';

function syntheticActionSnapshot(): WorldModelSnapshot {
  const now = new Date().toISOString();
  return {
    programId: 'integration-test-program',
    nodes: [],
    edges: [],
    hypotheses: [
      {
        id: 'hyp-integration-1',
        engagementId: 'integration-test',
        statement: 'reflected XSS on the search endpoint of a synthetic test asset',
        vulnClass: 'xss',
        assetRef: 'https://synthetic-test-asset.invalid/search',
        supportingObservationIds: [],
        contradictingObservationIds: [],
        potentialImpact: 'medium',
        confidence: 0.4,
        priorityScore: 0.5,
        informationGain: 0.6,
        requiredEvidence: ['proof the payload executes in a real browser context'],
        nextInvestigation: 'source-aware Shannon scan of the affected endpoint',
        status: 'open',
        createdAt: now,
        updatedAt: now,
      },
      {
        id: 'hyp-integration-2',
        engagementId: 'integration-test',
        statement: 'an internal admin endpoint referenced only in client-side JS may lack server-side authorization',
        vulnClass: 'authz',
        assetRef: 'https://synthetic-test-asset.invalid/internal/admin/users',
        supportingObservationIds: [],
        contradictingObservationIds: [],
        potentialImpact: 'high',
        confidence: 0.3,
        priorityScore: 0.4,
        informationGain: 0.5,
        requiredEvidence: ['behavioral diff across auth states'],
        nextInvestigation: 'behavioral diff across auth states on the affected endpoint',
        status: 'open',
        createdAt: now,
        updatedAt: now,
      },
    ],
    recentObservations: [],
    completedActions: [],
    // Two real, distinct candidates -- a genuine choice for the model to
    // make, not a single forced option (which `selectNextBestAction`
    // already short-circuits without calling the provider at all).
    candidateActions: [
      {
        id: 'action-integration-1',
        engagementId: 'integration-test',
        kind: 'shannon',
        targetRef: 'https://synthetic-test-asset.invalid/search',
        hypothesisId: 'hyp-integration-1',
        rationale: 'confirm the reflected XSS candidate with a source-aware exploitation pass',
        expectedInformationGain: 0.6,
        cost: 0.6,
        status: 'queued',
        createdAt: now,
        completedAt: undefined,
        resultSummary: undefined,
      },
      {
        id: 'action-integration-2',
        engagementId: 'integration-test',
        kind: 'behavioral-diff',
        targetRef: 'https://synthetic-test-asset.invalid/internal/admin/users',
        hypothesisId: 'hyp-integration-2',
        rationale: 'behavioral diff across auth states to test for missing server-side authorization',
        expectedInformationGain: 0.5,
        cost: 0.35,
        status: 'queued',
        createdAt: now,
        completedAt: undefined,
        resultSummary: undefined,
      },
    ],
    round: 1,
  };
}

test('ClaudeCodeReasoningProvider.selectNextBestAction makes a real claude CLI call (OAuth session, no ANTHROPIC_API_KEY) and returns a schema-valid proposal chosen from real candidates', {
  skip,
}, async () => {
  assert.equal(
    process.env.ANTHROPIC_API_KEY,
    undefined,
    'this test must prove the OAuth path, not silently use an API key if one happens to be set',
  );
  const provider = new ClaudeCodeReasoningProvider({ timeoutMs: 120_000 });
  const proposal = await provider.selectNextBestAction(syntheticActionSnapshot());
  assert.ok(proposal, 'a real model call over a two-candidate snapshot must return a proposal');
  // Must be verbatim one of the two real candidates -- never invented.
  assert.ok(
    (proposal?.kind === 'shannon' && proposal.targetRef === 'https://synthetic-test-asset.invalid/search') ||
      (proposal?.kind === 'behavioral-diff' &&
        proposal.targetRef === 'https://synthetic-test-asset.invalid/internal/admin/users'),
    `proposal must match a real candidate verbatim, got: ${JSON.stringify(proposal)}`,
  );
  assert.ok((proposal?.whyThisAction.length ?? 0) > 0);
});

test('ClaudeCodeReasoningProvider.generateHypotheses makes a real claude CLI call grounded strictly in the supplied observations', {
  skip,
}, async () => {
  const provider = new ClaudeCodeReasoningProvider({ timeoutMs: 120_000 });
  const observation = {
    id: 'obs-integration-1',
    engagementId: 'integration-test',
    source: 'js-intelligence' as const,
    assetRef: 'https://synthetic-test-asset.invalid/search',
    vulnClass: 'xss',
    title: 'unescaped query parameter written into innerHTML',
    description: 'A synthetic bundle assigns a URL query parameter directly into element.innerHTML with no encoding.',
    severityHint: 'medium',
    confidenceHint: 'medium',
    verified: false,
    tags: ['synthetic'],
    collectedAt: new Date().toISOString(),
  };
  const proposals = await provider.generateHypotheses([observation], 'integration-test');
  assert.ok(
    proposals.length >= 1,
    'a real model call over one concrete observation must propose at least one hypothesis',
  );
  for (const proposal of proposals) {
    assert.ok(
      proposal.supportingObservationIds.every((id) => id === observation.id),
      'every cited supporting observation id must be one Claude was actually given, never invented',
    );
  }
});
