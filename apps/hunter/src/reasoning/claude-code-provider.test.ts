import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { H1BrainDisclosedReportRecord } from '../discovery/h1-brain-provider.js';
import type { CaptureResult } from '../recon/cli-adapters.js';
import type { Observation, WorldModelSnapshot } from '../types.js';
import { ClaudeCodeReasoningProvider } from './claude-code-provider.js';

const OBSERVATION: Observation = {
  id: 'obs-1',
  engagementId: 'e1',
  source: 'passive-recon',
  assetRef: 'https://app.example.com/search',
  vulnClass: 'xss',
  title: 'search reflects input',
  description: 'x',
  severityHint: 'medium',
  confidenceHint: 'low',
  verified: false,
  tags: [],
  collectedAt: new Date().toISOString(),
};

const DISCLOSED_REPORT: H1BrainDisclosedReportRecord = {
  id: 42,
  title: 'Reflected XSS in search',
  program: 'other-corp',
  weakness: 'Cross-site Scripting (XSS) - Reflected',
  writeup: 'A reflected XSS was found in the search parameter.',
};

function fakeCapture(envelope: unknown, overrides: Partial<CaptureResult> = {}): CaptureResult {
  return { stdout: JSON.stringify(envelope), stderr: '', exitCode: 0, timedOut: false, ...overrides };
}

function snapshotWithOneCandidate(): WorldModelSnapshot {
  const now = new Date().toISOString();
  return {
    programId: 'p1',
    nodes: [],
    edges: [],
    hypotheses: [
      {
        id: 'hyp-1',
        engagementId: 'e1',
        statement: 'xss on /search',
        vulnClass: 'xss',
        assetRef: 'https://app.example.com/search',
        supportingObservationIds: [],
        contradictingObservationIds: [],
        potentialImpact: 'medium',
        confidence: 0.4,
        priorityScore: 0.5,
        informationGain: 0.5,
        requiredEvidence: [],
        nextInvestigation: 'run shannon',
        status: 'open',
        createdAt: now,
        updatedAt: now,
      },
    ],
    recentObservations: [],
    completedActions: [],
    candidateActions: [
      {
        id: 'action-1',
        engagementId: 'e1',
        kind: 'shannon',
        targetRef: 'https://app.example.com/search',
        hypothesisId: 'hyp-1',
        rationale: 'run shannon',
        expectedInformationGain: 0.5,
        cost: 0.6,
        status: 'queued',
        createdAt: now,
        completedAt: undefined,
        resultSummary: undefined,
      },
    ],
    round: 1,
  };
}

test('selectNextBestAction never spawns claude when there are no candidate actions', async () => {
  let called = false;
  const provider = new ClaudeCodeReasoningProvider({
    spawnCaptureImpl: async () => {
      called = true;
      throw new Error('should not be called');
    },
  });
  const snapshot = { ...snapshotWithOneCandidate(), candidateActions: [] };
  const proposal = await provider.selectNextBestAction(snapshot);
  assert.equal(proposal, undefined);
  assert.equal(called, false);
});

test('selectNextBestAction parses and validates a well-formed structured_output response', async () => {
  let capturedArgs: readonly string[] | undefined;
  const provider = new ClaudeCodeReasoningProvider({
    spawnCaptureImpl: async (_binary, args) => {
      capturedArgs = args;
      return fakeCapture({
        is_error: false,
        subtype: 'success',
        structured_output: {
          kind: 'shannon',
          targetRef: 'https://app.example.com/search',
          hypothesisId: 'hyp-1',
          whyThisAction: 'source-aware confirmation',
          hypothesisTested: 'xss on /search',
          uncertaintyReduced: 'whether the sink is reachable',
          confirmingObservation: 'a verified Shannon finding',
          contradictingObservation: 'Shannon reports sanitized input',
          nextStepIfConfirmed: 'validate further',
          nextStepIfContradicted: 'drop the hypothesis',
        },
      });
    },
  });
  const proposal = await provider.selectNextBestAction(snapshotWithOneCandidate());
  assert.equal(proposal?.kind, 'shannon');
  assert.equal(proposal?.targetRef, 'https://app.example.com/search');
  // Real invocation shape, not assumed: -p <prompt>, --tools "" (no tool
  // access for a pure reasoning call), and a --json-schema forcing shape.
  assert.ok(capturedArgs?.includes('-p'));
  assert.ok(capturedArgs?.includes('--tools'));
  const toolsIndex = capturedArgs?.indexOf('--tools') ?? -1;
  assert.equal(capturedArgs?.[toolsIndex + 1], '');
  assert.ok(capturedArgs?.includes('--json-schema'));
  assert.ok(capturedArgs?.includes('--output-format'));
});

test('a --model option is forwarded as --model <alias>', async () => {
  let capturedArgs: readonly string[] | undefined;
  const provider = new ClaudeCodeReasoningProvider({
    model: 'sonnet',
    spawnCaptureImpl: async (_binary, args) => {
      capturedArgs = args;
      return fakeCapture({ is_error: false, structured_output: { hypotheses: [] } });
    },
  });
  await provider.generateHypotheses(
    [
      {
        id: 'obs-1',
        engagementId: 'e1',
        source: 'js-intelligence',
        assetRef: 'https://app.example.com/search',
        vulnClass: 'xss',
        title: 'x',
        description: 'x',
        severityHint: 'medium',
        confidenceHint: 'medium',
        verified: false,
        tags: [],
        collectedAt: new Date().toISOString(),
      },
    ],
    'e1',
  );
  const modelIndex = capturedArgs?.indexOf('--model') ?? -1;
  assert.ok(modelIndex >= 0);
  assert.equal(capturedArgs?.[modelIndex + 1], 'sonnet');
});

test('selectNextBestAction throws when the process exits non-zero, rather than fabricating a proposal', async () => {
  const provider = new ClaudeCodeReasoningProvider({
    spawnCaptureImpl: async () => ({ stdout: '', stderr: 'not logged in', exitCode: 1, timedOut: false }),
  });
  await assert.rejects(() => provider.selectNextBestAction(snapshotWithOneCandidate()), /exited 1/);
});

test('selectNextBestAction throws when the process times out, rather than hanging or fabricating a proposal', async () => {
  const provider = new ClaudeCodeReasoningProvider({
    spawnCaptureImpl: async () => ({ stdout: '', stderr: '', exitCode: 0, timedOut: true }),
  });
  await assert.rejects(() => provider.selectNextBestAction(snapshotWithOneCandidate()), /timed out/);
});

test('selectNextBestAction throws when stdout is not valid JSON', async () => {
  const provider = new ClaudeCodeReasoningProvider({
    spawnCaptureImpl: async () => ({ stdout: 'not json', stderr: '', exitCode: 0, timedOut: false }),
  });
  await assert.rejects(() => provider.selectNextBestAction(snapshotWithOneCandidate()), /did not return valid JSON/);
});

test('selectNextBestAction throws when the envelope reports is_error, rather than passing anything through', async () => {
  const provider = new ClaudeCodeReasoningProvider({
    spawnCaptureImpl: async () => fakeCapture({ is_error: true, result: 'permission denied' }),
  });
  await assert.rejects(() => provider.selectNextBestAction(snapshotWithOneCandidate()), /permission denied/);
});

test('selectNextBestAction throws when structured_output is missing entirely', async () => {
  const provider = new ClaudeCodeReasoningProvider({
    spawnCaptureImpl: async () => fakeCapture({ is_error: false, result: 'some prose, no structured output' }),
  });
  await assert.rejects(
    () => provider.selectNextBestAction(snapshotWithOneCandidate()),
    /did not include structured_output/,
  );
});

test("selectNextBestAction throws when structured_output fails Hunter's own schema validation, even though the CLI already enforced its JSON Schema", async () => {
  const provider = new ClaudeCodeReasoningProvider({
    spawnCaptureImpl: async () => fakeCapture({ is_error: false, structured_output: { kind: 'shannon' } }),
  });
  await assert.rejects(() => provider.selectNextBestAction(snapshotWithOneCandidate()), /schema validation/);
});

test('generateHypotheses returns an empty array without spawning claude when there are no observations', async () => {
  let called = false;
  const provider = new ClaudeCodeReasoningProvider({
    spawnCaptureImpl: async () => {
      called = true;
      throw new Error('should not be called');
    },
  });
  assert.deepEqual(await provider.generateHypotheses([], 'e1'), []);
  assert.equal(called, false);
});

test('generateHypotheses validates every proposed hypothesis in the array', async () => {
  const provider = new ClaudeCodeReasoningProvider({
    spawnCaptureImpl: async () =>
      fakeCapture({
        is_error: false,
        structured_output: {
          hypotheses: [
            {
              statement: 'xss on /search',
              vulnClass: 'xss',
              assetRef: 'https://app.example.com/search',
              potentialImpact: 'medium',
              confidence: 0.5,
              informationGain: 0.5,
              requiredEvidence: ['reproduction'],
              nextInvestigation: 'run shannon',
              supportingObservationIds: ['obs-1'],
            },
          ],
        },
      }),
  });
  const proposals = await provider.generateHypotheses(
    [
      {
        id: 'obs-1',
        engagementId: 'e1',
        source: 'js-intelligence',
        assetRef: 'https://app.example.com/search',
        vulnClass: 'xss',
        title: 'x',
        description: 'x',
        severityHint: 'medium',
        confidenceHint: 'medium',
        verified: false,
        tags: [],
        collectedAt: new Date().toISOString(),
      },
    ],
    'e1',
  );
  assert.equal(proposals.length, 1);
  assert.equal(proposals[0]?.vulnClass, 'xss');
});

test('findRelevantReports returns an empty array without spawning claude when there are no candidate reports', async () => {
  let called = false;
  const provider = new ClaudeCodeReasoningProvider({
    spawnCaptureImpl: async () => {
      called = true;
      throw new Error('should not be called');
    },
  });
  assert.deepEqual(await provider.findRelevantReports([OBSERVATION], []), []);
  assert.equal(called, false);
});

test('findRelevantReports validates and returns a well-formed match', async () => {
  const provider = new ClaudeCodeReasoningProvider({
    spawnCaptureImpl: async () =>
      fakeCapture({
        is_error: false,
        structured_output: {
          matches: [
            {
              reportId: DISCLOSED_REPORT.id,
              relatedAssetRef: OBSERVATION.assetRef,
              relevanceRationale: 'same reflected-XSS mechanism',
              suggestedNextInvestigation: 'try the same payload shape',
            },
          ],
        },
      }),
  });
  const proposals = await provider.findRelevantReports([OBSERVATION], [DISCLOSED_REPORT]);
  assert.equal(proposals.length, 1);
  assert.equal(proposals[0]?.reportId, DISCLOSED_REPORT.id);
});

test('findRelevantReports silently drops a match referencing an unknown report id or asset ref, never trusting a hallucinated one', async () => {
  const provider = new ClaudeCodeReasoningProvider({
    spawnCaptureImpl: async () =>
      fakeCapture({
        is_error: false,
        structured_output: {
          matches: [
            {
              reportId: 9999,
              relatedAssetRef: OBSERVATION.assetRef,
              relevanceRationale: 'x',
              suggestedNextInvestigation: 'x',
            },
          ],
        },
      }),
  });
  assert.deepEqual(await provider.findRelevantReports([OBSERVATION], [DISCLOSED_REPORT]), []);
});
