import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { H1BrainDisclosedReportRecord } from '../discovery/h1-brain-provider.js';
import type { Observation, RelevantReportProposal } from '../types.js';
import { findRelevantDisclosedReports, relevantReportMatchToObservation } from './disclosed-report-rag.js';
import { HeuristicReasoningProvider } from './heuristic-provider.js';
import { hypothesesFromObservations } from './hypothesis.js';
import type { ReasoningProvider } from './provider.js';
import type { ReasoningRouter } from './router.js';

const REPORT: H1BrainDisclosedReportRecord = {
  id: 42,
  title: 'Reflected XSS in search',
  program: 'other-corp',
  weakness: 'Cross-site Scripting (XSS) - Reflected',
  writeup: 'A reflected XSS was found in the search parameter, triggered via an unsanitized query string value.',
};

const OBSERVATION: Observation = {
  id: 'obs-1',
  engagementId: 'e1',
  source: 'passive-recon',
  assetRef: 'https://app.example.com/search',
  vulnClass: 'xss',
  title: 'search endpoint reflects input',
  description: 'test',
  severityHint: 'medium',
  confidenceHint: 'low',
  verified: false,
  tags: [],
  collectedAt: new Date().toISOString(),
};

class StubReportProvider implements ReasoningProvider {
  readonly source = 'claude' as const;
  constructor(private readonly proposals: readonly RelevantReportProposal[] = []) {}
  selectNextBestAction(): Promise<undefined> {
    return Promise.resolve(undefined);
  }
  generateHypotheses(): Promise<readonly []> {
    return Promise.resolve([]);
  }
  findRelevantReports(): Promise<readonly RelevantReportProposal[]> {
    return Promise.resolve(this.proposals);
  }
}

class FailingReportProvider implements ReasoningProvider {
  readonly source = 'claude' as const;
  selectNextBestAction(): Promise<undefined> {
    return Promise.resolve(undefined);
  }
  generateHypotheses(): Promise<readonly []> {
    return Promise.resolve([]);
  }
  findRelevantReports(): Promise<readonly RelevantReportProposal[]> {
    return Promise.reject(new Error('simulated ranking failure'));
  }
}

function routerWith(primary: ReasoningProvider): ReasoningRouter {
  const heuristic = new HeuristicReasoningProvider();
  return { primary, premium: primary, fallback: heuristic, configuredSource: 'claude' };
}

test('findRelevantDisclosedReports returns ok([]) without calling the provider when there are no disclosed reports', async () => {
  const provider = new StubReportProvider([
    { reportId: 1, relatedAssetRef: 'x', relevanceRationale: 'x', suggestedNextInvestigation: 'x' },
  ]);
  const result = await findRelevantDisclosedReports([OBSERVATION], [], routerWith(provider));
  assert.equal(result.ok, true);
  if (result.ok) assert.deepEqual(result.value, []);
});

test('findRelevantDisclosedReports returns a match for a valid provider proposal', async () => {
  const provider = new StubReportProvider([
    {
      reportId: REPORT.id,
      relatedAssetRef: OBSERVATION.assetRef,
      relevanceRationale: 'same reflected-XSS mechanism in a search parameter',
      suggestedNextInvestigation: 'try the same payload shape against the search endpoint',
    },
  ]);
  const result = await findRelevantDisclosedReports([OBSERVATION], [REPORT], routerWith(provider));
  assert.equal(result.ok, true);
  if (!result.ok) return;
  assert.equal(result.value.length, 1);
  assert.equal(result.value[0]?.report.id, REPORT.id);
  assert.equal(result.value[0]?.relatedAssetRef, OBSERVATION.assetRef);
});

test('findRelevantDisclosedReports never trusts a proposal referencing an unknown report id, even if the provider returned one', async () => {
  const provider = new StubReportProvider([
    { reportId: 9999, relatedAssetRef: OBSERVATION.assetRef, relevanceRationale: 'x', suggestedNextInvestigation: 'x' },
  ]);
  const result = await findRelevantDisclosedReports([OBSERVATION], [REPORT], routerWith(provider));
  assert.equal(result.ok, true);
  if (result.ok) assert.deepEqual(result.value, []);
});

test('findRelevantDisclosedReports folds a provider failure into a Result err, never a silent empty match', async () => {
  const result = await findRelevantDisclosedReports([OBSERVATION], [REPORT], routerWith(new FailingReportProvider()));
  assert.equal(result.ok, false);
  if (!result.ok) assert.match(result.error, /simulated ranking failure/);
});

test('relevantReportMatchToObservation maps a known weakness to the real vulnClass, always at low confidence', () => {
  const observation = relevantReportMatchToObservation(
    {
      report: REPORT,
      relatedAssetRef: OBSERVATION.assetRef,
      relevanceRationale: 'same mechanism',
      suggestedNextInvestigation: 'try it here',
    },
    'engagement-1',
  );
  assert.ok(observation);
  assert.equal(observation?.vulnClass, 'xss');
  assert.equal(observation?.source, 'disclosed-report-intelligence');
  assert.equal(observation?.assetRef, OBSERVATION.assetRef);
  assert.equal(observation?.confidenceHint, 'low');
  assert.equal(observation?.verified, false);
});

test('a matched relevant report flows end-to-end through the real hypothesesFromObservations pipeline into a supported xss hypothesis', async () => {
  const provider = new StubReportProvider([
    {
      reportId: REPORT.id,
      relatedAssetRef: OBSERVATION.assetRef,
      relevanceRationale: 'same reflected-XSS mechanism in a search parameter',
      suggestedNextInvestigation: 'try the same payload shape against the search endpoint',
    },
  ]);
  const ragResult = await findRelevantDisclosedReports([OBSERVATION], [REPORT], routerWith(provider));
  assert.equal(ragResult.ok, true);
  if (!ragResult.ok) return;

  const ragObservations = ragResult.value
    .map((match) => relevantReportMatchToObservation(match, 'engagement-1'))
    .filter((o): o is NonNullable<typeof o> => o !== undefined);
  assert.equal(ragObservations.length, 1);

  const hypotheses = hypothesesFromObservations([OBSERVATION, ...ragObservations], 'engagement-1');
  const xssHypothesis = hypotheses.find((h) => h.vulnClass === 'xss' && h.assetRef === OBSERVATION.assetRef);
  assert.ok(xssHypothesis, 'expected an xss hypothesis for the shared asset');
  assert.ok(
    xssHypothesis?.supportingObservationIds.includes(ragObservations[0]?.id ?? ''),
    'expected the disclosed-report observation to support the hypothesis',
  );
});

test('relevantReportMatchToObservation skips an unmapped weakness type rather than guessing a vulnClass', () => {
  const observation = relevantReportMatchToObservation(
    {
      report: { ...REPORT, weakness: 'Some Exotic Weakness Category' },
      relatedAssetRef: OBSERVATION.assetRef,
      relevanceRationale: 'x',
      suggestedNextInvestigation: 'x',
    },
    'engagement-1',
  );
  assert.equal(observation, undefined);
});
