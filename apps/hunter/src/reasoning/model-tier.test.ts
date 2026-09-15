import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { HuntAction, Hypothesis, WorldModelSnapshot } from '../types.js';
import { chooseModelTier } from './model-tier.js';

function snapshot(overrides: Partial<WorldModelSnapshot> = {}): WorldModelSnapshot {
  return {
    programId: 'p1',
    nodes: [],
    edges: [],
    hypotheses: [],
    recentObservations: [],
    completedActions: [],
    candidateActions: [],
    round: 1,
    ...overrides,
  };
}

function action(overrides: Partial<HuntAction> = {}): HuntAction {
  return {
    id: 'action-1',
    engagementId: 'e1',
    kind: 'active-recon',
    targetRef: 'https://app.example.com',
    hypothesisId: 'hyp-1',
    rationale: 'test',
    expectedInformationGain: 0.5,
    cost: 0.3,
    status: 'queued',
    createdAt: new Date().toISOString(),
    completedAt: undefined,
    resultSummary: undefined,
    ...overrides,
  };
}

function hypothesis(overrides: Partial<Hypothesis> = {}): Hypothesis {
  return {
    id: 'hyp-1',
    engagementId: 'e1',
    statement: 'test',
    vulnClass: 'xss',
    assetRef: 'https://app.example.com',
    supportingObservationIds: [],
    contradictingObservationIds: [],
    potentialImpact: 'medium',
    confidence: 0.5,
    priorityScore: 0.5,
    informationGain: 0.5,
    requiredEvidence: [],
    nextInvestigation: 'test',
    status: 'open',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    ...overrides,
  };
}

test('an empty snapshot is cheap', () => {
  assert.equal(chooseModelTier(snapshot()), 'cheap');
});

test('a snapshot with only cheap-kind candidates backed by medium-impact hypotheses is cheap', () => {
  const s = snapshot({
    candidateActions: [action({ kind: 'passive-recon' }), action({ kind: 'behavioral-diff' })],
    hypotheses: [hypothesis({ potentialImpact: 'medium' })],
  });
  assert.equal(chooseModelTier(s), 'cheap');
});

test('a candidate action of kind "shannon" is premium, regardless of hypothesis impact', () => {
  const s = snapshot({
    candidateActions: [action({ kind: 'shannon' })],
    hypotheses: [hypothesis({ potentialImpact: 'low' })],
  });
  assert.equal(chooseModelTier(s), 'premium');
});

test('a candidate backed by a high-impact hypothesis is premium', () => {
  const s = snapshot({
    candidateActions: [action({ kind: 'active-recon', hypothesisId: 'hyp-1' })],
    hypotheses: [hypothesis({ id: 'hyp-1', potentialImpact: 'high' })],
  });
  assert.equal(chooseModelTier(s), 'premium');
});

test('a candidate backed by a critical-impact hypothesis is premium', () => {
  const s = snapshot({
    candidateActions: [action({ kind: 'manual-review', hypothesisId: 'hyp-1' })],
    hypotheses: [hypothesis({ id: 'hyp-1', potentialImpact: 'critical' })],
  });
  assert.equal(chooseModelTier(s), 'premium');
});

test('a high-impact hypothesis that backs no candidate action does not force premium', () => {
  const s = snapshot({
    candidateActions: [action({ kind: 'passive-recon', hypothesisId: 'hyp-2' })],
    hypotheses: [
      hypothesis({ id: 'hyp-1', potentialImpact: 'critical' }),
      hypothesis({ id: 'hyp-2', potentialImpact: 'low' }),
    ],
  });
  assert.equal(chooseModelTier(s), 'cheap');
});
