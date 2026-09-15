/**
 * Claude-driven reasoning provider.
 *
 * A real implementation: it calls the Anthropic Messages API
 * (`https://api.anthropic.com/v1/messages`) over `fetch`, using Anthropic's
 * tool-use feature to force a structured JSON response, then validates
 * that response against `reasoning/schema.ts` before returning it. This is
 * the credential convention this repository already uses everywhere else
 * (`ANTHROPIC_API_KEY`, documented in the root CLAUDE.md's provider table)
 * — no new or invented mechanism.
 *
 * This provider is never the sole path: `reasoning/router.ts` always pairs
 * it with `HeuristicReasoningProvider` as a fallback, and nothing in this
 * package calls it unless `ANTHROPIC_API_KEY` is present in the
 * environment. A non-2xx response, a network error, a missing tool call in
 * the reply, or a reply that fails schema validation are all treated as
 * errors — never silently coerced into a usable-looking proposal.
 */

import type { H1BrainDisclosedReportRecord } from '../discovery/h1-brain-provider.js';
import type {
  ActionProposal,
  HypothesisProposal,
  Observation,
  RelevantReportProposal,
  WorldModelSnapshot,
} from '../types.js';
import type { ReasoningProvider } from './provider.js';
import { validateActionProposal, validateHypothesisProposal, validateRelevantReportProposal } from './schema.js';

export const ACTION_PROPOSAL_TOOL = {
  name: 'select_next_best_action',
  description:
    'Propose the single next-best action to investigate, given the current world model, hypotheses, and action queue. You may only propose an action that already appears in candidateActions — never invent a target, hypothesis id, or action kind.',
  input_schema: {
    type: 'object',
    properties: {
      kind: {
        type: 'string',
        enum: ['passive-recon', 'active-recon', 'js-intelligence', 'behavioral-diff', 'shannon', 'manual-review'],
      },
      targetRef: { type: 'string' },
      hypothesisId: { type: 'string' },
      whyThisAction: {
        type: 'string',
        description: 'Why this action, specifically, over the alternatives in candidateActions.',
      },
      hypothesisTested: { type: 'string' },
      uncertaintyReduced: { type: 'string' },
      confirmingObservation: { type: 'string', description: 'What observation would confirm the hypothesis.' },
      contradictingObservation: { type: 'string', description: 'What observation would contradict the hypothesis.' },
      nextStepIfConfirmed: { type: 'string' },
      nextStepIfContradicted: { type: 'string' },
    },
    required: [
      'kind',
      'targetRef',
      'hypothesisId',
      'whyThisAction',
      'hypothesisTested',
      'uncertaintyReduced',
      'confirmingObservation',
      'contradictingObservation',
      'nextStepIfConfirmed',
      'nextStepIfContradicted',
    ],
  },
} as const;

export const HYPOTHESIS_PROPOSAL_TOOL = {
  name: 'propose_hypotheses',
  description: 'Propose zero or more hypotheses grounded strictly in the supplied observations.',
  input_schema: {
    type: 'object',
    properties: {
      hypotheses: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            statement: { type: 'string' },
            vulnClass: { type: 'string' },
            assetRef: { type: 'string' },
            potentialImpact: { type: 'string', enum: ['low', 'medium', 'high', 'critical'] },
            confidence: { type: 'number' },
            informationGain: { type: 'number' },
            requiredEvidence: { type: 'array', items: { type: 'string' } },
            nextInvestigation: { type: 'string' },
            supportingObservationIds: { type: 'array', items: { type: 'string' } },
          },
          required: [
            'statement',
            'vulnClass',
            'assetRef',
            'potentialImpact',
            'confidence',
            'informationGain',
            'requiredEvidence',
            'nextInvestigation',
            'supportingObservationIds',
          ],
        },
      },
    },
    required: ['hypotheses'],
  },
} as const;

export const RELEVANT_REPORTS_TOOL = {
  name: 'find_relevant_reports',
  description:
    'Identify which of the candidate disclosed reports, if any, are genuinely technically relevant to the current engagement -- a real similarity in vulnerability mechanism, affected component, or attack surface, not merely the same weakness category label or the same platform. Only include a report you would actually point a human researcher at.',
  input_schema: {
    type: 'object',
    properties: {
      matches: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            reportId: {
              type: 'number',
              description: 'Must be one of the candidate report ids given below -- never invent one.',
            },
            relatedAssetRef: {
              type: 'string',
              description:
                "Must be one of the current engagement observations' own assetRef values given below -- the specific current-engagement asset this report's technique might apply to. Never invent one and never use the historical report's own asset.",
            },
            relevanceRationale: { type: 'string', description: 'Why this specific report is genuinely relevant.' },
            suggestedNextInvestigation: {
              type: 'string',
              description: 'What this report suggests trying against the current engagement, concretely.',
            },
          },
          required: ['reportId', 'relatedAssetRef', 'relevanceRationale', 'suggestedNextInvestigation'],
        },
      },
    },
    required: ['matches'],
  },
} as const;

export interface ClaudeReasoningProviderOptions {
  readonly apiKey: string;
  readonly model?: string;
  readonly baseUrl?: string;
  readonly fetchImpl?: typeof fetch;
  readonly timeoutMs?: number;
}

interface AnthropicToolUseBlock {
  readonly type: 'tool_use';
  readonly name: string;
  readonly input: unknown;
}

interface AnthropicMessageResponse {
  readonly content?: readonly (AnthropicToolUseBlock | { readonly type: string })[];
}

function isToolUseBlock(block: { readonly type: string }): block is AnthropicToolUseBlock {
  return block.type === 'tool_use';
}

export class ClaudeReasoningProvider implements ReasoningProvider {
  readonly source = 'claude' as const;

  constructor(private readonly options: ClaudeReasoningProviderOptions) {}

  private async callTool(toolName: string, tool: unknown, prompt: string): Promise<unknown> {
    const fetchImpl = this.options.fetchImpl ?? fetch;
    const response = await fetchImpl(`${this.options.baseUrl ?? 'https://api.anthropic.com'}/v1/messages`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-api-key': this.options.apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: this.options.model ?? 'claude-sonnet-4-6',
        max_tokens: 1536,
        tools: [tool],
        tool_choice: { type: 'tool', name: toolName },
        messages: [{ role: 'user', content: prompt }],
      }),
      signal: AbortSignal.timeout(this.options.timeoutMs ?? 30_000),
    });

    if (!response.ok) {
      const bodyText = await response.text();
      throw new Error(`Anthropic API responded ${response.status}: ${bodyText.slice(0, 500)}`);
    }

    const body = (await response.json()) as AnthropicMessageResponse;
    const toolUse = (body.content ?? []).find(
      (block): block is AnthropicToolUseBlock => isToolUseBlock(block) && block.name === toolName,
    );
    if (!toolUse) {
      throw new Error(`Claude response did not include the expected "${toolName}" tool call`);
    }
    return toolUse.input;
  }

  async selectNextBestAction(snapshot: WorldModelSnapshot): Promise<ActionProposal | undefined> {
    if (snapshot.candidateActions.length === 0) {
      return undefined;
    }
    const prompt = buildActionSelectionPrompt(snapshot);
    const input = await this.callTool(ACTION_PROPOSAL_TOOL.name, ACTION_PROPOSAL_TOOL, prompt);
    const validated = validateActionProposal(input);
    if (!validated.ok) {
      throw new Error(`Claude's action proposal failed schema validation: ${validated.error}`);
    }
    return validated.value;
  }

  async generateHypotheses(
    observations: readonly Observation[],
    engagementId: string,
  ): Promise<readonly HypothesisProposal[]> {
    if (observations.length === 0) {
      return [];
    }
    const prompt = buildHypothesisPrompt(observations, engagementId);
    const input = await this.callTool(HYPOTHESIS_PROPOSAL_TOOL.name, HYPOTHESIS_PROPOSAL_TOOL, prompt);
    if (typeof input !== 'object' || input === null || !Array.isArray((input as Record<string, unknown>).hypotheses)) {
      throw new Error('Claude\'s hypothesis proposal did not include a "hypotheses" array');
    }
    const proposals: HypothesisProposal[] = [];
    for (const raw of (input as { hypotheses: readonly unknown[] }).hypotheses) {
      const validated = validateHypothesisProposal(raw);
      if (!validated.ok) {
        throw new Error(`Claude's hypothesis proposal failed schema validation: ${validated.error}`);
      }
      proposals.push(validated.value);
    }
    return proposals;
  }

  async findRelevantReports(
    observations: readonly Observation[],
    disclosedReports: readonly H1BrainDisclosedReportRecord[],
  ): Promise<readonly RelevantReportProposal[]> {
    if (disclosedReports.length === 0) {
      return [];
    }
    const prompt = buildRelevantReportsPrompt(observations, disclosedReports);
    const input = await this.callTool(RELEVANT_REPORTS_TOOL.name, RELEVANT_REPORTS_TOOL, prompt);
    if (typeof input !== 'object' || input === null || !Array.isArray((input as Record<string, unknown>).matches)) {
      throw new Error('Claude\'s relevant-reports proposal did not include a "matches" array');
    }
    const validKnownIds = new Set(disclosedReports.map((r) => r.id));
    const validAssetRefs = new Set(observations.map((o) => o.assetRef));
    const proposals: RelevantReportProposal[] = [];
    for (const raw of (input as { matches: readonly unknown[] }).matches) {
      const validated = validateRelevantReportProposal(raw);
      if (!validated.ok) {
        throw new Error(`Claude's relevant-reports proposal failed schema validation: ${validated.error}`);
      }
      // Never trust a hallucinated report id or asset ref -- same
      // discipline `policy.ts` applies to action proposals against
      // `candidateActions`.
      if (!validKnownIds.has(validated.value.reportId) || !validAssetRefs.has(validated.value.relatedAssetRef)) {
        continue;
      }
      proposals.push(validated.value);
    }
    return proposals;
  }
}

export function buildActionSelectionPrompt(snapshot: WorldModelSnapshot): string {
  return [
    'You are the reasoning layer of an authorized security-research controller (Hunter).',
    'You may only PROPOSE the next-best action to investigate; a separate deterministic policy layer decides whether it is allowed to run.',
    'You must choose one entry from candidateActions verbatim (same kind, targetRef, hypothesisId) — never invent a target or hypothesis id.',
    '',
    `Round: ${snapshot.round}`,
    `World model: ${snapshot.nodes.length} node(s), ${snapshot.edges.length} edge(s).`,
    `Hypotheses: ${JSON.stringify(snapshot.hypotheses.map((h) => ({ id: h.id, vulnClass: h.vulnClass, assetRef: h.assetRef, status: h.status, confidence: h.confidence, priorityScore: h.priorityScore })))}`,
    `Recent observations: ${JSON.stringify(snapshot.recentObservations.slice(-20).map((o) => ({ id: o.id, vulnClass: o.vulnClass, source: o.source, verified: o.verified })))}`,
    `Completed actions (do not repeat): ${JSON.stringify(snapshot.completedActions.map((a) => ({ kind: a.kind, targetRef: a.targetRef, status: a.status })))}`,
    `Candidate actions (choose exactly one): ${JSON.stringify(snapshot.candidateActions.map((a) => ({ kind: a.kind, targetRef: a.targetRef, hypothesisId: a.hypothesisId, rationale: a.rationale, expectedInformationGain: a.expectedInformationGain, cost: a.cost })))}`,
    '',
    'Reason about what is known, what is uncertain, corroboration and contradictions, and expected information gain versus cost, then call select_next_best_action.',
  ].join('\n');
}

export function buildHypothesisPrompt(observations: readonly Observation[], engagementId: string): string {
  return [
    'You are the reasoning layer of an authorized security-research controller (Hunter).',
    `Engagement: ${engagementId}`,
    'Propose hypotheses grounded strictly in these observations — every supportingObservationIds entry must be one of the ids below. Do not invent an asset or observation that is not present.',
    JSON.stringify(
      observations.map((o) => ({
        id: o.id,
        assetRef: o.assetRef,
        vulnClass: o.vulnClass,
        title: o.title,
        severityHint: o.severityHint,
        confidenceHint: o.confidenceHint,
        verified: o.verified,
      })),
    ),
    'Call propose_hypotheses.',
  ].join('\n');
}

const WRITEUP_EXCERPT_MAX_CHARS = 1500;

export function buildRelevantReportsPrompt(
  observations: readonly Observation[],
  disclosedReports: readonly H1BrainDisclosedReportRecord[],
): string {
  return [
    'You are the reasoning layer of an authorized security-research controller (Hunter).',
    "Below are the observations collected so far on the current engagement, and a set of candidate historical HackerOne disclosed reports (from other programs/researchers) that might be technically relevant. For every match you report, relatedAssetRef must be exactly one of the assetRef values from the current engagement observations below -- never the historical report's own asset, and never invented.",
    'Current engagement observations:',
    JSON.stringify(
      observations.map((o) => ({
        assetRef: o.assetRef,
        vulnClass: o.vulnClass,
        title: o.title,
        description: o.description,
      })),
    ),
    'Candidate disclosed reports:',
    JSON.stringify(
      disclosedReports.map((r) => ({
        id: r.id,
        title: r.title,
        weakness: r.weakness,
        writeupExcerpt: r.writeup.slice(0, WRITEUP_EXCERPT_MAX_CHARS),
      })),
    ),
    'Call find_relevant_reports with only the reports that are genuinely, technically relevant -- an empty "matches" array is a correct answer when none are.',
  ].join('\n');
}
