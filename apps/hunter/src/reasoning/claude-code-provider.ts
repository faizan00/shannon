/**
 * Claude Code (OAuth) reasoning provider.
 *
 * For an operator using Claude Code with a Claude Pro/Max subscription
 * (OAuth) instead of `ANTHROPIC_API_KEY` — Hunter's own credential model
 * cannot reach that: `claude-provider.ts`'s `ClaudeReasoningProvider` calls
 * `https://api.anthropic.com/v1/messages` directly with an `x-api-key`
 * header, which is a different authentication scheme than a Claude Code
 * OAuth session, and this package has zero third-party dependencies (no
 * `@anthropic-ai/claude-agent-sdk`) by design — see the README.
 *
 * The verified, correct integration point is the `claude` CLI binary
 * itself, run as a real subprocess exactly the way this package already
 * shells out to every other real tool it drives (`recon/cli-adapters.ts`,
 * `shannon/execution-adapter.ts`): `claude` already handles Claude Code's
 * OAuth session end to end (login, token refresh, credential storage) —
 * this provider never touches or reads any of that itself, it only invokes
 * the CLI's own non-interactive "print mode" and reads its JSON output.
 *
 * Verified directly against the real, installed `claude` CLI (v2.1.266) in
 * an OAuth session with no `ANTHROPIC_API_KEY` set, not assumed from
 * `--help` text:
 *
 *   claude -p "<prompt>" --output-format json --tools "" \
 *     --json-schema '<JSON Schema>' [--model <alias>]
 *
 * returns a JSON envelope whose `structured_output` field is the model's
 * response, already parsed and already validated against the supplied
 * JSON Schema by the CLI itself — real inference (`claude-sonnet-5`, real
 * `total_cost_usd`, real `session_id`), not an echo of the input. `--tools
 * ""` disables all of Claude Code's own tools (Bash/Read/Write/…) for this
 * call: this provider only ever wants a JSON proposal, never file or
 * command access, and asking for none is safer than trusting a permission
 * mode to deny everything correctly.
 *
 * `reasoning/schema.ts`'s `validateActionProposal`/`validateHypothesisProposal`
 * still run against the CLI's own `structured_output` afterward — the
 * CLI's `--json-schema` enforces *shape*, not Hunter's full semantics
 * (e.g. that a proposed action really does match something in
 * `candidateActions`, which `reasoning/policy.ts` checks downstream
 * regardless of provider). Never trust a model's output through one
 * validation layer alone.
 *
 * Explicitly opt-in, exactly like `liveRecon`/`liveShannon`: `router.ts`
 * only selects this provider when `HUNTER_USE_CLAUDE_CODE=1` is set (and
 * the `claude` binary is genuinely present) — never merely because the
 * binary happens to exist on PATH. A developer machine with Claude Code
 * installed for unrelated reasons must not silently start spending a
 * Claude subscription's usage on every Hunter round.
 */

import { spawnCapture } from '../recon/cli-adapters.js';
import type { ActionProposal, HypothesisProposal, Observation, WorldModelSnapshot } from '../types.js';
import {
  ACTION_PROPOSAL_TOOL,
  buildActionSelectionPrompt,
  buildHypothesisPrompt,
  HYPOTHESIS_PROPOSAL_TOOL,
} from './claude-provider.js';
import type { ReasoningProvider } from './provider.js';
import { validateActionProposal, validateHypothesisProposal } from './schema.js';

export interface ClaudeCodeReasoningProviderOptions {
  /** Model alias/name forwarded to `claude --model`. Defaults to the CLI's own default model. */
  readonly model?: string;
  /** Defaults to 'claude' (resolved via PATH, exactly like every other adapter in this package). */
  readonly binary?: string;
  readonly timeoutMs?: number;
  /** Injectable for tests — defaults to the real `recon/cli-adapters.ts:spawnCapture`. */
  readonly spawnCaptureImpl?: typeof spawnCapture;
}

interface ClaudeCodeResultEnvelope {
  readonly is_error?: boolean;
  readonly subtype?: string;
  readonly result?: string;
  readonly structured_output?: unknown;
}

function parseEnvelope(stdout: string): ClaudeCodeResultEnvelope {
  try {
    return JSON.parse(stdout) as ClaudeCodeResultEnvelope;
  } catch (error) {
    throw new Error(`claude CLI did not return valid JSON on stdout: ${(error as Error).message}`);
  }
}

export class ClaudeCodeReasoningProvider implements ReasoningProvider {
  readonly source = 'claude' as const;

  constructor(private readonly options: ClaudeCodeReasoningProviderOptions = {}) {}

  private async invoke(prompt: string, jsonSchema: object): Promise<unknown> {
    const capture = this.options.spawnCaptureImpl ?? spawnCapture;
    const binary = this.options.binary ?? 'claude';
    const args = [
      '-p',
      prompt,
      '--output-format',
      'json',
      '--tools',
      '',
      '--json-schema',
      JSON.stringify(jsonSchema),
      ...(this.options.model !== undefined ? ['--model', this.options.model] : []),
    ];
    const result = await capture(binary, args, this.options.timeoutMs ?? 60_000);
    if (result.timedOut) {
      throw new Error(`claude CLI timed out after ${this.options.timeoutMs ?? 60_000}ms`);
    }
    if (result.exitCode !== 0) {
      throw new Error(`claude CLI exited ${result.exitCode}: ${(result.stderr || result.stdout).slice(0, 500)}`);
    }
    const envelope = parseEnvelope(result.stdout);
    if (envelope.is_error) {
      throw new Error(`claude CLI reported an error: ${envelope.result ?? envelope.subtype ?? 'unknown error'}`);
    }
    if (envelope.structured_output === undefined) {
      throw new Error('claude CLI response did not include structured_output for the requested --json-schema');
    }
    return envelope.structured_output;
  }

  async selectNextBestAction(snapshot: WorldModelSnapshot): Promise<ActionProposal | undefined> {
    if (snapshot.candidateActions.length === 0) {
      return undefined;
    }
    const prompt = buildActionSelectionPrompt(snapshot);
    const output = await this.invoke(prompt, ACTION_PROPOSAL_TOOL.input_schema);
    const validated = validateActionProposal(output);
    if (!validated.ok) {
      throw new Error(`Claude Code's action proposal failed schema validation: ${validated.error}`);
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
    const output = await this.invoke(prompt, HYPOTHESIS_PROPOSAL_TOOL.input_schema);
    if (
      typeof output !== 'object' ||
      output === null ||
      !Array.isArray((output as Record<string, unknown>).hypotheses)
    ) {
      throw new Error('Claude Code\'s hypothesis proposal did not include a "hypotheses" array');
    }
    const proposals: HypothesisProposal[] = [];
    for (const raw of (output as { hypotheses: readonly unknown[] }).hypotheses) {
      const validated = validateHypothesisProposal(raw);
      if (!validated.ok) {
        throw new Error(`Claude Code's hypothesis proposal failed schema validation: ${validated.error}`);
      }
      proposals.push(validated.value);
    }
    return proposals;
  }
}
