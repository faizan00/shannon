/**
 * `ToolAdapter` wrapper around `recon/mobile-app-intel.ts`. Deliberately
 * NOT registered in `tools/default-registry.ts`'s `buildDefaultToolRegistry()`
 * or `DEFAULT_PREFERRED_TOOL_NAMES` — exactly the same reasoning
 * `default-registry.ts`'s own docstring gives for leaving Shannon out: this
 * needs a real, operator-supplied local file path
 * (`MobileAppAnalysisInput.filePath`) that cannot be derived from a
 * `HuntAction.targetRef` the way every registry-driven adapter's input can,
 * so it has no business competing for a slot in the round loop's automatic
 * `firstAvailable` tool selection for any generic `ActionKind`. A caller
 * that has a real `.apk`/`.ipa` in hand invokes this adapter (or
 * `recon/mobile-app-intel.ts:analyzeMobileApp` directly) explicitly.
 */

import { analyzeMobileApp } from '../recon/mobile-app-intel.js';
import { isToolInstalled } from '../recon/sources.js';
import type { ActionKind, ToolCapability, ToolRisk, ToolScopeRequirement } from '../types.js';
import type { ToolAdapter, ToolRunResult } from './registry.js';

export interface MobileAppAnalysisInput {
  /** Real local path to an operator-supplied .apk/.ipa file -- never fetched from an app store by this package. */
  readonly filePath: string;
  readonly assetRef: string;
  readonly engagementId: string;
}

export class MobileAppAdapter implements ToolAdapter<MobileAppAnalysisInput> {
  readonly name = 'mobile-app-intel';
  readonly kind: ActionKind = 'passive-recon';
  readonly scopeRequirement: ToolScopeRequirement = 'none';
  readonly requiresAuthorization = false;
  readonly cost = 0.25;
  readonly risk: ToolRisk = 'none';
  readonly timeoutMs = 60_000;

  async capability(): Promise<ToolCapability> {
    const available = await isToolInstalled('unzip');
    return {
      available,
      reason: available
        ? 'identity assumed from presence: unzip is a standard, near-universal utility'
        : '"unzip" was not found on PATH',
      version: undefined,
    };
  }

  async run(input: MobileAppAnalysisInput): Promise<ToolRunResult> {
    try {
      const result = await analyzeMobileApp(input.filePath, input.assetRef, input.engagementId);
      return {
        ok: true,
        summary: `mobile-app-intel analyzed ${result.filesAnalyzed} file(s) (${result.stringsExtracted} string(s) extracted), found ${result.discoveries.length} endpoint(s), ${result.observations.length} potential secret(s)`,
        discoveries: result.discoveries,
        observations: result.observations,
        raw: result,
      };
    } catch (error) {
      return {
        ok: false,
        summary: `mobile-app-intel failed: ${(error as Error).message}`,
        discoveries: [],
        observations: [],
        raw: undefined,
      };
    }
  }
}
