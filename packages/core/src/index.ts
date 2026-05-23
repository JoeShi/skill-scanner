/**
 * @skill-scanner/core — Skill Security Scanner Engine
 * R0-R11 static analysis for agent skill marketplace packages.
 */

export { ScannerEngine, createDefaultEngine, SCANNER_VERSION } from './engine';
export { isBlocked, formatReport } from './formatter';
export * from './types';

// Re-export scanner modules for advanced use
export { ManifestValidationModule } from './modules/manifest-validation';
export { NetworkDiffModule } from './modules/network-diff';
export { FsDiffModule } from './modules/fs-diff';
export { ProcessSpawnModule } from './modules/process-spawn';
export { DangerousApiModule } from './modules/dangerous-api';
export { SecretsScanModule } from './modules/secrets-scan';
export { NarrowWaistBypassModule } from './modules/narrow-waist-bypass';
export { SbomCveModule } from './modules/sbom-cve';
export { SemgrepScannerModule } from './semgrep-runner';

// Marketplace adapters
export * from './marketplace';

// Reporters
export * from './reporter';

// Custom-ruleset security primitives (Gatekeeper PR — C1 + C3)
export {
  validateRuleset,
  originForLoad,
  RulesetValidationError,
  type Rule,
  type Ruleset,
  type LoadRulesetOptions,
} from './ruleset-loader';
export { mergeFindings, decideFromFindings } from './finding-merge';
