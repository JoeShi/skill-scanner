/**
 * Skill Scanner Engine - Core Types
 * Output format: <tier> <severity> [critical:*] ref:skill-name#<rule-id>
 * aligned with v0.1 review protocol
 */

export type Severity = 'P0' | 'P1' | 'P2';
export type Tier = 'blocker' | 'suggestion' | 'nit';
export type CriticalTag = '[critical:security]' | '[critical:perf]';
export type ThreatCategory =
  | 'malicious-code'
  | 'data-exfiltration'
  | 'privilege-escalation'
  | 'supply-chain-poisoning';

/**
 * `rule_origin` distinguishes core rules (shipped in `@skill-scanner/core`)
 * from user-supplied custom rules. Per Slock #skill-security-scanner msg
 * 41b39e76 (Gatekeeper) §C2.
 *
 * Core rules can never be impersonated by custom rules — the loader
 * rewrites any `'core'` literal coming from a user-supplied file to
 * `custom:<path>`.
 */
export type RuleOrigin = 'core' | `custom:${string}`;


export interface ScanFinding {
  /** Rule ID, e.g., "R3-manifest-integrity" */
  ruleId: string;
  /** Tier: blocker / suggestion / nit */
  tier: Tier;
  /** Severity: P0 / P1 / P2 */
  severity: Severity;
  /** critical tag for security/perf */
  criticalTag?: CriticalTag;
  /** Human-readable message */
  message: string;
  /** File path relative to skill root */
  file?: string;
  /** Line number if applicable */
  line?: number;
  /** Column if applicable */
  column?: number;
  /** Threat category */
  category: ThreatCategory;
  /** Raw evidence (snippet, diff, etc.) */
  evidence?: string;
  /** Recommended fix or mitigation */
  recommendation?: string;
  /**
   * Which ruleset the finding came from. Optional today (existing scanner
   * modules emit findings without it); the ruleset-loader stamps it in
   * future iterations. Per Gatekeeper 41b39e76 §C2.
   */
  ruleOrigin?: RuleOrigin;
  /**
   * Trace anchor in the form `skill-<name>#<rule-id>` — grep-able across
   * audit chain (per v0.1 review protocol).
   */
  ref?: string;
  /** Origins that contributed to this finding after mergeFindings() (C3 audit trail). */
  mergedFrom?: NonNullable<RuleOrigin>[];
}

export interface SkillManifest {
  name: string;
  version: string;
  description?: string;
  /** Declared capabilities */
  capabilities?: CapabilityDeclaration[];
  /** Declared outbound domains */
  domains?: string[];
  /** Declared FS paths */
  fsPaths?: string[];
  /** Entry point */
  main?: string;
  /** Dependencies */
  dependencies?: Record<string, string>;
  /** Dev dependencies */
  devDependencies?: Record<string, string>;
  /** Author / publisher */
  author?: string;
  /** License */
  license?: string;
  /** Raw manifest object for diff scanning */
  [key: string]: unknown;
}

export interface CapabilityDeclaration {
  name: string;
  /** e.g., "im.send", "email.read", "fs.read" */
  resource: string;
  /** Detailed scope, e.g., "~/.config" */
  scope?: string;
  /** Why this capability is needed */
  reason?: string;
}

export interface ScanContext {
  /** Skill name */
  skillName: string;
  /** Absolute path to skill directory */
  skillPath: string;
  /** Parsed manifest */
  manifest: SkillManifest;
  /** Manifest raw text for diff analysis */
  manifestRaw: string;
  /** All source files (relative paths) */
  sourceFiles: string[];
  /** Temporary working directory */
  tmpDir?: string;
}

export interface ScanResult {
  /** Unique event ID for audit trail join (per Arch 5a3c2c91) */
  eventId: string;
  skillName: string;
  skillVersion: string;
  /** Metadata for each ruleset used — enables finding provenance trace */
  rulesetMeta: RulesetMeta[];
  /** Total findings */
  findings: ScanFinding[];
  /** Summary by severity */
  summary: {
    P0: number;
    P1: number;
    P2: number;
  };
  /** Scan duration in ms */
  durationMs: number;
  /** Scanner engine version */
  scannerVersion: string;
  /** ISO timestamp */
  scannedAt: string;
  /** Coverage dimensions scanned */
  coverage: string[];
  /** Confidence based on coverage */
  confidence: 'high' | 'medium' | 'low';
  /** Known blind spots */
  knownBlindSpots: string[];
  /** Auto decision for install pipeline */
  decision: 'allowed' | 'requires-user-consent' | 'blocked';
}

export interface ScannerModule {
  name: string;
  /** Run the scan module */
  scan(ctx: ScanContext): Promise<ScanFinding[]> | ScanFinding[];
}

// ─── Custom Ruleset extensibility (Gatekeeper PR #1 spec → impl PR #N) ────

/**
 * Custom ruleset trust policy — gates loading of user-supplied rules.
 * Per Slock #skill-security-scanner msg dab0ea89 (Arch) + 41b39e76
 * (Gatekeeper) §C4.
 */
export type RulesetTrustPolicy = 'signed' | 'warn' | 'allow';

/** Default trust policy for v1 — unsigned ruleset loads but emits warning. */
export const DEFAULT_RULESET_TRUST_POLICY: RulesetTrustPolicy = 'warn';

/**
 * Metadata about a single ruleset that contributed to a scan.
 *
 * The `source` field uses the same `'core' | 'custom:<path>'` discriminant
 * as `RuleOrigin`, so downstream consumers can join `ScanFinding.ruleOrigin`
 * to the contributing `RulesetMeta` entry.
 *
 * Per Slock #skill-security-scanner msg 41b39e76 (Gatekeeper) — full ruleset
 * trace, no implicit trust.
 */
export interface RulesetMeta {
  /** `'core'` for the built-in ruleset, absolute path for custom rulesets. */
  source: 'core' | string;
  version: string;
  /** SHA-256 hex digest (first 16 chars) of the ruleset file; '' for built-in core. */
  hash: string;
  /** Omitted for built-in core (not loaded through the trust gate). */
  signatureStatus?: 'verified' | 'unverified' | 'unsigned';
  /** Omitted for built-in core (not subject to custom-ruleset trust policy). */
  trustPolicy?: RulesetTrustPolicy;
  /** How many findings this ruleset contributed to the scan. */
  findingsContributed?: number;
}
