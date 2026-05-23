/**
 * @skill-scanner/core/ruleset-loader
 *
 * Implements Custom Ruleset Security constraint C1 — schema validation on load.
 * Per Slock #skill-security-scanner msg 41b39e76 (Gatekeeper) §C1, ratified by
 * Arch dab0ea89 + Maya 3b6ba5ac.
 */

import { z } from 'zod';
import type { RuleOrigin, Severity, Tier } from './types.js';

const TierSchema = z.enum(['blocker', 'suggestion', 'nit']) satisfies z.ZodType<Tier>;
const SeveritySchema = z.enum(['P0', 'P1', 'P2']) satisfies z.ZodType<Severity>;

/**
 * The rule ID pattern intentionally rejects punctuation that would let a
 * custom ruleset spoof a `core` ID (e.g. `core:R5`, `R5/inject`, `R5\nfake`).
 * Strict lowercase-kebab plus optional digit suffix.
 */
const RuleIdSchema = z
  .string()
  .min(1)
  .max(128)
  .regex(/^[a-z][a-z0-9-]*$/, 'rule id must be lowercase kebab (no special chars)');

/**
 * Per C5 (no template expansion against scanner-internal context), `message`
 * is a plain string — markdown text fine, but Semgrep metavars (`$VAR`) are
 * the only interpolation the engine does. We cap length to discourage
 * blob-of-prose payloads designed for prompt injection downstream.
 */
const MessageSchema = z.string().min(1).max(2000);

const RuleEnvelopeSchema = z
  .object({
    id: RuleIdSchema,
    languages: z.array(z.string()).min(1).optional(),
    severity: z.string().optional(), // Semgrep severity (ERROR/WARNING/INFO) — passthrough
    message: MessageSchema,
    metadata: z
      .object({
        tier: TierSchema,
        severity: SeveritySchema,
        dimension: z.array(z.string()).optional(),
        // Custom rules are NOT allowed to set rule_origin — the loader
        // overrides it on every finding. We don't even allow the field here.
      })
      .strict(),
    paths: z
      .object({
        include: z.array(z.string()).optional(),
        exclude: z.array(z.string()).optional(),
      })
      .strict()
      .optional(),
  })
  // Strict mode: reject unknown top-level fields. Per C1, this stops attackers
  // from smuggling extension fields the engine might honor in a later version.
  .strict();

const RulesetSchema = z
  .object({
    rules: z.array(RuleEnvelopeSchema).min(1),
  })
  .strict();

export type Rule = z.infer<typeof RuleEnvelopeSchema>;
export type Ruleset = z.infer<typeof RulesetSchema>;

export interface LoadRulesetOptions {
  /**
   * Path of the ruleset file (used to compute `rule_origin` for findings
   * emitted by these rules). For built-in core rules, pass `'core'`.
   */
  source: 'core' | { customPath: string };
}

/**
 * Stamp a `RuleOrigin` onto each rule based on the load source.
 *
 * Per C2: `'core'` is reserved for rules shipped in `packages/core/rules/`.
 * Custom rules always get `custom:<path>` regardless of what the source file
 * tries to claim.
 */
export function originForLoad(opts: LoadRulesetOptions): RuleOrigin {
  return opts.source === 'core' ? 'core' : `custom:${opts.source.customPath}`;
}

export class RulesetValidationError extends Error {
  constructor(
    public readonly issues: Array<{ path: string; message: string }>,
    public readonly source: string,
  ) {
    super(
      `ruleset validation failed (${issues.length} issue${issues.length === 1 ? '' : 's'}) ` +
        `in ${source}: ${issues
          .slice(0, 3)
          .map((i) => `${i.path}: ${i.message}`)
          .join('; ')}${issues.length > 3 ? ` (+${issues.length - 3} more)` : ''}`,
    );
    this.name = 'RulesetValidationError';
  }
}

/**
 * Validate a parsed ruleset object (already loaded from YAML/JSON elsewhere).
 *
 * Throws `RulesetValidationError` if the input fails schema. The error lists
 * every issue so users see the full picture instead of fixing one error at a
 * time.
 *
 * NB: this validates the *envelope* — rule semantics (does `pattern` make
 * sense, does `pattern-regex` compile) are still Semgrep's job. We only own
 * shape + identity + non-spoofability.
 */
export function validateRuleset(input: unknown, source: string): Ruleset {
  const result = RulesetSchema.safeParse(input);
  if (result.success) {
    return result.data;
  }
  const issues = result.error.issues.map((i) => ({
    path: i.path.join('.') || '<root>',
    message: i.message,
  }));
  throw new RulesetValidationError(issues, source);
}
