/**
 * @skill-scanner/core/finding-merge
 *
 * Implements Custom Ruleset Security constraint C3 — severity asymmetry:
 * custom rules can upgrade core severity, never downgrade it.
 *
 * Per Slock #skill-security-scanner msg 41b39e76 (Gatekeeper) §C3,
 * ratified by Arch dab0ea89 + Maya 3b6ba5ac.
 *
 * The merge operates over `ScanFinding` arrays produced by core + custom
 * rule runs against the same skill. Findings are grouped by an "identity"
 * tuple — same skill, same source location, same rule semantic — and the
 * merge enforces:
 *
 *   1. Custom rules can never DROP a core finding.
 *   2. Custom rules can never lower the severity of a core finding.
 *   3. Custom rules CAN raise the severity of a core finding (P2 → P1 → P0).
 *   4. Custom-only findings keep their declared severity.
 *
 * The merge always preserves `ruleOrigin: 'core'` on the final finding when
 * a core rule contributed — even if the severity was raised by a custom
 * rule. Downstream consumers that want to see the custom contribution can
 * read `mergedFrom` (filled in when ≥2 findings collapsed into one).
 */

import type { ScanFinding, Severity } from './types.js';

/** Ordering: P0 most severe (smallest rank), P2 least severe (largest rank). */
const SEVERITY_RANK: Record<Severity, number> = {
  P0: 0,
  P1: 1,
  P2: 2,
};

const TIER_FOR_SEVERITY: Record<Severity, ScanFinding['tier']> = {
  P0: 'blocker',
  P1: 'suggestion',
  P2: 'nit',
};

/** Pick the higher-severity (lower rank) of two severities. */
function maxSeverity(a: Severity, b: Severity): Severity {
  return SEVERITY_RANK[a] <= SEVERITY_RANK[b] ? a : b;
}

/**
 * Identity key for grouping findings that refer to the same underlying
 * issue. Two findings collapse into one merged finding iff they share:
 *   - same `ref` (skill + rule semantic)
 *   - same `location.file` (same source location)
 *   - same `location.line` (same exact violation)
 */
function identityKey(f: ScanFinding): string {
  // Use `ref` if set, else fall back to `ruleId` (origin/main scanner modules
  // currently emit findings without `ref`). Two findings collapse iff same
  // semantic identity AND same source location.
  const ident = f.ref ?? f.ruleId;
  return `${ident}::${f.file ?? ''}::${f.line ?? ''}`;
}

interface MergedFinding extends ScanFinding {
  /**
   * If multiple findings collapsed, this lists the contributing
   * `ruleOrigin` values in input order. Single-source findings have a
   * 1-element array.
   */
  mergedFrom: NonNullable<ScanFinding['ruleOrigin']>[];
}

/**
 * Merge core + custom findings under the C3 severity asymmetry invariant.
 *
 * Input order matters only for tie-breaking metadata fields (message,
 * recommendation): when two findings collapse, the core finding's text
 * wins so users see the canonical core message. Custom findings only ever
 * influence the merged severity (upward) and add their `ruleOrigin` to
 * `mergedFrom` for trace.
 *
 * @param core    findings from core rules (ruleOrigin: 'core')
 * @param customs findings from custom rules (ruleOrigin: 'custom:<path>')
 */
export function mergeFindings(
  core: readonly ScanFinding[],
  customs: readonly ScanFinding[],
): MergedFinding[] {
  // Defensive guard: confirm ruleOrigin is consistent with the bucket.
  // A malicious custom rule that lies about its origin gets caught here.
  // Note: `ruleOrigin` is optional in the underlying type to keep existing
  // scanner modules backward-compatible. mergeFindings stamps a default
  // when it's missing so the merge invariants always hold downstream.
  for (const c of core) {
    if (c.ruleOrigin !== undefined && c.ruleOrigin !== 'core') {
      throw new Error(
        `mergeFindings: finding in 'core' bucket has ruleOrigin=${c.ruleOrigin} (expected 'core' or undefined)`,
      );
    }
  }
  for (const c of customs) {
    if (c.ruleOrigin === 'core') {
      throw new Error(
        'mergeFindings: finding in customs bucket has ruleOrigin="core" — ' +
          'custom rules cannot impersonate core. Reject before merge.',
      );
    }
    if (c.ruleOrigin === undefined) {
      throw new Error(
        'mergeFindings: custom finding has no ruleOrigin — must be set to ' +
          '`custom:<path>` by the loader before merge.',
      );
    }
  }

  const byKey = new Map<string, MergedFinding>();

  // Seed with core findings — these are the floor that customs can raise.
  for (const f of core) {
    const stampedOrigin: NonNullable<ScanFinding['ruleOrigin']> =
      f.ruleOrigin ?? 'core';
    byKey.set(identityKey(f), {
      ...f,
      ruleOrigin: stampedOrigin,
      mergedFrom: [stampedOrigin],
    });
  }

  for (const c of customs) {
    const key = identityKey(c);
    // Type-narrowed by the guard loop above: customs always have ruleOrigin set
    // and it's not 'core'.
    const customOrigin = c.ruleOrigin as NonNullable<ScanFinding['ruleOrigin']>;
    const existing = byKey.get(key);
    if (!existing) {
      // Custom-only finding — keeps its own severity and origin.
      byKey.set(key, { ...c, ruleOrigin: customOrigin, mergedFrom: [customOrigin] });
      continue;
    }
    // C3: a custom rule can RAISE the severity of an existing finding,
    // never lower it. The final ruleOrigin stays whatever was there
    // first (typically 'core').
    const newSeverity = maxSeverity(existing.severity, c.severity);
    existing.severity = newSeverity;
    existing.tier = TIER_FOR_SEVERITY[newSeverity];
    existing.mergedFrom.push(customOrigin);
  }

  return [...byKey.values()];
}

/**
 * Helper: top-level decision based on the merged findings' severity.
 *
 * Mirrors QuickPort install-pipeline behavior:
 *   - any P0 → 'blocked'
 *   - else any P1 → 'requires-user-consent'
 *   - else 'allowed'
 */
export function decideFromFindings(
  findings: readonly ScanFinding[],
): 'blocked' | 'requires-user-consent' | 'allowed' {
  let hasP1 = false;
  for (const f of findings) {
    if (f.severity === 'P0') return 'blocked';
    if (f.severity === 'P1') hasP1 = true;
  }
  return hasP1 ? 'requires-user-consent' : 'allowed';
}
