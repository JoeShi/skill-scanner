/**
 * Severity-asymmetry merge — exercises C3 per
 * docs/specs/custom-ruleset-security.md.
 *
 * Scenarios under test:
 *   - core P0 + custom P2 for same finding → final P0 (core floor preserved)
 *   - core P2 + custom P0 for same finding → final P0 (custom upgrades)
 *   - core absent + custom-only finding → custom severity preserved
 *   - merge tracks ruleOrigin contributions in mergedFrom
 *   - decideFromFindings collapses to install-pipeline decision
 *
 * Adversarial scenarios:
 *   - custom finding with ruleOrigin='core' → throws (defense in depth)
 *   - core bucket containing a non-'core' ruleOrigin finding → throws
 *   - custom finding with no ruleOrigin → throws (loader must stamp)
 */

import { describe, expect, test } from 'vitest';
import { decideFromFindings, mergeFindings } from '../finding-merge.js';
import type { ScanFinding } from '../types.js';

function fixture(partial: Partial<ScanFinding> = {}): ScanFinding {
  return {
    ruleId: 'r-keychain',
    ruleOrigin: 'core',
    tier: 'blocker',
    severity: 'P0',
    category: 'privilege-escalation',
    ref: 'skill-foo#R5',
    message: 'msg',
    file: 'index.js',
    line: 42,
    ...partial,
  };
}

describe('mergeFindings (C3: custom can never downgrade core)', () => {
  test('core P0 vs custom P2 same identity → final P0 (custom did NOT downgrade)', () => {
    const core: ScanFinding[] = [fixture({ severity: 'P0' })];
    const customs: ScanFinding[] = [
      fixture({
        severity: 'P2',
        tier: 'nit',
        ruleOrigin: 'custom:/tmp/evil.yml',
      }),
    ];
    const merged = mergeFindings(core, customs);
    expect(merged).toHaveLength(1);
    expect(merged[0]?.severity).toBe('P0');
    expect(merged[0]?.tier).toBe('blocker');
    expect(merged[0]?.ruleOrigin).toBe('core');
    expect(merged[0]?.mergedFrom).toEqual(['core', 'custom:/tmp/evil.yml']);
  });

  test('core P2 + custom P0 same identity → final P0 (custom upgrade allowed)', () => {
    const core: ScanFinding[] = [fixture({ severity: 'P2', tier: 'nit' })];
    const customs: ScanFinding[] = [
      fixture({
        severity: 'P0',
        tier: 'blocker',
        ruleOrigin: 'custom:/etc/strict.yml',
      }),
    ];
    const merged = mergeFindings(core, customs);
    expect(merged).toHaveLength(1);
    expect(merged[0]?.severity).toBe('P0');
    expect(merged[0]?.tier).toBe('blocker');
    // ruleOrigin stays 'core' — but the custom contribution is logged.
    expect(merged[0]?.ruleOrigin).toBe('core');
    expect(merged[0]?.mergedFrom).toEqual(['core', 'custom:/etc/strict.yml']);
  });

  test('custom-only finding (no core counterpart) keeps its own severity', () => {
    const customs: ScanFinding[] = [
      fixture({
        severity: 'P1',
        tier: 'suggestion',
        ruleOrigin: 'custom:/tmp/extra.yml',
        ref: 'skill-foo#R-extra',
      }),
    ];
    const merged = mergeFindings([], customs);
    expect(merged).toHaveLength(1);
    expect(merged[0]?.severity).toBe('P1');
    expect(merged[0]?.ruleOrigin).toBe('custom:/tmp/extra.yml');
    expect(merged[0]?.mergedFrom).toEqual(['custom:/tmp/extra.yml']);
  });

  test('multiple custom rules raising same core finding are all logged', () => {
    const core: ScanFinding[] = [fixture({ severity: 'P2', tier: 'nit' })];
    const customs: ScanFinding[] = [
      fixture({ severity: 'P1', tier: 'suggestion', ruleOrigin: 'custom:/a.yml' }),
      fixture({ severity: 'P0', tier: 'blocker', ruleOrigin: 'custom:/b.yml' }),
    ];
    const merged = mergeFindings(core, customs);
    expect(merged).toHaveLength(1);
    expect(merged[0]?.severity).toBe('P0');
    expect(merged[0]?.mergedFrom).toEqual(['core', 'custom:/a.yml', 'custom:/b.yml']);
  });

  test('throws if a custom finding claims ruleOrigin=core (defense in depth)', () => {
    const customs: ScanFinding[] = [
      // Imagine the loader didn't reject this — finding-merge is the second
      // line of defense and must still throw.
      fixture({ ruleOrigin: 'core' }),
    ];
    expect(() => mergeFindings([], customs)).toThrow(/cannot impersonate core/);
  });

  test('throws if a finding in the core bucket has non-core ruleOrigin', () => {
    const core: ScanFinding[] = [
      fixture({ ruleOrigin: 'custom:/tmp/x.yml' }),
    ];
    expect(() => mergeFindings(core, [])).toThrow(/expected 'core'/);
  });

  test('throws if a custom finding has no ruleOrigin (loader skipped stamp)', () => {
    const customs: ScanFinding[] = [
      fixture({ severity: 'P1', tier: 'suggestion', ruleOrigin: undefined }),
    ];
    expect(() => mergeFindings([], customs)).toThrow(/no ruleOrigin/);
  });

  test('core finding with no ruleOrigin gets stamped to "core" by merge', () => {
    const core: ScanFinding[] = [fixture({ severity: 'P0', ruleOrigin: undefined })];
    const merged = mergeFindings(core, []);
    expect(merged).toHaveLength(1);
    expect(merged[0]?.ruleOrigin).toBe('core');
    expect(merged[0]?.mergedFrom).toEqual(['core']);
  });

  test('different files / lines do not collapse', () => {
    const a = fixture({ severity: 'P0', file: 'a.js', line: 10 });
    const b = fixture({ severity: 'P0', file: 'b.js', line: 10 });
    const c = fixture({ severity: 'P0', file: 'a.js', line: 11 });
    const merged = mergeFindings([a, b, c], []);
    expect(merged).toHaveLength(3);
  });

  test('falls back to ruleId when ref is missing (origin/main scanner modules)', () => {
    const a = fixture({ severity: 'P0', ref: undefined, ruleId: 'R5-keychain' });
    const b = fixture({ severity: 'P0', ref: undefined, ruleId: 'R5-keychain' });
    const merged = mergeFindings([a, b], []);
    // Same ruleId + same file/line → collapse to one
    expect(merged).toHaveLength(1);
  });
});

describe('decideFromFindings', () => {
  test('any P0 → blocked', () => {
    expect(
      decideFromFindings([
        fixture({ severity: 'P2', tier: 'nit' }),
        fixture({ severity: 'P0' }),
      ]),
    ).toBe('blocked');
  });

  test('only P1 + P2 → requires-user-consent', () => {
    expect(
      decideFromFindings([
        fixture({ severity: 'P2', tier: 'nit' }),
        fixture({ severity: 'P1', tier: 'suggestion' }),
      ]),
    ).toBe('requires-user-consent');
  });

  test('only P2 → allowed', () => {
    expect(decideFromFindings([fixture({ severity: 'P2', tier: 'nit' })])).toBe(
      'allowed',
    );
  });

  test('empty findings → allowed', () => {
    expect(decideFromFindings([])).toBe('allowed');
  });
});
