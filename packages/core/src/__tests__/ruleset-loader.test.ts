/**
 * Malicious-ruleset attack fixtures — exercise C1 (schema validate on load)
 * and C2 (rule_origin distinct) per docs/specs/custom-ruleset-security.md.
 */

import { describe, expect, test } from 'vitest';
import {
  RulesetValidationError,
  originForLoad,
  validateRuleset,
} from '../ruleset-loader.js';

describe('validateRuleset (C1: schema validation on load)', () => {
  test('accepts a minimal valid ruleset', () => {
    const ok = {
      rules: [
        {
          id: 'r-keychain-direct',
          message: 'Direct keychain access detected.',
          metadata: {
            tier: 'blocker',
            severity: 'P0',
            dimension: ['critical:security'],
          },
        },
      ],
    };
    const result = validateRuleset(ok, 'fixture://ok');
    expect(result.rules).toHaveLength(1);
    expect(result.rules[0]?.id).toBe('r-keychain-direct');
  });

  test('rejects unknown top-level fields (strict mode catches smuggled extensions)', () => {
    const sneaky = {
      rules: [
        {
          id: 'r-ok',
          message: 'msg',
          metadata: { tier: 'blocker', severity: 'P0' },
        },
      ],
      // attacker tries to add a top-level field hoping a future engine
      // version will honor it
      auto_install: true,
    };
    expect(() => validateRuleset(sneaky, 'fixture://sneaky')).toThrow(
      RulesetValidationError,
    );
  });

  test('rejects unknown metadata fields (e.g. ruleOrigin spoof attempt)', () => {
    const spoof = {
      rules: [
        {
          id: 'r-spoof',
          message: 'msg',
          metadata: {
            tier: 'blocker',
            severity: 'P0',
            // C2: a malicious ruleset tries to claim its findings come
            // from core. The schema must reject this.
            ruleOrigin: 'core',
          },
        },
      ],
    };
    expect(() => validateRuleset(spoof, 'fixture://spoof')).toThrow(
      RulesetValidationError,
    );
  });

  test('rejects rule id with special chars (prevents core-id impersonation)', () => {
    const badId = {
      rules: [
        {
          id: 'core:R5',
          message: 'msg',
          metadata: { tier: 'blocker', severity: 'P0' },
        },
      ],
    };
    expect(() => validateRuleset(badId, 'fixture://bad-id')).toThrow(
      RulesetValidationError,
    );
  });

  test('rejects rule id starting with digit', () => {
    const badId = {
      rules: [
        {
          id: '5-bad',
          message: 'msg',
          metadata: { tier: 'blocker', severity: 'P0' },
        },
      ],
    };
    expect(() => validateRuleset(badId, 'fixture://digit-prefix')).toThrow(
      RulesetValidationError,
    );
  });

  test('rejects severity outside the P0/P1/P2 enum', () => {
    const badSev = {
      rules: [
        {
          id: 'r-x',
          message: 'msg',
          metadata: { tier: 'blocker', severity: 'CRITICAL' },
        },
      ],
    };
    expect(() => validateRuleset(badSev, 'fixture://bad-sev')).toThrow(
      RulesetValidationError,
    );
  });

  test('rejects extremely long message (prompt-injection blob defense)', () => {
    const longMsg = {
      rules: [
        {
          id: 'r-long',
          message: 'x'.repeat(2001),
          metadata: { tier: 'blocker', severity: 'P0' },
        },
      ],
    };
    expect(() => validateRuleset(longMsg, 'fixture://long')).toThrow(
      RulesetValidationError,
    );
  });

  test('rejects empty rules array (no valid use case + likely tampering)', () => {
    const empty = { rules: [] };
    expect(() => validateRuleset(empty, 'fixture://empty')).toThrow(
      RulesetValidationError,
    );
  });

  test('error includes all issues, not just the first', () => {
    const multipleIssues = {
      rules: [
        { id: 'core:bad', message: 'm', metadata: { tier: 'blocker', severity: 'WAT' } },
      ],
    };
    try {
      validateRuleset(multipleIssues, 'fixture://multi');
      throw new Error('expected RulesetValidationError to throw');
    } catch (err) {
      expect(err).toBeInstanceOf(RulesetValidationError);
      const e = err as RulesetValidationError;
      expect(e.issues.length).toBeGreaterThanOrEqual(2);
      expect(e.source).toBe('fixture://multi');
    }
  });
});

describe('originForLoad (C2: rule_origin distinct)', () => {
  test("returns 'core' for the core source", () => {
    expect(originForLoad({ source: 'core' })).toBe('core');
  });

  test("returns 'custom:<path>' for a user-supplied ruleset", () => {
    const o = originForLoad({ source: { customPath: '/users/alice/my-rules.yml' } });
    expect(o).toBe('custom:/users/alice/my-rules.yml');
  });

  test('always wraps custom paths — no way to produce a bare `core` from a custom load', () => {
    // Even if the path string contains 'core', the prefix `custom:` is non-removable.
    const o = originForLoad({ source: { customPath: 'core' } });
    expect(o).toBe('custom:core');
  });
});
