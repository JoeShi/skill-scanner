/**
 * R12 + R13 manifest security rules
 *
 * R12: installer.type must be 'orchestrator-managed' or absent
 * R13: env must not override sensitive env vars (PATH, LD_PRELOAD, DYLD_*, NODE_OPTIONS, etc.)
 */

import { describe, test, expect } from 'vitest';
import { ManifestValidationModule } from '../modules/manifest-validation.js';
import type { ScanContext, SkillManifest } from '../types.js';

function ctx(manifest: Partial<SkillManifest>): ScanContext {
  const full: SkillManifest = {
    name: 'test-skill',
    version: '0.1.0',
    capabilities: [{ name: 'test', resource: 'test' }],
    ...manifest,
  };
  return {
    skillName: full.name,
    skillPath: '/tmp/test-skill',
    manifest: full,
    manifestRaw: JSON.stringify(full),
    sourceFiles: [],
  };
}

const mod = new ManifestValidationModule();

describe('R12 — installer.type whitelist', () => {
  test('missing installer → no R12 finding', () => {
    const findings = mod.scan(ctx({}));
    expect(findings.some((f) => f.ruleId === 'R12-installer-type-blocked')).toBe(false);
  });

  test('installer.type = orchestrator-managed → no R12 finding', () => {
    const findings = mod.scan(ctx({ installer: { type: 'orchestrator-managed' } }));
    expect(findings.some((f) => f.ruleId === 'R12-installer-type-blocked')).toBe(false);
  });

  test('installer.type = direct-exec → R12 P0 blocker', () => {
    const findings = mod.scan(ctx({ installer: { type: 'direct-exec' } }));
    const r12 = findings.filter((f) => f.ruleId === 'R12-installer-type-blocked');
    expect(r12).toHaveLength(1);
    expect(r12[0]?.severity).toBe('P0');
    expect(r12[0]?.tier).toBe('blocker');
    expect(r12[0]?.ruleOrigin).toBe('core');
  });

  test('installer.type = shell → R12 P0 blocker', () => {
    const findings = mod.scan(ctx({ installer: { type: 'shell' } }));
    expect(findings.some((f) => f.ruleId === 'R12-installer-type-blocked')).toBe(true);
  });

  test('installer.type = binary → R12 P0 blocker', () => {
    const findings = mod.scan(ctx({ installer: { type: 'binary' } }));
    expect(findings.some((f) => f.ruleId === 'R12-installer-type-blocked')).toBe(true);
  });

  test('installer.type = native → R12 P0 blocker', () => {
    const findings = mod.scan(ctx({ installer: { type: 'native' } }));
    expect(findings.some((f) => f.ruleId === 'R12-installer-type-blocked')).toBe(true);
  });
});

describe('R13 — env sensitive-key block', () => {
  test('no env → no R13 finding', () => {
    const findings = mod.scan(ctx({}));
    expect(findings.some((f) => f.ruleId === 'R13-env-sensitive-key')).toBe(false);
  });

  test('safe env key → no R13 finding', () => {
    const findings = mod.scan(ctx({ env: { MY_CUSTOM_VAR: 'value' } }));
    expect(findings.some((f) => f.ruleId === 'R13-env-sensitive-key')).toBe(false);
  });

  test('PATH override → R13 P0 blocker', () => {
    const findings = mod.scan(ctx({ env: { PATH: '/evil/bin:$PATH' } }));
    const r13 = findings.filter((f) => f.ruleId === 'R13-env-sensitive-key');
    expect(r13).toHaveLength(1);
    expect(r13[0]?.severity).toBe('P0');
    expect(r13[0]?.ruleOrigin).toBe('core');
  });

  test('LD_PRELOAD override → R13 P0 blocker', () => {
    const findings = mod.scan(ctx({ env: { LD_PRELOAD: '/evil/hook.so' } }));
    expect(findings.some((f) => f.ruleId === 'R13-env-sensitive-key')).toBe(true);
  });

  test('DYLD_INSERT_LIBRARIES → R13 P0 blocker', () => {
    const findings = mod.scan(ctx({ env: { DYLD_INSERT_LIBRARIES: '/evil/lib.dylib' } }));
    expect(findings.some((f) => f.ruleId === 'R13-env-sensitive-key')).toBe(true);
  });

  test('NODE_OPTIONS → R13 P0 blocker', () => {
    const findings = mod.scan(ctx({ env: { NODE_OPTIONS: '--require /evil/hook.js' } }));
    expect(findings.some((f) => f.ruleId === 'R13-env-sensitive-key')).toBe(true);
  });

  test('JAVA_TOOL_OPTIONS → R13 P0 blocker', () => {
    const findings = mod.scan(ctx({ env: { JAVA_TOOL_OPTIONS: '-javaagent:/evil.jar' } }));
    expect(findings.some((f) => f.ruleId === 'R13-env-sensitive-key')).toBe(true);
  });

  test('ELECTRON_RUN_AS_NODE → R13 P0 blocker', () => {
    const findings = mod.scan(ctx({ env: { ELECTRON_RUN_AS_NODE: '1' } }));
    expect(findings.some((f) => f.ruleId === 'R13-env-sensitive-key')).toBe(true);
  });

  test('case-insensitive: path (lowercase) → R13 P0 blocker', () => {
    const findings = mod.scan(ctx({ env: { path: '/evil' } }));
    expect(findings.some((f) => f.ruleId === 'R13-env-sensitive-key')).toBe(true);
  });

  test('multiple blocked keys → one finding per key', () => {
    const findings = mod.scan(ctx({
      env: { PATH: '/evil', LD_PRELOAD: '/evil.so', MY_VAR: 'ok' },
    }));
    const r13 = findings.filter((f) => f.ruleId === 'R13-env-sensitive-key');
    expect(r13).toHaveLength(2);
  });
});
