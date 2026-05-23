/**
 * R0 — Manifest Structure Validation Module
 * Validates required fields, semver, capabilities schema
 *
 * R12 — installer.type whitelist (ClawHub installer field)
 * R12-bis — installer.command/script content validation (shell metachar + path containment + first-token policy)
 * R13 — env sensitive-key block (PATH, LD_PRELOAD, DYLD_INSERT_LIBRARIES, NODE_OPTIONS, etc.)
 */

import * as path from 'path';
import { ScanContext, ScanFinding, ScannerModule } from '../types';
import { validateManifestStructure } from '../manifest';

const INSTALLER_TYPE_ALLOWED = new Set(['orchestrator-managed']);

// R12-bis: shell metacharacters that indicate command injection in installer.command
// Ordered: multi-char operators first for better evidence reporting
const COMMAND_METACHAR_RE = /&&|\|\||\$\(|>>|<<|[;`><|&\\]/;

const R12BIS_RECOMMENDATION =
  'installer.command / .script must be a benign invocation. ' +
  'To run multi-step setup, ship a script inside the skill directory and reference it via installer.script: ./setup.sh. ' +
  'To depend on system tools, declare them in manifest.requirements instead of embedding in installer.command.';

// Case-insensitive block list per Gatekeeper R13 spec + R13 supplement (ELECTRON_RUN_AS_NODE)
const ENV_BLOCK_LIST = new Set([
  'PATH',
  'LD_PRELOAD',
  'LD_LIBRARY_PATH',
  'DYLD_INSERT_LIBRARIES',
  'DYLD_LIBRARY_PATH',
  'DYLD_FRAMEWORK_PATH',
  'NODE_OPTIONS',
  'PYTHONPATH',
  'PYTHONSTARTUP',
  'JAVA_TOOL_OPTIONS',
  '_JAVA_OPTIONS',
  'RUBYOPT',
  'PERL5OPT',
  'ELECTRON_RUN_AS_NODE',
]);

export class ManifestValidationModule implements ScannerModule {
  name = 'manifest-validation';

  scan(ctx: ScanContext): ScanFinding[] {
    const findings: ScanFinding[] = [];
    const errors = validateManifestStructure(ctx.manifest);

    for (const err of errors) {
      findings.push({
        ruleId: 'R0-manifest-structure',
        tier: 'blocker',
        severity: 'P0',
        criticalTag: '[critical:security]',
        message: `Manifest structure violation: ${err}`,
        file: 'manifest.json',
        category: 'malicious-code',
        recommendation: 'Fix manifest.json to comply with required schema',
        ruleOrigin: 'core',
      });
    }

    // Check for required capability declarations (v1 must declare)
    if (!ctx.manifest.capabilities || ctx.manifest.capabilities.length === 0) {
      findings.push({
        ruleId: 'R0-missing-capabilities',
        tier: 'blocker',
        severity: 'P0',
        criticalTag: '[critical:security]',
        message: 'Manifest missing capabilities declaration. v1 requires explicit capability listing.',
        file: 'manifest.json',
        category: 'privilege-escalation',
        recommendation: 'Add capabilities section to manifest.json',
        ruleOrigin: 'core',
      });
    }

    // Check for credentials.via = install-orchestrator
    const creds = (ctx.manifest as any).capabilities?.credentials;
    if (creds && creds.via !== 'install-orchestrator') {
      findings.push({
        ruleId: 'R5-credentials-bypass',
        tier: 'blocker',
        severity: 'P0',
        criticalTag: '[critical:security]',
        message: `Credentials.via must be "install-orchestrator", found: ${creds.via}`,
        file: 'manifest.json',
        category: 'privilege-escalation',
        recommendation: 'Set capabilities.credentials.via to "install-orchestrator"',
        ruleOrigin: 'core',
      });
    }

    // R12 — installer.type whitelist
    const installerType = ctx.manifest.installer?.type;
    if (installerType !== undefined && !INSTALLER_TYPE_ALLOWED.has(installerType)) {
      findings.push({
        ruleId: 'R12-installer-type-blocked',
        tier: 'blocker',
        severity: 'P0',
        criticalTag: '[critical:security]',
        message: `manifest.installer.type="${installerType}" bypasses the orchestrator spawn whitelist (HF-7). Only "orchestrator-managed" is allowed.`,
        file: 'manifest.json',
        category: 'privilege-escalation',
        evidence: `installer.type: ${installerType}`,
        recommendation: 'Set installer.type to "orchestrator-managed" or omit the installer field entirely.',
        ruleOrigin: 'core',
      });
    }

    // R12-bis — installer.command / .script content validation
    const installer = ctx.manifest.installer;
    if (installer) {
      const { command, script } = installer;

      if (command !== undefined) {
        // Check 1: shell metachar injection
        const metacharMatch = command.match(COMMAND_METACHAR_RE);
        if (metacharMatch) {
          findings.push({
            ruleId: 'R12-bis-command-metachar',
            tier: 'blocker',
            severity: 'P0',
            criticalTag: '[critical:security]',
            message: `manifest.installer.command contains shell metachar "${metacharMatch[0]}" — arbitrary command injection vector (HF-7 bypass).`,
            file: 'manifest.json',
            category: 'privilege-escalation',
            evidence: `installer.command: ${command}`,
            recommendation: R12BIS_RECOMMENDATION,
            ruleOrigin: 'core',
          });
        }

        // Check 3: first-token absolute path policy
        const firstToken = command.trim().split(/\s+/)[0] ?? '';
        if (firstToken && path.isAbsolute(firstToken)) {
          findings.push({
            ruleId: 'R12-bis-command-interpreter',
            tier: 'blocker',
            severity: 'P0',
            criticalTag: '[critical:security]',
            message: `manifest.installer.command first token "${firstToken}" is an absolute system path — use a known interpreter name (node/python3/sh/bash/pwsh) or a skill-internal relative path instead.`,
            file: 'manifest.json',
            category: 'privilege-escalation',
            evidence: `installer.command: ${command}`,
            recommendation: R12BIS_RECOMMENDATION,
            ruleOrigin: 'core',
          });
        }
      }

      if (script !== undefined) {
        // Check 2: path containment (no traversal, no absolute paths)
        const normalizedScript = path.normalize(script);
        if (path.isAbsolute(normalizedScript) || normalizedScript.startsWith('..')) {
          findings.push({
            ruleId: 'R12-bis-script-path',
            tier: 'blocker',
            severity: 'P0',
            criticalTag: '[critical:security]',
            message: `manifest.installer.script "${script}" resolves outside the skill package boundary — path traversal / absolute path injection.`,
            file: 'manifest.json',
            category: 'privilege-escalation',
            evidence: `installer.script: ${script}`,
            recommendation: R12BIS_RECOMMENDATION,
            ruleOrigin: 'core',
          });
        }
      }
    }

    // R13 — env sensitive-key block (case-insensitive per Windows env semantics)
    const env = ctx.manifest.env;
    if (env && typeof env === 'object') {
      for (const key of Object.keys(env)) {
        if (ENV_BLOCK_LIST.has(key.toUpperCase())) {
          findings.push({
            ruleId: 'R13-env-sensitive-key',
            tier: 'blocker',
            severity: 'P0',
            criticalTag: '[critical:security]',
            message: `manifest.env overrides "${key}" — sensitive env var injection vector (HF-3/HF-7 bypass).`,
            file: 'manifest.json',
            category: 'privilege-escalation',
            evidence: `env.${key}`,
            recommendation: `Remove env.${key} from the manifest. Sensitive env vars cannot be overridden by skills.`,
            ruleOrigin: 'core',
          });
        }
      }
    }

    return findings;
  }
}
