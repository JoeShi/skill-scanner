import { Reporter } from './types';
import { ScanResult } from '../types';

export class TerminalReporter implements Reporter {
  name = 'terminal';

  render(result: ScanResult): string {
    const lines: string[] = [];

    // Header
    const headerColor = result.decision === 'blocked' ? '\x1b[31m' : result.decision === 'requires-user-consent' ? '\x1b[33m' : '\x1b[32m';
    const reset = '\x1b[0m';

    lines.push(`${headerColor}╔══════════════════════════════════════════════════════════════╗${reset}`);
    lines.push(`${headerColor}║  Skill Scan: ${result.skillName.padEnd(45)}║${reset}`);
    lines.push(`${headerColor}║  Decision:  ${result.decision.toUpperCase().padEnd(46)}║${reset}`);
    lines.push(`${headerColor}╚══════════════════════════════════════════════════════════════╝${reset}`);
    lines.push('');

    // Summary
    lines.push(`  P0 (Blocker):     ${result.summary.P0}`);
    lines.push(`  P1 (Consent):     ${result.summary.P1}`);
    lines.push(`  P2 (Suggestion):  ${result.summary.P2}`);
    lines.push(`  Duration:         ${result.durationMs}ms`);
    lines.push('');

    // Findings
    if (result.findings.length > 0) {
      const p0Findings = result.findings.filter((f) => f.severity === 'P0');
      const p1Findings = result.findings.filter((f) => f.severity === 'P1');

      if (p0Findings.length > 0) {
        lines.push('\x1b[31m  P0 BLOCKERS:\x1b[0m');
        for (const f of p0Findings) {
          lines.push(`    ❌ ${f.ruleId}: ${f.message}`);
          if (f.file) lines.push(`       File: ${f.file}`);
          if (f.recommendation) lines.push(`       → ${f.recommendation}`);
        }
        lines.push('');
      }

      if (p1Findings.length > 0) {
        lines.push('\x1b[33m  P1 REQUIRES CONSENT:\x1b[0m');
        for (const f of p1Findings) {
          lines.push(`    ⚠️  ${f.ruleId}: ${f.message}`);
        }
        lines.push('');
      }
    } else {
      lines.push('\x1b[32m  ✅ No findings. Skill passed all checks.\x1b[0m');
      lines.push('');
    }

    return lines.join('\n');
  }
}
