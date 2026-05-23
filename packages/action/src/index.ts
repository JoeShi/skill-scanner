import * as core from '@actions/core';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { createDefaultEngine, createReporter } from '@skill-scanner/core';
import type { ReporterFormat, Severity } from '@skill-scanner/core';

const SEVERITY_RANK: Record<Severity | 'none', number> = { P0: 2, P1: 1, P2: 0, none: -1 };

async function run(): Promise<void> {
  try {
    const target = core.getInput('target', { required: true });
    const failOn = (core.getInput('fail-on') || 'P0') as Severity | 'none';
    const format = (core.getInput('format') || 'sarif') as ReporterFormat;
    const rulesetPath = core.getInput('ruleset');

    if (rulesetPath) {
      core.warning(`Custom ruleset ${rulesetPath} provided — C4 wiring not yet implemented; ignoring.`);
    }

    core.info(`skill-scanner: scanning ${target}`);
    const engine = createDefaultEngine();
    const result = await engine.scan(target);

    core.info(`Scan complete: P0=${result.summary.P0} P1=${result.summary.P1} P2=${result.summary.P2} decision=${result.decision}`);

    const reporter = createReporter(format);
    const output = reporter.render(result);

    let sarifFile = '';
    if (format === 'sarif') {
      sarifFile = path.join(os.tmpdir(), `skill-scanner-${result.eventId}.sarif`);
      fs.writeFileSync(sarifFile, output, 'utf-8');
      core.info(`SARIF written to ${sarifFile}`);
    } else {
      core.info(output);
    }

    const totalFindings = result.findings.length;
    const blocked = SEVERITY_RANK[failOn] >= 0 &&
      result.findings.some((f) => SEVERITY_RANK[f.severity] >= SEVERITY_RANK[failOn]);

    core.setOutput('sarif-file', sarifFile);
    core.setOutput('findings-count', String(totalFindings));
    core.setOutput('blocked', String(blocked));

    if (blocked) {
      core.setFailed(
        `skill-scanner: scan blocked — ${result.summary.P0} P0, ${result.summary.P1} P1 findings (fail-on=${failOn})`,
      );
    }
  } catch (err) {
    core.setFailed(`skill-scanner: unexpected error — ${err}`);
  }
}

run();
