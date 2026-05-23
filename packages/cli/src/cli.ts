#!/usr/bin/env node
/**
 * skillchk — Skill Security Scanner CLI
 * Usage: skillchk scan <skill-path>
 */

import { Command } from 'commander';
import * as path from 'path';
import { createDefaultEngine, formatReport } from '@skill-scanner/core';

const program = new Command();

program
  .name('skillchk')
  .description('Scan agent skills for security risks')
  .version('0.1.0');

program
  .command('scan <skill-path>')
  .description('Scan a skill package directory')
  .option('--fail-on <level>', 'Fail on P0|P1|none', 'P0')
  .option('--format <fmt>', 'Output format: terminal|json|markdown', 'terminal')
  .action(async (skillPath: string, options: { failOn: string; format: string }) => {
    const resolvedPath = path.resolve(skillPath);
    const engine = createDefaultEngine();
    const result = await engine.scan(resolvedPath);

    if (options.format === 'json') {
      console.log(JSON.stringify(result, null, 2));
    } else if (options.format === 'markdown') {
      console.log(formatReport(result));
    } else {
      console.log(formatReport(result));
    }

    const failLevel = options.failOn;
    if (failLevel === 'P0' && result.summary.P0 > 0) {
      process.exit(1);
    }
    if (failLevel === 'P1' && (result.summary.P0 > 0 || result.summary.P1 > 0)) {
      process.exit(1);
    }
  });

program.parse();
