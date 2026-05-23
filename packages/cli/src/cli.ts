#!/usr/bin/env node
/**
 * skillchk — Skill Security Scanner CLI
 * Usage: skillchk scan <skill-path-or-url>
 */

import { Command } from 'commander';
import * as path from 'path';
import {
  createDefaultEngine,
  createReporter,
  createMarketplaceRegistryWithDefaults,
  ReporterFormat,
} from '@skill-scanner/core';

const program = new Command();

program
  .name('skillchk')
  .description('Scan agent skills for security risks')
  .version('0.1.0');

program
  .command('scan <target>')
  .description('Scan a skill package (local path or marketplace URL)')
  .option('--fail-on <level>', 'Fail on P0|P1|none', 'P0')
  .option(
    '--format <fmt>',
    'Output format: terminal|json|markdown',
    'terminal'
  )
  .option('--force', 'Force refetch even if cached')
  .option('--keep-extracted', 'Keep extracted files after scan')
  .action(
    async (
      target: string,
      options: {
        failOn: string;
        format: string;
        force?: boolean;
        keepExtracted?: boolean;
      }
    ) => {
      const registry = createMarketplaceRegistryWithDefaults();
      const source = registry.findSource(target);

      if (!source) {
        console.error(`Error: Cannot recognize marketplace source for "${target}"`);
        console.error('Supported: local directory, GitHub URLs (skills.sh), ClawHub URLs/slugs');
        process.exit(1);
      }

      console.error(`Fetching from ${source.name}...`);
      const skill = await source.fetch(target, {
        force: options.force,
      });

      console.error(`Scanning ${skill.skillName}...`);
      const engine = createDefaultEngine();
      const result = await engine.scan(skill.path);

      // Render report
      const format = options.format as ReporterFormat;
      const reporter = createReporter(format);
      console.log(reporter.render(result));

      // Cleanup unless --keep-extracted
      if (!options.keepExtracted && !skill.fromCache) {
        await skill.cleanup();
      }

      // Exit code based on severity policy
      const failLevel = options.failOn;
      if (failLevel === 'P0' && result.summary.P0 > 0) {
        process.exit(1);
      }
      if (failLevel === 'P1' && (result.summary.P0 > 0 || result.summary.P1 > 0)) {
        process.exit(1);
      }
    }
  );

program
  .command('list-marketplaces')
  .description('List supported marketplaces')
  .action(() => {
    const registry = createMarketplaceRegistryWithDefaults();
    console.log('Supported marketplaces:');
    for (const name of registry.listSources()) {
      console.log(`  - ${name}`);
    }
  });

program.parse();
