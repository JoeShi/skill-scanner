import { ScanResult, ScanFinding } from '../types';
import { Reporter } from './types';

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  defaultConfiguration: { level: 'error' | 'warning' | 'note' };
  properties: { tags: string[] };
}

interface SarifResult {
  ruleId: string;
  ruleIndex: number;
  level: 'error' | 'warning' | 'note';
  message: { text: string };
  locations: Array<{
    physicalLocation: {
      artifactLocation: { uri: string; uriBaseId: string };
      region?: { startLine: number; startColumn?: number };
    };
  }>;
}

function severityToLevel(severity: ScanFinding['severity']): 'error' | 'warning' | 'note' {
  if (severity === 'P0') return 'error';
  if (severity === 'P1') return 'warning';
  return 'note';
}

function toSarifName(ruleId: string): string {
  return ruleId
    .split('-')
    .map((s) => s.charAt(0).toUpperCase() + s.slice(1))
    .join('');
}

export class SarifReporter implements Reporter {
  name = 'sarif';

  render(result: ScanResult): string {
    const ruleMap = new Map<string, number>();
    const rules: SarifRule[] = [];

    for (const f of result.findings) {
      if (!ruleMap.has(f.ruleId)) {
        ruleMap.set(f.ruleId, rules.length);
        rules.push({
          id: f.ruleId,
          name: toSarifName(f.ruleId),
          shortDescription: { text: f.message },
          defaultConfiguration: { level: severityToLevel(f.severity) },
          properties: { tags: ['security', f.category] },
        });
      }
    }

    const results: SarifResult[] = result.findings.map((f) => ({
      ruleId: f.ruleId,
      ruleIndex: ruleMap.get(f.ruleId)!,
      level: severityToLevel(f.severity),
      message: {
        text: f.recommendation ? `${f.message} — ${f.recommendation}` : f.message,
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: f.file ?? '',
              uriBaseId: '%SRCROOT%',
            },
            ...(f.line !== undefined
              ? { region: { startLine: f.line, ...(f.column !== undefined ? { startColumn: f.column } : {}) } }
              : {}),
          },
        },
      ],
    }));

    const sarif = {
      $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              name: 'skill-scanner',
              version: result.scannerVersion,
              informationUri: 'https://github.com/JoeShi/skill-scanner',
              rules,
            },
          },
          results,
          properties: {
            eventId: result.eventId,
            skillName: result.skillName,
            skillVersion: result.skillVersion,
            decision: result.decision,
            scannedAt: result.scannedAt,
          },
        },
      ],
    };

    return JSON.stringify(sarif, null, 2);
  }
}
