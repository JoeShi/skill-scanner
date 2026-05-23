// Canonical ScanReport types — matches Gatekeeper PR #1 scanner-rules.md v1.1 interface
// rule_origin and rulesetMeta fields per custom-ruleset-security.md C1-C5

export type ScanSeverity = "P0" | "P1" | "P2";

export type RuleOrigin = "core" | `custom:${string}`;

export interface ScanFinding {
  ruleId: string;
  severity: ScanSeverity;
  message: string;
  location: {
    file: string;
    line?: number;
    column?: number;
  };
  ruleOrigin: RuleOrigin;
  eventId?: string;
}

export interface RulesetMeta {
  source: "core" | string;
  version: string;
  hash: string;
  signatureStatus: "verified" | "unverified" | "unsigned";
  trustPolicy: "signed" | "warn" | "allow";
}

export interface ScanReport {
  eventId: string;
  skillId: string;
  skillVersion?: string;
  marketplaceSource?: string;
  scannerVersion: string;
  rulesetVersion: string;
  rulesetMeta: RulesetMeta[];
  scannedAt: string;
  findings: ScanFinding[];
  summary: {
    total: number;
    P0: number;
    P1: number;
    P2: number;
  };
}
