# `@skill-scanner/core` — Capability Validation Rules (R0-R11)

> Status: **STUB v0.1** — forked from QuickPort `notes/quickwork-scanner-rules-draft.md`
> (commits 6652affb / 9f62d2ea / c733a5e5 / 4222fd3d in QuickPort thread).
> Iterating via PRs — content TBD beyond canonical headers + tables.

## Source-of-truth

This document is the canonical rule definition for `@skill-scanner/core`. Both
[`JoeShi/quickport`](https://github.com/JoeShi/quickport) and the standalone
`skillchk` CLI consume the same rules via the npm package.

## Design principles

1. **Manifest declarative**: skills must explicitly declare their `capabilities`
   (network domains / fs paths / process spawn / ipc endpoints / credential
   surface). Static AST scanning compares declared vs actual call sites.
2. **diff = blocker**: any actual call outside the declared envelope produces
   a `blocker P0 [critical:security]` finding.
3. **Output schema same as v0.1 review protocol**: findings emit as
   `<tier> <severity> [critical:*] ref:skill-<name>#<rule-id>` so reviewers
   (human or LLM) parse them with the same grep tooling.
4. **Observer, not governor** (per Arch dab0ea89): scanner does not enforce
   runtime invariants — it surfaces violations as findings. Governor-level HF
   constraints (HF-1/2/4/5/6 in QuickPort) are dropped here; HF-3/3'F/7/8/9
   become detection dimensions.

## Rule index (R0-R11)

| ID | Name | Severity baseline | Source language |
|---|---|---|---|
| R0 | Manifest structure validation | P0 | n/a |
| R1 | Network domain diff (declared vs actual) | P0 | js / ts / py |
| R2 | FS path diff + sensitive paths | P0 | js / ts / py |
| R3 | Process spawn diff | P0 | js / ts / py |
| R4 | IPC endpoint diff (v2 D-mode candidate) | P0 | js / ts |
| R5 | Narrow-waist bypass (governor APIs) | P0 | js / ts / py |
| R6 | Hardcoded secrets / credentials | P0 | generic regex |
| R7 | Dangerous APIs (eval / Function / vm / shell injection / dynamic require) | P0 / P1 | js / ts / py |
| R8 | SBOM / CVE — osv-scanner integration | P0 (CVSS≥7) / P1 (4-7) / P2 (<4) | dependency manifests |
| R9 | Capability completeness (over-claim detection) | P1 | js / ts / py |
| R10 | Skill version freshness (re-scan on bump) | n/a (gate) | metadata |
| R11 | MCP `server.listOfferings()` diff (deferred) | TBD | runtime |

> **Per-rule sections** (R0-R11) are stubs and will be filled in follow-up
> commits matching QuickPort `notes/quickwork-scanner-rules-draft.md` v0
> verbatim, with `@quickport/orchestrator/*` allowlist references replaced
> with `@skill-scanner/core/*` and observer-mode framing.

## ScanReport canonical interface (v1.1)

Identical to QuickPort canonical `ScanReport` interface (msg 266aaa44 + Cody
10050681 + Arch 5a3c2c91 — `eventId` for cross-event join key).

```typescript
export interface ScanReport {
  eventId: string;       // UUID v4 or sha256(canonical fields)
  skill: string;
  version: string;
  scannedAt: string;     // ISO 8601
  coverage: string[];    // e.g. ["static-analysis", "sbom-cve"]
  confidence: 'high' | 'medium' | 'low';
  knownBlindSpots: string[];
  findings: Finding[];
  decision: 'allowed' | 'requires-user-consent' | 'blocked';
}

export interface Finding {
  ruleId: string;
  ruleOrigin: 'core' | `custom:${string}`;  // NEW v1.1 (per docs/specs/custom-ruleset-security.md)
  tier: 'blocker' | 'suggestion' | 'nit';
  severity: 'P0' | 'P1' | 'P2';
  dimension: string[];   // e.g. ["critical:security"]
  ref: string;           // e.g. "skill-foo#R3"
  message: string;
  evidence?: string;
  recommendation?: string;
}
```

## ADR-001 exception interface

P1 findings require user consent + ADR-style trade-off note (5 sub-fields:
`approved_by` / `business_reason` / `expires_at` / `revoke_trigger` /
`review_due`). For the standalone CLI (observer mode), this manifests as an
auto-generated trade-off section in the signed report when user passes
`--accept-p1=<reason>`.

## Detection dimensions ported from QuickPort 9 HF (observer mode)

| HF | QuickPort role | skill-scanner role |
|---|---|---|
| HF-1 / 2 / 4 / 5 / 6 | governor enforce | **drop** (CLI doesn't hold tokens / write keychain / write audit) |
| HF-3 / 3'F | governor enforce | **observe**: scan for `child_process.spawn` outside explicit sandbox wrapping |
| HF-7 | governor enforce | **observe**: scan for skill code attempting MCP spawn outside allowed paths |
| HF-8 | governor enforce | **observe**: scan manifest for binary integrity hash + verify if shipped |
| HF-9 | governor enforce | **observe**: OAuth scope over-claim detection (manifest declares > actual usage) |

## TODO (follow-up PRs)

- [ ] Fork R0-R11 per-rule definitions verbatim from QuickPort
- [ ] Reference `packages/core/rules/skill-scanner-rules.yml` (Semgrep YAML)
- [ ] Cross-reference `docs/specs/custom-ruleset-security.md` for ruleset-loading invariants
- [ ] Cross-reference `docs/specs/self-test-fixtures.md` for `--self-test` flag spec
