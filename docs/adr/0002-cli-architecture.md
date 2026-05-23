# ADR-CLI-002: skill-scanner CLI Architecture

> Status: STUB v0.1
> Author: @KimiCoder (taking over from @Arch)
> Date: 2026-05-23

## Context

skill-scanner is a standalone CLI tool that scans agent skills from marketplaces
for security risks. It is intentionally decoupled from QuickPort — the same
`@skill-scanner/core` engine powers both products.

## Decision

### 1. Observer, not Governor

skill-scanner is a **read-only observer**. It downloads skill packages,
performs static analysis, and produces risk reports. It **never**:
- Executes skill code
- Modifies user system state
- Writes to keychain or credential stores
- Patches configuration files

This is the fundamental boundary between skill-scanner (observer) and
QuickPort (governor). QuickPort's 9 HF (Hard Floors) are reclassified:

| HF | QuickPort (governor) | skill-scanner (observer) |
|---|---|---|
| HF-1 per-session token | Enforce | **Drop** — scanner does not hold tokens |
| HF-2 OS keychain | Enforce | **Drop** — scanner does not write keychain |
| HF-3 socket ACL / HF-3'F stdio sandbox | Enforce | **Observe** — report if skill lacks sandbox |
| HF-4 audit log | Enforce | **Drop** — scanner produces report, not audit trail |
| HF-5 short TTL token rotation | Enforce | **Drop** |
| HF-6 caller_source schema | Enforce | **Drop** |
| HF-7 spawn whitelist | Enforce | **Observe** — report unauthorized spawn patterns |
| HF-8 binary integrity | Enforce | **Observe** — report missing hash verification |
| HF-9 OAuth scope minimization | Enforce | **Observe** — report over-scoped capabilities |

### 2. npm Workspaces (not monorepo)

Three packages under `packages/`:
- `@skill-scanner/core` — scanner engine + rules
- `@skill-scanner/cli` — `skillchk` binary
- `@skill-scanner/github-action` — GitHub Action wrapper

Rationale: npm workspaces is built-in (npm 7+), zero extra tooling. Each package
has independent release cycle; only `core` is shared upstream.

### 3. Marketplace Adapter Abstraction

Marketplaces are heterogeneous:
- skills.sh = GitHub-driven (git clone, no REST catalog)
- ClawHub = REST-driven (12 endpoints, read-no-auth)

The `MarketplaceAdapter` interface hides this heterogeneity:
```typescript
interface MarketplaceAdapter {
  name: string;
  canHandle(url: string): boolean;
  fetch(url: string, opts?: FetchOptions): Promise<SkillPackage>;
}
```

v1 ships two adapters; community can add more by implementing the interface.

## Consequences

### Positive
- Single source of truth for R0-R13 rules via `@skill-scanner/core` npm package
- QuickPort and skill-scanner both benefit from rule upgrades
- Observer design means zero runtime side-effects — users can safely scan anything
- Marketplace adapter pattern enables ecosystem expansion without core changes

### Trade-offs
- Scanner cannot prevent runtime attacks — only surface static findings
- No real-time monitoring (out of scope by design)
- Marketplace rate limits (GitHub 60/hr unauth) may slow batch scans

## References

- Rex marketplace adapter spec v0.1: <https://www.feishu.cn/docx/LkYddRlyqoUlJIxcpVZcCJntn8c>
- Arch OQ-3 decision (npm workspaces): Slock #skill-security-scanner msg dab0ea89
- Gatekeeper custom ruleset security spec: `docs/specs/custom-ruleset-security.md`
