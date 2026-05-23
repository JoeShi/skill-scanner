# ADR-CLI-003: Capability Scanner Design (R0-R13)

> Status: STUB v0.1
> Author: @KimiCoder (taking over from @Arch)
> Date: 2026-05-23

## Context

The skill-scanner capability validation engine implements R0-R13 static analysis
rules for detecting security risks in agent skills. These rules cover manifest
structure, network boundaries, filesystem access, process spawn, dangerous APIs,
secrets leakage, narrow-waist bypass, dependency CVEs, and marketplace-specific
manifest fields.

## Decision

### 1. R0-R13 Rule Index

| ID | Name | Severity | Source | Status |
|---|---|---|---|---|
| R0 | Manifest structure validation | P0 | n/a | ✅ v0.1 |
| R1 | Network domain diff (declared vs actual) | P0 | js/ts/py | ✅ v0.1 |
| R2 | FS path diff + sensitive paths | P0 | js/ts/py | ✅ v0.1 |
| R3 | Process spawn diff | P0 | js/ts/py | ✅ v0.1 |
| R4 | IPC endpoint diff | P1 | js/ts | 🟡 deferred |
| R5 | Narrow waist bypass (keychain / config / audit) | P0 | js/ts/py | ✅ v0.1 |
| R6 | Hardcoded secrets | P0 | js/ts/py | ✅ v0.1 |
| R7 | Dangerous API (eval / Function / vm) | P0 | js/ts | ✅ v0.1 |
| R7-bis | Shell injection | P0 | js/ts | ✅ v0.1 |
| R8 | SBOM CVE | P1 | n/a | ⚠️ stub |
| R9 | Capability completeness | P2 | n/a | 🟡 deferred |
| R10 | Version freshness | P2 | n/a | 🟡 deferred |
| R11 | MCP listOfferings diff | P1 | n/a | 🟡 deferred |
| R12 | Manifest installer.type whitelist | P0 | n/a | 🟡 v0.2 (ClawHub) |
| R13 | Manifest env sensitive-key block | P0 | n/a | 🟡 v0.2 (ClawHub) |

### 2. Why HF-7 + HF-3'F are Direct Mitigations

OX Security (2026-04-15) disclosed a critical systemic vulnerability affecting
~200,000 MCP servers across 9 marketplaces (10 CVEs). The MCP stdio protocol
layer does not provide process isolation — launcher and spawned server share
permissions by default.

HF-7 (spawn whitelist) + HF-3'F (OS sandbox) are direct mitigations against
this industry-wide vulnerability. They are not over-design.

R3 catches code-level unauthorized spawn; R12/R13 catch metadata-level
bypass at manifest parse time (earlier in the pipeline).

### 3. Custom Ruleset Security (C1-C5)

| Constraint | Description | Implementation |
|---|---|---|
| C1 | Schema validation on load | `ruleset-loader.ts` — zod strict mode |
| C2 | Origin stamping | Loader rewrites `'core'` claim from custom files |
| C3 | Severity asymmetry | `finding-merge.ts` — custom can upgrade, never downgrade |
| C4 | Trust policy | `--ruleset-trust-policy=warn\|signed\|allow` (v0.x) |
| C5 | No template expansion | Semgrep config rejects `${...}` against scanner context |

### 4. Known Limitations

**L1: Natural-language prompt injection in SKILL.md is out of scope.**

R1-R13 detect code execution paths (fetch/exec/spawn/eval). They cannot prevent
malicious natural-language instructions embedded in SKILL.md or manifest
descriptions. arXiv 2604.03081 (2026-05-22) demonstrates that "minor edits to
SKILL.md make agents go rogue" and that regex/AST-based detection is insufficient.

**Mitigation layers:**
- v1 structural: SKILL.md must have capability declaration (manifest-driven)
- v2 candidate: LLM-based semantic review of manifest descriptions
- User-layer: Skills with free-form SKILL.md require P1 explicit consent

**L2: Cross-file taint analysis**

Multi-step attacks where sensitive data flows across files are not reliably
detected by per-file regex scanning. Requires `ts-morph` / `babel` post-processor
deferred to v2+.

### 5. Self-Test Fixtures

16 minimal poisoned-skill fixtures (one per R-rule) plus real-world malicious
samples from marketplace research. Run via `skillchk --self-test`.

## Consequences

### Positive
- Industry events (ClawHavoc 341, Snyk ToxicSkills 36%, OX Security 200K servers)
  directly validate the R0-R13 coverage matrix
- Custom ruleset extensibility lets enterprises layer internal policies
- Self-test fixtures establish trust baseline for scanner integrity

### Trade-offs
- R8 SBOM-CVE is stub only (osv-scanner integration v0.3)
- Win credential bindings not covered (v0.3)
- LLM semantic review deferred to v2+

## Future Work

| Version | Items |
|---|---|
| v0.2 | R12+R13 ClawHub fields, SARIF upload workflow, self-test fixtures real-world |
| v0.3 | R8 osv-scanner, Win credential bindings (CredWrite), slopsquatting detection |
| v2+ | LLM semantic review, cross-file taint analysis, native FFI detection |

## References

- `packages/core/docs/scanner-rules.md` — canonical rule definitions
- `docs/specs/custom-ruleset-security.md` — C1-C5 full spec
- `docs/specs/self-test-fixtures.md` — fixture layout spec
- Rex timeline doc: <https://www.feishu.cn/docx/BUxqd9I6vomRV0xuActcVZl9njZ>
- Rex marketplace spec: <https://www.feishu.cn/docx/LkYddRlyqoUlJIxcpVZcCJntn8c>
- OX Security MCP RCE: <https://www.ox.security/blog/the-mother-of-all-ai-supply-chains-critical-systemic-vulnerability-at-the-core-of-the-mcp/>
- arXiv 2604.03081: <https://arxiv.org/abs/2604.03081>
