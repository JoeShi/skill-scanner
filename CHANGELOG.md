# Changelog

## [0.1.0] — 2026-05-23

### Added

- **Scanner engine** (`@skill-scanner/core`) — R0–R13 static analysis rules
  - R0: Manifest structure validation
  - R1: Network domain diff (declared vs actual)
  - R2: FS path diff + sensitive paths
  - R3: Process spawn diff
  - R5: Narrow-waist bypass (governor APIs)
  - R6: Hardcoded secrets
  - R7: Dangerous APIs (eval / vm / shell injection)
  - R12: Installer.type whitelist (ClawHub manifest security)
  - R12-bis: Installer command/script content validation
  - R13: Env sensitive-key block list (PATH, LD_PRELOAD, DYLD_*, NODE_OPTIONS, etc.)
- **Custom ruleset security** (C1–C5)
  - C1: zod schema validation for custom rulesets
  - C2: `ruleOrigin` stamping (custom cannot spoof core)
  - C3: Severity asymmetry merge (custom may upgrade, never downgrade)
  - C4: Trust policy (`signed` / `warn` / `allow`)
  - C5: Semgrep template expansion guard
- **Marketplace adapters** — skills.sh (GitHub), ClawHub (REST), local directory
- **Output formats** — terminal, JSON, markdown, SARIF 2.1.0 (GitHub Code Scanning compatible)
- **CLI** (`skillchk`) — `scan <target>` with `--fail-on`, `--format`, `--force`, `--keep-extracted`
- **GitHub Action** — SARIF upload, configurable inputs/outputs
- **SkillManifest normalization** — YAML frontmatter parser, installer/env/publisher fields
- **Self-test fixtures** — 16 synthetic poisoned-skill fixtures + real-world samples
- **Documentation** — README, ADR-CLI-001/002/003, scanner-rules.md, custom-ruleset-security.md

### Known limitations

- R8 (SBOM/CVE via osv-scanner) is a stub — integration pending v0.2
- R4 (IPC endpoint diff) deferred to v2
- R9 (capability completeness) deferred to v2
- R10 (version freshness) deferred to v2
- R11 (MCP `listOfferings` diff) deferred to v2
- Cross-file taint analysis deferred to v2+
- LLM semantic review of SKILL.md descriptions deferred to v2+

### Contributors

- @KimiCoder — scanner engine, CLI, marketplace adapters, custom ruleset loader/merge, README §3/§4
- @Jack — R12+R13+R12-bis implementation, §5 Architecture & Design
- @Gatekeeper — C1+C3 spec + impl, security review, §4.3 + §6
- @Maya — repo creation, product design, README §1/§2/§7/§8
- @Arch — ADR-CLI-001 stub (handed off)
