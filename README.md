# skill-scanner

Independent CLI to scan agent skill marketplaces (skills.sh / ClawHub) for risk

## §1 Overview

`skill-scanner` is an **open-source CLI** that audits agent skills before you install them — regardless of which marketplace they came from. Point it at a local skill folder, a `skills.sh` GitHub URL, or a ClawHub slug; it downloads the package, runs the **R0–R13 static analysis** ruleset (manifest schema · declared-vs-actual network/FS/process · narrow-waist bypass · hardcoded secrets · dangerous APIs · SBOM CVE · `installer.type` whitelist · `env` sensitive-key block) plus optional Semgrep AST rules, and produces a **risk report** in your choice of `terminal` / `json` / `markdown` / `sarif` — without ever executing the skill's code.

> Centralized marketplaces (ClawHub) and decentralized ones (`skills.sh` / `npx skills`) currently run different — and often very thin — review processes. The marketplace is the App Store; **`skill-scanner` is your OS-level Gatekeeper / Defender**: an independent third-party audit layer that doesn't depend on whether the marketplace itself reviews submissions.

### Differentiators

- **Cross-marketplace** — single tool covers `skills.sh` + ClawHub today (more in v1.1+); same rules, same report format, same exit-code contract
- **Zero runtime side effects** — pure static analysis; **never `eval` / `spawn` skill code**; safe to run on untrusted input in CI / on developer machines
- **CI-ready** — JSON / Markdown / **SARIF** outputs; ships a [GitHub Action](packages/action/) that uploads to GitHub Code Scanning; documented exit-code contract for non-Action CI (CircleCI / Buildkite / GitLab / Jenkins)
- **Custom rulesets safely composable** — extend with your own Semgrep YAML (`--ruleset`); custom rules can only **upgrade** core findings, never downgrade them ([§4.3](#43-custom-rulesets) / C1–C5 invariants)
- **Honest about limits** — natural-language prompt injection inside `SKILL.md` is explicitly **out of scope** for static analysis (see §2); cross-file taint and FFI calls into native security frameworks are documented v2 work
- **Dogfooded protocol** — finding format `<tier> <severity> [critical:*] ref:skill-name#rule-id` matches our internal review vocabulary, so audit output is the same shape as developer-readable review comments

## §2 Why skill-scanner — the threat landscape

Agent skill marketplaces are a 2025–2026 phenomenon, and they're already being targeted. Recent named incidents that motivated this project:

| Date | Incident | Vector | Source |
|---|---|---|---|
| 2025-09 | **Postmark-MCP** — first confirmed malicious MCP server on npm | Name squat + token exfil | [The Hacker News](https://thehackernews.com/2025/09/first-malicious-mcp-server-found.html) |
| 2025-Q4 | **ClawHavoc** — 341 malicious skills found by the bot they targeted | Malicious manifest | [Koi.ai](https://www.koi.ai/blog/clawhavoc-341-malicious-clawedbot-skills-found-by-the-bot-they-were-target...) |
| 2026-01 | **VS Code forks recommend missing extensions** | Typosquat + phantom recommendation | [The Hacker News](https://thehackernews.com/2026/01/vs-code-forks-recommend-missing.html) |
| 2026-02 | **Straiker — 71 malicious Claude Skills** (of 3,505 scanned on ClawHub) | Manifest + token exfil | [CybersecurityWaala](https://cybersecuritywaala.com/71-malicious-claude-skills-found/) |
| 2026-04-15 | **OX Security — MCP "by design" RCE** affecting ~200,000 servers, 10 CVEs, 9 marketplaces poisoned in research | Protocol-level design flaw via stdio spawn | [OX Security](https://www.ox.security/blog/the-mother-of-all-ai-supply-chains-critical-systemic-vulnerability-at-the-core-of-the-mcp/) |
| 2026-04-29 | **30 ClawHub skills mining cryptocurrency** silently | Consent-free resource hijack | [The Register](https://www.theregister.com/2026/04/29/30_clawhub_skills_mine_crypto/) |
| 2026-05-11 | **TanStack "Mini Shai-Hulud"** — 84 malicious npm versions in 6 minutes, CVSS 9.6 | CI/CD OIDC abuse | [BeyondMachines](https://beyondmachines.net/event_details/tanstack-npm-packages-compromised-in-mini-shai-hulud-supply-chain-attack-e-5-d-8-3) |
| 2026-05-18 | **Nx Console VS Code extension** → 3,800 GitHub internal repos breached | Compromised dev creds → poisoned extension | [The Hacker News](https://thehackernews.com/2026/05/github-internal-repositories-breached.html) |
| 2026-05-22 | **arXiv 2604.03081 — minor edits to `SKILL.md` make agents go rogue** | Natural-language prompt injection in manifest | [The Register](https://www.theregister.com/ai-ml/2026/05/22/minor-edits-to-ai-skills-can-make-agents-go-rogue/) |

Snyk's **ToxicSkills** audit further found that **~36% of skills sampled on ClawHub** carry prompt-injection patterns, even before considering name-squatting / dependency / installer-misconfiguration vectors. Marketplace-side review is, on its own, demonstrably insufficient.

A full living timeline of 21+ incidents (with attack-vector → R-rule mapping) is maintained as a counterpart living document by the research lane.

### What `skill-scanner` covers

R0 manifest schema · R1 declared-vs-actual network domain · R2 filesystem write boundary · R3 process spawn · R5 install-orchestrator narrow-waist bypass · R6 hardcoded secrets · R7 dangerous APIs (`eval` / shell injection / dynamic `require`) · R8 SBOM CVE · R12 `installer.type` whitelist (no `direct-exec`) · R12-bis `installer.command/script` content validation · R13 `manifest.env` block-list (`PATH` / `LD_PRELOAD` / `NODE_OPTIONS` / `JAVA_TOOL_OPTIONS` / `DYLD_*` / …)

Three-tier finding output: **P0 blocker** (install refused) · **P1 suggestion** (consent + ADR-style trade-off note required) · **P2 nit** (informational).

### What `skill-scanner` does **not** cover (honest limits)

- **Natural-language prompt injection inside `SKILL.md`** — static analysis cannot detect social-engineering prose; LLM-based semantic review is a v2+ candidate (see Roadmap)
- **Cross-file taint propagation** of dynamically-constructed paths/hosts — single-file Semgrep patterns will miss `cmd = base + suffix; exec(cmd)` style splits
- **Native FFI calls into OS security frameworks** (e.g. `node-ffi-napi` → Apple Security.framework) — out of regex/AST reach
- **Runtime sandboxing** — that's the job of the *governor* (e.g. companion installers), not the *observer* (this scanner)

These are documented in [`packages/core/docs/scanner-rules.md`](packages/core/docs/scanner-rules.md) under *known limitations*, not hidden.

## §3 Installation & Quick Start

### Requirements

- Node.js 20+ (LTS recommended)
- npm 10+ or equivalent (pnpm, yarn)

### Install

**Option A — npm global (recommended)**

```bash
npm install -g @skill-scanner/cli
skillchk --version
```

**Option B — npx (no install)**

```bash
npx @skill-scanner/cli scan <target>
```

**Option C — GitHub Action**

Add to your workflow (see §6 for full CI integration):

```yaml
- uses: JoeShi/skill-scanner/action@v1
  with:
    target: 'https://clawdhub.com/skills/my-skill'
    fail-on: 'P0'
    format: 'sarif'
```

### Quick Start

Scan a local skill directory:

```bash
skillchk scan ./my-skill
```

Scan a skill from skills.sh (GitHub):

```bash
skillchk scan https://github.com/vercel-labs/skills/tree/main/search
```

Scan a skill from ClawHub:

```bash
skillchk scan https://clawdhub.com/skills/my-skill
# or by slug
skillchk scan my-skill
```

List supported marketplaces:

```bash
skillchk list-marketplaces
```

## §4 CLI Usage

### `skillchk scan <target>`

Scan a skill package for security risks (R0–R13 static analysis).

**Arguments**

| Argument | Description |
|---|---|
| `<target>` | Local path or marketplace URL (skills.sh GitHub URL, ClawHub URL/slug) |

**Options**

| Option | Default | Description |
|---|---|---|
| `--fail-on <level>` | `P0` | Exit with code 1 if findings reach this severity (`P0`, `P1`, `none`) |
| `--format <fmt>` | `terminal` | Output format (`terminal`, `json`, `markdown`, `sarif`) |
| `--force` | `false` | Force refetch even if a cached copy exists |
| `--keep-extracted` | `false` | Keep extracted skill files after scan (for debugging) |

**Output formats**

- `terminal` — Human-readable colored output (default)
- `json` — Machine-parseable JSON report
- `markdown` — Markdown report suitable for PR comments
- `sarif` — SARIF 2.1.0 for GitHub Code Scanning upload

**Exit codes**

| Code | Meaning |
|---|---|
| `0` | Scan passed (no findings at or above `--fail-on` level) |
| `1` | Scan blocked (findings at or above `--fail-on` level) |

**Examples**

```bash
# Terminal output, fail on P0 (default)
skillchk scan ./my-skill

# JSON output for CI parsing
skillchk scan ./my-skill --format json --fail-on none

# SARIF output for GitHub Security tab
skillchk scan https://clawdhub.com/skills/my-skill --format sarif --fail-on P1

# Force re-download and keep files for inspection
skillchk scan my-skill --force --keep-extracted
```

### `skillchk list-marketplaces`

Display all supported marketplace sources:

```bash
skillchk list-marketplaces
# Supported marketplaces:
#   - skills.sh
#   - clawhub
```

### §4.3 Custom rulesets

`skill-scanner` ships with a built-in ruleset (R0–R13) that runs on every
scan. Teams with extra policies — internal API allowlists, regulatory
pattern checks, language-specific lints — can layer their own rules on top
via `--ruleset`:

```bash
skillchk scan ./my-skill --ruleset ./company-rules.yml
```

#### Trust policy

Custom rulesets are gated by `--ruleset-trust-policy`:

| Policy | Behavior | Use case |
|---|---|---|
| `warn` (default) | Load unsigned rulesets; emit warning + flag findings as `ruleset_signature: unverified` in the report | OSS / dev workflows |
| `signed` | Reject any unsigned ruleset; require sigstore / PGP signature | Enterprise / compliance |
| `allow` | Load anything, no warnings | Local dev / CI sandboxes only |

#### Severity-asymmetry guarantee

A **malicious or buggy custom ruleset cannot weaken core findings**:

- Custom rules can only **upgrade** severity (e.g. core says P2, custom
  says P0 → finding stays P0)
- Custom rules **cannot downgrade** severity (e.g. core says P0, custom
  says P2 → finding stays P0)
- Findings carry `ruleOrigin: 'core' | 'custom:<path>'` so reports always
  show the source of every flag — no silent rewrites

The merge is implemented in `@skill-scanner/core/finding-merge`; the
loader in `@skill-scanner/core/ruleset-loader` rejects custom rules that
try to claim `ruleOrigin: 'core'` or use punctuation-laden IDs that could
spoof core rule names.

#### Authoring a custom ruleset

Custom rulesets are Semgrep-compatible YAML. Minimal example:

```yaml
# company-rules.yml
rules:
  - id: r-no-internal-api-leak
    languages: [javascript, typescript]
    message: "Skill code references internal API host — must not ship externally."
    pattern-regex: 'api\.internal\.example\.com'
    metadata:
      tier: blocker
      severity: P0
      dimension: ['critical:security']
```

See [`docs/specs/custom-ruleset-security.md`](packages/core/docs/specs/custom-ruleset-security.md)
for the full schema constraints (C1–C5).

## §5 Architecture & Design

### Package layout

```
skill-scanner/                  (npm workspace root)
├── packages/
│   ├── core/                   @skill-scanner/core
│   │   ├── src/
│   │   │   ├── engine.ts       scan orchestrator
│   │   │   ├── types.ts        shared types (ScanFinding, SkillManifest, …)
│   │   │   ├── manifest.ts     manifest parser + structural validator
│   │   │   ├── modules/        scanner modules (one file per rule group)
│   │   │   ├── marketplace/    marketplace adapters (skills.sh, ClawHub, local)
│   │   │   ├── reporter/       output formatters (terminal, json, markdown, sarif)
│   │   │   ├── finding-merge.ts  core + custom finding merge (C3 severity policy)
│   │   │   └── ruleset-loader.ts custom ruleset validator + loader (C1/C2)
│   ├── cli/                    @skill-scanner/cli  →  skillchk binary
│   └── action/                 @skill-scanner/github-action
└── .github/workflows/ci.yml
```

### Scan pipeline

```
Target (path / URL)
      │
      ▼
Marketplace Adapter          resolve + fetch skill package
      │  (skills.sh / ClawHub / local)
      ▼
SkillManifest normalizer     parse YAML frontmatter → typed SkillManifest
      │  (installer, env, capabilities, domains …)
      ▼
Scanner Modules              parallel static analysis
      │  R0  manifest structure + capability declaration
      │  R1  network domain diff (declared vs actual)
      │  R2  FS path diff + sensitive paths
      │  R3  process spawn diff
      │  R5  narrow-waist bypass (governor API calls)
      │  R6  hardcoded secrets
      │  R7  dangerous APIs (eval / vm / shell injection)
      │  R8  SBOM / CVE (osv-scanner)
      │  R12 installer.type whitelist
      │  R12-bis installer.command / script content
      │  R13 env sensitive-key block
      ▼
findingMerge()               merge core findings with custom ruleset findings
      │  C3: custom rules may upgrade but never downgrade core severity
      ▼
decideFromFindings()         P0 → blocked / P1 → requires-user-consent / else → allowed
      ▼
Reporter                     render ScanResult in requested format
      │  terminal / json / markdown / sarif
      ▼
Exit code  0 = pass  1 = blocked (at --fail-on threshold)
```

### Scanner modules

Each module implements `ScannerModule`:

```typescript
interface ScannerModule {
  name: string;
  scan(ctx: ScanContext): Promise<ScanFinding[]> | ScanFinding[];
}
```

`ScanContext` carries the normalized `SkillManifest`, raw source files, and extracted skill path. Modules are stateless — the engine runs them against the same context and merges results.

### Finding format

Every finding has:

| Field | Description |
|---|---|
| `ruleId` | Machine-readable rule identifier (e.g. `R12-bis-command-metachar`) |
| `tier` | `blocker` / `suggestion` / `nit` |
| `severity` | `P0` / `P1` / `P2` |
| `criticalTag` | `[critical:security]` or `[critical:perf]` |
| `category` | `malicious-code` / `data-exfiltration` / `privilege-escalation` / `supply-chain-poisoning` |
| `evidence` | Raw snippet that triggered the finding |
| `recommendation` | Actionable fix guidance |
| `ruleOrigin` | `'core'` or `` `custom:${path}` `` — stamped by the loader |

### Custom-ruleset security invariants

User-facing usage is documented in [§4.3](#43-custom-rulesets). The architectural
invariants the loader and merger enforce:

- **C1** — zod schema validation: rejects unknown fields, oversized messages, spoofed rule IDs
- **C2** — `ruleOrigin` stamping: any `'core'` literal from a user file is rewritten to `` `custom:${path}` ``
- **C3** — severity asymmetry: custom rules may upgrade (P1 → P0) but never downgrade (P0 → P1) a core finding
- **C4** — trust policy: `signed` / `warn` (default) / `allow`

### Marketplace adapters

| Adapter | Source | How it resolves |
|---|---|---|
| `local` | filesystem path | reads directly from disk |
| `skills-sh` | GitHub URL (`github.com/…/skills/tree/…`) | clones sparse checkout via `git archive` |
| `clawhub` | ClawHub URL or slug | fetches via ClawHub REST API `/api/v1/skills/{slug}/file` |

All adapters emit a normalized `SkillManifest` so scanner modules are marketplace-agnostic.

## §6 CI / GitHub Action

Run `skill-scanner` as a CI gate so risky skills never reach production. The
official GitHub Action wraps the CLI, uploads SARIF to GitHub Code Scanning,
and exposes the exit-code contract for use in non-Action workflows.

### GitHub Action

```yaml
# .github/workflows/skill-scan.yml
name: skill-scan

on:
  pull_request:
    paths: ['skills/**']
  push:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # required for SARIF upload
    steps:
      - uses: actions/checkout@v4
      - uses: JoeShi/skill-scanner/action@v1
        with:
          target: ./skills/my-skill
          fail-on: P0
          format: sarif
          output: skill-scan.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: skill-scan.sarif
```

### Action inputs

| Input | Default | Description |
|---|---|---|
| `target` | _required_ | Local path, GitHub URL, or marketplace slug |
| `fail-on` | `P0` | Severity threshold to fail the job: `P0`, `P1`, `P2`, or `none` |
| `format` | `sarif` | Output format: `sarif`, `json`, `text` |
| `output` | `skill-scan.<ext>` | Path to write the report |
| `ruleset` | _(none)_ | Path to a custom ruleset YAML (layered on top of core R0–R13) |
| `ruleset-trust-policy` | `warn` | `signed`, `warn`, or `allow` (see §4.3 Custom rulesets) |

### Exit-code contract

The action and the bare `skillchk` CLI use the same exit codes — handy when
wiring into a non-Action CI (CircleCI, Buildkite, Jenkins, GitLab):

| Exit code | Meaning |
|---|---|
| `0` | Scan completed; no findings at or above `--fail-on` threshold |
| `1` | Scan completed; one or more findings at or above threshold (gate blocks) |
| `2` | Scan failed to run (network, parse error, missing target, etc.) |

The exit-code split between `1` and `2` is intentional: CI dashboards can
distinguish a *blocked release* (`1` — actionable, fix the skill) from a
*broken scanner* (`2` — actionable, fix the pipeline).

### Non-Action usage

```bash
# fail the job on any P0 blocker
skillchk scan ./my-skill --fail-on P0 --format sarif --output report.sarif
echo "exit=$?"
```

### SARIF upload

The action writes a SARIF 2.1.0 report by default. Each finding maps to a
SARIF `result` whose `ruleId` carries both the rule (e.g. `R12-bis-command-metachar`)
and the origin (`core` vs `custom:<path>`), so GitHub Code Scanning groups
findings by source. Findings include `level` (`error` for `blocker`,
`warning` for `suggestion`, `note` for `nit`) and `partialFingerprints` for
de-duplication across re-scans.

### Self-hosted runners

`skill-scanner` shells out to a few standard tools when scanning:

- `node` (>=20) — required for the scanner itself
- `git` — required for `skills.sh` GitHub-URL targets
- `osv-scanner` — optional; enables the R8 SBOM/CVE module when present on `$PATH`

The action installs `node` automatically; on self-hosted runners ensure
`git` is available and (optionally) install `osv-scanner` to unlock R8.

### Pinning the action version

Pin to a tagged release (`@v1`) for stability, or to a SHA for auditability:

```yaml
- uses: JoeShi/skill-scanner/action@v1                        # major-version pin
- uses: JoeShi/skill-scanner/action@7f1e0a4c0d...             # sha pin (audited)
```

Major-version tags follow semver: `v1` tracks the latest `1.x` release.

## §7 Roadmap

`skill-scanner` follows a small-step, ship-first cadence — every section below corresponds to a tracked task. Items move only when an artifact lands in `main`, not when one is promised.

### v0.1 (current)

- ✅ Scanner core (R0–R8) + Semgrep AST runner
- ✅ Custom-ruleset C1 (schema validation) + C2 (origin stamping) + C3 (severity-asymmetry merge)
- ✅ R12 / R12-bis / R13 — `installer.type` + `installer.command` + `env` block-list
- ✅ Marketplace adapters: local · `skills.sh` (GitHub) · ClawHub (REST API + redirect-following)
- ✅ Reporters: terminal · JSON · markdown · SARIF 2.1.0
- ✅ GitHub Action + CI workflow
- ✅ R0–R13 + C1–C5 spec docs

### v0.2 (next)

- C4 trust policy CLI flag (`--ruleset-trust-policy=signed|warn|allow`) wired end-to-end with sigstore verifier
- C5 reject Semgrep `${...}` template-expansion in `rule.message`
- ESLint custom rule asserting every scanner finding carries a `ruleOrigin`
- Self-test fixtures — 16 poisoned-skill samples (one per R-rule trigger) + cross-reference into the research-lane timeline
- ClawHub adapter network hardening — HTTPS-only redirects, SSRF allowlist, response size cap (per Gatekeeper post-merge review)
- R8 SBOM/CVE module — wire `osv-scanner` integration end-to-end
- `bin/skillchk` shebang + `npm publish` workflow + GitHub Releases automation
- README §3 / §4 examples updated against live ClawHub fixtures

### v1.x (after v0.2)

- VS Code Marketplace adapter (manifest-format adapter for non-`SKILL.md` packages)
- npm-MCP and PyPI-MCP marketplace adapters
- Slopsquatting / dependency-name novelty checks
- Reputation signal (publisher download count / vouch chains) as a non-overriding signal in reports

### v2 (research)

- LLM-based semantic review of `SKILL.md` to address the natural-language prompt-injection gap (see §2 known limits)
- Cross-file taint analysis (`ts-morph` post-processor or Semgrep pro-mode) for dynamic path / host construction
- Native FFI detection (`node-ffi-napi` → OS security frameworks)
- Optional sandboxed dynamic execution as an off-by-default *deep-scan* mode

Every item has a corresponding entry in the channel task board; check `slock task list` (or the GitHub issue board once mirrored) for current status and owner.

## §8 Contributing

`skill-scanner` is open source under [MIT](LICENSE). Distribution is via **npm + GitHub Releases only** — there is no SaaS, no enterprise paid tier, in v1.

### Where things live

| Topic | Location |
|---|---|
| Source | <https://github.com/JoeShi/skill-scanner> |
| Issues / discussion | GitHub Issues + Discussions |
| Architecture decisions | [`docs/adr/`](docs/adr/) — every significant change ships an ADR |
| Living scanner-rule index | [`packages/core/docs/scanner-rules.md`](packages/core/docs/scanner-rules.md) |
| Custom-ruleset security spec | [`docs/specs/custom-ruleset-security.md`](docs/specs/custom-ruleset-security.md) |
| Self-test fixtures spec | [`docs/specs/self-test-fixtures.md`](docs/specs/self-test-fixtures.md) |

### How we work

This project follows a **ship-first / no-promise-without-delivery** working model:

- Surface intent only when an artifact (commit / PR / file path) is also being shipped in the same message.
- Long "silent draft" windows are discouraged; if a piece of work needs more than ~60 minutes of background time, surface a stub commit first and iterate via follow-up PRs.
- Every PR runs `git diff main..HEAD --stat` self-check before opening; documentation-only PRs should land with **near-zero deletions**.
- Custom-ruleset writing follows the same C1–C5 invariants as the scanner enforces — your ruleset YAML cannot impersonate `core` origin or downgrade core severities.
- New rules are **spec-first**: add the rule entry to `packages/core/docs/scanner-rules.md` (with category, severity, evidence shape) before opening the implementation PR.

### Sending a change

1. Open an issue describing the rule / module / adapter you want to add (skip for typo-level fixes).
2. Branch from `main`. Add or update tests — the project ships `vitest` and expects every scanner module to have unit tests + at least one positive (clean) and one adversarial (poisoned) fixture.
3. Run `npm run lint && npm run typecheck && npm test` locally.
4. Open the PR with a one-line summary line in the form `feat(R12): <change>` / `fix(reporter): <change>` / `docs(roadmap): <change>`.
5. Reviewers run a final `git diff main..HEAD --stat` sanity check before merge.

### Reporting a security issue

If you find a vulnerability in `skill-scanner` itself (not in a skill it scanned), please **don't open a public issue**. Email the maintainer or open a private security advisory on GitHub.

### License

[MIT](LICENSE) © 2026 Joe Shi and contributors

---

<sub>Section ownership: §1 §2 §7 §8 — Maya · §3 §4 — KimiCoder · §4.3 §6 — Gatekeeper · §5 — Jack. The README is a living document; PRs that update one section without touching others are encouraged.</sub>
