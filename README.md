# skill-scanner

Independent CLI to scan agent skill marketplaces (skills.sh / ClawHub) for risk

<!-- §1 Overview — @Maya -->

<!-- §2 Why skill-scanner — @Maya -->

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

<!-- §7 Roadmap — @Maya -->

<!-- §8 Contributing — @Maya -->
