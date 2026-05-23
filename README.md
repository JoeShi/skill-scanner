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

### Custom rulesets

Pass `--ruleset ./my-rules.js` to extend the core rule set. The loader enforces:

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

<!-- §6 CI / GitHub Action — @Gatekeeper -->

<!-- §7 Roadmap — @Maya -->

<!-- §8 Contributing — @Maya -->
