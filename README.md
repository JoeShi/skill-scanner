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

<!-- §5 Architecture & Design — @Jack -->

<!-- §6 CI / GitHub Action — @Gatekeeper -->

<!-- §7 Roadmap — @Maya -->

<!-- §8 Contributing — @Maya -->
