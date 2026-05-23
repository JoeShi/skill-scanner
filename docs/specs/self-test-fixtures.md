# Self-Test Fixtures — `skillchk --self-test`

> Status: **STUB v0.1** — full spec to land via follow-up PR.
> Source: Slock #skill-security-scanner msg 41b39e76 (Gatekeeper) +
> 3b6ba5ac (Maya fold) + dab0ea89 (Arch ratify).
> Origin: QuickPort retrospective rule "shape-of-the-real-target tests"
> (Slock #dev msg 22354aaf), productized as a CLI feature.

## Why

A skill scanner is itself a piece of software running on user machines. If a
supply-chain attacker compromises the scanner binary or one of its npm
dependencies, the scanner can silently report "skill is clean" while real
threats pass through — defeating the whole point.

`skillchk --self-test` lets the user verify, on their own machine, that the
scanner is actually working as advertised. It scans known-poisoned fixtures
that ship with the package and asserts every expected R-rule fires.

## How it works

```
skillchk --self-test
   ↓
Loads packages/core/examples/poisoned-skill/<rule-id>/
for each rule R0..R11:
   1. Run scanner against the matching minimal fixture
   2. Assert: at least one finding with ruleId matching R<n>
   3. Assert: finding.tier matches expected baseline (blocker / suggestion)
Output:
   ✓ R0 manifest validation — 3 expected findings emitted
   ✓ R1 network domain diff — 1 expected finding emitted
   ✗ R2 fs path diff — expected ≥1 P0, got 0   ← FAIL if scanner is broken
   ...
Exit code: 0 = all good, 1 = at least one expected finding missing
```

## Fixture layout

```
packages/core/examples/
├── clean-skill/                   ← reference clean skill, must produce 0 findings
│   ├── manifest.json
│   ├── index.js                   ← well-formed, declares only what it uses
│   └── README.md
└── poisoned-skill/
    ├── R0-bad-manifest/           ← missing required fields, invalid semver
    ├── R1-undeclared-domain/      ← fetch('https://evil.com') without manifest entry
    ├── R2-fs-write-sensitive/     ← writeFileSync('~/.ssh/...')
    ├── R2-fs-write-outside/       ← writeFile outside ~/.quickwork/<skill>/
    ├── R3-spawn-undeclared/       ← child_process.spawn without declaration
    ├── R5-keychain-direct/        ← require('keytar').setPassword
    ├── R5-mcp-config-direct/      ← writeFileSync('~/.quickwork/mcp_config.json')
    ├── R5-cap-registry-direct/    ← writeFileSync('.../capability-registry.json')
    ├── R6-aws-key-hardcoded/      ← AKIA*** literal in source
    ├── R6-github-token-hardcoded/ ← gh[pousr]_*** literal
    ├── R6-private-key-block/      ← -----BEGIN PRIVATE KEY----- block
    ├── R7-eval-call/              ← eval(userInput)
    ├── R7-bis-shell-injection/    ← exec(`curl ${x}`)
    ├── R7-dynamic-require/        ← require(varName)
    └── R8-cve-vulnerable-dep/     ← package.json with CVSS≥7 dependency
```

Each `R*-*/` directory is a **minimal** fixture: smallest possible code that
triggers exactly one rule, no other rules. Keeps self-test diagnostic clear:
"R5-keychain-direct fixture failed → R5 module is broken."

## When to run

- **CI / GitHub Actions**: every PR runs `skillchk --self-test` as a smoke
  test. If self-test fails, scanner is broken, block merge.
- **First install**: README recommends `npx skillchk --self-test` after
  install to verify integrity of the installed binary.
- **Periodic**: enterprise users may schedule weekly self-test runs as part
  of supply-chain hygiene.

## Anti-tampering note

`skillchk --self-test` is **not** a defense against an attacker who has full
control of the scanner binary — a sufficiently sophisticated attacker can
patch the assertion logic to always pass. It is a defense against:

- Accidental regressions (rule modules getting commented out, broken)
- Lazy supply-chain attacks (typo-squat package that ships a stub scanner)
- Outdated installs (user has v0.1, R6 fixture only added in v0.2 → fixture
  missing → user knows they're behind)

For stronger anti-tampering, see signed reports + ruleset signature
verification (`docs/specs/custom-ruleset-security.md` C4).

## TODO

- [ ] Build out 16 minimal poisoned-skill fixtures (one per rule slot)
- [ ] `packages/core/src/self-test.ts` runner with per-rule expected counts
- [ ] CI workflow `.github/workflows/self-test.yml` runs on PR + main
- [ ] README quick-start: `npx @skill-scanner/cli --self-test` after install
