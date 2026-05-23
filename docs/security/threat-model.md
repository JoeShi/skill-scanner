# Threat Model — Agent Skill Poisoning & skill-scanner Coverage

> **Purpose**: Living document mapping real-world agent-skill poisoning
> incidents to `skill-scanner` rules (R0–R13, custom ruleset constraints
> C1–C5). Updated when new public incidents land or new rules ship.
>
> **Audience**: contributors evaluating proposed rules, security reviewers
> deciding whether to trust a skill, and downstream consumers reading
> `skillchk` findings.
>
> **Source-of-truth for rule definitions**: see
> [`packages/core/docs/scanner-rules.md`](../../packages/core/docs/scanner-rules.md)
> (R0–R13) and [`docs/specs/custom-ruleset-security.md`](../specs/custom-ruleset-security.md)
> (C1–C5).

## 1. Known attack vectors (sorted by scanner priority)

The vectors below are ordered by how much surface area they expose and how
many incidents in §2 have exploited them. Each vector lists the rule(s)
that observe it; rules marked **stub** are scheduled in
[`packages/core/docs/scanner-rules.md`](../../packages/core/docs/scanner-rules.md)
but not yet implemented in `packages/core/src/modules/`.

| # | Vector | What the attacker does | Rules |
|---|---|---|---|
| 1 | **Token / credential exfiltration** | call to attacker domain that wasn't in the manifest's declared network capabilities | R1 (network-domain-diff) + R6 (secrets-scan) |
| 2 | **Sensitive filesystem read or write** | `~/.ssh/`, `~/.aws/`, `~/Library/Keychains/`, `/etc/`, OS keychain accessor APIs | R2 (fs-write-sensitive + fs-read sub-rules) |
| 3 | **Unauthorized child process spawn** | `child_process.spawn` / `subprocess.Popen` outside the orchestrator-managed path | R3 (process-spawn-diff) |
| 4 | **Narrow-waist bypass** | direct write of `mcp_config.json`, direct keychain calls, anything that should route through governor APIs | R5 (narrow-waist-bypass) |
| 5 | **Hardcoded secrets / credentials** | committed AWS keys, GitHub tokens, private keys, JWT secrets | R6 (secrets-scan) |
| 6 | **Dangerous JS/Python APIs** | `eval`, `Function()`, `vm.runInThisContext`, shell injection in `exec`/`spawn`, dynamic `require()` of user-controlled paths | R7 (eval-exec-inject + shell-injection + dynamic-require) |
| 7 | **Vulnerable dependency** | imports a package version with a known CVE; transitive deps on slopsquatting names | R8 (sbom-cve, **stub — osv-scanner integration scheduled for v0.2**) |
| 8 | **Manifest installer-type bypass** (ClawHub-specific) | `installer.type: direct-exec / shell / binary / native` — bypasses spawn whitelist + sandbox profile | R12 (manifest installer-type whitelist) |
| 8a | **Manifest installer-script abuse** (R12-bis) | `installer: { type: script, script: <inline shell> }` — same outcome via the script subkey, escaping the type-whitelist | R12-bis (manifest installer-script regex / shell-detection) |
| 9 | **Manifest env injection** (ClawHub-specific) | `env: { LD_PRELOAD: '...' }` or `NODE_OPTIONS: '--require=./payload.js'` — runs attacker code at process start | R13 (manifest env block list) |
| 10 | **Capability over-claim** | manifest declares `network: ['*']` to dodge R1, then makes specific exfil calls | R9 (capability completeness — over-claim detection) |
| 11 | **Stale-version replay** | a previously-scanned skill ships a backdoor in the next version, but cache says "already scanned" | R10 (skill version freshness gate) |
| 12 | **Custom-ruleset attack on the scanner itself** | a user-supplied ruleset downgrades core findings, injects noise, or impersonates `rule_origin: 'core'` | C1–C3 (custom ruleset security constraints in [`docs/specs/custom-ruleset-security.md`](../specs/custom-ruleset-security.md)) |
| 13 | **Manifest prompt injection** | natural-language prompt-injection text in the SKILL.md description that flips an LLM-based reviewer's verdict | **NOT covered by R0–R13** — see §4.1 |
| 14 | **Dynamic-context bypass** | skill executes via dynamic-context commands before the host model evaluates the skill at all | **Out-of-scope (host-side)** — see §4.5.1 |
| 15 | **Slopsquatting** (AI-hallucinated package name) | typosquatting tuned for names that LLMs commonly generate but aren't real packages | partial (R8 typo lists), **dependency-novelty check scheduled for v1.x** — see §4.5.2 |


## 2. Industry incident timeline (2024-03 → 2026-05)

> Companion document with full per-event detail, screenshots and source URLs:
> Feishu doc — *Agent Skill 投毒事件 Timeline & QuickPort Scanner 防护映射 v0.1.1*
> (`https://www.feishu.cn/docx/BUxqd9I6vomRV0xuActcVZl9njZ`).
> The table below is the grep-able digest. Each row's "Rule(s)" column lists
> the `skill-scanner` rule(s) that would observe (or fail to observe) the
> attack, given the same artifact today.

| Date | Incident | Platform | Scale | Vector | Rule(s) |
|---|---|---|---|---|---|
| 2024-03 | ChatGPT plugin OAuth scope abuse | OpenAI plugins | ecosystem-wide | R0 manifest scope spoofing | R0 |
| 2025-07 | Malicious Solidity extensions | Cursor / Open VSX | ~$500K crypto stolen | R6 private-key exfil + ecosystem-context | R6 (R-context check is v2 candidate) |
| 2025-09 | **Postmark-MCP** email theft (first malicious MCP server) | npm + MCP | 1,500 weekly DLs | R1 + R6 (BCC injection) | R1, R6 |
| 2025-10 | **GlassWorm** (worm) | npm / PyPI / VS Code | multi-ecosystem | R7 obfuscated code + R8 dependency hijack | R7, R8 (R8 stub) |
| 2025-10 | GitHub Copilot PR injection | GitHub | private repos exposed | manifest prompt injection | **uncovered** — see §4.1 |
| 2025-10 | Sneaky Mermaid (M365 Copilot indirect prompt injection) | Microsoft 365 | enterprise mail | indirect prompt injection | **uncovered** — see §4.1 |
| 2026-01 | **CursorJack** single-click RCE via deeplinks | Cursor IDE | RCE on click | unannounced URL handler / deeplink schema | R0 + new sub-rule (declared URL handlers) |
| 2026-01 | Claude Code CVE-2026-21852 | Claude Code | API key exfil | R6 + R1 | R6, R1 |
| 2026-02 | **ClawHavoc** — 341 (later 824+) malicious ClawHub skills | ClawHub (OpenClaw community) | mass marketplace | R0 + R7 + R3 | R0, R3, R7 |
| 2026-02 | **Snyk ToxicSkills** study | ClawHub | 36.8% of skills flagged | R0 + R7 manifest taint | R0, R7 |
| 2026-02 | **Straiker** report | ClawHub | 71 / 3,505 malicious + 73 high-risk | R0 + R6 token exfil | R0, R6 |
| 2026-03 | **GlassWorm** GitHub stolen-token campaign | GitHub / PyPI | Python ecosystem | R6 + R8 | R6, R8 (stub) |
| 2026-03 | **LiteLLM** trojanized v1.82.7/8 | PyPI | credential harvesting + k8s lateral | R6 + R8 | R6, R8 (stub) |
| 2026-03 | **SentinelOne**: Claude Code executes zero-day via trojanized LiteLLM | Claude Code | autonomous attack chain | downstream of R6+R8 failure | R6, R8 (stub) |
| 2026-03 | **RoguePilot** — Copilot token theft via symlink + JSON `$schema` | GitHub Codespaces | private repos | R2 fs-read + symlink-following | R2 (sub-rule scheduled) |
| 2026-04 | **OX Security MCP "by-design" RCE** | ~200,000 MCP servers, 10 CVEs, 9 marketplaces | systemic | protocol-design RCE | R3 + scanner-host HF-7 spawn whitelist + HF-3'F sandbox |
| 2026-04 | **30 ClawHub cryptomining skills** by single author | ClawHub | bypassed moderation | R3 + capability over-claim | R3, R9 |
| 2026-05-11 | **Mini Shai-Hulud worm** (TanStack) | npm + PyPI | 170+ packages, CVSS 9.6 — OpenAI / Mistral / GitHub / Grafana | R8 + GitHub Actions OIDC abuse | R8 (stub — high-priority for v0.2) |
| 2026-05-18 | **Nx Console** VS Code extension → 3,800 GitHub internal repos breached | VS Code Marketplace | data offered for $50K-$95K | R5 narrow-waist + R6 token storage | R5, R6 |
| 2026-05 | **Datadog**: dynamic-context-command bypass | coding agent skills | model-level prompt-injection defense bypassed | dynamic-context bypass | **out-of-scope (host-side)** — see §4.5.1 |
| 2026-05 | **SentinelOne + Prompt Security**: Claude Code dependency hijack via marketplace skills | Claude Code marketplace | PoC | manifest dependency vs actual install diff | R8 + R1 |
| 2026-05 | **MCP SDK systemic vulnerabilities** (multi-SDK) | All MCP SDKs | architectural | protocol layer | scanner host-side HF-7 |
| 2026-05-22 | **arXiv 2604.03081** — SKILL.md natural-language prompt injection | All skill ecosystems | research disclosure | manifest prompt injection | **uncovered** — see §4.1 |

## 3. Coverage matrix — what skill-scanner does and does not catch

### 3.1 Strong coverage

These rules are implemented in `packages/core/src/modules/` and exercised
by the existing test suite. Each row cites the §2 incident that motivates
the rule.

| Vector | Rule | Module | Motivating incident(s) |
|---|---|---|---|
| Token / credential exfil | R1 + R6 | `network-domain-diff.ts` + `secrets-scan.ts` | Postmark-MCP (2025-09), Nx Console (2026-05), RoguePilot (2026-03), LiteLLM (2026-03), CVE-2026-21852 (2026-01) |
| Sensitive FS write/read | R2 | `fs-diff.ts` | Solidity ext (2025-07), RoguePilot (2026-03) |
| Process spawn unauthorized | R3 | `process-spawn.ts` | OX MCP (2026-04), GlassWorm (2025-10), 30 ClawHub crypto miners (2026-04) |
| Narrow-waist bypass | R5 | `narrow-waist-bypass.ts` | Nx Console (2026-05) |
| Hardcoded secrets | R6 | `secrets-scan.ts` | LiteLLM, Postmark-MCP, CVE-2026-21852 |
| Eval / shell injection | R7 | `dangerous-api.ts` (incl. `R7-bis-shell-injection`, `R7-dynamic-require`) | GlassWorm (2025-10), Mini Shai-Hulud (2026-05) |
| Manifest declarations | R0 | `manifest-validation.ts` | ClawHavoc (2026-02), Straiker (2026-02), ToxicSkills (2026-02), all marketplace mass campaigns |
| Capability over-claim | R9 | `manifest-validation.ts` | 30 ClawHub crypto miners (2026-04) |
| Manifest installer-type bypass | R12 + R12-bis | `manifest-r12-r13.ts` (R12) + `manifest-r12-bis.ts` (R12-bis), shipped in `430e7b1` (PR #9) and `8b2c349` (PR #11); 39 tests across `manifest-r12-r13.test.ts` + `manifest-r12-bis.test.ts` | ClawHub manifest schema enables direct-exec installers; R12-bis covers shell-script installers |
| Manifest env injection | R13 | `manifest-r12-r13.ts`, shipped in `430e7b1` (PR #9); covered by `manifest-r12-r13.test.ts` | ClawHub manifest schema enables PATH / LD_PRELOAD / NODE_OPTIONS injection |

### 3.2 Stub coverage (scheduled, not yet implemented)

| Vector | Rule | Status | Why it matters |
|---|---|---|---|
| Vulnerable dependency / CVE | R8 (osv-scanner integration) | **stub — scheduled for v0.2** | Mini Shai-Hulud (CVSS 9.6, OpenAI/Mistral/GitHub) and LiteLLM trojanized are direct dependency-CVE incidents the stub does not catch yet |
| Skill version freshness re-scan | R10 | gate-only | every R8 incident illustrates a single version going from clean to malicious |
| MCP `server.listOfferings()` runtime diff | R11 | deferred | covers runtime drift, not static |
| IPC endpoint diff | R4 | v2 D-mode | not yet a public incident, but designed for the eventual D-mode threat model |

### 3.3 Custom-ruleset constraints (scanner-on-scanner attack surface)

`skillchk --ruleset=./my-rules.yml` lets users supply rules. These five
constraints (defined in [`docs/specs/custom-ruleset-security.md`](../specs/custom-ruleset-security.md))
keep the scanner itself trustworthy:

| ID | What it prevents |
|---|---|
| C1 | malformed or unknown-field rulesets passing schema validation |
| C2 | a custom rule impersonating `rule_origin: 'core'` |
| C3 | a custom rule **downgrading** a core finding's severity (custom can upgrade, never downgrade) |
| C4 | unsigned rulesets loading silently (default `--ruleset-trust-policy=warn`) |
| C5 | Semgrep template-expansion against scanner-internal context |

## 4. Known limitations / v2+ deferred

The static-analysis approach R0–R13 takes has firm ceilings. We declare
them explicitly — same four limits as
[`README.md` §2 honest-limits](../../README.md#2-why-skill-scanner--the-threat-landscape)
and [`packages/core/docs/scanner-rules.md` §Known limitations](../../packages/core/docs/scanner-rules.md#known-limitations) —
so users (and downstream LLM reviewers) don't develop false confidence.

### 4.1 Natural-language prompt injection inside `SKILL.md`

A skill author writes innocuous-looking prose in `SKILL.md` that contains
a prompt-injection payload aimed at any LLM-based reviewer or any agent
that loads the skill. arXiv 2604.03081 (2026-05-22) demonstrated that
"minor edits to `SKILL.md` make agents go rogue", and the attack
survives regex / AST static analysis intact.

- **Why R0–R13 cannot catch it**: the malicious payload is well-formed
  English. Regex and AST scanners cannot distinguish "trigger-phrases for
  the agent's loader" from "instructions that subvert the user's intent".
- **v2+ path**: LLM-based semantic review of `SKILL.md` prose (separate
  model from the host agent, run before the skill is approved).
- **Related incidents**: Sneaky Mermaid (M365 Copilot, 2025-10), GitHub
  Copilot PR injection (2025-10).

### 4.2 Cross-file taint propagation

Single-file Semgrep patterns miss dynamically-constructed paths and hosts
that are split across files (e.g. `cmd = base + suffix; exec(cmd)` where
`base` and `suffix` are defined in different modules).

- **Why R0–R13 cannot fully catch it**: each Semgrep rule operates on a
  single file. Cross-module data flow requires a project-wide AST or a
  Semgrep pro-mode post-processor.
- **v2+ path**: `ts-morph` cross-file taint pass or Semgrep pro-mode.

### 4.3 Native FFI calls

Native FFI bindings (`Security.framework` on macOS,
`NCryptOpenStorageProvider` on Windows, etc.) accessed via Node's
`node-ffi-napi` or Python's `ctypes` can read sensitive material in ways
that regex scanners miss. The OX Security MCP RCE (2026-04) implies this
surface is in attacker scope.

- **v2+ path**: FFI-binding allowlist + cross-file taint propagation
  (overlaps with §4.2).

### 4.4 Runtime sandboxing — the scanner is an *observer*, not a *governor*

`skill-scanner` surfaces violations as findings; it does not enforce
runtime invariants. The companion installer / orchestrator
(QuickPort's HF-1/2/4/5/6 in QuickPort's threat model) is the runtime
governor that actually denies a spawn / a write / an outbound connection.

- **Why this matters for users**: a `[blocker]` finding from
  `skill-scanner` means "the host should refuse to install this skill".
  If the host installs it anyway, the scanner cannot stop the skill
  from running.
- **v2+ path**: `skill-scanner` will continue as an observer; runtime
  enforcement remains the orchestrator's responsibility.

### 4.5 Out-of-scope adjacent vectors (real but not in canonical limits)

These two vectors are real attacker techniques that have appeared in
2026 incidents, but they are **not** in the canonical R0–R13 ceiling
list because they sit at host-side protocol or registry-novelty layers,
not in the skill content the scanner inspects. Listed here so reviewers
of `skill-scanner` findings know to look for them separately.

#### 4.5.1 Dynamic-context-command bypass

Datadog disclosed (2026-05) that some agent platforms execute skill code
via *dynamic context commands* — code paths that run before the host LLM
ever evaluates the skill. Any prompt-injection or model-level safety
heuristic that depends on the LLM seeing the skill is bypassed by
construction.

- **Why this is host-side, not scanner-side**: this is an agent-platform
  protocol issue. Static analysis can flag a skill that *uses* known
  dynamic-context API calls, but it cannot change how the host
  executes the skill.
- **What `skill-scanner` could add (v2+ candidate)**: a sub-rule that
  flags use of well-known dynamic-context APIs (separate from R7's
  general dangerous-API list).

#### 4.5.2 Slopsquatting (AI-hallucinated package names)

LLMs frequently suggest package names that don't actually exist.
Attackers register the hallucinated name and ship malware. Standard
typosquatting distance algorithms miss this because the name isn't a typo
of any real package — it's a fresh name that statistically matches AI
generation patterns.

- **Why R8 stub doesn't fully catch it**: typosquatting lists are
  reactive and incomplete. The novelty signal (no historical downloads,
  registered recently, plausible AI-generated name) is a different
  detector class.
- **v1.x path**: dependency-novelty check combining registry age,
  download history, and an LLM-cross-validation heuristic
  (in [`README.md` §7 Roadmap v1.x](../../README.md#v1x-after-v02)).
- **Related incidents**: parts of Mini Shai-Hulud (2026-05) propagated
  through dev environments where AI-recommended package names were
  installed without verification.


## 5. References

### 5.1 In-repo

- [`packages/core/docs/scanner-rules.md`](../../packages/core/docs/scanner-rules.md) — R0–R13 canonical rule definitions
- [`docs/specs/custom-ruleset-security.md`](../specs/custom-ruleset-security.md) — C1–C5 custom-ruleset constraints
- [`docs/specs/self-test-fixtures.md`](../specs/self-test-fixtures.md) — 16 poisoned-skill fixtures spec
- [`packages/core/examples/vendor-allowlist-recommended.yml`](../../packages/core/examples/vendor-allowlist-recommended.yml) — vendor allowlist baseline

### 5.2 External — incidents

| Incident | Source |
|---|---|
| ClawHavoc 341 (Koi Security — canonical) | https://www.koi.ai/blog/clawhavoc-341-malicious-clawedbot-skills-found-by-the-bot-they-were-targeting |
| Snyk ToxicSkills | https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/ |
| Straiker — Built on ClawHub | https://www.straiker.ai/blog/built-on-clawhub-spread-on-moltbook-the-new-agent-to-agent-attack-chain |
| Postmark-MCP | https://thehackernews.com/2025/09/first-malicious-mcp-server-found.html |
| Postmark-MCP (Snyk advisory) | https://snyk.io/blog/malicious-mcp-server-on-npm-postmark-mcp-harvests-emails/ |
| OX Security MCP RCE | https://www.ox.security/blog/the-mother-of-all-ai-supply-chains-critical-systemic-vulnerability-at-the-core-of-the-mcp/ |
| Datadog dynamic-context bypass | https://securitylabs.datadoghq.com/articles/malicious-skills-supply-chain-risks-in-coding-agents-with-dynamic-context/ |
| SentinelOne — Marketplace dependency hijack | https://www.sentinelone.com/blog/marketplace-skills-and-dependency-hijack-in-claude-code/ |
| SentinelOne — Claude executing zero-day | https://www.sentinelone.com/blog/how-sentinelones-ai-edr-autonomously-discovered-and-stopped-anthropics-claude-from-executing-a-zero-day-supply-chain-attack-globally/ |
| Mini Shai-Hulud (Microsoft) | https://www.microsoft.com/en-us/security/blog/2026/05/20/mini-shai-hulud-compromised-antv-npm-packages-enable-ci-cd-credential-theft/ |
| Mini Shai-Hulud (OpenAI response) | https://openai.com/index/our-response-to-the-tanstack-npm-supply-chain-attack/ |
| Nx Console GitHub breach | https://thehackernews.com/2026/05/github-internal-repositories-breached.html |
| Nx Console (StepSecurity) | https://www.stepsecurity.io/blog/nx-console-vs-code-extension-compromised |
| 30 ClawHub crypto miners (The Register) | https://www.theregister.com/2026/04/29/30_clawhub_skills_mine_crypto/ |
| GlassWorm | https://www.malwarebytes.com/blog/news/2026/03/glassworm-attack-installs-fake-browser-extension-for-surveillance |
| GlassWorm — GitHub stolen tokens | https://thehackernews.com/2026/03/glassworm-attack-uses-stolen-github.html |
| LiteLLM trojanized | https://docs.litellm.ai/blog/security-update-march-2026 |
| LiteLLM (Cybernews) | https://cybernews.com/security/critical-litellm-supply-chain-attack-sends-shockwaves/ |
| CursorJack | https://www.proofpoint.com/us/blog/threat-insight/cursorjack-weaponizing-deeplinks-to |
| RoguePilot Copilot | https://orca.security/resources/blog/roguepilot-github-copilot-vulnerability |
| Solidity extensions (Kaspersky) | https://www.kaspersky.com/blog/malicious-extensions-for-cursor-ai/53802/ |
| Indirect prompt injection (Unit 42) | https://unit42.paloaltonetworks.com/indirect-prompt-injection-poisons-ai-longterm-memory |
| AIShellJack (arXiv) | https://arxiv.org/html/2509.22040v1 |
| arXiv 2604.03081 — SKILL.md prompt injection | https://arxiv.org/abs/2604.03081 |

### 5.3 External — marketplaces

- skills.sh (Vercel Labs): https://skills.sh/ , https://github.com/vercel-labs/skills , https://vercel.com/docs/agent-resources/skills
- ClawHub (OpenClaw community — **not** Anthropic official): https://clawdhub.com/ , https://clawdhub.mintlify.app/clawhub/http-api , https://github.com/openclaw/clawhub

### 5.4 Companion documents (Feishu — internal review)

- *Agent Skill 投毒事件 Timeline & QuickPort Scanner 防护映射 v0.1.1* — full per-event analysis with QuickPort/skill-scanner mapping
- *skill-scanner — Marketplace Adapter Spec v0.1 (skills.sh + ClawHub)* — adapter interfaces, REST endpoints, normalized SkillManifest

These two Feishu docs are the source-of-truth for the human-readable
analysis; this `threat-model.md` is the grep-able, version-controlled
counterpart in the repo.

## Changelog

- **v0.1.1** (this PR's revision, after Gatekeeper review 90a6e20f + nit fadc9ff3) —
  - Blocker fix: §3.1 R12/R13 status updated to "implemented in `430e7b1` (PR #9) + `8b2c349` (PR #11)" with test files cited, replacing the outdated "pending normalize" claim.
  - Blocker fix: §4 restructured to match the canonical 4-bullet limits in `README.md` §2 + `packages/core/docs/scanner-rules.md` §Known limitations (SKILL.md prompt injection / cross-file taint / native FFI / runtime sandboxing). Dynamic-context bypass + slopsquatting moved to a new §4.5 "Out-of-scope adjacent vectors" — they are real but not in the canonical list.
  - Suggestion fix: §3.2 R8 retag from v0.3 → v0.2 (matches `README.md` §7 Roadmap).
  - Nit fix (Gatekeeper fadc9ff3): two derivative R8 references at §1 row 7 and §2 row "Mini Shai-Hulud" also retagged v0.3 → v0.2 for consistency.
  - Suggestion fix: §1 split row #8 into row 8 (R12) + row 8a (R12-bis manifest installer-script abuse).
  - Suggestion fix: §5.2 dropped truncated Hacker News ClawHavoc URL; Koi Security URL kept as canonical.
  - Suggestion fix: §2 title widened to "2024-03 → 2026-05" to include the 2024-03 ChatGPT plugin OAuth row.

- **v0.1** (2026-05-23, initial commit) — initial release. Reflects R0–R13 spec
  (PR #8 / `d9b0dd9`). Catches up incidents through 2026-05-22 (arXiv
  2604.03081). Notes ClawHub identity correction
  (OpenClaw community, not Anthropic official) per fact-check on
  2026-05-23.
