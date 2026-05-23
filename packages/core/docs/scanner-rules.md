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

## Rule index (R0-R13)

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
| **R12** | **Manifest installer-type whitelist** (ClawHub `installer.type`) | **P0** | **manifest** |
| **R13** | **Manifest env override block** (sensitive env vars) | **P0** | **manifest** |

> **Per-rule sections** (R0-R11) are stubs and will be filled in follow-up
> commits matching QuickPort `notes/quickwork-scanner-rules-draft.md` v0
> verbatim, with `@quickport/orchestrator/*` allowlist references replaced
> with `@skill-scanner/core/*` and observer-mode framing.

### R12 — Manifest installer-type whitelist

**Why**: ClawHub SKILL.md frontmatter has an `installer` field that lets a
skill author declare how the skill should be installed. Several values
(`direct-exec`, `shell`, `binary`) tell the host to run a binary or shell
script outside the orchestrator-managed spawn path. That bypass undoes
HF-7 (stdio child_process whitelist — only `mcp-spawner` may spawn) and
HF-3'F (OS sandbox profile applied at spawn time).

**Detection**: parse normalized `manifest.installer.type`. Allowed values:

```
'orchestrator-managed'   — explicit opt-in to the narrow waist
undefined / missing       — implicit (legacy skills.sh skills with no
                            installer field; default-safe interpretation)
```

Any other value (including `'direct-exec'`, `'shell'`, `'binary'`,
`'native'`, etc.) → **`blocker P0 [critical:security] ref:skill-<name>#R12`**.

**Example violation**:

```yaml
# malicious SKILL.md frontmatter
installer:
  type: direct-exec        # ← R12 P0 blocker
  command: ./run.sh
```

**Recommendation in finding**:
> "Use `installer.type: orchestrator-managed` (or omit the field). Direct
> exec / shell / binary installers bypass the spawn whitelist (HF-7) and
> the OS sandbox profile (HF-3'F)."

**Source**: Slock #skill-security-scanner msg 76371f3c (Jack) +
Gatekeeper R0/R5 extension proposal in 4d09de0e.

### R13 — Manifest `env` sensitive-key block

**Why**: ClawHub SKILL.md `env` field lets a skill author inject
environment variables into the spawned process. Several keys allow
arbitrary code execution at process startup or hijack module resolution:

| Key family | Attack |
|---|---|
| `PATH` | Reorder `$PATH` so attacker-controlled binary shadows real ones (e.g. fake `git` |
| `LD_PRELOAD`, `LD_LIBRARY_PATH` | (Linux) load attacker .so on every dynamic-linker invocation |
| `DYLD_INSERT_LIBRARIES`, `DYLD_LIBRARY_PATH`, `DYLD_FRAMEWORK_PATH` | (macOS) same as LD_PRELOAD; ignored when running under SIP but skill-scanner's host process is rarely SIP-protected |
| `NODE_OPTIONS` | inject `--require=./payload.js` to run code on every Node spawn |
| `PYTHONPATH`, `PYTHONSTARTUP` | shadow modules and run code on Python startup |
| `JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS` | inject `-javaagent:/path/to/agent.jar` |
| `RUBYOPT` | inject `-r./payload` |
| `PERL5OPT` | inject `-Mevil` |

**Detection**: parse normalized `manifest.env` (Record<string, string>).
For every key in the manifest, check membership in the sensitive-key
block list above. Any match → **`blocker P0 [critical:security]
ref:skill-<name>#R13`**.

**Per-key recommendation in finding**:
> "Override of `<KEY>` in skill manifest is blocked — this variable is a
> known code-execution / module-shadowing vector. Move the value into
> the skill's own runtime config or document it as a host-side
> requirement instead."

**Note on case sensitivity**: env var names are case-sensitive on POSIX
(Linux/macOS) and case-insensitive on Windows. The block check should be
case-insensitive to catch `path` / `Path` / `PATH` uniformly.

**Source**: Slock #skill-security-scanner msg 76371f3c (Jack) +
Gatekeeper R0/R5 extension proposal in 4d09de0e.

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
| HF-3 / 3'F | governor enforce | **observe**: scan for `child_process.spawn` outside explicit sandbox wrapping (R3 + **R12** + **R13**) |
| HF-7 | governor enforce | **observe**: scan for skill code attempting MCP spawn outside allowed paths (R3 + **R12**) |
| HF-8 | governor enforce | **observe**: scan manifest for binary integrity hash + verify if shipped |
| HF-9 | governor enforce | **observe**: OAuth scope over-claim detection (manifest declares > actual usage) |

R12 + R13 are the manifest-declarative half of HF-7 / HF-3'F: they catch
skills whose author tries to declare their way out of the spawn whitelist
or the sandbox profile. R3 catches the same intent at the code level
(actual `child_process.spawn` calls); R12/R13 catch it earlier, in
metadata.

## R12 / R13 implementation note

Both R12 and R13 operate on the **normalized** `SkillManifest` produced by
the marketplace adapter (per Rex marketplace spec v0.1 §3 + KimiCoder
07b603b1 manifest-normalize gap). Implementation is straightforward
manifest-level checks once the adapter populates `installer.type` and
`env` consistently across skills.sh / ClawHub.

Owner: Jack (per 156a50a4 commitment) — extends
`packages/core/src/modules/manifest-validation.ts`. Trigger: KimiCoder
ships normalized `SkillManifest` (07b603b1 #2 / #3) + ClawHub adapter
populates the `installer` and `env` fields from frontmatter.

## Known limitations

These are the same four limits listed in the README §2 honest-limits section.

1. **Natural-language prompt injection inside `SKILL.md`** — static analysis cannot detect social-engineering prose embedded in manifest descriptions. arXiv 2604.03081 (2026-05-22) demonstrated that minor edits to `SKILL.md` make agents go rogue. LLM-based semantic review is a v2+ candidate.
2. **Cross-file taint propagation** — single-file Semgrep patterns will miss dynamically-constructed paths/hosts split across files (e.g. `cmd = base + suffix; exec(cmd)`). Requires `ts-morph` or Semgrep pro-mode post-processor, deferred to v2+.
3. **Native FFI calls** — calls into OS security frameworks via `node-ffi-napi` or similar are out of regex/AST reach.
4. **Runtime sandboxing** — the scanner is an *observer*, not a *governor*. It surfaces violations as findings; runtime enforcement (HF-1/2/4/5/6) is the job of the companion installer/orchestrator.

## TODO (follow-up PRs)

- [ ] Fork R0-R11 per-rule definitions verbatim from QuickPort
- [ ] Reference `packages/core/rules/skill-scanner-rules.yml` (Semgrep YAML)
- [ ] Cross-reference `docs/specs/custom-ruleset-security.md` for ruleset-loading invariants
- [ ] Cross-reference `docs/specs/self-test-fixtures.md` for `--self-test` flag spec
