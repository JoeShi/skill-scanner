# Custom Ruleset Security — P0 Design Constraints

> Status: **STUB v0.1** — full spec to land via follow-up PR.
> Source: Slock #skill-security-scanner msg 41b39e76 (Gatekeeper) +
> 3b6ba5ac (Maya fold) + dab0ea89 (Arch ratify).

## Problem

`skillchk --ruleset=./my-rules.yml` lets users supply Semgrep rules outside
the core `@skill-scanner/core` ruleset. This is also a **scanner-on-scanner
attack surface**: a malicious ruleset can:

1. Mark all real findings as `P2` (silent severity downgrade)
2. Inject noise rules that drown real findings
3. Embed prompt-injection in the `message` field, attacking any downstream
   LLM-based reviewer
4. Spoof `rule_origin` to look like core

## P0 design constraints (must land in v0.1)

### C1 — Schema validation on load

Every loaded ruleset must pass shape validation before any rule runs:

- `id` matches `^[a-z][a-z0-9-]*$` (no special chars to spoof core IDs)
- `severity` is exactly one of `P0` / `P1` / `P2`
- `tier` is exactly one of `blocker` / `suggestion` / `nit`
- `paths` (if present) is a string array
- `message` is plain string ≤ 2000 chars; markdown allowed but **no template
  expansion against scanner-internal context**
- Any unknown top-level field → reject (strict mode)

Implementation: `zod` or `ajv` schema in `@skill-scanner/core`.

### C2 — `rule_origin` distinct in every Finding

```typescript
ruleOrigin: 'core' | `custom:${string}`;
```

- `'core'` is reserved for rules shipped in `packages/core/rules/`
- `'custom:<path>'` records the absolute path to the ruleset file at load time
- Custom rules that try to set `ruleOrigin: 'core'` are silently rewritten to
  `custom:<path>` during the merge step

This lets users (and downstream tools) distinguish core findings from
user-supplied findings in any report format.

### C3 — Severity asymmetry: custom can upgrade, never downgrade core

Merge logic in `@skill-scanner/core`:

```
finalSeverity(coreFinding, ...customFindings) =
   max(coreFinding.severity, ...customFindings.severity)   // P0 > P1 > P2

custom-only finding   → keeps custom severity (any value)
core finding present  → custom can only raise severity, never lower it
```

This blocks the silent-downgrade attack: even if `evil.yml` declares P2 for
the same skill code that core marks P0, the merged finding stays P0.

### C4 — Trust policy gates loading

Three trust modes (per Arch dab0ea89):

```
--ruleset-trust-policy=signed  (enterprise)
   → reject ruleset without valid sigstore / PGP signature

--ruleset-trust-policy=warn    (v1 default)
   → load unsigned but emit console.warn + finding flag
     `ruleset_signature: unverified` on every report

--ruleset-trust-policy=allow   (dev mode only)
   → load any, no warning

Default = `warn`.
```

### C5 — No template expansion against internal context

Custom rule `message` strings must not be interpolated against scanner state.
e.g. a custom rule cannot emit `"matched ${process.env.HOME}"` — only literal
strings + Semgrep metavars expand.

This blocks prompt-injection attacks that try to leak host info via report
text.

## Reporting on ruleset trust

Every `ScanReport` includes:

```typescript
rulesetMeta: {
  core: { version: string, fileHash: string };
  customs: Array<{
    path: string;
    fileHash: string;
    signatureVerified: boolean;
    findingsContributed: number;
  }>;
}
```

Allows downstream consumers (CI / human review) to see exactly which rulesets
contributed which findings — full trace, no implicit trust.

## TODO

- [ ] Implement zod schema in `packages/core/src/ruleset-loader.ts`
- [ ] Implement merge with severity invariant in `packages/core/src/finding-merge.ts`
- [ ] Add tests: malicious ruleset fixtures that try each attack (downgrade /
      noise injection / origin spoof / message template) and assert merge
      result is safe
- [ ] sigstore signature verifier (likely v0.2 enterprise tier)
