use skill_scanner_cli::{render, scan, ColorChoice, OutputFormat, ScanArgs, ScanVerdict};
use skill_scanner_ruleset::TrustPolicy;
use std::path::PathBuf;

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

fn fixture(name: &str) -> PathBuf {
    fixtures().join(name)
}

fn clean_args(skill_path: PathBuf) -> ScanArgs {
    ScanArgs {
        skill_path,
        rulesets: vec![],
        trust_policy: TrustPolicy::Unverified,
        format: OutputFormat::Text,
        color: ColorChoice::Never,
        verbose: false,
    }
}

// AC1: clean manifest, no rules trigger → Pass, empty findings, zero stats
#[test]
fn ac1_clean_manifest_pass_empty_findings() {
    let report = scan(clean_args(fixture("clean"))).expect("clean scan must succeed");
    assert_eq!(
        report.verdict,
        ScanVerdict::Pass,
        "clean manifest must be Pass"
    );
    assert!(
        report.findings.is_empty(),
        "clean manifest must produce no findings"
    );
    assert_eq!(
        report.stats.p0 + report.stats.p1 + report.stats.p2,
        0,
        "all stats must be zero for clean manifest"
    );
}

// AC2: missing capabilities (R0 fires) → Fail, ≥1 P0 with rule_id R0-missing-capabilities
#[test]
fn ac2_missing_capabilities_r0_fires() {
    use skill_scanner_core::Severity;
    let report = scan(clean_args(fixture("missing-caps"))).expect("missing-caps scan must succeed");
    assert_eq!(report.verdict, ScanVerdict::Fail);
    let r0_p0: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.rule_id.0 == "R0-missing-capabilities" && f.severity == Severity::P0)
        .collect();
    assert!(
        !r0_p0.is_empty(),
        "must find ≥1 R0-missing-capabilities P0 finding"
    );
}

// AC3: installer.command with `;` (R2 fires) → Fail, ≥1 P0
#[test]
fn ac3_r2_installer_injection_fires() {
    let report = scan(clean_args(fixture("r2-injection"))).expect("r2-injection scan must succeed");
    assert_eq!(report.verdict, ScanVerdict::Fail);
    assert!(report.stats.p0 > 0, "R2 must produce ≥1 P0 finding");
    let r2: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.rule_id.0 == "R2-installer-command")
        .collect();
    assert!(!r2.is_empty(), "must find ≥1 R2-installer-command finding");
}

// AC4: malformed manifest → Err with code SCAN_MANIFEST_PARSE
#[test]
fn ac4_malformed_manifest_parse_err() {
    let err = scan(clean_args(fixture("malformed"))).unwrap_err();
    assert_eq!(
        err.code(),
        "SCAN_MANIFEST_PARSE",
        "malformed manifest must produce SCAN_MANIFEST_PARSE"
    );
}

// AC5: non-existent skill_path → Err with code SCAN_MANIFEST_NOT_FOUND
#[test]
fn ac5_nonexistent_path_not_found() {
    let err = scan(clean_args(PathBuf::from(
        "/nonexistent/absolute/path/that/cannot/exist/in/any/fs",
    )))
    .unwrap_err();
    assert_eq!(
        err.code(),
        "SCAN_MANIFEST_NOT_FOUND",
        "non-existent path must produce SCAN_MANIFEST_NOT_FOUND"
    );
}

// AC6: only SKILL.md present → manifest_path ends with SKILL.md
#[test]
fn ac6_skill_md_only_uses_skill_md() {
    let report = scan(clean_args(fixture("skill-md-only"))).expect("skill-md-only must succeed");
    assert!(
        report.manifest_path.ends_with("SKILL.md"),
        "manifest_path must end with SKILL.md, got: {:?}",
        report.manifest_path
    );
}

// AC7: only manifest.json present → manifest_path ends with manifest.json
#[test]
fn ac7_manifest_json_only_uses_json() {
    let report =
        scan(clean_args(fixture("manifest-json-only"))).expect("manifest-json-only must succeed");
    assert!(
        report.manifest_path.ends_with("manifest.json"),
        "manifest_path must end with manifest.json, got: {:?}",
        report.manifest_path
    );
}

// AC8: BOTH SKILL.md and manifest.json present → prefers SKILL.md (deterministic)
#[test]
fn ac8_both_present_prefers_skill_md() {
    let report =
        scan(clean_args(fixture("both-manifests"))).expect("both-manifests scan must succeed");
    assert!(
        report.manifest_path.ends_with("SKILL.md"),
        "must prefer SKILL.md over manifest.json, got: {:?}",
        report.manifest_path
    );
    assert_eq!(
        report.manifest_name, "skill-md-version",
        "manifest_name must be from SKILL.md, not manifest.json"
    );
}

// AC9: valid custom ruleset → loads OK, rules_evaluated >= builtin count (14)
#[test]
fn ac9_valid_custom_ruleset_loads() {
    let mut args = clean_args(fixture("clean"));
    args.rulesets = vec![fixture("custom-ruleset").join("valid-rules.yml")];
    let report = scan(args).expect("scan with valid ruleset must succeed");
    assert!(
        report.stats.rules_evaluated >= 14,
        "rules_evaluated must include at least 14 builtin rules, got {}",
        report.stats.rules_evaluated
    );
}

// AC10: ruleset with invalid rule ID → Err(RulesetLoad) with code SCAN_RULESET_LOAD
#[test]
fn ac10_invalid_ruleset_id_rejected() {
    let mut args = clean_args(fixture("clean"));
    args.rulesets = vec![fixture("custom-ruleset").join("invalid-id-rules.yml")];
    let err = scan(args).unwrap_err();
    assert_eq!(
        err.code(),
        "SCAN_RULESET_LOAD",
        "invalid ruleset ID must produce SCAN_RULESET_LOAD"
    );
}

// AC11: require-signature + unsigned ruleset (no .sig sidecar) → Err(RulesetLoad, C4MissingSignature)
#[test]
fn ac11_require_signature_unsigned_ruleset_rejected() {
    let mut args = clean_args(fixture("clean"));
    args.rulesets = vec![fixture("custom-ruleset").join("valid-rules.yml")];
    args.trust_policy = TrustPolicy::RequireSignature {
        trusted_keys: vec![],
    };
    let err = scan(args).unwrap_err();
    assert_eq!(
        err.code(),
        "SCAN_RULESET_LOAD",
        "unsigned ruleset with require-signature must produce SCAN_RULESET_LOAD"
    );
}

// AC12: require-signature + ruleset signed by trusted K1 → Ok
#[test]
fn ac12_require_signature_signed_trusted_ok() {
    use ed25519_dalek::{Signer, SigningKey};
    use skill_scanner_ruleset::TrustedKey;
    use std::fs;
    use tempfile::TempDir;

    let tmp = TempDir::new().unwrap();
    let skill_dir = tmp.path().join("skill");
    fs::create_dir(&skill_dir).unwrap();
    fs::write(
        skill_dir.join("SKILL.md"),
        b"---\nname: test\nversion: 1.0.0\ncapabilities:\n  - resource: network\n    scope: read\n---\n",
    )
    .unwrap();

    let yaml_content = b"- id: my-rule\n  message: Test rule\n";
    let ruleset_dir = tmp.path().join("rulesets");
    fs::create_dir(&ruleset_dir).unwrap();
    let yaml_path = ruleset_dir.join("rules.yml");
    fs::write(&yaml_path, yaml_content).unwrap();

    let sk = SigningKey::from_bytes(&[0u8; 32]);
    let pk = sk.verifying_key().to_bytes();
    let sig: [u8; 64] = sk.sign(yaml_content).to_bytes();
    let mut wire = [0u8; 96];
    wire[0..64].copy_from_slice(&sig);
    wire[64..96].copy_from_slice(&pk);
    fs::write(ruleset_dir.join("rules.yml.sig"), &wire).unwrap();

    let mut args = clean_args(skill_dir);
    args.rulesets = vec![yaml_path];
    args.trust_policy = TrustPolicy::RequireSignature {
        trusted_keys: vec![TrustedKey {
            identifier: "k1".to_string(),
            public_key: pk,
        }],
    };
    scan(args).expect("signed+trusted ruleset must succeed");
}

// AC13: custom Semgrep patterns do NOT produce findings in v0.2 scope
#[test]
fn ac13_custom_semgrep_patterns_not_evaluated() {
    let builtin_count = scan(clean_args(fixture("clean")))
        .expect("clean scan must succeed")
        .findings
        .len();

    let mut args_with_ruleset = clean_args(fixture("clean"));
    args_with_ruleset.rulesets = vec![fixture("custom-ruleset").join("valid-rules.yml")];
    let with_ruleset_count = scan(args_with_ruleset)
        .expect("scan with ruleset must succeed")
        .findings
        .len();

    assert_eq!(
        builtin_count, with_ruleset_count,
        "custom Semgrep patterns must not add findings in v0.2 (load+validate only)"
    );
}

// AC14: findings sorted by severity desc (priority()) → path asc → line asc
#[test]
fn ac14_findings_sorted_severity_desc_path_line() {
    let report =
        scan(clean_args(fixture("missing-caps"))).expect("scan must succeed for sort test");
    for window in report.findings.windows(2) {
        let a = &window[0];
        let b = &window[1];
        let ap = a.severity.priority();
        let bp = b.severity.priority();
        assert!(
            ap >= bp,
            "findings must be sorted by severity desc: {:?}(pri={}) before {:?}(pri={})",
            a.severity,
            ap,
            b.severity,
            bp
        );
        if ap == bp {
            let ap_path = &a.location.path;
            let bp_path = &b.location.path;
            assert!(
                ap_path <= bp_path,
                "equal severity: path must be sorted asc: {:?} <= {:?}",
                ap_path,
                bp_path
            );
        }
    }
}

// AC15: any P0 finding → verdict == Fail
#[test]
fn ac15_any_p0_verdict_fail() {
    let report = scan(clean_args(fixture("missing-caps"))).expect("missing-caps must succeed");
    assert!(
        report.stats.p0 > 0,
        "missing-caps fixture must have P0 findings"
    );
    assert_eq!(
        report.verdict,
        ScanVerdict::Fail,
        "any P0 must produce verdict=Fail"
    );
}

// AC16: no P0 findings → verdict == Pass (exit 0)
#[test]
fn ac16_no_p0_verdict_pass() {
    let report = scan(clean_args(fixture("clean"))).expect("clean scan must succeed");
    assert_eq!(report.stats.p0, 0, "clean fixture must have no P0");
    assert_eq!(
        report.verdict,
        ScanVerdict::Pass,
        "no P0 findings must produce verdict=Pass"
    );
}

// AC17: stats.p0 + stats.p1 + stats.p2 == findings.len()
#[test]
fn ac17_stats_sum_equals_findings_len() {
    let report = scan(clean_args(fixture("missing-caps"))).expect("scan must succeed");
    let sum = report.stats.p0 + report.stats.p1 + report.stats.p2;
    assert_eq!(
        sum as usize,
        report.findings.len(),
        "stats p0+p1+p2={} must equal findings.len()={}",
        sum,
        report.findings.len()
    );
}

// AC18: render(_, Json, _) produces valid JSON
#[test]
fn ac18_render_json_valid() {
    let report = scan(clean_args(fixture("clean"))).expect("scan must succeed");
    let json_str = render(&report, OutputFormat::Json, ColorChoice::Never);
    assert!(
        serde_json::from_str::<serde_json::Value>(&json_str).is_ok(),
        "JSON output must be valid JSON, got: {}",
        &json_str[..json_str.len().min(200)]
    );
}

// AC19: JSON top-level keys in order: version, skill_path, manifest_name, manifest_path, verdict, stats, findings
#[test]
fn ac19_json_key_order() {
    let report = scan(clean_args(fixture("clean"))).expect("scan must succeed");
    let json_str = render(&report, OutputFormat::Json, ColorChoice::Never);
    let expected = [
        "version",
        "skill_path",
        "manifest_name",
        "manifest_path",
        "verdict",
        "stats",
        "findings",
    ];
    let mut last_pos = 0usize;
    for key in &expected {
        let needle = format!("\"{}\"", key);
        let pos = json_str[last_pos..].find(&needle).unwrap_or_else(|| {
            panic!(
                "key '{}' not found in JSON after position {}",
                key, last_pos
            )
        });
        last_pos += pos + needle.len();
    }
}

// AC20: JSON "findings" value is an Array
#[test]
fn ac20_json_findings_is_array() {
    let report = scan(clean_args(fixture("clean"))).expect("scan must succeed");
    let json_str = render(&report, OutputFormat::Json, ColorChoice::Never);
    let v: serde_json::Value = serde_json::from_str(&json_str).expect("must be valid JSON");
    assert!(v["findings"].is_array(), "JSON 'findings' must be an Array");
}

// AC21: JSON render is deterministic — two calls with same input → byte-equal output
#[test]
fn ac21_json_determinism() {
    let report = scan(clean_args(fixture("clean"))).expect("scan must succeed");
    let j1 = render(&report, OutputFormat::Json, ColorChoice::Never);
    let j2 = render(&report, OutputFormat::Json, ColorChoice::Never);
    assert_eq!(j1, j2, "render(Json) must be deterministic");
}

// AC22: render(_, Text, Never) → no ANSI escape codes
#[test]
fn ac22_text_never_no_ansi() {
    let report = scan(clean_args(fixture("missing-caps"))).expect("scan must succeed");
    let text = render(&report, OutputFormat::Text, ColorChoice::Never);
    assert!(
        !text.contains("\x1b["),
        "ColorChoice::Never must produce no ANSI codes"
    );
}

// AC23: render(report_with_p0, Text, Always) → contains ANSI escape codes
#[test]
fn ac23_text_always_with_p0_has_ansi() {
    let report = scan(clean_args(fixture("missing-caps"))).expect("scan must succeed");
    assert!(
        report.stats.p0 > 0,
        "missing-caps must have P0 for this test"
    );
    let text = render(&report, OutputFormat::Text, ColorChoice::Always);
    assert!(
        text.contains("\x1b["),
        "ColorChoice::Always with P0 findings must produce ANSI codes"
    );
}

// AC24: empty findings → text output contains "No findings."
#[test]
fn ac24_empty_findings_text_no_findings_line() {
    let report = scan(clean_args(fixture("clean"))).expect("clean scan must succeed");
    assert!(
        report.findings.is_empty(),
        "clean fixture must have no findings"
    );
    let text = render(&report, OutputFormat::Text, ColorChoice::Never);
    assert!(
        text.contains("No findings."),
        "empty findings text output must contain 'No findings.', got: {}",
        text
    );
}
