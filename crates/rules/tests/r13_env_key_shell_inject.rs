use skill_scanner_core::{RuleId, RuleOrigin, Severity};
use skill_scanner_manifest::SkillManifest;
use skill_scanner_rules::r13::R13EnvKeyShellInject;
use skill_scanner_rules::{builtin_rules, Rule};
use std::collections::HashMap;
use std::path::Path;

fn base_manifest() -> SkillManifest {
    SkillManifest {
        name: "test-skill".to_string(),
        version: "1.0.0".to_string(),
        description: Some("A test skill".to_string()),
        main: Some("index.js".to_string()),
        author: Some("Alice".to_string()),
        license: Some("MIT".to_string()),
        capabilities: None,
        domains: None,
        fs_paths: None,
        dependencies: None,
        dev_dependencies: None,
        publisher: None,
        installer: None,
        env: None,
    }
}

fn env_manifest(pairs: &[(&str, &str)]) -> SkillManifest {
    let mut env = HashMap::new();
    for (k, v) in pairs {
        env.insert(k.to_string(), v.to_string());
    }
    SkillManifest {
        env: Some(env),
        ..base_manifest()
    }
}

// AC1: correct rule ID
#[test]
fn ac1_r13_env_key_shell_inject_id() {
    let rule = R13EnvKeyShellInject::new();
    assert_eq!(rule.id(), &RuleId("R13-env-key-shell-inject".to_string()));
}

// AC2: BuiltIn origin
#[test]
fn ac2_r13_env_key_shell_inject_origin() {
    let rule = R13EnvKeyShellInject::new();
    assert_eq!(rule.origin(), RuleOrigin::BuiltIn);
}

// AC3: env = None → 0 findings
#[test]
fn ac3_env_none_no_findings() {
    let rule = R13EnvKeyShellInject::new();
    let manifest = base_manifest();
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert!(
        findings.is_empty(),
        "env=None must produce 0 findings, got: {:?}",
        findings
    );
}

// AC4: env = empty HashMap → 0 findings
#[test]
fn ac4_env_empty_no_findings() {
    let rule = R13EnvKeyShellInject::new();
    let manifest = SkillManifest {
        env: Some(HashMap::new()),
        ..base_manifest()
    };
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert!(
        findings.is_empty(),
        "env={{}} must produce 0 findings, got: {:?}",
        findings
    );
}

// AC5: safe env keys → 0 findings
#[test]
fn ac5_safe_keys_no_findings() {
    let rule = R13EnvKeyShellInject::new();
    let manifest = env_manifest(&[
        ("NORMAL_KEY", "value"),
        ("PORT", "3000"),
        ("API_URL", "https://api.example.com"),
        ("NODE_ENV", "production"),
    ]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert!(
        findings.is_empty(),
        "safe keys must produce 0 findings, got: {:?}",
        findings
    );
}

// AC6: key containing ";" (semicolon) → 1 finding, P0 severity
#[test]
fn ac6_semicolon_in_key_produces_p0_finding() {
    let rule = R13EnvKeyShellInject::new();
    let manifest = env_manifest(&[("FOO;rm -rf /", "value")]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "key with ';' must produce 1 finding, got: {}",
        findings.len()
    );
    assert_eq!(
        findings[0].severity,
        Severity::P0,
        "R13 findings must be P0"
    );
}

// AC7: key containing "|" (pipe) → 1 finding
#[test]
fn ac7_pipe_in_key_produces_finding() {
    let rule = R13EnvKeyShellInject::new();
    let manifest = env_manifest(&[("FOO|bar", "value")]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "key with '|' must produce 1 finding, got: {}",
        findings.len()
    );
}

// AC8: key containing "&" (ampersand) → 1 finding
#[test]
fn ac8_ampersand_in_key_produces_finding() {
    let rule = R13EnvKeyShellInject::new();
    let manifest = env_manifest(&[("FOO&bar", "value")]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "key with '&' must produce 1 finding, got: {}",
        findings.len()
    );
}

// AC9: key containing "$" (dollar sign) → 1 finding
#[test]
fn ac9_dollar_in_key_produces_finding() {
    let rule = R13EnvKeyShellInject::new();
    let manifest = env_manifest(&[("FOO$BAR", "value")]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "key with '$' must produce 1 finding, got: {}",
        findings.len()
    );
}

// AC10: key containing backtick → 1 finding
#[test]
fn ac10_backtick_in_key_produces_finding() {
    let rule = R13EnvKeyShellInject::new();
    let manifest = env_manifest(&[("FOO`cmd`", "value")]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "key with backtick must produce 1 finding, got: {}",
        findings.len()
    );
}

// AC11: key containing "<" or ">" (redirection) → 1 finding each
#[test]
fn ac11_redirection_chars_produce_findings() {
    let rule = R13EnvKeyShellInject::new();
    let manifest = env_manifest(&[("FOO<bar", "value")]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "key with '<' must produce 1 finding, got: {}",
        findings.len()
    );
}

// AC12: multiple keys with shell metachars → one finding per dangerous key
#[test]
fn ac12_multiple_dangerous_keys_multiple_findings() {
    let rule = R13EnvKeyShellInject::new();
    let manifest = env_manifest(&[
        ("FOO;bar", "value1"),
        ("BAZ|qux", "value2"),
        ("SAFE_KEY", "value3"),
    ]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        2,
        "expected 2 findings for 2 dangerous keys, got: {}",
        findings.len()
    );
}

// AC13: mixed safe + dangerous → only dangerous keys flagged
#[test]
fn ac13_mixed_keys_only_dangerous_flagged() {
    let rule = R13EnvKeyShellInject::new();
    let manifest = env_manifest(&[
        ("PORT", "3000"),
        ("INJECT$HERE", "value"),
        ("LOG_LEVEL", "debug"),
    ]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "only \"INJECT$HERE\" should be flagged, got: {}",
        findings.len()
    );
}

// AC14: non-overlap with R1/R5 — "DB_PASSWORD" is R1, not R13
#[test]
fn ac14_r1_r13_non_overlap() {
    let rule = R13EnvKeyShellInject::new();
    let manifest = env_manifest(&[("DB_PASSWORD", "hunter2")]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert!(
        findings.is_empty(),
        "DB_PASSWORD has no shell metachar, must produce 0 R13 findings, got: {:?}",
        findings
    );
}

// AC15: finding.location.path matches manifest_path argument
#[test]
fn ac15_finding_location_path() {
    let rule = R13EnvKeyShellInject::new();
    let manifest = env_manifest(&[("FOO;inject", "value")]);
    let expected_path = Path::new("/tmp/skill/manifest.json");
    let findings = rule.check(&manifest, expected_path);
    assert!(!findings.is_empty());
    assert_eq!(
        findings[0].location.path.as_path(),
        expected_path,
        "finding.location.path must match manifest_path"
    );
}

// AC16: builtin_rules() includes R13EnvKeyShellInject
#[test]
fn ac16_builtin_rules_contains_r13() {
    let rules = builtin_rules();
    let ids: Vec<String> = rules.iter().map(|r| r.id().0.clone()).collect();
    assert!(
        ids.contains(&"R13-env-key-shell-inject".to_string()),
        "builtin_rules must include R13-env-key-shell-inject, got: {:?}",
        ids
    );
}

// AC17: R13EnvKeyShellInject is Send + Sync
#[test]
fn ac17_r13_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<R13EnvKeyShellInject>();
    let _: Box<dyn Rule + Send + Sync> = Box::new(R13EnvKeyShellInject::new());
}
