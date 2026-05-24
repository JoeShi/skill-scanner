use skill_scanner_core::{RuleId, RuleOrigin, Severity};
use skill_scanner_manifest::SkillManifest;
use skill_scanner_rules::r1::R1SensitiveEnvKey;
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
fn ac1_r1_sensitive_env_id() {
    let rule = R1SensitiveEnvKey::new();
    assert_eq!(rule.id(), &RuleId("R1-sensitive-env-key".to_string()));
}

// AC2: BuiltIn origin
#[test]
fn ac2_r1_sensitive_env_origin() {
    let rule = R1SensitiveEnvKey::new();
    assert_eq!(rule.origin(), RuleOrigin::BuiltIn);
}

// AC3: env = None → zero findings
#[test]
fn ac3_env_none_no_findings() {
    let rule = R1SensitiveEnvKey::new();
    let manifest = base_manifest();
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert!(
        findings.is_empty(),
        "env=None must produce zero findings, got: {:?}",
        findings
    );
}

// AC4: non-sensitive env keys → zero findings
#[test]
fn ac4_non_sensitive_keys_no_findings() {
    let rule = R1SensitiveEnvKey::new();
    let manifest = env_manifest(&[("PORT", "3000"), ("DEBUG", "true"), ("LOG_LEVEL", "info")]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert!(
        findings.is_empty(),
        "non-sensitive keys must produce zero findings, got: {:?}",
        findings
    );
}

// AC5: PASSWORD key → 1 finding, P1 severity
#[test]
fn ac5_password_key_produces_p1_finding() {
    let rule = R1SensitiveEnvKey::new();
    let manifest = env_manifest(&[("DB_PASSWORD", "hunter2")]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "expected 1 finding for DB_PASSWORD, got: {}",
        findings.len()
    );
    assert_eq!(findings[0].severity, Severity::P1, "R1 findings must be P1");
}

// AC6: SECRET key → 1 finding
#[test]
fn ac6_secret_key_produces_finding() {
    let rule = R1SensitiveEnvKey::new();
    let manifest = env_manifest(&[("APP_SECRET", "xyz")]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(findings.len(), 1, "expected 1 finding for APP_SECRET");
}

// AC7: TOKEN substring match — API_TOKEN contains "TOKEN" → 1 finding
#[test]
fn ac7_token_substring_match() {
    let rule = R1SensitiveEnvKey::new();
    let manifest = env_manifest(&[("API_TOKEN", "tok_abc")]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "API_TOKEN must match TOKEN pattern, got: {}",
        findings.len()
    );
}

// AC8: APIKEY (exact pattern) → 1 finding
#[test]
fn ac8_apikey_pattern_match() {
    let rule = R1SensitiveEnvKey::new();
    let manifest = env_manifest(&[("APIKEY", "abc123")]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(findings.len(), 1, "APIKEY must match APIKEY pattern");
}

// AC9: case-insensitive — "my_password" matches PASSWORD pattern
#[test]
fn ac9_case_insensitive_matching() {
    let rule = R1SensitiveEnvKey::new();
    let manifest = env_manifest(&[("my_password", "secret")]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "my_password must match case-insensitively, got: {}",
        findings.len()
    );
}

// AC10: multiple matching keys → one finding per key
#[test]
fn ac10_multiple_matching_keys_multiple_findings() {
    let rule = R1SensitiveEnvKey::new();
    let manifest = env_manifest(&[
        ("DB_PASSWORD", "pw1"),
        ("API_SECRET", "sk"),
        ("AUTH_TOKEN", "tok"),
    ]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        3,
        "expected 3 findings for 3 sensitive keys, got: {}",
        findings.len()
    );
}

// AC11: mixed env — only sensitive keys get findings
#[test]
fn ac11_mixed_env_only_sensitive_flagged() {
    let rule = R1SensitiveEnvKey::new();
    let manifest = env_manifest(&[
        ("PORT", "8080"),
        ("CLIENT_SECRET", "s3cr3t"),
        ("LOG_LEVEL", "warn"),
    ]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "only CLIENT_SECRET should be flagged, got: {}",
        findings.len()
    );
}

// AC12: finding.location.path matches manifest_path argument
#[test]
fn ac12_finding_location_path() {
    let rule = R1SensitiveEnvKey::new();
    let manifest = env_manifest(&[("DB_PASSWORD", "pw")]);
    let expected_path = Path::new("/tmp/skill/manifest.json");
    let findings = rule.check(&manifest, expected_path);
    assert!(!findings.is_empty());
    assert_eq!(
        findings[0].location.path.as_path(),
        expected_path,
        "finding.location.path must match manifest_path"
    );
}

// AC13: builtin_rules() includes R1SensitiveEnvKey
#[test]
fn ac13_builtin_rules_contains_r1() {
    let rules = builtin_rules();
    let ids: Vec<String> = rules.iter().map(|r| r.id().0.clone()).collect();
    assert!(
        ids.contains(&"R1-sensitive-env-key".to_string()),
        "builtin_rules must include R1-sensitive-env-key, got: {:?}",
        ids
    );
}

// AC14: R1SensitiveEnvKey is Send + Sync
#[test]
fn ac14_r1_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<R1SensitiveEnvKey>();
    let _: Box<dyn Rule + Send + Sync> = Box::new(R1SensitiveEnvKey::new());
}
