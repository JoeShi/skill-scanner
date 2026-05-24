use skill_scanner_core::{RuleId, RuleOrigin, Severity};
use skill_scanner_manifest::SkillManifest;
use skill_scanner_rules::r6::R6EnvValueSecrets;
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
fn ac1_r6_env_value_secrets_id() {
    let rule = R6EnvValueSecrets::new();
    assert_eq!(rule.id(), &RuleId("R6-env-value-secrets".to_string()));
}

// AC2: BuiltIn origin
#[test]
fn ac2_r6_env_value_secrets_origin() {
    let rule = R6EnvValueSecrets::new();
    assert_eq!(rule.origin(), RuleOrigin::BuiltIn);
}

// AC3: env = None → 0 findings
#[test]
fn ac3_env_none_no_findings() {
    let rule = R6EnvValueSecrets::new();
    let manifest = base_manifest();
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert!(
        findings.is_empty(),
        "env=None must produce 0 findings, got: {:?}",
        findings
    );
}

// AC4: env values with no secret patterns → 0 findings
#[test]
fn ac4_non_secret_values_no_findings() {
    let rule = R6EnvValueSecrets::new();
    let manifest = env_manifest(&[
        ("API_URL", "https://api.example.com"),
        ("PORT", "3000"),
        ("DB_HOST", "localhost"),
    ]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert!(
        findings.is_empty(),
        "non-secret values must produce 0 findings, got: {:?}",
        findings
    );
}

// AC5: AWS access key in value → 1 finding, P0 severity
#[test]
fn ac5_aws_access_key_produces_p0_finding() {
    let rule = R6EnvValueSecrets::new();
    // AWS access key: AKIA + 16 uppercase alphanumeric chars
    let manifest = env_manifest(&[("AWS_KEY", "AKIAIOSFODNN7EXAMPLE")]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "AWS access key value must produce 1 finding, got: {}",
        findings.len()
    );
    assert_eq!(findings[0].severity, Severity::P0, "R6 findings must be P0");
}

// AC6: GitHub token in value → 1 finding
#[test]
fn ac6_github_token_produces_finding() {
    let rule = R6EnvValueSecrets::new();
    // GitHub personal access token: ghp_ + 36+ alphanumeric/underscore chars
    let manifest = env_manifest(&[("GH_TOKEN", "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890")]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "GitHub token value must produce 1 finding, got: {}",
        findings.len()
    );
}

// AC7: Private key block in value → 1 finding
#[test]
fn ac7_private_key_block_produces_finding() {
    let rule = R6EnvValueSecrets::new();
    let manifest = env_manifest(&[(
        "PRIVATE_KEY",
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEo...\n-----END RSA PRIVATE KEY-----",
    )]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "private key block must produce 1 finding, got: {}",
        findings.len()
    );
}

// AC8: Slack token in value → 1 finding
#[test]
fn ac8_slack_token_produces_finding() {
    let rule = R6EnvValueSecrets::new();
    let manifest = env_manifest(&[(
        "SLACK_TOKEN",
        "xoxb-FAKE-000000000-TESTONLY-not-a-real-token",
    )]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "Slack token value must produce 1 finding, got: {}",
        findings.len()
    );
}

// AC9: OPENSSH private key variant → 1 finding
#[test]
fn ac9_openssh_private_key_produces_finding() {
    let rule = R6EnvValueSecrets::new();
    let manifest = env_manifest(&[(
        "SSH_KEY",
        "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNza...",
    )]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "OPENSSH private key must produce 1 finding, got: {}",
        findings.len()
    );
}

// AC10: multiple env entries with secrets → one finding per matching value
#[test]
fn ac10_multiple_secret_values_multiple_findings() {
    let rule = R6EnvValueSecrets::new();
    let manifest = env_manifest(&[
        ("AWS_KEY", "AKIAIOSFODNN7EXAMPLE"),
        ("GH_TOKEN", "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"),
    ]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        2,
        "expected 2 findings for 2 secret values, got: {}",
        findings.len()
    );
}

// AC11: mixed env — only secret values produce findings
#[test]
fn ac11_mixed_env_only_secrets_flagged() {
    let rule = R6EnvValueSecrets::new();
    let manifest = env_manifest(&[
        ("PORT", "3000"),
        ("AWS_KEY", "AKIAIOSFODNN7EXAMPLE"),
        ("LOG_LEVEL", "debug"),
    ]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "only AWS key should be flagged, got: {}",
        findings.len()
    );
}

// AC12: R1 / R6 non-overlap — key "DB_PASSWORD" with benign value → R6 produces 0 findings
// (R1 catches the key name; R6 checks value content only)
#[test]
fn ac12_r1_r6_non_overlap() {
    let rule = R6EnvValueSecrets::new();
    let manifest = env_manifest(&[("DB_PASSWORD", "hunter2")]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert!(
        findings.is_empty(),
        "benign value under credential-named key must produce 0 R6 findings, got: {:?}",
        findings
    );
}

// AC13: finding.location.path matches manifest_path argument
#[test]
fn ac13_finding_location_path() {
    let rule = R6EnvValueSecrets::new();
    let manifest = env_manifest(&[("KEY", "AKIAIOSFODNN7EXAMPLE")]);
    let expected_path = Path::new("/tmp/skill/manifest.json");
    let findings = rule.check(&manifest, expected_path);
    assert!(!findings.is_empty());
    assert_eq!(
        findings[0].location.path.as_path(),
        expected_path,
        "finding.location.path must match manifest_path"
    );
}

// AC14: builtin_rules() includes R6EnvValueSecrets
#[test]
fn ac14_builtin_rules_contains_r6() {
    let rules = builtin_rules();
    let ids: Vec<String> = rules.iter().map(|r| r.id().0.clone()).collect();
    assert!(
        ids.contains(&"R6-env-value-secrets".to_string()),
        "builtin_rules must include R6-env-value-secrets, got: {:?}",
        ids
    );
}

// AC15: R6EnvValueSecrets is Send + Sync
#[test]
fn ac15_r6_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<R6EnvValueSecrets>();
    let _: Box<dyn Rule + Send + Sync> = Box::new(R6EnvValueSecrets::new());
}
