use skill_scanner_core::{RuleId, RuleOrigin, Severity};
use skill_scanner_manifest::SkillManifest;
use skill_scanner_rules::r5::R5EnvSystemVar;
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
fn ac1_r5_env_system_var_id() {
    let rule = R5EnvSystemVar::new();
    assert_eq!(rule.id(), &RuleId("R5-env-system-var".to_string()));
}

// AC2: BuiltIn origin
#[test]
fn ac2_r5_env_system_var_origin() {
    let rule = R5EnvSystemVar::new();
    assert_eq!(rule.origin(), RuleOrigin::BuiltIn);
}

// AC3: env = None → 0 findings
#[test]
fn ac3_env_none_no_findings() {
    let rule = R5EnvSystemVar::new();
    let manifest = base_manifest();
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert!(
        findings.is_empty(),
        "env=None must produce 0 findings, got: {:?}",
        findings
    );
}

// AC4: non-blocked env keys → 0 findings
#[test]
fn ac4_non_blocked_keys_no_findings() {
    let rule = R5EnvSystemVar::new();
    let manifest = env_manifest(&[
        ("PORT", "3000"),
        ("LOG_LEVEL", "info"),
        ("APP_ENV", "production"),
    ]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert!(
        findings.is_empty(),
        "non-blocked keys must produce 0 findings, got: {:?}",
        findings
    );
}

// AC5: PATH key (uppercase) → 1 finding, P0 severity
#[test]
fn ac5_path_key_produces_p0_finding() {
    let rule = R5EnvSystemVar::new();
    let manifest = env_manifest(&[("PATH", "/usr/bin:/usr/local/bin")]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "PATH must produce 1 finding, got: {}",
        findings.len()
    );
    assert_eq!(findings[0].severity, Severity::P0, "R5 findings must be P0");
}

// AC6: PATH key (lowercase) → 1 finding (case-insensitive match)
#[test]
fn ac6_path_lowercase_case_insensitive() {
    let rule = R5EnvSystemVar::new();
    let manifest = env_manifest(&[("path", "/usr/bin")]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "\"path\" must match PATH case-insensitively, got: {}",
        findings.len()
    );
}

// AC7: LD_PRELOAD → 1 finding
#[test]
fn ac7_ld_preload_produces_finding() {
    let rule = R5EnvSystemVar::new();
    let manifest = env_manifest(&[("LD_PRELOAD", "/tmp/evil.so")]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "LD_PRELOAD must produce 1 finding, got: {}",
        findings.len()
    );
}

// AC8: NODE_OPTIONS → 1 finding
#[test]
fn ac8_node_options_produces_finding() {
    let rule = R5EnvSystemVar::new();
    let manifest = env_manifest(&[("NODE_OPTIONS", "--require /tmp/evil.js")]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "NODE_OPTIONS must produce 1 finding, got: {}",
        findings.len()
    );
}

// AC9: ELECTRON_RUN_AS_NODE → 1 finding
#[test]
fn ac9_electron_run_as_node_produces_finding() {
    let rule = R5EnvSystemVar::new();
    let manifest = env_manifest(&[("ELECTRON_RUN_AS_NODE", "1")]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "ELECTRON_RUN_AS_NODE must produce 1 finding, got: {}",
        findings.len()
    );
}

// AC10: multiple blocked keys → one finding per blocked key
#[test]
fn ac10_multiple_blocked_keys_multiple_findings() {
    let rule = R5EnvSystemVar::new();
    let manifest = env_manifest(&[
        ("PATH", "/usr/bin"),
        ("LD_PRELOAD", "/tmp/evil.so"),
        ("NODE_OPTIONS", "--inspect"),
    ]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        3,
        "expected 3 findings for 3 blocked keys, got: {}",
        findings.len()
    );
}

// AC11: mixed env — only blocked keys produce findings
#[test]
fn ac11_mixed_env_only_blocked_flagged() {
    let rule = R5EnvSystemVar::new();
    let manifest = env_manifest(&[
        ("PORT", "8080"),
        ("PYTHONPATH", "/tmp/injected"),
        ("LOG_LEVEL", "debug"),
    ]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "only PYTHONPATH should be flagged, got: {}",
        findings.len()
    );
}

// AC12: R1 and R5 non-overlap — "DB_PASSWORD" triggers R1 but not R5
#[test]
fn ac12_r1_r5_non_overlap() {
    let rule = R5EnvSystemVar::new();
    let manifest = env_manifest(&[("DB_PASSWORD", "hunter2")]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert!(
        findings.is_empty(),
        "DB_PASSWORD is R1 (credential keyword), not R5 (system var), got: {:?}",
        findings
    );
}

// AC13: finding.location.path matches manifest_path argument
#[test]
fn ac13_finding_location_path() {
    let rule = R5EnvSystemVar::new();
    let manifest = env_manifest(&[("PATH", "/usr/bin")]);
    let expected_path = Path::new("/tmp/skill/manifest.json");
    let findings = rule.check(&manifest, expected_path);
    assert!(!findings.is_empty());
    assert_eq!(
        findings[0].location.path.as_path(),
        expected_path,
        "finding.location.path must match manifest_path"
    );
}

// AC14: builtin_rules() includes R5EnvSystemVar
#[test]
fn ac14_builtin_rules_contains_r5() {
    let rules = builtin_rules();
    let ids: Vec<String> = rules.iter().map(|r| r.id().0.clone()).collect();
    assert!(
        ids.contains(&"R5-env-system-var".to_string()),
        "builtin_rules must include R5-env-system-var, got: {:?}",
        ids
    );
}

// AC15: R5EnvSystemVar is Send + Sync
#[test]
fn ac15_r5_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<R5EnvSystemVar>();
    let _: Box<dyn Rule + Send + Sync> = Box::new(R5EnvSystemVar::new());
}
