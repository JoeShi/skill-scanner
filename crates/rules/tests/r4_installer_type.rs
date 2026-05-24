use skill_scanner_core::{RuleId, RuleOrigin, Severity};
use skill_scanner_manifest::{InstallerConfig, SkillManifest};
use skill_scanner_rules::r4::R4InstallerTypeBlocked;
use skill_scanner_rules::{builtin_rules, Rule};
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

fn manifest_with_installer_type(installer_type: &str) -> SkillManifest {
    SkillManifest {
        installer: Some(InstallerConfig {
            r#type: Some(installer_type.to_string()),
            command: None,
            script: None,
        }),
        ..base_manifest()
    }
}

// AC1: correct rule ID
#[test]
fn ac1_r4_installer_type_id() {
    let rule = R4InstallerTypeBlocked::new();
    assert_eq!(rule.id(), &RuleId("R4-installer-type-blocked".to_string()));
}

// AC2: BuiltIn origin
#[test]
fn ac2_r4_installer_type_origin() {
    let rule = R4InstallerTypeBlocked::new();
    assert_eq!(rule.origin(), RuleOrigin::BuiltIn);
}

// AC3: installer = None → 0 findings
#[test]
fn ac3_installer_none_no_findings() {
    let rule = R4InstallerTypeBlocked::new();
    let manifest = base_manifest();
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert!(
        findings.is_empty(),
        "installer=None must produce 0 findings, got: {:?}",
        findings
    );
}

// AC4: installer present but type = None → 0 findings
#[test]
fn ac4_installer_type_none_no_findings() {
    let rule = R4InstallerTypeBlocked::new();
    let manifest = SkillManifest {
        installer: Some(InstallerConfig {
            r#type: None,
            command: None,
            script: None,
        }),
        ..base_manifest()
    };
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert!(
        findings.is_empty(),
        "installer.type=None must produce 0 findings, got: {:?}",
        findings
    );
}

// AC5: installer.type = "orchestrator-managed" (the only allowed value) → 0 findings
#[test]
fn ac5_orchestrator_managed_no_findings() {
    let rule = R4InstallerTypeBlocked::new();
    let manifest = manifest_with_installer_type("orchestrator-managed");
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert!(
        findings.is_empty(),
        "\"orchestrator-managed\" must produce 0 findings, got: {:?}",
        findings
    );
}

// AC6: installer.type = "npm" → 1 finding, P0 severity
#[test]
fn ac6_npm_type_produces_p0_finding() {
    let rule = R4InstallerTypeBlocked::new();
    let manifest = manifest_with_installer_type("npm");
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "\"npm\" installer.type must produce 1 finding, got: {}",
        findings.len()
    );
    assert_eq!(findings[0].severity, Severity::P0, "R4 findings must be P0");
}

// AC7: installer.type = "pip" → 1 finding
#[test]
fn ac7_pip_type_produces_finding() {
    let rule = R4InstallerTypeBlocked::new();
    let manifest = manifest_with_installer_type("pip");
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "\"pip\" installer.type must produce 1 finding, got: {}",
        findings.len()
    );
}

// AC8: installer.type = "custom-script" → 1 finding
#[test]
fn ac8_custom_script_type_produces_finding() {
    let rule = R4InstallerTypeBlocked::new();
    let manifest = manifest_with_installer_type("custom-script");
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "\"custom-script\" installer.type must produce 1 finding, got: {}",
        findings.len()
    );
}

// AC9: installer.type = "" (empty string) → 1 finding (not in allowed set)
#[test]
fn ac9_empty_string_type_produces_finding() {
    let rule = R4InstallerTypeBlocked::new();
    let manifest = manifest_with_installer_type("");
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "empty installer.type must produce 1 finding, got: {}",
        findings.len()
    );
}

// AC10: installer.type = "ORCHESTRATOR-MANAGED" (wrong case) → 1 finding (exact match, case-sensitive)
#[test]
fn ac10_wrong_case_produces_finding() {
    let rule = R4InstallerTypeBlocked::new();
    let manifest = manifest_with_installer_type("ORCHESTRATOR-MANAGED");
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "\"ORCHESTRATOR-MANAGED\" (wrong case) must produce 1 finding, got: {}",
        findings.len()
    );
}

// AC11: finding.location.path matches manifest_path argument
#[test]
fn ac11_finding_location_path() {
    let rule = R4InstallerTypeBlocked::new();
    let manifest = manifest_with_installer_type("npm");
    let expected_path = Path::new("/tmp/skill/manifest.json");
    let findings = rule.check(&manifest, expected_path);
    assert!(!findings.is_empty());
    assert_eq!(
        findings[0].location.path.as_path(),
        expected_path,
        "finding.location.path must match manifest_path"
    );
}

// AC12: builtin_rules() includes R4InstallerTypeBlocked
#[test]
fn ac12_builtin_rules_contains_r4() {
    let rules = builtin_rules();
    let ids: Vec<String> = rules.iter().map(|r| r.id().0.clone()).collect();
    assert!(
        ids.contains(&"R4-installer-type-blocked".to_string()),
        "builtin_rules must include R4-installer-type-blocked, got: {:?}",
        ids
    );
}

// AC13: R4InstallerTypeBlocked is Send + Sync
#[test]
fn ac13_r4_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<R4InstallerTypeBlocked>();
    let _: Box<dyn Rule + Send + Sync> = Box::new(R4InstallerTypeBlocked::new());
}
