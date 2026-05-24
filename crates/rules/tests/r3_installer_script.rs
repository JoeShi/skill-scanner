use skill_scanner_core::{RuleId, RuleOrigin, Severity};
use skill_scanner_manifest::{InstallerConfig, SkillManifest};
use skill_scanner_rules::r3::R3InstallerScript;
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

fn manifest_with_script(script: &str) -> SkillManifest {
    SkillManifest {
        installer: Some(InstallerConfig {
            r#type: None,
            command: None,
            script: Some(script.to_string()),
        }),
        ..base_manifest()
    }
}

// AC1: correct rule ID
#[test]
fn ac1_r3_installer_script_id() {
    let rule = R3InstallerScript::new();
    assert_eq!(rule.id(), &RuleId("R3-installer-script".to_string()));
}

// AC2: BuiltIn origin
#[test]
fn ac2_r3_installer_script_origin() {
    let rule = R3InstallerScript::new();
    assert_eq!(rule.origin(), RuleOrigin::BuiltIn);
}

// AC3: installer = None → 0 findings
#[test]
fn ac3_installer_none_no_findings() {
    let rule = R3InstallerScript::new();
    let manifest = base_manifest();
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert!(
        findings.is_empty(),
        "installer=None must produce 0 findings, got: {:?}",
        findings
    );
}

// AC4: installer present but script = None → 0 findings
#[test]
fn ac4_script_none_no_findings() {
    let rule = R3InstallerScript::new();
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
        "script=None must produce 0 findings, got: {:?}",
        findings
    );
}

// AC5: relative path with ./ prefix → 0 findings
#[test]
fn ac5_dot_slash_relative_no_findings() {
    let rule = R3InstallerScript::new();
    let manifest = manifest_with_script("./setup.sh");
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert!(
        findings.is_empty(),
        "./setup.sh must produce 0 findings, got: {:?}",
        findings
    );
}

// AC6: bare relative path (no ./ prefix) → 0 findings
#[test]
fn ac6_bare_relative_no_findings() {
    let rule = R3InstallerScript::new();
    let manifest = manifest_with_script("setup.sh");
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert!(
        findings.is_empty(),
        "setup.sh must produce 0 findings, got: {:?}",
        findings
    );
}

// AC7: absolute path → 1 finding, P0 severity
#[test]
fn ac7_absolute_path_produces_p0_finding() {
    let rule = R3InstallerScript::new();
    let manifest = manifest_with_script("/tmp/setup.sh");
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "/tmp/setup.sh must produce 1 finding, got: {}",
        findings.len()
    );
    assert_eq!(findings[0].severity, Severity::P0, "R3 findings must be P0");
}

// AC8: single parent traversal → 1 finding
#[test]
fn ac8_parent_traversal_produces_finding() {
    let rule = R3InstallerScript::new();
    let manifest = manifest_with_script("../sibling/setup.sh");
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "../sibling/setup.sh must produce 1 finding, got: {}",
        findings.len()
    );
}

// AC9: deep traversal escape → 1 finding
#[test]
fn ac9_deep_traversal_produces_finding() {
    let rule = R3InstallerScript::new();
    let manifest = manifest_with_script("../../etc/passwd");
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "../../etc/passwd must produce 1 finding, got: {}",
        findings.len()
    );
}

// AC10: finding.location.path matches manifest_path argument
#[test]
fn ac10_finding_location_path() {
    let rule = R3InstallerScript::new();
    let manifest = manifest_with_script("/tmp/evil.sh");
    let expected_path = Path::new("/tmp/skill/manifest.json");
    let findings = rule.check(&manifest, expected_path);
    assert!(!findings.is_empty());
    assert_eq!(
        findings[0].location.path.as_path(),
        expected_path,
        "finding.location.path must match manifest_path"
    );
}

// AC11: builtin_rules() includes R3InstallerScript
#[test]
fn ac11_builtin_rules_contains_r3() {
    let rules = builtin_rules();
    let ids: Vec<String> = rules.iter().map(|r| r.id().0.clone()).collect();
    assert!(
        ids.contains(&"R3-installer-script".to_string()),
        "builtin_rules must include R3-installer-script, got: {:?}",
        ids
    );
}

// AC12: R3InstallerScript is Send + Sync
#[test]
fn ac12_r3_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<R3InstallerScript>();
    let _: Box<dyn Rule + Send + Sync> = Box::new(R3InstallerScript::new());
}
