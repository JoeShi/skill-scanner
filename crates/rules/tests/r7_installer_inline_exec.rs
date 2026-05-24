use skill_scanner_core::{RuleId, RuleOrigin, Severity};
use skill_scanner_manifest::{InstallerConfig, SkillManifest};
use skill_scanner_rules::r7::R7InstallerInlineExec;
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

fn manifest_with_command(command: &str) -> SkillManifest {
    SkillManifest {
        installer: Some(InstallerConfig {
            r#type: None,
            command: Some(command.to_string()),
            script: None,
        }),
        ..base_manifest()
    }
}

// AC1: correct rule ID
#[test]
fn ac1_r7_installer_inline_exec_id() {
    let rule = R7InstallerInlineExec::new();
    assert_eq!(rule.id(), &RuleId("R7-installer-inline-exec".to_string()));
}

// AC2: BuiltIn origin
#[test]
fn ac2_r7_installer_inline_exec_origin() {
    let rule = R7InstallerInlineExec::new();
    assert_eq!(rule.origin(), RuleOrigin::BuiltIn);
}

// AC3: installer = None → 0 findings
#[test]
fn ac3_installer_none_no_findings() {
    let rule = R7InstallerInlineExec::new();
    let manifest = base_manifest();
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert!(
        findings.is_empty(),
        "installer=None must produce 0 findings, got: {:?}",
        findings
    );
}

// AC4: installer present but command = None → 0 findings
#[test]
fn ac4_command_none_no_findings() {
    let rule = R7InstallerInlineExec::new();
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
        "command=None must produce 0 findings, got: {:?}",
        findings
    );
}

// AC5: benign relative command → 0 findings
#[test]
fn ac5_benign_command_no_findings() {
    let rule = R7InstallerInlineExec::new();
    let manifest = manifest_with_command("node ./setup.js --install");
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert!(
        findings.is_empty(),
        "benign command must produce 0 findings, got: {:?}",
        findings
    );
}

// AC6: "bash -c" → 1 finding, P0 severity
#[test]
fn ac6_bash_c_produces_p0_finding() {
    let rule = R7InstallerInlineExec::new();
    let manifest = manifest_with_command("bash -c \"echo hello\"");
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "\"bash -c\" must produce 1 finding, got: {}",
        findings.len()
    );
    assert_eq!(findings[0].severity, Severity::P0, "R7 findings must be P0");
}

// AC7: "sh -c" → 1 finding
#[test]
fn ac7_sh_c_produces_finding() {
    let rule = R7InstallerInlineExec::new();
    let manifest = manifest_with_command("sh -c 'npm install'");
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "\"sh -c\" must produce 1 finding, got: {}",
        findings.len()
    );
}

// AC8: "python -c" → 1 finding
#[test]
fn ac8_python_c_produces_finding() {
    let rule = R7InstallerInlineExec::new();
    let manifest = manifest_with_command("python -c \"import os; os.system('id')\"");
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "\"python -c\" must produce 1 finding, got: {}",
        findings.len()
    );
}

// AC9: "python3 -c" → 1 finding
#[test]
fn ac9_python3_c_produces_finding() {
    let rule = R7InstallerInlineExec::new();
    let manifest = manifest_with_command("python3 -c \"print('setup')\"");
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "\"python3 -c\" must produce 1 finding, got: {}",
        findings.len()
    );
}

// AC10: "node -e" → 1 finding
#[test]
fn ac10_node_e_produces_finding() {
    let rule = R7InstallerInlineExec::new();
    let manifest = manifest_with_command("node -e \"require('fs').writeFileSync('x', 'y')\"");
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "\"node -e\" must produce 1 finding, got: {}",
        findings.len()
    );
}

// AC11: "node --eval" → 1 finding
#[test]
fn ac11_node_eval_produces_finding() {
    let rule = R7InstallerInlineExec::new();
    let manifest = manifest_with_command("node --eval \"console.log('setup')\"");
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "\"node --eval\" must produce 1 finding, got: {}",
        findings.len()
    );
}

// AC12: "ruby -e" → 1 finding
#[test]
fn ac12_ruby_e_produces_finding() {
    let rule = R7InstallerInlineExec::new();
    let manifest = manifest_with_command("ruby -e \"puts 'hello'\"");
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "\"ruby -e\" must produce 1 finding, got: {}",
        findings.len()
    );
}

// AC13: "perl -e" → 1 finding
#[test]
fn ac13_perl_e_produces_finding() {
    let rule = R7InstallerInlineExec::new();
    let manifest = manifest_with_command("perl -e \"print 'hello'\"");
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "\"perl -e\" must produce 1 finding, got: {}",
        findings.len()
    );
}

// AC14: case-insensitive — "BASH -C" → 1 finding
#[test]
fn ac14_case_insensitive_match() {
    let rule = R7InstallerInlineExec::new();
    let manifest = manifest_with_command("BASH -C \"echo test\"");
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "\"BASH -C\" must match case-insensitively, got: {}",
        findings.len()
    );
}

// AC15: finding.location.path matches manifest_path argument
#[test]
fn ac15_finding_location_path() {
    let rule = R7InstallerInlineExec::new();
    let manifest = manifest_with_command("bash -c \"echo hello\"");
    let expected_path = Path::new("/tmp/skill/manifest.json");
    let findings = rule.check(&manifest, expected_path);
    assert!(!findings.is_empty());
    assert_eq!(
        findings[0].location.path.as_path(),
        expected_path,
        "finding.location.path must match manifest_path"
    );
}

// AC16: builtin_rules() includes R7InstallerInlineExec
#[test]
fn ac16_builtin_rules_contains_r7() {
    let rules = builtin_rules();
    let ids: Vec<String> = rules.iter().map(|r| r.id().0.clone()).collect();
    assert!(
        ids.contains(&"R7-installer-inline-exec".to_string()),
        "builtin_rules must include R7-installer-inline-exec, got: {:?}",
        ids
    );
}

// AC17: R7InstallerInlineExec is Send + Sync
#[test]
fn ac17_r7_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<R7InstallerInlineExec>();
    let _: Box<dyn Rule + Send + Sync> = Box::new(R7InstallerInlineExec::new());
}
