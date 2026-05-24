use skill_scanner_core::{RuleId, RuleOrigin, Severity};
use skill_scanner_manifest::SkillManifest;
use skill_scanner_rules::r8::R8FsPathsEscape;
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

fn manifest_with_paths(paths: &[&str]) -> SkillManifest {
    SkillManifest {
        fs_paths: Some(paths.iter().map(|s| s.to_string()).collect()),
        ..base_manifest()
    }
}

// AC1: correct rule ID
#[test]
fn ac1_r8_fs_paths_escape_id() {
    let rule = R8FsPathsEscape::new();
    assert_eq!(rule.id(), &RuleId("R8-fs-paths-escape".to_string()));
}

// AC2: BuiltIn origin
#[test]
fn ac2_r8_fs_paths_escape_origin() {
    let rule = R8FsPathsEscape::new();
    assert_eq!(rule.origin(), RuleOrigin::BuiltIn);
}

// AC3: fs_paths = None → 0 findings
#[test]
fn ac3_fs_paths_none_no_findings() {
    let rule = R8FsPathsEscape::new();
    let manifest = base_manifest();
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert!(
        findings.is_empty(),
        "fs_paths=None must produce 0 findings, got: {:?}",
        findings
    );
}

// AC4: fs_paths = empty vec → 0 findings
#[test]
fn ac4_fs_paths_empty_no_findings() {
    let rule = R8FsPathsEscape::new();
    let manifest = manifest_with_paths(&[]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert!(
        findings.is_empty(),
        "fs_paths=[] must produce 0 findings, got: {:?}",
        findings
    );
}

// AC5: benign relative paths → 0 findings
#[test]
fn ac5_benign_relative_paths_no_findings() {
    let rule = R8FsPathsEscape::new();
    let manifest = manifest_with_paths(&["./data", "cache/", "assets", "data/output.json"]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert!(
        findings.is_empty(),
        "benign relative paths must produce 0 findings, got: {:?}",
        findings
    );
}

// AC6: Unix absolute path → 1 finding, P0 severity
#[test]
fn ac6_unix_absolute_path_produces_p0_finding() {
    let rule = R8FsPathsEscape::new();
    let manifest = manifest_with_paths(&["/etc/passwd"]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "\"/etc/passwd\" must produce 1 finding, got: {}",
        findings.len()
    );
    assert_eq!(findings[0].severity, Severity::P0, "R8 findings must be P0");
}

// AC7: home-dir prefix "~" → 1 finding
#[test]
fn ac7_home_dir_tilde_produces_finding() {
    let rule = R8FsPathsEscape::new();
    let manifest = manifest_with_paths(&["~/.ssh/id_rsa"]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "\"~/.ssh/id_rsa\" must produce 1 finding, got: {}",
        findings.len()
    );
}

// AC8: parent traversal ".." segment → 1 finding
#[test]
fn ac8_parent_traversal_produces_finding() {
    let rule = R8FsPathsEscape::new();
    let manifest = manifest_with_paths(&["../../secret"]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "\"../../secret\" must produce 1 finding, got: {}",
        findings.len()
    );
}

// AC9: embedded ".." traversal in otherwise relative path → 1 finding
#[test]
fn ac9_embedded_traversal_produces_finding() {
    let rule = R8FsPathsEscape::new();
    let manifest = manifest_with_paths(&["data/../../../etc"]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "\"data/../../../etc\" must produce 1 finding, got: {}",
        findings.len()
    );
}

// AC10: Windows-style absolute path "C:\" → 1 finding
#[test]
fn ac10_windows_absolute_path_produces_finding() {
    let rule = R8FsPathsEscape::new();
    let manifest = manifest_with_paths(&["C:\\Windows\\System32"]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "\"C:\\Windows\\System32\" must produce 1 finding, got: {}",
        findings.len()
    );
}

// AC11: Windows forward-slash absolute path "C:/..." → 1 finding
#[test]
fn ac11_windows_forward_slash_absolute_produces_finding() {
    let rule = R8FsPathsEscape::new();
    let manifest = manifest_with_paths(&["C:/Users/secret"]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "\"C:/Users/secret\" must produce 1 finding, got: {}",
        findings.len()
    );
}

// AC12: multiple dangerous paths → one finding per dangerous path
#[test]
fn ac12_multiple_dangerous_paths_multiple_findings() {
    let rule = R8FsPathsEscape::new();
    let manifest = manifest_with_paths(&["/etc/passwd", "~/.ssh", "../../secret"]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        3,
        "expected 3 findings for 3 dangerous paths, got: {}",
        findings.len()
    );
}

// AC13: mixed safe + dangerous → only dangerous paths flagged
#[test]
fn ac13_mixed_paths_only_dangerous_flagged() {
    let rule = R8FsPathsEscape::new();
    let manifest = manifest_with_paths(&["./data", "/etc/hosts", "cache/"]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "only \"/etc/hosts\" should be flagged, got: {}",
        findings.len()
    );
}

// AC14: finding.location.path matches manifest_path argument
#[test]
fn ac14_finding_location_path() {
    let rule = R8FsPathsEscape::new();
    let manifest = manifest_with_paths(&["/etc/passwd"]);
    let expected_path = Path::new("/tmp/skill/manifest.json");
    let findings = rule.check(&manifest, expected_path);
    assert!(!findings.is_empty());
    assert_eq!(
        findings[0].location.path.as_path(),
        expected_path,
        "finding.location.path must match manifest_path"
    );
}

// AC15: builtin_rules() includes R8FsPathsEscape
#[test]
fn ac15_builtin_rules_contains_r8() {
    let rules = builtin_rules();
    let ids: Vec<String> = rules.iter().map(|r| r.id().0.clone()).collect();
    assert!(
        ids.contains(&"R8-fs-paths-escape".to_string()),
        "builtin_rules must include R8-fs-paths-escape, got: {:?}",
        ids
    );
}

// AC16: R8FsPathsEscape is Send + Sync
#[test]
fn ac16_r8_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<R8FsPathsEscape>();
    let _: Box<dyn Rule + Send + Sync> = Box::new(R8FsPathsEscape::new());
}
