use skill_scanner_core::{RuleId, RuleOrigin, Severity};
use skill_scanner_manifest::SkillManifest;
use skill_scanner_rules::r12::R12MainFieldEscape;
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

fn manifest_with_main(main: Option<&str>) -> SkillManifest {
    SkillManifest {
        main: main.map(|s| s.to_string()),
        ..base_manifest()
    }
}

// AC1: correct rule ID
#[test]
fn ac1_r12_main_field_escape_id() {
    let rule = R12MainFieldEscape::new();
    assert_eq!(rule.id(), &RuleId("R12-main-field-escape".to_string()));
}

// AC2: BuiltIn origin
#[test]
fn ac2_r12_main_field_escape_origin() {
    let rule = R12MainFieldEscape::new();
    assert_eq!(rule.origin(), RuleOrigin::BuiltIn);
}

// AC3: main = None → 0 findings
#[test]
fn ac3_main_none_no_findings() {
    let rule = R12MainFieldEscape::new();
    let manifest = manifest_with_main(None);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert!(
        findings.is_empty(),
        "main=None must produce 0 findings, got: {:?}",
        findings
    );
}

// AC4: safe "./index.js" → 0 findings
#[test]
fn ac4_dot_slash_relative_no_findings() {
    let rule = R12MainFieldEscape::new();
    let manifest = manifest_with_main(Some("./index.js"));
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert!(
        findings.is_empty(),
        "\"./index.js\" must produce 0 findings, got: {:?}",
        findings
    );
}

// AC5: safe bare "index.js" → 0 findings
#[test]
fn ac5_bare_relative_no_findings() {
    let rule = R12MainFieldEscape::new();
    let manifest = manifest_with_main(Some("index.js"));
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert!(
        findings.is_empty(),
        "\"index.js\" must produce 0 findings, got: {:?}",
        findings
    );
}

// AC6: safe subpath "src/main.js" → 0 findings
#[test]
fn ac6_subpath_no_findings() {
    let rule = R12MainFieldEscape::new();
    let manifest = manifest_with_main(Some("src/main.js"));
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert!(
        findings.is_empty(),
        "\"src/main.js\" must produce 0 findings, got: {:?}",
        findings
    );
}

// AC7: Unix absolute path → 1 finding, P0 severity
#[test]
fn ac7_unix_absolute_path_produces_p0_finding() {
    let rule = R12MainFieldEscape::new();
    let manifest = manifest_with_main(Some("/usr/bin/evil.js"));
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "\"/usr/bin/evil.js\" must produce 1 finding, got: {}",
        findings.len()
    );
    assert_eq!(
        findings[0].severity,
        Severity::P0,
        "R12 findings must be P0"
    );
}

// AC8: home-dir prefix "~" → 1 finding
#[test]
fn ac8_home_dir_tilde_produces_finding() {
    let rule = R12MainFieldEscape::new();
    let manifest = manifest_with_main(Some("~/.evil/run.js"));
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "\"~/.evil/run.js\" must produce 1 finding, got: {}",
        findings.len()
    );
}

// AC9: parent traversal ".." → 1 finding
#[test]
fn ac9_traversal_produces_finding() {
    let rule = R12MainFieldEscape::new();
    let manifest = manifest_with_main(Some("../../etc/malware.js"));
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "\"../../etc/malware.js\" must produce 1 finding, got: {}",
        findings.len()
    );
}

// AC10: "http://" remote URL → 1 finding (fetch-and-execute)
#[test]
fn ac10_http_url_produces_finding() {
    let rule = R12MainFieldEscape::new();
    let manifest = manifest_with_main(Some("http://evil.com/malware.js"));
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "\"http://\" must produce 1 finding, got: {}",
        findings.len()
    );
}

// AC11: "https://" remote URL → 1 finding (RCE primitive even over HTTPS)
#[test]
fn ac11_https_url_produces_finding() {
    let rule = R12MainFieldEscape::new();
    let manifest = manifest_with_main(Some("https://evil.com/malware.js"));
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "\"https://\" in main must produce 1 finding (RCE), got: {}",
        findings.len()
    );
}

// AC12: "ftp://" remote URL → 1 finding
#[test]
fn ac12_ftp_url_produces_finding() {
    let rule = R12MainFieldEscape::new();
    let manifest = manifest_with_main(Some("ftp://files.example.com/evil.js"));
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "\"ftp://\" must produce 1 finding, got: {}",
        findings.len()
    );
}

// AC13: "git://" remote URL → 1 finding
#[test]
fn ac13_git_url_produces_finding() {
    let rule = R12MainFieldEscape::new();
    let manifest = manifest_with_main(Some("git://github.com/evil/payload.js"));
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "\"git://\" must produce 1 finding, got: {}",
        findings.len()
    );
}

// AC14: Windows absolute path "C:\..." → 1 finding
#[test]
fn ac14_windows_absolute_produces_finding() {
    let rule = R12MainFieldEscape::new();
    let manifest = manifest_with_main(Some("C:\\Windows\\evil.exe"));
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "\"C:\\...\" must produce 1 finding, got: {}",
        findings.len()
    );
}

// AC15: finding.location.path matches manifest_path argument
#[test]
fn ac15_finding_location_path() {
    let rule = R12MainFieldEscape::new();
    let manifest = manifest_with_main(Some("/usr/bin/evil.js"));
    let expected_path = Path::new("/tmp/skill/manifest.json");
    let findings = rule.check(&manifest, expected_path);
    assert!(!findings.is_empty());
    assert_eq!(
        findings[0].location.path.as_path(),
        expected_path,
        "finding.location.path must match manifest_path"
    );
}

// AC16: builtin_rules() includes R12MainFieldEscape
#[test]
fn ac16_builtin_rules_contains_r12() {
    let rules = builtin_rules();
    let ids: Vec<String> = rules.iter().map(|r| r.id().0.clone()).collect();
    assert!(
        ids.contains(&"R12-main-field-escape".to_string()),
        "builtin_rules must include R12-main-field-escape, got: {:?}",
        ids
    );
}

// AC17: R12MainFieldEscape is Send + Sync
#[test]
fn ac17_r12_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<R12MainFieldEscape>();
    let _: Box<dyn Rule + Send + Sync> = Box::new(R12MainFieldEscape::new());
}
