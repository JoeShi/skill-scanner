use skill_scanner_core::{RuleId, RuleOrigin, Severity};
use skill_scanner_manifest::SkillManifest;
use skill_scanner_rules::r10::R10DependencyProtocol;
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

fn manifest_with_deps(pairs: &[(&str, &str)]) -> SkillManifest {
    let mut deps = HashMap::new();
    for (k, v) in pairs {
        deps.insert(k.to_string(), v.to_string());
    }
    SkillManifest {
        dependencies: Some(deps),
        ..base_manifest()
    }
}

fn manifest_with_dev_deps(pairs: &[(&str, &str)]) -> SkillManifest {
    let mut dev_deps = HashMap::new();
    for (k, v) in pairs {
        dev_deps.insert(k.to_string(), v.to_string());
    }
    SkillManifest {
        dev_dependencies: Some(dev_deps),
        ..base_manifest()
    }
}

// AC1: correct rule ID
#[test]
fn ac1_r10_dependency_protocol_id() {
    let rule = R10DependencyProtocol::new();
    assert_eq!(rule.id(), &RuleId("R10-dependency-protocol".to_string()));
}

// AC2: BuiltIn origin
#[test]
fn ac2_r10_dependency_protocol_origin() {
    let rule = R10DependencyProtocol::new();
    assert_eq!(rule.origin(), RuleOrigin::BuiltIn);
}

// AC3: dependencies = None AND dev_dependencies = None → 0 findings
#[test]
fn ac3_both_deps_none_no_findings() {
    let rule = R10DependencyProtocol::new();
    let manifest = base_manifest();
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert!(
        findings.is_empty(),
        "both deps=None must produce 0 findings, got: {:?}",
        findings
    );
}

// AC4: semver version values → 0 findings
#[test]
fn ac4_semver_values_no_findings() {
    let rule = R10DependencyProtocol::new();
    let manifest = manifest_with_deps(&[
        ("lodash", "4.17.21"),
        ("express", "^4.18.0"),
        ("react", "~18.2.0"),
    ]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert!(
        findings.is_empty(),
        "semver values must produce 0 findings, got: {:?}",
        findings
    );
}

// AC5: https:// registry URL → 0 findings (secure protocol not flagged)
#[test]
fn ac5_https_url_no_findings() {
    let rule = R10DependencyProtocol::new();
    let manifest = manifest_with_deps(&[("pkg", "https://registry.example.com/pkg-1.0.0.tgz")]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert!(
        findings.is_empty(),
        "https:// must produce 0 findings, got: {:?}",
        findings
    );
}

// AC6: git+https:// → 0 findings (secure git protocol not flagged)
#[test]
fn ac6_git_https_url_no_findings() {
    let rule = R10DependencyProtocol::new();
    let manifest = manifest_with_deps(&[("pkg", "git+https://github.com/user/repo.git")]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert!(
        findings.is_empty(),
        "git+https:// must produce 0 findings, got: {:?}",
        findings
    );
}

// AC7: "file:" prefix → 1 finding, P0 severity
#[test]
fn ac7_file_prefix_produces_p0_finding() {
    let rule = R10DependencyProtocol::new();
    let manifest = manifest_with_deps(&[("local-pkg", "file:../local-package")]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "\"file:\" must produce 1 finding, got: {}",
        findings.len()
    );
    assert_eq!(
        findings[0].severity,
        Severity::P0,
        "R10 findings must be P0"
    );
}

// AC8: bare "git:" prefix (git protocol) → 1 finding
#[test]
fn ac8_bare_git_prefix_produces_finding() {
    let rule = R10DependencyProtocol::new();
    let manifest = manifest_with_deps(&[("pkg", "git://github.com/user/repo.git")]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "\"git:\" must produce 1 finding, got: {}",
        findings.len()
    );
}

// AC9: "git+http:" prefix (git over HTTP) → 1 finding
#[test]
fn ac9_git_http_prefix_produces_finding() {
    let rule = R10DependencyProtocol::new();
    let manifest = manifest_with_deps(&[("pkg", "git+http://github.com/user/repo.git")]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "\"git+http:\" must produce 1 finding, got: {}",
        findings.len()
    );
}

// AC10: "http:" prefix (plain HTTP registry URL) → 1 finding
#[test]
fn ac10_http_prefix_produces_finding() {
    let rule = R10DependencyProtocol::new();
    let manifest = manifest_with_deps(&[("pkg", "http://registry.example.com/pkg-1.0.0.tgz")]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "\"http:\" must produce 1 finding, got: {}",
        findings.len()
    );
}

// AC11: dangerous protocol in dev_dependencies → 1 finding (not only dependencies)
#[test]
fn ac11_dev_deps_dangerous_protocol_produces_finding() {
    let rule = R10DependencyProtocol::new();
    let manifest = manifest_with_dev_deps(&[("test-helper", "file:../test-helper")]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "dev_dependencies file: must produce 1 finding, got: {}",
        findings.len()
    );
}

// AC12: dangerous values in both dependencies and dev_dependencies → findings from both
#[test]
fn ac12_both_dicts_produce_findings() {
    let rule = R10DependencyProtocol::new();
    let mut deps = HashMap::new();
    deps.insert("pkg-a".to_string(), "file:../pkg-a".to_string());
    let mut dev_deps = HashMap::new();
    dev_deps.insert("pkg-b".to_string(), "git://github.com/x/y".to_string());
    let manifest = SkillManifest {
        dependencies: Some(deps),
        dev_dependencies: Some(dev_deps),
        ..base_manifest()
    };
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        2,
        "expected 2 findings (one per dict), got: {}",
        findings.len()
    );
}

// AC13: multiple dangerous values in same HashMap → one finding per dangerous value
#[test]
fn ac13_multiple_dangerous_values_multiple_findings() {
    let rule = R10DependencyProtocol::new();
    let manifest = manifest_with_deps(&[
        ("pkg-a", "file:../pkg-a"),
        ("pkg-b", "git://github.com/x/y"),
        ("pkg-c", "http://registry.example.com/pkg.tgz"),
    ]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        3,
        "expected 3 findings for 3 dangerous values, got: {}",
        findings.len()
    );
}

// AC14: mixed safe + dangerous → only dangerous values flagged
#[test]
fn ac14_mixed_deps_only_dangerous_flagged() {
    let rule = R10DependencyProtocol::new();
    let manifest = manifest_with_deps(&[
        ("lodash", "4.17.21"),
        ("local-pkg", "file:../local-pkg"),
        ("express", "^4.18.0"),
    ]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "only file: should be flagged, got: {}",
        findings.len()
    );
}

// AC15: finding.location.path matches manifest_path argument
#[test]
fn ac15_finding_location_path() {
    let rule = R10DependencyProtocol::new();
    let manifest = manifest_with_deps(&[("pkg", "file:../pkg")]);
    let expected_path = Path::new("/tmp/skill/manifest.json");
    let findings = rule.check(&manifest, expected_path);
    assert!(!findings.is_empty());
    assert_eq!(
        findings[0].location.path.as_path(),
        expected_path,
        "finding.location.path must match manifest_path"
    );
}

// AC16: builtin_rules() includes R10DependencyProtocol
#[test]
fn ac16_builtin_rules_contains_r10() {
    let rules = builtin_rules();
    let ids: Vec<String> = rules.iter().map(|r| r.id().0.clone()).collect();
    assert!(
        ids.contains(&"R10-dependency-protocol".to_string()),
        "builtin_rules must include R10-dependency-protocol, got: {:?}",
        ids
    );
}

// AC17: R10DependencyProtocol is Send + Sync
#[test]
fn ac17_r10_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<R10DependencyProtocol>();
    let _: Box<dyn Rule + Send + Sync> = Box::new(R10DependencyProtocol::new());
}
