use skill_scanner_core::{RuleId, RuleOrigin, Severity};
use skill_scanner_manifest::{CapabilityDeclaration, SkillManifest};
use skill_scanner_rules::r0::{R0ManifestStructure, R0MissingCapabilities};
use skill_scanner_rules::{builtin_rules, Rule};
use std::path::Path;

fn valid_manifest() -> SkillManifest {
    SkillManifest {
        name: "test-skill".to_string(),
        version: "1.0.0".to_string(),
        description: Some("A test skill".to_string()),
        main: Some("index.js".to_string()),
        author: Some("Alice".to_string()),
        license: Some("MIT".to_string()),
        capabilities: Some(vec![CapabilityDeclaration {
            resource: "fs.read".to_string(),
            scope: None,
            name: None,
            reason: None,
        }]),
        domains: None,
        fs_paths: None,
        dependencies: None,
        dev_dependencies: None,
        publisher: None,
        installer: None,
        env: None,
    }
}

// AC1: R0ManifestStructure has correct rule ID
#[test]
fn ac1_r0_structure_id() {
    let rule = R0ManifestStructure::new();
    assert_eq!(rule.id(), &RuleId("R0-manifest-structure".to_string()));
}

// AC2: R0ManifestStructure has BuiltIn origin
#[test]
fn ac2_r0_structure_origin() {
    let rule = R0ManifestStructure::new();
    assert_eq!(rule.origin(), RuleOrigin::BuiltIn);
}

// AC3: valid manifest → zero findings
#[test]
fn ac3_r0_structure_valid_no_findings() {
    let rule = R0ManifestStructure::new();
    let findings = rule.check(&valid_manifest(), Path::new("manifest.json"));
    assert!(
        findings.is_empty(),
        "expected no findings for valid manifest, got: {:?}",
        findings
    );
}

// AC4: missing required fields → at least one finding per missing field
#[test]
fn ac4_r0_structure_missing_fields_produce_findings() {
    let rule = R0ManifestStructure::new();
    let manifest = SkillManifest {
        description: None,
        main: None,
        author: None,
        license: None,
        ..valid_manifest()
    };
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert!(
        findings.len() >= 4,
        "expected ≥4 findings for 4 missing required fields, got: {}",
        findings.len()
    );
}

// AC5: all findings from R0ManifestStructure have P0 severity
#[test]
fn ac5_r0_structure_findings_severity_p0() {
    let rule = R0ManifestStructure::new();
    let manifest = SkillManifest {
        description: None,
        ..valid_manifest()
    };
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert!(!findings.is_empty(), "expected at least one finding");
    for f in &findings {
        assert_eq!(
            f.severity,
            Severity::P0,
            "R0 findings must be P0, got {:?}",
            f.severity
        );
    }
}

// AC6: finding.location.path matches the manifest_path argument
#[test]
fn ac6_r0_structure_finding_location_path() {
    let rule = R0ManifestStructure::new();
    let manifest = SkillManifest {
        description: None,
        ..valid_manifest()
    };
    let expected_path = Path::new("/tmp/my-skill/manifest.json");
    let findings = rule.check(&manifest, expected_path);
    assert!(!findings.is_empty(), "expected at least one finding");
    for f in &findings {
        assert_eq!(
            f.location.path.as_path(),
            expected_path,
            "finding.location.path must match manifest_path"
        );
    }
}

// AC7: R0MissingCapabilities has correct rule ID
#[test]
fn ac7_r0_capabilities_id() {
    let rule = R0MissingCapabilities::new();
    assert_eq!(rule.id(), &RuleId("R0-missing-capabilities".to_string()));
}

// AC8: R0MissingCapabilities has BuiltIn origin
#[test]
fn ac8_r0_capabilities_origin() {
    let rule = R0MissingCapabilities::new();
    assert_eq!(rule.origin(), RuleOrigin::BuiltIn);
}

// AC9: manifest with non-empty capabilities → zero findings
#[test]
fn ac9_r0_capabilities_present_no_findings() {
    let rule = R0MissingCapabilities::new();
    let findings = rule.check(&valid_manifest(), Path::new("manifest.json"));
    assert!(
        findings.is_empty(),
        "expected no findings when capabilities present, got: {:?}",
        findings
    );
}

// AC10: manifest with capabilities = None → one finding
#[test]
fn ac10_r0_capabilities_none_produces_finding() {
    let rule = R0MissingCapabilities::new();
    let manifest = SkillManifest {
        capabilities: None,
        ..valid_manifest()
    };
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "expected exactly 1 finding for None capabilities, got: {}",
        findings.len()
    );
}

// AC11: manifest with capabilities = empty vec → one finding
#[test]
fn ac11_r0_capabilities_empty_vec_produces_finding() {
    let rule = R0MissingCapabilities::new();
    let manifest = SkillManifest {
        capabilities: Some(vec![]),
        ..valid_manifest()
    };
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "expected exactly 1 finding for empty capabilities, got: {}",
        findings.len()
    );
}

// AC12: R0MissingCapabilities finding has P0 severity
#[test]
fn ac12_r0_capabilities_finding_severity_p0() {
    let rule = R0MissingCapabilities::new();
    let manifest = SkillManifest {
        capabilities: None,
        ..valid_manifest()
    };
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert!(!findings.is_empty());
    assert_eq!(findings[0].severity, Severity::P0);
}

// AC13: builtin_rules() contains both R0 sub-rules
#[test]
fn ac13_builtin_rules_contains_r0_rules() {
    let rules = builtin_rules();
    let ids: Vec<String> = rules.iter().map(|r| r.id().0.clone()).collect();
    assert!(
        ids.contains(&"R0-manifest-structure".to_string()),
        "builtin_rules must include R0-manifest-structure, got: {:?}",
        ids
    );
    assert!(
        ids.contains(&"R0-missing-capabilities".to_string()),
        "builtin_rules must include R0-missing-capabilities, got: {:?}",
        ids
    );
}

// AC14: Rule trait is Send + Sync (compile-time check)
#[test]
fn ac14_rule_trait_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<R0ManifestStructure>();
    assert_send_sync::<R0MissingCapabilities>();
    // dyn Rule must also be usable across threads
    let _: Box<dyn Rule + Send + Sync> = Box::new(R0ManifestStructure::new());
}
