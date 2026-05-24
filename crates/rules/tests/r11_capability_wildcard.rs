use skill_scanner_core::{RuleId, RuleOrigin, Severity};
use skill_scanner_manifest::{CapabilityDeclaration, SkillManifest};
use skill_scanner_rules::r11::R11CapabilityWildcard;
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

fn manifest_with_capabilities(caps: Vec<CapabilityDeclaration>) -> SkillManifest {
    SkillManifest {
        capabilities: Some(caps),
        ..base_manifest()
    }
}

fn cap(resource: &str, scope: Option<&str>) -> CapabilityDeclaration {
    CapabilityDeclaration {
        resource: resource.to_string(),
        scope: scope.map(|s| s.to_string()),
        name: None,
        reason: None,
    }
}

// AC1: correct rule ID
#[test]
fn ac1_r11_capability_wildcard_id() {
    let rule = R11CapabilityWildcard::new();
    assert_eq!(rule.id(), &RuleId("R11-capability-wildcard".to_string()));
}

// AC2: BuiltIn origin
#[test]
fn ac2_r11_capability_wildcard_origin() {
    let rule = R11CapabilityWildcard::new();
    assert_eq!(rule.origin(), RuleOrigin::BuiltIn);
}

// AC3: capabilities = None → 0 findings
#[test]
fn ac3_capabilities_none_no_findings() {
    let rule = R11CapabilityWildcard::new();
    let manifest = base_manifest();
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert!(
        findings.is_empty(),
        "capabilities=None must produce 0 findings, got: {:?}",
        findings
    );
}

// AC4: capabilities = empty vec → 0 findings
#[test]
fn ac4_capabilities_empty_no_findings() {
    let rule = R11CapabilityWildcard::new();
    let manifest = manifest_with_capabilities(vec![]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert!(
        findings.is_empty(),
        "capabilities=[] must produce 0 findings, got: {:?}",
        findings
    );
}

// AC5: capabilities with specific (non-wildcard) scopes → 0 findings
#[test]
fn ac5_specific_scopes_no_findings() {
    let rule = R11CapabilityWildcard::new();
    let manifest = manifest_with_capabilities(vec![
        cap("network.outbound", Some("read")),
        cap("fs", Some("files:data")),
        cap("process", Some("spawn:allowed")),
    ]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert!(
        findings.is_empty(),
        "specific scopes must produce 0 findings, got: {:?}",
        findings
    );
}

// AC6: scope = None (undeclared) → 0 findings
#[test]
fn ac6_scope_none_no_findings() {
    let rule = R11CapabilityWildcard::new();
    let manifest = manifest_with_capabilities(vec![cap("network.outbound", None)]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert!(
        findings.is_empty(),
        "scope=None must produce 0 findings, got: {:?}",
        findings
    );
}

// AC7: scope = "*" → 1 finding, P0 severity
#[test]
fn ac7_scope_bare_wildcard_produces_p0_finding() {
    let rule = R11CapabilityWildcard::new();
    let manifest = manifest_with_capabilities(vec![cap("network.outbound", Some("*"))]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "scope=\"*\" must produce 1 finding, got: {}",
        findings.len()
    );
    assert_eq!(
        findings[0].severity,
        Severity::P0,
        "R11 findings must be P0"
    );
}

// AC8: scope = "read:*" (partial wildcard) → 1 finding
#[test]
fn ac8_scope_partial_wildcard_produces_finding() {
    let rule = R11CapabilityWildcard::new();
    let manifest = manifest_with_capabilities(vec![cap("fs", Some("read:*"))]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "scope=\"read:*\" must produce 1 finding, got: {}",
        findings.len()
    );
}

// AC9: multiple capabilities with wildcard scopes → one finding per wildcard entry
#[test]
fn ac9_multiple_wildcard_scopes_multiple_findings() {
    let rule = R11CapabilityWildcard::new();
    let manifest = manifest_with_capabilities(vec![
        cap("network.outbound", Some("*")),
        cap("fs", Some("write:*")),
        cap("process", Some("*")),
    ]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        3,
        "expected 3 findings for 3 wildcard scopes, got: {}",
        findings.len()
    );
}

// AC10: mixed safe + wildcard scopes → only wildcard-scoped entries flagged
#[test]
fn ac10_mixed_capabilities_only_wildcards_flagged() {
    let rule = R11CapabilityWildcard::new();
    let manifest = manifest_with_capabilities(vec![
        cap("network.outbound", Some("read")),
        cap("fs", Some("write:*")),
        cap("process", None),
    ]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "only scope=\"write:*\" should be flagged, got: {}",
        findings.len()
    );
}

// AC11: finding.location.path matches manifest_path argument
#[test]
fn ac11_finding_location_path() {
    let rule = R11CapabilityWildcard::new();
    let manifest = manifest_with_capabilities(vec![cap("network.outbound", Some("*"))]);
    let expected_path = Path::new("/tmp/skill/manifest.json");
    let findings = rule.check(&manifest, expected_path);
    assert!(!findings.is_empty());
    assert_eq!(
        findings[0].location.path.as_path(),
        expected_path,
        "finding.location.path must match manifest_path"
    );
}

// AC12: builtin_rules() includes R11CapabilityWildcard
#[test]
fn ac12_builtin_rules_contains_r11() {
    let rules = builtin_rules();
    let ids: Vec<String> = rules.iter().map(|r| r.id().0.clone()).collect();
    assert!(
        ids.contains(&"R11-capability-wildcard".to_string()),
        "builtin_rules must include R11-capability-wildcard, got: {:?}",
        ids
    );
}

// AC13: R11CapabilityWildcard is Send + Sync
#[test]
fn ac13_r11_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<R11CapabilityWildcard>();
    let _: Box<dyn Rule + Send + Sync> = Box::new(R11CapabilityWildcard::new());
}
