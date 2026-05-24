use skill_scanner_core::{RuleId, RuleOrigin, Severity};
use skill_scanner_manifest::SkillManifest;
use skill_scanner_rules::r9::R9DomainsWildcard;
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

fn manifest_with_domains(domains: &[&str]) -> SkillManifest {
    SkillManifest {
        domains: Some(domains.iter().map(|s| s.to_string()).collect()),
        ..base_manifest()
    }
}

// AC1: correct rule ID
#[test]
fn ac1_r9_domains_wildcard_id() {
    let rule = R9DomainsWildcard::new();
    assert_eq!(rule.id(), &RuleId("R9-domains-wildcard".to_string()));
}

// AC2: BuiltIn origin
#[test]
fn ac2_r9_domains_wildcard_origin() {
    let rule = R9DomainsWildcard::new();
    assert_eq!(rule.origin(), RuleOrigin::BuiltIn);
}

// AC3: domains = None → 0 findings
#[test]
fn ac3_domains_none_no_findings() {
    let rule = R9DomainsWildcard::new();
    let manifest = base_manifest();
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert!(
        findings.is_empty(),
        "domains=None must produce 0 findings, got: {:?}",
        findings
    );
}

// AC4: domains = empty vec → 0 findings
#[test]
fn ac4_domains_empty_no_findings() {
    let rule = R9DomainsWildcard::new();
    let manifest = manifest_with_domains(&[]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert!(
        findings.is_empty(),
        "domains=[] must produce 0 findings, got: {:?}",
        findings
    );
}

// AC5: benign specific domains → 0 findings
#[test]
fn ac5_benign_specific_domains_no_findings() {
    let rule = R9DomainsWildcard::new();
    let manifest =
        manifest_with_domains(&["api.example.com", "cdn.service.io", "auth.provider.net"]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert!(
        findings.is_empty(),
        "specific domains must produce 0 findings, got: {:?}",
        findings
    );
}

// AC6: bare wildcard "*" → 1 finding, P0 severity
#[test]
fn ac6_bare_wildcard_produces_p0_finding() {
    let rule = R9DomainsWildcard::new();
    let manifest = manifest_with_domains(&["*"]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "\"*\" must produce 1 finding, got: {}",
        findings.len()
    );
    assert_eq!(findings[0].severity, Severity::P0, "R9 findings must be P0");
}

// AC7: wildcard subdomain "*.example.com" → 1 finding
#[test]
fn ac7_wildcard_subdomain_produces_finding() {
    let rule = R9DomainsWildcard::new();
    let manifest = manifest_with_domains(&["*.example.com"]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "\"*.example.com\" must produce 1 finding, got: {}",
        findings.len()
    );
}

// AC8: leading-dot wildcard ".*" → 1 finding
#[test]
fn ac8_leading_dot_wildcard_produces_finding() {
    let rule = R9DomainsWildcard::new();
    let manifest = manifest_with_domains(&[".*"]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "\".*\" must produce 1 finding, got: {}",
        findings.len()
    );
}

// AC9: embedded wildcard "api.*.com" → 1 finding
#[test]
fn ac9_embedded_wildcard_produces_finding() {
    let rule = R9DomainsWildcard::new();
    let manifest = manifest_with_domains(&["api.*.com"]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "\"api.*.com\" must produce 1 finding, got: {}",
        findings.len()
    );
}

// AC10: multiple wildcard domains → one finding per wildcard entry
#[test]
fn ac10_multiple_wildcards_multiple_findings() {
    let rule = R9DomainsWildcard::new();
    let manifest = manifest_with_domains(&["*", "*.evil.io", "data.*.net"]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        3,
        "expected 3 findings for 3 wildcard domains, got: {}",
        findings.len()
    );
}

// AC11: mixed safe + wildcard → only wildcard entries flagged
#[test]
fn ac11_mixed_domains_only_wildcards_flagged() {
    let rule = R9DomainsWildcard::new();
    let manifest = manifest_with_domains(&["api.example.com", "*.evil.io", "cdn.service.net"]);
    let findings = rule.check(&manifest, Path::new("manifest.json"));
    assert_eq!(
        findings.len(),
        1,
        "only \"*.evil.io\" should be flagged, got: {}",
        findings.len()
    );
}

// AC12: finding.location.path matches manifest_path argument
#[test]
fn ac12_finding_location_path() {
    let rule = R9DomainsWildcard::new();
    let manifest = manifest_with_domains(&["*"]);
    let expected_path = Path::new("/tmp/skill/manifest.json");
    let findings = rule.check(&manifest, expected_path);
    assert!(!findings.is_empty());
    assert_eq!(
        findings[0].location.path.as_path(),
        expected_path,
        "finding.location.path must match manifest_path"
    );
}

// AC13: builtin_rules() includes R9DomainsWildcard
#[test]
fn ac13_builtin_rules_contains_r9() {
    let rules = builtin_rules();
    let ids: Vec<String> = rules.iter().map(|r| r.id().0.clone()).collect();
    assert!(
        ids.contains(&"R9-domains-wildcard".to_string()),
        "builtin_rules must include R9-domains-wildcard, got: {:?}",
        ids
    );
}

// AC14: R9DomainsWildcard is Send + Sync
#[test]
fn ac14_r9_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<R9DomainsWildcard>();
    let _: Box<dyn Rule + Send + Sync> = Box::new(R9DomainsWildcard::new());
}
