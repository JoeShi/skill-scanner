//! R9 — domains-wildcard rule
//! Detects wildcard patterns in manifest.domains entries.

use skill_scanner_core::{Finding, Location, RuleId, RuleOrigin, Severity};
use skill_scanner_manifest::SkillManifest;
use std::path::Path;

use crate::Rule;

pub struct R9DomainsWildcard;

impl Default for R9DomainsWildcard {
    fn default() -> Self {
        Self
    }
}

impl R9DomainsWildcard {
    pub fn new() -> Self {
        Self
    }
}

impl Rule for R9DomainsWildcard {
    fn id(&self) -> &RuleId {
        static ID: std::sync::LazyLock<RuleId> =
            std::sync::LazyLock::new(|| RuleId("R9-domains-wildcard".to_string()));
        &ID
    }

    fn origin(&self) -> RuleOrigin {
        RuleOrigin::BuiltIn
    }

    fn check(&self, manifest: &SkillManifest, manifest_path: &Path) -> Vec<Finding> {
        let domains = match &manifest.domains {
            Some(d) => d,
            None => return vec![],
        };

        let mut findings = Vec::new();
        for domain in domains {
            if domain.contains('*') {
                findings.push(Finding {
                    rule_id: self.id().clone(),
                    rule_origin: self.origin(),
                    severity: Severity::P0,
                    message: format!(
                        r#"manifest.domains entry "{}" contains a wildcard pattern"#,
                        domain
                    ),
                    location: Location {
                        path: manifest_path.to_path_buf(),
                        line: None,
                        column: None,
                    },
                });
            }
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use skill_scanner_manifest::SkillManifest;
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

    #[test]
    fn red_id_is_r9() {
        let r = R9DomainsWildcard::new();
        assert_eq!(r.id().0, "R9-domains-wildcard");
    }

    #[test]
    fn red_origin_is_builtin() {
        let r = R9DomainsWildcard::new();
        assert!(matches!(r.origin(), RuleOrigin::BuiltIn));
    }

    #[test]
    fn red_none_domains_no_findings() {
        let r = R9DomainsWildcard::new();
        let m = base_manifest();
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert!(findings.is_empty());
    }

    #[test]
    fn red_empty_domains_no_findings() {
        let r = R9DomainsWildcard::new();
        let m = manifest_with_domains(&[]);
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert!(findings.is_empty());
    }

    #[test]
    fn red_benign_domains_no_findings() {
        let r = R9DomainsWildcard::new();
        let m = manifest_with_domains(&["api.example.com", "cdn.service.io", "auth.provider.net"]);
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert!(findings.is_empty());
    }

    #[test]
    fn red_bare_wildcard_produces_p0() {
        let r = R9DomainsWildcard::new();
        let m = manifest_with_domains(&["*"]);
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::P0);
    }

    #[test]
    fn red_wildcard_subdomain_produces_finding() {
        let r = R9DomainsWildcard::new();
        let m = manifest_with_domains(&["*.example.com"]);
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn red_leading_dot_wildcard_produces_finding() {
        let r = R9DomainsWildcard::new();
        let m = manifest_with_domains(&[".*"]);
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn red_embedded_wildcard_produces_finding() {
        let r = R9DomainsWildcard::new();
        let m = manifest_with_domains(&["api.*.com"]);
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn red_multiple_wildcards_multiple_findings() {
        let r = R9DomainsWildcard::new();
        let m = manifest_with_domains(&["*", "*.evil.io", "data.*.net"]);
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 3);
    }

    #[test]
    fn red_mixed_domains_only_wildcards_flagged() {
        let r = R9DomainsWildcard::new();
        let m = manifest_with_domains(&["api.example.com", "*.evil.io", "cdn.service.net"]);
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("*.evil.io"));
    }

    #[test]
    fn red_location_path_matches_manifest_path() {
        let r = R9DomainsWildcard::new();
        let m = manifest_with_domains(&["*"]);
        let expected_path = Path::new("/tmp/skill/manifest.json");
        let findings = r.check(&m, expected_path);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].location.path.as_path(), expected_path);
    }

    #[test]
    fn red_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<R9DomainsWildcard>();
    }
}
