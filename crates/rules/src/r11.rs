//! R11 — capability-wildcard rule
//! Detects wildcard patterns in manifest.capabilities scope fields.

use skill_scanner_core::{Finding, Location, RuleId, RuleOrigin, Severity};
use skill_scanner_manifest::SkillManifest;
use std::path::Path;

use crate::Rule;

pub struct R11CapabilityWildcard;

impl Default for R11CapabilityWildcard {
    fn default() -> Self {
        Self
    }
}

impl R11CapabilityWildcard {
    pub fn new() -> Self {
        Self
    }
}

impl Rule for R11CapabilityWildcard {
    fn id(&self) -> &RuleId {
        static ID: std::sync::LazyLock<RuleId> =
            std::sync::LazyLock::new(|| RuleId("R11-capability-wildcard".to_string()));
        &ID
    }

    fn origin(&self) -> RuleOrigin {
        RuleOrigin::BuiltIn
    }

    fn check(&self, manifest: &SkillManifest, manifest_path: &Path) -> Vec<Finding> {
        let capabilities = match &manifest.capabilities {
            Some(c) => c,
            None => return vec![],
        };

        let mut findings = Vec::new();
        for cap in capabilities {
            if let Some(scope) = &cap.scope {
                if scope.contains('*') {
                    findings.push(Finding {
                        rule_id: self.id().clone(),
                        rule_origin: self.origin(),
                        severity: Severity::P0,
                        message: format!(
                            r#"manifest.capabilities scope "{}" for resource "{}" contains a wildcard"#,
                            scope, cap.resource
                        ),
                        location: Location {
                            path: manifest_path.to_path_buf(),
                            line: None,
                            column: None,
                        },
                    });
                }
            }
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use skill_scanner_manifest::{CapabilityDeclaration, SkillManifest};
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

    #[test]
    fn red_id_is_r11() {
        let r = R11CapabilityWildcard::new();
        assert_eq!(r.id().0, "R11-capability-wildcard");
    }

    #[test]
    fn red_origin_is_builtin() {
        let r = R11CapabilityWildcard::new();
        assert!(matches!(r.origin(), RuleOrigin::BuiltIn));
    }

    #[test]
    fn red_none_capabilities_no_findings() {
        let r = R11CapabilityWildcard::new();
        let m = base_manifest();
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert!(findings.is_empty());
    }

    #[test]
    fn red_empty_capabilities_no_findings() {
        let r = R11CapabilityWildcard::new();
        let m = manifest_with_capabilities(vec![]);
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert!(findings.is_empty());
    }

    #[test]
    fn red_specific_scopes_no_findings() {
        let r = R11CapabilityWildcard::new();
        let m = manifest_with_capabilities(vec![
            cap("network.outbound", Some("read")),
            cap("fs", Some("files:data")),
            cap("process", Some("spawn:allowed")),
        ]);
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert!(findings.is_empty());
    }

    #[test]
    fn red_scope_none_no_findings() {
        let r = R11CapabilityWildcard::new();
        let m = manifest_with_capabilities(vec![cap("network.outbound", None)]);
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert!(findings.is_empty());
    }

    #[test]
    fn red_bare_wildcard_produces_p0() {
        let r = R11CapabilityWildcard::new();
        let m = manifest_with_capabilities(vec![cap("network.outbound", Some("*"))]);
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::P0);
    }

    #[test]
    fn red_partial_wildcard_produces_finding() {
        let r = R11CapabilityWildcard::new();
        let m = manifest_with_capabilities(vec![cap("fs", Some("read:*"))]);
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn red_multiple_wildcards_multiple_findings() {
        let r = R11CapabilityWildcard::new();
        let m = manifest_with_capabilities(vec![
            cap("network.outbound", Some("*")),
            cap("fs", Some("write:*")),
            cap("process", Some("*")),
        ]);
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 3);
    }

    #[test]
    fn red_mixed_capabilities_only_wildcards_flagged() {
        let r = R11CapabilityWildcard::new();
        let m = manifest_with_capabilities(vec![
            cap("network.outbound", Some("read")),
            cap("fs", Some("write:*")),
            cap("process", None),
        ]);
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("write:*"));
    }

    #[test]
    fn red_location_path_matches_manifest_path() {
        let r = R11CapabilityWildcard::new();
        let m = manifest_with_capabilities(vec![cap("network.outbound", Some("*"))]);
        let expected_path = Path::new("/tmp/skill/manifest.json");
        let findings = r.check(&m, expected_path);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].location.path.as_path(), expected_path);
    }

    #[test]
    fn red_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<R11CapabilityWildcard>();
    }
}
