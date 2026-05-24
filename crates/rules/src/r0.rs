use skill_scanner_core::{Finding, Location, RuleId, RuleOrigin, Severity};
use skill_scanner_manifest::SkillManifest;
use std::path::Path;

fn make_finding(rule_id: RuleId, message: String, path: &Path) -> Finding {
    Finding {
        rule_id,
        rule_origin: RuleOrigin::BuiltIn,
        severity: Severity::P0,
        message,
        location: Location {
            path: path.to_path_buf(),
            line: None,
            column: None,
        },
    }
}

/// R0-manifest-structure: validates that required manifest fields are present.
pub struct R0ManifestStructure;

impl Default for R0ManifestStructure {
    fn default() -> Self {
        Self
    }
}

impl R0ManifestStructure {
    pub fn new() -> Self {
        Self
    }
}

impl super::Rule for R0ManifestStructure {
    fn id(&self) -> &RuleId {
        static ID: std::sync::LazyLock<RuleId> =
            std::sync::LazyLock::new(|| RuleId("R0-manifest-structure".to_string()));
        &ID
    }

    fn origin(&self) -> RuleOrigin {
        RuleOrigin::BuiltIn
    }

    fn check(&self, manifest: &SkillManifest, manifest_path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let id = self.id().clone();

        if manifest.description.is_none() {
            findings.push(make_finding(
                id.clone(),
                "manifest.description is required".to_string(),
                manifest_path,
            ));
        }
        if manifest.main.is_none() {
            findings.push(make_finding(
                id.clone(),
                "manifest.main is required".to_string(),
                manifest_path,
            ));
        }
        if manifest.author.is_none() {
            findings.push(make_finding(
                id.clone(),
                "manifest.author is required".to_string(),
                manifest_path,
            ));
        }
        if manifest.license.is_none() {
            findings.push(make_finding(
                id.clone(),
                "manifest.license is required".to_string(),
                manifest_path,
            ));
        }

        findings
    }
}

/// R0-missing-capabilities: validates that capabilities are present and non-empty.
pub struct R0MissingCapabilities;

impl Default for R0MissingCapabilities {
    fn default() -> Self {
        Self
    }
}

impl R0MissingCapabilities {
    pub fn new() -> Self {
        Self
    }
}

impl super::Rule for R0MissingCapabilities {
    fn id(&self) -> &RuleId {
        static ID: std::sync::LazyLock<RuleId> =
            std::sync::LazyLock::new(|| RuleId("R0-missing-capabilities".to_string()));
        &ID
    }

    fn origin(&self) -> RuleOrigin {
        RuleOrigin::BuiltIn
    }

    fn check(&self, manifest: &SkillManifest, manifest_path: &Path) -> Vec<Finding> {
        let missing = match &manifest.capabilities {
            None => true,
            Some(v) => v.is_empty(),
        };
        if missing {
            vec![make_finding(
                self.id().clone(),
                "manifest.capabilities is required and must not be empty".to_string(),
                manifest_path,
            )]
        } else {
            vec![]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Rule;
    use skill_scanner_manifest::{CapabilityDeclaration, SkillManifest};
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

    #[test]
    fn r0_structure_valid_manifest_empty() {
        let rule = R0ManifestStructure::new();
        let findings = rule.check(&valid_manifest(), Path::new("m.json"));
        assert!(findings.is_empty());
    }

    #[test]
    fn r0_structure_all_required_missing() {
        let rule = R0ManifestStructure::new();
        let manifest = SkillManifest {
            description: None,
            main: None,
            author: None,
            license: None,
            ..valid_manifest()
        };
        let findings = rule.check(&manifest, Path::new("m.json"));
        assert_eq!(findings.len(), 4);
    }

    #[test]
    fn r0_capabilities_none_finding() {
        let rule = R0MissingCapabilities::new();
        let manifest = SkillManifest {
            capabilities: None,
            ..valid_manifest()
        };
        let findings = rule.check(&manifest, Path::new("m.json"));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::P0);
    }

    #[test]
    fn r0_capabilities_empty_finding() {
        let rule = R0MissingCapabilities::new();
        let manifest = SkillManifest {
            capabilities: Some(vec![]),
            ..valid_manifest()
        };
        let findings = rule.check(&manifest, Path::new("m.json"));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn r0_capabilities_present_no_finding() {
        let rule = R0MissingCapabilities::new();
        let findings = rule.check(&valid_manifest(), Path::new("m.json"));
        assert!(findings.is_empty());
    }

    #[test]
    fn r0_rules_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<R0ManifestStructure>();
        assert_send_sync::<R0MissingCapabilities>();
    }
}
