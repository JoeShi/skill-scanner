//! R4 — installer-type-blocked rule
//! Only "orchestrator-managed" is permitted for installer.type.
//! Any other value (including wrong case or empty string) is blocked
//! with a P0 finding.
//!
//! [deviation from TS R-numbering: Rust R4 maps to TS R12 installer.type whitelist;
//!  TS R4 (AST-scan rule) is a separate future slice]

use skill_scanner_core::{Finding, Location, RuleId, RuleOrigin, Severity};
use skill_scanner_manifest::SkillManifest;
use std::path::Path;

use crate::Rule;

pub struct R4InstallerTypeBlocked;

impl Default for R4InstallerTypeBlocked {
    fn default() -> Self {
        Self
    }
}

impl R4InstallerTypeBlocked {
    pub fn new() -> Self {
        Self
    }
}

/// The only permitted value for `installer.type`.
const ALLOWED_INSTALLER_TYPE: &str = "orchestrator-managed";

impl Rule for R4InstallerTypeBlocked {
    fn id(&self) -> &RuleId {
        static ID: std::sync::LazyLock<RuleId> =
            std::sync::LazyLock::new(|| RuleId("R4-installer-type-blocked".to_string()));
        &ID
    }

    fn origin(&self) -> RuleOrigin {
        RuleOrigin::BuiltIn
    }

    fn check(&self, manifest: &SkillManifest, manifest_path: &Path) -> Vec<Finding> {
        let installer_type = match &manifest.installer {
            Some(inst) => match &inst.r#type {
                Some(t) => t,
                None => return vec![],
            },
            None => return vec![],
        };

        if installer_type == ALLOWED_INSTALLER_TYPE {
            return vec![];
        }

        vec![Finding {
            rule_id: self.id().clone(),
            rule_origin: self.origin(),
            severity: Severity::P0,
            message: format!(
                r#"installer.type "{}" is not allowed (only "orchestrator-managed" permitted)"#,
                installer_type
            ),
            location: Location {
                path: manifest_path.to_path_buf(),
                line: None,
                column: None,
            },
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use skill_scanner_manifest::{InstallerConfig, SkillManifest};
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

    fn manifest_with_installer_type(installer_type: &str) -> SkillManifest {
        SkillManifest {
            installer: Some(InstallerConfig {
                r#type: Some(installer_type.to_string()),
                command: None,
                script: None,
            }),
            ..base_manifest()
        }
    }

    #[test]
    fn red_id_is_r4() {
        let r = R4InstallerTypeBlocked::new();
        assert_eq!(r.id().0, "R4-installer-type-blocked");
    }

    #[test]
    fn red_origin_is_builtin() {
        let r = R4InstallerTypeBlocked::new();
        assert!(matches!(r.origin(), RuleOrigin::BuiltIn));
    }

    #[test]
    fn red_no_installer_no_findings() {
        let r = R4InstallerTypeBlocked::new();
        let m = base_manifest();
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert!(findings.is_empty());
    }

    #[test]
    fn red_installer_no_type_no_findings() {
        let r = R4InstallerTypeBlocked::new();
        let m = SkillManifest {
            installer: Some(InstallerConfig {
                r#type: None,
                command: None,
                script: None,
            }),
            ..base_manifest()
        };
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert!(findings.is_empty());
    }

    #[test]
    fn red_orchestrator_managed_no_findings() {
        let r = R4InstallerTypeBlocked::new();
        let m = manifest_with_installer_type("orchestrator-managed");
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert!(findings.is_empty());
    }

    #[test]
    fn red_npm_type_produces_p0() {
        let r = R4InstallerTypeBlocked::new();
        let m = manifest_with_installer_type("npm");
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::P0);
    }

    #[test]
    fn red_pip_type_produces_finding() {
        let r = R4InstallerTypeBlocked::new();
        let m = manifest_with_installer_type("pip");
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn red_custom_script_type_produces_finding() {
        let r = R4InstallerTypeBlocked::new();
        let m = manifest_with_installer_type("custom-script");
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn red_empty_string_type_produces_finding() {
        let r = R4InstallerTypeBlocked::new();
        let m = manifest_with_installer_type("");
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn red_wrong_case_produces_finding() {
        let r = R4InstallerTypeBlocked::new();
        let m = manifest_with_installer_type("ORCHESTRATOR-MANAGED");
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn red_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<R4InstallerTypeBlocked>();
    }
}
