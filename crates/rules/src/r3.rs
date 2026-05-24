//! R3 — installer.script rule
//! Detects installer.script paths that are absolute or contain parent-directory traversal.

use skill_scanner_core::{Finding, Location, RuleId, RuleOrigin, Severity};
use skill_scanner_manifest::SkillManifest;
use std::path::Path;

use crate::Rule;

pub struct R3InstallerScript;

impl Default for R3InstallerScript {
    fn default() -> Self {
        Self
    }
}

impl R3InstallerScript {
    pub fn new() -> Self {
        Self
    }
}

impl Rule for R3InstallerScript {
    fn id(&self) -> &RuleId {
        static ID: std::sync::LazyLock<RuleId> =
            std::sync::LazyLock::new(|| RuleId("R3-installer-script".to_string()));
        &ID
    }

    fn origin(&self) -> RuleOrigin {
        RuleOrigin::BuiltIn
    }

    fn check(&self, manifest: &SkillManifest, manifest_path: &Path) -> Vec<Finding> {
        let installer = match &manifest.installer {
            Some(i) => i,
            None => return vec![],
        };

        let script = match &installer.script {
            Some(s) => s,
            None => return vec![],
        };

        let path = Path::new(script);
        let is_dangerous = path.is_absolute() || path.components().any(|c| c.as_os_str() == "..");

        if is_dangerous {
            vec![Finding {
                rule_id: self.id().clone(),
                rule_origin: self.origin(),
                severity: Severity::P0,
                message: format!(
                    r#"installer.script "{}" uses absolute or traversal path"#,
                    script
                ),
                location: Location {
                    path: manifest_path.to_path_buf(),
                    line: None,
                    column: None,
                },
            }]
        } else {
            vec![]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use skill_scanner_manifest::{InstallerConfig, SkillManifest};
    use std::path::Path;

    fn base_manifest() -> SkillManifest {
        SkillManifest {
            name: "test".to_string(),
            version: "1.0.0".to_string(),
            description: Some("x".to_string()),
            main: Some("index.js".to_string()),
            author: Some("a".to_string()),
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

    #[test]
    fn red_id_is_r3() {
        let r = R3InstallerScript::new();
        assert_eq!(r.id().0, "R3-installer-script");
    }

    #[test]
    fn red_origin_is_builtin() {
        let r = R3InstallerScript::new();
        assert!(matches!(r.origin(), RuleOrigin::BuiltIn));
    }

    #[test]
    fn red_none_installer_no_findings() {
        let r = R3InstallerScript::new();
        let m = base_manifest();
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert!(findings.is_empty());
    }

    #[test]
    fn red_none_script_no_findings() {
        let r = R3InstallerScript::new();
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
    fn red_safe_relative_paths() {
        let r = R3InstallerScript::new();
        for script in ["./setup.sh", "setup.sh", "scripts/setup.sh"] {
            let m = SkillManifest {
                installer: Some(InstallerConfig {
                    r#type: None,
                    command: None,
                    script: Some(script.to_string()),
                }),
                ..base_manifest()
            };
            let findings = r.check(&m, Path::new("/tmp/test"));
            assert!(findings.is_empty(), "{} should be safe", script);
        }
    }

    #[test]
    fn red_absolute_path_finding() {
        let r = R3InstallerScript::new();
        let m = SkillManifest {
            installer: Some(InstallerConfig {
                r#type: None,
                command: None,
                script: Some("/tmp/evil.sh".to_string()),
            }),
            ..base_manifest()
        };
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::P0);
    }

    #[test]
    fn red_traversal_path_finding() {
        let r = R3InstallerScript::new();
        let m = SkillManifest {
            installer: Some(InstallerConfig {
                r#type: None,
                command: None,
                script: Some("../sibling/setup.sh".to_string()),
            }),
            ..base_manifest()
        };
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn red_deep_traversal_finding() {
        let r = R3InstallerScript::new();
        let m = SkillManifest {
            installer: Some(InstallerConfig {
                r#type: None,
                command: None,
                script: Some("../../etc/passwd".to_string()),
            }),
            ..base_manifest()
        };
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn red_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<R3InstallerScript>();
    }
}
