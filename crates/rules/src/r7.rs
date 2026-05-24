//! R7 — installer-inline-exec rule
//! Detects inline code execution via interpreter flags in installer.command.

use skill_scanner_core::{Finding, Location, RuleId, RuleOrigin, Severity};
use skill_scanner_manifest::SkillManifest;
use std::path::Path;

use crate::Rule;

pub struct R7InstallerInlineExec;

impl Default for R7InstallerInlineExec {
    fn default() -> Self {
        Self
    }
}

impl R7InstallerInlineExec {
    pub fn new() -> Self {
        Self
    }
}

/// Interpreter inline execution flags that allow arbitrary code to be
/// passed directly on the command line.
static INLINE_EXEC_PATTERNS: &[&str] = &[
    "bash -c",
    "sh -c",
    "python -c",
    "python3 -c",
    "node -e",
    "node --eval",
    "ruby -e",
    "perl -e",
];

impl Rule for R7InstallerInlineExec {
    fn id(&self) -> &RuleId {
        static ID: std::sync::LazyLock<RuleId> =
            std::sync::LazyLock::new(|| RuleId("R7-installer-inline-exec".to_string()));
        &ID
    }

    fn origin(&self) -> RuleOrigin {
        RuleOrigin::BuiltIn
    }

    fn check(&self, manifest: &SkillManifest, manifest_path: &Path) -> Vec<Finding> {
        let command = match &manifest.installer {
            Some(inst) => match &inst.command {
                Some(cmd) => cmd,
                None => return vec![],
            },
            None => return vec![],
        };

        let command_lower = command.to_lowercase();
        if INLINE_EXEC_PATTERNS
            .iter()
            .any(|p| command_lower.contains(p))
        {
            vec![Finding {
                rule_id: self.id().clone(),
                rule_origin: self.origin(),
                severity: Severity::P0,
                message: format!(
                    r#"installer.command "{}" contains inline code execution flag"#,
                    command
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

    fn manifest_with_command(command: &str) -> SkillManifest {
        SkillManifest {
            installer: Some(InstallerConfig {
                r#type: None,
                command: Some(command.to_string()),
                script: None,
            }),
            ..base_manifest()
        }
    }

    #[test]
    fn red_id_is_r7() {
        let r = R7InstallerInlineExec::new();
        assert_eq!(r.id().0, "R7-installer-inline-exec");
    }

    #[test]
    fn red_origin_is_builtin() {
        let r = R7InstallerInlineExec::new();
        assert!(matches!(r.origin(), RuleOrigin::BuiltIn));
    }

    #[test]
    fn red_no_installer_no_findings() {
        let r = R7InstallerInlineExec::new();
        let m = base_manifest();
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert!(findings.is_empty());
    }

    #[test]
    fn red_installer_no_command_no_findings() {
        let r = R7InstallerInlineExec::new();
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
    fn red_benign_command_no_findings() {
        let r = R7InstallerInlineExec::new();
        let m = manifest_with_command("node ./setup.js --install");
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert!(findings.is_empty());
    }

    #[test]
    fn red_bash_c_produces_p0() {
        let r = R7InstallerInlineExec::new();
        let m = manifest_with_command("bash -c \"echo hello\"");
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::P0);
    }

    #[test]
    fn red_sh_c_produces_finding() {
        let r = R7InstallerInlineExec::new();
        let m = manifest_with_command("sh -c 'npm install'");
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn red_python_c_produces_finding() {
        let r = R7InstallerInlineExec::new();
        let m = manifest_with_command("python -c \"import os; os.system('id')\"");
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn red_python3_c_produces_finding() {
        let r = R7InstallerInlineExec::new();
        let m = manifest_with_command("python3 -c \"print('setup')\"");
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn red_node_e_produces_finding() {
        let r = R7InstallerInlineExec::new();
        let m = manifest_with_command("node -e \"require('fs').writeFileSync('x', 'y')\"");
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn red_node_eval_produces_finding() {
        let r = R7InstallerInlineExec::new();
        let m = manifest_with_command("node --eval \"console.log('setup')\"");
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn red_ruby_e_produces_finding() {
        let r = R7InstallerInlineExec::new();
        let m = manifest_with_command("ruby -e \"puts 'hello'\"");
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn red_perl_e_produces_finding() {
        let r = R7InstallerInlineExec::new();
        let m = manifest_with_command("perl -e \"print 'hello'\"");
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn red_case_insensitive_match() {
        let r = R7InstallerInlineExec::new();
        let m = manifest_with_command("BASH -C \"echo test\"");
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn red_location_path_matches_manifest_path() {
        let r = R7InstallerInlineExec::new();
        let m = manifest_with_command("bash -c \"echo hello\"");
        let expected_path = Path::new("/tmp/skill/manifest.json");
        let findings = r.check(&m, expected_path);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].location.path.as_path(), expected_path);
    }

    #[test]
    fn red_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<R7InstallerInlineExec>();
    }
}
