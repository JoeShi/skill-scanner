//! R13 — env-key-shell-inject rule
//! Detects shell metacharacters in manifest.env key names.

use skill_scanner_core::{Finding, Location, RuleId, RuleOrigin, Severity};
use skill_scanner_manifest::SkillManifest;
use std::path::Path;

use crate::Rule;

pub struct R13EnvKeyShellInject;

impl Default for R13EnvKeyShellInject {
    fn default() -> Self {
        Self
    }
}

impl R13EnvKeyShellInject {
    pub fn new() -> Self {
        Self
    }
}

/// Shell metacharacters that, if present in an env key name, could be
/// exploited for command injection when the key is interpolated.
const SHELL_METACHARS: &[char] = &[';', '|', '&', '$', '`', '!', '(', ')', '{', '}', '<', '>'];

impl Rule for R13EnvKeyShellInject {
    fn id(&self) -> &RuleId {
        static ID: std::sync::LazyLock<RuleId> =
            std::sync::LazyLock::new(|| RuleId("R13-env-key-shell-inject".to_string()));
        &ID
    }

    fn origin(&self) -> RuleOrigin {
        RuleOrigin::BuiltIn
    }

    fn check(&self, manifest: &SkillManifest, manifest_path: &Path) -> Vec<Finding> {
        let env = match &manifest.env {
            Some(e) => e,
            None => return vec![],
        };

        let mut findings = Vec::new();
        for key in env.keys() {
            if key.chars().any(|c| SHELL_METACHARS.contains(&c)) {
                findings.push(Finding {
                    rule_id: self.id().clone(),
                    rule_origin: self.origin(),
                    severity: Severity::P0,
                    message: format!(
                        r#"manifest.env key "{}" contains shell metacharacters"#,
                        key
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

    fn env_manifest(pairs: &[(&str, &str)]) -> SkillManifest {
        let mut env = HashMap::new();
        for (k, v) in pairs {
            env.insert(k.to_string(), v.to_string());
        }
        SkillManifest {
            env: Some(env),
            ..base_manifest()
        }
    }

    #[test]
    fn red_id_is_r13() {
        let r = R13EnvKeyShellInject::new();
        assert_eq!(r.id().0, "R13-env-key-shell-inject");
    }

    #[test]
    fn red_origin_is_builtin() {
        let r = R13EnvKeyShellInject::new();
        assert!(matches!(r.origin(), RuleOrigin::BuiltIn));
    }

    #[test]
    fn red_none_env_no_findings() {
        let r = R13EnvKeyShellInject::new();
        let m = base_manifest();
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert!(findings.is_empty());
    }

    #[test]
    fn red_empty_env_no_findings() {
        let r = R13EnvKeyShellInject::new();
        let m = SkillManifest {
            env: Some(HashMap::new()),
            ..base_manifest()
        };
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert!(findings.is_empty());
    }

    #[test]
    fn red_safe_keys_no_findings() {
        let r = R13EnvKeyShellInject::new();
        let m = env_manifest(&[
            ("NORMAL_KEY", "value"),
            ("PORT", "3000"),
            ("API_URL", "https://api.example.com"),
            ("NODE_ENV", "production"),
        ]);
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert!(findings.is_empty());
    }

    #[test]
    fn red_semicolon_in_key_produces_p0() {
        let r = R13EnvKeyShellInject::new();
        let m = env_manifest(&[("FOO;rm -rf /", "value")]);
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::P0);
    }

    #[test]
    fn red_pipe_in_key_produces_finding() {
        let r = R13EnvKeyShellInject::new();
        let m = env_manifest(&[("FOO|bar", "value")]);
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn red_ampersand_in_key_produces_finding() {
        let r = R13EnvKeyShellInject::new();
        let m = env_manifest(&[("FOO&bar", "value")]);
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn red_dollar_in_key_produces_finding() {
        let r = R13EnvKeyShellInject::new();
        let m = env_manifest(&[("FOO$BAR", "value")]);
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn red_backtick_in_key_produces_finding() {
        let r = R13EnvKeyShellInject::new();
        let m = env_manifest(&[("FOO`cmd`", "value")]);
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn red_redirection_char_produces_finding() {
        let r = R13EnvKeyShellInject::new();
        let m = env_manifest(&[("FOO<bar", "value")]);
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn red_multiple_dangerous_keys_multiple_findings() {
        let r = R13EnvKeyShellInject::new();
        let m = env_manifest(&[
            ("FOO;bar", "value1"),
            ("BAZ|qux", "value2"),
            ("SAFE_KEY", "value3"),
        ]);
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn red_mixed_keys_only_dangerous_flagged() {
        let r = R13EnvKeyShellInject::new();
        let m = env_manifest(&[
            ("PORT", "3000"),
            ("INJECT$HERE", "value"),
            ("LOG_LEVEL", "debug"),
        ]);
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("INJECT$HERE"));
    }

    #[test]
    fn red_r1_r13_non_overlap() {
        let r = R13EnvKeyShellInject::new();
        let m = env_manifest(&[("DB_PASSWORD", "hunter2")]);
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert!(findings.is_empty());
    }

    #[test]
    fn red_location_path_matches_manifest_path() {
        let r = R13EnvKeyShellInject::new();
        let m = env_manifest(&[("FOO;inject", "value")]);
        let expected_path = Path::new("/tmp/skill/manifest.json");
        let findings = r.check(&m, expected_path);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].location.path.as_path(), expected_path);
    }

    #[test]
    fn red_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<R13EnvKeyShellInject>();
    }
}
