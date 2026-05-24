//! R5 — env-system-var rule
//! Detects manifest.env keys that override critical system environment variables.

use skill_scanner_core::{Finding, Location, RuleId, RuleOrigin, Severity};
use skill_scanner_manifest::SkillManifest;
use std::path::Path;

use crate::Rule;

pub struct R5EnvSystemVar;

impl Default for R5EnvSystemVar {
    fn default() -> Self {
        Self
    }
}

impl R5EnvSystemVar {
    pub fn new() -> Self {
        Self
    }
}

static ENV_BLOCK_LIST: &[&str] = &[
    "PATH",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "DYLD_FRAMEWORK_PATH",
    "NODE_OPTIONS",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS",
    "RUBYOPT",
    "PERL5OPT",
    "ELECTRON_RUN_AS_NODE",
];

impl Rule for R5EnvSystemVar {
    fn id(&self) -> &RuleId {
        static ID: std::sync::LazyLock<RuleId> =
            std::sync::LazyLock::new(|| RuleId("R5-env-system-var".to_string()));
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
            let key_upper = key.to_uppercase();
            if ENV_BLOCK_LIST.iter().any(|p| key_upper == *p) {
                findings.push(Finding {
                    rule_id: self.id().clone(),
                    rule_origin: self.origin(),
                    severity: Severity::P0,
                    message: format!(
                        r#"manifest.env key "{}" overrides a critical system environment variable"#,
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

    #[test]
    fn red_id_is_r5() {
        let r = R5EnvSystemVar::new();
        assert_eq!(r.id().0, "R5-env-system-var");
    }

    #[test]
    fn red_origin_is_builtin() {
        let r = R5EnvSystemVar::new();
        assert!(matches!(r.origin(), RuleOrigin::BuiltIn));
    }

    #[test]
    fn red_none_env_no_findings() {
        let r = R5EnvSystemVar::new();
        let m = SkillManifest {
            env: None,
            ..Default::default()
        };
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert!(findings.is_empty());
    }

    #[test]
    fn red_safe_keys_no_findings() {
        let r = R5EnvSystemVar::new();
        let mut env = HashMap::new();
        env.insert("PORT".to_string(), "3000".to_string());
        env.insert("LOG_LEVEL".to_string(), "info".to_string());
        let m = SkillManifest {
            env: Some(env),
            ..Default::default()
        };
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert!(findings.is_empty());
    }

    #[test]
    fn red_path_key_finding() {
        let r = R5EnvSystemVar::new();
        let mut env = HashMap::new();
        env.insert("PATH".to_string(), "/usr/bin".to_string());
        let m = SkillManifest {
            env: Some(env),
            ..Default::default()
        };
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::P0);
        assert!(findings[0].message.contains("PATH"));
    }

    #[test]
    fn red_path_lowercase_case_insensitive() {
        let r = R5EnvSystemVar::new();
        let mut env = HashMap::new();
        env.insert("path".to_string(), "/usr/bin".to_string());
        let m = SkillManifest {
            env: Some(env),
            ..Default::default()
        };
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::P0);
    }

    #[test]
    fn red_ld_preload_finding() {
        let r = R5EnvSystemVar::new();
        let mut env = HashMap::new();
        env.insert("LD_PRELOAD".to_string(), "/tmp/evil.so".to_string());
        let m = SkillManifest {
            env: Some(env),
            ..Default::default()
        };
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn red_node_options_finding() {
        let r = R5EnvSystemVar::new();
        let mut env = HashMap::new();
        env.insert(
            "NODE_OPTIONS".to_string(),
            "--require /tmp/evil.js".to_string(),
        );
        let m = SkillManifest {
            env: Some(env),
            ..Default::default()
        };
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn red_electron_run_as_node_finding() {
        let r = R5EnvSystemVar::new();
        let mut env = HashMap::new();
        env.insert("ELECTRON_RUN_AS_NODE".to_string(), "1".to_string());
        let m = SkillManifest {
            env: Some(env),
            ..Default::default()
        };
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn red_multiple_blocked_keys() {
        let r = R5EnvSystemVar::new();
        let mut env = HashMap::new();
        env.insert("PATH".to_string(), "/usr/bin".to_string());
        env.insert("LD_PRELOAD".to_string(), "/tmp/evil.so".to_string());
        env.insert("NODE_OPTIONS".to_string(), "--inspect".to_string());
        let m = SkillManifest {
            env: Some(env),
            ..Default::default()
        };
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 3);
    }

    #[test]
    fn red_mixed_env_only_blocked_flagged() {
        let r = R5EnvSystemVar::new();
        let mut env = HashMap::new();
        env.insert("PORT".to_string(), "8080".to_string());
        env.insert("PYTHONPATH".to_string(), "/tmp/injected".to_string());
        env.insert("LOG_LEVEL".to_string(), "debug".to_string());
        let m = SkillManifest {
            env: Some(env),
            ..Default::default()
        };
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("PYTHONPATH"));
    }

    #[test]
    fn red_r1_r5_non_overlap() {
        let r = R5EnvSystemVar::new();
        let mut env = HashMap::new();
        env.insert("DB_PASSWORD".to_string(), "hunter2".to_string());
        let m = SkillManifest {
            env: Some(env),
            ..Default::default()
        };
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert!(findings.is_empty());
    }

    #[test]
    fn red_location_path_matches_manifest_path() {
        let r = R5EnvSystemVar::new();
        let mut env = HashMap::new();
        env.insert("PATH".to_string(), "/usr/bin".to_string());
        let m = SkillManifest {
            env: Some(env),
            ..Default::default()
        };
        let expected_path = Path::new("/tmp/skill/manifest.json");
        let findings = r.check(&m, expected_path);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].location.path.as_path(), expected_path);
    }

    #[test]
    fn red_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<R5EnvSystemVar>();
    }
}
