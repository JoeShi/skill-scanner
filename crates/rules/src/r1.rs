//! R1 — sensitive-env-key rule
//! Detects manifest.env keys that suggest hardcoded credentials.

use skill_scanner_core::{Finding, Location, RuleId, RuleOrigin, Severity};
use skill_scanner_manifest::SkillManifest;
use std::path::Path;

use crate::Rule;

pub struct R1SensitiveEnvKey;

impl Default for R1SensitiveEnvKey {
    fn default() -> Self {
        Self
    }
}

impl R1SensitiveEnvKey {
    pub fn new() -> Self {
        Self
    }
}

static SENSITIVE_PATTERNS: &[&str] = &[
    "PASSWORD",
    "SECRET",
    "TOKEN",
    "API_KEY",
    "APIKEY",
    "PRIVATE_KEY",
    "PRIVATE",
    "CREDENTIALS",
    "AUTH",
    "ACCESS_KEY",
    "CLIENT_SECRET",
];

impl Rule for R1SensitiveEnvKey {
    fn id(&self) -> &RuleId {
        static ID: std::sync::LazyLock<RuleId> =
            std::sync::LazyLock::new(|| RuleId("R1-sensitive-env-key".to_string()));
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
            if SENSITIVE_PATTERNS.iter().any(|p| key_upper.contains(p)) {
                findings.push(Finding {
                    rule_id: self.id().clone(),
                    rule_origin: self.origin(),
                    severity: Severity::P1,
                    message: format!(
                        r#"manifest.env key "{}" suggests hardcoded credential"#,
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
    fn red_id_is_r1() {
        let r = R1SensitiveEnvKey::new();
        assert_eq!(r.id().0, "R1-sensitive-env-key");
    }

    #[test]
    fn red_origin_is_builtin() {
        let r = R1SensitiveEnvKey::new();
        assert!(matches!(r.origin(), RuleOrigin::BuiltIn));
    }

    #[test]
    fn red_none_env_no_findings() {
        let r = R1SensitiveEnvKey::new();
        let m = SkillManifest {
            env: None,
            ..Default::default()
        };
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert!(findings.is_empty());
    }

    #[test]
    fn red_safe_keys_no_findings() {
        let r = R1SensitiveEnvKey::new();
        let mut env = HashMap::new();
        env.insert("PORT".to_string(), "3000".to_string());
        env.insert("DEBUG".to_string(), "true".to_string());
        let m = SkillManifest {
            env: Some(env),
            ..Default::default()
        };
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert!(findings.is_empty());
    }

    #[test]
    fn red_password_key_finding() {
        let r = R1SensitiveEnvKey::new();
        let mut env = HashMap::new();
        env.insert("DB_PASSWORD".to_string(), "secret123".to_string());
        let m = SkillManifest {
            env: Some(env),
            ..Default::default()
        };
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::P1);
        assert!(findings[0].message.contains("DB_PASSWORD"));
    }

    #[test]
    fn red_case_insensitive() {
        let r = R1SensitiveEnvKey::new();
        let mut env = HashMap::new();
        env.insert("apikey".to_string(), "xxx".to_string());
        let m = SkillManifest {
            env: Some(env),
            ..Default::default()
        };
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn red_multiple_matching_keys() {
        let r = R1SensitiveEnvKey::new();
        let mut env = HashMap::new();
        env.insert("PASSWORD".to_string(), "x".to_string());
        env.insert("SECRET".to_string(), "y".to_string());
        let m = SkillManifest {
            env: Some(env),
            ..Default::default()
        };
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn red_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<R1SensitiveEnvKey>();
    }
}
