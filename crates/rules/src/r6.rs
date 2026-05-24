//! R6 — env-value-secrets rule
//! Scans manifest.env values for hardcoded secrets using regex patterns.
//! One P0 finding per matching value.
//!
//! [deviation from TS R-numbering: Rust R6 = manifest.env value secrets scan (manifest-level);
//!  TS R6 (full source AST secret scan) is a separate future slice]

use regex::Regex;
use skill_scanner_core::{Finding, Location, RuleId, RuleOrigin, Severity};
use skill_scanner_manifest::SkillManifest;
use std::path::Path;

use crate::Rule;

pub struct R6EnvValueSecrets;

impl Default for R6EnvValueSecrets {
    fn default() -> Self {
        Self
    }
}

impl R6EnvValueSecrets {
    pub fn new() -> Self {
        Self
    }
}

/// Compiled secret-detection regexes, initialised once on first use.
static SECRET_PATTERNS: std::sync::LazyLock<Vec<(&'static str, Regex)>> =
    std::sync::LazyLock::new(|| {
        vec![
            ("aws-access-key", Regex::new(r"AKIA[0-9A-Z]{16}").unwrap()),
            (
                "github-token",
                Regex::new(r"gh[pousr]_[A-Za-z0-9_]{36,}").unwrap(),
            ),
            (
                "private-key-block",
                Regex::new(r"-----BEGIN (?:RSA |OPENSSH |PGP |EC )?PRIVATE KEY-----").unwrap(),
            ),
            (
                "slack-token",
                Regex::new(r"xox[baprs]-[0-9a-zA-Z\-]+").unwrap(),
            ),
        ]
    });

impl Rule for R6EnvValueSecrets {
    fn id(&self) -> &RuleId {
        static ID: std::sync::LazyLock<RuleId> =
            std::sync::LazyLock::new(|| RuleId("R6-env-value-secrets".to_string()));
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

        for (key, value) in env {
            for (pattern_name, regex) in &*SECRET_PATTERNS {
                if regex.is_match(value) {
                    findings.push(Finding {
                        rule_id: self.id().clone(),
                        rule_origin: self.origin(),
                        severity: Severity::P0,
                        message: format!(
                            r#"manifest.env value for "{}" matches {} secret pattern"#,
                            key, pattern_name
                        ),
                        location: Location {
                            path: manifest_path.to_path_buf(),
                            line: None,
                            column: None,
                        },
                    });
                    // One finding per value, not per pattern match
                    break;
                }
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
    fn red_id_is_r6() {
        let r = R6EnvValueSecrets::new();
        assert_eq!(r.id().0, "R6-env-value-secrets");
    }

    #[test]
    fn red_origin_is_builtin() {
        let r = R6EnvValueSecrets::new();
        assert!(matches!(r.origin(), RuleOrigin::BuiltIn));
    }

    #[test]
    fn red_no_env_no_findings() {
        let r = R6EnvValueSecrets::new();
        let m = base_manifest();
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert!(findings.is_empty());
    }

    #[test]
    fn red_non_secret_values_no_findings() {
        let r = R6EnvValueSecrets::new();
        let m = env_manifest(&[
            ("API_URL", "https://api.example.com"),
            ("PORT", "3000"),
            ("DB_HOST", "localhost"),
        ]);
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert!(findings.is_empty());
    }

    #[test]
    fn red_aws_access_key_produces_p0() {
        let r = R6EnvValueSecrets::new();
        let m = env_manifest(&[("AWS_KEY", "AKIAIOSFODNN7EXAMPLE")]);
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::P0);
    }

    #[test]
    fn red_github_token_produces_finding() {
        let r = R6EnvValueSecrets::new();
        let m = env_manifest(&[("GH_TOKEN", "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890")]);
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn red_private_key_block_produces_finding() {
        let r = R6EnvValueSecrets::new();
        let m = env_manifest(&[(
            "PRIVATE_KEY",
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEo...\n-----END RSA PRIVATE KEY-----",
        )]);
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn red_slack_token_produces_finding() {
        let r = R6EnvValueSecrets::new();
        let m = env_manifest(&[(
            "SLACK_TOKEN",
            "xoxb-FAKE-000000000-TESTONLY-not-a-real-token",
        )]);
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn red_openssh_private_key_produces_finding() {
        let r = R6EnvValueSecrets::new();
        let m = env_manifest(&[(
            "SSH_KEY",
            "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNza...",
        )]);
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn red_multiple_secret_values_multiple_findings() {
        let r = R6EnvValueSecrets::new();
        let m = env_manifest(&[
            ("AWS_KEY", "AKIAIOSFODNN7EXAMPLE"),
            ("GH_TOKEN", "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"),
        ]);
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn red_mixed_env_only_secrets_flagged() {
        let r = R6EnvValueSecrets::new();
        let m = env_manifest(&[
            ("PORT", "3000"),
            ("AWS_KEY", "AKIAIOSFODNN7EXAMPLE"),
            ("LOG_LEVEL", "debug"),
        ]);
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn red_r1_r6_non_overlap() {
        let r = R6EnvValueSecrets::new();
        let m = env_manifest(&[("DB_PASSWORD", "hunter2")]);
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert!(findings.is_empty());
    }

    #[test]
    fn red_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<R6EnvValueSecrets>();
    }
}
