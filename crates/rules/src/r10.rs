//! R10 — dependency-protocol rule
//! Detects unsafe protocol prefixes in manifest.dependencies and
//! manifest.dev_dependencies values.
//!
//! [deviation from TS R-numbering: Rust R10 = manifest dependency protocol
//!  validation (manifest-level); TS R10 (AST scan) is a separate future slice]

use skill_scanner_core::{Finding, Location, RuleId, RuleOrigin, Severity};
use skill_scanner_manifest::SkillManifest;
use std::collections::HashMap;
use std::path::Path;

use crate::Rule;

pub struct R10DependencyProtocol;

impl Default for R10DependencyProtocol {
    fn default() -> Self {
        Self
    }
}

impl R10DependencyProtocol {
    pub fn new() -> Self {
        Self
    }
}

/// Checks whether a dependency value uses an unsafe protocol.
fn is_unsafe_protocol(value: &str) -> bool {
    value.starts_with("file:")
        || value.starts_with("git:")
        || value.starts_with("git+http:")
        || value.starts_with("http:")
}

/// Scans a single dependency map and returns findings.
fn scan_deps(
    rule_id: &RuleId,
    rule_origin: &RuleOrigin,
    deps: &HashMap<String, String>,
    manifest_path: &Path,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (key, value) in deps {
        if is_unsafe_protocol(value) {
            findings.push(Finding {
                rule_id: rule_id.clone(),
                rule_origin: rule_origin.clone(),
                severity: Severity::P0,
                message: format!(
                    r#"dependency "{}" uses unsafe protocol prefix: "{}""#,
                    key, value
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

impl Rule for R10DependencyProtocol {
    fn id(&self) -> &RuleId {
        static ID: std::sync::LazyLock<RuleId> =
            std::sync::LazyLock::new(|| RuleId("R10-dependency-protocol".to_string()));
        &ID
    }

    fn origin(&self) -> RuleOrigin {
        RuleOrigin::BuiltIn
    }

    fn check(&self, manifest: &SkillManifest, manifest_path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(ref deps) = manifest.dependencies {
            findings.extend(scan_deps(self.id(), &self.origin(), deps, manifest_path));
        }

        if let Some(ref dev_deps) = manifest.dev_dependencies {
            findings.extend(scan_deps(
                self.id(),
                &self.origin(),
                dev_deps,
                manifest_path,
            ));
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

    fn manifest_with_deps(pairs: &[(&str, &str)]) -> SkillManifest {
        let mut deps = HashMap::new();
        for (k, v) in pairs {
            deps.insert(k.to_string(), v.to_string());
        }
        SkillManifest {
            dependencies: Some(deps),
            ..base_manifest()
        }
    }

    fn manifest_with_dev_deps(pairs: &[(&str, &str)]) -> SkillManifest {
        let mut dev_deps = HashMap::new();
        for (k, v) in pairs {
            dev_deps.insert(k.to_string(), v.to_string());
        }
        SkillManifest {
            dev_dependencies: Some(dev_deps),
            ..base_manifest()
        }
    }

    #[test]
    fn red_id_is_r10() {
        let r = R10DependencyProtocol::new();
        assert_eq!(r.id().0, "R10-dependency-protocol");
    }

    #[test]
    fn red_origin_is_builtin() {
        let r = R10DependencyProtocol::new();
        assert!(matches!(r.origin(), RuleOrigin::BuiltIn));
    }

    #[test]
    fn red_no_deps_no_findings() {
        let r = R10DependencyProtocol::new();
        let m = base_manifest();
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert!(findings.is_empty());
    }

    #[test]
    fn red_semver_safe() {
        let r = R10DependencyProtocol::new();
        let m = manifest_with_deps(&[("lodash", "^4.17.21")]);
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert!(findings.is_empty());
    }

    #[test]
    fn red_https_safe() {
        let r = R10DependencyProtocol::new();
        let m = manifest_with_deps(&[("pkg", "https://example.com/pkg.tgz")]);
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert!(findings.is_empty());
    }

    #[test]
    fn red_git_https_safe() {
        let r = R10DependencyProtocol::new();
        let m = manifest_with_deps(&[("lib", "git+https://github.com/org/repo.git")]);
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert!(findings.is_empty());
    }

    #[test]
    fn red_file_prefix_produces_p0() {
        let r = R10DependencyProtocol::new();
        let m = manifest_with_deps(&[("local", "file:///opt/malicious")]);
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::P0);
    }

    #[test]
    fn red_git_bare_prefix_produces_finding() {
        let r = R10DependencyProtocol::new();
        let m = manifest_with_deps(&[("lib", "git://github.com/org/repo.git")]);
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn red_git_http_prefix_produces_finding() {
        let r = R10DependencyProtocol::new();
        let m = manifest_with_deps(&[("lib", "git+http://github.com/org/repo.git")]);
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn red_http_prefix_produces_finding() {
        let r = R10DependencyProtocol::new();
        let m = manifest_with_deps(&[("pkg", "http://insecure.example.com/pkg.tgz")]);
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn red_multiple_unsafe_multiple_findings() {
        let r = R10DependencyProtocol::new();
        let m = manifest_with_deps(&[("a", "file:///opt/x"), ("b", "http://evil.com")]);
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn red_mixed_deps_only_unsafe_flagged() {
        let r = R10DependencyProtocol::new();
        let m = manifest_with_deps(&[("safe", "^1.0.0"), ("unsafe", "file:///opt/x")]);
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn red_dev_dependencies_checked() {
        let r = R10DependencyProtocol::new();
        let m = manifest_with_dev_deps(&[("dev-lib", "git://github.com/org/repo.git")]);
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn red_cross_dict_both_checked() {
        let r = R10DependencyProtocol::new();
        let m = SkillManifest {
            dependencies: Some({
                let mut d = HashMap::new();
                d.insert("prod".to_string(), "file:///opt/x".to_string());
                d
            }),
            dev_dependencies: Some({
                let mut d = HashMap::new();
                d.insert("dev".to_string(), "http://evil.com".to_string());
                d
            }),
            ..base_manifest()
        };
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn red_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<R10DependencyProtocol>();
    }
}
