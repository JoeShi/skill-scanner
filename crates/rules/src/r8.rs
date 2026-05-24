//! R8 — fs-paths-escape rule
//! Detects sandbox-escape patterns in manifest.fs_paths entries.
//!
//! [deviation from TS R-numbering: Rust R8 = manifest.fs_paths escape detection
//!  (manifest-level); TS R8 (AST scan) is a separate future slice]

use skill_scanner_core::{Finding, Location, RuleId, RuleOrigin, Severity};
use skill_scanner_manifest::SkillManifest;
use std::path::Path;

use crate::Rule;

pub struct R8FsPathsEscape;

impl Default for R8FsPathsEscape {
    fn default() -> Self {
        Self
    }
}

impl R8FsPathsEscape {
    pub fn new() -> Self {
        Self
    }
}

/// Checks whether a single path entry is dangerous.
fn is_dangerous_path(entry: &str) -> bool {
    // Empty strings are not dangerous (no sandbox escape)
    if entry.is_empty() {
        return false;
    }

    // 1. Unix absolute path
    if entry.starts_with('/') {
        return true;
    }

    // 2. Home-dir prefix
    if entry.starts_with('~') {
        return true;
    }

    // 3. Path traversal: contains ".." as a path segment
    // We split on both / and \ to catch cross-platform traversal.
    for segment in entry.split(['/', '\\']) {
        if segment == ".." {
            return true;
        }
    }

    // 4. Windows absolute path: drive letter + colon + slash/backslash
    // e.g. "C:\", "C:/", "d:\", "D:/"
    let bytes = entry.as_bytes();
    if bytes.len() >= 3 {
        let first = bytes[0];
        let second = bytes[1];
        let third = bytes[2];
        if second == b':' && first.is_ascii_alphabetic() && (third == b'\\' || third == b'/') {
            return true;
        }
    }

    false
}

impl Rule for R8FsPathsEscape {
    fn id(&self) -> &RuleId {
        static ID: std::sync::LazyLock<RuleId> =
            std::sync::LazyLock::new(|| RuleId("R8-fs-paths-escape".to_string()));
        &ID
    }

    fn origin(&self) -> RuleOrigin {
        RuleOrigin::BuiltIn
    }

    fn check(&self, manifest: &SkillManifest, manifest_path: &Path) -> Vec<Finding> {
        let paths = match &manifest.fs_paths {
            Some(p) => p,
            None => return vec![],
        };

        let mut findings = Vec::new();
        for entry in paths {
            if is_dangerous_path(entry) {
                findings.push(Finding {
                    rule_id: self.id().clone(),
                    rule_origin: self.origin(),
                    severity: Severity::P0,
                    message: format!(
                        r#"fs_paths entry "{}" escapes sandbox (absolute, home-dir, traversal, or drive-letter)"#,
                        entry
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

    fn manifest_with_paths(paths: &[&str]) -> SkillManifest {
        SkillManifest {
            fs_paths: Some(paths.iter().map(|s| s.to_string()).collect()),
            ..base_manifest()
        }
    }

    #[test]
    fn red_id_is_r8() {
        let r = R8FsPathsEscape::new();
        assert_eq!(r.id().0, "R8-fs-paths-escape");
    }

    #[test]
    fn red_origin_is_builtin() {
        let r = R8FsPathsEscape::new();
        assert!(matches!(r.origin(), RuleOrigin::BuiltIn));
    }

    #[test]
    fn red_no_fs_paths_no_findings() {
        let r = R8FsPathsEscape::new();
        let m = base_manifest();
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert!(findings.is_empty());
    }

    #[test]
    fn red_empty_fs_paths_no_findings() {
        let r = R8FsPathsEscape::new();
        let m = manifest_with_paths(&[]);
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert!(findings.is_empty());
    }

    #[test]
    fn red_benign_relative_paths_no_findings() {
        let r = R8FsPathsEscape::new();
        let m = manifest_with_paths(&["./data", "cache/", "assets", "data/output.json"]);
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert!(findings.is_empty());
    }

    #[test]
    fn red_unix_absolute_produces_p0() {
        let r = R8FsPathsEscape::new();
        let m = manifest_with_paths(&["/etc/passwd"]);
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::P0);
    }

    #[test]
    fn red_home_dir_tilde_produces_finding() {
        let r = R8FsPathsEscape::new();
        let m = manifest_with_paths(&["~/.ssh/id_rsa"]);
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn red_parent_traversal_produces_finding() {
        let r = R8FsPathsEscape::new();
        let m = manifest_with_paths(&["../../secret"]);
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn red_embedded_traversal_produces_finding() {
        let r = R8FsPathsEscape::new();
        let m = manifest_with_paths(&["data/../../../etc"]);
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn red_windows_backslash_absolute_produces_finding() {
        let r = R8FsPathsEscape::new();
        let m = manifest_with_paths(&["C:\\Windows\\System32"]);
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn red_windows_forward_slash_absolute_produces_finding() {
        let r = R8FsPathsEscape::new();
        let m = manifest_with_paths(&["C:/Users/secret"]);
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn red_multiple_dangerous_multiple_findings() {
        let r = R8FsPathsEscape::new();
        let m = manifest_with_paths(&["/etc/passwd", "~/.ssh", "../../secret"]);
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 3);
    }

    #[test]
    fn red_mixed_paths_only_dangerous_flagged() {
        let r = R8FsPathsEscape::new();
        let m = manifest_with_paths(&["./data", "/etc/hosts", "cache/"]);
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn red_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<R8FsPathsEscape>();
    }
}
