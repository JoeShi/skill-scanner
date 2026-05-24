//! R12 — main-field-escape rule
//! Detects sandbox-escape and remote-execution patterns in
//! manifest.main (the skill entry-point script path).
//!
//! [deviation from TS R-numbering: Rust R12 = manifest.main path/URL escape
//!  detection (manifest-level); TS R12 (installer.type whitelist) is
//!  functionally equivalent to Rust R4 already shipped.]

use skill_scanner_core::{Finding, Location, RuleId, RuleOrigin, Severity};
use skill_scanner_manifest::SkillManifest;
use std::path::Path;

use crate::Rule;

pub struct R12MainFieldEscape;

impl Default for R12MainFieldEscape {
    fn default() -> Self {
        Self
    }
}

impl R12MainFieldEscape {
    pub fn new() -> Self {
        Self
    }
}

/// Checks whether a main-field value is dangerous.
fn is_dangerous_main(entry: &str) -> bool {
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

    // 3. Path traversal: contains ".." as a segment
    for segment in entry.split(['/', '\\']) {
        if segment == ".." {
            return true;
        }
    }

    // 4. Remote URL schemes (fetch-and-execute = RCE primitive)
    if entry.starts_with("http:")
        || entry.starts_with("https:")
        || entry.starts_with("ftp:")
        || entry.starts_with("git:")
    {
        return true;
    }

    // 5. Windows absolute path: drive letter + colon + slash/backslash
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

impl Rule for R12MainFieldEscape {
    fn id(&self) -> &RuleId {
        static ID: std::sync::LazyLock<RuleId> =
            std::sync::LazyLock::new(|| RuleId("R12-main-field-escape".to_string()));
        &ID
    }

    fn origin(&self) -> RuleOrigin {
        RuleOrigin::BuiltIn
    }

    fn check(&self, manifest: &SkillManifest, manifest_path: &Path) -> Vec<Finding> {
        let main = match &manifest.main {
            Some(m) => m,
            None => return vec![],
        };

        if is_dangerous_main(main) {
            vec![Finding {
                rule_id: self.id().clone(),
                rule_origin: self.origin(),
                severity: Severity::P0,
                message: format!(
                    r#"main field "{}" escapes sandbox or references remote code"#,
                    main
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

    fn manifest_with_main(main: Option<&str>) -> SkillManifest {
        SkillManifest {
            main: main.map(|s| s.to_string()),
            ..base_manifest()
        }
    }

    #[test]
    fn red_id_is_r12() {
        let r = R12MainFieldEscape::new();
        assert_eq!(r.id().0, "R12-main-field-escape");
    }

    #[test]
    fn red_origin_is_builtin() {
        let r = R12MainFieldEscape::new();
        assert!(matches!(r.origin(), RuleOrigin::BuiltIn));
    }

    #[test]
    fn red_main_none_no_findings() {
        let r = R12MainFieldEscape::new();
        let m = manifest_with_main(None);
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert!(findings.is_empty());
    }

    #[test]
    fn red_dot_slash_relative_safe() {
        let r = R12MainFieldEscape::new();
        let m = manifest_with_main(Some("./index.js"));
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert!(findings.is_empty());
    }

    #[test]
    fn red_bare_relative_safe() {
        let r = R12MainFieldEscape::new();
        let m = manifest_with_main(Some("index.js"));
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert!(findings.is_empty());
    }

    #[test]
    fn red_subpath_safe() {
        let r = R12MainFieldEscape::new();
        let m = manifest_with_main(Some("src/main.js"));
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert!(findings.is_empty());
    }

    #[test]
    fn red_unix_absolute_produces_p0() {
        let r = R12MainFieldEscape::new();
        let m = manifest_with_main(Some("/usr/bin/evil.js"));
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::P0);
    }

    #[test]
    fn red_home_dir_tilde_produces_finding() {
        let r = R12MainFieldEscape::new();
        let m = manifest_with_main(Some("~/.evil/run.js"));
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn red_traversal_produces_finding() {
        let r = R12MainFieldEscape::new();
        let m = manifest_with_main(Some("../../etc/malware.js"));
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn red_http_url_produces_finding() {
        let r = R12MainFieldEscape::new();
        let m = manifest_with_main(Some("http://evil.com/malware.js"));
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn red_https_url_produces_finding() {
        let r = R12MainFieldEscape::new();
        let m = manifest_with_main(Some("https://evil.com/malware.js"));
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn red_ftp_url_produces_finding() {
        let r = R12MainFieldEscape::new();
        let m = manifest_with_main(Some("ftp://files.example.com/evil.js"));
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn red_git_url_produces_finding() {
        let r = R12MainFieldEscape::new();
        let m = manifest_with_main(Some("git://github.com/evil/payload.js"));
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn red_windows_absolute_produces_finding() {
        let r = R12MainFieldEscape::new();
        let m = manifest_with_main(Some("C:\\Windows\\evil.exe"));
        let findings = r.check(&m, Path::new("/tmp/test"));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn red_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<R12MainFieldEscape>();
    }
}
