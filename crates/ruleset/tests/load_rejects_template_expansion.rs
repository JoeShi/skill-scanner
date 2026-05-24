use skill_scanner_ruleset::RulesetValidationError;
use std::io::Write;
use std::path::PathBuf;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

#[test]
fn ac7_whole_ruleset_aborts_on_single_rejection() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad-ruleset.yml");
    let mut file = std::fs::File::create(&path).unwrap();
    writeln!(file, "- id: r-good").unwrap();
    writeln!(file, "  message: OK rule").unwrap();
    writeln!(file, "- id: r-bad").unwrap();
    writeln!(file, "  message: Bad rule with ${{X}}").unwrap();
    writeln!(file, "- id: r-also-good").unwrap();
    writeln!(file, "  message: Another OK rule").unwrap();

    let res = skill_scanner_ruleset::load_from_path(&path);
    assert!(
        res.is_err(),
        "load must fail when any rule has template expansion"
    );
    let err = res.unwrap_err();
    assert_eq!(err.code(), "RULESET_C5_TEMPLATE_EXPANSION");
}

#[test]
fn ac10_no_io_in_validator_dep_closure() {
    // Compile-time signature check: validator is a pure Fn, not async
    fn check_pure_fn<F>(_f: F)
    where
        F: Fn(&skill_scanner_ruleset::semgrep::SemgrepRule) -> Result<(), RulesetValidationError>,
    {
    }
    check_pure_fn(skill_scanner_ruleset::reject_template_expansion);

    // Source-text grep: validator file must NOT contain forbidden I/O patterns
    let validator_path = workspace_root()
        .join("crates")
        .join("ruleset")
        .join("src")
        .join("validators")
        .join("reject_template_expansion.rs");
    let src = std::fs::read_to_string(&validator_path)
        .unwrap_or_else(|e| panic!("failed to read validator source: {}", e));
    let forbidden = [
        "std::fs",
        "std::net",
        "std::process",
        "tokio::",
        "reqwest::",
    ];
    for pat in &forbidden {
        assert!(
            !src.contains(pat),
            "validator source must not contain '{}': found forbidden I/O pattern",
            pat
        );
    }
}

#[test]
fn ac11_no_semgrep_binary_required() {
    // This test verifies by construction: we run `cargo test` without semgrep installed
    // If the test binary runs, the validator works without external binary
    let r = skill_scanner_ruleset::semgrep::SemgrepRule {
        id: "r-test".to_string(),
        message: "plain".to_string(),
        _rest: serde_yaml::Value::Null,
    };
    assert!(skill_scanner_ruleset::reject_template_expansion(&r).is_ok());
}

#[test]
fn ac13_re_export_compiles() {
    // This file compiles → re-export works
    let _ = skill_scanner_ruleset::reject_template_expansion;
}

#[test]
fn ac15_only_ruleset_lists_regex() {
    // Static parse of each crate's Cargo.toml: ruleset and rules may list regex
    // (rules added in L1.9 when R6-env-value-secrets landed its regex-based secret scan)
    let crates = ["core", "rules", "ruleset", "manifest", "clawhub", "cli"];
    for name in &crates {
        let manifest_path = workspace_root()
            .join("crates")
            .join(name)
            .join("Cargo.toml");
        let content = std::fs::read_to_string(&manifest_path)
            .unwrap_or_else(|e| panic!("failed to read {} Cargo.toml: {}", name, e));
        let doc: toml::Table = content.parse().expect("valid toml");
        let deps = doc
            .get("dependencies")
            .and_then(|d| d.as_table())
            .unwrap_or(&toml::map::Map::new())
            .clone();
        let has_regex = deps.contains_key("regex");
        if *name == "ruleset" || *name == "rules" {
            assert!(has_regex, "{} must list regex", name);
        } else {
            assert!(!has_regex, "{} must not list regex", name);
        }
    }
}
