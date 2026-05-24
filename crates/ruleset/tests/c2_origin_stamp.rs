use skill_scanner_core::RuleOrigin;
use skill_scanner_ruleset::semgrep::SemgrepRule;
use skill_scanner_ruleset::{custom_origin, validate_no_origin_spoof};
use std::io::Write;
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn rule_clean(id: &str) -> SemgrepRule {
    SemgrepRule {
        id: id.to_string(),
        message: "test".to_string(),
        _rest: serde_yaml::Value::Null,
    }
}

fn rule_with_safe_extra(id: &str) -> SemgrepRule {
    let mut map = serde_yaml::Mapping::new();
    map.insert(
        serde_yaml::Value::String("languages".to_string()),
        serde_yaml::Value::Sequence(vec![serde_yaml::Value::String("python".to_string())]),
    );
    SemgrepRule {
        id: id.to_string(),
        message: "test".to_string(),
        _rest: serde_yaml::Value::Mapping(map),
    }
}

fn rule_with_origin_claim(id: &str, origin_val: &str) -> SemgrepRule {
    let mut map = serde_yaml::Mapping::new();
    map.insert(
        serde_yaml::Value::String("rule_origin".to_string()),
        serde_yaml::Value::String(origin_val.to_string()),
    );
    SemgrepRule {
        id: id.to_string(),
        message: "test".to_string(),
        _rest: serde_yaml::Value::Mapping(map),
    }
}

// AC1: custom_origin(path) returns RuleOrigin::Custom { ruleset_id }
#[test]
fn ac1_custom_origin_returns_custom_variant() {
    let path = Path::new("/tmp/my-rules.yml");
    let origin = custom_origin(path);
    match origin {
        RuleOrigin::Custom { ruleset_id } => {
            assert!(
                !ruleset_id.is_empty(),
                "custom_origin must return a non-empty ruleset_id"
            );
        }
        other => panic!("expected RuleOrigin::Custom, got {:?}", other),
    }
}

// AC2: custom_origin never returns BuiltIn
#[test]
fn ac2_custom_origin_not_builtin() {
    let origin = custom_origin(Path::new("/tmp/rules.yml"));
    assert_ne!(
        origin,
        RuleOrigin::BuiltIn,
        "custom_origin must never return BuiltIn"
    );
}

// AC3: custom_origin never returns Semgrep
#[test]
fn ac3_custom_origin_not_semgrep() {
    let origin = custom_origin(Path::new("/tmp/rules.yml"));
    assert!(
        !matches!(origin, RuleOrigin::Semgrep { .. }),
        "custom_origin must never return Semgrep variant"
    );
}

// AC4: two different paths → two different ruleset_id values
#[test]
fn ac4_different_paths_different_ruleset_id() {
    let origin_a = custom_origin(Path::new("/tmp/a.yml"));
    let origin_b = custom_origin(Path::new("/tmp/b.yml"));
    assert_ne!(
        origin_a, origin_b,
        "different paths must produce different custom origins"
    );
}

// AC5: validate_no_origin_spoof Ok for rule with no extra fields (_rest: Null)
#[test]
fn ac5_clean_rule_ok() {
    let r = rule_clean("r-clean");
    assert!(
        validate_no_origin_spoof(&r).is_ok(),
        "rule with no extra fields must produce Ok"
    );
}

// AC6: Ok for rule with safe extra fields (languages, patterns)
#[test]
fn ac6_safe_extra_fields_ok() {
    let r = rule_with_safe_extra("r-safe");
    assert!(
        validate_no_origin_spoof(&r).is_ok(),
        "rule with safe extra fields must produce Ok"
    );
}

// AC7: rule_origin: "built-in" → RULESET_C2_ORIGIN_SPOOF
#[test]
fn ac7_built_in_claim_rejected() {
    let r = rule_with_origin_claim("r-spoof", "built-in");
    let err = validate_no_origin_spoof(&r).unwrap_err();
    assert_eq!(
        err.code(),
        "RULESET_C2_ORIGIN_SPOOF",
        "rule_origin: built-in must produce RULESET_C2_ORIGIN_SPOOF"
    );
}

// AC8: rule_origin: "core" → RULESET_C2_ORIGIN_SPOOF
#[test]
fn ac8_core_claim_rejected() {
    let r = rule_with_origin_claim("r-spoof", "core");
    let err = validate_no_origin_spoof(&r).unwrap_err();
    assert_eq!(
        err.code(),
        "RULESET_C2_ORIGIN_SPOOF",
        "rule_origin: core must produce RULESET_C2_ORIGIN_SPOOF"
    );
}

// AC9: rule_origin: "custom" → RULESET_C2_ORIGIN_SPOOF
//   Custom rules must never self-declare origin — any value is a spoof attempt;
//   the loader stamps RuleOrigin exclusively.
#[test]
fn ac9_any_rule_origin_claim_rejected() {
    let r = rule_with_origin_claim("r-self-label", "custom");
    let err = validate_no_origin_spoof(&r).unwrap_err();
    assert_eq!(
        err.code(),
        "RULESET_C2_ORIGIN_SPOOF",
        "any rule_origin value must be rejected — loader stamps origin exclusively"
    );
}

// AC10: error includes offending rule_id in message; code is RULESET_C2_ORIGIN_SPOOF
#[test]
fn ac10_error_includes_rule_id() {
    let r = rule_with_origin_claim("my-spoof-rule", "built-in");
    let err = validate_no_origin_spoof(&r).unwrap_err();
    assert_eq!(err.code(), "RULESET_C2_ORIGIN_SPOOF");
    let msg = format!("{}", err);
    assert!(
        msg.contains("my-spoof-rule"),
        "error message must contain offending rule_id, got: {}",
        msg
    );
}

// AC11: load_from_path rejects YAML rule with rule_origin field → RULESET_C2_ORIGIN_SPOOF
#[test]
fn ac11_load_rejects_rule_origin_in_yaml() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("spoof.yml");
    let mut file = std::fs::File::create(&path).unwrap();
    writeln!(file, "- id: r-spoof").unwrap();
    writeln!(file, "  message: I am totally legit").unwrap();
    writeln!(file, "  rule_origin: built-in").unwrap();

    let res = skill_scanner_ruleset::load_from_path(&path);
    assert!(
        res.is_err(),
        "load must fail when any rule claims rule_origin"
    );
    assert_eq!(res.unwrap_err().code(), "RULESET_C2_ORIGIN_SPOOF");
}

// AC12: determinism — same rule, same result on repeated calls
#[test]
fn ac12_determinism() {
    let r = rule_with_origin_claim("r-spoof", "built-in");
    let res1 = validate_no_origin_spoof(&r);
    let res2 = validate_no_origin_spoof(&r);
    assert_eq!(
        format!("{:?}", res1),
        format!("{:?}", res2),
        "validator must be deterministic"
    );
}

// AC13: pure function check (no I/O in validator source)
#[test]
fn ac13_validator_is_pure() {
    fn check_pure_fn<F>(_f: F)
    where
        F: Fn(&SemgrepRule) -> Result<(), skill_scanner_ruleset::RulesetValidationError>,
    {
    }
    check_pure_fn(validate_no_origin_spoof);

    let validator_path = workspace_root()
        .join("crates")
        .join("ruleset")
        .join("src")
        .join("validators")
        .join("validate_no_origin_spoof.rs");
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
            "validate_no_origin_spoof.rs must not contain '{}': found forbidden I/O pattern",
            pat
        );
    }
}

// AC14: custom_origin same path twice → identical ruleset_id (idempotent)
#[test]
fn ac14_custom_origin_same_path_idempotent() {
    let path = Path::new("/tmp/rules.yml");
    let origin_a = custom_origin(path);
    let origin_b = custom_origin(path);
    assert_eq!(
        origin_a, origin_b,
        "custom_origin must be idempotent for the same path"
    );
}
