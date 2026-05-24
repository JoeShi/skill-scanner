use skill_scanner_ruleset::semgrep::SemgrepRule;
use skill_scanner_ruleset::{validate_id_format, validate_message_length, RulesetValidationError};
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

fn rule(id: &str, message: &str) -> SemgrepRule {
    SemgrepRule {
        id: id.to_string(),
        message: message.to_string(),
        _rest: serde_yaml::Value::Null,
    }
}

// AC1: valid id "my-rule" → Ok
#[test]
fn ac1_valid_id_my_rule() {
    let r = rule("my-rule", "safe message");
    assert!(
        validate_id_format(&r).is_ok(),
        "\"my-rule\" must be a valid id"
    );
}

// AC2: valid id "a" (single char minimum) → Ok
#[test]
fn ac2_valid_single_char_id() {
    let r = rule("a", "safe message");
    assert!(
        validate_id_format(&r).is_ok(),
        "\"a\" must be a valid single-char id"
    );
}

// AC3: valid id "ab-cd-ef01" (lowercase + hyphen + digit) → Ok
#[test]
fn ac3_valid_alphanumeric_hyphenated() {
    let r = rule("ab-cd-ef01", "safe message");
    assert!(
        validate_id_format(&r).is_ok(),
        "\"ab-cd-ef01\" must be a valid id"
    );
}

// AC4: uppercase "MY-RULE" → RULESET_C1_INVALID_ID
#[test]
fn ac4_uppercase_id_rejected() {
    let r = rule("MY-RULE", "msg");
    let err = validate_id_format(&r).unwrap_err();
    assert_eq!(
        err.code(),
        "RULESET_C1_INVALID_ID",
        "uppercase id must produce RULESET_C1_INVALID_ID"
    );
}

// AC5: colon "core:R5" → RULESET_C1_INVALID_ID (core ID spoof prevention)
#[test]
fn ac5_colon_in_id_rejected() {
    let r = rule("core:R5", "msg");
    let err = validate_id_format(&r).unwrap_err();
    assert_eq!(
        err.code(),
        "RULESET_C1_INVALID_ID",
        "colon in id must be rejected as potential core ID spoof"
    );
}

// AC6: slash "a/b" → RULESET_C1_INVALID_ID
#[test]
fn ac6_slash_in_id_rejected() {
    let r = rule("a/b", "msg");
    let err = validate_id_format(&r).unwrap_err();
    assert_eq!(
        err.code(),
        "RULESET_C1_INVALID_ID",
        "slash in id must produce RULESET_C1_INVALID_ID"
    );
}

// AC7: leading digit "1abc" → RULESET_C1_INVALID_ID
#[test]
fn ac7_leading_digit_rejected() {
    let r = rule("1abc", "msg");
    let err = validate_id_format(&r).unwrap_err();
    assert_eq!(
        err.code(),
        "RULESET_C1_INVALID_ID",
        "leading digit must produce RULESET_C1_INVALID_ID"
    );
}

// AC8: leading hyphen "-abc" → RULESET_C1_INVALID_ID
#[test]
fn ac8_leading_hyphen_rejected() {
    let r = rule("-abc", "msg");
    let err = validate_id_format(&r).unwrap_err();
    assert_eq!(
        err.code(),
        "RULESET_C1_INVALID_ID",
        "leading hyphen must produce RULESET_C1_INVALID_ID"
    );
}

// AC9: space "my rule" → RULESET_C1_INVALID_ID
#[test]
fn ac9_space_in_id_rejected() {
    let r = rule("my rule", "msg");
    let err = validate_id_format(&r).unwrap_err();
    assert_eq!(
        err.code(),
        "RULESET_C1_INVALID_ID",
        "space in id must produce RULESET_C1_INVALID_ID"
    );
}

// AC10: empty "" → RULESET_C1_INVALID_ID
#[test]
fn ac10_empty_id_rejected() {
    let r = rule("", "msg");
    let err = validate_id_format(&r).unwrap_err();
    assert_eq!(
        err.code(),
        "RULESET_C1_INVALID_ID",
        "empty id must produce RULESET_C1_INVALID_ID"
    );
}

// AC11: message of exactly 2000 bytes → Ok
#[test]
fn ac11_message_2000_bytes_ok() {
    let msg = "a".repeat(2000);
    let r = rule("r-test", &msg);
    assert!(
        validate_message_length(&r).is_ok(),
        "message of exactly 2000 bytes must be Ok"
    );
}

// AC12: message of 2001 bytes → RULESET_C1_MESSAGE_TOO_LONG
#[test]
fn ac12_message_2001_bytes_rejected() {
    let msg = "a".repeat(2001);
    let r = rule("r-test", &msg);
    let err = validate_message_length(&r).unwrap_err();
    assert_eq!(
        err.code(),
        "RULESET_C1_MESSAGE_TOO_LONG",
        "2001-byte message must produce RULESET_C1_MESSAGE_TOO_LONG"
    );
}

// AC13: empty message → Ok (C5 handles template injection separately)
#[test]
fn ac13_empty_message_ok() {
    let r = rule("r-test", "");
    assert!(
        validate_message_length(&r).is_ok(),
        "empty message must be Ok for length check"
    );
}

// AC14: load_from_path: YAML rule with invalid id → RULESET_C1_INVALID_ID
#[test]
fn ac14_load_rejects_invalid_id() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad-id.yml");
    let mut file = std::fs::File::create(&path).unwrap();
    writeln!(file, "- id: INVALID-UPPERCASE").unwrap();
    writeln!(file, "  message: Looks fine").unwrap();

    let res = skill_scanner_ruleset::load_from_path(&path);
    assert!(res.is_err(), "load must fail for rule with invalid id");
    assert_eq!(
        res.unwrap_err().code(),
        "RULESET_C1_INVALID_ID",
        "load must return RULESET_C1_INVALID_ID for invalid id"
    );
}

// AC15: load_from_path: YAML rule with 2001-char message → RULESET_C1_MESSAGE_TOO_LONG
#[test]
fn ac15_load_rejects_overlong_message() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("long-msg.yml");
    let mut file = std::fs::File::create(&path).unwrap();
    let long_msg = "x".repeat(2001);
    writeln!(file, "- id: r-long-msg").unwrap();
    writeln!(file, "  message: {}", long_msg).unwrap();

    let res = skill_scanner_ruleset::load_from_path(&path);
    assert!(
        res.is_err(),
        "load must fail for rule with overlong message"
    );
    assert_eq!(
        res.unwrap_err().code(),
        "RULESET_C1_MESSAGE_TOO_LONG",
        "load must return RULESET_C1_MESSAGE_TOO_LONG for overlong message"
    );
}

// AC16: validator functions are pure (no I/O in source)
#[test]
fn ac16_validators_are_pure() {
    fn check_pure_fn<F>(_f: F)
    where
        F: Fn(&SemgrepRule) -> Result<(), RulesetValidationError>,
    {
    }
    check_pure_fn(validate_id_format);
    check_pure_fn(validate_message_length);

    let validator_path = workspace_root()
        .join("crates")
        .join("ruleset")
        .join("src")
        .join("validators")
        .join("validate_id_format.rs");
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
            "validate_id_format.rs must not contain '{}': found forbidden I/O pattern",
            pat
        );
    }
}
