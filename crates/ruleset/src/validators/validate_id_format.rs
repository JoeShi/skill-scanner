//! C1 — schema validation validators
//! Checks SemgrepRule id format (`^[a-z][a-z0-9-]*$`) and message length (≤2000 bytes).

use crate::error::RulesetValidationError;
use crate::semgrep::SemgrepRule;

/// Validates that `rule.id` matches `^[a-z][a-z0-9-]*$`.
///
/// Valid:   "my-rule", "a", "ab-cd-ef01"
/// Invalid: "MY-RULE", "core:R5", "a/b", "1abc", "-abc", "my rule", ""
pub fn validate_id_format(rule: &SemgrepRule) -> Result<(), RulesetValidationError> {
    let id = &rule.id;

    if id.is_empty() {
        return Err(RulesetValidationError::C1InvalidId {
            rule_id: id.clone(),
        });
    }

    let mut chars = id.chars();
    let first = chars.next().unwrap();
    if !first.is_ascii_lowercase() {
        return Err(RulesetValidationError::C1InvalidId {
            rule_id: id.clone(),
        });
    }

    for c in chars {
        if !c.is_ascii_lowercase() && !c.is_ascii_digit() && c != '-' {
            return Err(RulesetValidationError::C1InvalidId {
                rule_id: id.clone(),
            });
        }
    }

    Ok(())
}

/// Validates that `rule.message` is at most 2000 bytes long.
pub fn validate_message_length(rule: &SemgrepRule) -> Result<(), RulesetValidationError> {
    let len = rule.message.len();
    if len > 2000 {
        return Err(RulesetValidationError::C1MessageTooLong {
            rule_id: rule.id.clone(),
            len,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::semgrep::SemgrepRule;

    fn rule(id: &str, message: &str) -> SemgrepRule {
        SemgrepRule {
            id: id.to_string(),
            message: message.to_string(),
            _rest: serde_yaml::Value::Null,
        }
    }

    #[test]
    fn red_valid_id_my_rule() {
        let r = rule("my-rule", "safe message");
        assert!(validate_id_format(&r).is_ok());
    }

    #[test]
    fn red_valid_single_char_id() {
        let r = rule("a", "safe message");
        assert!(validate_id_format(&r).is_ok());
    }

    #[test]
    fn red_valid_alphanumeric_hyphenated() {
        let r = rule("ab-cd-ef01", "safe message");
        assert!(validate_id_format(&r).is_ok());
    }

    #[test]
    fn red_uppercase_id_rejected() {
        let r = rule("MY-RULE", "msg");
        let err = validate_id_format(&r).unwrap_err();
        assert_eq!(err.code(), "RULESET_C1_INVALID_ID");
    }

    #[test]
    fn red_colon_id_rejected() {
        let r = rule("core:R5", "msg");
        let err = validate_id_format(&r).unwrap_err();
        assert_eq!(err.code(), "RULESET_C1_INVALID_ID");
    }

    #[test]
    fn red_slash_id_rejected() {
        let r = rule("a/b", "msg");
        let err = validate_id_format(&r).unwrap_err();
        assert_eq!(err.code(), "RULESET_C1_INVALID_ID");
    }

    #[test]
    fn red_leading_digit_rejected() {
        let r = rule("1abc", "msg");
        let err = validate_id_format(&r).unwrap_err();
        assert_eq!(err.code(), "RULESET_C1_INVALID_ID");
    }

    #[test]
    fn red_leading_hyphen_rejected() {
        let r = rule("-abc", "msg");
        let err = validate_id_format(&r).unwrap_err();
        assert_eq!(err.code(), "RULESET_C1_INVALID_ID");
    }

    #[test]
    fn red_space_in_id_rejected() {
        let r = rule("my rule", "msg");
        let err = validate_id_format(&r).unwrap_err();
        assert_eq!(err.code(), "RULESET_C1_INVALID_ID");
    }

    #[test]
    fn red_empty_id_rejected() {
        let r = rule("", "msg");
        let err = validate_id_format(&r).unwrap_err();
        assert_eq!(err.code(), "RULESET_C1_INVALID_ID");
    }

    #[test]
    fn red_message_2000_bytes_ok() {
        let msg = "a".repeat(2000);
        let r = rule("r-test", &msg);
        assert!(validate_message_length(&r).is_ok());
    }

    #[test]
    fn red_message_2001_bytes_rejected() {
        let msg = "a".repeat(2001);
        let r = rule("r-test", &msg);
        let err = validate_message_length(&r).unwrap_err();
        assert_eq!(err.code(), "RULESET_C1_MESSAGE_TOO_LONG");
    }

    #[test]
    fn red_empty_message_ok() {
        let r = rule("r-test", "");
        assert!(validate_message_length(&r).is_ok());
    }
}
