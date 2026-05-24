use skill_scanner_ruleset::semgrep::SemgrepRule;
use skill_scanner_ruleset::{reject_template_expansion, RulesetValidationError};

fn rule(id: &str, message: &str) -> SemgrepRule {
    SemgrepRule {
        id: id.to_string(),
        message: message.to_string(),
        _rest: serde_yaml::Value::Null,
    }
}

// AC1: ${SECRET} → rejected
#[test]
fn ac1_template_expansion_rejected() {
    let r = rule("r-secret", "Found ${SECRET}");
    let err = reject_template_expansion(&r).unwrap_err();
    match &err {
        RulesetValidationError::TemplateExpansion {
            rule_id,
            offending_fragment,
        } => {
            assert_eq!(rule_id, "r-secret");
            assert_eq!(offending_fragment, "${SECRET}");
        }
        _ => panic!("expected TemplateExpansion, got {:?}", err),
    }
    assert_eq!(err.code(), "RULESET_C5_TEMPLATE_EXPANSION");
}

// AC2: $VAR (no braces) → permitted
#[test]
fn ac2_bare_metavariable_permitted() {
    let r = rule("r-bare", "$VAR is bad");
    assert!(reject_template_expansion(&r).is_ok());
}

// AC3: multiple ${} → first match reported
#[test]
fn ac3_first_match_reported() {
    let r = rule("r-multi", "prefix ${A} middle ${B} suffix");
    let err = reject_template_expansion(&r).unwrap_err();
    match &err {
        RulesetValidationError::TemplateExpansion {
            offending_fragment, ..
        } => {
            assert_eq!(offending_fragment, "${A}");
        }
        _ => panic!("expected TemplateExpansion"),
    }
}

// AC4: empty ${} → rejected
#[test]
fn ac4_empty_braces_rejected() {
    let r = rule("r-empty", "empty ${}");
    let err = reject_template_expansion(&r).unwrap_err();
    match &err {
        RulesetValidationError::TemplateExpansion {
            offending_fragment, ..
        } => {
            assert_eq!(offending_fragment, "${}");
        }
        _ => panic!("expected TemplateExpansion"),
    }
}

// AC5: escaped \${SECRET} → still rejected (escape NOT recognized)
#[test]
fn ac5_escaped_not_recognized() {
    let r = rule("r-esc", "escaped \\${SECRET}");
    let err = reject_template_expansion(&r).unwrap_err();
    match &err {
        RulesetValidationError::TemplateExpansion {
            offending_fragment, ..
        } => {
            assert_eq!(offending_fragment, "${SECRET}");
        }
        _ => panic!("expected TemplateExpansion"),
    }
}

// AC6: plain text → permitted
#[test]
fn ac6_plain_text_permitted() {
    let r = rule("r-plain", "plain text only");
    assert!(reject_template_expansion(&r).is_ok());
}

// AC8: Display format exact match
#[test]
fn ac8_display_format_exact() {
    let r = rule("r-secret", "Found ${SECRET}");
    let err = reject_template_expansion(&r).unwrap_err();
    let expected = r#"Custom ruleset rule "r-secret" rejected: rule.message contains template expansion ${SECRET} (rule code RULESET_C5_TEMPLATE_EXPANSION)"#;
    assert_eq!(format!("{}", err), expected);
}

// AC9: determinism
#[test]
fn ac9_determinism() {
    let r = rule("r-dup", "Found ${SECRET}");
    let res1 = reject_template_expansion(&r);
    let res2 = reject_template_expansion(&r);
    assert_eq!(res1, res2);
    assert_eq!(format!("{:?}", res1), format!("{:?}", res2));
}

// AC14: trait bounds
#[test]
fn ac14_trait_bounds() {
    fn check_bounds<T: PartialEq + Eq + std::fmt::Debug + std::error::Error + Send + Sync>(_t: &T) {
    }
    let r = rule("r-bound", "Found ${SECRET}");
    let err = reject_template_expansion(&r).unwrap_err();
    check_bounds(&err);
}
