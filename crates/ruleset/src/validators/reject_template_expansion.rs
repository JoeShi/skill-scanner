use crate::error::RulesetValidationError;
use crate::semgrep::SemgrepRule;
use once_cell::sync::Lazy;
use regex::Regex;

static TEMPLATE_EXPANSION_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\$\{[^}]*\}").expect("template expansion regex is valid"));

pub fn reject_template_expansion(rule: &SemgrepRule) -> Result<(), RulesetValidationError> {
    // Fast path: avoid regex overhead when there's no '${' at all
    if !rule.message.contains("${") {
        return Ok(());
    }
    if let Some(m) = TEMPLATE_EXPANSION_RE.find(&rule.message) {
        return Err(RulesetValidationError::TemplateExpansion {
            rule_id: rule.id.clone(),
            offending_fragment: m.as_str().to_string(),
        });
    }
    Ok(())
}
