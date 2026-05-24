// C2 — origin stamp validator
// Rejects any custom ruleset YAML that contains a `rule_origin` field.
// The loader stamps origin exclusively; custom rules may not self-declare.

use crate::error::RulesetValidationError;
use crate::semgrep::SemgrepRule;
use skill_scanner_core::RuleOrigin;
use std::path::Path;

pub fn validate_no_origin_spoof(rule: &SemgrepRule) -> Result<(), RulesetValidationError> {
    let has_origin = match &rule._rest {
        serde_yaml::Value::Mapping(map) => {
            map.contains_key(serde_yaml::Value::String("rule_origin".to_string()))
        }
        _ => false,
    };

    if has_origin {
        Err(RulesetValidationError::C2OriginSpoof {
            rule_id: rule.id.clone(),
        })
    } else {
        Ok(())
    }
}

pub fn custom_origin(path: &Path) -> RuleOrigin {
    RuleOrigin::Custom {
        ruleset_id: path.display().to_string(),
    }
}
