// C1 — schema validation validators (stub — to be implemented by KimiCoder)
use crate::error::RulesetValidationError;
use crate::semgrep::SemgrepRule;

pub fn validate_id_format(_rule: &SemgrepRule) -> Result<(), RulesetValidationError> {
    todo!("C1 validate_id_format: implement ^[a-z][a-z0-9-]*$ check")
}

pub fn validate_message_length(_rule: &SemgrepRule) -> Result<(), RulesetValidationError> {
    todo!("C1 validate_message_length: implement 2000-byte cap")
}
