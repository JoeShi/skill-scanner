// C2 — origin stamp validator (stub — to be implemented by KimiDev)
use crate::error::RulesetValidationError;
use crate::semgrep::SemgrepRule;
use skill_scanner_core::RuleOrigin;
use std::path::Path;

pub fn validate_no_origin_spoof(_rule: &SemgrepRule) -> Result<(), RulesetValidationError> {
    todo!("C2 validate_no_origin_spoof: reject any rule_origin key in _rest")
}

pub fn custom_origin(_path: &Path) -> RuleOrigin {
    todo!(
        "C2 custom_origin: return RuleOrigin::Custom {{ ruleset_id: path.display().to_string() }}"
    )
}
