//! skill-scanner-ruleset — custom ruleset loader and validators

pub mod error;
pub mod semgrep;
pub mod validators;

pub use error::RulesetValidationError;
pub use validators::reject_template_expansion;
pub use validators::validate_id_format::{validate_id_format, validate_message_length};
pub use validators::validate_no_origin_spoof::{custom_origin, validate_no_origin_spoof};

use std::path::Path;

pub fn load_from_path(path: &Path) -> Result<Vec<semgrep::SemgrepRule>, RulesetValidationError> {
    if !path.exists() {
        return Ok(vec![]);
    }
    let content = std::fs::read_to_string(path).map_err(|e| RulesetValidationError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    let rules: Vec<semgrep::SemgrepRule> =
        serde_yaml::from_str(&content).map_err(|e| RulesetValidationError::Yaml { source: e })?;
    for rule in &rules {
        validators::reject_template_expansion(rule)?;
    }
    Ok(rules)
}
