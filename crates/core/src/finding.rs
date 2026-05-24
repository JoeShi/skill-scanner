use crate::{Location, RuleId, RuleOrigin, Severity};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Finding {
    pub rule_id: RuleId,
    pub rule_origin: RuleOrigin,
    pub severity: Severity,
    pub message: String,
    pub location: Location,
}
