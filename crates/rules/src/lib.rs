//! skill-scanner-rules — built-in rule definitions (R0–R13)

use skill_scanner_core::{RuleId, RuleOrigin};

pub trait Rule {
    fn id(&self) -> &RuleId;
    fn origin(&self) -> RuleOrigin;
}

pub fn builtin_rules() -> Vec<Box<dyn Rule>> {
    vec![]
}
