//! skill-scanner-rules — built-in rule definitions (R0–R13)

use skill_scanner_core::{Finding, RuleId, RuleOrigin};
use skill_scanner_manifest::SkillManifest;
use std::path::Path;

pub mod r0;
pub mod r1;

pub trait Rule: Send + Sync {
    fn id(&self) -> &RuleId;
    fn origin(&self) -> RuleOrigin;
    fn check(&self, manifest: &SkillManifest, manifest_path: &Path) -> Vec<Finding>;
}

pub fn builtin_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(r0::R0ManifestStructure::new()),
        Box::new(r0::R0MissingCapabilities::new()),
    ]
}
