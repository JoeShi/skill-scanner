//! skill-scanner-rules — built-in rule definitions (R0–R13)

use skill_scanner_core::{Finding, RuleId, RuleOrigin};
use skill_scanner_manifest::SkillManifest;
use std::path::Path;

pub mod r0;
pub mod r1;
pub mod r10;
pub mod r11;
pub mod r12;
pub mod r13;
pub mod r2;
pub mod r3;
pub mod r4;
pub mod r5;
pub mod r6;
pub mod r7;
pub mod r8;
pub mod r9;

pub trait Rule: Send + Sync {
    fn id(&self) -> &RuleId;
    fn origin(&self) -> RuleOrigin;
    fn check(&self, manifest: &SkillManifest, manifest_path: &Path) -> Vec<Finding>;
}

pub fn builtin_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(r0::R0ManifestStructure::new()),
        Box::new(r0::R0MissingCapabilities::new()),
        Box::new(r1::R1SensitiveEnvKey::new()),
        Box::new(r2::R2InstallerCommand::new()),
        Box::new(r3::R3InstallerScript::new()),
        Box::new(r4::R4InstallerTypeBlocked::new()),
        Box::new(r5::R5EnvSystemVar::new()),
        Box::new(r6::R6EnvValueSecrets::new()),
        Box::new(r7::R7InstallerInlineExec::new()),
        Box::new(r8::R8FsPathsEscape::new()),
        Box::new(r9::R9DomainsWildcard::new()),
        Box::new(r10::R10DependencyProtocol::new()),
        Box::new(r11::R11CapabilityWildcard::new()),
        Box::new(r12::R12MainFieldEscape::new()),
        Box::new(r13::R13EnvKeyShellInject::new()),
    ]
}
