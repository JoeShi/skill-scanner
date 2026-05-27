use std::collections::HashSet;
use std::path::Path;

use regex::Regex;

use crate::manifest::validate_manifest_structure;
use crate::types::{
    CriticalTag, ScanContext, ScanFinding, ScannerModule, Severity, ThreatCategory, Tier,
    RuleOrigin,
};

const INSTALLER_TYPE_ALLOWED: &[&str] = &["orchestrator-managed"];

const R12BIS_RECOMMENDATION: &str = "installer.command / .script must be a benign invocation. \
To run multi-step setup, ship a script inside the skill directory and reference it via \
installer.script: ./setup.sh. To depend on system tools, declare them in \
manifest.requirements instead of embedding in installer.command.";

fn env_block_list() -> HashSet<&'static str> {
    [
        "PATH",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "DYLD_FRAMEWORK_PATH",
        "NODE_OPTIONS",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "JAVA_TOOL_OPTIONS",
        "_JAVA_OPTIONS",
        "RUBYOPT",
        "PERL5OPT",
        "ELECTRON_RUN_AS_NODE",
    ]
    .into_iter()
    .collect()
}

pub struct ManifestValidationModule;

impl ScannerModule for ManifestValidationModule {
    fn name(&self) -> &str {
        "manifest-validation"
    }

    fn scan(&self, ctx: &ScanContext) -> Vec<ScanFinding> {
        let mut findings = Vec::new();

        // R0 - structure validation
        let errors = validate_manifest_structure(&ctx.manifest);
        for err in errors {
            findings.push(ScanFinding {
                rule_id: "R0-manifest-structure".to_string(),
                tier: Tier::Blocker,
                severity: Severity::P0,
                critical_tag: Some(CriticalTag::Security),
                message: format!("Manifest structure violation: {}", err),
                file: Some("manifest.json".to_string()),
                line: None,
                column: None,
                category: ThreatCategory::MaliciousCode,
                evidence: None,
                recommendation: Some(
                    "Fix manifest.json to comply with required schema".to_string(),
                ),
                rule_origin: Some(RuleOrigin::Core),
                ref_anchor: None,
                merged_from: None,
            });
        }

        // Check for required capability declarations
        let has_capabilities = ctx
            .manifest
            .capabilities
            .as_ref()
            .map(|c| {
                if let Some(arr) = c.as_array() {
                    !arr.is_empty()
                } else {
                    c.is_object()
                }
            })
            .unwrap_or(false);

        if !has_capabilities {
            findings.push(ScanFinding {
                rule_id: "R0-missing-capabilities".to_string(),
                tier: Tier::Blocker,
                severity: Severity::P0,
                critical_tag: Some(CriticalTag::Security),
                message: "Manifest missing capabilities declaration. v1 requires explicit capability listing.".to_string(),
                file: Some("manifest.json".to_string()),
                line: None,
                column: None,
                category: ThreatCategory::PrivilegeEscalation,
                evidence: None,
                recommendation: Some("Add capabilities section to manifest.json".to_string()),
                rule_origin: Some(RuleOrigin::Core),
                ref_anchor: None,
                merged_from: None,
            });
        }

        // R12 - installer.type whitelist
        if let Some(ref installer) = ctx.manifest.installer {
            if let Some(ref installer_type) = installer.installer_type {
                if !INSTALLER_TYPE_ALLOWED.contains(&installer_type.as_str()) {
                    findings.push(ScanFinding {
                        rule_id: "R12-installer-type-blocked".to_string(),
                        tier: Tier::Blocker,
                        severity: Severity::P0,
                        critical_tag: Some(CriticalTag::Security),
                        message: format!(
                            "manifest.installer.type=\"{}\" bypasses the orchestrator spawn whitelist (HF-7). Only \"orchestrator-managed\" is allowed.",
                            installer_type
                        ),
                        file: Some("manifest.json".to_string()),
                        line: None,
                        column: None,
                        category: ThreatCategory::PrivilegeEscalation,
                        evidence: Some(format!("installer.type: {}", installer_type)),
                        recommendation: Some("Set installer.type to \"orchestrator-managed\" or omit the installer field entirely.".to_string()),
                        rule_origin: Some(RuleOrigin::Core),
                        ref_anchor: None,
                        merged_from: None,
                    });
                }
            }

            // R12-bis - command content validation
            if let Some(ref command) = installer.command {
                let metachar_re = Regex::new(r"&&|\|\||\$\(|>>|<<|[;`><|&\\]").unwrap();
                if let Some(m) = metachar_re.find(command) {
                    findings.push(ScanFinding {
                        rule_id: "R12-bis-command-metachar".to_string(),
                        tier: Tier::Blocker,
                        severity: Severity::P0,
                        critical_tag: Some(CriticalTag::Security),
                        message: format!(
                            "manifest.installer.command contains shell metachar \"{}\" -- arbitrary command injection vector (HF-7 bypass).",
                            m.as_str()
                        ),
                        file: Some("manifest.json".to_string()),
                        line: None,
                        column: None,
                        category: ThreatCategory::PrivilegeEscalation,
                        evidence: Some(format!("installer.command: {}", command)),
                        recommendation: Some(R12BIS_RECOMMENDATION.to_string()),
                        rule_origin: Some(RuleOrigin::Core),
                        ref_anchor: None,
                        merged_from: None,
                    });
                }

                // First-token absolute path policy
                let first_token = command.split_whitespace().next().unwrap_or("");
                if !first_token.is_empty() && Path::new(first_token).is_absolute() {
                    findings.push(ScanFinding {
                        rule_id: "R12-bis-command-interpreter".to_string(),
                        tier: Tier::Blocker,
                        severity: Severity::P0,
                        critical_tag: Some(CriticalTag::Security),
                        message: format!(
                            "manifest.installer.command first token \"{}\" is an absolute system path -- use a known interpreter name (node/python3/sh/bash/pwsh) or a skill-internal relative path instead.",
                            first_token
                        ),
                        file: Some("manifest.json".to_string()),
                        line: None,
                        column: None,
                        category: ThreatCategory::PrivilegeEscalation,
                        evidence: Some(format!("installer.command: {}", command)),
                        recommendation: Some(R12BIS_RECOMMENDATION.to_string()),
                        rule_origin: Some(RuleOrigin::Core),
                        ref_anchor: None,
                        merged_from: None,
                    });
                }
            }

            // R12-bis - script path containment
            if let Some(ref script) = installer.script {
                let normalized = Path::new(script);
                if normalized.is_absolute() || script.starts_with("..") {
                    findings.push(ScanFinding {
                        rule_id: "R12-bis-script-path".to_string(),
                        tier: Tier::Blocker,
                        severity: Severity::P0,
                        critical_tag: Some(CriticalTag::Security),
                        message: format!(
                            "manifest.installer.script \"{}\" resolves outside the skill package boundary -- path traversal / absolute path injection.",
                            script
                        ),
                        file: Some("manifest.json".to_string()),
                        line: None,
                        column: None,
                        category: ThreatCategory::PrivilegeEscalation,
                        evidence: Some(format!("installer.script: {}", script)),
                        recommendation: Some(R12BIS_RECOMMENDATION.to_string()),
                        rule_origin: Some(RuleOrigin::Core),
                        ref_anchor: None,
                        merged_from: None,
                    });
                }
            }
        }

        // R13 - env sensitive-key block
        if let Some(ref env) = ctx.manifest.env {
            let block_list = env_block_list();
            for key in env.keys() {
                if block_list.contains(key.to_uppercase().as_str()) {
                    findings.push(ScanFinding {
                        rule_id: "R13-env-sensitive-key".to_string(),
                        tier: Tier::Blocker,
                        severity: Severity::P0,
                        critical_tag: Some(CriticalTag::Security),
                        message: format!(
                            "manifest.env overrides \"{}\" -- sensitive env var injection vector (HF-3/HF-7 bypass).",
                            key
                        ),
                        file: Some("manifest.json".to_string()),
                        line: None,
                        column: None,
                        category: ThreatCategory::PrivilegeEscalation,
                        evidence: Some(format!("env.{}", key)),
                        recommendation: Some(format!(
                            "Remove env.{} from the manifest. Sensitive env vars cannot be overridden by skills.",
                            key
                        )),
                        rule_origin: Some(RuleOrigin::Core),
                        ref_anchor: None,
                        merged_from: None,
                    });
                }
            }
        }

        findings
    }
}
