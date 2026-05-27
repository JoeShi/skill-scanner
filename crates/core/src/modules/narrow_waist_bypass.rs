use std::fs;
use std::path::Path;

use regex::Regex;

use crate::types::{
    CriticalTag, RuleOrigin, ScanContext, ScanFinding, ScannerModule, Severity, ThreatCategory,
    Tier,
};

struct BypassPattern {
    regex: Regex,
    message: &'static str,
    rule_id: &'static str,
    recommendation: &'static str,
}

fn js_bypass_patterns() -> Vec<BypassPattern> {
    vec![
        BypassPattern {
            regex: Regex::new(r#"require\(['"]keytar['"]\)"#).unwrap(),
            message: "Direct keytar import (bypass orchestrator credentials API)",
            rule_id: "R5-direct-keychain-access",
            recommendation: "Use @quickport/orchestrator/credentials/* API instead of keytar",
        },
        BypassPattern {
            regex: Regex::new(r#"require\(['"]node-credential-manager['"]\)"#).unwrap(),
            message: "Direct node-credential-manager import (bypass orchestrator)",
            rule_id: "R5-direct-keychain-access",
            recommendation: "Use @quickport/orchestrator/credentials/* API",
        },
        BypassPattern {
            regex: Regex::new(r#"require\(['"]credential-manager['"]\)"#).unwrap(),
            message: "Direct credential-manager import (bypass orchestrator)",
            rule_id: "R5-direct-keychain-access",
            recommendation: "Use @quickport/orchestrator/credentials/* API",
        },
        BypassPattern {
            regex: Regex::new(r#"spawn\(['"]security['"]|exec\(['"]security\s+add-generic-password"#).unwrap(),
            message: "Direct macOS security command (bypass orchestrator credentials API)",
            rule_id: "R5-direct-keychain-access",
            recommendation: "Use @quickport/orchestrator/credentials/* API",
        },
        BypassPattern {
            regex: Regex::new(r#"writeFile(?:Sync)?\(['"`](?:~\/\.quickwork\/|.*?quickport\/state\/)\.audit\.json['"`]"#).unwrap(),
            message: "Direct audit log write (bypass orchestrator audit API)",
            rule_id: "R5-direct-audit-log-write",
            recommendation: "Use official audit logging APIs",
        },
        BypassPattern {
            regex: Regex::new(r#"writeFile(?:Sync)?\(['"`][^'"`]*mcp_config\.json['"`]"#).unwrap(),
            message: "Direct mcp_config.json write (bypass quick-config-patcher 5-invariants protocol)",
            rule_id: "R5-direct-quick-config-write",
            recommendation: "Use @quickport/orchestrator/quick-config-patcher/* API with atomic write + backup + schema validate + audit + rollback",
        },
        BypassPattern {
            regex: Regex::new(r#"writeFile(?:Sync)?\(['"`][^'"`]*capability-registry\.json['"`]"#).unwrap(),
            message: "Direct capability-registry.json write (bypass capability-registry module)",
            rule_id: "R5-direct-capability-registry-write",
            recommendation: "Use @quickport/orchestrator/capability-registry/* API",
        },
    ]
}

fn py_bypass_patterns() -> Vec<BypassPattern> {
    vec![BypassPattern {
        regex: Regex::new(r"keyring\.(set_password|get_password|delete_password)\s*\(").unwrap(),
        message: "Direct Python keyring access (bypass orchestrator credentials API)",
        rule_id: "R5-py-direct-keychain-access",
        recommendation: "Use @quickport/orchestrator/credentials/* API",
    }]
}

pub struct NarrowWaistBypassModule;

impl ScannerModule for NarrowWaistBypassModule {
    fn name(&self) -> &str {
        "narrow-waist-bypass"
    }

    fn scan(&self, ctx: &ScanContext) -> Vec<ScanFinding> {
        let mut findings = Vec::new();
        let js_ext_re = Regex::new(r"\.(js|ts|jsx|tsx|mjs|cjs)$").unwrap();
        let test_re = Regex::new(r"\.(test|spec)\.(ts|js)$").unwrap();

        let js_files: Vec<&String> = ctx
            .source_files
            .iter()
            .filter(|f| js_ext_re.is_match(f))
            .filter(|f| !test_re.is_match(f))
            .filter(|f| !f.contains("/test/") && !f.contains("/tests/"))
            .filter(|f| !f.contains("/fixtures/"))
            .filter(|f| !f.contains("orchestrator/"))
            .collect();

        let py_files: Vec<&String> = ctx
            .source_files
            .iter()
            .filter(|f| f.ends_with(".py"))
            .filter(|f| !f.contains("orchestrator/"))
            .filter(|f| !f.contains("/test/") && !f.contains("/tests/"))
            .collect();

        let js_patterns = js_bypass_patterns();
        let py_patterns_list = py_bypass_patterns();

        for rel_path in &js_files {
            let full_path = Path::new(&ctx.skill_path).join(rel_path);
            let content = match fs::read_to_string(&full_path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            for pattern in &js_patterns {
                for m in pattern.regex.find_iter(&content) {
                    let evidence = &m.as_str()[..m.as_str().len().min(80)];
                    findings.push(ScanFinding {
                        rule_id: pattern.rule_id.to_string(),
                        tier: Tier::Blocker,
                        severity: Severity::P0,
                        critical_tag: Some(CriticalTag::Security),
                        message: pattern.message.to_string(),
                        file: Some((*rel_path).clone()),
                        line: None,
                        column: None,
                        category: ThreatCategory::PrivilegeEscalation,
                        evidence: Some(evidence.to_string()),
                        recommendation: Some(pattern.recommendation.to_string()),
                        rule_origin: Some(RuleOrigin::Core),
                        ref_anchor: None,
                        merged_from: None,
                    });
                }
            }
        }

        for rel_path in &py_files {
            let full_path = Path::new(&ctx.skill_path).join(rel_path);
            let content = match fs::read_to_string(&full_path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            for pattern in &py_patterns_list {
                for m in pattern.regex.find_iter(&content) {
                    let evidence = &m.as_str()[..m.as_str().len().min(80)];
                    findings.push(ScanFinding {
                        rule_id: pattern.rule_id.to_string(),
                        tier: Tier::Blocker,
                        severity: Severity::P0,
                        critical_tag: Some(CriticalTag::Security),
                        message: pattern.message.to_string(),
                        file: Some((*rel_path).clone()),
                        line: None,
                        column: None,
                        category: ThreatCategory::PrivilegeEscalation,
                        evidence: Some(evidence.to_string()),
                        recommendation: Some(pattern.recommendation.to_string()),
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
