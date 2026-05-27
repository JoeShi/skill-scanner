use std::fs;
use std::path::Path;

use regex::Regex;

use crate::types::{
    CriticalTag, RuleOrigin, ScanContext, ScanFinding, ScannerModule, Severity, ThreatCategory,
    Tier,
};

struct SecretPattern {
    regex: Regex,
    message: &'static str,
}

fn secret_patterns() -> Vec<SecretPattern> {
    vec![
        SecretPattern {
            regex: Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(),
            message: "Hardcoded AWS access key detected",
        },
        SecretPattern {
            regex: Regex::new(r"gh[pousr]_[A-Za-z0-9_]{36,}").unwrap(),
            message: "Hardcoded GitHub token detected",
        },
        SecretPattern {
            regex: Regex::new(r"-----BEGIN (?:RSA |OPENSSH |PGP |EC )?PRIVATE KEY-----").unwrap(),
            message: "Private key block detected",
        },
        SecretPattern {
            regex: Regex::new(r"xox[baprs]-[0-9a-zA-Z\-]+").unwrap(),
            message: "Hardcoded Slack token detected",
        },
        SecretPattern {
            regex: Regex::new(
                r#"(?i)(?:api[_\-]?key|apikey|api[_\-]?secret)["']?\s*[:=]\s*["']([a-zA-Z0-9_\-]{16,})["']"#,
            )
            .unwrap(),
            message: "Possible hardcoded API key detected",
        },
    ]
}

pub struct SecretsScanModule;

impl ScannerModule for SecretsScanModule {
    fn name(&self) -> &str {
        "secrets-scan"
    }

    fn scan(&self, ctx: &ScanContext) -> Vec<ScanFinding> {
        let mut findings = Vec::new();
        let code_ext_re =
            Regex::new(r"\.(js|ts|jsx|tsx|py|mjs|cjs|json|yaml|yml|md)$").unwrap();
        let code_files: Vec<&String> = ctx
            .source_files
            .iter()
            .filter(|f| code_ext_re.is_match(f))
            .collect();

        let patterns = secret_patterns();

        for rel_path in code_files {
            let full_path = Path::new(&ctx.skill_path).join(rel_path);
            let content = match fs::read_to_string(&full_path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            for pattern in &patterns {
                for m in pattern.regex.find_iter(&content) {
                    let matched = m.as_str();
                    let display = if matched.len() > 20 {
                        format!("{}...", &matched[..20])
                    } else {
                        matched.to_string()
                    };
                    findings.push(ScanFinding {
                        rule_id: "R6-secrets-scan".to_string(),
                        tier: Tier::Blocker,
                        severity: Severity::P0,
                        critical_tag: Some(CriticalTag::Security),
                        message: format!("{}: {}", pattern.message, display),
                        file: Some(rel_path.clone()),
                        line: None,
                        column: None,
                        category: ThreatCategory::MaliciousCode,
                        evidence: Some(matched[..matched.len().min(40)].to_string()),
                        recommendation: Some(
                            "Remove hardcoded secrets; use @quickport/orchestrator/credentials/* API"
                                .to_string(),
                        ),
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
