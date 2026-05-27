use std::fs;
use std::path::Path;

use regex::Regex;

use crate::types::{
    CriticalTag, RuleOrigin, ScanContext, ScanFinding, ScannerModule, Severity, ThreatCategory,
    Tier,
};

struct DangerousApiPattern {
    regex: Regex,
    message: &'static str,
    rule_id: &'static str,
    category: ThreatCategory,
    recommendation: &'static str,
    severity: Severity,
    tier: Tier,
}

fn dangerous_patterns() -> Vec<DangerousApiPattern> {
    vec![
        DangerousApiPattern {
            regex: Regex::new(r"eval\s*\(").unwrap(),
            message: "eval() can execute arbitrary code",
            rule_id: "R7-eval-exec-inject",
            category: ThreatCategory::PrivilegeEscalation,
            recommendation: "Use JSON.parse for data or a proper sandbox like vm2 (still risky)",
            severity: Severity::P0,
            tier: Tier::Blocker,
        },
        DangerousApiPattern {
            regex: Regex::new(r"new\s+Function\s*\(").unwrap(),
            message: "Function() constructor compiles arbitrary JS",
            rule_id: "R7-eval-exec-inject",
            category: ThreatCategory::PrivilegeEscalation,
            recommendation: "Avoid dynamic code compilation; pre-compile known functions",
            severity: Severity::P0,
            tier: Tier::Blocker,
        },
        DangerousApiPattern {
            regex: Regex::new(r"vm\.runInThisContext\s*\(").unwrap(),
            message: "vm.runInThisContext() runs code in same context",
            rule_id: "R7-eval-exec-inject",
            category: ThreatCategory::PrivilegeEscalation,
            recommendation: "Use isolated-vm with restricted API surface",
            severity: Severity::P0,
            tier: Tier::Blocker,
        },
        DangerousApiPattern {
            regex: Regex::new(r"vm\.runInNewContext\s*\(").unwrap(),
            message: "vm.runInNewContext() with untrusted input",
            rule_id: "R7-eval-exec-inject",
            category: ThreatCategory::PrivilegeEscalation,
            recommendation: "Validate all inputs and use strict context options",
            severity: Severity::P0,
            tier: Tier::Blocker,
        },
        DangerousApiPattern {
            regex: Regex::new(r"exec(?:Sync|File)?\s*\(`[^`]*\$\{").unwrap(),
            message: "Shell command with template literal interpolation -- injection risk",
            rule_id: "R7-bis-shell-injection",
            category: ThreatCategory::PrivilegeEscalation,
            recommendation: "Use execFile with array arguments or sanitize with shell-quote",
            severity: Severity::P0,
            tier: Tier::Blocker,
        },
        DangerousApiPattern {
            regex: Regex::new(r"exec(?:Sync|File)?\s*\([^)]*\+\s*[^)]*\)").unwrap(),
            message: "Shell command with string concatenation -- injection risk",
            rule_id: "R7-bis-shell-injection",
            category: ThreatCategory::PrivilegeEscalation,
            recommendation: "Use execFile with array arguments or sanitize with shell-quote",
            severity: Severity::P0,
            tier: Tier::Blocker,
        },
        DangerousApiPattern {
            regex: Regex::new(r"exec(?:Sync)?\s*\(\$?[a-zA-Z_]\w*\s*\)").unwrap(),
            message: "Shell command with dynamic variable -- injection risk",
            rule_id: "R7-bis-shell-injection",
            category: ThreatCategory::PrivilegeEscalation,
            recommendation: "Use execFile with array arguments or sanitize with shell-quote",
            severity: Severity::P0,
            tier: Tier::Blocker,
        },
        DangerousApiPattern {
            regex: Regex::new(r"require\s*\(\$?[a-zA-Z_]\w*\s*\)").unwrap(),
            message: "Dynamic require() with variable -- arbitrary module loading risk",
            rule_id: "R7-dynamic-require",
            category: ThreatCategory::PrivilegeEscalation,
            recommendation: "Use static imports or a known-allowlist require wrapper",
            severity: Severity::P1,
            tier: Tier::Suggestion,
        },
    ]
}

pub struct DangerousApiModule;

impl ScannerModule for DangerousApiModule {
    fn name(&self) -> &str {
        "dangerous-api"
    }

    fn scan(&self, ctx: &ScanContext) -> Vec<ScanFinding> {
        let mut findings = Vec::new();
        let code_ext_re = Regex::new(r"\.(js|ts|jsx|tsx|mjs|cjs)$").unwrap();
        let test_re = Regex::new(r"\.(test|spec)\.(ts|js)$").unwrap();

        let source_files: Vec<&String> = ctx
            .source_files
            .iter()
            .filter(|f| code_ext_re.is_match(f))
            .filter(|f| !test_re.is_match(f))
            .filter(|f| !f.contains("/test/") && !f.contains("/tests/"))
            .filter(|f| !f.contains("/fixtures/"))
            .collect();

        let patterns = dangerous_patterns();

        for rel_path in source_files {
            let full_path = Path::new(&ctx.skill_path).join(rel_path);
            let content = match fs::read_to_string(&full_path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            for pattern in &patterns {
                for m in pattern.regex.find_iter(&content) {
                    let byte_offset = m.start();
                    let line_number = content[..byte_offset].matches('\n').count() as u32 + 1;
                    let evidence = &m.as_str()[..m.as_str().len().min(80)];
                    findings.push(ScanFinding {
                        rule_id: pattern.rule_id.to_string(),
                        tier: pattern.tier,
                        severity: pattern.severity,
                        critical_tag: Some(CriticalTag::Security),
                        message: pattern.message.to_string(),
                        file: Some(rel_path.clone()),
                        line: Some(line_number),
                        column: None,
                        category: pattern.category.clone(),
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
