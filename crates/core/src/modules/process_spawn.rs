use std::fs;
use std::path::Path;

use regex::Regex;

use crate::types::{
    CriticalTag, RuleOrigin, ScanContext, ScanFinding, ScannerModule, Severity, ThreatCategory,
    Tier,
};

fn js_spawn_patterns() -> Vec<Regex> {
    vec![
        Regex::new(r"child_process\.(spawn|exec|execFile|fork)\s*\(").unwrap(),
        Regex::new(r#"require\(['"]child_process['"]\)\.(spawn|exec|execFile|fork)\s*\("#).unwrap(),
    ]
}

fn py_spawn_patterns() -> Vec<Regex> {
    vec![
        Regex::new(r"subprocess\.(run|Popen|call|check_call|check_output)\s*\(").unwrap(),
        Regex::new(r"os\.(system|popen|exec|execv|execve)\s*\(").unwrap(),
    ]
}

pub struct ProcessSpawnModule;

impl ScannerModule for ProcessSpawnModule {
    fn name(&self) -> &str {
        "process-spawn-diff"
    }

    fn scan(&self, ctx: &ScanContext) -> Vec<ScanFinding> {
        let mut findings = Vec::new();
        let code_ext_re = Regex::new(r"\.(js|ts|jsx|tsx|py|mjs|cjs)$").unwrap();
        let code_files: Vec<&String> = ctx
            .source_files
            .iter()
            .filter(|f| code_ext_re.is_match(f))
            .collect();

        let js_patterns = js_spawn_patterns();
        let py_patterns = py_spawn_patterns();

        for rel_path in code_files {
            let full_path = Path::new(&ctx.skill_path).join(rel_path);
            let content = match fs::read_to_string(&full_path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let is_python = rel_path.ends_with(".py");
            let patterns = if is_python {
                &py_patterns
            } else {
                &js_patterns
            };

            for pattern in patterns {
                for m in pattern.find_iter(&content) {
                    let byte_offset = m.start();
                    let line_number = content[..byte_offset].matches('\n').count() as u32 + 1;
                    findings.push(ScanFinding {
                        rule_id: "R3-process-spawn-diff".to_string(),
                        tier: Tier::Blocker,
                        severity: Severity::P0,
                        critical_tag: Some(CriticalTag::Security),
                        message: format!("Process spawn detected: {}", m.as_str().trim()),
                        file: Some(rel_path.clone()),
                        line: Some(line_number),
                        column: None,
                        category: ThreatCategory::MaliciousCode,
                        evidence: Some(m.as_str().trim().to_string()),
                        recommendation: Some(
                            "Declare in manifest.capabilities.process.spawn or remove; only the official orchestrator may spawn processes".to_string(),
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
