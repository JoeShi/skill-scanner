use std::fs;
use std::path::Path;

use regex::Regex;

use crate::types::{
    CriticalTag, RuleOrigin, ScanContext, ScanFinding, ScannerModule, Severity, ThreatCategory,
    Tier,
};

const SENSITIVE_PATHS: &[&str] = &[
    "~/.ssh",
    "~/.aws",
    "~/.gnupg",
    "~/.bashrc",
    "~/.zshrc",
    "/etc",
    "/usr/bin",
    "/usr/local/bin",
    "~/Library/LaunchAgents",
    "/etc/cron.d",
    "~/.quickwork/mcp_config.json",
];

fn fs_write_patterns() -> Vec<Regex> {
    vec![
        Regex::new(r#"fs\.writeFile\s*\(\s*['"`]([^'"`]+)['"`]"#).unwrap(),
        Regex::new(r#"fs\.writeFileSync\s*\(\s*['"`]([^'"`]+)['"`]"#).unwrap(),
        Regex::new(r#"fs\.appendFile\s*\(\s*['"`]([^'"`]+)['"`]"#).unwrap(),
        Regex::new(r#"fs\.appendFileSync\s*\(\s*['"`]([^'"`]+)['"`]"#).unwrap(),
        Regex::new(r#"fs\.open\s*\(\s*['"`]([^'"`]+)['"`]"#).unwrap(),
        Regex::new(r#"fs\.createWriteStream\s*\(\s*['"`]([^'"`]+)['"`]"#).unwrap(),
    ]
}

fn fs_read_patterns() -> Vec<Regex> {
    vec![
        Regex::new(r#"fs\.readFile\s*\(\s*['"`]([^'"`]+)['"`]"#).unwrap(),
        Regex::new(r#"fs\.readFileSync\s*\(\s*['"`]([^'"`]+)['"`]"#).unwrap(),
        Regex::new(r#"fs\.createReadStream\s*\(\s*['"`]([^'"`]+)['"`]"#).unwrap(),
    ]
}

fn is_sensitive_path(target_path: &str) -> bool {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let normalized = target_path.replace("~/", &format!("{}/", home));
    for sensitive in SENSITIVE_PATHS {
        let sens_norm = sensitive.replace("~/", &format!("{}/", home));
        if normalized.starts_with(&sens_norm) || normalized == sens_norm {
            return true;
        }
    }
    false
}

fn is_outside_skill_dir(target_path: &str, skill_name: &str) -> bool {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let normalized = target_path.replace("~/", &format!("{}/", home));
    let allowed_prefix = format!("{}/.quickwork/quickport/skills/{}", home, skill_name);
    !normalized.starts_with(&allowed_prefix)
}

struct PathMatch {
    path: String,
    line: u32,
}

fn extract_paths_from_content(content: &str, patterns: &[Regex]) -> Vec<PathMatch> {
    let mut results = Vec::new();
    for (i, line_content) in content.lines().enumerate() {
        for pattern in patterns {
            for cap in pattern.captures_iter(line_content) {
                if let Some(m) = cap.get(1) {
                    results.push(PathMatch {
                        path: m.as_str().to_string(),
                        line: (i + 1) as u32,
                    });
                }
            }
        }
    }
    results
}

pub struct FsDiffModule;

impl ScannerModule for FsDiffModule {
    fn name(&self) -> &str {
        "fs-path-diff"
    }

    fn scan(&self, ctx: &ScanContext) -> Vec<ScanFinding> {
        let mut findings = Vec::new();
        let code_ext_re = Regex::new(r"\.(js|ts|jsx|tsx|mjs|cjs)$").unwrap();
        let code_files: Vec<&String> = ctx
            .source_files
            .iter()
            .filter(|f| code_ext_re.is_match(f))
            .collect();

        let write_patterns = fs_write_patterns();
        let read_patterns = fs_read_patterns();

        for rel_path in code_files {
            let full_path = Path::new(&ctx.skill_path).join(rel_path);
            let content = match fs::read_to_string(&full_path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            // Check writes
            let writes = extract_paths_from_content(&content, &write_patterns);
            for w in &writes {
                if is_sensitive_path(&w.path) {
                    findings.push(ScanFinding {
                        rule_id: "R2-fs-write-sensitive".to_string(),
                        tier: Tier::Blocker,
                        severity: Severity::P0,
                        critical_tag: Some(CriticalTag::Security),
                        message: format!("Writing to sensitive path: {}", w.path),
                        file: Some(rel_path.clone()),
                        line: Some(w.line),
                        column: None,
                        category: ThreatCategory::PrivilegeEscalation,
                        evidence: Some(w.path.clone()),
                        recommendation: Some(format!(
                            "Avoid writing to {}. Use ~/.quickwork/quickport/skills/{}/ instead",
                            w.path, ctx.skill_name
                        )),
                        rule_origin: Some(RuleOrigin::Core),
                        ref_anchor: None,
                        merged_from: None,
                    });
                } else if is_outside_skill_dir(&w.path, &ctx.skill_name) {
                    findings.push(ScanFinding {
                        rule_id: "R2-fs-write-outside-skill-dir".to_string(),
                        tier: Tier::Blocker,
                        severity: Severity::P0,
                        critical_tag: Some(CriticalTag::Security),
                        message: format!("Writing outside skill directory: {}", w.path),
                        file: Some(rel_path.clone()),
                        line: Some(w.line),
                        column: None,
                        category: ThreatCategory::PrivilegeEscalation,
                        evidence: Some(w.path.clone()),
                        recommendation: Some(format!(
                            "Write to ~/.quickwork/quickport/skills/{}/ or declare in manifest.capabilities.fs.write",
                            ctx.skill_name
                        )),
                        rule_origin: Some(RuleOrigin::Core),
                        ref_anchor: None,
                        merged_from: None,
                    });
                }
            }

            // Check reads of sensitive paths
            let reads = extract_paths_from_content(&content, &read_patterns);
            for r in &reads {
                if is_sensitive_path(&r.path) {
                    findings.push(ScanFinding {
                        rule_id: "R2-fs-read-sensitive".to_string(),
                        tier: Tier::Blocker,
                        severity: Severity::P0,
                        critical_tag: Some(CriticalTag::Security),
                        message: format!("Reading sensitive path: {}", r.path),
                        file: Some(rel_path.clone()),
                        line: Some(r.line),
                        column: None,
                        category: ThreatCategory::PrivilegeEscalation,
                        evidence: Some(r.path.clone()),
                        recommendation: Some(format!(
                            "Avoid reading {} unless explicitly declared in manifest.capabilities.fs.read",
                            r.path
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
