//! L2.1 — skillchk scan orchestration
//!
//! Orchestrates manifest discovery → builtin rules → custom rulesets → C3 merge → sort → render.

use serde::Serialize;
use skill_scanner_core::{Finding, Severity};
use skill_scanner_ruleset::{merge_findings, TrustPolicy};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct ScanArgs {
    pub skill_path: PathBuf,
    pub rulesets: Vec<PathBuf>,
    pub trust_policy: TrustPolicy,
    pub format: OutputFormat,
    pub color: ColorChoice,
    pub verbose: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Json,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ColorChoice {
    Always,
    Never,
    Auto,
}

#[derive(Debug, Serialize)]
pub struct ScanReport {
    pub version: String,
    pub skill_path: PathBuf,
    pub manifest_name: String,
    pub manifest_path: PathBuf,
    pub verdict: ScanVerdict,
    pub stats: ScanReportStats,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ScanVerdict {
    Pass,
    Fail,
}

#[derive(Debug, Serialize)]
pub struct ScanReportStats {
    pub files_scanned: u32,
    pub rules_evaluated: u32,
    pub p0: u32,
    pub p1: u32,
    pub p2: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("manifest not found at {path}")]
    ManifestNotFound { path: PathBuf },
    #[error("manifest parse error: {0}")]
    ManifestParse(skill_scanner_manifest::ManifestError),
    #[error("ruleset load error at {path}: {source}")]
    RulesetLoad {
        path: PathBuf,
        #[source]
        source: skill_scanner_ruleset::RulesetValidationError,
    },
    #[error("IO error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

impl ScanError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::ManifestNotFound { .. } => "SCAN_MANIFEST_NOT_FOUND",
            Self::ManifestParse(_) => "SCAN_MANIFEST_PARSE",
            Self::RulesetLoad { .. } => "SCAN_RULESET_LOAD",
            Self::Io { .. } => "SCAN_IO",
        }
    }
}

/// Orchestrate manifest discovery → builtin rules → custom rulesets → C3 merge → sort.
///
/// Manifest discovery order: SKILL.md preferred over manifest.json.
/// Sort order: severity desc (priority()) → path asc → line asc → col asc → message asc.
pub fn scan(args: ScanArgs) -> Result<ScanReport, ScanError> {
    let skill_path = &args.skill_path;

    // 1. Manifest discovery: SKILL.md > manifest.json
    let skill_md = skill_path.join("SKILL.md");
    let manifest_json = skill_path.join("manifest.json");

    let (manifest, manifest_path) = if skill_md.exists() {
        let content = std::fs::read_to_string(&skill_md).map_err(|e| ScanError::Io {
            path: skill_md.clone(),
            source: e,
        })?;
        let manifest = skill_scanner_manifest::parse_skill_md_frontmatter(&content, skill_path);
        (manifest, skill_md)
    } else if manifest_json.exists() {
        let content = std::fs::read_to_string(&manifest_json).map_err(|e| ScanError::Io {
            path: manifest_json.clone(),
            source: e,
        })?;
        let value: serde_json::Value = serde_json::from_str(&content).map_err(|e| {
            ScanError::ManifestParse(skill_scanner_manifest::ManifestError::Parse(e.to_string()))
        })?;
        let manifest = skill_scanner_manifest::normalize_manifest(value);
        (manifest, manifest_json)
    } else {
        return Err(ScanError::ManifestNotFound {
            path: skill_path.to_path_buf(),
        });
    };

    // 2. Evaluate builtin rules
    let mut findings = Vec::new();
    let rules = skill_scanner_rules::builtin_rules();
    for rule in &rules {
        findings.extend(rule.check(&manifest, &manifest_path));
    }

    // 3. Load custom rulesets (with trust policy)
    let mut rules_evaluated = rules.len() as u32;
    for ruleset_path in &args.rulesets {
        let yaml_bytes = std::fs::read(ruleset_path).map_err(|e| ScanError::Io {
            path: ruleset_path.clone(),
            source: e,
        })?;

        // Sidecar signature: <ruleset>.yml.sig (append .sig, do NOT replace extension)
        let mut sig_path_os = ruleset_path.as_os_str().to_os_string();
        sig_path_os.push(".sig");
        let sig_path = PathBuf::from(sig_path_os);

        let sig_bytes = if sig_path.exists() {
            Some(std::fs::read(&sig_path).map_err(|e| ScanError::Io {
                path: sig_path.clone(),
                source: e,
            })?)
        } else {
            None
        };

        // Verify signature if policy requires it
        skill_scanner_ruleset::verify_ruleset_signature(
            &yaml_bytes,
            sig_bytes.as_deref(),
            &args.trust_policy,
        )
        .map_err(|e| ScanError::RulesetLoad {
            path: ruleset_path.clone(),
            source: e,
        })?;

        // Load and validate ruleset (C1+C2+C5)
        let custom_rules = skill_scanner_ruleset::load_from_path(ruleset_path).map_err(|e| {
            ScanError::RulesetLoad {
                path: ruleset_path.clone(),
                source: e,
            }
        })?;
        rules_evaluated += custom_rules.len() as u32;
    }

    // 4. Merge findings (C3)
    findings = merge_findings(findings);

    // 5. Sort: severity desc → path asc → line asc → col asc → message asc
    findings.sort_by(|a, b| {
        let sev = b.severity.priority().cmp(&a.severity.priority());
        if sev != std::cmp::Ordering::Equal {
            return sev;
        }
        let path = a.location.path.cmp(&b.location.path);
        if path != std::cmp::Ordering::Equal {
            return path;
        }
        let line = a
            .location
            .line
            .unwrap_or(u32::MAX)
            .cmp(&b.location.line.unwrap_or(u32::MAX));
        if line != std::cmp::Ordering::Equal {
            return line;
        }
        let col = a
            .location
            .column
            .unwrap_or(u32::MAX)
            .cmp(&b.location.column.unwrap_or(u32::MAX));
        if col != std::cmp::Ordering::Equal {
            return col;
        }
        a.message.cmp(&b.message)
    });

    // 6. Compute stats and verdict
    let p0 = count_by_severity(&findings, Severity::P0);
    let p1 = count_by_severity(&findings, Severity::P1);
    let p2 = count_by_severity(&findings, Severity::P2);

    let verdict = if p0 > 0 {
        ScanVerdict::Fail
    } else {
        ScanVerdict::Pass
    };

    Ok(ScanReport {
        version: "0.2.0".to_string(),
        skill_path: skill_path.clone(),
        manifest_name: manifest.name.clone(),
        manifest_path,
        verdict,
        stats: ScanReportStats {
            files_scanned: 1,
            rules_evaluated,
            p0,
            p1,
            p2,
        },
        findings,
    })
}

fn count_by_severity(findings: &[Finding], sev: Severity) -> u32 {
    findings.iter().filter(|f| f.severity == sev).count() as u32
}

/// Pure renderer. Text uses ANSI color per ColorChoice; JSON is serde_json::to_string_pretty.
pub fn render(report: &ScanReport, format: OutputFormat, color: ColorChoice) -> String {
    match format {
        OutputFormat::Json => render_json(report),
        OutputFormat::Text => render_text(report, color),
    }
}

fn render_json(report: &ScanReport) -> String {
    serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".to_string())
}

fn render_text(report: &ScanReport, color: ColorChoice) -> String {
    use std::io::IsTerminal;
    let use_color = match color {
        ColorChoice::Always => true,
        ColorChoice::Never => false,
        ColorChoice::Auto => std::io::stdout().is_terminal(),
    };

    let mut lines = Vec::new();
    lines.push(format!(
        "skillchk {} — scanning '{}' at '{}'",
        report.version,
        report.manifest_name,
        report.manifest_path.display()
    ));
    lines.push(String::new());

    if report.findings.is_empty() {
        lines.push("No findings.".to_string());
    } else {
        lines.push(format!("{} finding(s):", report.findings.len()));
        lines.push(String::new());
        for finding in &report.findings {
            let sev_label = format!("[{:?}]", finding.severity);
            let sev_colored = if use_color {
                match finding.severity {
                    Severity::P0 => format!("\x1b[31m{}\x1b[0m", sev_label),
                    Severity::P1 => format!("\x1b[33m{}\x1b[0m", sev_label),
                    Severity::P2 => format!("\x1b[37m{}\x1b[0m", sev_label),
                }
            } else {
                sev_label
            };
            lines.push(format!("  {} {}", sev_colored, finding.rule_id.0));
            let loc = format_location(&finding.location);
            lines.push(format!("        {}", loc));
            lines.push(format!("        {}", finding.message));
        }
    }

    lines.push(String::new());
    lines.push(format!(
        "Severity: P0={}  P1={}  P2={}",
        report.stats.p0, report.stats.p1, report.stats.p2
    ));
    let verdict_str = match report.verdict {
        ScanVerdict::Pass => "PASS",
        ScanVerdict::Fail => "FAIL",
    };
    lines.push(format!("Verdict: {}", verdict_str));

    lines.join("\n")
}

fn format_location(loc: &skill_scanner_core::Location) -> String {
    let path = loc.path.display();
    match (loc.line, loc.column) {
        (Some(line), Some(col)) => format!("{}:{}:{}", path, line, col),
        (Some(line), None) => format!("{}:{}", path, line),
        (None, Some(col)) => format!("{}::: {}", path, col),
        (None, None) => format!("{}", path),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use skill_scanner_core::{Location, RuleId, RuleOrigin};

    fn finding(rule_id: &str, sev: Severity, msg: &str, path: &str) -> Finding {
        Finding {
            rule_id: RuleId(rule_id.to_string()),
            rule_origin: RuleOrigin::BuiltIn,
            severity: sev,
            message: msg.to_string(),
            location: Location {
                path: PathBuf::from(path),
                line: Some(1),
                column: None,
            },
        }
    }

    #[test]
    fn red_render_json_valid() {
        let report = ScanReport {
            version: "0.2.0".to_string(),
            skill_path: PathBuf::from("/tmp/skill"),
            manifest_name: "test".to_string(),
            manifest_path: PathBuf::from("/tmp/skill/SKILL.md"),
            verdict: ScanVerdict::Pass,
            stats: ScanReportStats {
                files_scanned: 1,
                rules_evaluated: 14,
                p0: 0,
                p1: 0,
                p2: 0,
            },
            findings: vec![],
        };
        let json = render(&report, OutputFormat::Json, ColorChoice::Never);
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("must be valid JSON");
        assert!(parsed.is_object());
    }

    #[test]
    fn red_render_text_never_no_ansi() {
        let report = ScanReport {
            version: "0.2.0".to_string(),
            skill_path: PathBuf::from("/tmp/skill"),
            manifest_name: "test".to_string(),
            manifest_path: PathBuf::from("/tmp/skill/SKILL.md"),
            verdict: ScanVerdict::Fail,
            stats: ScanReportStats {
                files_scanned: 1,
                rules_evaluated: 14,
                p0: 1,
                p1: 0,
                p2: 0,
            },
            findings: vec![finding("r1", Severity::P0, "msg", "a.rs")],
        };
        let text = render(&report, OutputFormat::Text, ColorChoice::Never);
        assert!(!text.contains("\x1b["), "Never must not contain ANSI codes");
    }

    #[test]
    fn red_render_text_always_has_ansi() {
        let report = ScanReport {
            version: "0.2.0".to_string(),
            skill_path: PathBuf::from("/tmp/skill"),
            manifest_name: "test".to_string(),
            manifest_path: PathBuf::from("/tmp/skill/SKILL.md"),
            verdict: ScanVerdict::Fail,
            stats: ScanReportStats {
                files_scanned: 1,
                rules_evaluated: 14,
                p0: 1,
                p1: 0,
                p2: 0,
            },
            findings: vec![finding("r1", Severity::P0, "msg", "a.rs")],
        };
        let text = render(&report, OutputFormat::Text, ColorChoice::Always);
        assert!(text.contains("\x1b["), "Always must contain ANSI codes");
    }

    #[test]
    fn red_render_empty_findings() {
        let report = ScanReport {
            version: "0.2.0".to_string(),
            skill_path: PathBuf::from("/tmp/skill"),
            manifest_name: "test".to_string(),
            manifest_path: PathBuf::from("/tmp/skill/SKILL.md"),
            verdict: ScanVerdict::Pass,
            stats: ScanReportStats {
                files_scanned: 1,
                rules_evaluated: 14,
                p0: 0,
                p1: 0,
                p2: 0,
            },
            findings: vec![],
        };
        let text = render(&report, OutputFormat::Text, ColorChoice::Never);
        assert!(text.contains("No findings."));
    }

    #[test]
    fn red_json_determinism() {
        let report = ScanReport {
            version: "0.2.0".to_string(),
            skill_path: PathBuf::from("/tmp/skill"),
            manifest_name: "test".to_string(),
            manifest_path: PathBuf::from("/tmp/skill/SKILL.md"),
            verdict: ScanVerdict::Pass,
            stats: ScanReportStats {
                files_scanned: 1,
                rules_evaluated: 14,
                p0: 0,
                p1: 0,
                p2: 0,
            },
            findings: vec![],
        };
        let j1 = render(&report, OutputFormat::Json, ColorChoice::Never);
        let j2 = render(&report, OutputFormat::Json, ColorChoice::Never);
        assert_eq!(j1, j2);
    }
}
