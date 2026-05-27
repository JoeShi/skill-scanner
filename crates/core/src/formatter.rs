use crate::types::{ScanFinding, ScanResult, Severity};

/// Format a single finding in the v0.1 review protocol format:
/// <tier> <severity> [critical:*] ref:skill-name#<rule-id>
pub fn format_finding(finding: &ScanFinding, skill_name: &str) -> String {
    let mut parts: Vec<String> = Vec::new();
    parts.push(finding.tier.as_str().to_string());
    parts.push(format!("{:?}", finding.severity));
    if let Some(ref tag) = finding.critical_tag {
        parts.push(tag.as_str().to_string());
    }
    parts.push(format!("ref:{}#{}", skill_name, finding.rule_id));

    let mut line = parts.join(" ");
    line.push_str(&format!(" -- {}", finding.message));
    if let Some(ref file) = finding.file {
        line.push_str(&format!(" ({}", file));
        if let Some(l) = finding.line {
            line.push_str(&format!(":{}", l));
        }
        line.push(')');
    }
    line
}

/// Format a complete scan report
pub fn format_report(result: &ScanResult) -> String {
    let mut lines: Vec<String> = Vec::new();
    lines.push(format!(
        "# Scan Report: {}@{}",
        result.skill_name, result.skill_version
    ));
    lines.push(format!(
        "Scanner: v{} | Duration: {}ms | At: {}",
        result.scanner_version, result.duration_ms, result.scanned_at
    ));
    lines.push(String::new());
    lines.push(format!(
        "## Summary: P0={} P1={} P2={}",
        result.summary.p0, result.summary.p1, result.summary.p2
    ));
    lines.push(String::new());

    if result.findings.is_empty() {
        lines.push("No findings".to_string());
        return lines.join("\n");
    }

    let severities = [Severity::P0, Severity::P1, Severity::P2];
    let labels = ["P0", "P1", "P2"];

    for (sev, label) in severities.iter().zip(labels.iter()) {
        let findings: Vec<_> = result.findings.iter().filter(|f| f.severity == *sev).collect();
        if findings.is_empty() {
            continue;
        }
        lines.push(format!("### {} ({})", label, findings.len()));
        for f in &findings {
            lines.push(format!("- {}", format_finding(f, &result.skill_name)));
            if let Some(ref evidence) = f.evidence {
                lines.push(format!("  Evidence: `{}`", evidence));
            }
            if let Some(ref rec) = f.recommendation {
                lines.push(format!("  Recommendation: {}", rec));
            }
        }
        lines.push(String::new());
    }

    lines.join("\n")
}

/// Check if scan result blocks installation (any P0 finding)
pub fn is_blocked(result: &ScanResult) -> bool {
    result.findings.iter().any(|f| f.severity == Severity::P0)
}

/// Check if scan result requires explicit user acceptance (P1 findings)
pub fn requires_acceptance(result: &ScanResult) -> bool {
    result.findings.iter().any(|f| f.severity == Severity::P1)
}
