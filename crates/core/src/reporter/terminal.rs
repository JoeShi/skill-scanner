use crate::types::{Decision, ScanResult, Severity};

use super::Reporter;

pub struct TerminalReporter;

impl Reporter for TerminalReporter {
    fn name(&self) -> &str {
        "terminal"
    }

    fn render(&self, result: &ScanResult) -> String {
        let mut lines: Vec<String> = Vec::new();

        let (header_color, reset) = match result.decision {
            Decision::Blocked => ("\x1b[31m", "\x1b[0m"),
            Decision::RequiresUserConsent => ("\x1b[33m", "\x1b[0m"),
            Decision::Allowed => ("\x1b[32m", "\x1b[0m"),
        };

        let decision_upper = result.decision.as_str().to_uppercase();
        let skill_padded = format!("{:<45}", result.skill_name);
        let decision_padded = format!("{:<46}", decision_upper);

        lines.push(format!(
            "{}╔══════════════════════════════════════════════════════════════╗{}",
            header_color, reset
        ));
        lines.push(format!(
            "{}║  Skill Scan: {}║{}",
            header_color, skill_padded, reset
        ));
        lines.push(format!(
            "{}║  Decision:  {}║{}",
            header_color, decision_padded, reset
        ));
        lines.push(format!(
            "{}╚══════════════════════════════════════════════════════════════╝{}",
            header_color, reset
        ));
        lines.push(String::new());

        lines.push(format!("  P0 (Blocker):     {}", result.summary.p0));
        lines.push(format!("  P1 (Consent):     {}", result.summary.p1));
        lines.push(format!("  P2 (Suggestion):  {}", result.summary.p2));
        lines.push(format!("  Duration:         {}ms", result.duration_ms));
        lines.push(String::new());

        if !result.findings.is_empty() {
            let p0_findings: Vec<_> = result
                .findings
                .iter()
                .filter(|f| f.severity == Severity::P0)
                .collect();
            let p1_findings: Vec<_> = result
                .findings
                .iter()
                .filter(|f| f.severity == Severity::P1)
                .collect();

            if !p0_findings.is_empty() {
                lines.push("\x1b[31m  P0 BLOCKERS:\x1b[0m".to_string());
                for f in &p0_findings {
                    lines.push(format!("    {} {}: {}", "\u{274C}", f.rule_id, f.message));
                    if let Some(ref file) = f.file {
                        lines.push(format!("       File: {}", file));
                    }
                    if let Some(ref rec) = f.recommendation {
                        lines.push(format!("       -> {}", rec));
                    }
                }
                lines.push(String::new());
            }

            if !p1_findings.is_empty() {
                lines.push("\x1b[33m  P1 REQUIRES CONSENT:\x1b[0m".to_string());
                for f in &p1_findings {
                    lines.push(format!("    \u{26A0}\u{FE0F}  {}: {}", f.rule_id, f.message));
                }
                lines.push(String::new());
            }
        } else {
            lines.push(
                "\x1b[32m  \u{2705} No findings. Skill passed all checks.\x1b[0m".to_string(),
            );
            lines.push(String::new());
        }

        lines.join("\n")
    }
}
