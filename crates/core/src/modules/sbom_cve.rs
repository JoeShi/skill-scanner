use std::path::Path;
use std::process::Command;

use crate::types::{
    CriticalTag, RuleOrigin, ScanContext, ScanFinding, ScannerModule, Severity, ThreatCategory,
    Tier,
};

fn parse_npm_audit(output: &str) -> Vec<AuditAdvisory> {
    let data: serde_json::Value = match serde_json::from_str(output) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let mut advisories = Vec::new();
    if let Some(vulns) = data.get("vulnerabilities").and_then(|v| v.as_object()) {
        for (name, info) in vulns {
            let severity = info
                .get("severity")
                .and_then(|v| v.as_str())
                .unwrap_or("info")
                .to_string();
            let title = info
                .get("via")
                .and_then(|v| {
                    if let Some(arr) = v.as_array() {
                        arr.first()
                            .and_then(|item| item.get("title"))
                            .and_then(|t| t.as_str())
                            .map(|s| s.to_string())
                    } else {
                        v.as_str().map(|s| s.to_string())
                    }
                })
                .unwrap_or_else(|| "Unknown vulnerability".to_string());
            let range = info
                .get("range")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let fix_available = info
                .get("fixAvailable")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            advisories.push(AuditAdvisory {
                module_name: name.clone(),
                title,
                severity,
                vulnerable_versions: range,
                patched_versions: if fix_available {
                    "available".to_string()
                } else {
                    "none".to_string()
                },
            });
        }
    }

    advisories
}

struct AuditAdvisory {
    module_name: String,
    title: String,
    severity: String,
    vulnerable_versions: String,
    patched_versions: String,
}

fn cvss_from_severity(sev: &str) -> f64 {
    match sev.to_lowercase().as_str() {
        "critical" => 9.0,
        "high" => 7.5,
        "moderate" => 5.5,
        "low" => 3.0,
        _ => 0.0,
    }
}

fn severity_from_cvss(cvss: f64) -> Severity {
    if cvss >= 7.0 {
        Severity::P0
    } else if cvss >= 4.0 {
        Severity::P1
    } else {
        Severity::P2
    }
}

fn tier_from_cvss(cvss: f64) -> Tier {
    if cvss >= 7.0 {
        Tier::Blocker
    } else if cvss >= 4.0 {
        Tier::Suggestion
    } else {
        Tier::Nit
    }
}

pub struct SbomCveModule;

impl ScannerModule for SbomCveModule {
    fn name(&self) -> &str {
        "sbom-cve-scanner"
    }

    fn scan(&self, ctx: &ScanContext) -> Vec<ScanFinding> {
        let mut findings = Vec::new();
        let package_json_path = Path::new(&ctx.skill_path).join("package.json");

        if !package_json_path.exists() {
            return findings;
        }

        match run_npm_audit(&ctx.skill_path) {
            Ok(output) => {
                let advisories = parse_npm_audit(&output);
                for adv in advisories {
                    let cvss = cvss_from_severity(&adv.severity);
                    let sev = severity_from_cvss(cvss);
                    let tier = tier_from_cvss(cvss);

                    findings.push(ScanFinding {
                        rule_id: "R8-sbom-cve".to_string(),
                        tier,
                        severity: sev,
                        critical_tag: Some(CriticalTag::Security),
                        message: format!(
                            "{}: {} (severity: {})",
                            adv.module_name, adv.title, adv.severity
                        ),
                        file: Some("package.json".to_string()),
                        line: None,
                        column: None,
                        category: ThreatCategory::SupplyChainPoisoning,
                        evidence: Some(format!(
                            "Vulnerable versions: {}; Patched: {}",
                            adv.vulnerable_versions, adv.patched_versions
                        )),
                        recommendation: Some(if adv.patched_versions == "available" {
                            format!(
                                "Run npm audit fix or upgrade {}",
                                adv.module_name
                            )
                        } else {
                            format!(
                                "Monitor for patch availability; consider removing {}",
                                adv.module_name
                            )
                        }),
                        rule_origin: Some(RuleOrigin::Core),
                        ref_anchor: None,
                        merged_from: None,
                    });
                }
            }
            Err(err) => {
                findings.push(ScanFinding {
                    rule_id: "R8-engine-error".to_string(),
                    tier: Tier::Suggestion,
                    severity: Severity::P1,
                    critical_tag: Some(CriticalTag::Security),
                    message: format!("npm audit failed: {}", err),
                    file: Some("package.json".to_string()),
                    line: None,
                    column: None,
                    category: ThreatCategory::SupplyChainPoisoning,
                    evidence: Some(err.to_string()),
                    recommendation: Some(
                        "Ensure Node.js and npm are available in PATH".to_string(),
                    ),
                    rule_origin: Some(RuleOrigin::Core),
                    ref_anchor: None,
                    merged_from: None,
                });
            }
        }

        findings
    }
}

fn run_npm_audit(skill_path: &str) -> Result<String, String> {
    let output = Command::new("npm")
        .args(["audit", "--json"])
        .current_dir(skill_path)
        .output()
        .map_err(|e| format!("Failed to run npm audit: {}", e))?;

    // npm audit exits 1 when vulnerabilities found, 0 when clean
    if output.status.code() == Some(0) || output.status.code() == Some(1) {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!(
            "npm audit exited {}: {}",
            output.status.code().unwrap_or(-1),
            stderr
        ))
    }
}
