use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

use regex::Regex;

use crate::types::{
    CriticalTag, RuleOrigin, ScanContext, ScanFinding, ScannerModule, Severity, ThreatCategory,
    Tier,
};

fn js_network_patterns() -> Vec<Regex> {
    vec![
        Regex::new(r#"fetch\s*\(\s*['"`]([^'"`]+)['"`]"#).unwrap(),
        Regex::new(r#"axios\.[a-z]+\s*\(\s*['"`]([^'"`]+)['"`]"#).unwrap(),
        Regex::new(r#"http\.request\s*\(\s*['"`]([^'"`]+)['"`]"#).unwrap(),
        Regex::new(r#"https?\.get\s*\(\s*['"`]([^'"`]+)['"`]"#).unwrap(),
        Regex::new(r#"new\s+URL\s*\(\s*['"`]([^'"`]+)['"`]"#).unwrap(),
        Regex::new(r#"WebSocket\s*\(\s*['"`]([^'"`]+)['"`]"#).unwrap(),
    ]
}

fn py_network_patterns() -> Vec<Regex> {
    vec![
        Regex::new(r#"requests\.[a-z]+\s*\(\s*['"`]([^'"`]+)['"`]"#).unwrap(),
        Regex::new(r#"urllib\.request\.urlopen\s*\(\s*['"`]([^'"`]+)['"`]"#).unwrap(),
        Regex::new(r#"httpx\.[a-z]+\s*\(\s*['"`]([^'"`]+)['"`]"#).unwrap(),
    ]
}

fn extract_host(url_str: &str) -> Option<String> {
    let url_with_scheme = if !url_str.contains("://") && !url_str.starts_with("//") {
        format!("http://{}", url_str)
    } else {
        url_str.to_string()
    };

    // Try URL parse
    if let Ok(url) = url::Url::parse(&url_with_scheme) {
        if let Some(host) = url.host_str() {
            return Some(host.to_string());
        }
    }

    // Fallback: try regex extraction
    let host_re =
        Regex::new(r"^([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)").unwrap();
    host_re.captures(url_str).map(|c| c[1].to_string())
}

fn extract_hosts_from_content(content: &str, patterns: &[Regex]) -> HashSet<String> {
    let mut hosts = HashSet::new();
    for pattern in patterns {
        for cap in pattern.captures_iter(content) {
            if let Some(url_match) = cap.get(1) {
                if let Some(host) = extract_host(url_match.as_str()) {
                    hosts.insert(host);
                }
            }
        }
    }
    hosts
}

pub struct NetworkDiffModule;

impl ScannerModule for NetworkDiffModule {
    fn name(&self) -> &str {
        "network-domain-diff"
    }

    fn scan(&self, ctx: &ScanContext) -> Vec<ScanFinding> {
        let mut findings = Vec::new();

        // Gather declared domains
        let declared_domains: HashSet<String> = ctx
            .manifest
            .domains
            .as_ref()
            .map(|d| d.iter().cloned().collect())
            .unwrap_or_default();

        // Also check capabilities.network.domains
        let capability_domains: HashSet<String> = ctx
            .manifest
            .capabilities
            .as_ref()
            .and_then(|c| c.get("network"))
            .and_then(|n| n.get("domains"))
            .and_then(|d| d.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        let all_declared: HashSet<String> = declared_domains
            .union(&capability_domains)
            .cloned()
            .collect();

        let js_patterns = js_network_patterns();
        let py_patterns = py_network_patterns();

        let code_ext_re = Regex::new(r"\.(js|ts|jsx|tsx|py|mjs|cjs)$").unwrap();
        let code_files: Vec<&String> = ctx
            .source_files
            .iter()
            .filter(|f| code_ext_re.is_match(f))
            .collect();

        let mut actual_hosts: HashSet<String> = HashSet::new();
        let mut host_to_files: HashMap<String, Vec<String>> = HashMap::new();

        for rel_path in &code_files {
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

            let hosts = extract_hosts_from_content(&content, patterns);
            for host in hosts {
                actual_hosts.insert(host.clone());
                host_to_files
                    .entry(host)
                    .or_default()
                    .push(rel_path.to_string());
            }
        }

        // R1: undeclared domains
        for host in &actual_hosts {
            if !all_declared.contains(host) {
                findings.push(ScanFinding {
                    rule_id: "R1-network-domain-diff".to_string(),
                    tier: Tier::Blocker,
                    severity: Severity::P0,
                    critical_tag: Some(CriticalTag::Security),
                    message: format!(
                        "Code accesses \"{}\" but it is not declared in manifest capabilities.network.domains",
                        host
                    ),
                    file: host_to_files.get(host).and_then(|v| v.first()).cloned(),
                    line: None,
                    column: None,
                    category: ThreatCategory::DataExfiltration,
                    evidence: host_to_files
                        .get(host)
                        .map(|v| format!("Found in: {}", v.join(", "))),
                    recommendation: Some(format!(
                        "Add \"{}\" to manifest.capabilities.network.domains or remove the network call",
                        host
                    )),
                    rule_origin: Some(RuleOrigin::Core),
                    ref_anchor: None,
                    merged_from: None,
                });
            }
        }

        // R9: declared but unused
        for declared in &all_declared {
            if !declared.is_empty() && !actual_hosts.contains(declared) {
                findings.push(ScanFinding {
                    rule_id: "R9-capability-overclaim".to_string(),
                    tier: Tier::Suggestion,
                    severity: Severity::P1,
                    critical_tag: Some(CriticalTag::Security),
                    message: format!(
                        "Domain \"{}\" declared in manifest but never used in code",
                        declared
                    ),
                    file: Some("manifest.json".to_string()),
                    line: None,
                    column: None,
                    category: ThreatCategory::PrivilegeEscalation,
                    evidence: None,
                    recommendation: Some(
                        "Remove unused domain declaration to follow least privilege".to_string(),
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
