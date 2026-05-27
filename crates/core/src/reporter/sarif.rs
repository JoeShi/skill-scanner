use std::collections::HashMap;

use serde_json::json;

use crate::types::{ScanResult, Severity};

use super::Reporter;

pub struct SarifReporter;

fn severity_to_level(severity: Severity) -> &'static str {
    match severity {
        Severity::P0 => "error",
        Severity::P1 => "warning",
        Severity::P2 => "note",
    }
}

fn to_sarif_name(rule_id: &str) -> String {
    rule_id
        .split('-')
        .map(|s| {
            let mut c = s.chars();
            match c.next() {
                None => String::new(),
                Some(first) => first.to_uppercase().to_string() + c.as_str(),
            }
        })
        .collect()
}

impl Reporter for SarifReporter {
    fn name(&self) -> &str {
        "sarif"
    }

    fn render(&self, result: &ScanResult) -> String {
        let mut rule_map: HashMap<String, usize> = HashMap::new();
        let mut rules: Vec<serde_json::Value> = Vec::new();

        for f in &result.findings {
            if !rule_map.contains_key(&f.rule_id) {
                rule_map.insert(f.rule_id.clone(), rules.len());
                rules.push(json!({
                    "id": f.rule_id,
                    "name": to_sarif_name(&f.rule_id),
                    "shortDescription": {"text": f.message},
                    "defaultConfiguration": {"level": severity_to_level(f.severity)},
                    "properties": {"tags": ["security", f.category.as_str()]}
                }));
            }
        }

        let results: Vec<serde_json::Value> = result
            .findings
            .iter()
            .map(|f| {
                let rule_index = rule_map.get(&f.rule_id).copied().unwrap_or(0);
                let message_text = match &f.recommendation {
                    Some(rec) => format!("{} -- {}", f.message, rec),
                    None => f.message.clone(),
                };

                let mut location = json!({
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f.file.as_deref().unwrap_or(""),
                            "uriBaseId": "%SRCROOT%"
                        }
                    }
                });

                if let Some(line) = f.line {
                    let mut region = json!({"startLine": line});
                    if let Some(col) = f.column {
                        region["startColumn"] = json!(col);
                    }
                    location["physicalLocation"]["region"] = region;
                }

                json!({
                    "ruleId": f.rule_id,
                    "ruleIndex": rule_index,
                    "level": severity_to_level(f.severity),
                    "message": {"text": message_text},
                    "locations": [location]
                })
            })
            .collect();

        let sarif = json!({
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "skill-scanner",
                        "version": result.scanner_version,
                        "informationUri": "https://github.com/JoeShi/skill-scanner",
                        "rules": rules
                    }
                },
                "results": results,
                "properties": {
                    "eventId": result.event_id,
                    "skillName": result.skill_name,
                    "skillVersion": result.skill_version,
                    "decision": result.decision.as_str(),
                    "scannedAt": result.scanned_at
                }
            }]
        });

        serde_json::to_string_pretty(&sarif)
            .unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e))
    }
}
