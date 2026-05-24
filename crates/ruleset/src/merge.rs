//! C3 — finding merge / dedup / severity policy
//!
//! Dedup key: (rule_id, location.path, location.line, location.column, message)
//! Severity policy: most-severe wins per P0 > P1 > P2 (using `priority()`).
//! Order: output preserves FIRST occurrence position of each dedup key.
//! rule_origin on canonical finding = FIRST contributor's value.

use skill_scanner_core::Finding;
use std::collections::HashMap;

/// Merge a `Vec<Finding>` by collapsing exact-match duplicates and applying
/// the C3 severity-merge policy.
pub fn merge_findings(findings: Vec<Finding>) -> Vec<Finding> {
    let mut seen: HashMap<DedupKey, usize> = HashMap::new();
    let mut result: Vec<Finding> = Vec::new();

    for finding in findings {
        let key = DedupKey::from(&finding);
        if let Some(&idx) = seen.get(&key) {
            // Same dedup key seen before — keep the most severe
            if finding.severity.priority() > result[idx].severity.priority() {
                result[idx].severity = finding.severity;
            }
        } else {
            seen.insert(key, result.len());
            result.push(finding);
        }
    }

    result
}

/// The 5-tuple dedup key extracted from a `Finding`.
/// severity and rule_origin are intentionally excluded.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DedupKey {
    rule_id: String,
    path: std::path::PathBuf,
    line: Option<u32>,
    column: Option<u32>,
    message: String,
}

impl From<&Finding> for DedupKey {
    fn from(f: &Finding) -> Self {
        Self {
            rule_id: f.rule_id.0.clone(),
            path: f.location.path.clone(),
            line: f.location.line,
            column: f.location.column,
            message: f.message.clone(),
        }
    }
}
