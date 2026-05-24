// C3 — finding merge / dedup / severity policy (stub — to be implemented by KimiCoder or KimiDev)
use skill_scanner_core::Finding;

/// Merge a Vec<Finding> by collapsing exact-match duplicates and applying
/// the C3 severity-merge policy.
///
/// Dedup key: (rule_id, location.path, location.line, location.column, message)
/// Severity policy: most-severe wins per P0 > P1 > P2.
/// Order: output preserves FIRST occurrence position of each dedup key.
/// rule_origin on canonical finding = FIRST contributor's value.
pub fn merge_findings(_findings: Vec<Finding>) -> Vec<Finding> {
    todo!("C3 merge_findings: implement dedup + severity-merge policy")
}
