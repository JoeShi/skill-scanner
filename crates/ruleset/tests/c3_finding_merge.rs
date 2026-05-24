use skill_scanner_core::{Finding, Location, RuleId, RuleOrigin, Severity};
use skill_scanner_ruleset::merge_findings;
use std::path::PathBuf;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn loc(path: &str, line: Option<u32>, col: Option<u32>) -> Location {
    Location {
        path: PathBuf::from(path),
        line,
        column: col,
    }
}

fn finding(rule_id: &str, sev: Severity, msg: &str, path: &str) -> Finding {
    Finding {
        rule_id: RuleId(rule_id.to_string()),
        rule_origin: RuleOrigin::BuiltIn,
        severity: sev,
        message: msg.to_string(),
        location: loc(path, Some(1), None),
    }
}

fn finding_at(
    rule_id: &str,
    sev: Severity,
    msg: &str,
    path: &str,
    line: Option<u32>,
    col: Option<u32>,
) -> Finding {
    Finding {
        rule_id: RuleId(rule_id.to_string()),
        rule_origin: RuleOrigin::BuiltIn,
        severity: sev,
        message: msg.to_string(),
        location: loc(path, line, col),
    }
}

fn finding_with_origin(
    rule_id: &str,
    sev: Severity,
    msg: &str,
    path: &str,
    origin: RuleOrigin,
) -> Finding {
    Finding {
        rule_id: RuleId(rule_id.to_string()),
        rule_origin: origin,
        severity: sev,
        message: msg.to_string(),
        location: loc(path, Some(1), None),
    }
}

// AC1: empty input → empty output
#[test]
fn ac1_empty_input() {
    let result = merge_findings(vec![]);
    assert!(result.is_empty(), "merge of empty input must be empty");
}

// AC2: single finding → passthrough; output == input
#[test]
fn ac2_single_finding_passthrough() {
    let f = finding("r1", Severity::P0, "msg", "a.rs");
    let result = merge_findings(vec![f.clone()]);
    assert_eq!(
        result,
        vec![f],
        "single finding must pass through unchanged"
    );
}

// AC3: two distinct findings (different rule_id) → both preserved, original order
#[test]
fn ac3_two_distinct_preserved_in_order() {
    let f1 = finding("r1", Severity::P0, "msg", "a.rs");
    let f2 = finding("r2", Severity::P1, "msg", "a.rs");
    let result = merge_findings(vec![f1.clone(), f2.clone()]);
    assert_eq!(
        result.len(),
        2,
        "two distinct findings must both be preserved"
    );
    assert_eq!(result[0], f1, "first finding must be in position 0");
    assert_eq!(result[1], f2, "second finding must be in position 1");
}

// AC4: two byte-identical findings → single finding output
#[test]
fn ac4_identical_findings_deduped() {
    let f = finding("r1", Severity::P0, "msg", "a.rs");
    let result = merge_findings(vec![f.clone(), f.clone()]);
    assert_eq!(result.len(), 1, "identical findings must be deduped to one");
    assert_eq!(result[0], f);
}

// AC5: same dedup key, severities [P1, P0] → severity P0 (most severe wins)
#[test]
fn ac5_severity_merge_p1_then_p0() {
    let f1 = finding_at("r1", Severity::P1, "msg", "a.rs", Some(5), Some(3));
    let f2 = finding_at("r1", Severity::P0, "msg", "a.rs", Some(5), Some(3));
    let result = merge_findings(vec![f1, f2]);
    assert_eq!(result.len(), 1, "same dedup key must produce 1 finding");
    assert_eq!(
        result[0].severity,
        Severity::P0,
        "P0 must win over P1 when merging"
    );
}

// AC6: same dedup key, severities [P0, P1] → severity P0 (commutative)
#[test]
fn ac6_severity_merge_p0_then_p1_commutative() {
    let f1 = finding_at("r1", Severity::P0, "msg", "a.rs", Some(5), Some(3));
    let f2 = finding_at("r1", Severity::P1, "msg", "a.rs", Some(5), Some(3));
    let result = merge_findings(vec![f1, f2]);
    assert_eq!(result.len(), 1, "same dedup key must produce 1 finding");
    assert_eq!(
        result[0].severity,
        Severity::P0,
        "severity merge must be commutative: [P0,P1] == [P1,P0] == P0"
    );
}

// AC7: same dedup key, severities [P2, P1] → severity P1
#[test]
fn ac7_severity_merge_p2_then_p1() {
    let f1 = finding_at("r1", Severity::P2, "msg", "a.rs", Some(1), None);
    let f2 = finding_at("r1", Severity::P1, "msg", "a.rs", Some(1), None);
    let result = merge_findings(vec![f1, f2]);
    assert_eq!(result.len(), 1);
    assert_eq!(
        result[0].severity,
        Severity::P1,
        "P1 must win over P2 when merging"
    );
}

// AC8: same dedup key, severities [P2, P2] → severity P2
#[test]
fn ac8_severity_merge_same_severity() {
    let f1 = finding_at("r1", Severity::P2, "msg", "a.rs", Some(1), None);
    let f2 = finding_at("r1", Severity::P2, "msg", "a.rs", Some(1), None);
    let result = merge_findings(vec![f1, f2]);
    assert_eq!(result.len(), 1);
    assert_eq!(
        result[0].severity,
        Severity::P2,
        "equal severities must stay P2"
    );
}

// AC9: same dedup key, severities [P1, P0, P2] → severity P0 (associativity)
#[test]
fn ac9_severity_merge_associative_three_contributors() {
    let f1 = finding_at("r1", Severity::P1, "msg", "a.rs", Some(1), None);
    let f2 = finding_at("r1", Severity::P0, "msg", "a.rs", Some(1), None);
    let f3 = finding_at("r1", Severity::P2, "msg", "a.rs", Some(1), None);
    let result = merge_findings(vec![f1, f2, f3]);
    assert_eq!(result.len(), 1);
    assert_eq!(
        result[0].severity,
        Severity::P0,
        "P0 must win when merging [P1, P0, P2]"
    );
}

// AC10: order preservation — input [A, B, A] → output [A, B]
#[test]
fn ac10_order_first_occurrence_preserved() {
    let a = finding("r-alpha", Severity::P0, "finding-alpha", "file.rs");
    let b = finding("r-beta", Severity::P1, "finding-beta", "other.rs");
    let result = merge_findings(vec![a.clone(), b.clone(), a.clone()]);
    assert_eq!(result.len(), 2, "duplicate A must be removed");
    assert_eq!(
        result[0].rule_id, a.rule_id,
        "A must appear first (first occurrence)"
    );
    assert_eq!(
        result[1].rule_id, b.rule_id,
        "B must appear second (first occurrence)"
    );
}

// AC11: same rule_id + path, differing message → both preserved (message is part of dedup key)
#[test]
fn ac11_differing_message_not_deduped() {
    let f1 = finding("r1", Severity::P0, "message-alpha", "a.rs");
    let f2 = finding("r1", Severity::P0, "message-beta", "a.rs");
    let result = merge_findings(vec![f1, f2]);
    assert_eq!(
        result.len(),
        2,
        "different messages must not be deduped (message is part of dedup key)"
    );
}

// AC12: same rule_id + message, differing location.line → both preserved
#[test]
fn ac12_differing_line_not_deduped() {
    let f1 = finding_at("r1", Severity::P0, "msg", "a.rs", Some(1), None);
    let f2 = finding_at("r1", Severity::P0, "msg", "a.rs", Some(2), None);
    let result = merge_findings(vec![f1, f2]);
    assert_eq!(
        result.len(),
        2,
        "different location.line must not be deduped"
    );
}

// AC13: same rule_id + message, differing location.column → both preserved
#[test]
fn ac13_differing_column_not_deduped() {
    let f1 = finding_at("r1", Severity::P0, "msg", "a.rs", Some(1), Some(1));
    let f2 = finding_at("r1", Severity::P0, "msg", "a.rs", Some(1), Some(5));
    let result = merge_findings(vec![f1, f2]);
    assert_eq!(
        result.len(),
        2,
        "different location.column must not be deduped"
    );
}

// AC14: same dedup key, differing rule_origin → canonical finding has FIRST contributor's origin
#[test]
fn ac14_rule_origin_from_first_contributor() {
    let first_origin = RuleOrigin::BuiltIn;
    let second_origin = RuleOrigin::Custom {
        ruleset_id: "/tmp/custom.yml".to_string(),
    };
    let f1 = finding_with_origin("r1", Severity::P0, "msg", "a.rs", first_origin.clone());
    let f2 = finding_with_origin("r1", Severity::P0, "msg", "a.rs", second_origin);
    let result = merge_findings(vec![f1, f2]);
    assert_eq!(result.len(), 1);
    assert_eq!(
        result[0].rule_origin, first_origin,
        "canonical rule_origin must be FIRST contributor's value"
    );
}

// AC15: determinism — same input → byte-equal serde_json output across two calls
#[test]
fn ac15_determinism_serde_json() {
    let findings = vec![
        finding_at("r1", Severity::P0, "msg-a", "a.rs", Some(1), None),
        finding_at("r1", Severity::P1, "msg-a", "a.rs", Some(1), None),
        finding("r2", Severity::P2, "msg-b", "b.rs"),
    ];
    let r1 = merge_findings(findings.clone());
    let r2 = merge_findings(findings);
    let j1 = serde_json::to_string(&r1).unwrap();
    let j2 = serde_json::to_string(&r2).unwrap();
    assert_eq!(j1, j2, "merge_findings must be deterministic");
}

// AC16: no I/O in merge.rs source
#[test]
fn ac16_no_io_in_merge_source() {
    let merge_path = workspace_root()
        .join("crates")
        .join("ruleset")
        .join("src")
        .join("merge.rs");
    let src = std::fs::read_to_string(&merge_path)
        .unwrap_or_else(|e| panic!("failed to read merge.rs: {}", e));
    let forbidden = [
        "std::fs",
        "std::net",
        "std::process",
        "tokio::",
        "reqwest::",
    ];
    for pat in &forbidden {
        assert!(
            !src.contains(pat),
            "merge.rs must not contain '{}': found forbidden I/O pattern",
            pat
        );
    }
}

// AC17: re-export compiles — use skill_scanner_ruleset::merge_findings compiles
#[test]
fn ac17_reexport_compiles() {
    let _ = skill_scanner_ruleset::merge_findings;
}

// AC18: pure function — 100 calls with same input → byte-equal outputs
#[test]
fn ac18_pure_function_100_calls() {
    let findings = vec![
        finding_at("r1", Severity::P1, "msg", "a.rs", Some(1), None),
        finding_at("r1", Severity::P0, "msg", "a.rs", Some(1), None),
        finding("r2", Severity::P2, "other", "b.rs"),
    ];
    let first = serde_json::to_string(&merge_findings(findings.clone())).unwrap();
    for _ in 0..99 {
        let s = serde_json::to_string(&merge_findings(findings.clone())).unwrap();
        assert_eq!(
            s, first,
            "merge_findings must be pure: all 100 calls must be byte-equal"
        );
    }
}
