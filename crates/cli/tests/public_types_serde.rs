use std::path::PathBuf;

#[allow(dead_code)]
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

use skill_scanner_core::*;

#[test]
fn ac10_all_public_types_present_and_reexported() {
    // These must compile — if any type is missing, this test fails at compile time
    let _f: Finding;
    let _s: Severity;
    let _r: RuleId;
    let _o: RuleOrigin;
    let _l: Location;
    let _sr: ScanResult;
    let _ss: ScanStats;
}

#[test]
fn ac11_serde_round_trip_is_byte_stable() {
    let finding = Finding {
        rule_id: RuleId("R12-installer-type-blocked".to_string()),
        rule_origin: RuleOrigin::BuiltIn,
        severity: Severity::P0,
        message: "installer.type=direct-exec is blocked".to_string(),
        location: Location {
            path: PathBuf::from("manifest.json"),
            line: Some(5),
            column: Some(12),
        },
    };
    let json1 = serde_json::to_string(&finding).unwrap();
    let json2 = serde_json::to_string(&finding).unwrap();
    assert_eq!(json1, json2, "serde output must be byte-stable across runs");

    let decoded: Finding = serde_json::from_str(&json1).unwrap();
    assert_eq!(decoded, finding, "round-trip must be lossless");
}
