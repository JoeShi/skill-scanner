use std::time::Instant;

#[test]
fn ac12_perf_100k_calls_under_100ms() {
    let r = skill_scanner_ruleset::semgrep::SemgrepRule {
        id: "r-perf".to_string(),
        message: "a".repeat(256),
        _rest: serde_yaml::Value::Null,
    };
    let start = Instant::now();
    for _ in 0..100_000 {
        let _ = skill_scanner_ruleset::reject_template_expansion(&r);
    }
    let elapsed = start.elapsed();
    let threshold_ms = if cfg!(debug_assertions) { 200 } else { 100 };
    assert!(
        elapsed.as_millis() < threshold_ms,
        "100K calls took {} ms, expected < {} ms",
        elapsed.as_millis(),
        threshold_ms
    );
}
