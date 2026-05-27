use assert_cmd::Command;
use predicates::prelude::*;

fn cmd() -> Command {
    Command::cargo_bin("skillchk").unwrap()
}

fn bad_skill_path() -> String {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    format!("{}/../../crates/core/tests/fixtures/bad-skill", manifest_dir)
}

fn clean_skill_path() -> String {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    format!(
        "{}/../../crates/core/tests/fixtures/clean-skill",
        manifest_dir
    )
}

#[test]
fn test_help_output() {
    cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Scan agent skills for security risks"))
        .stdout(predicate::str::contains("scan"))
        .stdout(predicate::str::contains("list-marketplaces"));
}

#[test]
fn test_scan_help() {
    cmd()
        .args(["scan", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--fail-on"))
        .stdout(predicate::str::contains("--format"))
        .stdout(predicate::str::contains("--force"))
        .stdout(predicate::str::contains("--keep-extracted"))
        .stdout(predicate::str::contains("--ruleset"))
        .stdout(predicate::str::contains("--ruleset-trust-policy"));
}

#[test]
fn test_scan_bad_skill_exits_with_1() {
    cmd()
        .args(["scan", &bad_skill_path()])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("P0"));
}

#[test]
fn test_scan_clean_skill_exits_with_0() {
    cmd()
        .args(["scan", &clean_skill_path()])
        .assert()
        .success();
}

#[test]
fn test_scan_clean_skill_fail_on_p1_exits_with_1() {
    cmd()
        .args(["scan", "--fail-on", "P1", &clean_skill_path()])
        .assert()
        .code(1);
}

#[test]
fn test_scan_fail_on_none_always_passes() {
    cmd()
        .args(["scan", "--fail-on", "none", &bad_skill_path()])
        .assert()
        .success();
}

#[test]
fn test_list_marketplaces() {
    cmd()
        .arg("list-marketplaces")
        .assert()
        .success()
        .stdout(predicate::str::contains("local"))
        .stdout(predicate::str::contains("skills.sh"))
        .stdout(predicate::str::contains("clawhub"));
}

#[test]
fn test_scan_json_format_produces_valid_json() {
    let output = cmd()
        .args(["scan", "--format", "json", &clean_skill_path()])
        .output()
        .expect("failed to run skillchk");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("output should be valid JSON");
    assert!(parsed.get("findings").is_some());
    assert!(parsed.get("skillName").is_some());
}

#[test]
fn test_scan_nonexistent_target_exits_with_2() {
    cmd()
        .args(["scan", "/nonexistent/path/to/skill"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("Cannot recognize marketplace source"));
}
