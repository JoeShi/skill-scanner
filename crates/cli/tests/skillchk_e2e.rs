use assert_cmd::Command;
use predicates::prelude::*;
use std::path::PathBuf;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn skillchk() -> Command {
    Command::cargo_bin("skillchk").expect("skillchk binary must be present")
}

// AC25: subprocess skillchk scan <clean> → exit 0
#[test]
fn ac25_clean_scan_exits_0() {
    skillchk()
        .arg("scan")
        .arg(fixture("clean"))
        .assert()
        .success()
        .code(0);
}

// AC26: subprocess skillchk scan <p0-fail> → exit 1
#[test]
fn ac26_p0_fail_exits_1() {
    skillchk()
        .arg("scan")
        .arg(fixture("missing-caps"))
        .assert()
        .failure()
        .code(1);
}

// AC27: subprocess skillchk scan <nonexistent> → exit 2, stderr non-empty
#[test]
fn ac27_nonexistent_exits_2_stderr_nonempty() {
    skillchk()
        .arg("scan")
        .arg("/nonexistent/absolute/path/that/cannot/exist/in/any/fs")
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::is_empty().not());
}

// AC28: skillchk --version → exit 0, stdout contains "0.2.0"
//       skillchk scan --help → exit 0, stdout contains "scan"
#[test]
fn ac28_version_and_help() {
    skillchk()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("0.2.0"));

    skillchk()
        .arg("scan")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("scan"));
}
