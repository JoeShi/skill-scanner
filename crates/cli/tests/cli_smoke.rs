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

use std::process::Command;

fn skillchk(args: &[&str]) -> std::process::Output {
    Command::new("cargo")
        .args(["run", "-p", "skill-scanner-cli", "--"])
        .args(args)
        .output()
        .expect("cargo run must work")
}

#[test]
fn ac8_help_contains_skillchk() {
    let out = skillchk(&["--help"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("skillchk"), "help must contain 'skillchk'");
}

#[test]
fn ac9_version_contains_0_2_0() {
    let out = skillchk(&["--version"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("0.2.0"), "version must contain '0.2.0'");
}
