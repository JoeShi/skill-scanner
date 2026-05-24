use std::path::PathBuf;
use std::process::Command;

#[allow(dead_code)]
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn cargo(args: &[&str]) -> std::process::Output {
    Command::new("cargo")
        .current_dir(workspace_root())
        .args(args)
        .output()
        .expect("cargo must be available")
}

#[test]
fn ac3_build_workspace_exits_0() {
    let out = cargo(&["build", "--workspace"]);
    assert!(
        out.status.success(),
        "cargo build failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn ac4_test_workspace_exits_0() {
    // Use --no-run to avoid recursive test invocation
    let out = cargo(&["test", "--workspace", "--no-run"]);
    assert!(
        out.status.success(),
        "cargo test --no-run failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn ac5_clippy_workspace_exits_0() {
    let out = cargo(&[
        "clippy",
        "--workspace",
        "--all-targets",
        "--",
        "-D",
        "warnings",
    ]);
    assert!(
        out.status.success(),
        "cargo clippy failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn ac6_fmt_check_exits_0() {
    let out = cargo(&["fmt", "--all", "--", "--check"]);
    assert!(
        out.status.success(),
        "cargo fmt check failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn ac7_deny_check_exits_0() {
    // Use --disable-fetch and CARGO_NET_OFFLINE to avoid network hangs in CI/test envs
    let out = Command::new("cargo")
        .current_dir(workspace_root())
        .env("CARGO_NET_OFFLINE", "true")
        .args(["deny", "check", "--disable-fetch"])
        .output()
        .expect("cargo deny must be available");
    assert!(
        out.status.success(),
        "cargo deny check failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}
