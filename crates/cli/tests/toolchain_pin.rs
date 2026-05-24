use std::fs;
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

#[test]
fn ac15_rust_toolchain_pins_1_85() {
    let path = workspace_root().join("rust-toolchain.toml");
    let content = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {}", path.display(), e));
    assert!(
        content.contains("1.85"),
        "rust-toolchain.toml must pin 1.85"
    );
}
