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
fn ac16_no_package_json_at_root() {
    assert!(
        !workspace_root().join("package.json").exists(),
        "package.json must not exist at repo root"
    );
}

#[test]
fn ac16_no_node_modules() {
    assert!(
        !workspace_root().join("node_modules").exists(),
        "node_modules must not exist at repo root"
    );
}
