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
fn ac1_workspace_lists_exactly_6_crates() {
    let cargo_toml = fs::read_to_string(workspace_root().join("Cargo.toml")).unwrap();
    let doc: toml::Table = cargo_toml.parse().unwrap();
    let members = doc["workspace"]["members"].as_array().unwrap();
    let expected = vec![
        "crates/core",
        "crates/rules",
        "crates/ruleset",
        "crates/manifest",
        "crates/clawhub",
        "crates/cli",
    ];
    let actual: Vec<String> = members
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(actual, expected, "workspace members must match spec §2.1");
}

#[test]
fn ac2_each_crate_has_version_edition_rust_version() {
    let crates = ["core", "rules", "ruleset", "manifest", "clawhub", "cli"];
    for c in &crates {
        let path = workspace_root().join(format!("crates/{}/Cargo.toml", c));
        let content = fs::read_to_string(&path).unwrap();
        let doc: toml::Table = content.parse().unwrap();
        let pkg = doc["package"].as_table().unwrap();
        println!("{} keys: {:?}", c, pkg.keys().collect::<Vec<_>>());
        assert!(pkg.contains_key("version"), "{} missing version", c);
        assert!(pkg.contains_key("edition"), "{} missing edition", c);
        assert!(
            pkg.contains_key("rust-version"),
            "{} missing rust-version",
            c
        );
    }
}
