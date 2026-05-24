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
    // Read workspace defaults for value verification
    let ws_toml = fs::read_to_string(workspace_root().join("Cargo.toml")).unwrap();
    let ws_doc: toml::Table = ws_toml.parse().unwrap();
    let ws_pkg = ws_doc["workspace"]["package"].as_table().unwrap();
    let ws_version = ws_pkg["version"].as_str().unwrap();
    let ws_edition = ws_pkg["edition"].as_str().unwrap();
    let ws_rust_version = ws_pkg["rust-version"].as_str().unwrap();

    let crates = ["core", "rules", "ruleset", "manifest", "clawhub", "cli"];
    for c in &crates {
        let path = workspace_root().join(format!("crates/{}/Cargo.toml", c));
        let content = fs::read_to_string(&path).unwrap();
        let doc: toml::Table = content.parse().unwrap();
        let pkg = doc["package"].as_table().unwrap();

        // Verify key presence
        assert!(pkg.contains_key("version"), "{} missing version", c);
        assert!(pkg.contains_key("edition"), "{} missing edition", c);
        assert!(
            pkg.contains_key("rust-version"),
            "{} missing rust-version",
            c
        );

        // Verify resolved values match workspace defaults (inheritance)
        let _version = pkg["version"].as_str().unwrap_or(
            pkg["version"]
                .as_bool()
                .map(|_| "workspace")
                .unwrap_or("unknown"),
        );
        // When using workspace inheritance, the value may be a boolean true or the string "workspace"
        // toml crate parses "version.workspace = true" as a Table with "workspace" key = true
        let version_val = if let Some(v) = pkg["version"].as_str() {
            v.to_string()
        } else if pkg["version"]
            .as_table()
            .map(|t| t.contains_key("workspace"))
            .unwrap_or(false)
        {
            ws_version.to_string()
        } else {
            panic!("{} version is not a string or workspace inheritance", c)
        };

        let edition_val = if let Some(v) = pkg["edition"].as_str() {
            v.to_string()
        } else if pkg["edition"]
            .as_table()
            .map(|t| t.contains_key("workspace"))
            .unwrap_or(false)
        {
            ws_edition.to_string()
        } else {
            panic!("{} edition is not a string or workspace inheritance", c)
        };

        let rust_version_val = if let Some(v) = pkg["rust-version"].as_str() {
            v.to_string()
        } else if pkg["rust-version"]
            .as_table()
            .map(|t| t.contains_key("workspace"))
            .unwrap_or(false)
        {
            ws_rust_version.to_string()
        } else {
            panic!(
                "{} rust-version is not a string or workspace inheritance",
                c
            )
        };

        assert_eq!(
            version_val, ws_version,
            "{} version must match workspace default",
            c
        );
        assert_eq!(
            edition_val, ws_edition,
            "{} edition must match workspace default",
            c
        );
        assert_eq!(
            rust_version_val, ws_rust_version,
            "{} rust-version must match workspace default",
            c
        );
    }
}
