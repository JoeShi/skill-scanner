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
fn ac17_lockfile_exists_and_resolves_under_msrv() {
    // AC17 proxy: Cargo.lock must exist and contain resolved packages.
    // Full verification (diff against cargo +1.86 generate-lockfile) is CI-only.
    let lock_path = workspace_root().join("Cargo.lock");
    assert!(lock_path.exists(), "Cargo.lock must exist");

    let content = fs::read_to_string(&lock_path)
        .unwrap_or_else(|e| panic!("failed to read Cargo.lock: {}", e));

    // Parse as TOML to verify structure
    let doc: toml::Table = content.parse().expect("Cargo.lock must be valid TOML");

    // Must have version = 4 (Cargo.lock format)
    let version = doc["version"]
        .as_integer()
        .expect("Cargo.lock must have version");
    assert_eq!(version, 4, "Cargo.lock format version must be 4");

    // Must have packages array
    let packages = doc["package"]
        .as_array()
        .expect("Cargo.lock must have [[package]] entries");
    assert!(
        !packages.is_empty(),
        "Cargo.lock must contain resolved packages"
    );

    // Must contain our workspace crates
    let workspace_crates = [
        "skill-scanner-core",
        "skill-scanner-rules",
        "skill-scanner-ruleset",
        "skill-scanner-manifest",
        "skill-scanner-clawhub",
        "skill-scanner-cli",
    ];
    for name in &workspace_crates {
        let found = packages.iter().any(|p| {
            p.as_table()
                .and_then(|t| t.get("name"))
                .and_then(|n| n.as_str())
                == Some(name)
        });
        assert!(found, "Cargo.lock must contain workspace crate {}", name);
    }
}
