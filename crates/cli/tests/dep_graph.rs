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

fn read_manifest(name: &str) -> toml::Table {
    let path = workspace_root()
        .join("crates")
        .join(name)
        .join("Cargo.toml");
    let content = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {}", path.display(), e));
    content.parse().expect("valid toml")
}

fn dep_names(manifest: &toml::Table) -> Vec<String> {
    let deps = manifest
        .get("dependencies")
        .and_then(|d| d.as_table())
        .unwrap_or(&toml::map::Map::new())
        .clone();
    deps.keys().map(|k| k.to_string()).collect()
}

#[test]
fn ac12_core_has_zero_workspace_internal_deps() {
    let manifest = read_manifest("core");
    let deps = dep_names(&manifest);
    let workspace_internal = [
        "skill-scanner-core",
        "skill-scanner-rules",
        "skill-scanner-ruleset",
        "skill-scanner-manifest",
        "skill-scanner-clawhub",
        "skill-scanner-cli",
    ];
    for dep in &deps {
        assert!(
            !workspace_internal.contains(&dep.as_str()),
            "core must not depend on workspace crate {}",
            dep
        );
    }
}

#[test]
fn ac13_no_anyhow_in_lib_crates() {
    let lib_crates = ["core", "rules", "ruleset", "manifest", "clawhub"];
    for name in &lib_crates {
        let manifest = read_manifest(name);
        let deps = dep_names(&manifest);
        assert!(
            !deps.contains(&"anyhow".to_string()),
            "{} must not depend on anyhow",
            name
        );
    }
}

#[test]
fn ac14_only_clawhub_and_cli_use_reqwest_or_tokio() {
    let restricted = ["reqwest", "tokio"];
    let all_crates = ["core", "rules", "ruleset", "manifest", "clawhub", "cli"];
    for name in &all_crates {
        let manifest = read_manifest(name);
        let deps = dep_names(&manifest);
        for dep in &deps {
            if restricted.contains(&dep.as_str()) {
                assert!(
                    *name == "clawhub" || *name == "cli",
                    "{} must not depend on {}",
                    name,
                    dep
                );
            }
        }
    }
}
