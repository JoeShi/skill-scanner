use skill_scanner_manifest::{validate_manifest_structure, InstallerConfig, SkillManifest};
use std::collections::HashMap;

fn full_valid_manifest() -> SkillManifest {
    SkillManifest {
        name: "foo".to_string(),
        version: "1.0.0".to_string(),
        description: Some("x".to_string()),
        main: Some("index.js".to_string()),
        author: Some("a".to_string()),
        license: Some("MIT".to_string()),
        capabilities: None,
        domains: None,
        fs_paths: None,
        dependencies: None,
        dev_dependencies: None,
        publisher: None,
        installer: None,
        env: None,
    }
}

// AC15: all required fields present → no errors
#[test]
fn ac15_valid_manifest_no_errors() {
    let errors = validate_manifest_structure(&full_valid_manifest());
    assert!(
        errors.is_empty(),
        "expected no errors for valid manifest, got: {:?}",
        errors
    );
}

// AC16: missing required fields → each one reported
#[test]
fn ac16_missing_required_fields_all_reported() {
    let m = SkillManifest {
        name: "foo".to_string(),
        version: "1.0.0".to_string(),
        description: None,
        main: None,
        author: None,
        license: None,
        capabilities: None,
        domains: None,
        fs_paths: None,
        dependencies: None,
        dev_dependencies: None,
        publisher: None,
        installer: None,
        env: None,
    };
    let errors = validate_manifest_structure(&m);
    assert!(
        errors.iter().any(|e| e.contains("description")),
        "expected missing-description error, got: {:?}",
        errors
    );
    assert!(
        errors.iter().any(|e| e.contains("main")),
        "expected missing-main error, got: {:?}",
        errors
    );
    assert!(
        errors.iter().any(|e| e.contains("author")),
        "expected missing-author error, got: {:?}",
        errors
    );
    assert!(
        errors.iter().any(|e| e.contains("license")),
        "expected missing-license error, got: {:?}",
        errors
    );
}

// AC17: invalid semver version → error
#[test]
fn ac17_invalid_semver_reported() {
    let m = SkillManifest {
        version: "not-semver".to_string(),
        ..full_valid_manifest()
    };
    let errors = validate_manifest_structure(&m);
    assert!(
        errors
            .iter()
            .any(|e| e.contains("semver") || e.contains("version") || e.contains("not-semver")),
        "expected semver error, got: {:?}",
        errors
    );
}

// AC18: valid installer + env → no errors from those fields
#[test]
fn ac18_valid_installer_and_env_no_extra_errors() {
    let mut env = HashMap::new();
    env.insert("PATH".to_string(), "/bad".to_string());
    let m = SkillManifest {
        installer: Some(InstallerConfig {
            r#type: Some("direct-exec".to_string()),
            command: None,
            script: None,
        }),
        env: Some(env),
        ..full_valid_manifest()
    };
    let errors = validate_manifest_structure(&m);
    // installer.type as string is valid; env as HashMap<String,String> is valid
    // Only required-field or semver errors are allowed; no installer/env shape errors
    assert!(
        !errors
            .iter()
            .any(|e| e.contains("installer") || e.contains("env")),
        "unexpected installer/env errors: {:?}",
        errors
    );
}
