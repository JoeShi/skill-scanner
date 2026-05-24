use serde_json::json;
use skill_scanner_manifest::normalize_manifest;

// AC1: fills missing version with "0.0.0"
#[test]
fn ac1_fills_missing_version() {
    let m = normalize_manifest(json!({ "name": "foo" }));
    assert_eq!(m.version, "0.0.0");
    assert_eq!(m.name, "foo");
}

// AC2: copies author to publisher when publisher absent
#[test]
fn ac2_copies_author_to_publisher() {
    let m = normalize_manifest(json!({
        "name": "foo",
        "version": "1.0.0",
        "author": "Acme Corp"
    }));
    assert_eq!(m.publisher.as_deref(), Some("Acme Corp"));
    assert_eq!(m.author.as_deref(), Some("Acme Corp"));
}

// AC3: keeps explicit publisher over author
#[test]
fn ac3_keeps_explicit_publisher_over_author() {
    let m = normalize_manifest(json!({
        "name": "foo",
        "version": "1.0.0",
        "author": "Alice",
        "publisher": "Acme Corp"
    }));
    assert_eq!(m.publisher.as_deref(), Some("Acme Corp"));
}

// AC4: normalizes installer.type to lowercase
#[test]
fn ac4_lowercases_installer_type() {
    let m = normalize_manifest(json!({
        "name": "foo",
        "version": "1.0.0",
        "installer": { "type": "DIRECT-EXEC", "command": "./run.sh" }
    }));
    let installer = m.installer.expect("installer must be present");
    assert_eq!(installer.r#type.as_deref(), Some("direct-exec"));
}

// AC5: drops malformed installer (non-object)
#[test]
fn ac5_drops_malformed_installer() {
    let m = normalize_manifest(json!({
        "name": "foo",
        "version": "1.0.0",
        "installer": "bad"
    }));
    assert!(m.installer.is_none(), "malformed installer must be dropped");
}

// AC6: normalizes env values to strings (number/bool → string)
#[test]
fn ac6_coerces_env_values_to_strings() {
    let m = normalize_manifest(json!({
        "name": "foo",
        "version": "1.0.0",
        "env": { "PORT": 3000, "DEBUG": true }
    }));
    let env = m.env.expect("env must be present");
    assert_eq!(env.get("PORT").map(|s| s.as_str()), Some("3000"));
    assert_eq!(env.get("DEBUG").map(|s| s.as_str()), Some("true"));
}

// AC7: drops malformed env (array instead of object)
#[test]
fn ac7_drops_malformed_env_array() {
    let m = normalize_manifest(json!({
        "name": "foo",
        "version": "1.0.0",
        "env": ["bad"]
    }));
    assert!(m.env.is_none(), "malformed env (array) must be dropped");
}

// AC8: uses "unknown" for missing name; preserves present name
#[test]
fn ac8_uses_unknown_for_missing_name() {
    let m = normalize_manifest(json!({ "version": "1.0.0" }));
    assert_eq!(m.name, "unknown");
}

#[test]
fn ac8_preserves_present_name() {
    let m = normalize_manifest(json!({ "name": "my-skill", "version": "1.0.0" }));
    assert_eq!(m.name, "my-skill");
}

// AC9: installer fields preserved (type, command, script)
#[test]
fn ac9_installer_command_script_preserved() {
    let m = normalize_manifest(json!({
        "name": "foo",
        "version": "1.0.0",
        "installer": { "type": "orchestrator-managed", "command": "run.sh", "script": "setup.sh" }
    }));
    let installer = m.installer.expect("installer must be present");
    assert_eq!(installer.command.as_deref(), Some("run.sh"));
    assert_eq!(installer.script.as_deref(), Some("setup.sh"));
    assert_eq!(installer.r#type.as_deref(), Some("orchestrator-managed"));
}
