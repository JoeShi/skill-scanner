use skill_scanner_manifest::parse_manifest;
use std::fs;

// AC19: parse_manifest reads manifest.json when present
#[test]
fn ac19_reads_manifest_json() {
    let dir = tempfile::tempdir().unwrap();
    let manifest_path = dir.path().join("manifest.json");
    let json = r#"{"name":"my-skill","version":"1.2.3","description":"A skill","main":"index.js","author":"Alice","license":"MIT"}"#;
    fs::write(&manifest_path, json).unwrap();

    let m = parse_manifest(dir.path()).expect("must succeed with manifest.json");
    assert_eq!(m.name, "my-skill");
    assert_eq!(m.version, "1.2.3");
}

// AC20: parse_manifest falls back to SKILL.md frontmatter when manifest.json absent
#[test]
fn ac20_falls_back_to_skill_md() {
    let dir = tempfile::tempdir().unwrap();
    let skill_md_path = dir.path().join("SKILL.md");
    let md = "\
---
name: from-skill-md
version: 2.0.0
description: A skill from SKILL.md
main: index.js
author: Bob
license: MIT
---
# Skill
";
    fs::write(&skill_md_path, md).unwrap();

    let m = parse_manifest(dir.path()).expect("must succeed with SKILL.md");
    assert_eq!(m.name, "from-skill-md");
    assert_eq!(m.version, "2.0.0");
}

// AC21: parse_manifest returns Err when neither manifest.json nor SKILL.md present
#[test]
fn ac21_error_when_no_manifest_found() {
    let dir = tempfile::tempdir().unwrap();
    let result = parse_manifest(dir.path());
    assert!(
        result.is_err(),
        "must return Err when neither manifest.json nor SKILL.md present"
    );
}

// AC22: parse_manifest normalizes manifest.json content (version default, publisher copy)
#[test]
fn ac22_manifest_json_normalized() {
    let dir = tempfile::tempdir().unwrap();
    let manifest_path = dir.path().join("manifest.json");
    // version absent, author present, publisher absent
    let json = r#"{"name":"foo","author":"Carol"}"#;
    fs::write(&manifest_path, json).unwrap();

    let m = parse_manifest(dir.path()).expect("must succeed");
    assert_eq!(m.version, "0.0.0", "version must default to 0.0.0");
    assert_eq!(m.publisher.as_deref(), Some("Carol"), "author must copy to publisher");
}

// AC23: parse_manifest normalizes SKILL.md content
#[test]
fn ac23_skill_md_normalized() {
    let dir = tempfile::tempdir().unwrap();
    let skill_md_path = dir.path().join("SKILL.md");
    let md = "\
---
name: test-skill
author: Dave
installer:
  type: UPPER-CASE
---
";
    fs::write(&skill_md_path, md).unwrap();

    let m = parse_manifest(dir.path()).expect("must succeed");
    assert_eq!(m.publisher.as_deref(), Some("Dave"), "author must copy to publisher");
    let installer = m.installer.expect("installer must be present");
    assert_eq!(installer.r#type.as_deref(), Some("upper-case"), "installer.type must be lowercased");
}
