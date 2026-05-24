use skill_scanner_manifest::parse_skill_md_frontmatter;
use std::path::Path;

// AC10: parses full frontmatter — name, version, description, capabilities, domains, installer, env
#[test]
fn ac10_parses_full_frontmatter() {
    let md = "\
---
name: my-skill
version: 1.2.3
description: A test skill
capabilities:
  - resource: fs.read
    scope: /tmp
domains:
  - api.example.com
installer:
  type: orchestrator-managed
env:
  FOO: bar
---

# Skill
";
    let m = parse_skill_md_frontmatter(md, Path::new("/tmp/my-skill"));
    assert_eq!(m.name, "my-skill");
    assert_eq!(m.version, "1.2.3");
    assert_eq!(m.description.as_deref(), Some("A test skill"));

    let caps = m.capabilities.expect("capabilities must be present");
    assert_eq!(caps.len(), 1);
    assert_eq!(caps[0].resource, "fs.read");
    assert_eq!(caps[0].scope.as_deref(), Some("/tmp"));

    let domains = m.domains.expect("domains must be present");
    assert_eq!(domains, vec!["api.example.com"]);

    let installer = m.installer.expect("installer must be present");
    assert_eq!(installer.r#type.as_deref(), Some("orchestrator-managed"));

    let env = m.env.expect("env must be present");
    assert_eq!(env.get("FOO").map(|s| s.as_str()), Some("bar"));
}

// AC11: falls back to directory name when no frontmatter
#[test]
fn ac11_fallback_to_dir_name_no_frontmatter() {
    let m = parse_skill_md_frontmatter("# Just markdown", Path::new("/tmp/cool-skill"));
    assert_eq!(m.name, "cool-skill");
    assert_eq!(m.version, "0.0.0");
}

// AC12: falls back to directory name when frontmatter is empty/absent separator
#[test]
fn ac12_fallback_to_dir_name_empty_frontmatter() {
    let m = parse_skill_md_frontmatter("---\n---\n", Path::new("/tmp/cool-skill"));
    assert_eq!(m.name, "cool-skill");
    assert_eq!(m.version, "0.0.0");
}

// AC13: normalizes publisher from author during frontmatter parse
#[test]
fn ac13_publisher_from_author_in_frontmatter() {
    let md = "\
---
name: test
author: Alice
---
";
    let m = parse_skill_md_frontmatter(md, Path::new("/tmp/test"));
    assert_eq!(m.author.as_deref(), Some("Alice"));
    assert_eq!(m.publisher.as_deref(), Some("Alice"));
}

// AC14: explicit publisher in frontmatter overrides author
#[test]
fn ac14_explicit_publisher_wins_in_frontmatter() {
    let md = "\
---
name: test
author: Alice
publisher: Acme Corp
---
";
    let m = parse_skill_md_frontmatter(md, Path::new("/tmp/test"));
    assert_eq!(m.publisher.as_deref(), Some("Acme Corp"));
    assert_eq!(m.author.as_deref(), Some("Alice"));
}
