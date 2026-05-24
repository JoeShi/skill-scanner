//! skill-scanner-manifest — manifest parse and normalize

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct SkillManifest {
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub main: Option<String>,
    pub author: Option<String>,
    pub publisher: Option<String>,
    pub license: Option<String>,
    pub capabilities: Option<Vec<CapabilityDeclaration>>,
    pub domains: Option<Vec<String>>,
    pub fs_paths: Option<Vec<String>>,
    pub dependencies: Option<HashMap<String, String>>,
    pub dev_dependencies: Option<HashMap<String, String>>,
    pub installer: Option<InstallerConfig>,
    pub env: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct InstallerConfig {
    #[serde(rename = "type")]
    pub r#type: Option<String>,
    pub command: Option<String>,
    pub script: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct CapabilityDeclaration {
    pub resource: String,
    pub scope: Option<String>,
    pub name: Option<String>,
    pub reason: Option<String>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ManifestError {
    #[error("manifest not found")]
    NotFound,
    #[error("IO error: {0}")]
    Io(String),
    #[error("parse error: {0}")]
    Parse(String),
}

// ---------------------------------------------------------------------------
// normalize_manifest — AC1–AC9
// ---------------------------------------------------------------------------

pub fn normalize_manifest(value: serde_json::Value) -> SkillManifest {
    let mut manifest: SkillManifest = match serde_json::from_value(value.clone()) {
        Ok(m) => m,
        Err(_) => {
            // Fallback: try to build manually from the JSON map
            let map = match value.as_object() {
                Some(m) => m.clone(),
                None => {
                    return SkillManifest {
                        name: "unknown".to_string(),
                        version: "0.0.0".to_string(),
                        ..Default::default()
                    }
                }
            };
            SkillManifest {
                name: map
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string(),
                version: map
                    .get("version")
                    .and_then(|v| v.as_str())
                    .unwrap_or("0.0.0")
                    .to_string(),
                description: map
                    .get("description")
                    .and_then(|v| v.as_str())
                    .map(String::from),
                main: map.get("main").and_then(|v| v.as_str()).map(String::from),
                author: map.get("author").and_then(|v| v.as_str()).map(String::from),
                publisher: map
                    .get("publisher")
                    .and_then(|v| v.as_str())
                    .map(String::from),
                license: map
                    .get("license")
                    .and_then(|v| v.as_str())
                    .map(String::from),
                capabilities: None,
                domains: None,
                fs_paths: None,
                dependencies: None,
                dev_dependencies: None,
                installer: parse_installer_value(map.get("installer")),
                env: parse_env_value(map.get("env")),
            }
        }
    };

    // AC1: default version
    if manifest.version.is_empty() {
        manifest.version = "0.0.0".to_string();
    }

    // AC8: default name
    if manifest.name.is_empty() {
        manifest.name = "unknown".to_string();
    }

    // AC2: copy author to publisher when publisher absent
    if manifest.publisher.is_none() && manifest.author.is_some() {
        manifest.publisher = manifest.author.clone();
    }

    // AC4: lowercase installer.type
    if let Some(ref mut installer) = manifest.installer {
        if let Some(ref mut t) = installer.r#type {
            *t = t.to_lowercase();
        }
    }

    // AC6: coerce env values to strings (handled in parse_env_value)
    // but ensure any existing env is stringified
    if let Some(ref mut env) = manifest.env {
        for _v in env.values_mut() {
            // already strings from our parsing
        }
    }

    manifest
}

fn parse_installer_value(value: Option<&serde_json::Value>) -> Option<InstallerConfig> {
    let obj = value?.as_object()?;
    Some(InstallerConfig {
        r#type: obj.get("type").and_then(|v| v.as_str()).map(String::from),
        command: obj
            .get("command")
            .and_then(|v| v.as_str())
            .map(String::from),
        script: obj.get("script").and_then(|v| v.as_str()).map(String::from),
    })
}

fn parse_env_value(value: Option<&serde_json::Value>) -> Option<HashMap<String, String>> {
    let obj = value?.as_object()?;
    let mut map = HashMap::new();
    for (k, v) in obj {
        let s = match v {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Number(n) => n.to_string(),
            serde_json::Value::Bool(b) => b.to_string(),
            _ => continue,
        };
        map.insert(k.clone(), s);
    }
    Some(map)
}

// ---------------------------------------------------------------------------
// parse_skill_md_frontmatter — AC10–AC14
// ---------------------------------------------------------------------------

pub fn parse_skill_md_frontmatter(content: &str, skill_path: &Path) -> SkillManifest {
    let dir_name = skill_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown")
        .to_string();

    // Extract YAML frontmatter between --- markers
    let trimmed = content.trim_start();
    let mut manifest = if let Some(after_open) = trimmed.strip_prefix("---") {
        if let Some(end) = after_open.find("---") {
            let yaml_block = &after_open[..end];
            let yaml_trimmed = yaml_block.trim();
            if yaml_trimmed.is_empty() {
                // Empty frontmatter
                SkillManifest {
                    name: dir_name.clone(),
                    version: "0.0.0".to_string(),
                    ..Default::default()
                }
            } else {
                match serde_yaml::from_str::<SkillManifest>(yaml_trimmed) {
                    Ok(mut m) => {
                        if m.name.is_empty() {
                            m.name = dir_name.clone();
                        }
                        if m.version.is_empty() {
                            m.version = "0.0.0".to_string();
                        }
                        // AC13: copy author to publisher
                        if m.publisher.is_none() && m.author.is_some() {
                            m.publisher = m.author.clone();
                        }
                        // lowercase installer.type
                        if let Some(ref mut installer) = m.installer {
                            if let Some(ref mut t) = installer.r#type {
                                *t = t.to_lowercase();
                            }
                        }
                        m
                    }
                    Err(_) => SkillManifest {
                        name: dir_name.clone(),
                        version: "0.0.0".to_string(),
                        ..Default::default()
                    },
                }
            }
        } else {
            SkillManifest {
                name: dir_name.clone(),
                version: "0.0.0".to_string(),
                ..Default::default()
            }
        }
    } else {
        SkillManifest {
            name: dir_name.clone(),
            version: "0.0.0".to_string(),
            ..Default::default()
        }
    };

    // Ensure name/version defaults
    if manifest.name.is_empty() {
        manifest.name = dir_name;
    }
    if manifest.version.is_empty() {
        manifest.version = "0.0.0".to_string();
    }

    manifest
}

// ---------------------------------------------------------------------------
// validate_manifest_structure — AC15–AC18
// ---------------------------------------------------------------------------

pub fn validate_manifest_structure(manifest: &SkillManifest) -> Vec<String> {
    let mut errors = Vec::new();

    if manifest.description.is_none() || manifest.description.as_ref().unwrap().is_empty() {
        errors.push("missing required field: description".to_string());
    }
    if manifest.main.is_none() || manifest.main.as_ref().unwrap().is_empty() {
        errors.push("missing required field: main".to_string());
    }
    if manifest.author.is_none() || manifest.author.as_ref().unwrap().is_empty() {
        errors.push("missing required field: author".to_string());
    }
    if manifest.license.is_none() || manifest.license.as_ref().unwrap().is_empty() {
        errors.push("missing required field: license".to_string());
    }

    // AC17: semver check
    if !manifest.version.is_empty() && !is_valid_semver(&manifest.version) {
        errors.push(format!("invalid semver version: {}", manifest.version));
    }

    errors
}

fn is_valid_semver(version: &str) -> bool {
    // Simple semver check: must have at least major.minor (digits.digits[.digits[-prerelease]])
    let parts: Vec<&str> = version.split('.').collect();
    if parts.len() < 2 {
        return false;
    }
    parts.iter().take(3).all(|p| {
        let num_part = p.split('-').next().unwrap_or(p);
        num_part.chars().all(|c| c.is_ascii_digit())
    })
}

// ---------------------------------------------------------------------------
// parse_manifest — AC19–AC23
// ---------------------------------------------------------------------------

pub fn parse_manifest(skill_path: &Path) -> Result<SkillManifest, ManifestError> {
    let manifest_json = skill_path.join("manifest.json");
    let skill_md = skill_path.join("SKILL.md");

    if manifest_json.exists() {
        let content = std::fs::read_to_string(&manifest_json)
            .map_err(|e| ManifestError::Io(e.to_string()))?;
        let value: serde_json::Value =
            serde_json::from_str(&content).map_err(|e| ManifestError::Parse(e.to_string()))?;
        Ok(normalize_manifest(value))
    } else if skill_md.exists() {
        let content =
            std::fs::read_to_string(&skill_md).map_err(|e| ManifestError::Io(e.to_string()))?;
        Ok(parse_skill_md_frontmatter(&content, skill_path))
    } else {
        Err(ManifestError::NotFound)
    }
}

// ---------------------------------------------------------------------------
// Default impls
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Self-discipline unit tests (Red → Green)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn red_normalize_missing_version() {
        let m = normalize_manifest(json!({ "name": "foo" }));
        assert_eq!(m.version, "0.0.0");
    }

    #[test]
    fn red_normalize_author_to_publisher() {
        let m = normalize_manifest(json!({ "name": "foo", "author": "Acme" }));
        assert_eq!(m.publisher, Some("Acme".to_string()));
    }

    #[test]
    fn red_normalize_explicit_publisher_wins() {
        let m = normalize_manifest(json!({
            "name": "foo",
            "author": "Alice",
            "publisher": "Acme"
        }));
        assert_eq!(m.publisher, Some("Acme".to_string()));
        assert_eq!(m.author, Some("Alice".to_string()));
    }

    #[test]
    fn red_normalize_installer_lowercase() {
        let m = normalize_manifest(json!({
            "name": "foo",
            "installer": { "type": "DIRECT-EXEC" }
        }));
        assert_eq!(m.installer.unwrap().r#type, Some("direct-exec".to_string()));
    }

    #[test]
    fn red_normalize_malformed_installer_dropped() {
        let m = normalize_manifest(json!({ "name": "foo", "installer": "bad" }));
        assert!(m.installer.is_none());
    }

    #[test]
    fn red_normalize_env_coerced() {
        let m = normalize_manifest(json!({
            "name": "foo",
            "env": { "PORT": 3000, "DEBUG": true }
        }));
        let env = m.env.unwrap();
        assert_eq!(env.get("PORT"), Some(&"3000".to_string()));
        assert_eq!(env.get("DEBUG"), Some(&"true".to_string()));
    }

    #[test]
    fn red_normalize_malformed_env_dropped() {
        let m = normalize_manifest(json!({ "name": "foo", "env": ["bad"] }));
        assert!(m.env.is_none());
    }

    #[test]
    fn red_normalize_unknown_name() {
        let m = normalize_manifest(json!({ "version": "1.0.0" }));
        assert_eq!(m.name, "unknown");
    }

    #[test]
    fn red_frontmatter_fallback_dir_name() {
        let m = parse_skill_md_frontmatter("# md", Path::new("/tmp/cool-skill"));
        assert_eq!(m.name, "cool-skill");
        assert_eq!(m.version, "0.0.0");
    }

    #[test]
    fn red_frontmatter_empty_fallback() {
        let m = parse_skill_md_frontmatter("---\n---\n", Path::new("/tmp/cool-skill"));
        assert_eq!(m.name, "cool-skill");
    }

    #[test]
    fn red_frontmatter_author_to_publisher() {
        let md = "---\nname: test\nauthor: Alice\n---\n";
        let m = parse_skill_md_frontmatter(md, Path::new("/tmp/test"));
        assert_eq!(m.publisher, Some("Alice".to_string()));
    }

    #[test]
    fn red_validate_required_fields() {
        let m = SkillManifest {
            name: "foo".to_string(),
            version: "1.0.0".to_string(),
            ..Default::default()
        };
        let errors = validate_manifest_structure(&m);
        assert!(errors.iter().any(|e| e.contains("description")));
        assert!(errors.iter().any(|e| e.contains("main")));
        assert!(errors.iter().any(|e| e.contains("author")));
        assert!(errors.iter().any(|e| e.contains("license")));
    }

    #[test]
    fn red_validate_semver() {
        let m = SkillManifest {
            name: "foo".to_string(),
            version: "not-semver".to_string(),
            description: Some("x".to_string()),
            main: Some("x".to_string()),
            author: Some("x".to_string()),
            license: Some("x".to_string()),
            ..Default::default()
        };
        let errors = validate_manifest_structure(&m);
        assert!(errors
            .iter()
            .any(|e| e.contains("semver") || e.contains("version")));
    }

    #[test]
    fn red_parse_manifest_not_found() {
        let tmp = std::env::temp_dir().join("nonexistent-dir-12345");
        let result = parse_manifest(&tmp);
        assert!(result.is_err());
    }
}
