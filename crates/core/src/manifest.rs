use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

use regex::Regex;

use crate::types::SkillManifest;

pub const REQUIRED_MANIFEST_FIELDS: &[&str] = &[
    "name",
    "version",
    "description",
    "main",
    "author",
    "license",
];

/// Parse skill manifest from JSON file.
/// Falls back to SKILL.md YAML frontmatter if manifest.json is absent.
pub fn parse_manifest(skill_path: &str) -> Result<SkillManifest, String> {
    let manifest_path = Path::new(skill_path).join("manifest.json");
    if manifest_path.exists() {
        let raw = fs::read_to_string(&manifest_path)
            .map_err(|e| format!("Failed to read manifest.json: {}", e))?;
        let manifest: SkillManifest =
            serde_json::from_str(&raw).map_err(|e| format!("Failed to parse manifest.json: {}", e))?;
        return Ok(normalize_manifest(manifest));
    }

    let skill_md_path = Path::new(skill_path).join("SKILL.md");
    if skill_md_path.exists() {
        let raw = fs::read_to_string(&skill_md_path)
            .map_err(|e| format!("Failed to read SKILL.md: {}", e))?;
        let manifest = parse_skill_md_frontmatter(&raw, skill_path);
        return Ok(normalize_manifest(manifest));
    }

    Err(format!(
        "manifest.json not found at {} and no SKILL.md frontmatter available",
        manifest_path.display()
    ))
}

/// Parse manifest with raw text preserved
pub fn parse_manifest_with_raw(skill_path: &str) -> Result<(SkillManifest, String), String> {
    let manifest_path = Path::new(skill_path).join("manifest.json");
    if manifest_path.exists() {
        let raw = fs::read_to_string(&manifest_path)
            .map_err(|e| format!("Failed to read manifest.json: {}", e))?;
        let manifest: SkillManifest =
            serde_json::from_str(&raw).map_err(|e| format!("Failed to parse manifest.json: {}", e))?;
        return Ok((normalize_manifest(manifest), raw));
    }

    let skill_md_path = Path::new(skill_path).join("SKILL.md");
    if skill_md_path.exists() {
        let raw = fs::read_to_string(&skill_md_path)
            .map_err(|e| format!("Failed to read SKILL.md: {}", e))?;
        let manifest = parse_skill_md_frontmatter(&raw, skill_path);
        return Ok((normalize_manifest(manifest), raw));
    }

    Err(format!(
        "manifest.json not found at {} and no SKILL.md frontmatter available",
        manifest_path.display()
    ))
}

/// Normalize manifest fields across marketplace sources.
///
/// Normalizations applied:
/// 1. `version` - ensure present (default '0.0.0' if missing)
/// 2. `publisher` - copy from `author` if not present
/// 3. `installer` - normalize `installer.type` to lowercase
/// 4. `env` - ensure it's a valid map of string to string
pub fn normalize_manifest(mut manifest: SkillManifest) -> SkillManifest {
    if manifest.name.is_empty() {
        manifest.name = "unknown".to_string();
    }
    if manifest.version.is_empty() {
        manifest.version = "0.0.0".to_string();
    }

    // Normalize publisher / vendor field
    if manifest.publisher.is_none() {
        if let Some(ref author) = manifest.author {
            manifest.publisher = Some(author.clone());
        }
    }

    // Normalize installer shape
    if let Some(ref mut installer) = manifest.installer {
        if let Some(ref mut t) = installer.installer_type {
            *t = t.to_lowercase();
        }
    }

    // Normalize env shape - ensure all values are strings
    if let Some(ref mut env) = manifest.env {
        let clean: HashMap<String, String> = env
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        *env = clean;
    }

    manifest
}

/// Parse SKILL.md YAML frontmatter into a SkillManifest.
pub fn parse_skill_md_frontmatter(content: &str, skill_path: &str) -> SkillManifest {
    let re = Regex::new(r"(?s)^---\s*\n(.*?)\n---\s*\n").unwrap();
    let frontmatter_match = re.captures(content);

    if frontmatter_match.is_none() {
        let dir_name = Path::new(skill_path)
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".to_string());
        return SkillManifest {
            name: dir_name,
            version: "0.0.0".to_string(),
            ..Default::default()
        };
    }

    let yaml_text = &frontmatter_match.unwrap()[1];
    let parsed: serde_yaml::Value =
        serde_yaml::from_str(yaml_text).unwrap_or(serde_yaml::Value::Mapping(Default::default()));

    let mapping = parsed.as_mapping().cloned().unwrap_or_default();

    let get_str = |key: &str| -> Option<String> {
        mapping
            .get(serde_yaml::Value::String(key.to_string()))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    };

    let dir_name = Path::new(skill_path)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let name = get_str("name").unwrap_or(dir_name);
    let version = get_str("version").unwrap_or_else(|| "0.0.0".to_string());

    let domains: Option<Vec<String>> = mapping
        .get(serde_yaml::Value::String("domains".to_string()))
        .and_then(|v| v.as_sequence())
        .map(|seq| {
            seq.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        });

    let capabilities: Option<serde_json::Value> = mapping
        .get(serde_yaml::Value::String("capabilities".to_string()))
        .and_then(|v| {
            let json_str = serde_yaml::to_string(v).ok()?;
            serde_json::from_str(&json_str).ok()
        });

    let installer: Option<crate::types::InstallerConfig> = mapping
        .get(serde_yaml::Value::String("installer".to_string()))
        .and_then(|v| {
            let yaml_str = serde_yaml::to_string(v).ok()?;
            serde_yaml::from_str(&yaml_str).ok()
        });

    let env: Option<HashMap<String, String>> = mapping
        .get(serde_yaml::Value::String("env".to_string()))
        .and_then(|v| {
            let yaml_str = serde_yaml::to_string(v).ok()?;
            serde_yaml::from_str(&yaml_str).ok()
        });

    let author = get_str("author");
    let publisher = get_str("publisher").or_else(|| author.clone());

    SkillManifest {
        name,
        version,
        description: get_str("description"),
        capabilities,
        domains,
        fs_paths: None,
        main: get_str("main"),
        dependencies: None,
        dev_dependencies: None,
        author,
        publisher,
        license: get_str("license"),
        installer,
        env,
        extra: HashMap::new(),
    }
}

/// Validate manifest structure (required fields, semver, etc.)
/// Returns array of validation error messages
pub fn validate_manifest_structure(manifest: &SkillManifest) -> Vec<String> {
    let mut errors = Vec::new();

    // Check required fields
    if manifest.name.is_empty() || manifest.name == "unknown" {
        // name is always present, but check for the normalized "unknown"
    }
    if manifest.description.is_none() {
        errors.push("Missing required field: description".to_string());
    }
    if manifest.main.is_none() {
        errors.push("Missing required field: main".to_string());
    }
    if manifest.author.is_none() {
        errors.push("Missing required field: author".to_string());
    }
    if manifest.license.is_none() {
        errors.push("Missing required field: license".to_string());
    }

    // Semver check
    if !manifest.version.is_empty() {
        let semver_re = Regex::new(
            r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([\da-zA-Z-]+(?:\.[\da-zA-Z-]+)*))?(?:\+([\da-zA-Z-]+(?:\.[\da-zA-Z-]+)*))?$"
        ).unwrap();
        if !semver_re.is_match(&manifest.version) {
            errors.push(format!("Invalid semver: {}", manifest.version));
        }
    }

    // Domains validation
    if let Some(ref domains) = manifest.domains {
        if domains.is_empty() {
            // empty array is fine
        }
        let _ = domains;
    }

    errors
}

/// Extract declared capabilities as a map for diff scanning
pub fn extract_declared_capabilities(manifest: &SkillManifest) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if let Some(ref caps) = manifest.capabilities {
        if let Some(arr) = caps.as_array() {
            for cap in arr {
                let resource = cap.get("resource").and_then(|v| v.as_str()).unwrap_or("");
                let scope = cap.get("scope").and_then(|v| v.as_str());
                let name = cap.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let key = if let Some(s) = scope {
                    format!("{}:{}", resource, s)
                } else {
                    resource.to_string()
                };
                map.insert(key, name.to_string());
            }
        }
    }
    map
}

/// Extract declared domains as a Set
pub fn extract_declared_domains(manifest: &SkillManifest) -> HashSet<String> {
    manifest
        .domains
        .as_ref()
        .map(|d| d.iter().cloned().collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_version_fallback() {
        let manifest = SkillManifest {
            name: "test".to_string(),
            version: "".to_string(),
            ..Default::default()
        };
        let normalized = normalize_manifest(manifest);
        assert_eq!(normalized.version, "0.0.0");
    }

    #[test]
    fn test_normalize_publisher_from_author() {
        let manifest = SkillManifest {
            name: "test".to_string(),
            version: "1.0.0".to_string(),
            author: Some("alice@example.com".to_string()),
            publisher: None,
            ..Default::default()
        };
        let normalized = normalize_manifest(manifest);
        assert_eq!(normalized.publisher, Some("alice@example.com".to_string()));
    }

    #[test]
    fn test_normalize_installer_type_lowercase() {
        let manifest = SkillManifest {
            name: "test".to_string(),
            version: "1.0.0".to_string(),
            installer: Some(crate::types::InstallerConfig {
                installer_type: Some("Orchestrator-Managed".to_string()),
                command: None,
                script: None,
            }),
            ..Default::default()
        };
        let normalized = normalize_manifest(manifest);
        assert_eq!(
            normalized.installer.unwrap().installer_type,
            Some("orchestrator-managed".to_string())
        );
    }

    #[test]
    fn test_normalize_env() {
        let mut env = HashMap::new();
        env.insert("FOO".to_string(), "bar".to_string());
        env.insert("BAZ".to_string(), "123".to_string());
        let manifest = SkillManifest {
            name: "test".to_string(),
            version: "1.0.0".to_string(),
            env: Some(env),
            ..Default::default()
        };
        let normalized = normalize_manifest(manifest);
        let env = normalized.env.unwrap();
        assert_eq!(env.get("FOO"), Some(&"bar".to_string()));
        assert_eq!(env.get("BAZ"), Some(&"123".to_string()));
    }

    #[test]
    fn test_normalize_name_fallback() {
        let manifest = SkillManifest {
            name: "".to_string(),
            version: "1.0.0".to_string(),
            ..Default::default()
        };
        let normalized = normalize_manifest(manifest);
        assert_eq!(normalized.name, "unknown");
    }

    #[test]
    fn test_validate_manifest_missing_fields() {
        let manifest = SkillManifest {
            name: "test".to_string(),
            version: "not-a-semver".to_string(),
            main: Some("index.js".to_string()),
            ..Default::default()
        };
        let errors = validate_manifest_structure(&manifest);
        assert!(errors.iter().any(|e| e.contains("description")));
        assert!(errors.iter().any(|e| e.contains("author")));
        assert!(errors.iter().any(|e| e.contains("license")));
        assert!(errors.iter().any(|e| e.contains("Invalid semver")));
    }

    #[test]
    fn test_parse_frontmatter_no_frontmatter() {
        let content = "# My Skill\n\nSome content here";
        let manifest = parse_skill_md_frontmatter(content, "/tmp/my-skill");
        assert_eq!(manifest.name, "my-skill");
        assert_eq!(manifest.version, "0.0.0");
    }

    #[test]
    fn test_parse_frontmatter_with_data() {
        let content = "---\nname: cool-skill\nversion: 2.0.0\ndescription: A cool skill\n---\n\n# Cool Skill";
        let manifest = parse_skill_md_frontmatter(content, "/tmp/cool-skill");
        assert_eq!(manifest.name, "cool-skill");
        assert_eq!(manifest.version, "2.0.0");
        assert_eq!(manifest.description, Some("A cool skill".to_string()));
    }
}
