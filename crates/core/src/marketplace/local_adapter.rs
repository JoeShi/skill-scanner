use std::fs;
use std::path::Path;

use super::types::{FetchOptions, FetchedSkill, MarketplaceSource};

pub struct LocalDirectoryAdapter;

impl MarketplaceSource for LocalDirectoryAdapter {
    fn name(&self) -> &str {
        "local"
    }

    fn can_handle(&self, url: &str) -> bool {
        let resolved = Path::new(url);
        resolved.exists() && resolved.is_dir()
    }

    fn fetch(&self, url: &str, _opts: &FetchOptions) -> Result<FetchedSkill, String> {
        let resolved = fs::canonicalize(url)
            .map_err(|e| format!("Failed to resolve path: {}", e))?;
        let resolved_str = resolved.to_string_lossy().to_string();

        let manifest_path = resolved.join("manifest.json");
        let mut skill_name = resolved
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        if manifest_path.exists() {
            if let Ok(content) = fs::read_to_string(&manifest_path) {
                if let Ok(manifest) = serde_json::from_str::<serde_json::Value>(&content) {
                    if let Some(name) = manifest.get("name").and_then(|v| v.as_str()) {
                        skill_name = name.to_string();
                    }
                }
            }
        }

        Ok(FetchedSkill {
            path: resolved_str.clone(),
            source: "local".to_string(),
            url: resolved_str,
            skill_name,
            fetched_at: chrono::Utc::now().to_rfc3339(),
            from_cache: true,
        })
    }
}
