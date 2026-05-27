use std::fs;
use std::path::Path;

use regex::Regex;

use super::types::{FetchOptions, FetchedSkill, MarketplaceSource};

const CLAWHUB_API_BASE: &str = "https://clawdhub.com/api/v1";
const MAX_REDIRECTS: u32 = 5;

pub struct ClawHubAdapter;

impl MarketplaceSource for ClawHubAdapter {
    fn name(&self) -> &str {
        "clawhub"
    }

    fn can_handle(&self, url: &str) -> bool {
        url.starts_with("https://clawdhub.com/")
            || url.starts_with("https://clawdhub.ai/")
            || url.starts_with("https://github.com/openclaw/")
            || Regex::new(r"^[a-zA-Z0-9-]+$").unwrap().is_match(url)
    }

    fn fetch(&self, url: &str, opts: &FetchOptions) -> Result<FetchedSkill, String> {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        let cache_dir = opts
            .cache_dir
            .clone()
            .unwrap_or_else(|| format!("{}/.cache/skill-scanner/clawhub", home));
        let ttl_ms = opts.cache_ttl_hours.unwrap_or(24) * 60 * 60 * 1000;

        let slug = extract_slug(url);
        let dest_dir = format!("{}/{}", cache_dir, slug);
        let meta_path = format!("{}/.skill-scanner-meta.json", dest_dir);

        // Check cache
        if !opts.force && Path::new(&meta_path).exists() {
            if let Ok(content) = fs::read_to_string(&meta_path) {
                if let Ok(meta) = serde_json::from_str::<serde_json::Value>(&content) {
                    if let Some(fetched_at) = meta.get("fetchedAt").and_then(|v| v.as_str()) {
                        if let Ok(fetched_time) = chrono::DateTime::parse_from_rfc3339(fetched_at) {
                            let age =
                                chrono::Utc::now().signed_duration_since(fetched_time).num_milliseconds();
                            if (age as u64) < ttl_ms {
                                let skill_name = meta
                                    .get("skillName")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or(&slug)
                                    .to_string();
                                return Ok(FetchedSkill {
                                    path: dest_dir,
                                    source: "clawhub".to_string(),
                                    url: url.to_string(),
                                    skill_name,
                                    fetched_at: chrono::Utc::now().to_rfc3339(),
                                    from_cache: true,
                                });
                            }
                        }
                    }
                }
            }
        }

        // Fetch from ClawHub API
        fs::create_dir_all(&dest_dir)
            .map_err(|e| format!("Failed to create directory: {}", e))?;

        // 1. Get skill metadata
        let meta_url = format!("{}/skills/{}", CLAWHUB_API_BASE, slug);
        let skill_meta_str = http_get(&meta_url, 0)?;
        let skill_meta: serde_json::Value = serde_json::from_str(&skill_meta_str)
            .map_err(|_| format!("Invalid JSON from {}", meta_url))?;
        let skill_name = skill_meta
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or(&slug)
            .to_string();
        let version = skill_meta
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("latest")
            .to_string();

        // 2. Download skill files
        let file_url = format!("{}/skills/{}/file", CLAWHUB_API_BASE, slug);
        let file_data = http_get(&file_url, 0)?;
        if let Ok(files) = serde_json::from_str::<serde_json::Value>(&file_data) {
            if let Some(obj) = files.as_object() {
                for (file_path, content) in obj {
                    let full_path = format!("{}/{}", dest_dir, file_path);
                    if let Some(parent) = Path::new(&full_path).parent() {
                        let _ = fs::create_dir_all(parent);
                    }
                    if let Some(content_str) = content.as_str() {
                        let _ = fs::write(&full_path, content_str);
                    }
                }
            }
        } else {
            // If not JSON, write as single file
            let _ = fs::write(format!("{}/SKILL.md", dest_dir), &file_data);
        }

        // Write metadata
        let meta = serde_json::json!({
            "fetchedAt": chrono::Utc::now().to_rfc3339(),
            "url": url,
            "slug": slug,
            "version": version,
            "skillName": skill_name,
        });
        let _ = fs::write(&meta_path, serde_json::to_string_pretty(&meta).unwrap());

        Ok(FetchedSkill {
            path: dest_dir,
            source: "clawhub".to_string(),
            url: url.to_string(),
            skill_name,
            fetched_at: chrono::Utc::now().to_rfc3339(),
            from_cache: false,
        })
    }
}

fn extract_slug(url: &str) -> String {
    if url.starts_with("https://clawdhub.com/skills/") || url.starts_with("https://clawdhub.ai/skills/") {
        let re = Regex::new(r"/skills/([^/?]+)").unwrap();
        if let Some(cap) = re.captures(url) {
            return cap[1].to_string();
        }
    }
    if url.starts_with("https://github.com/openclaw/") {
        return url.split('/').next_back().unwrap_or(url).to_string();
    }
    // Assume it's already a slug
    url.to_string()
}

/// HTTP GET with redirect following (up to MAX_REDIRECTS)
fn http_get(url: &str, redirect_count: u32) -> Result<String, String> {
    if redirect_count > MAX_REDIRECTS {
        return Err(format!("Too many redirects (> {}) for {}", MAX_REDIRECTS, url));
    }

    // Use a simple blocking HTTP client via std::net
    // For production, reqwest would be used, but for the core library
    // we keep it simple with a basic implementation
    let _parsed = url::Url::parse(url).map_err(|e| format!("Invalid URL: {}", e))?;

    // For HTTPS, we need TLS. Since we don't have reqwest as a dep in core,
    // we'll use a simple approach that works for the adapter pattern.
    // In practice, the CLI crate would provide the HTTP implementation.
    // For now, return an error indicating network fetch is not available in core.
    Err(format!(
        "HTTP fetch not available in core library. Use CLI with reqwest for network operations. URL: {}",
        url
    ))
}
