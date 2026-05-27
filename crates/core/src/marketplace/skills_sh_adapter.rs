use std::fs;
use std::path::Path;
use std::process::Command;

use regex::Regex;

use super::types::{FetchOptions, FetchedSkill, MarketplaceSource};

pub struct SkillsShAdapter;

impl MarketplaceSource for SkillsShAdapter {
    fn name(&self) -> &str {
        "skills.sh"
    }

    fn can_handle(&self, url: &str) -> bool {
        url.starts_with("https://skills.sh/")
            || url.starts_with("https://github.com/vercel-labs/skills")
            || url.starts_with("https://github.com/")
    }

    fn fetch(&self, url: &str, opts: &FetchOptions) -> Result<FetchedSkill, String> {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        let cache_dir = opts
            .cache_dir
            .clone()
            .unwrap_or_else(|| format!("{}/.cache/skill-scanner/skills-sh", home));
        let ttl_ms = opts.cache_ttl_hours.unwrap_or(24) * 60 * 60 * 1000;

        let github_url = normalize_to_github_url(url)?;
        let repo_name = extract_repo_name(&github_url);
        let dest_dir = format!("{}/{}", cache_dir, repo_name);
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
                                return Ok(build_fetched_skill(
                                    &dest_dir,
                                    url,
                                    &repo_name,
                                    true,
                                ));
                            }
                        }
                    }
                }
            }
        }

        // Fetch via git clone
        fs::create_dir_all(&dest_dir)
            .map_err(|e| format!("Failed to create directory: {}", e))?;

        let output = Command::new("git")
            .args(["clone", "--depth", "1", &github_url, &dest_dir])
            .output()
            .map_err(|e| format!("Failed to run git clone: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("git clone failed: {}", stderr));
        }

        // Write metadata
        let meta = serde_json::json!({
            "fetchedAt": chrono::Utc::now().to_rfc3339(),
            "url": github_url,
        });
        let _ = fs::write(&meta_path, serde_json::to_string_pretty(&meta).unwrap());

        Ok(build_fetched_skill(&dest_dir, url, &repo_name, false))
    }
}

fn normalize_to_github_url(url: &str) -> Result<String, String> {
    if url.starts_with("https://skills.sh/") {
        return Err(
            "skills.sh short URLs not yet supported. Please provide the full GitHub URL."
                .to_string(),
        );
    }
    Ok(url.to_string())
}

fn extract_repo_name(github_url: &str) -> String {
    let re = Regex::new(r"github\.com/([^/]+/[^/]+)").unwrap();
    re.captures(github_url)
        .map(|c| c[1].replace('/', "--"))
        .unwrap_or_else(|| "unknown".to_string())
}

fn build_fetched_skill(dest_dir: &str, url: &str, repo_name: &str, from_cache: bool) -> FetchedSkill {
    let mut skill_name = repo_name.to_string();
    let skill_md_path = format!("{}/SKILL.md", dest_dir);
    if Path::new(&skill_md_path).exists() {
        if let Ok(content) = fs::read_to_string(&skill_md_path) {
            let name_re = Regex::new(r"(?m)^name:\s*(.+)$").unwrap();
            if let Some(cap) = name_re.captures(&content) {
                skill_name = cap[1].trim().to_string();
            }
        }
    }

    FetchedSkill {
        path: dest_dir.to_string(),
        source: "skills.sh".to_string(),
        url: url.to_string(),
        skill_name,
        fetched_at: chrono::Utc::now().to_rfc3339(),
        from_cache,
    }
}
