//! Marketplace adapter types - abstracts fetching skills from different marketplaces

/// Options for fetching a skill
#[derive(Debug, Clone)]
pub struct FetchOptions {
    /// Cache directory
    pub cache_dir: Option<String>,
    /// TTL in hours (default: 24)
    pub cache_ttl_hours: Option<u64>,
    /// Force refetch even if cached
    pub force: bool,
}

impl Default for FetchOptions {
    fn default() -> Self {
        FetchOptions {
            cache_dir: None,
            cache_ttl_hours: Some(24),
            force: false,
        }
    }
}

/// A fetched skill package
#[derive(Debug, Clone)]
pub struct FetchedSkill {
    /// Local directory where skill is unpacked
    pub path: String,
    /// Marketplace source name
    pub source: String,
    /// Original URL/identifier
    pub url: String,
    /// Skill name from manifest or URL
    pub skill_name: String,
    /// When fetched (ISO timestamp)
    pub fetched_at: String,
    /// Whether this is a cached copy
    pub from_cache: bool,
}

/// Trait for marketplace source adapters
pub trait MarketplaceSource: Send + Sync {
    fn name(&self) -> &str;
    /// Recognizes if a URL or identifier belongs to this marketplace
    fn can_handle(&self, url: &str) -> bool;
    /// Fetch skill package to a local directory
    fn fetch(&self, url: &str, opts: &FetchOptions) -> Result<FetchedSkill, String>;
}

/// Registry of marketplace sources
pub trait MarketplaceRegistry {
    fn register(&mut self, source: Box<dyn MarketplaceSource>);
    fn find_source(&self, url: &str) -> Option<&dyn MarketplaceSource>;
    fn list_sources(&self) -> Vec<&str>;
}
