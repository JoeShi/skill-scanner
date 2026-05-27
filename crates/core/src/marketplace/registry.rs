use super::types::{MarketplaceRegistry, MarketplaceSource};

pub struct DefaultMarketplaceRegistry {
    sources: Vec<Box<dyn MarketplaceSource>>,
}

impl DefaultMarketplaceRegistry {
    pub fn new() -> Self {
        DefaultMarketplaceRegistry {
            sources: Vec::new(),
        }
    }
}

impl Default for DefaultMarketplaceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl MarketplaceRegistry for DefaultMarketplaceRegistry {
    fn register(&mut self, source: Box<dyn MarketplaceSource>) {
        self.sources.push(source);
    }

    fn find_source(&self, url: &str) -> Option<&dyn MarketplaceSource> {
        self.sources
            .iter()
            .find(|s| s.can_handle(url))
            .map(|s| s.as_ref())
    }

    fn list_sources(&self) -> Vec<&str> {
        self.sources.iter().map(|s| s.name()).collect()
    }
}

/// Create a default registry (adapters registered by CLI main entry)
pub fn create_default_registry() -> DefaultMarketplaceRegistry {
    DefaultMarketplaceRegistry::new()
}
