//! skill-scanner-core — public types and shared contracts

pub mod finding;
pub mod location;
pub mod rule;
pub mod scan;
pub mod severity;

pub use finding::Finding;
pub use location::Location;
pub use rule::{RuleId, RuleOrigin};
pub use scan::{ScanResult, ScanStats};
pub use severity::Severity;
