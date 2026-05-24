//! skill-scanner-clawhub — ClawHub marketplace adapter

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ClawHubError {
    #[error("not implemented")]
    NotImplemented,
}

pub async fn fetch_skill(_slug: &str) -> Result<bytes::Bytes, ClawHubError> {
    Err(ClawHubError::NotImplemented)
}
