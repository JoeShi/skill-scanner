//! skill-scanner-manifest — manifest parse and normalize

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Manifest {
    pub name: String,
    pub version: String,
}

pub fn parse(_bytes: &[u8]) -> Result<Manifest, ManifestError> {
    Err(ManifestError::NotImplemented)
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ManifestError {
    #[error("not implemented")]
    NotImplemented,
}
