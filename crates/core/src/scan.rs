use crate::Finding;

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ScanResult {
    pub findings: Vec<Finding>,
    pub stats: ScanStats,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ScanStats {
    pub files_scanned: u32,
    pub rules_evaluated: u32,
    pub duration_ms: u64,
}
