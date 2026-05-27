use crate::types::ScanResult;

use super::Reporter;

pub struct JsonReporter;

impl Reporter for JsonReporter {
    fn name(&self) -> &str {
        "json"
    }

    fn render(&self, result: &ScanResult) -> String {
        serde_json::to_string_pretty(result).unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e))
    }
}
