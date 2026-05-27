pub mod terminal;
pub mod json;
pub mod markdown;
pub mod sarif;

use crate::types::ScanResult;

/// Reporter trait - all reporters implement this
pub trait Reporter {
    fn name(&self) -> &str;
    fn render(&self, result: &ScanResult) -> String;
}

/// Supported output formats
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReporterFormat {
    Terminal,
    Json,
    Markdown,
    Sarif,
}

/// Create a reporter for the given format
pub fn create_reporter(format: ReporterFormat) -> Box<dyn Reporter> {
    match format {
        ReporterFormat::Terminal => Box::new(terminal::TerminalReporter),
        ReporterFormat::Json => Box::new(json::JsonReporter),
        ReporterFormat::Markdown => Box::new(markdown::MarkdownReporter),
        ReporterFormat::Sarif => Box::new(sarif::SarifReporter),
    }
}
