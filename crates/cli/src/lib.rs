// L2.1 — skillchk scan orchestration (stub — to be implemented by KimiCoder)

use serde::Serialize;
use skill_scanner_core::Finding;
use skill_scanner_ruleset::TrustPolicy;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct ScanArgs {
    pub skill_path: PathBuf,
    pub rulesets: Vec<PathBuf>,
    pub trust_policy: TrustPolicy,
    pub format: OutputFormat,
    pub color: ColorChoice,
    pub verbose: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Json,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ColorChoice {
    Always,
    Never,
    Auto,
}

#[derive(Debug, Serialize)]
pub struct ScanReport {
    pub version: String,
    pub skill_path: PathBuf,
    pub manifest_name: String,
    pub manifest_path: PathBuf,
    pub verdict: ScanVerdict,
    pub stats: ScanReportStats,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ScanVerdict {
    Pass,
    Fail,
}

#[derive(Debug, Serialize)]
pub struct ScanReportStats {
    pub files_scanned: u32,
    pub rules_evaluated: u32,
    pub p0: u32,
    pub p1: u32,
    pub p2: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("manifest not found at {path}")]
    ManifestNotFound { path: PathBuf },
    #[error("manifest parse error: {0}")]
    ManifestParse(skill_scanner_manifest::ManifestError),
    #[error("ruleset load error at {path}: {source}")]
    RulesetLoad {
        path: PathBuf,
        source: skill_scanner_ruleset::RulesetValidationError,
    },
    #[error("IO error at {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
}

impl ScanError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::ManifestNotFound { .. } => "SCAN_MANIFEST_NOT_FOUND",
            Self::ManifestParse(_) => "SCAN_MANIFEST_PARSE",
            Self::RulesetLoad { .. } => "SCAN_RULESET_LOAD",
            Self::Io { .. } => "SCAN_IO",
        }
    }
}

/// Orchestrate manifest discovery → builtin rules → custom rulesets → C3 merge → sort.
///
/// Manifest discovery order: SKILL.md preferred over manifest.json.
/// Sort order: severity desc (priority()) → path asc → line asc → col asc → message asc.
pub fn scan(_args: ScanArgs) -> Result<ScanReport, ScanError> {
    todo!("L2.1 scan: implement manifest discovery + rule evaluation + C3 merge + sort")
}

/// Pure renderer. Text uses ANSI color per ColorChoice; JSON is serde_json::to_string_pretty.
pub fn render(_report: &ScanReport, _format: OutputFormat, _color: ColorChoice) -> String {
    todo!("L2.1 render: implement text (ANSI color) and JSON output formats")
}
