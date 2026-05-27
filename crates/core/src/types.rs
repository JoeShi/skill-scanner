use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Severity level: P0 (most severe, blocked), P1 (consent required), P2 (suggestion)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Severity {
    P0,
    P1,
    P2,
}

impl Severity {
    /// Returns numeric rank: lower = more severe
    pub fn rank(self) -> u8 {
        match self {
            Severity::P0 => 0,
            Severity::P1 => 1,
            Severity::P2 => 2,
        }
    }

    /// Pick the higher-severity (lower rank) of two severities
    pub fn max(self, other: Severity) -> Severity {
        if self.rank() <= other.rank() {
            self
        } else {
            other
        }
    }
}

/// Tier: blocker / suggestion / nit
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    Blocker,
    Suggestion,
    Nit,
}

impl Tier {
    pub fn for_severity(severity: Severity) -> Tier {
        match severity {
            Severity::P0 => Tier::Blocker,
            Severity::P1 => Tier::Suggestion,
            Severity::P2 => Tier::Nit,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Tier::Blocker => "blocker",
            Tier::Suggestion => "suggestion",
            Tier::Nit => "nit",
        }
    }
}

/// Critical tag for security/perf
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CriticalTag {
    #[serde(rename = "[critical:security]")]
    Security,
    #[serde(rename = "[critical:perf]")]
    Perf,
}

impl CriticalTag {
    pub fn as_str(&self) -> &'static str {
        match self {
            CriticalTag::Security => "[critical:security]",
            CriticalTag::Perf => "[critical:perf]",
        }
    }
}

/// Threat category
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ThreatCategory {
    MaliciousCode,
    DataExfiltration,
    PrivilegeEscalation,
    SupplyChainPoisoning,
}

impl ThreatCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            ThreatCategory::MaliciousCode => "malicious-code",
            ThreatCategory::DataExfiltration => "data-exfiltration",
            ThreatCategory::PrivilegeEscalation => "privilege-escalation",
            ThreatCategory::SupplyChainPoisoning => "supply-chain-poisoning",
        }
    }
}

/// Rule origin: 'core' for built-in rules, 'custom:<path>' for user-supplied
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RuleOrigin {
    Core,
    Custom(String),
}

impl RuleOrigin {
    pub fn core() -> Self {
        RuleOrigin::Core
    }

    pub fn custom(path: &str) -> Self {
        RuleOrigin::Custom(format!("custom:{}", path))
    }

    pub fn as_str(&self) -> &str {
        match self {
            RuleOrigin::Core => "core",
            RuleOrigin::Custom(s) => s,
        }
    }

    pub fn is_core(&self) -> bool {
        matches!(self, RuleOrigin::Core)
    }
}

impl std::fmt::Display for RuleOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A single finding produced by a scanner module
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanFinding {
    pub rule_id: String,
    pub tier: Tier,
    pub severity: Severity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub critical_tag: Option<CriticalTag>,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column: Option<u32>,
    pub category: ThreatCategory,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recommendation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_origin: Option<RuleOrigin>,
    #[serde(rename = "ref", skip_serializing_if = "Option::is_none")]
    pub ref_anchor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merged_from: Option<Vec<RuleOrigin>>,
}

/// Installer configuration (ClawHub frontmatter)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InstallerConfig {
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub installer_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub script: Option<String>,
}

/// Parsed skill manifest
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SkillManifest {
    pub name: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domains: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fs_paths: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub main: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dependencies: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dev_dependencies: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publisher: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub installer: Option<InstallerConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env: Option<HashMap<String, String>>,
    /// Raw extra fields for diff scanning
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// Declared capability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityDeclaration {
    pub name: String,
    pub resource: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Context passed to scanner modules
#[derive(Debug, Clone)]
pub struct ScanContext {
    pub skill_name: String,
    pub skill_path: String,
    pub manifest: SkillManifest,
    pub manifest_raw: String,
    pub source_files: Vec<String>,
    pub tmp_dir: Option<String>,
}

/// Install-pipeline decision
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Decision {
    Allowed,
    RequiresUserConsent,
    Blocked,
}

impl Decision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Decision::Allowed => "allowed",
            Decision::RequiresUserConsent => "requires-user-consent",
            Decision::Blocked => "blocked",
        }
    }
}

/// Confidence level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

/// Scan result
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanResult {
    pub event_id: String,
    pub skill_name: String,
    pub skill_version: String,
    pub ruleset_meta: Vec<RulesetMeta>,
    pub findings: Vec<ScanFinding>,
    pub summary: ScanSummary,
    pub duration_ms: u64,
    pub scanner_version: String,
    pub scanned_at: String,
    pub coverage: Vec<String>,
    pub confidence: Confidence,
    pub known_blind_spots: Vec<String>,
    pub decision: Decision,
}

/// Summary counts by severity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    #[serde(rename = "P0")]
    pub p0: usize,
    #[serde(rename = "P1")]
    pub p1: usize,
    #[serde(rename = "P2")]
    pub p2: usize,
}

/// Trust policy for custom rulesets
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RulesetTrustPolicy {
    Signed,
    Warn,
    Allow,
}

/// Default trust policy for v1
pub const DEFAULT_RULESET_TRUST_POLICY: RulesetTrustPolicy = RulesetTrustPolicy::Warn;

/// Signature status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SignatureStatus {
    Verified,
    Unverified,
    Unsigned,
}

/// Metadata about a single ruleset that contributed to a scan
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RulesetMeta {
    pub source: String,
    pub version: String,
    pub hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_status: Option<SignatureStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_policy: Option<RulesetTrustPolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub findings_contributed: Option<usize>,
}

/// Trait implemented by all scanner modules
pub trait ScannerModule: Send + Sync {
    fn name(&self) -> &str;
    fn scan(&self, ctx: &ScanContext) -> Vec<ScanFinding>;
}
