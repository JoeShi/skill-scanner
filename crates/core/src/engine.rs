use std::collections::HashSet;
use std::path::Path;
use std::time::Instant;

use uuid::Uuid;
use walkdir::WalkDir;

use crate::manifest::parse_manifest_with_raw;
use crate::modules::dangerous_api::DangerousApiModule;
use crate::modules::fs_diff::FsDiffModule;
use crate::modules::manifest_validation::ManifestValidationModule;
use crate::modules::narrow_waist_bypass::NarrowWaistBypassModule;
use crate::modules::network_diff::NetworkDiffModule;
use crate::modules::process_spawn::ProcessSpawnModule;
use crate::modules::sbom_cve::SbomCveModule;
use crate::modules::secrets_scan::SecretsScanModule;
use crate::types::{
    Confidence, Decision, RulesetMeta, ScanContext, ScanFinding, ScanResult, ScanSummary,
    ScannerModule, Severity, Tier, CriticalTag, ThreatCategory,
};

pub const SCANNER_VERSION: &str = "1.0.0";

pub struct ScannerEngine {
    modules: Vec<Box<dyn ScannerModule>>,
}

impl ScannerEngine {
    pub fn new() -> Self {
        ScannerEngine {
            modules: Vec::new(),
        }
    }

    pub fn register(&mut self, module: Box<dyn ScannerModule>) {
        self.modules.push(module);
    }

    pub fn scan(&self, skill_path: &str) -> Result<ScanResult, String> {
        let start = Instant::now();
        let skill_name = Path::new(skill_path)
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        let (manifest, manifest_raw) = parse_manifest_with_raw(skill_path)?;
        let source_files = self.collect_source_files(skill_path);

        let ctx = ScanContext {
            skill_name: skill_name.clone(),
            skill_path: skill_path.to_string(),
            manifest: manifest.clone(),
            manifest_raw,
            source_files,
            tmp_dir: None,
        };

        let mut findings: Vec<ScanFinding> = Vec::new();
        for module in &self.modules {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| module.scan(&ctx))) {
                Ok(mod_findings) => {
                    findings.extend(mod_findings);
                }
                Err(_) => {
                    findings.push(ScanFinding {
                        rule_id: "R0-engine-error".to_string(),
                        tier: Tier::Blocker,
                        severity: Severity::P0,
                        critical_tag: Some(CriticalTag::Security),
                        message: format!("Scanner module \"{}\" crashed", module.name()),
                        file: None,
                        line: None,
                        column: None,
                        category: ThreatCategory::MaliciousCode,
                        evidence: None,
                        recommendation: None,
                        rule_origin: Some(crate::types::RuleOrigin::Core),
                        ref_anchor: None,
                        merged_from: None,
                    });
                }
            }
        }

        let duration_ms = start.elapsed().as_millis() as u64;

        let summary = ScanSummary {
            p0: findings.iter().filter(|f| f.severity == Severity::P0).count(),
            p1: findings.iter().filter(|f| f.severity == Severity::P1).count(),
            p2: findings.iter().filter(|f| f.severity == Severity::P2).count(),
        };

        let decision = if summary.p0 > 0 {
            Decision::Blocked
        } else if summary.p1 > 0 {
            Decision::RequiresUserConsent
        } else {
            Decision::Allowed
        };

        let core_ruleset_meta = RulesetMeta {
            source: "core".to_string(),
            version: SCANNER_VERSION.to_string(),
            hash: String::new(),
            signature_status: None,
            trust_policy: None,
            findings_contributed: None,
        };

        let result = ScanResult {
            event_id: Uuid::new_v4().to_string(),
            skill_name: manifest.name.clone(),
            skill_version: manifest.version.clone(),
            ruleset_meta: vec![core_ruleset_meta],
            findings,
            summary,
            duration_ms,
            scanner_version: SCANNER_VERSION.to_string(),
            scanned_at: chrono::Utc::now().to_rfc3339(),
            coverage: vec![
                "manifest-validation".to_string(),
                "declared-vs-actual".to_string(),
                "static-analysis".to_string(),
                "fs-boundary".to_string(),
                "sbom-cve".to_string(),
            ],
            confidence: Confidence::Medium,
            known_blind_spots: vec![
                "polymorphic-malware".to_string(),
                "supply-chain-zero-day".to_string(),
                "dynamic-host-construction".to_string(),
            ],
            decision,
        };

        Ok(result)
    }

    fn collect_source_files(&self, skill_path: &str) -> Vec<String> {
        let ignore_dirs: HashSet<&str> = [
            "node_modules",
            ".git",
            "dist",
            "build",
            "coverage",
            ".quickwork",
        ]
        .into_iter()
        .collect();

        let mut files = Vec::new();
        let walker = WalkDir::new(skill_path).into_iter();

        for entry in walker
            .filter_entry(|e| {
                if e.file_type().is_dir() {
                    let name = e.file_name().to_string_lossy();
                    !ignore_dirs.contains(name.as_ref())
                } else {
                    true
                }
            })
            .flatten()
        {
            if entry.file_type().is_file() {
                if let Ok(rel) = entry.path().strip_prefix(skill_path) {
                    files.push(rel.to_string_lossy().to_string());
                }
            }
        }

        files
    }
}

impl Default for ScannerEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience factory: create engine with all scanner modules registered
pub fn create_default_engine() -> ScannerEngine {
    let mut engine = ScannerEngine::new();
    engine.register(Box::new(ManifestValidationModule));
    engine.register(Box::new(NetworkDiffModule));
    engine.register(Box::new(FsDiffModule));
    engine.register(Box::new(ProcessSpawnModule));
    engine.register(Box::new(DangerousApiModule));
    engine.register(Box::new(SecretsScanModule));
    engine.register(Box::new(NarrowWaistBypassModule));
    engine.register(Box::new(SbomCveModule));
    engine
}
