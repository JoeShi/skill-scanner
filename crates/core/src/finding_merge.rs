//! Implements Custom Ruleset Security constraint C3 - severity asymmetry:
//! custom rules can upgrade core severity, never downgrade it.

use crate::types::{RuleOrigin, ScanFinding, Severity, Tier};
use std::collections::HashMap;

/// A finding after merge, with provenance tracking
#[derive(Debug, Clone)]
pub struct MergedFinding {
    pub finding: ScanFinding,
    pub merged_from: Vec<RuleOrigin>,
}

/// Identity key for grouping findings that refer to the same underlying issue.
fn identity_key(f: &ScanFinding) -> String {
    let ident = f.ref_anchor.as_deref().unwrap_or(&f.rule_id);
    let file = f.file.as_deref().unwrap_or("");
    let line = f.line.map(|l| l.to_string()).unwrap_or_default();
    format!("{}::{}::{}", ident, file, line)
}

/// Merge core + custom findings under the C3 severity asymmetry invariant.
///
/// Custom rules can RAISE the severity of a core finding, never lower it.
/// Custom-only findings keep their declared severity.
///
/// Panics/errors if:
/// - A finding in the core bucket has a non-core ruleOrigin
/// - A finding in the customs bucket has ruleOrigin="core" (impersonation)
/// - A custom finding has no ruleOrigin (loader must stamp it)
pub fn merge_findings(
    core: &[ScanFinding],
    customs: &[ScanFinding],
) -> Result<Vec<MergedFinding>, String> {
    // Defensive guard: confirm ruleOrigin is consistent with the bucket
    for c in core {
        if let Some(ref origin) = c.rule_origin {
            if !origin.is_core() {
                return Err(format!(
                    "mergeFindings: finding in 'core' bucket has ruleOrigin={} (expected 'core' or undefined)",
                    origin
                ));
            }
        }
    }
    for c in customs {
        match &c.rule_origin {
            Some(origin) if origin.is_core() => {
                return Err(
                    "mergeFindings: finding in customs bucket has ruleOrigin=\"core\" -- \
                     custom rules cannot impersonate core. Reject before merge."
                        .to_string(),
                );
            }
            None => {
                return Err(
                    "mergeFindings: custom finding has no ruleOrigin -- must be set to \
                     `custom:<path>` by the loader before merge."
                        .to_string(),
                );
            }
            _ => {}
        }
    }

    let mut by_key: HashMap<String, MergedFinding> = HashMap::new();

    // Seed with core findings - these are the floor that customs can raise
    for f in core {
        let stamped_origin = f
            .rule_origin
            .clone()
            .unwrap_or(RuleOrigin::Core);
        let key = identity_key(f);
        let mut merged_finding = f.clone();
        merged_finding.rule_origin = Some(stamped_origin.clone());
        by_key.insert(
            key,
            MergedFinding {
                finding: merged_finding,
                merged_from: vec![stamped_origin],
            },
        );
    }

    for c in customs {
        let key = identity_key(c);
        let custom_origin = c.rule_origin.clone().unwrap();

        if let Some(existing) = by_key.get_mut(&key) {
            // C3: a custom rule can RAISE the severity, never lower it
            let new_severity = existing.finding.severity.max(c.severity);
            existing.finding.severity = new_severity;
            existing.finding.tier = Tier::for_severity(new_severity);
            existing.merged_from.push(custom_origin);
        } else {
            // Custom-only finding - keeps its own severity and origin
            let mut merged_finding = c.clone();
            merged_finding.rule_origin = Some(custom_origin.clone());
            by_key.insert(
                key,
                MergedFinding {
                    finding: merged_finding,
                    merged_from: vec![custom_origin],
                },
            );
        }
    }

    Ok(by_key.into_values().collect())
}

/// Top-level decision based on the merged findings' severity.
///
/// - any P0 -> 'blocked'
/// - else any P1 -> 'requires-user-consent'
/// - else 'allowed'
pub fn decide_from_findings(findings: &[ScanFinding]) -> &'static str {
    let mut has_p1 = false;
    for f in findings {
        if f.severity == Severity::P0 {
            return "blocked";
        }
        if f.severity == Severity::P1 {
            has_p1 = true;
        }
    }
    if has_p1 {
        "requires-user-consent"
    } else {
        "allowed"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{CriticalTag, ThreatCategory};

    fn fixture(overrides: Option<FixtureOverrides>) -> ScanFinding {
        let o = overrides.unwrap_or_default();
        ScanFinding {
            rule_id: o.rule_id.unwrap_or_else(|| "r-keychain".to_string()),
            tier: o.tier.unwrap_or(Tier::Blocker),
            severity: o.severity.unwrap_or(Severity::P0),
            critical_tag: Some(CriticalTag::Security),
            message: "msg".to_string(),
            file: Some(o.file.unwrap_or_else(|| "index.js".to_string())),
            line: Some(o.line.unwrap_or(42)),
            column: None,
            category: ThreatCategory::PrivilegeEscalation,
            evidence: None,
            recommendation: None,
            rule_origin: o.rule_origin,
            ref_anchor: o.ref_anchor,
            merged_from: None,
        }
    }

    #[derive(Default)]
    struct FixtureOverrides {
        rule_id: Option<String>,
        tier: Option<Tier>,
        severity: Option<Severity>,
        rule_origin: Option<RuleOrigin>,
        ref_anchor: Option<String>,
        file: Option<String>,
        line: Option<u32>,
    }

    #[test]
    fn test_core_p0_vs_custom_p2_stays_p0() {
        let core = vec![fixture(Some(FixtureOverrides {
            severity: Some(Severity::P0),
            rule_origin: Some(RuleOrigin::Core),
            ref_anchor: Some("skill-foo#R5".to_string()),
            ..Default::default()
        }))];
        let customs = vec![fixture(Some(FixtureOverrides {
            severity: Some(Severity::P2),
            tier: Some(Tier::Nit),
            rule_origin: Some(RuleOrigin::Custom("custom:/tmp/evil.yml".to_string())),
            ref_anchor: Some("skill-foo#R5".to_string()),
            ..Default::default()
        }))];
        let merged = merge_findings(&core, &customs).unwrap();
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].finding.severity, Severity::P0);
        assert_eq!(merged[0].finding.tier, Tier::Blocker);
        assert_eq!(merged[0].finding.rule_origin, Some(RuleOrigin::Core));
        assert_eq!(
            merged[0].merged_from,
            vec![
                RuleOrigin::Core,
                RuleOrigin::Custom("custom:/tmp/evil.yml".to_string())
            ]
        );
    }

    #[test]
    fn test_core_p2_custom_p0_upgrades_to_p0() {
        let core = vec![fixture(Some(FixtureOverrides {
            severity: Some(Severity::P2),
            tier: Some(Tier::Nit),
            rule_origin: Some(RuleOrigin::Core),
            ref_anchor: Some("skill-foo#R5".to_string()),
            ..Default::default()
        }))];
        let customs = vec![fixture(Some(FixtureOverrides {
            severity: Some(Severity::P0),
            tier: Some(Tier::Blocker),
            rule_origin: Some(RuleOrigin::Custom("custom:/etc/strict.yml".to_string())),
            ref_anchor: Some("skill-foo#R5".to_string()),
            ..Default::default()
        }))];
        let merged = merge_findings(&core, &customs).unwrap();
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].finding.severity, Severity::P0);
        assert_eq!(merged[0].finding.tier, Tier::Blocker);
        // ruleOrigin stays 'core'
        assert_eq!(merged[0].finding.rule_origin, Some(RuleOrigin::Core));
    }

    #[test]
    fn test_custom_only_keeps_own_severity() {
        let customs = vec![fixture(Some(FixtureOverrides {
            severity: Some(Severity::P1),
            tier: Some(Tier::Suggestion),
            rule_origin: Some(RuleOrigin::Custom("custom:/tmp/extra.yml".to_string())),
            ref_anchor: Some("skill-foo#R-extra".to_string()),
            ..Default::default()
        }))];
        let merged = merge_findings(&[], &customs).unwrap();
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].finding.severity, Severity::P1);
        assert_eq!(
            merged[0].finding.rule_origin,
            Some(RuleOrigin::Custom("custom:/tmp/extra.yml".to_string()))
        );
    }

    #[test]
    fn test_reject_custom_claiming_core_origin() {
        let customs = vec![fixture(Some(FixtureOverrides {
            rule_origin: Some(RuleOrigin::Core),
            ..Default::default()
        }))];
        let result = merge_findings(&[], &customs);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("cannot impersonate core"));
    }

    #[test]
    fn test_reject_core_bucket_with_non_core_origin() {
        let core = vec![fixture(Some(FixtureOverrides {
            rule_origin: Some(RuleOrigin::Custom("custom:/tmp/x.yml".to_string())),
            ..Default::default()
        }))];
        let result = merge_findings(&core, &[]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("expected 'core'"));
    }

    #[test]
    fn test_reject_custom_without_rule_origin() {
        let customs = vec![fixture(Some(FixtureOverrides {
            severity: Some(Severity::P1),
            tier: Some(Tier::Suggestion),
            rule_origin: None,
            ..Default::default()
        }))];
        let result = merge_findings(&[], &customs);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("no ruleOrigin"));
    }

    #[test]
    fn test_core_finding_no_origin_stamped_to_core() {
        let core = vec![fixture(Some(FixtureOverrides {
            severity: Some(Severity::P0),
            rule_origin: None,
            ref_anchor: Some("skill-foo#R5".to_string()),
            ..Default::default()
        }))];
        let merged = merge_findings(&core, &[]).unwrap();
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].finding.rule_origin, Some(RuleOrigin::Core));
        assert_eq!(merged[0].merged_from, vec![RuleOrigin::Core]);
    }

    #[test]
    fn test_different_files_do_not_collapse() {
        let a = fixture(Some(FixtureOverrides {
            severity: Some(Severity::P0),
            rule_origin: Some(RuleOrigin::Core),
            ref_anchor: Some("skill-foo#R5".to_string()),
            file: Some("a.js".to_string()),
            line: Some(10),
            ..Default::default()
        }));
        let b = fixture(Some(FixtureOverrides {
            severity: Some(Severity::P0),
            rule_origin: Some(RuleOrigin::Core),
            ref_anchor: Some("skill-foo#R5".to_string()),
            file: Some("b.js".to_string()),
            line: Some(10),
            ..Default::default()
        }));
        let c = fixture(Some(FixtureOverrides {
            severity: Some(Severity::P0),
            rule_origin: Some(RuleOrigin::Core),
            ref_anchor: Some("skill-foo#R5".to_string()),
            file: Some("a.js".to_string()),
            line: Some(11),
            ..Default::default()
        }));
        let merged = merge_findings(&[a, b, c], &[]).unwrap();
        assert_eq!(merged.len(), 3);
    }

    #[test]
    fn test_decide_from_findings_p0_blocked() {
        let findings = vec![
            fixture(Some(FixtureOverrides {
                severity: Some(Severity::P2),
                ..Default::default()
            })),
            fixture(Some(FixtureOverrides {
                severity: Some(Severity::P0),
                ..Default::default()
            })),
        ];
        assert_eq!(decide_from_findings(&findings), "blocked");
    }

    #[test]
    fn test_decide_from_findings_p1_consent() {
        let findings = vec![
            fixture(Some(FixtureOverrides {
                severity: Some(Severity::P2),
                ..Default::default()
            })),
            fixture(Some(FixtureOverrides {
                severity: Some(Severity::P1),
                ..Default::default()
            })),
        ];
        assert_eq!(decide_from_findings(&findings), "requires-user-consent");
    }

    #[test]
    fn test_decide_from_findings_p2_allowed() {
        let findings = vec![fixture(Some(FixtureOverrides {
            severity: Some(Severity::P2),
            ..Default::default()
        }))];
        assert_eq!(decide_from_findings(&findings), "allowed");
    }

    #[test]
    fn test_decide_from_findings_empty_allowed() {
        assert_eq!(decide_from_findings(&[]), "allowed");
    }
}
