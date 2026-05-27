//! Implements Custom Ruleset Security constraint C1 - schema validation on load.
//! And C2 - rule_origin distinct (origin stamping).

use regex::Regex;

use crate::types::{RuleOrigin, Severity, Tier};

/// A validated rule envelope
#[derive(Debug, Clone)]
pub struct Rule {
    pub id: String,
    pub languages: Option<Vec<String>>,
    pub severity: Option<String>,
    pub message: String,
    pub metadata: RuleMetadata,
    pub paths: Option<RulePaths>,
}

/// Metadata on a rule
#[derive(Debug, Clone)]
pub struct RuleMetadata {
    pub tier: Tier,
    pub severity: Severity,
    pub dimension: Option<Vec<String>>,
}

/// Path includes/excludes
#[derive(Debug, Clone)]
pub struct RulePaths {
    pub include: Option<Vec<String>>,
    pub exclude: Option<Vec<String>>,
}

/// A validated ruleset
#[derive(Debug, Clone)]
pub struct Ruleset {
    pub rules: Vec<Rule>,
}

/// Options for loading a ruleset
pub enum LoadRulesetSource {
    Core,
    Custom { path: String },
}

/// Stamp a RuleOrigin based on the load source.
/// Per C2: 'core' is reserved for rules shipped in packages/core/rules/.
/// Custom rules always get 'custom:<path>'.
pub fn origin_for_load(source: &LoadRulesetSource) -> RuleOrigin {
    match source {
        LoadRulesetSource::Core => RuleOrigin::Core,
        LoadRulesetSource::Custom { path } => RuleOrigin::custom(path),
    }
}

/// Validation error with all issues listed
#[derive(Debug, Clone)]
pub struct RulesetValidationError {
    pub issues: Vec<ValidationIssue>,
    pub source: String,
}

impl std::fmt::Display for RulesetValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let preview: Vec<String> = self
            .issues
            .iter()
            .take(3)
            .map(|i| format!("{}: {}", i.path, i.message))
            .collect();
        write!(
            f,
            "ruleset validation failed ({} issue{}) in {}: {}{}",
            self.issues.len(),
            if self.issues.len() == 1 { "" } else { "s" },
            self.source,
            preview.join("; "),
            if self.issues.len() > 3 {
                format!(" (+{} more)", self.issues.len() - 3)
            } else {
                String::new()
            }
        )
    }
}

impl std::error::Error for RulesetValidationError {}

#[derive(Debug, Clone)]
pub struct ValidationIssue {
    pub path: String,
    pub message: String,
}

/// Validate a parsed ruleset object.
/// Throws RulesetValidationError if the input fails schema.
pub fn validate_ruleset(
    input: &serde_json::Value,
    source: &str,
) -> Result<Ruleset, RulesetValidationError> {
    let mut issues: Vec<ValidationIssue> = Vec::new();

    // Check for unknown top-level fields (strict mode)
    if let Some(obj) = input.as_object() {
        for key in obj.keys() {
            if key != "rules" {
                issues.push(ValidationIssue {
                    path: "<root>".to_string(),
                    message: format!("Unrecognized key \"{}\"", key),
                });
            }
        }
    } else {
        issues.push(ValidationIssue {
            path: "<root>".to_string(),
            message: "Expected an object".to_string(),
        });
        return Err(RulesetValidationError {
            issues,
            source: source.to_string(),
        });
    }

    // Check rules array exists and is non-empty
    let rules_value = input.get("rules");
    let rules_array = match rules_value {
        Some(v) => match v.as_array() {
            Some(arr) => arr,
            None => {
                issues.push(ValidationIssue {
                    path: "rules".to_string(),
                    message: "Expected array".to_string(),
                });
                return Err(RulesetValidationError {
                    issues,
                    source: source.to_string(),
                });
            }
        },
        None => {
            issues.push(ValidationIssue {
                path: "<root>".to_string(),
                message: "Missing required field: rules".to_string(),
            });
            return Err(RulesetValidationError {
                issues,
                source: source.to_string(),
            });
        }
    };

    if rules_array.is_empty() {
        issues.push(ValidationIssue {
            path: "rules".to_string(),
            message: "Array must contain at least 1 element(s)".to_string(),
        });
        return Err(RulesetValidationError {
            issues,
            source: source.to_string(),
        });
    }

    // Validate each rule
    let rule_id_re = Regex::new(r"^[a-z][a-z0-9-]*$").unwrap();
    let mut validated_rules: Vec<Rule> = Vec::new();

    for (i, rule_val) in rules_array.iter().enumerate() {
        let rule_path = format!("rules.{}", i);

        let rule_obj = match rule_val.as_object() {
            Some(o) => o,
            None => {
                issues.push(ValidationIssue {
                    path: rule_path,
                    message: "Expected object".to_string(),
                });
                continue;
            }
        };

        // Check for unknown top-level rule fields
        let allowed_rule_fields = ["id", "languages", "severity", "message", "metadata", "paths"];
        for key in rule_obj.keys() {
            if !allowed_rule_fields.contains(&key.as_str()) {
                issues.push(ValidationIssue {
                    path: format!("{}.{}", rule_path, key),
                    message: format!("Unrecognized key \"{}\"", key),
                });
            }
        }

        // Validate id
        let id = match rule_obj.get("id").and_then(|v| v.as_str()) {
            Some(id) => {
                if id.is_empty() || id.len() > 128 {
                    issues.push(ValidationIssue {
                        path: format!("{}.id", rule_path),
                        message: "rule id must be between 1 and 128 characters".to_string(),
                    });
                } else if !rule_id_re.is_match(id) {
                    issues.push(ValidationIssue {
                        path: format!("{}.id", rule_path),
                        message: "rule id must be lowercase kebab (no special chars)".to_string(),
                    });
                }
                id.to_string()
            }
            None => {
                issues.push(ValidationIssue {
                    path: format!("{}.id", rule_path),
                    message: "Required".to_string(),
                });
                String::new()
            }
        };

        // Validate message
        let message = match rule_obj.get("message").and_then(|v| v.as_str()) {
            Some(msg) => {
                if msg.is_empty() {
                    issues.push(ValidationIssue {
                        path: format!("{}.message", rule_path),
                        message: "String must contain at least 1 character(s)".to_string(),
                    });
                } else if msg.len() > 2000 {
                    issues.push(ValidationIssue {
                        path: format!("{}.message", rule_path),
                        message: "String must contain at most 2000 character(s)".to_string(),
                    });
                }
                msg.to_string()
            }
            None => {
                issues.push(ValidationIssue {
                    path: format!("{}.message", rule_path),
                    message: "Required".to_string(),
                });
                String::new()
            }
        };

        // Validate metadata
        let metadata = match rule_obj.get("metadata") {
            Some(meta_val) => {
                if let Some(meta_obj) = meta_val.as_object() {
                    // Check for unknown metadata fields (strict)
                    let allowed_meta_fields = ["tier", "severity", "dimension"];
                    for key in meta_obj.keys() {
                        if !allowed_meta_fields.contains(&key.as_str()) {
                            issues.push(ValidationIssue {
                                path: format!("{}.metadata.{}", rule_path, key),
                                message: format!("Unrecognized key \"{}\"", key),
                            });
                        }
                    }

                    let tier = match meta_obj.get("tier").and_then(|v| v.as_str()) {
                        Some("blocker") => Some(Tier::Blocker),
                        Some("suggestion") => Some(Tier::Suggestion),
                        Some("nit") => Some(Tier::Nit),
                        Some(other) => {
                            issues.push(ValidationIssue {
                                path: format!("{}.metadata.tier", rule_path),
                                message: format!(
                                    "Invalid enum value. Expected 'blocker' | 'suggestion' | 'nit', received '{}'",
                                    other
                                ),
                            });
                            None
                        }
                        None => {
                            issues.push(ValidationIssue {
                                path: format!("{}.metadata.tier", rule_path),
                                message: "Required".to_string(),
                            });
                            None
                        }
                    };

                    let severity = match meta_obj.get("severity").and_then(|v| v.as_str()) {
                        Some("P0") => Some(Severity::P0),
                        Some("P1") => Some(Severity::P1),
                        Some("P2") => Some(Severity::P2),
                        Some(other) => {
                            issues.push(ValidationIssue {
                                path: format!("{}.metadata.severity", rule_path),
                                message: format!(
                                    "Invalid enum value. Expected 'P0' | 'P1' | 'P2', received '{}'",
                                    other
                                ),
                            });
                            None
                        }
                        None => {
                            issues.push(ValidationIssue {
                                path: format!("{}.metadata.severity", rule_path),
                                message: "Required".to_string(),
                            });
                            None
                        }
                    };

                    let dimension = meta_obj
                        .get("dimension")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                .collect()
                        });

                    match (tier, severity) {
                        (Some(t), Some(s)) => Some(RuleMetadata {
                            tier: t,
                            severity: s,
                            dimension,
                        }),
                        _ => None,
                    }
                } else {
                    issues.push(ValidationIssue {
                        path: format!("{}.metadata", rule_path),
                        message: "Expected object".to_string(),
                    });
                    None
                }
            }
            None => {
                issues.push(ValidationIssue {
                    path: format!("{}.metadata", rule_path),
                    message: "Required".to_string(),
                });
                None
            }
        };

        // Validate paths if present
        let paths = rule_obj.get("paths").and_then(|p| {
            if let Some(paths_obj) = p.as_object() {
                let allowed_paths_fields = ["include", "exclude"];
                for key in paths_obj.keys() {
                    if !allowed_paths_fields.contains(&key.as_str()) {
                        issues.push(ValidationIssue {
                            path: format!("{}.paths.{}", rule_path, key),
                            message: format!("Unrecognized key \"{}\"", key),
                        });
                    }
                }
                let include = paths_obj
                    .get("include")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect()
                    });
                let exclude = paths_obj
                    .get("exclude")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect()
                    });
                Some(RulePaths { include, exclude })
            } else {
                issues.push(ValidationIssue {
                    path: format!("{}.paths", rule_path),
                    message: "Expected object".to_string(),
                });
                None
            }
        });

        // Validate languages if present
        let languages = rule_obj.get("languages").and_then(|l| {
            l.as_array().map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
        });

        let semgrep_severity = rule_obj
            .get("severity")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        if let Some(meta) = metadata {
            validated_rules.push(Rule {
                id,
                languages,
                severity: semgrep_severity,
                message,
                metadata: meta,
                paths,
            });
        }
    }

    if !issues.is_empty() {
        return Err(RulesetValidationError {
            issues,
            source: source.to_string(),
        });
    }

    Ok(Ruleset {
        rules: validated_rules,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_accepts_minimal_valid_ruleset() {
        let input = json!({
            "rules": [{
                "id": "r-keychain-direct",
                "message": "Direct keychain access detected.",
                "metadata": {
                    "tier": "blocker",
                    "severity": "P0",
                    "dimension": ["critical:security"]
                }
            }]
        });
        let result = validate_ruleset(&input, "fixture://ok");
        assert!(result.is_ok());
        let ruleset = result.unwrap();
        assert_eq!(ruleset.rules.len(), 1);
        assert_eq!(ruleset.rules[0].id, "r-keychain-direct");
    }

    #[test]
    fn test_rejects_unknown_top_level_fields() {
        let input = json!({
            "rules": [{
                "id": "r-ok",
                "message": "msg",
                "metadata": {"tier": "blocker", "severity": "P0"}
            }],
            "auto_install": true
        });
        let result = validate_ruleset(&input, "fixture://sneaky");
        assert!(result.is_err());
    }

    #[test]
    fn test_rejects_unknown_metadata_fields() {
        let input = json!({
            "rules": [{
                "id": "r-spoof",
                "message": "msg",
                "metadata": {
                    "tier": "blocker",
                    "severity": "P0",
                    "ruleOrigin": "core"
                }
            }]
        });
        let result = validate_ruleset(&input, "fixture://spoof");
        assert!(result.is_err());
    }

    #[test]
    fn test_rejects_rule_id_with_special_chars() {
        let input = json!({
            "rules": [{
                "id": "core:R5",
                "message": "msg",
                "metadata": {"tier": "blocker", "severity": "P0"}
            }]
        });
        let result = validate_ruleset(&input, "fixture://bad-id");
        assert!(result.is_err());
    }

    #[test]
    fn test_rejects_rule_id_starting_with_digit() {
        let input = json!({
            "rules": [{
                "id": "5-bad",
                "message": "msg",
                "metadata": {"tier": "blocker", "severity": "P0"}
            }]
        });
        let result = validate_ruleset(&input, "fixture://digit-prefix");
        assert!(result.is_err());
    }

    #[test]
    fn test_rejects_invalid_severity() {
        let input = json!({
            "rules": [{
                "id": "r-x",
                "message": "msg",
                "metadata": {"tier": "blocker", "severity": "CRITICAL"}
            }]
        });
        let result = validate_ruleset(&input, "fixture://bad-sev");
        assert!(result.is_err());
    }

    #[test]
    fn test_rejects_long_message() {
        let long_msg = "x".repeat(2001);
        let input = json!({
            "rules": [{
                "id": "r-long",
                "message": long_msg,
                "metadata": {"tier": "blocker", "severity": "P0"}
            }]
        });
        let result = validate_ruleset(&input, "fixture://long");
        assert!(result.is_err());
    }

    #[test]
    fn test_rejects_empty_rules_array() {
        let input = json!({"rules": []});
        let result = validate_ruleset(&input, "fixture://empty");
        assert!(result.is_err());
    }

    #[test]
    fn test_error_includes_all_issues() {
        let input = json!({
            "rules": [{
                "id": "core:bad",
                "message": "m",
                "metadata": {"tier": "blocker", "severity": "WAT"}
            }]
        });
        let result = validate_ruleset(&input, "fixture://multi");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.issues.len() >= 2);
        assert_eq!(err.source, "fixture://multi");
    }

    #[test]
    fn test_origin_for_load_core() {
        let origin = origin_for_load(&LoadRulesetSource::Core);
        assert_eq!(origin, RuleOrigin::Core);
    }

    #[test]
    fn test_origin_for_load_custom() {
        let origin = origin_for_load(&LoadRulesetSource::Custom {
            path: "/users/alice/my-rules.yml".to_string(),
        });
        assert_eq!(
            origin,
            RuleOrigin::Custom("custom:/users/alice/my-rules.yml".to_string())
        );
    }

    #[test]
    fn test_origin_for_load_custom_core_path() {
        // Even if the path string contains 'core', the prefix 'custom:' is non-removable
        let origin = origin_for_load(&LoadRulesetSource::Custom {
            path: "core".to_string(),
        });
        assert_eq!(
            origin,
            RuleOrigin::Custom("custom:core".to_string())
        );
    }
}
