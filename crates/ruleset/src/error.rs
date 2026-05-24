use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum RulesetValidationError {
    #[error("Custom ruleset rule \"{rule_id}\" rejected: rule.message contains template expansion {offending_fragment} (rule code RULESET_C5_TEMPLATE_EXPANSION)")]
    TemplateExpansion {
        rule_id: String,
        offending_fragment: String,
    },
    #[error("Custom ruleset rule \"{rule_id}\" rejected: id does not match ^[a-z][a-z0-9-]*$ (rule code RULESET_C1_INVALID_ID)")]
    C1InvalidId { rule_id: String },
    #[error("Custom ruleset rule \"{rule_id}\" rejected: message is {len} bytes, exceeds 2000-byte limit (rule code RULESET_C1_MESSAGE_TOO_LONG)")]
    C1MessageTooLong { rule_id: String, len: usize },
    #[error("Custom ruleset rule \"{rule_id}\" rejected: rule_origin field must not be present in custom ruleset YAML (rule code RULESET_C2_ORIGIN_SPOOF)")]
    C2OriginSpoof { rule_id: String },
    #[error("IO error reading {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("YAML parse error: {source}")]
    Yaml { source: serde_yaml::Error },
}

impl RulesetValidationError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::TemplateExpansion { .. } => "RULESET_C5_TEMPLATE_EXPANSION",
            Self::C1InvalidId { .. } => "RULESET_C1_INVALID_ID",
            Self::C1MessageTooLong { .. } => "RULESET_C1_MESSAGE_TOO_LONG",
            Self::C2OriginSpoof { .. } => "RULESET_C2_ORIGIN_SPOOF",
            Self::Io { .. } => "RULESET_IO",
            Self::Yaml { .. } => "RULESET_YAML",
        }
    }
}

impl PartialEq for RulesetValidationError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::TemplateExpansion {
                    rule_id: a,
                    offending_fragment: b,
                },
                Self::TemplateExpansion {
                    rule_id: c,
                    offending_fragment: d,
                },
            ) => a == c && b == d,
            (Self::C1InvalidId { rule_id: a }, Self::C1InvalidId { rule_id: b }) => a == b,
            (
                Self::C1MessageTooLong { rule_id: a, len: b },
                Self::C1MessageTooLong { rule_id: c, len: d },
            ) => a == c && b == d,
            (Self::C2OriginSpoof { rule_id: a }, Self::C2OriginSpoof { rule_id: b }) => a == b,
            _ => false,
        }
    }
}

impl Eq for RulesetValidationError {}
