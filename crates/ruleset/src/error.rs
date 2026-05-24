use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum RulesetValidationError {
    #[error("Custom ruleset rule \"{rule_id}\" rejected: rule.message contains template expansion {offending_fragment} (rule code RULESET_C5_TEMPLATE_EXPANSION)")]
    TemplateExpansion {
        rule_id: String,
        offending_fragment: String,
    },
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
            _ => false,
        }
    }
}

impl Eq for RulesetValidationError {}
