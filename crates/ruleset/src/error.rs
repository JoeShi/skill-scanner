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
    #[error(
        "custom ruleset rejected: signature required by trust policy but no .sig sidecar found"
    )]
    C4MissingSignature,
    #[error("custom ruleset rejected: signature is malformed or invalid: {reason}")]
    C4InvalidSignature { reason: String },
    #[error(
        "custom ruleset rejected: signing key {key_fingerprint} is not in the trusted-keys allowlist"
    )]
    C4UntrustedKey { key_fingerprint: String },
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
            Self::C4MissingSignature => "RULESET_C4_MISSING_SIGNATURE",
            Self::C4InvalidSignature { .. } => "RULESET_C4_INVALID_SIGNATURE",
            Self::C4UntrustedKey { .. } => "RULESET_C4_UNTRUSTED_KEY",
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
            (Self::C4MissingSignature, Self::C4MissingSignature) => true,
            (Self::C4InvalidSignature { reason: a }, Self::C4InvalidSignature { reason: b }) => {
                a == b
            }
            (
                Self::C4UntrustedKey { key_fingerprint: a },
                Self::C4UntrustedKey { key_fingerprint: b },
            ) => a == b,
            _ => false,
        }
    }
}

impl Eq for RulesetValidationError {}
