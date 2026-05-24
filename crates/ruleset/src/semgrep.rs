use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct SemgrepRule {
    pub id: String,
    pub message: String,
    #[serde(flatten)]
    pub _rest: serde_yaml::Value,
}
