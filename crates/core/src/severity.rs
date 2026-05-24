#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    P0,
    P1,
    P2,
}

impl Severity {
    /// Higher return value = more severe. P0 is highest (2), P2 is lowest (0).
    pub fn priority(self) -> u8 {
        match self {
            Severity::P0 => 2,
            Severity::P1 => 1,
            Severity::P2 => 0,
        }
    }
}
