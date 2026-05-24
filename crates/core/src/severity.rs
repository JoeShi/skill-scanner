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
        todo!("C3 amendment: Severity::priority() — P0=2, P1=1, P2=0")
    }
}
