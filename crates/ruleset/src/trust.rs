// C4 — cryptographic trust policy (stub — to be implemented by KimiDev)
use crate::error::RulesetValidationError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustPolicy {
    Unverified,
    RequireSignature { trusted_keys: Vec<TrustedKey> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedKey {
    pub identifier: String,
    pub public_key: [u8; 32],
}

/// Pure Ed25519 trust gate. No filesystem I/O — caller provides bytes.
///
/// Wire format for sig_bytes: [sig: 0..64][pubkey: 64..96] = 96 bytes total.
/// TrustPolicy::Unverified always returns Ok.
/// TrustPolicy::RequireSignature verifies Ed25519 (RFC 8032 PureEdDSA) and
/// checks that the embedded public key is in trusted_keys.
pub fn verify_ruleset_signature(
    _yaml_bytes: &[u8],
    _sig_bytes: Option<&[u8]>,
    _policy: &TrustPolicy,
) -> Result<(), RulesetValidationError> {
    todo!("C4 verify_ruleset_signature: implement TrustPolicy + Ed25519 wire verification")
}
