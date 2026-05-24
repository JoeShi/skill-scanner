// C4 — cryptographic trust policy
// Pure Ed25519 trust gate. No filesystem I/O — caller provides bytes.

use crate::error::RulesetValidationError;
use sha2::{Digest, Sha256};

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
    yaml_bytes: &[u8],
    sig_bytes: Option<&[u8]>,
    policy: &TrustPolicy,
) -> Result<(), RulesetValidationError> {
    match policy {
        TrustPolicy::Unverified => Ok(()),
        TrustPolicy::RequireSignature { trusted_keys } => {
            let sig_data = match sig_bytes {
                Some(data) => data,
                None => return Err(RulesetValidationError::C4MissingSignature),
            };

            if sig_data.len() != 96 {
                return Err(RulesetValidationError::C4InvalidSignature {
                    reason: "wire format must be 96 bytes".to_string(),
                });
            }

            let signature_bytes: [u8; 64] = sig_data[0..64].try_into().unwrap();
            let public_key_bytes: [u8; 32] = sig_data[64..96].try_into().unwrap();

            let verifying_key = match ed25519_dalek::VerifyingKey::from_bytes(&public_key_bytes) {
                Ok(vk) => vk,
                Err(_) => {
                    return Err(RulesetValidationError::C4InvalidSignature {
                        reason: "signature does not verify".to_string(),
                    })
                }
            };

            let signature = ed25519_dalek::Signature::from_bytes(&signature_bytes);

            if verifying_key.verify_strict(yaml_bytes, &signature).is_err() {
                return Err(RulesetValidationError::C4InvalidSignature {
                    reason: "signature does not verify".to_string(),
                });
            }

            let is_trusted = trusted_keys
                .iter()
                .any(|tk| tk.public_key == public_key_bytes);

            if is_trusted {
                Ok(())
            } else {
                let fingerprint = compute_fingerprint(&public_key_bytes);
                Err(RulesetValidationError::C4UntrustedKey {
                    key_fingerprint: fingerprint,
                })
            }
        }
    }
}

fn compute_fingerprint(public_key: &[u8; 32]) -> String {
    let hash = Sha256::digest(public_key);
    hash.iter().map(|b| format!("{:02x}", b)).collect()
}
