use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use skill_scanner_ruleset::{
    verify_ruleset_signature, RulesetValidationError, TrustPolicy, TrustedKey,
};
use static_assertions::assert_impl_all;

const YAML: &[u8] = b"id: test-rule\nmessage: test message";

fn make_key(seed: [u8; 32]) -> (SigningKey, [u8; 32]) {
    let sk = SigningKey::from_bytes(&seed);
    let pk = sk.verifying_key().to_bytes();
    (sk, pk)
}

fn sign_wire(yaml: &[u8], sk: &SigningKey, pk: &[u8; 32]) -> [u8; 96] {
    let sig = sk.sign(yaml).to_bytes();
    let mut wire = [0u8; 96];
    wire[0..64].copy_from_slice(&sig);
    wire[64..96].copy_from_slice(pk);
    wire
}

fn trusted_key(id: &str, pk: [u8; 32]) -> TrustedKey {
    TrustedKey {
        identifier: id.to_string(),
        public_key: pk,
    }
}

fn fingerprint(pk: &[u8; 32]) -> String {
    let hash = Sha256::digest(pk);
    hash.iter().map(|b| format!("{:02x}", b)).collect()
}

// AC1: Unverified + sig=None → Ok
#[test]
fn ac1_unverified_sig_none_ok() {
    let result = verify_ruleset_signature(YAML, None, &TrustPolicy::Unverified);
    assert!(result.is_ok(), "Unverified + sig=None must return Ok");
}

// AC2: Unverified + sig=Some(any 96 bytes) → Ok
#[test]
fn ac2_unverified_sig_some_ok() {
    let wire = [0xAB; 96];
    let result = verify_ruleset_signature(YAML, Some(&wire), &TrustPolicy::Unverified);
    assert!(result.is_ok(), "Unverified + sig=Some(96) must return Ok");
}

// AC3: Unverified + sig=Some(empty) → Ok (Unverified ignores sig)
#[test]
fn ac3_unverified_empty_sig_ok() {
    let result = verify_ruleset_signature(YAML, Some(&[]), &TrustPolicy::Unverified);
    assert!(
        result.is_ok(),
        "Unverified + sig=Some(empty) must return Ok"
    );
}

// AC4: RequireSignature{[K]} + sig=None → C4MissingSignature
#[test]
fn ac4_require_sig_none_missing() {
    let (_, pk) = make_key([0u8; 32]);
    let policy = TrustPolicy::RequireSignature {
        trusted_keys: vec![trusted_key("k1", pk)],
    };
    let err = verify_ruleset_signature(YAML, None, &policy).unwrap_err();
    assert_eq!(
        err.code(),
        "RULESET_C4_MISSING_SIGNATURE",
        "sig=None with RequireSignature must produce RULESET_C4_MISSING_SIGNATURE"
    );
}

// AC5: RequireSignature + sig=Some(0 bytes) → C4InvalidSignature
#[test]
fn ac5_require_sig_0_bytes_invalid() {
    let (_, pk) = make_key([0u8; 32]);
    let policy = TrustPolicy::RequireSignature {
        trusted_keys: vec![trusted_key("k1", pk)],
    };
    let err = verify_ruleset_signature(YAML, Some(&[]), &policy).unwrap_err();
    assert_eq!(
        err.code(),
        "RULESET_C4_INVALID_SIGNATURE",
        "0-byte sig must produce RULESET_C4_INVALID_SIGNATURE"
    );
}

// AC6: RequireSignature + sig=Some(95 bytes) → C4InvalidSignature
#[test]
fn ac6_require_sig_95_bytes_invalid() {
    let (_, pk) = make_key([0u8; 32]);
    let policy = TrustPolicy::RequireSignature {
        trusted_keys: vec![trusted_key("k1", pk)],
    };
    let err = verify_ruleset_signature(YAML, Some(&[0xAA; 95]), &policy).unwrap_err();
    assert_eq!(
        err.code(),
        "RULESET_C4_INVALID_SIGNATURE",
        "95-byte sig must produce RULESET_C4_INVALID_SIGNATURE"
    );
}

// AC7: RequireSignature + sig=Some(97 bytes) → C4InvalidSignature
#[test]
fn ac7_require_sig_97_bytes_invalid() {
    let (_, pk) = make_key([0u8; 32]);
    let policy = TrustPolicy::RequireSignature {
        trusted_keys: vec![trusted_key("k1", pk)],
    };
    let err = verify_ruleset_signature(YAML, Some(&[0xAA; 97]), &policy).unwrap_err();
    assert_eq!(
        err.code(),
        "RULESET_C4_INVALID_SIGNATURE",
        "97-byte sig must produce RULESET_C4_INVALID_SIGNATURE"
    );
}

// AC8: RequireSignature + sig=Some(96 deterministic garbage) → C4InvalidSignature("signature does not verify")
#[test]
fn ac8_require_sig_96_invalid_bytes() {
    let (_, pk) = make_key([0u8; 32]);
    let policy = TrustPolicy::RequireSignature {
        trusted_keys: vec![trusted_key("k1", pk)],
    };
    let bad_wire = [0xDE; 96]; // deterministic, not a valid signature
    let err = verify_ruleset_signature(YAML, Some(&bad_wire), &policy).unwrap_err();
    assert_eq!(
        err.code(),
        "RULESET_C4_INVALID_SIGNATURE",
        "invalid 96-byte sig must produce RULESET_C4_INVALID_SIGNATURE"
    );
}

// AC9: RequireSignature{[K]} + valid sig by K → Ok
#[test]
fn ac9_valid_sig_trusted_key_ok() {
    let (sk, pk) = make_key([0u8; 32]);
    let wire = sign_wire(YAML, &sk, &pk);
    let policy = TrustPolicy::RequireSignature {
        trusted_keys: vec![trusted_key("k1", pk)],
    };
    let result = verify_ruleset_signature(YAML, Some(&wire), &policy);
    assert!(result.is_ok(), "valid sig by trusted key must return Ok");
}

// AC10: RequireSignature{[K1]} + valid sig by K2 (different key) → C4UntrustedKey with correct fingerprint
#[test]
fn ac10_valid_sig_untrusted_key_rejected() {
    let (_, pk1) = make_key([0u8; 32]);
    let (sk2, pk2) = make_key([1u8; 32]);
    let policy = TrustPolicy::RequireSignature {
        trusted_keys: vec![trusted_key("k1", pk1)],
    };
    let wire = sign_wire(YAML, &sk2, &pk2);
    let err = verify_ruleset_signature(YAML, Some(&wire), &policy).unwrap_err();
    assert_eq!(
        err.code(),
        "RULESET_C4_UNTRUSTED_KEY",
        "valid sig by untrusted key must produce RULESET_C4_UNTRUSTED_KEY"
    );
    let expected_fp = fingerprint(&pk2);
    if let RulesetValidationError::C4UntrustedKey { key_fingerprint } = &err {
        assert_eq!(
            key_fingerprint, &expected_fp,
            "key_fingerprint must be SHA-256 fingerprint of signer's public key"
        );
    } else {
        panic!("expected C4UntrustedKey, got {:?}", err);
    }
}

// AC11: valid sig over original yaml, but tampered yaml passed → C4InvalidSignature
#[test]
fn ac11_tampered_yaml_sig_invalid() {
    let (sk, pk) = make_key([0u8; 32]);
    let original = b"id: test-rule\nmessage: original";
    let tampered = b"id: test-rule\nmessage: tampered";
    let wire = sign_wire(original, &sk, &pk);
    let policy = TrustPolicy::RequireSignature {
        trusted_keys: vec![trusted_key("k1", pk)],
    };
    let err = verify_ruleset_signature(tampered, Some(&wire), &policy).unwrap_err();
    assert_eq!(
        err.code(),
        "RULESET_C4_INVALID_SIGNATURE",
        "sig over different data must produce RULESET_C4_INVALID_SIGNATURE"
    );
}

// AC12: RequireSignature{[]} + valid sig → C4UntrustedKey (empty list = no one trusted)
#[test]
fn ac12_empty_trusted_keys_always_untrusted() {
    let (sk, pk) = make_key([0u8; 32]);
    let wire = sign_wire(YAML, &sk, &pk);
    let policy = TrustPolicy::RequireSignature {
        trusted_keys: vec![],
    };
    let err = verify_ruleset_signature(YAML, Some(&wire), &policy).unwrap_err();
    assert_eq!(
        err.code(),
        "RULESET_C4_UNTRUSTED_KEY",
        "empty trusted_keys must always produce RULESET_C4_UNTRUSTED_KEY"
    );
}

// AC13: RequireSignature{[K1,K2,K3]} + valid sig by K2 → Ok (any-of semantics)
#[test]
fn ac13_any_of_trusted_keys_ok() {
    let (_, pk1) = make_key([0u8; 32]);
    let (sk2, pk2) = make_key([1u8; 32]);
    let (_, pk3) = make_key([2u8; 32]);
    let wire = sign_wire(YAML, &sk2, &pk2);
    let policy = TrustPolicy::RequireSignature {
        trusted_keys: vec![
            trusted_key("k1", pk1),
            trusted_key("k2", pk2),
            trusted_key("k3", pk3),
        ],
    };
    let result = verify_ruleset_signature(YAML, Some(&wire), &policy);
    assert!(result.is_ok(), "sig by any trusted key must return Ok");
}

// AC14: RequireSignature{[K1,K1]} (duplicate) + valid sig by K1 → Ok
#[test]
fn ac14_duplicate_trusted_keys_ok() {
    let (sk1, pk1) = make_key([0u8; 32]);
    let wire = sign_wire(YAML, &sk1, &pk1);
    let policy = TrustPolicy::RequireSignature {
        trusted_keys: vec![trusted_key("k1-a", pk1), trusted_key("k1-b", pk1)],
    };
    let result = verify_ruleset_signature(YAML, Some(&wire), &policy);
    assert!(
        result.is_ok(),
        "duplicate trusted keys + valid sig must return Ok"
    );
}

// AC15: error.code() returns stable strings for all three C4 variants
#[test]
fn ac15_error_codes_stable() {
    let (_, pk) = make_key([0u8; 32]);
    let policy = TrustPolicy::RequireSignature {
        trusted_keys: vec![trusted_key("k1", pk)],
    };

    let missing = verify_ruleset_signature(YAML, None, &policy).unwrap_err();
    assert_eq!(missing.code(), "RULESET_C4_MISSING_SIGNATURE");

    let invalid = verify_ruleset_signature(YAML, Some(&[]), &policy).unwrap_err();
    assert_eq!(invalid.code(), "RULESET_C4_INVALID_SIGNATURE");

    let (sk2, pk2) = make_key([1u8; 32]);
    let wire2 = sign_wire(YAML, &sk2, &pk2);
    let untrusted = verify_ruleset_signature(YAML, Some(&wire2), &policy).unwrap_err();
    assert_eq!(untrusted.code(), "RULESET_C4_UNTRUSTED_KEY");
}

// AC16: determinism — 100 calls same input → byte-equal Result
#[test]
fn ac16_determinism_100_calls() {
    let (sk, pk) = make_key([0u8; 32]);
    let wire = sign_wire(YAML, &sk, &pk);
    let policy = TrustPolicy::RequireSignature {
        trusted_keys: vec![trusted_key("k1", pk)],
    };
    let first = format!("{:?}", verify_ruleset_signature(YAML, Some(&wire), &policy));
    for _ in 0..99 {
        let r = format!("{:?}", verify_ruleset_signature(YAML, Some(&wire), &policy));
        assert_eq!(r, first, "verify_ruleset_signature must be deterministic");
    }
}

// AC17: no I/O in trust.rs source
#[test]
fn ac17_no_io_in_trust_source() {
    let workspace_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let trust_path = workspace_root
        .join("crates")
        .join("ruleset")
        .join("src")
        .join("trust.rs");
    let src = std::fs::read_to_string(&trust_path)
        .unwrap_or_else(|e| panic!("failed to read trust.rs: {}", e));
    let forbidden = [
        "std::fs",
        "std::net",
        "std::process",
        "tokio::",
        "reqwest::",
    ];
    for pat in &forbidden {
        assert!(
            !src.contains(pat),
            "trust.rs must not contain '{}': found forbidden I/O pattern",
            pat
        );
    }
}

// AC18: re-export compiles
#[test]
fn ac18_reexport_compiles() {
    let _ = skill_scanner_ruleset::verify_ruleset_signature;
}

// AC19: TrustPolicy and TrustedKey implement required trait bounds
#[test]
fn ac19_trait_bounds() {
    assert_impl_all!(TrustPolicy: std::fmt::Debug, Clone, PartialEq, Eq, Send, Sync);
    assert_impl_all!(TrustedKey: std::fmt::Debug, Clone, PartialEq, Eq, Send, Sync);
}

// AC20: constant-time verification — max/min timing ratio < 50x across rejection paths
#[test]
fn ac20_constant_time_bound() {
    use std::time::Instant;
    let (sk, pk) = make_key([0u8; 32]);
    let valid_wire = sign_wire(YAML, &sk, &pk);
    let policy = TrustPolicy::RequireSignature {
        trusted_keys: vec![trusted_key("k1", pk)],
    };
    let mut times: Vec<u128> = Vec::with_capacity(256);
    for i in 0u8..=255 {
        let mut bad_wire = [0u8; 96];
        bad_wire[0] = i;
        bad_wire[63] = 255u8.wrapping_sub(i);
        bad_wire[64] = i.wrapping_add(1);
        let start = Instant::now();
        let _ = verify_ruleset_signature(YAML, Some(&bad_wire), &policy);
        times.push(start.elapsed().as_nanos());
    }
    let start = Instant::now();
    let _ = verify_ruleset_signature(YAML, Some(&valid_wire), &policy);
    times.push(start.elapsed().as_nanos());
    let max_t = *times.iter().max().unwrap();
    let min_t = times.iter().copied().filter(|&t| t > 0).min().unwrap_or(1);
    let ratio = max_t as f64 / min_t as f64;
    assert!(
        ratio < 50.0,
        "timing ratio max/min={:.1}x must be < 50x (constant-time bound)",
        ratio
    );
}

// AC21: key_fingerprint is lowercase hex SHA-256 of signer's public key, exactly 64 chars, no prefix
#[test]
fn ac21_fingerprint_format() {
    let (_, pk1) = make_key([0u8; 32]);
    let (sk2, pk2) = make_key([1u8; 32]);
    let wire = sign_wire(YAML, &sk2, &pk2);
    let policy = TrustPolicy::RequireSignature {
        trusted_keys: vec![trusted_key("k1", pk1)],
    };
    let err = verify_ruleset_signature(YAML, Some(&wire), &policy).unwrap_err();
    if let RulesetValidationError::C4UntrustedKey { key_fingerprint } = err {
        assert_eq!(
            key_fingerprint.len(),
            64,
            "fingerprint must be exactly 64 chars"
        );
        assert!(
            key_fingerprint
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "fingerprint must be lowercase hex, got: {}",
            key_fingerprint
        );
        assert!(
            !key_fingerprint.starts_with("sha256:"),
            "fingerprint must not have 'sha256:' prefix"
        );
        assert_eq!(
            key_fingerprint,
            fingerprint(&pk2),
            "fingerprint must equal lowercase hex(SHA-256(signer_pubkey))"
        );
    } else {
        panic!("expected C4UntrustedKey");
    }
}

// AC22: wire format — sig at bytes 0..64, pubkey at 64..96
#[test]
fn ac22_wire_format_byte_offsets() {
    let (sk, pk) = make_key([0u8; 32]);
    let sig = sk.sign(YAML).to_bytes();

    // Correctly laid out wire: sig@0..64, pk@64..96 — must verify Ok
    let mut correct_wire = [0u8; 96];
    correct_wire[0..64].copy_from_slice(&sig);
    correct_wire[64..96].copy_from_slice(&pk);
    let policy = TrustPolicy::RequireSignature {
        trusted_keys: vec![trusted_key("k1", pk)],
    };
    assert!(
        verify_ruleset_signature(YAML, Some(&correct_wire), &policy).is_ok(),
        "correctly formatted wire (sig@0..64, pk@64..96) must verify Ok"
    );

    // Corrupt sig bytes (0..64) — must fail even though pk@64..96 is correct
    let mut corrupted_sig_wire = correct_wire;
    corrupted_sig_wire[0] ^= 0xFF;
    assert!(
        verify_ruleset_signature(YAML, Some(&corrupted_sig_wire), &policy).is_err(),
        "corrupted sig bytes must cause verification failure"
    );

    // Corrupt pk bytes (64..96) — should produce UntrustedKey or InvalidSig
    let mut corrupted_pk_wire = correct_wire;
    corrupted_pk_wire[64] ^= 0xFF;
    assert!(
        verify_ruleset_signature(YAML, Some(&corrupted_pk_wire), &policy).is_err(),
        "corrupted pk bytes must cause failure"
    );
}
