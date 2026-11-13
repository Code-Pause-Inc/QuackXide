//! `HPK2` vectors from implementations other than this crate (ADR 0007,
//! "Proof of interoperability"), written by `frontend/scripts/hpk2-vectors.mjs`:
//!
//! - `fixtures/envelope/hpk2-kem.json`: X-Wing values from `@noble/post-quantum`.
//! - `fixtures/envelope/hpk2-js-sealed.json`: frames sealed by `hpke-js`.
//!
//! Every seed in them is public and test-only (`docs/DATA_POLICY.md`).

use std::path::PathBuf;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use platform_crypto::{CryptoError, EnvelopeSuite, SuitePolicy, TenantKeypair, info};
use serde_json::Value;
use x_wing::{Decapsulate as _, DecapsulationKey, Decapsulator as _, KeyExport as _};

fn fixture(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../fixtures/envelope")
        .join(name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_str(&text).expect("fixture JSON")
}

fn bytes(value: &Value, key: &str) -> Vec<u8> {
    B64.decode(
        value[key]
            .as_str()
            .unwrap_or_else(|| panic!("missing {key}")),
    )
    .expect("base64")
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("missing {key}"))
}

fn keypair(seed: &[u8]) -> TenantKeypair {
    let framed = [&b"HPK2"[..], seed].concat();
    TenantKeypair::from_private_key_bytes(&framed, SuitePolicy::PRODUCTION).expect("HPK2 seed")
}

#[test]
fn xwing_kem_matches_noble() {
    let vectors = fixture("hpk2-kem.json");
    let vectors = vectors["vectors"].as_array().expect("vectors");
    assert!(!vectors.is_empty());
    for v in vectors {
        let seed: [u8; 32] = bytes(v, "seed_b64").try_into().expect("32-byte seed");
        let public_key = bytes(v, "public_key_b64");

        let dk = DecapsulationKey::from(seed);
        let ek = dk.encapsulation_key();
        assert_eq!(ek.to_bytes().as_slice(), public_key, "public key");
        // hpke's X-Wing key from the same seed is the same key.
        assert_eq!(
            keypair(&seed).public_key().to_raw(),
            public_key,
            "hpke public key"
        );

        let randomness: [u8; 64] = bytes(v, "encapsulation_randomness_b64")
            .try_into()
            .expect("64 bytes");
        let (ciphertext, shared) = ek.encapsulate_deterministic(&randomness.into());
        assert_eq!(
            ciphertext.as_slice(),
            bytes(v, "ciphertext_b64"),
            "ciphertext"
        );
        assert_eq!(
            shared.as_slice(),
            bytes(v, "shared_secret_b64"),
            "shared secret"
        );

        let noble_ct = x_wing::Ciphertext::try_from(bytes(v, "ciphertext_b64").as_slice())
            .expect("1120 bytes");
        assert_eq!(
            dk.decapsulate(&noble_ct).as_slice(),
            bytes(v, "shared_secret_b64")
        );
    }
}

fn info_for(envelope: &Value) -> Vec<u8> {
    let f: Vec<&str> = envelope["fields"]
        .as_array()
        .expect("fields")
        .iter()
        .map(|v| v.as_str().expect("field"))
        .collect();
    let suite = EnvelopeSuite::Hpk2;
    match text(envelope, "kind") {
        "connector_object" => info::connector_object(suite, f[0], f[1], f[2]),
        "snapshot_manifest" => info::snapshot_manifest(suite, f[0], f[1], f[2]),
        "steward_upload" => info::steward_upload(suite, f[0], f[1], f[2]),
        "research_result" => info::research_result(suite, f[0], f[1]),
        other => panic!("unknown kind {other}"),
    }
}

fn recipient(vectors: &Value, name: &str) -> TenantKeypair {
    let r = vectors["recipients"]
        .as_array()
        .expect("recipients")
        .iter()
        .find(|r| r["name"] == name)
        .expect("recipient");
    let kp = keypair(&bytes(r, "seed_b64"));
    assert_eq!(
        kp.public_key().to_raw(),
        bytes(r, "public_b64"),
        "recipient {name}"
    );
    kp
}

#[test]
fn hpk2_opens_hpke_js_frames() {
    let vectors = fixture("hpk2-js-sealed.json");
    let envelopes = vectors["envelopes"].as_array().expect("envelopes");
    assert!(envelopes.len() >= 4);
    for e in envelopes {
        let info = info_for(e);
        // The Rust builders and the TypeScript generator agree on the string.
        assert_eq!(info, text(e, "info").as_bytes());
        // Tenant envelopes use empty AAD; the binding is in `info`.
        assert_eq!(text(e, "aad_b64"), "");
        let to = recipient(&vectors, text(e, "recipient"));
        let opened = to
            .open_envelope(&info, &bytes(e, "envelope_b64"))
            .expect("open");
        assert_eq!(opened.expose(), text(e, "plaintext").as_bytes());
    }
}

#[test]
fn hpk2_refuses_negative_vectors() {
    let vectors = fixture("hpk2-js-sealed.json");
    let negative = vectors["negative"].as_array().expect("negative");
    assert_eq!(negative.len(), 4);
    for n in negative {
        let to = recipient(&vectors, text(n, "recipient"));
        let result = to.open_envelope(text(n, "info").as_bytes(), &bytes(n, "envelope_b64"));
        let case = text(n, "case");
        match text(n, "expect") {
            "open_failed" => assert!(matches!(result, Err(CryptoError::OpenFailed)), "{case}"),
            "suite_mismatch" => {
                assert!(matches!(result, Err(CryptoError::SuiteMismatch)), "{case}")
            }
            other => panic!("unknown expectation {other}"),
        }
    }
}
