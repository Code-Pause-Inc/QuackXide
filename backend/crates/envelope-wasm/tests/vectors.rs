//! Cross-implementation envelope vectors (`fixtures/envelope/`).
//!
//! `hpk1.json` is written by [`generate`] below from public seeds and a
//! seeded RNG, so it is reproducible: the first test fails if the file and
//! the generator disagree. Regenerate it with
//! `UPDATE_ENVELOPE_VECTORS=1 cargo test -p envelope-wasm --test vectors`.
//! `frontend/src/lib/crypto/envelope.test.ts` checks the same file against
//! the wasm build.
//!
//! `hpk1-browser-sealed.json` holds envelopes sealed by the wasm build
//! (`frontend/scripts/browser-sealed-vectors.mjs`); they must open here.
//!
//! Every key in these files is test-only: derived from a seed published in
//! this file, never used for real data (`docs/DATA_POLICY.md`).

use std::path::PathBuf;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use envelope_wasm::{
    connector_object_info, research_result_info, snapshot_manifest_info, steward_upload_info,
};
use platform_crypto::{TenantKeypair, hpke_seal_to_tenant_with_rng};
use rand::SeedableRng;
use rand::rngs::StdRng;
use serde_json::{Value, json};

const RNG_SEED: [u8; 32] = *b"envelope vectors, test-only seed";
const RECIPIENTS: [(&str, &str); 2] = [
    ("a", "test-only envelope recipient a"),
    ("b", "test-only envelope recipient b"),
];
const TENANT: &str = "6f2c8a2e-1111-4222-8333-444455556666";
const DATASET: &str = "00000000-dddd-4ddd-8ddd-000000000001";
const OBJECT: &str = "00000000-aaaa-4bbb-8ccc-000000000001";
const PLAINTEXT: &str = "synthetic cohort rows: site-a,42\nsite-b,17\n";

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../fixtures/envelope")
}

fn recipient(name: &str) -> TenantKeypair {
    let (_, seed) = RECIPIENTS
        .iter()
        .find(|(n, _)| *n == name)
        .expect("known recipient");
    TenantKeypair::derive(seed.as_bytes())
}

fn utf8(bytes: Vec<u8>) -> String {
    String::from_utf8(bytes).expect("info strings are UTF-8")
}

fn generate() -> Value {
    let mut rng = StdRng::from_seed(RNG_SEED);
    let a = recipient("a");
    let b = recipient("b");
    let a_raw = a.public_key().to_raw();

    let recipients: Vec<Value> = RECIPIENTS
        .iter()
        .map(|(name, seed)| {
            json!({
                "name": name,
                "seed_utf8": seed,
                "public_b64": B64.encode(recipient(name).public_key().to_raw()),
            })
        })
        .collect();

    let enrollment = json!([
        { "name": "valid", "public_b64": B64.encode(&a_raw), "valid": true },
        { "name": "wrong length (31 bytes)", "public_b64": B64.encode(&a_raw[..31]), "valid": false },
        { "name": "wrong length (33 bytes)", "public_b64": B64.encode([&a_raw[..], &[0]].concat()), "valid": false },
        { "name": "empty", "public_b64": "", "valid": false },
        { "name": "bad base64", "public_b64": "not base64!", "valid": false },
    ]);

    let info = json!([
        { "kind": "steward_upload", "fields": [TENANT, DATASET, OBJECT],
          "info": utf8(steward_upload_info(TENANT, DATASET, OBJECT).unwrap()) },
        { "kind": "connector_object", "fields": [TENANT, "lab-results", OBJECT],
          "info": utf8(connector_object_info(TENANT, "lab-results", OBJECT).unwrap()) },
        { "kind": "snapshot_manifest", "fields": [TENANT, "lab-results", "00000000000000000001"],
          "info": utf8(snapshot_manifest_info(TENANT, "lab-results", "00000000000000000001").unwrap()) },
        { "kind": "research_result", "fields": [TENANT, DATASET],
          "info": utf8(research_result_info(TENANT, DATASET).unwrap()) },
    ]);
    let refused_fields = json!(["", "|", "a|b"]);

    let upload_info = steward_upload_info(TENANT, DATASET, OBJECT).unwrap();
    let other_info = steward_upload_info(TENANT, DATASET, DATASET).unwrap();
    let seal = |to: &TenantKeypair, rng: &mut StdRng| {
        hpke_seal_to_tenant_with_rng(&to.public_key(), &upload_info, PLAINTEXT.as_bytes(), rng)
            .expect("seal")
    };
    let to_a = seal(&a, &mut rng);
    let to_b = seal(&b, &mut rng);
    let mut tampered = to_a.clone();
    *tampered.last_mut().expect("non-empty") ^= 0x01;
    let mut relabelled = to_a.clone();
    relabelled[..4].copy_from_slice(b"HPK2");

    let entry = |name: &str, info: &[u8], envelope: &[u8], error: Option<&str>| {
        json!({
            "name": name,
            "recipient": "a",
            "info": utf8(info.to_vec()),
            "plaintext": PLAINTEXT,
            "envelope_b64": B64.encode(envelope),
            "error": error,
        })
    };
    let envelopes = json!([
        entry("opens", &upload_info, &to_a, None),
        entry(
            "tampered ciphertext",
            &upload_info,
            &tampered,
            Some("open failed (ciphertext rejected)")
        ),
        entry(
            "wrong info",
            &other_info,
            &to_a,
            Some("open failed (ciphertext rejected)")
        ),
        entry(
            "wrong recipient",
            &upload_info,
            &to_b,
            Some("open failed (ciphertext rejected)")
        ),
        entry(
            "wrong frame magic",
            &upload_info,
            &relabelled,
            Some("invalid envelope framing")
        ),
        entry(
            "truncated frame",
            &upload_info,
            &to_a[..20],
            Some("invalid envelope framing")
        ),
    ]);

    json!({
        "description": "HPK1 envelope vectors. Test-only: every key derives from a seed published here. Generated by backend/crates/envelope-wasm/tests/vectors.rs.",
        "suite": {
            "magic": "HPK1",
            "kem": "DHKEM(X25519, HKDF-SHA256)",
            "kdf": "HKDF-SHA256",
            "aead": "AES-256-GCM",
            "public_key_bytes": 32,
            "encapped_key_bytes": 32,
            "tag_bytes": 16,
        },
        "recipients": recipients,
        "enrollment": enrollment,
        "info": info,
        "refused_info_fields": refused_fields,
        "envelopes": envelopes,
    })
}

fn read_json(name: &str) -> Value {
    let path = fixtures_dir().join(name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_str(&text).expect("vector file is JSON")
}

fn open(entry: &Value) -> Result<Vec<u8>, String> {
    let keypair = recipient(entry["recipient"].as_str().expect("recipient"));
    let envelope = B64
        .decode(entry["envelope_b64"].as_str().expect("envelope"))
        .expect("base64");
    keypair
        .open_envelope(entry["info"].as_str().expect("info").as_bytes(), &envelope)
        .map(|opened| opened.expose().to_vec())
        .map_err(|e| e.to_string())
}

#[test]
fn committed_vectors_match_the_generator() {
    let generated = generate();
    let mut text = serde_json::to_string_pretty(&generated).expect("serialize");
    text.push('\n');
    if std::env::var_os("UPDATE_ENVELOPE_VECTORS").is_some() {
        std::fs::create_dir_all(fixtures_dir()).expect("fixtures dir");
        std::fs::write(fixtures_dir().join("hpk1.json"), &text).expect("write vectors");
    }
    assert_eq!(
        read_json("hpk1.json"),
        generated,
        "fixtures/envelope/hpk1.json is stale; regenerate it (see this file's header)"
    );
}

#[test]
fn recipients_derive_from_their_published_seeds() {
    for r in read_json("hpk1.json")["recipients"]
        .as_array()
        .expect("recipients")
    {
        let derived = TenantKeypair::derive(r["seed_utf8"].as_str().expect("seed").as_bytes());
        assert_eq!(B64.encode(derived.public_key().to_raw()), r["public_b64"]);
    }
}

#[test]
fn envelope_vectors_open_or_fail_as_recorded() {
    for entry in read_json("hpk1.json")["envelopes"]
        .as_array()
        .expect("envelopes")
    {
        let name = entry["name"].as_str().expect("name");
        match entry["error"].as_str() {
            None => assert_eq!(
                open(entry).unwrap_or_else(|e| panic!("{name}: {e}")),
                entry["plaintext"].as_str().expect("plaintext").as_bytes(),
                "{name}"
            ),
            Some(error) => assert_eq!(open(entry).expect_err(name), error, "{name}"),
        }
    }
}

#[test]
fn info_vectors_match_and_refused_fields_are_refused() {
    let vectors = read_json("hpk1.json");
    for refused in vectors["refused_info_fields"].as_array().expect("refused") {
        let field = refused.as_str().expect("field");
        assert!(steward_upload_info(field, DATASET, OBJECT).is_err());
        assert!(research_result_info(TENANT, field).is_err());
    }
    // The backend's typed wrappers produce the same strings as the vectors.
    let connector = vectors["info"]
        .as_array()
        .expect("info")
        .iter()
        .find(|v| v["kind"] == "connector_object")
        .expect("connector vector");
    let f: Vec<&str> = connector["fields"]
        .as_array()
        .expect("fields")
        .iter()
        .map(|v| v.as_str().expect("field"))
        .collect();
    assert_eq!(
        utf8(platform_crypto::info::connector_object(f[0], f[1], f[2])),
        connector["info"]
    );
}

#[test]
fn browser_sealed_envelopes_open_in_rust() {
    let sealed = read_json("hpk1-browser-sealed.json");
    let envelopes = sealed["envelopes"].as_array().expect("envelopes");
    assert!(!envelopes.is_empty());
    for entry in envelopes {
        assert_eq!(
            open(entry).expect("browser-sealed envelope opens"),
            entry["plaintext"].as_str().expect("plaintext").as_bytes()
        );
    }
}
