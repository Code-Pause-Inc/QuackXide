//! Evidence-bundle vectors (`fixtures/attestation/bundles.json`) for the
//! browser module's tests. The bundles carry no token: tests mint one with
//! each entry's `binding_nonce` as its second nonce.

use std::collections::BTreeMap;
use std::path::PathBuf;

use platform_crypto::{EnvelopeSuite, ResultSigningKey, TenantKeypair};
use platform_enclave::binding::EnclaveKeyBinding;
use platform_enclave::bundle::{AttestationBundle, KeyWire, SigningKeysWire};
use platform_enclave::config::config_digest;
use platform_enclave::simulated_token::{DEFAULT_SIM_ISSUER, SIMULATED_IMAGE_DIGEST};
use serde::{Deserialize, Serialize};
use serde_json::Value;

const NOTE: &str = "Test-only keys. Written by `cargo test -p platform-enclave --test attestation_vectors -- --ignored write_vectors`.";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Simulator {
    issuer: String,
    image_digest: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    /// An `AttestationBundle` without its `token`.
    bundle: Value,
    env: BTreeMap<String, String>,
    /// The second nonce a token must carry: the binding digest, base64url.
    binding_nonce: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Vectors {
    note: String,
    simulator: Simulator,
    bundles: BTreeMap<String, Entry>,
}

fn path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../fixtures/attestation/bundles.json")
}

fn bundle_of(entry: &Entry) -> AttestationBundle {
    let mut bundle = entry.bundle.clone();
    bundle["token"] = Value::String(String::new());
    serde_json::from_value(bundle).expect("a bundle without its token")
}

fn binding_of(bundle: &AttestationBundle, env: &BTreeMap<String, String>) -> EnclaveKeyBinding {
    let keys = bundle.bound_keys().expect("the bundle's keys decode");
    keys.binding(config_digest(|name| env.get(name).cloned()))
}

#[test]
fn vectors_match_the_code() {
    let vectors: Vectors =
        serde_json::from_slice(&std::fs::read(path()).expect("fixtures/attestation/bundles.json"))
            .expect("the vector file parses");
    assert_eq!(vectors.simulator.issuer, DEFAULT_SIM_ISSUER);
    assert_eq!(vectors.simulator.image_digest, SIMULATED_IMAGE_DIGEST);
    let names: Vec<_> = vectors.bundles.keys().map(String::as_str).collect();
    assert_eq!(names, ["bound", "hpk1", "loosened", "other"]);
    for (name, entry) in &vectors.bundles {
        assert!(
            entry.bundle.get("token").is_none(),
            "{name} carries a token"
        );
        let bundle = bundle_of(entry);
        let binding = binding_of(&bundle, &entry.env);
        assert_eq!(binding.key_id(), bundle.key_id, "{name} key_id");
        assert_eq!(
            binding.key_id(),
            entry.binding_nonce,
            "{name} binding_nonce"
        );
    }
    let keys = |name: &str| bundle_of(&vectors.bundles[name]).request_key;
    assert_eq!(keys("bound"), keys("loosened"));
    assert_ne!(keys("bound"), keys("other"));
    assert_eq!(keys("hpk1").suite, "HPK1");
}

fn entry(suite: EnvelopeSuite, seed: &[u8], min_cohort: &str) -> Entry {
    let request = TenantKeypair::derive(suite, seed).public_key();
    entry_with(
        KeyWire::from_public_key(&request),
        SigningKeysWire::from_verifying_keys(&ResultSigningKey::generate().verifying_keys()),
        min_cohort,
    )
}

fn entry_with(request_key: KeyWire, signing_keys: SigningKeysWire, min_cohort: &str) -> Entry {
    let env = BTreeMap::from([
        ("TEE_ATTESTATION_REQUIRED".to_owned(), "true".to_owned()),
        ("FEATURE_ZK_ENABLED".to_owned(), "true".to_owned()),
        ("RESEARCH_MIN_COHORT_SIZE".to_owned(), min_cohort.to_owned()),
    ]);
    let mut bundle = AttestationBundle {
        version: 1,
        key_id: String::new(),
        token: String::new(),
        request_key,
        signing_keys,
        kms_public_key: None,
        tls_spki_sha256: None,
    };
    let nonce = binding_of(&bundle, &env).key_id();
    bundle.key_id.clone_from(&nonce);
    let mut bundle = serde_json::to_value(&bundle).expect("serialize");
    bundle.as_object_mut().expect("object").remove("token");
    Entry {
        bundle,
        env,
        binding_nonce: nonce,
    }
}

#[test]
#[ignore = "writes fixtures/attestation/bundles.json with fresh signing keys"]
fn write_vectors() {
    let bound = entry(
        EnvelopeSuite::Hpk2,
        b"quackxide-test-attestation-bound",
        "11",
    );
    let wire = |e: &Entry| -> (KeyWire, SigningKeysWire) {
        let b = bundle_of(e);
        (b.request_key, b.signing_keys)
    };
    let (request_key, signing_keys) = wire(&bound);
    let loosened = entry_with(request_key, signing_keys, "2");
    let other = entry(
        EnvelopeSuite::Hpk2,
        b"quackxide-test-attestation-other",
        "11",
    );
    let hpk1 = entry(
        EnvelopeSuite::Hpk1,
        b"quackxide-test-attestation-hpk1",
        "11",
    );
    let vectors = Vectors {
        note: NOTE.to_owned(),
        simulator: Simulator {
            issuer: DEFAULT_SIM_ISSUER.to_owned(),
            image_digest: SIMULATED_IMAGE_DIGEST.to_owned(),
        },
        bundles: BTreeMap::from([
            ("bound".to_owned(), bound),
            ("other".to_owned(), other),
            ("loosened".to_owned(), loosened),
            ("hpk1".to_owned(), hpk1),
        ]),
    };
    let mut json = serde_json::to_string_pretty(&vectors).expect("serialize");
    json.push('\n');
    std::fs::write(path(), json).expect("write the vector file");
}
