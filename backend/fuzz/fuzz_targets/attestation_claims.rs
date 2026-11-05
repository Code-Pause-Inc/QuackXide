#![no_main]
//! Signs fuzzer-supplied claims, so claim decoding and the release policy
//! are reached; `attestation_token` cannot get past the signature. A JSON
//! object's fields replace those of a valid claim set; other JSON is signed
//! as-is.

use std::sync::LazyLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use libfuzzer_sys::fuzz_target;
use platform_enclave::simulated_token::{SIMULATED_IMAGE_DIGEST, SimulatedClaims, TokenSigner};
use platform_enclave::token::{
    CLOCK_SKEW_LEEWAY_SECS, MAX_TOKEN_LIFETIME_SECS, ReleasePolicy, SIMULATED_AUDIENCE,
    TokenVerifier,
};
use serde_json::Value;

const ISS: &str = "urn:fuzz:attestation";
const NONCE: &str = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc";

static SIGNER: LazyLock<TokenSigner> =
    LazyLock::new(|| TokenSigner::generate(ISS, SimulatedClaims::default()));

static VERIFIER: LazyLock<TokenVerifier> = LazyLock::new(|| {
    let policy = ReleasePolicy {
        allowed_image_digests: vec![SIMULATED_IMAGE_DIGEST.into()],
    };
    TokenVerifier::new(&SIGNER.jwks(), ISS, SIMULATED_AUDIENCE, policy).expect("verifier")
});

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after 1970")
        .as_secs()
}

fuzz_target!(|data: &[u8]| {
    let Ok(input) = serde_json::from_slice::<Value>(data) else {
        return;
    };
    let claims = match input {
        Value::Object(fields) => {
            let now = now();
            let mut claims = SIGNER.claims_json(
                SIMULATED_AUDIENCE,
                &[NONCE.into()],
                now,
                Duration::from_secs(600),
            );
            claims.as_object_mut().expect("object").extend(fields);
            claims
        }
        other => other,
    };
    let token = SIGNER.sign_claims(&claims);
    // Whatever the claims, a token that verifies meets the release policy
    // and the age rules, judged from the claims that were signed.
    if let Ok(verified) = VERIFIER.verify(&token, &[NONCE.into()]) {
        assert_eq!(verified.image_digest(), SIMULATED_IMAGE_DIGEST);
        assert_eq!(verified.hwmodel(), "GCP_INTEL_TDX");
        assert!(verified.nonces().iter().any(|n| n == NONCE));
        assert_eq!(claims["swname"], "CONFIDENTIAL_SPACE");
        assert_eq!(claims["dbgstat"], "disabled-since-boot");
        let attributes = &claims["submods"]["confidential_space"]["support_attributes"];
        assert!(attributes.as_array().is_some_and(|a| a.iter().any(|v| v == "STABLE")));
        let iat = claims["iat"].as_u64().expect("verified iat is an integer");
        let exp = claims["exp"].as_u64().expect("verified exp is an integer");
        assert!(iat <= now() + CLOCK_SKEW_LEEWAY_SECS);
        assert!(iat <= exp && exp - iat <= MAX_TOKEN_LIFETIME_SECS);
    }
});
