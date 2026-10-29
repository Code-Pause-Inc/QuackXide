#![no_main]

use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;
use platform_enclave::simulated_token::{SIMULATED_IMAGE_DIGEST, SimulatedClaims, TokenSigner};
use platform_enclave::token::{ReleasePolicy, SIMULATED_AUDIENCE, TokenVerifier};

const ISS: &str = "urn:fuzz:attestation";

static VERIFIER: LazyLock<TokenVerifier> = LazyLock::new(|| {
    let signer = TokenSigner::generate(ISS, SimulatedClaims::default());
    let policy = ReleasePolicy {
        allowed_image_digests: vec![SIMULATED_IMAGE_DIGEST.into()],
    };
    TokenVerifier::new(&signer.jwks(), ISS, SIMULATED_AUDIENCE, policy).expect("verifier")
});

fuzz_target!(|token: &str| {
    // Without the signer's private key, no input can verify.
    assert!(VERIFIER.verify(token, &["fuzz".into()]).is_err());
    let _ = VERIFIER.knows_kid(token);
});
