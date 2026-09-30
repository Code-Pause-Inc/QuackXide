#![no_main]

use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;
use platform_auth::keygen::MIN_RSA_BITS;
use platform_auth::{JwtVerifier, generate_rs256_keypair};

const ISS: &str = "urn:platform:auth";
const AUD: &str = "urn:platform:drive";

static VERIFIERS: LazyLock<[JwtVerifier; 2]> = LazyLock::new(|| {
    let keypair = generate_rs256_keypair(MIN_RSA_BITS).expect("keygen");
    [
        JwtVerifier::hs256("fuzz-secret", ISS, AUD),
        JwtVerifier::rs256_from_jwks(&keypair.jwks_json, ISS, AUD).expect("verifier"),
    ]
});

fuzz_target!(|token: &str| {
    for verifier in VERIFIERS.iter() {
        assert!(verifier.verify(token).is_err());
    }
});
