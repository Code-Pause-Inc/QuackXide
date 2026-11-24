//! ADR 0010 "Browser verification": the five checks a client runs on an
//! enclave's evidence bundle before it seals a query to the bundle's
//! request key. The browser module (#239) and `enclave-check` both call
//! [`verify_evidence`]; it takes the key set and environment as arguments,
//! so it needs nothing wasm32 lacks.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::binding::EnclaveKeyBinding;
use crate::config::{ConfigPolicy, ConfigRefused, config_digest};
use crate::token::{TokenError, TokenVerifier, VerifiedToken};

/// The keys an evidence bundle names, decoded from its wire form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundKeys {
    /// The request key's suite magic, then its raw public key.
    pub request_key: Vec<u8>,
    pub signing_ed25519: [u8; 32],
    pub signing_ml_dsa_65: Vec<u8>,
    /// Empty until P50.
    pub kms_public_key: Vec<u8>,
    /// `None` until P67.
    pub tls_spki_sha256: Option<[u8; 32]>,
}

impl BoundKeys {
    /// The binding these keys make with `config_digest`.
    pub fn binding(&self, config_digest: [u8; 32]) -> EnclaveKeyBinding {
        EnclaveKeyBinding {
            request_key: self.request_key.clone(),
            signing_ed25519: self.signing_ed25519,
            signing_ml_dsa_65: self.signing_ml_dsa_65.clone(),
            kms_public_key: self.kms_public_key.clone(),
            tls_spki_sha256: self.tls_spki_sha256,
            config_digest,
        }
    }
}

/// An enclave whose evidence passed every check.
#[derive(Debug)]
pub struct VerifiedEnclave {
    /// Recomputed from the bundle's keys and the token's configuration.
    pub key_id: String,
    pub token: VerifiedToken,
}

/// The check an evidence bundle failed, numbered as ADR 0010 numbers them.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EvidenceError {
    #[error("check 1 (signature, issuer, audience, validity): {0}")]
    Signature(TokenError),
    #[error("check 2 (hardware, software, debug, support): {0}")]
    Platform(TokenError),
    #[error("check 3 (image digest): the image is not an allowed release")]
    ImageDigest,
    #[error("check 4 (challenge): the token does not carry this challenge")]
    Challenge,
    #[error("check 5 (binding): the token does not bind these keys and configuration")]
    Binding,
    #[error("check 5 (configuration): {0}")]
    Config(ConfigRefused),
    #[error("the request key is not HPK2 (ADR 0010 \"No downgrade\")")]
    RequestKeySuite,
}

impl From<TokenError> for EvidenceError {
    fn from(err: TokenError) -> Self {
        use TokenError as T;
        match err {
            T::TooLarge
            | T::Malformed
            | T::UnknownKey
            | T::BadSignature
            | T::WrongAlgorithm
            | T::Issuer
            | T::Audience
            | T::Expired
            | T::NotYetValid
            | T::LifetimeTooLong
            | T::BadKeySet
            | T::KeySetUnavailable => Self::Signature(err),
            T::Hardware | T::Software | T::Debug | T::SupportAttributes => Self::Platform(err),
            T::ImageDigest => Self::ImageDigest,
            // `verify_claims` never checks nonces; this one is ours.
            T::Nonce => Self::Challenge,
        }
    }
}

/// Run ADR 0010's five checks on `token` for a bundle that names `keys` and
/// `claimed_key_id`, in order: (1) signature, issuer, audience and validity,
/// (2) platform claims, (3) image digest, (4) exactly two nonces, the first
/// `challenge`, (5) the second nonce is the binding of `keys` and the
/// configuration the token reports, which is `claimed_key_id` and passes
/// `policy`. A request key other than `HPK2` is refused first.
pub fn verify_evidence(
    verifier: &TokenVerifier,
    token: &str,
    challenge: &[u8; 32],
    keys: &BoundKeys,
    claimed_key_id: &str,
    policy: ConfigPolicy,
) -> Result<VerifiedEnclave, EvidenceError> {
    if !keys.request_key.starts_with(b"HPK2") {
        return Err(EvidenceError::RequestKeySuite);
    }
    let verified = verifier.verify_claims(token)?;
    let [first, second] = verified.nonces() else {
        return Err(EvidenceError::Challenge);
    };
    if *first != URL_SAFE_NO_PAD.encode(challenge) {
        return Err(EvidenceError::Challenge);
    }
    let env = verified.container_env();
    let binding = keys.binding(config_digest(|name| env.get(name).cloned()));
    let key_id = binding.key_id();
    if *second != key_id || claimed_key_id != key_id {
        return Err(EvidenceError::Binding);
    }
    policy
        .check(|name| env.get(name).cloned())
        .map_err(EvidenceError::Config)?;
    Ok(VerifiedEnclave {
        key_id,
        token: verified,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::OnceLock;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::simulated_token::{SIMULATED_IMAGE_DIGEST, SimulatedClaims, TokenSigner};
    use crate::token::{
        BROWSER_ATTESTATION_AUDIENCE, ReleasePolicy, SIMULATED_AUDIENCE, nonces_from_bytes,
    };

    const ISSUER: &str = "http://sim-attestation:8070";
    const CHALLENGE: [u8; 32] = [3; 32];

    fn signer() -> &'static TokenSigner {
        static SIGNER: OnceLock<TokenSigner> = OnceLock::new();
        SIGNER.get_or_init(|| TokenSigner::generate(ISSUER, SimulatedClaims::default()))
    }

    fn verifier() -> TokenVerifier {
        TokenVerifier::new(
            &signer().jwks(),
            ISSUER,
            BROWSER_ATTESTATION_AUDIENCE,
            ReleasePolicy {
                allowed_image_digests: vec![SIMULATED_IMAGE_DIGEST.into()],
            },
        )
        .unwrap()
    }

    fn keys() -> BoundKeys {
        BoundKeys {
            request_key: [b"HPK2".as_slice(), &[7; 1216]].concat(),
            signing_ed25519: [8; 32],
            signing_ml_dsa_65: vec![9; 1952],
            kms_public_key: Vec::new(),
            tls_spki_sha256: None,
        }
    }

    fn env(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    /// The binding `keys` make with the configuration `env` reports.
    fn binding(keys: &BoundKeys, env: &BTreeMap<String, String>) -> EnclaveKeyBinding {
        keys.binding(crate::config::config_digest(|n| env.get(n).cloned()))
    }

    /// A token from `claims` binding `keys` and the claims' env to `challenge`.
    fn token_for(claims: SimulatedClaims, keys: &BoundKeys, challenge: &[u8; 32]) -> String {
        let nonces = nonces_from_bytes(&binding(keys, &claims.env).report_data(challenge)).unwrap();
        signer().with_claims(claims).sign(
            BROWSER_ATTESTATION_AUDIENCE,
            &nonces,
            Duration::from_secs(600),
        )
    }

    fn token() -> String {
        token_for(SimulatedClaims::default(), &keys(), &CHALLENGE)
    }

    fn check(
        token: &str,
        keys: &BoundKeys,
        policy: ConfigPolicy,
    ) -> Result<VerifiedEnclave, EvidenceError> {
        let key_id = binding(keys, &BTreeMap::new()).key_id();
        verify_evidence(&verifier(), token, &CHALLENGE, keys, &key_id, policy)
    }

    fn refusal(token: &str) -> EvidenceError {
        check(token, &keys(), ConfigPolicy::SIMULATOR).unwrap_err()
    }

    #[test]
    fn a_bound_bundle_verifies() {
        let verified = check(&token(), &keys(), ConfigPolicy::SIMULATOR).expect("verifies");
        assert_eq!(verified.key_id, binding(&keys(), &BTreeMap::new()).key_id());
    }

    #[test]
    fn a_tampered_token_fails_check_1() {
        let token = token();
        let (head, rest) = token.split_once('.').unwrap();
        let tampered = format!("{head}.{}", rest.replacen('e', "f", 1));
        assert!(matches!(refusal(&tampered), EvidenceError::Signature(_)));
    }

    #[test]
    fn another_signer_fails_check_1() {
        let other = TokenSigner::generate(ISSUER, SimulatedClaims::default());
        let nonces =
            nonces_from_bytes(&binding(&keys(), &BTreeMap::new()).report_data(&CHALLENGE)).unwrap();
        let token = other.sign(
            BROWSER_ATTESTATION_AUDIENCE,
            &nonces,
            Duration::from_secs(600),
        );
        assert_eq!(
            refusal(&token),
            EvidenceError::Signature(TokenError::UnknownKey)
        );
    }

    #[test]
    fn the_enclave_audience_fails_check_1() {
        let nonces =
            nonces_from_bytes(&binding(&keys(), &BTreeMap::new()).report_data(&CHALLENGE)).unwrap();
        let token = signer().sign(SIMULATED_AUDIENCE, &nonces, Duration::from_secs(600));
        assert_eq!(
            refusal(&token),
            EvidenceError::Signature(TokenError::Audience)
        );
    }

    #[test]
    fn an_expired_token_fails_check_1() {
        let nonces =
            nonces_from_bytes(&binding(&keys(), &BTreeMap::new()).report_data(&CHALLENGE)).unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let token = signer().sign_at(
            BROWSER_ATTESTATION_AUDIENCE,
            &nonces,
            now - 7200,
            Duration::from_secs(600),
        );
        assert_eq!(
            refusal(&token),
            EvidenceError::Signature(TokenError::Expired)
        );
    }

    #[test]
    fn a_debug_image_fails_check_2() {
        let claims = SimulatedClaims {
            dbgstat: "enabled".into(),
            ..SimulatedClaims::default()
        };
        assert_eq!(
            refusal(&token_for(claims, &keys(), &CHALLENGE)),
            EvidenceError::Platform(TokenError::Debug)
        );
    }

    #[test]
    fn other_hardware_fails_check_2() {
        let claims = SimulatedClaims {
            hwmodel: "GCP_AMD_SEV".into(),
            ..SimulatedClaims::default()
        };
        assert_eq!(
            refusal(&token_for(claims, &keys(), &CHALLENGE)),
            EvidenceError::Platform(TokenError::Hardware)
        );
    }

    #[test]
    fn an_image_not_allowed_fails_check_3() {
        let claims = SimulatedClaims {
            image_digest: format!("sha256:{}", "0".repeat(64)),
            ..SimulatedClaims::default()
        };
        assert_eq!(
            refusal(&token_for(claims, &keys(), &CHALLENGE)),
            EvidenceError::ImageDigest
        );
    }

    #[test]
    fn another_challenge_fails_check_4() {
        let token = token_for(SimulatedClaims::default(), &keys(), &[4; 32]);
        assert_eq!(refusal(&token), EvidenceError::Challenge);
    }

    #[test]
    fn three_nonces_fail_check_4() {
        let mut nonces =
            nonces_from_bytes(&binding(&keys(), &BTreeMap::new()).report_data(&CHALLENGE)).unwrap();
        nonces.push(nonces[1].clone());
        let token = signer().sign(
            BROWSER_ATTESTATION_AUDIENCE,
            &nonces,
            Duration::from_secs(600),
        );
        assert_eq!(refusal(&token), EvidenceError::Challenge);
    }

    #[test]
    fn a_key_not_bound_fails_check_5() {
        let mut swapped = keys();
        swapped.signing_ed25519[0] ^= 1;
        assert_eq!(
            check(&token(), &swapped, ConfigPolicy::SIMULATOR).unwrap_err(),
            EvidenceError::Binding
        );
    }

    #[test]
    fn a_claimed_key_id_that_is_not_the_binding_fails_check_5() {
        let other_id = binding(&keys(), &env(&[("FEATURE_ZK_ENABLED", "true")])).key_id();
        assert_eq!(
            verify_evidence(
                &verifier(),
                &token(),
                &CHALLENGE,
                &keys(),
                &other_id,
                ConfigPolicy::SIMULATOR
            )
            .unwrap_err(),
            EvidenceError::Binding
        );
    }

    #[test]
    fn a_configuration_the_binding_does_not_cover_fails_check_5() {
        // The nonce binds an empty configuration; the token reports k = 5.
        let nonces =
            nonces_from_bytes(&binding(&keys(), &BTreeMap::new()).report_data(&CHALLENGE)).unwrap();
        let token = signer()
            .with_env(env(&[("RESEARCH_MIN_COHORT_SIZE", "5")]))
            .sign(
                BROWSER_ATTESTATION_AUDIENCE,
                &nonces,
                Duration::from_secs(600),
            );
        assert_eq!(refusal(&token), EvidenceError::Binding);
    }

    #[test]
    fn a_loosened_configuration_fails_check_5() {
        let claims = SimulatedClaims {
            env: env(&[("RESEARCH_MIN_COHORT_SIZE", "1")]),
            ..SimulatedClaims::default()
        };
        let reported = claims.env.clone();
        let token = token_for(claims, &keys(), &CHALLENGE);
        let key_id = binding(&keys(), &reported).key_id();
        assert_eq!(
            verify_evidence(
                &verifier(),
                &token,
                &CHALLENGE,
                &keys(),
                &key_id,
                ConfigPolicy::SIMULATOR
            )
            .unwrap_err(),
            EvidenceError::Config(ConfigRefused::Loosens("RESEARCH_MIN_COHORT_SIZE"))
        );
    }

    #[test]
    fn release_policy_refuses_attestation_off() {
        let claims = SimulatedClaims {
            env: env(&[("TEE_ATTESTATION_REQUIRED", "false")]),
            ..SimulatedClaims::default()
        };
        let reported = claims.env.clone();
        let token = token_for(claims, &keys(), &CHALLENGE);
        let key_id = binding(&keys(), &reported).key_id();
        assert_eq!(
            verify_evidence(
                &verifier(),
                &token,
                &CHALLENGE,
                &keys(),
                &key_id,
                ConfigPolicy::RELEASE
            )
            .unwrap_err(),
            EvidenceError::Config(ConfigRefused::Loosens("TEE_ATTESTATION_REQUIRED"))
        );
        assert!(
            verify_evidence(
                &verifier(),
                &token,
                &CHALLENGE,
                &keys(),
                &key_id,
                ConfigPolicy::SIMULATOR
            )
            .is_ok()
        );
    }

    #[test]
    fn an_hpk1_request_key_is_refused() {
        let hpk1 = BoundKeys {
            request_key: [b"HPK1".as_slice(), &[7; 32]].concat(),
            ..keys()
        };
        let token = token_for(SimulatedClaims::default(), &hpk1, &CHALLENGE);
        assert_eq!(
            check(&token, &hpk1, ConfigPolicy::SIMULATOR).unwrap_err(),
            EvidenceError::RequestKeySuite
        );
    }

    #[test]
    fn each_refusal_names_its_check() {
        assert!(
            EvidenceError::ImageDigest
                .to_string()
                .starts_with("check 3")
        );
        assert!(EvidenceError::Binding.to_string().starts_with("check 5"));
    }
}
