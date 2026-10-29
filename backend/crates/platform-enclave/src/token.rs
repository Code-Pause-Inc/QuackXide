//! Verification of Confidential Space attestation tokens (ADR 0004, P47).
//!
//! Google's attestation service signs an RS256 token whose claims name the
//! hardware, the software, the debug state and the container image digest.
//! [`TokenVerifier`] checks the signature against a key set passed in, the
//! issuer, audience and validity window, the expected nonces, and the
//! release policy. Where the key set comes from (pinned or fetched) is the
//! caller's choice (ADR 0004 open question 3).

use std::collections::{HashMap, HashSet};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;

/// Tokens larger than this are refused before any parsing.
pub const MAX_TOKEN_BYTES: usize = 16 * 1024;
/// Allowed clock skew for `exp` and `nbf`, in seconds.
pub const CLOCK_SKEW_LEEWAY_SECS: u64 = 60;
/// Audience of the simulated TEE's tokens.
pub const SIMULATED_AUDIENCE: &str = "quackxide-enclave";

const HWMODEL_TDX: &str = "GCP_INTEL_TDX";
const SWNAME: &str = "CONFIDENTIAL_SPACE";
const DBGSTAT_DISABLED: &str = "disabled-since-boot";
const SUPPORT_STABLE: &str = "STABLE";

/// Why a token was refused. `Display` names the class only, never token
/// contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TokenError {
    #[error("attestation token too large")]
    TooLarge,
    #[error("attestation token malformed")]
    Malformed,
    #[error("attestation token signed by an unknown key")]
    UnknownKey,
    #[error("attestation token signature invalid")]
    BadSignature,
    #[error("attestation token algorithm not allowed")]
    WrongAlgorithm,
    #[error("attestation token issuer not expected")]
    Issuer,
    #[error("attestation token audience not expected")]
    Audience,
    #[error("attestation token expired")]
    Expired,
    #[error("attestation token not yet valid")]
    NotYetValid,
    #[error("attestation token nonce missing or wrong")]
    Nonce,
    #[error("attestation token hardware not allowed")]
    Hardware,
    #[error("attestation token software not allowed")]
    Software,
    #[error("attestation token reports a debug image")]
    Debug,
    #[error("attestation token image is not a stable production image")]
    SupportAttributes,
    #[error("attestation token image digest not allowed")]
    ImageDigest,
    #[error("attestation key set unusable")]
    BadKeySet,
    #[error("attestation key set unavailable")]
    KeySetUnavailable,
}

/// One base64url (no padding) nonce per 32-byte chunk of `input`, which
/// must be 32 bytes (a nonce) or 64 bytes (a nonce and a binding digest).
pub fn nonces_from_bytes(input: &[u8]) -> Result<Vec<String>, TokenError> {
    if input.len() != 32 && input.len() != 64 {
        return Err(TokenError::Nonce);
    }
    Ok(input
        .chunks(32)
        .map(|c| URL_SAFE_NO_PAD.encode(c))
        .collect())
}

/// What the release policy allows beyond the fixed claim values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleasePolicy {
    pub allowed_image_digests: Vec<String>,
}

/// A token that passed every check. Only [`TokenVerifier`] constructs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedToken {
    image_digest: String,
    hwmodel: String,
    nonces: Vec<String>,
}

impl VerifiedToken {
    pub fn image_digest(&self) -> &str {
        &self.image_digest
    }

    pub fn hwmodel(&self) -> &str {
        &self.hwmodel
    }

    pub fn nonces(&self) -> &[String] {
        &self.nonces
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Nonces {
    One(String),
    Many(Vec<String>),
}

#[derive(Deserialize)]
struct Claims {
    hwmodel: String,
    swname: String,
    dbgstat: String,
    eat_nonce: Nonces,
    submods: Submods,
}

#[derive(Deserialize)]
struct Submods {
    confidential_space: ConfidentialSpace,
    container: Container,
}

#[derive(Deserialize)]
struct ConfidentialSpace {
    #[serde(default)]
    support_attributes: Vec<String>,
}

#[derive(Deserialize)]
struct Container {
    image_digest: String,
}

/// Verifies RS256 attestation tokens against a fixed key set and policy.
pub struct TokenVerifier {
    keys: HashMap<String, DecodingKey>,
    validation: Validation,
    policy: ReleasePolicy,
}

impl TokenVerifier {
    /// Build a verifier. Keys without a `kid` are ignored; a key set with no
    /// usable RSA key is refused.
    pub fn new(
        keys: &JwkSet,
        issuer: &str,
        audience: &str,
        policy: ReleasePolicy,
    ) -> Result<Self, TokenError> {
        let mut by_kid = HashMap::new();
        for jwk in &keys.keys {
            let Some(kid) = jwk.common.key_id.clone() else {
                continue;
            };
            let key = DecodingKey::from_jwk(jwk).map_err(|_| TokenError::BadKeySet)?;
            by_kid.insert(kid, key);
        }
        if by_kid.is_empty() {
            return Err(TokenError::BadKeySet);
        }
        // Its own allowlist: never shared with platform-auth's RS256 verifier,
        // which ADR 0001 retires for platform tokens.
        let mut validation = Validation::new(Algorithm::RS256);
        validation.algorithms = vec![Algorithm::RS256];
        validation.leeway = CLOCK_SKEW_LEEWAY_SECS;
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.set_issuer(&[issuer]);
        validation.set_audience(&[audience]);
        validation.required_spec_claims =
            HashSet::from(["exp", "nbf", "iss", "aud"].map(String::from));
        Ok(Self {
            keys: by_kid,
            validation,
            policy,
        })
    }

    /// Whether the token's header names a key in this verifier's key set.
    pub fn knows_kid(&self, token: &str) -> bool {
        token.len() <= MAX_TOKEN_BYTES
            && decode_header(token)
                .ok()
                .and_then(|h| h.kid)
                .is_some_and(|kid| self.keys.contains_key(&kid))
    }

    /// Verify `token` and require every one of `expected_nonces` in it.
    pub fn verify(
        &self,
        token: &str,
        expected_nonces: &[String],
    ) -> Result<VerifiedToken, TokenError> {
        if token.len() > MAX_TOKEN_BYTES {
            return Err(TokenError::TooLarge);
        }
        let header = decode_header(token).map_err(|_| TokenError::Malformed)?;
        if header.alg != Algorithm::RS256 {
            return Err(TokenError::WrongAlgorithm);
        }
        let key = header
            .kid
            .as_ref()
            .and_then(|kid| self.keys.get(kid))
            .ok_or(TokenError::UnknownKey)?;
        let claims = decode::<Claims>(token, key, &self.validation)
            .map_err(|e| match e.kind() {
                ErrorKind::InvalidSignature => TokenError::BadSignature,
                ErrorKind::InvalidAlgorithm => TokenError::WrongAlgorithm,
                ErrorKind::InvalidIssuer => TokenError::Issuer,
                ErrorKind::InvalidAudience => TokenError::Audience,
                ErrorKind::ExpiredSignature => TokenError::Expired,
                ErrorKind::ImmatureSignature => TokenError::NotYetValid,
                _ => TokenError::Malformed,
            })?
            .claims;

        let nonces = match claims.eat_nonce {
            Nonces::One(n) => vec![n],
            Nonces::Many(ns) => ns,
        };
        if expected_nonces.is_empty() || !expected_nonces.iter().all(|n| nonces.contains(n)) {
            return Err(TokenError::Nonce);
        }
        if claims.hwmodel != HWMODEL_TDX {
            return Err(TokenError::Hardware);
        }
        if claims.swname != SWNAME {
            return Err(TokenError::Software);
        }
        if claims.dbgstat != DBGSTAT_DISABLED {
            return Err(TokenError::Debug);
        }
        let attributes = &claims.submods.confidential_space.support_attributes;
        if !attributes.iter().any(|a| a == SUPPORT_STABLE) {
            return Err(TokenError::SupportAttributes);
        }
        let digest = claims.submods.container.image_digest;
        if !self.policy.allowed_image_digests.contains(&digest) {
            return Err(TokenError::ImageDigest);
        }
        Ok(VerifiedToken {
            image_digest: digest,
            hwmodel: claims.hwmodel,
            nonces,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    use super::*;
    use crate::simulated_token::{SIMULATED_IMAGE_DIGEST, SimulatedClaims, TokenSigner};

    const ISSUER: &str = "https://sim.test";
    const MARKER: &str = "MARKERxMARKERxMARKERxMARKERxMARKERxMARKERx1";

    fn signer() -> &'static TokenSigner {
        static SIGNER: OnceLock<TokenSigner> = OnceLock::new();
        SIGNER.get_or_init(|| TokenSigner::generate(ISSUER, SimulatedClaims::default()))
    }

    fn other_signer() -> &'static TokenSigner {
        static SIGNER: OnceLock<TokenSigner> = OnceLock::new();
        SIGNER.get_or_init(|| TokenSigner::generate(ISSUER, SimulatedClaims::default()))
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn nonce() -> String {
        URL_SAFE_NO_PAD.encode([7u8; 32])
    }

    fn verifier() -> TokenVerifier {
        TokenVerifier::new(
            &signer().jwks(),
            ISSUER,
            SIMULATED_AUDIENCE,
            ReleasePolicy {
                allowed_image_digests: vec![SIMULATED_IMAGE_DIGEST.into()],
            },
        )
        .unwrap()
    }

    fn token_with(claims: SimulatedClaims) -> String {
        signer()
            .with_claims(claims)
            .sign(SIMULATED_AUDIENCE, &[nonce()], Duration::from_secs(600))
    }

    fn valid_token() -> String {
        signer().sign(SIMULATED_AUDIENCE, &[nonce()], Duration::from_secs(600))
    }

    fn err(token: &str) -> TokenError {
        verifier().verify(token, &[nonce()]).unwrap_err()
    }

    #[test]
    fn valid_token_verifies() {
        let verified = verifier().verify(&valid_token(), &[nonce()]).unwrap();
        assert_eq!(verified.image_digest(), SIMULATED_IMAGE_DIGEST);
        assert_eq!(verified.hwmodel(), "GCP_INTEL_TDX");
        assert_eq!(verified.nonces(), [nonce()]);
    }

    #[test]
    fn oversized_token_is_refused_before_parsing() {
        assert_eq!(err(&"a".repeat(MAX_TOKEN_BYTES + 1)), TokenError::TooLarge);
    }

    #[test]
    fn malformed_token() {
        assert_eq!(err("not.a.token"), TokenError::Malformed);
    }

    #[test]
    fn unknown_kid() {
        let token = other_signer().sign(SIMULATED_AUDIENCE, &[nonce()], Duration::from_secs(600));
        assert_eq!(err(&token), TokenError::UnknownKey);
    }

    #[test]
    fn tampered_payload() {
        let token = valid_token();
        let mut parts: Vec<&str> = token.split('.').collect();
        let payload = String::from_utf8(URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        let forged = URL_SAFE_NO_PAD.encode(payload.replace("disabled-since-boot", "enabled"));
        parts[1] = &forged;
        assert_eq!(err(&parts.join(".")), TokenError::BadSignature);
    }

    #[test]
    fn hs256_header_is_refused() {
        let token = valid_token();
        let parts: Vec<&str> = token.split('.').collect();
        let kid = signer().jwks().keys[0].common.key_id.clone().unwrap();
        let header = URL_SAFE_NO_PAD.encode(format!(r#"{{"alg":"HS256","kid":"{kid}"}}"#));
        let forged = format!("{header}.{}.{}", parts[1], parts[2]);
        assert_eq!(err(&forged), TokenError::WrongAlgorithm);
    }

    #[test]
    fn wrong_issuer() {
        let expecting_other = TokenVerifier::new(
            &signer().jwks(),
            "https://other.test",
            SIMULATED_AUDIENCE,
            ReleasePolicy {
                allowed_image_digests: vec![SIMULATED_IMAGE_DIGEST.into()],
            },
        )
        .unwrap();
        let result = expecting_other.verify(&valid_token(), &[nonce()]);
        assert_eq!(result.unwrap_err(), TokenError::Issuer);
    }

    #[test]
    fn wrong_audience() {
        let token = signer().sign("someone-else", &[nonce()], Duration::from_secs(600));
        assert_eq!(err(&token), TokenError::Audience);
    }

    #[test]
    fn expired() {
        let token = signer().sign_at(
            SIMULATED_AUDIENCE,
            &[nonce()],
            now() - 7200,
            Duration::from_secs(60),
        );
        assert_eq!(err(&token), TokenError::Expired);
    }

    #[test]
    fn not_yet_valid_beyond_leeway() {
        let token = signer().sign_at(
            SIMULATED_AUDIENCE,
            &[nonce()],
            now() + CLOCK_SKEW_LEEWAY_SECS + 5,
            Duration::from_secs(600),
        );
        assert_eq!(err(&token), TokenError::NotYetValid);
    }

    #[test]
    fn skew_within_leeway_is_accepted() {
        let token = signer().sign_at(
            SIMULATED_AUDIENCE,
            &[nonce()],
            now() + 30,
            Duration::from_secs(600),
        );
        assert!(verifier().verify(&token, &[nonce()]).is_ok());
    }

    #[test]
    fn missing_nonce() {
        let other = URL_SAFE_NO_PAD.encode([9u8; 32]);
        let token = signer().sign(SIMULATED_AUDIENCE, &[other], Duration::from_secs(600));
        assert_eq!(err(&token), TokenError::Nonce);
    }

    #[test]
    fn non_tdx_hardware() {
        let token = token_with(SimulatedClaims {
            hwmodel: "GCP_AMD_SEV".into(),
            ..SimulatedClaims::default()
        });
        assert_eq!(err(&token), TokenError::Hardware);
    }

    #[test]
    fn wrong_software() {
        let token = token_with(SimulatedClaims {
            swname: "GCE".into(),
            ..SimulatedClaims::default()
        });
        assert_eq!(err(&token), TokenError::Software);
    }

    #[test]
    fn debug_image() {
        let token = token_with(SimulatedClaims {
            dbgstat: "enabled".into(),
            ..SimulatedClaims::default()
        });
        assert_eq!(err(&token), TokenError::Debug);
    }

    #[test]
    fn missing_stable() {
        let token = token_with(SimulatedClaims {
            support_attributes: vec!["LATEST".into()],
            ..SimulatedClaims::default()
        });
        assert_eq!(err(&token), TokenError::SupportAttributes);
    }

    #[test]
    fn image_digest_not_allowed() {
        let token = token_with(SimulatedClaims {
            image_digest: format!("sha256:{}", "0".repeat(64)),
            ..SimulatedClaims::default()
        });
        assert_eq!(err(&token), TokenError::ImageDigest);
    }

    #[test]
    fn single_nonce_as_string_and_array_both_verify() {
        let second = URL_SAFE_NO_PAD.encode([8u8; 32]);
        let one = signer().sign(SIMULATED_AUDIENCE, &[nonce()], Duration::from_secs(600));
        let two = signer().sign(
            SIMULATED_AUDIENCE,
            &[nonce(), second.clone()],
            Duration::from_secs(600),
        );
        assert!(verifier().verify(&one, &[nonce()]).is_ok());
        assert!(verifier().verify(&two, &[nonce()]).is_ok());
        assert!(verifier().verify(&two, &[nonce(), second]).is_ok());
    }

    #[test]
    fn nonce_helper_round_trips() {
        let one = nonces_from_bytes(&[1u8; 32]).unwrap();
        assert_eq!(one, [URL_SAFE_NO_PAD.encode([1u8; 32])]);
        let mut both = [2u8; 64];
        both[32..].fill(3);
        let two = nonces_from_bytes(&both).unwrap();
        assert_eq!(
            two,
            [
                URL_SAFE_NO_PAD.encode([2u8; 32]),
                URL_SAFE_NO_PAD.encode([3u8; 32])
            ]
        );
        assert_eq!(two[0].len(), 43);
        assert!(nonces_from_bytes(&[0u8; 31]).is_err());
        assert!(nonces_from_bytes(&[0u8; 65]).is_err());
    }

    #[test]
    fn test_key_is_refused_by_another_key_set() {
        let production = TokenVerifier::new(
            &other_signer().jwks(),
            ISSUER,
            SIMULATED_AUDIENCE,
            ReleasePolicy {
                allowed_image_digests: vec![SIMULATED_IMAGE_DIGEST.into()],
            },
        )
        .unwrap();
        let result = production.verify(&valid_token(), &[nonce()]);
        assert_eq!(result.unwrap_err(), TokenError::UnknownKey);
    }

    #[test]
    fn errors_carry_no_token_text() {
        let tokens = [
            signer().sign("wrong", &[MARKER.into()], Duration::from_secs(600)),
            signer().sign(
                SIMULATED_AUDIENCE,
                &[MARKER.into()],
                Duration::from_secs(600),
            ),
            format!("{MARKER}.{MARKER}.{MARKER}"),
        ];
        for token in tokens {
            let message = err(&token).to_string();
            assert!(!message.contains("MARKER"), "{message}");
        }
    }

    #[test]
    fn knows_kid_reads_only_the_header() {
        assert!(verifier().knows_kid(&valid_token()));
        let other = other_signer().sign(SIMULATED_AUDIENCE, &[nonce()], Duration::from_secs(600));
        assert!(!verifier().knows_kid(&other));
    }
}
