//! DEV ONLY: a signer for Confidential Space-shaped attestation tokens.
//!
//! It plays Google's role for the simulated TEE and for tests: a throwaway
//! RSA-2048 key signs RS256 tokens whose claims follow Google's layout, and
//! [`TokenSigner::jwks`] publishes the matching key set.
//! [`SimulatedTokenProvider`] is the enclave side: it asks a signer, in
//! process or through the `sim-attestation` service, for tokens bound to its
//! nonces and verifies them with the production [`TokenVerifier`].
//! [`TamperedTokenProvider`] produces the tokens refusal tests need. Compiled
//! only with the `simulated` feature.

use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::jwk::{
    AlgorithmParameters, CommonParameters, Jwk, JwkSet, KeyAlgorithm, PublicKeyUse,
    RSAKeyParameters, RSAKeyType,
};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use rand::Rng as _;
use rsa::pkcs1::EncodeRsaPrivateKey as _;
use rsa::traits::PublicKeyParts as _;
use rsa::{RsaPrivateKey, rand_core::OsRng};
use serde_json::{Value, json};

use crate::token::{ReleasePolicy, SIMULATED_AUDIENCE, TokenVerifier, nonces_from_bytes};
use crate::{AttestationEvidence, AttestationProvider, EnclaveError, TeePlatform};

/// Issuer of the `sim-attestation` service's tokens unless
/// `SIM_ATTESTATION_ISSUER` says otherwise.
pub const DEFAULT_SIM_ISSUER: &str = "http://sim-attestation:8070";

/// Image digest the simulator reports by default; the dev release policy
/// allows it.
pub const SIMULATED_IMAGE_DIGEST: &str =
    "sha256:5155a7ab1d7e4c94d5bb3e1c6f0a3a4d6c7b8e9f00112233445566778899aabb";

/// The claims a simulated token carries. The default passes the dev policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimulatedClaims {
    pub hwmodel: String,
    pub swname: String,
    pub dbgstat: String,
    pub support_attributes: Vec<String>,
    pub image_digest: String,
}

impl Default for SimulatedClaims {
    fn default() -> Self {
        Self {
            hwmodel: "GCP_INTEL_TDX".into(),
            swname: "CONFIDENTIAL_SPACE".into(),
            dbgstat: "disabled-since-boot".into(),
            support_attributes: vec!["STABLE".into()],
            image_digest: SIMULATED_IMAGE_DIGEST.into(),
        }
    }
}

impl SimulatedClaims {
    /// The defaults, overridden by `SIM_TOKEN_HWMODEL`, `SIM_TOKEN_DBGSTAT`
    /// and `SIM_TOKEN_IMAGE_DIGEST` (the simulated TEE's tamper settings).
    pub fn from_env() -> Self {
        let mut claims = Self::default();
        let set = |field: &mut String, key: &str| {
            if let Ok(v) = std::env::var(key)
                && !v.trim().is_empty()
            {
                *field = v.trim().to_owned();
            }
        };
        set(&mut claims.hwmodel, "SIM_TOKEN_HWMODEL");
        set(&mut claims.dbgstat, "SIM_TOKEN_DBGSTAT");
        set(&mut claims.image_digest, "SIM_TOKEN_IMAGE_DIGEST");
        claims
    }
}

/// Signs simulated attestation tokens with a throwaway RSA-2048 key.
pub struct TokenSigner {
    issuer: String,
    claims: SimulatedClaims,
    kid: String,
    encoding_key: EncodingKey,
    jwk: Jwk,
}

impl TokenSigner {
    /// Generate a fresh key with a random key id.
    pub fn generate(issuer: impl Into<String>, claims: SimulatedClaims) -> Self {
        let private = RsaPrivateKey::new(&mut OsRng, 2048).expect("RSA-2048 key generation");
        let der = private.to_pkcs1_der().expect("PKCS#1 encoding");
        let encoding_key = EncodingKey::from_rsa_der(der.as_bytes());
        let kid = URL_SAFE_NO_PAD.encode(rand::rngs::OsRng.r#gen::<[u8; 16]>());
        let public = private.to_public_key();
        let jwk = Jwk {
            common: CommonParameters {
                public_key_use: Some(PublicKeyUse::Signature),
                key_id: Some(kid.clone()),
                key_algorithm: Some(KeyAlgorithm::RS256),
                ..CommonParameters::default()
            },
            algorithm: AlgorithmParameters::RSA(RSAKeyParameters {
                key_type: RSAKeyType::RSA,
                n: URL_SAFE_NO_PAD.encode(public.n().to_bytes_be()),
                e: URL_SAFE_NO_PAD.encode(public.e().to_bytes_be()),
            }),
        };
        Self {
            issuer: issuer.into(),
            claims,
            kid,
            encoding_key,
            jwk,
        }
    }

    /// The same key and issuer with different claims (tamper tests).
    pub fn with_claims(&self, claims: SimulatedClaims) -> Self {
        Self {
            issuer: self.issuer.clone(),
            claims,
            kid: self.kid.clone(),
            encoding_key: self.encoding_key.clone(),
            jwk: self.jwk.clone(),
        }
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The key set that verifies this signer's tokens.
    pub fn jwks(&self) -> JwkSet {
        JwkSet {
            keys: vec![self.jwk.clone()],
        }
    }

    /// Sign a token issued now and valid for `lifetime`.
    pub fn sign(&self, audience: &str, nonces: &[String], lifetime: Duration) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        self.sign_at(audience, nonces, now, lifetime)
    }

    /// Sign a token issued at `issued_at` (seconds since the epoch).
    pub fn sign_at(
        &self,
        audience: &str,
        nonces: &[String],
        issued_at: u64,
        lifetime: Duration,
    ) -> String {
        self.sign_claims(&self.claims_json(audience, nonces, issued_at, lifetime))
    }

    /// The claims [`Self::sign_at`] signs, for tests that edit them first.
    pub fn claims_json(
        &self,
        audience: &str,
        nonces: &[String],
        issued_at: u64,
        lifetime: Duration,
    ) -> Value {
        // Google sends one nonce as a string and several as an array.
        let eat_nonce = match nonces {
            [one] => Value::String(one.clone()),
            many => json!(many),
        };
        json!({
            "iss": self.issuer,
            "aud": audience,
            "iat": issued_at,
            "nbf": issued_at,
            "exp": issued_at + lifetime.as_secs(),
            "eat_nonce": eat_nonce,
            "hwmodel": self.claims.hwmodel,
            "swname": self.claims.swname,
            "dbgstat": self.claims.dbgstat,
            "submods": {
                "confidential_space": { "support_attributes": self.claims.support_attributes },
                "container": { "image_digest": self.claims.image_digest },
            },
        })
    }

    /// Sign arbitrary claims with this signer's key.
    pub fn sign_claims(&self, claims: &Value) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.kid.clone());
        encode(&header, claims, &self.encoding_key).expect("RS256 signing")
    }
}

enum TokenSource {
    InProcess(Arc<TokenSigner>),
    Http {
        base_url: String,
        client: reqwest::Client,
    },
}

/// Simulated Confidential Space evidence: a token bound to the caller's
/// nonces, verified against the signer's key set and `policy`.
pub struct SimulatedTokenProvider {
    source: TokenSource,
    issuer: String,
    policy: ReleasePolicy,
    verifier: RwLock<Option<TokenVerifier>>,
}

impl SimulatedTokenProvider {
    /// Sign in process (tests and single-process demos).
    pub fn in_process(signer: Arc<TokenSigner>, policy: ReleasePolicy) -> Self {
        let verifier = TokenVerifier::new(
            &signer.jwks(),
            signer.issuer(),
            SIMULATED_AUDIENCE,
            policy.clone(),
        )
        .ok();
        Self {
            issuer: signer.issuer().to_owned(),
            source: TokenSource::InProcess(signer),
            policy,
            verifier: RwLock::new(verifier),
        }
    }

    /// Ask the `sim-attestation` service at `base_url` for tokens and keys.
    pub fn from_url(base_url: &str, issuer: &str, policy: ReleasePolicy) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_default();
        Self {
            source: TokenSource::Http {
                base_url: base_url.trim_end_matches('/').to_owned(),
                client,
            },
            issuer: issuer.to_owned(),
            policy,
            verifier: RwLock::new(None),
        }
    }

    async fn token(&self, nonces: &[String]) -> Result<String, EnclaveError> {
        match &self.source {
            TokenSource::InProcess(signer) => {
                Ok(signer.sign(SIMULATED_AUDIENCE, nonces, Duration::from_secs(3600)))
            }
            TokenSource::Http { base_url, client } => {
                #[derive(serde::Deserialize)]
                struct TokenResponse {
                    token: String,
                }
                let body = json!({
                    "audience": SIMULATED_AUDIENCE,
                    "nonces": nonces,
                    "token_type": "OIDC",
                });
                let response = client
                    .post(format!("{base_url}/v1/token"))
                    .json(&body)
                    .send()
                    .await
                    .and_then(reqwest::Response::error_for_status)
                    .map_err(|_| unavailable())?;
                let parsed: TokenResponse = response.json().await.map_err(|_| unavailable())?;
                Ok(parsed.token)
            }
        }
    }

    /// Load the signer's key set, once more when a token names an unknown key.
    async fn ensure_keys_for(&self, token: &str) -> Result<(), EnclaveError> {
        let known = self
            .verifier
            .read()
            .map_err(|_| unavailable())?
            .as_ref()
            .is_some_and(|v| v.knows_kid(token));
        if known {
            return Ok(());
        }
        let jwks = match &self.source {
            TokenSource::InProcess(signer) => signer.jwks(),
            TokenSource::Http { base_url, client } => client
                .get(format!("{base_url}/jwks"))
                .send()
                .await
                .and_then(reqwest::Response::error_for_status)
                .map_err(|_| unavailable())?
                .json()
                .await
                .map_err(|_| unavailable())?,
        };
        let verifier =
            TokenVerifier::new(&jwks, &self.issuer, SIMULATED_AUDIENCE, self.policy.clone())
                .map_err(|e| EnclaveError::Rejected(e.to_string()))?;
        *self.verifier.write().map_err(|_| unavailable())? = Some(verifier);
        Ok(())
    }
}

// `Rejected`, not `Unavailable`: the gates let `Unavailable` through as
// development evidence, and a configured simulator that fails must refuse.
fn unavailable() -> EnclaveError {
    EnclaveError::Rejected("simulated attestation service unreachable".into())
}

#[async_trait]
impl AttestationProvider for SimulatedTokenProvider {
    async fn produce_evidence(&self, nonce: &[u8]) -> Result<AttestationEvidence, EnclaveError> {
        let nonces = nonces_from_bytes(nonce).map_err(|e| EnclaveError::Rejected(e.to_string()))?;
        let token = self.token(&nonces).await?;
        self.ensure_keys_for(&token).await?;
        Ok(AttestationEvidence {
            platform: TeePlatform::Simulated,
            nonce: nonce.to_vec(),
            token,
        })
    }

    fn verify_evidence(
        &self,
        evidence: &AttestationEvidence,
        expected_nonce: &[u8],
    ) -> Result<(), EnclaveError> {
        let nonces =
            nonces_from_bytes(expected_nonce).map_err(|e| EnclaveError::Rejected(e.to_string()))?;
        let guard = self.verifier.read().map_err(|_| unavailable())?;
        let verifier = guard.as_ref().ok_or_else(|| {
            EnclaveError::Rejected("simulated attestation keys not loaded".into())
        })?;
        verifier
            .verify(&evidence.token, &nonces)
            .map(|_| ())
            .map_err(|e| EnclaveError::Rejected(e.to_string()))
    }
}

/// One way a simulated token can fail verification. Each must be refused on
/// the query path and the sync path (P84).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tamper {
    DebugImage,
    UnlistedImageDigest,
    NonTdxHardware,
    WrongNonce,
    Expired,
    OtherKeySet,
}

impl Tamper {
    pub const ALL: [Tamper; 6] = [
        Tamper::DebugImage,
        Tamper::UnlistedImageDigest,
        Tamper::NonTdxHardware,
        Tamper::WrongNonce,
        Tamper::Expired,
        Tamper::OtherKeySet,
    ];
}

/// Simulated evidence tampered one way, for refusal tests: its tokens fail
/// `tamper`'s check, and it verifies them as [`SimulatedTokenProvider`] does,
/// with the honest signer's key set and `policy`.
pub struct TamperedTokenProvider {
    tamper: Tamper,
    signer: TokenSigner,
    honest: SimulatedTokenProvider,
}

impl TamperedTokenProvider {
    pub fn new(signer: Arc<TokenSigner>, policy: ReleasePolicy, tamper: Tamper) -> Self {
        let claims = |edit: fn(&mut SimulatedClaims)| {
            let mut claims = SimulatedClaims::default();
            edit(&mut claims);
            signer.with_claims(claims)
        };
        let tampered = match tamper {
            Tamper::DebugImage => claims(|c| c.dbgstat = "enabled".into()),
            Tamper::UnlistedImageDigest => {
                claims(|c| c.image_digest = format!("sha256:{}", "f".repeat(64)))
            }
            Tamper::NonTdxHardware => claims(|c| c.hwmodel = "GCP_AMD_SEV".into()),
            Tamper::WrongNonce | Tamper::Expired => claims(|_| ()),
            Tamper::OtherKeySet => {
                TokenSigner::generate(signer.issuer(), SimulatedClaims::default())
            }
        };
        Self {
            tamper,
            signer: tampered,
            honest: SimulatedTokenProvider::in_process(signer, policy),
        }
    }
}

#[async_trait]
impl AttestationProvider for TamperedTokenProvider {
    async fn produce_evidence(&self, nonce: &[u8]) -> Result<AttestationEvidence, EnclaveError> {
        let bound_to: Vec<u8> = match self.tamper {
            Tamper::WrongNonce => nonce.iter().map(|b| !b).collect(),
            _ => nonce.to_vec(),
        };
        let nonces =
            nonces_from_bytes(&bound_to).map_err(|e| EnclaveError::Rejected(e.to_string()))?;
        let lifetime = Duration::from_secs(3600);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let issued_at = match self.tamper {
            // Expired an hour ago, well past the verifier's leeway.
            Tamper::Expired => now.saturating_sub(2 * lifetime.as_secs()),
            _ => now,
        };
        let token = self
            .signer
            .sign_at(SIMULATED_AUDIENCE, &nonces, issued_at, lifetime);
        Ok(AttestationEvidence {
            platform: TeePlatform::Simulated,
            nonce: nonce.to_vec(),
            token,
        })
    }

    fn verify_evidence(
        &self,
        evidence: &AttestationEvidence,
        expected_nonce: &[u8],
    ) -> Result<(), EnclaveError> {
        self.honest.verify_evidence(evidence, expected_nonce)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use jsonwebtoken::decode_header;

    use crate::token::ReleasePolicy;

    use super::*;

    fn provider(claims: SimulatedClaims) -> SimulatedTokenProvider {
        let signer = TokenSigner::generate("https://sim.test", SimulatedClaims::default());
        SimulatedTokenProvider::in_process(
            std::sync::Arc::new(signer.with_claims(claims)),
            ReleasePolicy {
                allowed_image_digests: vec![SIMULATED_IMAGE_DIGEST.into()],
            },
        )
    }

    #[tokio::test]
    async fn token_provider_evidence_verifies() {
        let provider = provider(SimulatedClaims::default());
        let binding = [5u8; 64];
        let evidence = provider.produce_evidence(&binding).await.unwrap();
        assert_eq!(evidence.platform, TeePlatform::Simulated);
        assert!(!evidence.token.is_empty());
        provider.verify_evidence(&evidence, &binding).unwrap();
    }

    #[tokio::test]
    async fn token_provider_rejects_wrong_nonce() {
        let provider = provider(SimulatedClaims::default());
        let evidence = provider.produce_evidence(&[5u8; 32]).await.unwrap();
        assert!(provider.verify_evidence(&evidence, &[6u8; 32]).is_err());
    }

    #[tokio::test]
    async fn token_provider_refuses_debug_claims() {
        let provider = provider(SimulatedClaims {
            dbgstat: "enabled".into(),
            ..SimulatedClaims::default()
        });
        let evidence = provider.produce_evidence(&[5u8; 32]).await.unwrap();
        assert!(provider.verify_evidence(&evidence, &[5u8; 32]).is_err());
    }

    #[tokio::test]
    async fn gate_execution_verifies_simulated_tokens() {
        let good = provider(SimulatedClaims::default());
        let platform = crate::gate_execution(&good, false, &[1u8; 32])
            .await
            .unwrap();
        assert_eq!(platform, TeePlatform::Simulated);

        let debug = provider(SimulatedClaims {
            dbgstat: "enabled".into(),
            ..SimulatedClaims::default()
        });
        assert!(
            crate::gate_execution(&debug, false, &[1u8; 32])
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn unreachable_simulator_is_refused_even_when_not_required() {
        // A configured simulator that does not answer must refuse, not run unattested.
        let unreachable = SimulatedTokenProvider::from_url(
            "http://127.0.0.1:9",
            "https://sim.test",
            ReleasePolicy {
                allowed_image_digests: vec![SIMULATED_IMAGE_DIGEST.into()],
            },
        );
        assert!(
            crate::gate_execution(&unreachable, false, &[1u8; 32])
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn gate_execution_refuses_simulated_tokens_when_required() {
        let good = provider(SimulatedClaims::default());
        assert!(
            crate::gate_execution(&good, true, &[1u8; 32])
                .await
                .is_err()
        );
    }

    #[test]
    fn signer_publishes_the_key_it_signs_with() {
        let signer = TokenSigner::generate("https://sim.test", SimulatedClaims::default());
        let token = signer.sign("aud", &["n".repeat(43)], Duration::from_secs(60));

        let header = decode_header(&token).expect("header");
        assert_eq!(header.alg, jsonwebtoken::Algorithm::RS256);
        let jwks = signer.jwks();
        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(header.kid, jwks.keys[0].common.key_id);
    }
}
