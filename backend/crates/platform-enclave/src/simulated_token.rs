//! DEV ONLY: a signer for Confidential Space-shaped attestation tokens.
//!
//! It plays Google's role for the simulated TEE and for tests: a throwaway
//! RSA-2048 key signs RS256 tokens whose claims follow Google's layout, and
//! [`TokenSigner::jwks`] publishes the matching key set. Compiled only with
//! the `simulated` feature.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
        // Google sends one nonce as a string and several as an array.
        let eat_nonce = match nonces {
            [one] => Value::String(one.clone()),
            many => json!(many),
        };
        let claims = json!({
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
        });
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.kid.clone());
        encode(&header, &claims, &self.encoding_key).expect("RS256 signing")
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use jsonwebtoken::decode_header;

    use super::*;

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
