//! ADR 0010 "Evidence bundle": the wire types of `GET /api/v1/attestation`
//! and the one decode-and-verify step the browser module (#239) and
//! `enclave-check` both call. It needs nothing wasm32 lacks.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use platform_crypto::{
    CryptoError, EnvelopeSuite, ResultVerifyingKeys, SuitePolicy, TenantPublicKey,
};
use serde::{Deserialize, Serialize};

use crate::config::ConfigPolicy;
use crate::evidence::{BoundKeys, EvidenceError, verify_evidence};
use crate::token::TokenVerifier;

/// A public key on the wire: its suite name and its raw bytes, base64url
/// without padding (ADR 0010).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyWire {
    pub suite: String,
    pub public_key: String,
}

impl KeyWire {
    pub fn from_public_key(key: &TenantPublicKey) -> Self {
        Self {
            suite: key.suite().id().to_owned(),
            public_key: B64URL.encode(key.to_raw()),
        }
    }

    /// Parse under `policy`. The named suite must be the key's own.
    pub fn to_public_key(&self, policy: SuitePolicy) -> Result<TenantPublicKey, CryptoError> {
        let suite = EnvelopeSuite::from_id(&self.suite)?;
        let raw = B64URL
            .decode(&self.public_key)
            .map_err(|_| CryptoError::InvalidPublicKey)?;
        let key = TenantPublicKey::from_raw(&raw, policy)?;
        if key.suite() != suite {
            return Err(CryptoError::SuiteMismatch);
        }
        Ok(key)
    }
}

/// The two result-signing keys, base64url without padding (ADR 0010). The
/// signatures over a result are a different wire type, so neither can stand
/// in for the other.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningKeysWire {
    pub ed25519: String,
    pub ml_dsa_65: String,
}

impl SigningKeysWire {
    pub fn from_verifying_keys(keys: &ResultVerifyingKeys) -> Self {
        Self {
            ed25519: B64URL.encode(keys.ed25519_bytes()),
            ml_dsa_65: B64URL.encode(keys.ml_dsa_65_bytes()),
        }
    }

    pub fn to_verifying_keys(&self) -> Result<ResultVerifyingKeys, CryptoError> {
        let decode = |b64: &str| {
            B64URL
                .decode(b64)
                .map_err(|_| CryptoError::InvalidPublicKey)
        };
        ResultVerifyingKeys::from_bytes(&decode(&self.ed25519)?, &decode(&self.ml_dsa_65)?)
    }
}

/// `GET /api/v1/attestation`'s evidence bundle (ADR 0010 "Evidence bundle").
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationBundle {
    pub version: u32,
    pub key_id: String,
    pub token: String,
    pub request_key: KeyWire,
    pub signing_keys: SigningKeysWire,
    pub kms_public_key: Option<String>,
    pub tls_spki_sha256: Option<String>,
}

/// 32 bytes of base64url without padding (ADR 0010's byte fields), or
/// `None` for anything else.
pub fn decode_b64url_32(b64: &str) -> Option<[u8; 32]> {
    B64URL.decode(b64).ok()?.try_into().ok()
}

/// Why a bundle was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BundleError {
    #[error("unsupported bundle version {0}")]
    Version(u32),
    #[error("malformed {0} in the bundle")]
    Malformed(&'static str),
    #[error(transparent)]
    Evidence(#[from] EvidenceError),
}

impl AttestationBundle {
    /// The keys the bundle names, decoded from the wire. Refuses any
    /// version but 1.
    pub fn bound_keys(&self) -> Result<BoundKeys, BundleError> {
        if self.version != 1 {
            return Err(BundleError::Version(self.version));
        }
        // Either suite parses here; `verify_evidence` refuses all but HPK2.
        let request_key = self
            .request_key
            .to_public_key(SuitePolicy::DEVELOPMENT)
            .map_err(|_| BundleError::Malformed("request key"))?;
        let signing = self
            .signing_keys
            .to_verifying_keys()
            .map_err(|_| BundleError::Malformed("signing keys"))?;
        let kms_public_key = match &self.kms_public_key {
            None => Vec::new(),
            Some(b64) => B64URL
                .decode(b64)
                .map_err(|_| BundleError::Malformed("KMS public key"))?,
        };
        let tls_spki_sha256 = match &self.tls_spki_sha256 {
            None => None,
            Some(b64) => {
                Some(decode_b64url_32(b64).ok_or(BundleError::Malformed("TLS key digest"))?)
            }
        };
        Ok(BoundKeys {
            request_key: request_key.to_framed(),
            signing_ed25519: signing.ed25519_bytes(),
            signing_ml_dsa_65: signing.ml_dsa_65_bytes(),
            kms_public_key,
            tls_spki_sha256,
        })
    }
}

/// An enclave's keys, taken from a bundle that passed every check.
#[derive(Debug, Clone, Serialize)]
pub struct VerifiedBundle {
    pub key_id: String,
    /// The token's `exp`, seconds since the epoch.
    pub expires_at: u64,
    /// The image digest the token attests, one of the verifier's allowed ones.
    pub image_digest: String,
    pub request_key: KeyWire,
    pub signing_keys: SigningKeysWire,
}

/// Decode `bundle`'s keys and run [`verify_evidence`] against `challenge`.
pub fn verify_bundle(
    bundle: &AttestationBundle,
    challenge: &[u8; 32],
    verifier: &TokenVerifier,
    policy: ConfigPolicy,
) -> Result<VerifiedBundle, BundleError> {
    let keys = bundle.bound_keys()?;
    let verified = verify_evidence(
        verifier,
        &bundle.token,
        challenge,
        &keys,
        &bundle.key_id,
        policy,
    )?;
    Ok(VerifiedBundle {
        key_id: verified.key_id,
        expires_at: verified.token.expires_at(),
        image_digest: verified.token.image_digest().to_owned(),
        request_key: bundle.request_key.clone(),
        signing_keys: bundle.signing_keys.clone(),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use platform_crypto::{EnvelopeSuite, ResultSigningKey, TenantKeypair};

    use super::*;
    use crate::config::config_digest;
    use crate::simulated_token::{SIMULATED_IMAGE_DIGEST, SimulatedClaims, TokenSigner};
    use crate::token::{BROWSER_ATTESTATION_AUDIENCE, ReleasePolicy, nonces_from_bytes};

    const ISSUER: &str = "http://sim-attestation:8070";
    const CHALLENGE: [u8; 32] = [3; 32];
    const LIFETIME: u64 = 600;

    /// A bundle bound to `CHALLENGE`, its verifier and the token's `iat`.
    fn fixture(image_digest: &str) -> (AttestationBundle, TokenVerifier, u64) {
        let request = TenantKeypair::generate(EnvelopeSuite::CURRENT).public_key();
        let verifying = ResultSigningKey::generate().verifying_keys();
        let keys = BoundKeys {
            request_key: request.to_framed(),
            signing_ed25519: verifying.ed25519_bytes(),
            signing_ml_dsa_65: verifying.ml_dsa_65_bytes(),
            kms_public_key: Vec::new(),
            tls_spki_sha256: None,
        };
        let binding = keys.binding(config_digest(|_| None));
        let claims = SimulatedClaims {
            image_digest: image_digest.to_owned(),
            env: BTreeMap::new(),
            ..SimulatedClaims::default()
        };
        let signer = TokenSigner::generate(ISSUER, claims);
        let nonces = nonces_from_bytes(&binding.report_data(&CHALLENGE)).unwrap();
        let iat = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let token = signer.sign_at(
            BROWSER_ATTESTATION_AUDIENCE,
            &nonces,
            iat,
            Duration::from_secs(LIFETIME),
        );
        let verifier = TokenVerifier::new(
            &signer.jwks(),
            ISSUER,
            BROWSER_ATTESTATION_AUDIENCE,
            ReleasePolicy {
                allowed_image_digests: vec![SIMULATED_IMAGE_DIGEST.to_owned()],
            },
        )
        .unwrap();
        let bundle = AttestationBundle {
            version: 1,
            key_id: binding.key_id(),
            token,
            request_key: KeyWire::from_public_key(&request),
            signing_keys: SigningKeysWire::from_verifying_keys(&verifying),
            kms_public_key: None,
            tls_spki_sha256: None,
        };
        (bundle, verifier, iat)
    }

    fn verify(
        bundle: &AttestationBundle,
        verifier: &TokenVerifier,
    ) -> Result<VerifiedBundle, BundleError> {
        verify_bundle(bundle, &CHALLENGE, verifier, ConfigPolicy::SIMULATOR)
    }

    #[test]
    fn a_bound_bundle_verifies() {
        let (bundle, verifier, iat) = fixture(SIMULATED_IMAGE_DIGEST);
        let v = verify(&bundle, &verifier).expect("verifies");
        assert_eq!(v.key_id, bundle.key_id);
        assert_eq!(v.expires_at, iat + LIFETIME);
        assert_eq!(v.image_digest, SIMULATED_IMAGE_DIGEST);
        assert_eq!(v.request_key, bundle.request_key);
        assert_eq!(v.signing_keys, bundle.signing_keys);
    }

    #[test]
    fn version_2_is_refused() {
        let (mut bundle, verifier, _) = fixture(SIMULATED_IMAGE_DIGEST);
        bundle.version = 2;
        let err = verify(&bundle, &verifier).unwrap_err();
        assert_eq!(err, BundleError::Version(2));
        assert_eq!(err.to_string(), "unsupported bundle version 2");
    }

    #[test]
    fn a_malformed_request_key_is_refused() {
        let (mut bundle, verifier, _) = fixture(SIMULATED_IMAGE_DIGEST);
        bundle.request_key.public_key = "!!".to_owned();
        let err = verify(&bundle, &verifier).unwrap_err();
        assert_eq!(err, BundleError::Malformed("request key"));
        assert_eq!(err.to_string(), "malformed request key in the bundle");
    }

    #[test]
    fn malformed_signing_keys_are_refused() {
        let (mut bundle, verifier, _) = fixture(SIMULATED_IMAGE_DIGEST);
        bundle.signing_keys.ed25519 = B64URL.encode([0u8; 31]);
        assert_eq!(
            verify(&bundle, &verifier).unwrap_err(),
            BundleError::Malformed("signing keys")
        );
    }

    #[test]
    fn a_malformed_kms_key_or_tls_digest_is_refused() {
        let (mut bundle, verifier, _) = fixture(SIMULATED_IMAGE_DIGEST);
        bundle.kms_public_key = Some("!!".to_owned());
        assert_eq!(
            verify(&bundle, &verifier).unwrap_err(),
            BundleError::Malformed("KMS public key")
        );
        bundle.kms_public_key = None;
        bundle.tls_spki_sha256 = Some("AAAA".to_owned());
        assert_eq!(
            verify(&bundle, &verifier).unwrap_err(),
            BundleError::Malformed("TLS key digest")
        );
    }

    #[test]
    fn a_failed_check_names_it() {
        let other = format!("sha256:{}", "0".repeat(64));
        let (bundle, verifier, _) = fixture(&other);
        assert_eq!(
            verify(&bundle, &verifier).unwrap_err(),
            BundleError::Evidence(EvidenceError::ImageDigest)
        );
    }

    #[test]
    fn bound_keys_decodes_without_a_token_check() {
        let (bundle, _, _) = fixture(SIMULATED_IMAGE_DIGEST);
        let keys = bundle.bound_keys().expect("decodes");
        assert!(keys.request_key.starts_with(b"HPK2"));
        assert_eq!(
            keys.binding(config_digest(|_| None)).key_id(),
            bundle.key_id
        );
    }
}
