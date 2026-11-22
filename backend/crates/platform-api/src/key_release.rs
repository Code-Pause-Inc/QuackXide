//! Enclave runtime identity (`P85`) and, behind the `dev` feature, the
//! simulated TEE's key-release stand-in (`stand_in`).
//!
//! [`EnclaveIdentity`] is the enclave's in-RAM key set (ADR 0010); its
//! private keys never leave process memory.
//! [`AttestationBundle`] is the public evidence `GET /api/v1/attestation`
//! returns.
//!
//! The relying party, its clients and [`AttestedKeyProvider`] are a
//! development and simulation stand-in for Cloud KMS (ADR 0004). They are
//! compiled only with the `dev` feature, so a production build cannot
//! release keys through them.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use platform_crypto::{
    CryptoError, EnvelopeSuite, ResultSignature, ResultSigningKey, ResultVerifyingKeys,
    SecretBytes, TenantKeypair, TenantPublicKey,
};
use platform_enclave::EnclaveKeyBinding;
pub use platform_enclave::bundle::{AttestationBundle, KeyWire, SigningKeysWire, decode_b64url_32};

#[cfg(feature = "dev")]
use crate::ApiError;

#[cfg(feature = "dev")]
mod stand_in;
#[cfg(feature = "dev")]
pub use stand_in::*;

/// The enclave's key set (ADR 0010 "Enclave keys"), generated in RAM at
/// start: a request key in the current suite and a result-signing key. The
/// private halves never leave process memory and are wiped on drop. A
/// restart produces a new key set, so a new [`key_id`](Self::key_id).
pub struct EnclaveIdentity {
    request: TenantKeypair,
    signing: ResultSigningKey,
    /// The verifying keys as the wire carries them, encoded once: the
    /// public attestation route and every key release send them.
    signing_keys: SigningKeysWire,
    binding: EnclaveKeyBinding,
    key_id: String,
}

impl EnclaveIdentity {
    /// A fresh key set with no TLS key, bound to an empty configuration
    /// (local development and tests, whose tokens report none).
    pub fn generate() -> Self {
        Self::with_metadata(None, platform_enclave::config::config_digest(|_| None))
    }

    /// A fresh key set bound to `tls_spki_sha256` (`None` until P67) and
    /// `config_digest`. The KMS public key is empty until P50.
    pub fn with_metadata(tls_spki_sha256: Option<[u8; 32]>, config_digest: [u8; 32]) -> Self {
        let request = TenantKeypair::generate(EnvelopeSuite::CURRENT);
        let signing = ResultSigningKey::generate();
        let public = request.public_key();
        let verifying = signing.verifying_keys();
        let binding = EnclaveKeyBinding {
            request_key: public.to_framed(),
            signing_ed25519: verifying.ed25519_bytes(),
            signing_ml_dsa_65: verifying.ml_dsa_65_bytes(),
            kms_public_key: Vec::new(),
            tls_spki_sha256,
            config_digest,
        };
        let key_id = binding.key_id();
        Self {
            request,
            signing,
            signing_keys: SigningKeysWire::from_verifying_keys(&verifying),
            binding,
            key_id,
        }
    }

    /// The values bound into attestation tokens for this key set.
    pub fn binding(&self) -> &EnclaveKeyBinding {
        &self.binding
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn request_public_key(&self) -> TenantPublicKey {
        self.request.public_key()
    }

    pub fn verifying_keys(&self) -> ResultVerifyingKeys {
        self.signing.verifying_keys()
    }

    pub fn signing_keys(&self) -> &SigningKeysWire {
        &self.signing_keys
    }

    /// Open a frame sealed to the request key, inside enclave memory.
    pub fn open_request(&self, info: &[u8], envelope: &[u8]) -> Result<SecretBytes, CryptoError> {
        self.request.open_envelope(info, envelope)
    }

    /// Sign a sealed result with both result-signing keys.
    pub fn sign_result(&self, info: &[u8], frame: &[u8]) -> ResultSignature {
        self.signing.sign(info, frame)
    }

    #[cfg(feature = "dev")]
    /// Open a key-release HPKE envelope inside enclave RAM and reconstruct a
    /// transient zeroize-on-drop [`TenantKeypair`]. Released tenant keys must
    /// be `HPK2` in every mode: the stand-in holds no other suite.
    pub fn unwrap_released_key(
        &self,
        tenant: platform_core::TenantId,
        info: &[u8],
        wrapped_key: &[u8],
    ) -> Result<TenantKeypair, ApiError> {
        let raw_sk = self
            .open_request(info, wrapped_key)
            .map_err(|_| ApiError::AttestationUnavailable)?;
        TenantKeypair::from_private_key_bytes(
            raw_sk.expose(),
            platform_crypto::SuitePolicy::only(EnvelopeSuite::Hpk2),
        )
        .map_err(|e| {
            if matches!(e, CryptoError::SuiteRefused) {
                platform_telemetry::security_audit_event(
                    platform_telemetry::AuditKind::SuiteRefused,
                    Some(tenant),
                    "denied",
                    "refused a released tenant key that is not HPK2",
                );
            }
            ApiError::AttestationUnavailable
        })
    }
}

/// The configuration policy this build holds a deployment to (ADR 0010
/// check 5): the simulator's in `dev` builds, which run on the simulated
/// TEE, and the release policy otherwise.
pub fn compiled_config_policy() -> platform_enclave::config::ConfigPolicy {
    if cfg!(feature = "dev") {
        platform_enclave::config::ConfigPolicy::SIMULATOR
    } else {
        platform_enclave::config::ConfigPolicy::RELEASE
    }
}

impl Default for EnclaveIdentity {
    fn default() -> Self {
        Self::generate()
    }
}

impl std::fmt::Debug for EnclaveIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnclaveIdentity")
            .field("key_id", &self.key_id)
            .finish()
    }
}

/// The bundle for `identity`, carrying `token`.
pub fn attestation_bundle(identity: &EnclaveIdentity, token: String) -> AttestationBundle {
    let binding = identity.binding();
    AttestationBundle {
        version: 1,
        key_id: identity.key_id().to_owned(),
        token,
        request_key: KeyWire::from_public_key(&identity.request_public_key()),
        signing_keys: identity.signing_keys().clone(),
        kms_public_key: (!binding.kms_public_key.is_empty())
            .then(|| B64URL.encode(&binding.kms_public_key)),
        tls_spki_sha256: binding.tls_spki_sha256.map(|d| B64URL.encode(d)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use platform_crypto::{SuitePolicy, hpke_seal_to_tenant};

    #[test]
    fn generate_binds_an_empty_configuration() {
        assert_eq!(
            EnclaveIdentity::generate().binding().config_digest,
            platform_enclave::config::config_digest(|_| None)
        );
    }

    #[test]
    fn key_id_is_stable_per_identity_and_differs_between_identities() {
        let identity = EnclaveIdentity::generate();
        assert_eq!(identity.key_id(), identity.binding().key_id());
        assert_eq!(identity.key_id(), identity.key_id());
        assert_ne!(identity.key_id(), EnclaveIdentity::generate().key_id());
    }

    #[test]
    fn the_request_key_is_in_the_current_suite_and_bound() {
        let identity = EnclaveIdentity::generate();
        let key = identity.request_public_key();
        assert_eq!(key.suite(), EnvelopeSuite::CURRENT);
        let framed = key.to_framed();
        assert_eq!(identity.binding().request_key, framed);
    }

    #[test]
    fn open_request_opens_what_was_sealed_to_the_request_key() {
        let identity = EnclaveIdentity::generate();
        let sealed =
            hpke_seal_to_tenant(&identity.request_public_key(), b"info", b"query").expect("seal");
        let opened = identity.open_request(b"info", &sealed).expect("open");
        assert_eq!(opened.expose(), b"query");
        assert!(identity.open_request(b"other info", &sealed).is_err());
    }

    #[test]
    fn signed_results_verify_under_the_published_keys() {
        let identity = EnclaveIdentity::generate();
        let signature = identity.sign_result(b"info", b"frame");
        let wire = SigningKeysWire::from_verifying_keys(&identity.verifying_keys());
        let keys = wire.to_verifying_keys().expect("parse");
        keys.verify(b"info", b"frame", &signature)
            .expect("verifies");
        assert_eq!(identity.binding().signing_ed25519, keys.ed25519_bytes());
        assert_eq!(identity.binding().signing_ml_dsa_65, keys.ml_dsa_65_bytes());
    }

    #[test]
    fn key_wire_round_trips_and_refuses_a_mislabelled_suite() {
        let key = EnclaveIdentity::generate().request_public_key();
        let wire = KeyWire::from_public_key(&key);
        assert_eq!(wire.suite, "HPK2");
        let parsed = wire
            .to_public_key(SuitePolicy::only(EnvelopeSuite::Hpk2))
            .expect("parse");
        assert_eq!(parsed.to_raw(), key.to_raw());
        let mislabelled = KeyWire {
            suite: "HPK1".to_owned(),
            ..wire
        };
        assert!(mislabelled.to_public_key(SuitePolicy::DEVELOPMENT).is_err());
    }

    #[test]
    fn debug_shows_only_the_key_id() {
        let identity = EnclaveIdentity::generate();
        assert_eq!(
            format!("{identity:?}"),
            format!("EnclaveIdentity {{ key_id: {:?} }}", identity.key_id())
        );
    }
}
