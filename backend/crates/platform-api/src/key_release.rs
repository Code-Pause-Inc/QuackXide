//! Enclave runtime identity (`P85`) and, behind the `dev` feature, the
//! simulated TEE's key-release stand-in (`stand_in`).
//!
//! [`EnclaveIdentity`] is the ephemeral in-RAM HPKE keypair the enclave
//! generates at startup; its private key never leaves process memory.
//! [`AttestationBundle`] is the public evidence `GET /api/v1/attestation`
//! returns.
//!
//! The relying party, its clients and [`AttestedKeyProvider`] are a
//! development and simulation stand-in for Cloud KMS (ADR 0004). They are
//! compiled only with the `dev` feature, so a production build cannot
//! release keys through them.

use platform_crypto::{EnvelopeSuite, TenantKeypair};
use platform_enclave::{ReportDataBinding, fresh_nonce};
use serde::{Deserialize, Serialize};

#[cfg(feature = "dev")]
use crate::ApiError;

#[cfg(feature = "dev")]
mod stand_in;
#[cfg(feature = "dev")]
pub use stand_in::*;

/// Size of the enclave's key-release public key: X25519 (`HPK1`). It stays
/// `HPK1` until P85 (#176) builds ADR 0010's binding v2, because binding v1
/// (`platform_enclave::ReportDataBinding`) holds a 32-byte key. Only dev-only
/// key release opens envelopes sealed to it.
const ENCLAVE_HPKE_PUBLIC_KEY_BYTES: usize = 32;

/// Ephemeral enclave identity generated in RAM at process boot.
///
/// The private HPKE scalar lives only inside `ephemeral_hpke` (which zeroizes
/// on drop) and is never serialized, logged, or exported.
pub struct EnclaveIdentity {
    // Only the key-release stand-in opens envelopes sealed to this key, so a
    // production build keeps no private half until P85 adds a production use.
    #[cfg(feature = "dev")]
    ephemeral_hpke: TenantKeypair,
    ephemeral_hpke_public_raw: [u8; ENCLAVE_HPKE_PUBLIC_KEY_BYTES],
    result_signing_public_key: [u8; 32],
    tls_cert_sha256: [u8; 32],
    config_digest: [u8; 32],
}

impl EnclaveIdentity {
    /// Generate a fresh in-RAM enclave identity with default zeroed TLS/config
    /// digests (for local dev and tests).
    pub fn generate() -> Self {
        Self::with_metadata([0u8; 32], [0u8; 32])
    }

    /// Generate a fresh in-RAM enclave identity bound to `tls_cert_sha256` and
    /// `config_digest`.
    pub fn with_metadata(tls_cert_sha256: [u8; 32], config_digest: [u8; 32]) -> Self {
        let ephemeral_hpke = TenantKeypair::generate(EnvelopeSuite::Hpk1);
        let mut ephemeral_hpke_public_raw = [0u8; ENCLAVE_HPKE_PUBLIC_KEY_BYTES];
        ephemeral_hpke_public_raw.copy_from_slice(&ephemeral_hpke.public_key().to_raw());
        let result_signing_public_key = fresh_nonce();
        Self {
            #[cfg(feature = "dev")]
            ephemeral_hpke,
            ephemeral_hpke_public_raw,
            result_signing_public_key,
            tls_cert_sha256,
            config_digest,
        }
    }

    pub fn enclave_hpke_public_key(&self) -> &[u8; ENCLAVE_HPKE_PUBLIC_KEY_BYTES] {
        &self.ephemeral_hpke_public_raw
    }

    pub fn result_signing_public_key(&self) -> &[u8; 32] {
        &self.result_signing_public_key
    }

    pub fn tls_cert_sha256(&self) -> &[u8; 32] {
        &self.tls_cert_sha256
    }

    pub fn config_digest(&self) -> &[u8; 32] {
        &self.config_digest
    }

    /// Build the canonical 64-byte [`ReportDataBinding`] for `nonce`.
    pub fn binding_for_nonce(&self, nonce: [u8; 32]) -> ReportDataBinding {
        ReportDataBinding {
            nonce,
            enclave_hpke_public_key: self.ephemeral_hpke_public_raw,
            result_signing_public_key: self.result_signing_public_key,
            tls_cert_sha256: self.tls_cert_sha256,
            config_digest: self.config_digest,
        }
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
            .ephemeral_hpke
            .open_envelope(info, wrapped_key)
            .map_err(|_| ApiError::AttestationUnavailable)?;
        TenantKeypair::from_private_key_bytes(
            raw_sk.expose(),
            platform_crypto::SuitePolicy::PRODUCTION,
        )
        .map_err(|e| {
            if matches!(e, platform_crypto::CryptoError::SuiteRefused) {
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

impl Default for EnclaveIdentity {
    fn default() -> Self {
        Self::generate()
    }
}

/// Public evidence bundle returned by `GET /api/v1/attestation`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationBundle {
    pub platform: String,
    pub nonce_b64: String,
    pub token: String,
    pub enclave_hpke_public_key_b64: String,
    pub result_signing_public_key_b64: String,
    pub tls_cert_sha256_b64: String,
    pub config_digest_b64: String,
}
