//! TEE attestation for the confidential pipelines (ADR 0004: Confidential
//! Space on Intel TDX).
//!
//! Every pipeline is written against [`AttestationProvider`], so no code
//! path can skip attestation. [`token::TokenVerifier`] verifies Confidential
//! Space attestation tokens; the `simulated` feature adds a dev-only token
//! simulator. Acquiring tokens on hardware is P48.

use async_trait::async_trait;
use rand::Rng;

pub mod binding;
#[cfg(feature = "simulated")]
pub mod simulated_token;
pub mod token;

pub use binding::{REPORT_DATA_BYTES, ReportDataBinding};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeePlatform {
    /// Hardware evidence. No provider produces it today ([`SnpAttestation`]
    /// always refuses); P48 replaces it with Confidential Space on TDX.
    SevSnp,
    /// Simulated Confidential Space tokens from the `simulated` feature's
    /// provider. Accepted only when hardware attestation is not required;
    /// never valid in production.
    Simulated,
    /// Explicitly-insecure local development stand-in. Never valid in prod.
    Development,
}

/// Hardware (or simulated) evidence binding a caller-supplied freshness nonce.
#[derive(Debug, Clone)]
pub struct AttestationEvidence {
    pub platform: TeePlatform,
    /// Freshness nonce (or nonce and binding digest) the evidence binds.
    pub nonce: Vec<u8>,
    /// Confidential Space attestation token (simulated tokens today); empty
    /// for development evidence.
    pub token: String,
}

#[derive(Debug, thiserror::Error)]
pub enum EnclaveError {
    #[error("attestation unavailable: {0}")]
    Unavailable(String),
    #[error("attestation rejected: {0}")]
    Rejected(String),
}

#[async_trait]
pub trait AttestationProvider: Send + Sync {
    /// Produce evidence binding `nonce`. In production this is a Confidential
    /// Space attestation token; anything that cannot produce one must fail
    /// closed.
    async fn produce_evidence(&self, nonce: &[u8]) -> Result<AttestationEvidence, EnclaveError>;

    /// Verify `evidence` against `expected_nonce`. Token providers run
    /// [`token::TokenVerifier`] here.
    fn verify_evidence(
        &self,
        _evidence: &AttestationEvidence,
        _expected_nonce: &[u8],
    ) -> Result<(), EnclaveError> {
        Ok(())
    }
}

/// Development-only provider. [`DevAttestation::strict`] always fails;
/// [`DevAttestation::allow_insecure_dev`] fabricates `Development` evidence
/// and warns. It never claims to be real hardware.
pub struct DevAttestation {
    allow_insecure: bool,
}

impl DevAttestation {
    pub fn strict() -> Self {
        Self {
            allow_insecure: false,
        }
    }

    pub fn allow_insecure_dev() -> Self {
        tracing::warn!(
            "DevAttestation running in INSECURE dev mode — evidence is fabricated; never use in production"
        );
        Self {
            allow_insecure: true,
        }
    }
}

#[async_trait]
impl AttestationProvider for DevAttestation {
    async fn produce_evidence(&self, nonce: &[u8]) -> Result<AttestationEvidence, EnclaveError> {
        if !self.allow_insecure {
            return Err(EnclaveError::Unavailable(
                "no TEE hardware present; refusing to fabricate evidence (fail closed)".into(),
            ));
        }
        Ok(AttestationEvidence {
            platform: TeePlatform::Development,
            nonce: nonce.to_vec(),
            token: String::new(),
        })
    }
}

/// AMD SEV-SNP guest device exposed inside GCP Confidential VMs.
const SNP_GUEST_DEVICE: &str = "/dev/sev-guest";

/// SEV-SNP provider. Checks for the guest device, then refuses: signed-report
/// acquisition is not implemented, so with `TEE_ATTESTATION_REQUIRED=true`
/// confidential pipelines do not run.
pub struct SnpAttestation {
    device: std::path::PathBuf,
}

impl SnpAttestation {
    pub fn new() -> Self {
        Self {
            device: std::path::PathBuf::from(SNP_GUEST_DEVICE),
        }
    }
}

impl Default for SnpAttestation {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AttestationProvider for SnpAttestation {
    async fn produce_evidence(&self, _nonce: &[u8]) -> Result<AttestationEvidence, EnclaveError> {
        if !self.device.exists() {
            return Err(EnclaveError::Unavailable(
                "SEV-SNP guest device not present (not running in a Confidential VM)".into(),
            ));
        }
        Err(EnclaveError::Unavailable(
            "SEV-SNP device present, but signed-report acquisition ships with production \
             hardening; refusing to fabricate evidence"
                .into(),
        ))
    }
}

/// Decode a fixed-length hex string into `[u8; N]`.
pub fn decode_hex_array<const N: usize>(hex: &str) -> Option<[u8; N]> {
    let hex = hex.trim();
    if hex.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    for (i, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out[i] = ((hi << 4) | lo) as u8;
    }
    Some(out)
}

/// A fresh 32-byte attestation nonce from the operating system's RNG.
pub fn fresh_nonce() -> [u8; 32] {
    rand::rngs::OsRng.r#gen()
}

/// Execution gate for confidential workloads; `Ok` means execution may
/// proceed on the returned platform.
///
/// - `TeePlatform::SevSnp`: verified via `provider.verify_evidence`; proceeds
///   regardless of `require_attestation`.
/// - `TeePlatform::Simulated`: rejected when `require_attestation` is `true`
///   (never valid in production). When `require_attestation` is `false`, the
///   token is verified via `provider.verify_evidence` — any verification
///   failure refuses execution.
/// - `TeePlatform::Development`: rejected when `require_attestation` is `true`;
///   proceeds when `false`.
pub async fn gate_execution(
    provider: &dyn AttestationProvider,
    require_attestation: bool,
    nonce: &[u8],
) -> Result<TeePlatform, EnclaveError> {
    match provider.produce_evidence(nonce).await {
        Ok(evidence) if evidence.platform == TeePlatform::SevSnp => {
            provider.verify_evidence(&evidence, nonce)?;
            Ok(TeePlatform::SevSnp)
        }
        Ok(evidence) if evidence.platform == TeePlatform::Simulated => {
            if require_attestation {
                return Err(EnclaveError::Rejected(
                    "simulated evidence is not accepted when hardware attestation is required"
                        .into(),
                ));
            }
            provider.verify_evidence(&evidence, nonce)?;
            Ok(TeePlatform::Simulated)
        }
        Ok(_) if !require_attestation => Ok(TeePlatform::Development),
        Ok(_) => Err(EnclaveError::Rejected(
            "evidence platform is not SEV-SNP".into(),
        )),
        Err(EnclaveError::Unavailable(_)) if !require_attestation => Ok(TeePlatform::Development),
        Err(err) => Err(err),
    }
}

/// Refuses every request. Used when attestation is not required but no
/// simulator is available, so nothing runs on fabricated or missing evidence.
struct RejectingProvider;

#[async_trait]
impl AttestationProvider for RejectingProvider {
    async fn produce_evidence(&self, _nonce: &[u8]) -> Result<AttestationEvidence, EnclaveError> {
        // `Rejected`, not `Unavailable`: the gates let `Unavailable` through
        // as development evidence when attestation is not required.
        Err(EnclaveError::Rejected(
            "simulated attestation unavailable: build with the dev feature and set SIM_ATTESTATION_URL"
                .into(),
        ))
    }
}

/// The SNP provider when attestation is required. Otherwise the simulated
/// token provider, in builds with the `simulated` feature and
/// `SIM_ATTESTATION_URL` set, and a provider that refuses in all other cases.
pub fn provider_for(attestation_required: bool) -> std::sync::Arc<dyn AttestationProvider> {
    if attestation_required {
        return std::sync::Arc::new(SnpAttestation::new());
    }
    #[cfg(feature = "simulated")]
    if let Ok(url) = std::env::var("SIM_ATTESTATION_URL")
        && !url.trim().is_empty()
    {
        let issuer = std::env::var("SIM_ATTESTATION_ISSUER")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| simulated_token::DEFAULT_SIM_ISSUER.to_owned());
        let policy = token::ReleasePolicy {
            allowed_image_digests: vec![simulated_token::SIMULATED_IMAGE_DIGEST.to_owned()],
        };
        return std::sync::Arc::new(simulated_token::SimulatedTokenProvider::from_url(
            url.trim(),
            &issuer,
            policy,
        ));
    }
    std::sync::Arc::new(RejectingProvider)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_nonces_differ() {
        assert_ne!(fresh_nonce(), fresh_nonce());
    }

    #[tokio::test]
    async fn rejecting_provider_refuses_even_when_not_required() {
        // A build without the simulator must never fall back to running unattested.
        let result = gate_execution(&RejectingProvider, false, &fresh_nonce()).await;
        assert!(
            matches!(result, Err(EnclaveError::Rejected(_))),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn strict_dev_attestation_fails_closed() {
        let provider = DevAttestation::strict();
        assert!(provider.produce_evidence(b"nonce").await.is_err());
    }

    #[tokio::test]
    async fn insecure_dev_attestation_never_claims_real_hardware() {
        let provider = DevAttestation::allow_insecure_dev();
        let evidence = provider
            .produce_evidence(b"nonce")
            .await
            .expect("dev evidence");
        assert_eq!(evidence.platform, TeePlatform::Development);
        assert_eq!(evidence.nonce, b"nonce");
    }

    #[tokio::test]
    async fn snp_provider_fails_closed_off_confidential_hardware() {
        let provider = SnpAttestation::new();
        assert!(provider.produce_evidence(b"nonce").await.is_err());
    }

    struct SevSnpEvidence;

    #[async_trait]
    impl AttestationProvider for SevSnpEvidence {
        async fn produce_evidence(
            &self,
            nonce: &[u8],
        ) -> Result<AttestationEvidence, EnclaveError> {
            Ok(AttestationEvidence {
                platform: TeePlatform::SevSnp,
                nonce: nonce.to_vec(),
                token: String::new(),
            })
        }
    }

    #[tokio::test]
    async fn gate_proceeds_on_sev_snp_evidence() {
        for required in [true, false] {
            let platform = gate_execution(&SevSnpEvidence, required, b"nonce")
                .await
                .expect("SEV-SNP evidence proceeds");
            assert_eq!(platform, TeePlatform::SevSnp);
        }
    }

    #[tokio::test]
    async fn required_gate_rejects_development_evidence() {
        let provider = DevAttestation::allow_insecure_dev();
        let result = gate_execution(&provider, true, b"nonce").await;
        assert!(
            matches!(result, Err(EnclaveError::Rejected(_))),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn required_gate_refuses_when_the_provider_fails() {
        let provider = DevAttestation::strict();
        let result = gate_execution(&provider, true, b"nonce").await;
        assert!(
            matches!(result, Err(EnclaveError::Unavailable(_))),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn unrequired_gate_proceeds_unattested() {
        for provider in [
            DevAttestation::allow_insecure_dev(),
            DevAttestation::strict(),
        ] {
            let platform = gate_execution(&provider, false, b"nonce")
                .await
                .expect("development proceeds");
            assert_eq!(platform, TeePlatform::Development);
        }
    }
}
