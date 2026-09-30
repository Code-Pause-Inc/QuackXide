//! TEE attestation for the confidential pipelines (AMD SEV-SNP on GCP
//! Confidential VMs).
//!
//! Every pipeline is written against [`AttestationProvider`], so no code
//! path can skip attestation. SEV-SNP report acquisition is not implemented:
//! [`SnpAttestation`] probes the guest device and refuses. The dev stand-in
//! fails closed unless insecurity is requested explicitly.

use async_trait::async_trait;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeePlatform {
    /// AMD SEV-SNP (GCP Confidential VM) — the production platform.
    SevSnp,
    /// Explicitly-insecure local development stand-in. Never valid in prod.
    Development,
}

/// Hardware evidence binding a caller-supplied freshness nonce.
#[derive(Debug, Clone)]
pub struct AttestationEvidence {
    pub platform: TeePlatform,
    /// Freshness nonce echoed inside the signed report.
    pub nonce: Vec<u8>,
    /// Raw attestation report bytes (SEV-SNP report in production).
    pub report: Vec<u8>,
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
    /// Produce hardware evidence binding `nonce`. In production this is an
    /// SEV-SNP report; anything that cannot produce one must fail closed.
    async fn produce_evidence(&self, nonce: &[u8]) -> Result<AttestationEvidence, EnclaveError>;
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
            report: Vec::new(),
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

/// Execution gate for confidential workloads; `Ok` means execution may
/// proceed on the returned platform.
///
/// With `require_attestation`, only SEV-SNP evidence proceeds. Without it
/// (development only), dev evidence and attestation errors also proceed.
/// The connector pipeline has its own gate with per-outcome audit events.
pub async fn gate_execution(
    provider: &dyn AttestationProvider,
    require_attestation: bool,
    nonce: &[u8],
) -> Result<TeePlatform, EnclaveError> {
    match provider.produce_evidence(nonce).await {
        Ok(evidence) if evidence.platform == TeePlatform::SevSnp => Ok(TeePlatform::SevSnp),
        Ok(_) if !require_attestation => Ok(TeePlatform::Development),
        Ok(_) => Err(EnclaveError::Rejected(
            "evidence platform is not SEV-SNP".into(),
        )),
        Err(_) if !require_attestation => Ok(TeePlatform::Development),
        Err(err) => Err(err),
    }
}

/// The SNP provider when attestation is required, otherwise the insecure
/// dev provider.
pub fn provider_for(attestation_required: bool) -> std::sync::Arc<dyn AttestationProvider> {
    if attestation_required {
        std::sync::Arc::new(SnpAttestation::new())
    } else {
        std::sync::Arc::new(DevAttestation::allow_insecure_dev())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
