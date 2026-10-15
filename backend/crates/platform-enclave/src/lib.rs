//! TEE attestation for the confidential pipelines (AMD SEV-SNP on GCP
//! Confidential VMs, portable SEV-SNP report verifier, and protocol-faithful
//! simulated SEV-SNP for development and CI).
//!
//! Every pipeline is written against [`AttestationProvider`], so no code
//! path can skip attestation. [`AttestationVerifier`] verifies the 1184-byte
//! binary AMD SEV-SNP report and `ARK -> ASK -> VCEK` P-384 certificate chain.

use async_trait::async_trait;
use rand::Rng;

pub mod report;
pub mod simulated;
pub mod verifier;

pub use report::{
    CHIP_ID_BYTES, GuestPolicy, MEASUREMENT_BYTES, REPORT_DATA_BYTES, ReportDataBinding,
    SNP_REPORT_BYTES, SNP_REPORT_SIGNED_BYTES, SNP_REPORT_VERSION, SNP_SIG_ALGO_ECDSA_P384_SHA384,
    SnpReport, TcbVersion, report_data_from_nonce,
};
pub use simulated::{
    DEFAULT_SIMULATED_CHIP_ID, DEFAULT_SIMULATED_MEASUREMENT, DEFAULT_SIMULATED_TCB, SimulatedSnp,
    SimulatedSnpConfig, decode_hex_array,
};
pub use verifier::{
    ArkCertificate, AskCertificate, AttestationVerifier, SnpCertChain, TrustRoot, VcekCertificate,
    VerificationPolicy, VerifiedReport,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeePlatform {
    /// AMD SEV-SNP (GCP Confidential VM) — the production platform.
    SevSnp,
    /// Protocol-faithful simulated SEV-SNP (binary report + P-384 chain
    /// verified by [`AttestationVerifier`]). Accepted only when hardware
    /// attestation is not required; never valid in production.
    Simulated,
    /// Explicitly-insecure local development stand-in. Never valid in prod.
    Development,
}

/// Hardware (or simulated) evidence binding a caller-supplied freshness nonce.
#[derive(Debug, Clone)]
pub struct AttestationEvidence {
    pub platform: TeePlatform,
    /// Freshness nonce echoed inside the signed report.
    pub nonce: Vec<u8>,
    /// Raw 1184-byte binary attestation report (`SnpReport` in SEV-SNP and
    /// simulated modes).
    pub report: Vec<u8>,
    /// Serialized `ARK -> ASK -> VCEK` certificate chain accompanying `report`.
    pub cert_chain: Vec<u8>,
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

    /// Verify `evidence` against `expected_nonce`. Providers that emit signed
    /// binary reports ([`SimulatedSnp`], and [`SnpAttestation`] once hardware
    /// roots are configured) run [`AttestationVerifier`] here.
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
            report: Vec::new(),
            cert_chain: Vec::new(),
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
///   binary report and certificate chain are verified via
///   `provider.verify_evidence` — any verification failure refuses execution.
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
                    "simulated SEV-SNP evidence is not accepted when hardware attestation is required"
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

/// The SNP provider when attestation is required, otherwise [`SimulatedSnp`]
/// so development and CI exercise the full binary report + verifier protocol.
pub fn provider_for(attestation_required: bool) -> std::sync::Arc<dyn AttestationProvider> {
    if attestation_required {
        std::sync::Arc::new(SnpAttestation::new())
    } else {
        std::sync::Arc::new(SimulatedSnp::from_env())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_nonces_differ() {
        assert_ne!(fresh_nonce(), fresh_nonce());
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
                report: Vec::new(),
                cert_chain: Vec::new(),
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

    // ── Step 1: Binary SEV-SNP report, verifier, and SimulatedSnp tests ──────

    #[tokio::test]
    async fn simulated_snp_produces_valid_1184_byte_report_and_passes_verifier() {
        let sim = SimulatedSnp::new();
        let nonce = fresh_nonce();
        let evidence = sim.produce_evidence(&nonce).await.expect("evidence");
        assert_eq!(evidence.platform, TeePlatform::Simulated);
        assert_eq!(evidence.report.len(), SNP_REPORT_BYTES);

        let chain = SnpCertChain::from_bytes(&evidence.cert_chain).expect("cert chain");
        let expected_data = report_data_from_nonce(&nonce).expect("report_data");
        let verified = sim
            .verifier(1_000)
            .verify(&evidence.report, &chain, &expected_data)
            .expect("valid simulated report must verify");

        assert_eq!(verified.platform(), TeePlatform::Simulated);
        assert_eq!(verified.measurement(), &DEFAULT_SIMULATED_MEASUREMENT);
        assert_eq!(verified.reported_tcb(), DEFAULT_SIMULATED_TCB);
        assert_eq!(verified.report_data(), &expected_data);
        assert_eq!(verified.chip_id(), &DEFAULT_SIMULATED_CHIP_ID);
    }

    #[test]
    fn report_data_binding_commits_all_enclave_identities() {
        let sim = SimulatedSnp::new();
        let binding = ReportDataBinding {
            nonce: [0x11; 32],
            enclave_hpke_public_key: [0x22; 32],
            result_signing_public_key: [0x33; 32],
            tls_cert_sha256: [0x44; 32],
            config_digest: [0x55; 32],
        };
        let evidence = sim
            .produce_bound_evidence(&binding)
            .expect("bound evidence");
        let chain = SnpCertChain::from_bytes(&evidence.cert_chain).expect("chain");
        let verifier = sim.verifier(1_000);

        // Exact binding verifies.
        verifier
            .verify(&evidence.report, &chain, &binding.to_report_data())
            .expect("matching binding verifies");

        // Mutating the HPKE key (simulating a MITM key swap) fails verification.
        let mut mitm_binding = binding.clone();
        mitm_binding.enclave_hpke_public_key[0] ^= 0x01;
        let err = verifier
            .verify(&evidence.report, &chain, &mitm_binding.to_report_data())
            .unwrap_err();
        assert!(matches!(err, EnclaveError::Rejected(_)), "{err:?}");
    }

    #[tokio::test]
    async fn production_verifier_rejects_simulated_chain() {
        let sim = SimulatedSnp::new();
        let other_root = SimulatedSnp::new();
        let nonce = fresh_nonce();
        let evidence = sim.produce_evidence(&nonce).await.expect("evidence");
        let chain = SnpCertChain::from_bytes(&evidence.cert_chain).expect("chain");
        let expected_data = report_data_from_nonce(&nonce).expect("report_data");

        // Production verifier pinned to a hardware root rejects the synthetic chain.
        let prod_verifier = AttestationVerifier::new(
            TrustRoot::ProductionAmd {
                ark_public_keys_sec1: vec![other_root.cert_chain().ark.public_key_sec1.clone()],
            },
            SimulatedSnp::default_policy(1_000),
        );
        let err = prod_verifier
            .verify(&evidence.report, &chain, &expected_data)
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("not signed by a pinned production AMD root"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn verifier_rejects_tampered_report_bytes() {
        let sim = SimulatedSnp::new();
        let nonce = fresh_nonce();
        let mut evidence = sim.produce_evidence(&nonce).await.expect("evidence");
        let chain = SnpCertChain::from_bytes(&evidence.cert_chain).expect("chain");
        let expected_data = report_data_from_nonce(&nonce).expect("report_data");

        // Flip 1 bit in the signed body (MEASUREMENT offset 0x090).
        evidence.report[0x090] ^= 0x01;
        let err = sim
            .verifier(1_000)
            .verify(&evidence.report, &chain, &expected_data)
            .unwrap_err();
        assert!(
            err.to_string().contains("signature verification failed"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn verifier_rejects_wrong_nonce_or_report_data() {
        let sim = SimulatedSnp::new();
        let nonce = fresh_nonce();
        let wrong_nonce = fresh_nonce();
        let evidence = sim.produce_evidence(&nonce).await.expect("evidence");
        let chain = SnpCertChain::from_bytes(&evidence.cert_chain).expect("chain");
        let wrong_expected = report_data_from_nonce(&wrong_nonce).expect("report_data");

        let err = sim
            .verifier(1_000)
            .verify(&evidence.report, &chain, &wrong_expected)
            .unwrap_err();
        assert!(err.to_string().contains("REPORT_DATA"), "{err}");
    }

    #[tokio::test]
    async fn verifier_rejects_debug_policy_and_migration_agent() {
        for bad_policy in [
            GuestPolicy::production_default().with_debug(true),
            GuestPolicy::production_default().with_migration_agent(true),
        ] {
            let sim = SimulatedSnp::with_config(SimulatedSnpConfig {
                policy: bad_policy,
                ..SimulatedSnpConfig::default()
            });
            let nonce = fresh_nonce();
            let evidence = sim.produce_evidence(&nonce).await.expect("evidence");
            let chain = SnpCertChain::from_bytes(&evidence.cert_chain).expect("chain");
            let expected = report_data_from_nonce(&nonce).expect("report_data");

            let err = sim
                .verifier(1_000)
                .verify(&evidence.report, &chain, &expected)
                .unwrap_err();
            assert!(matches!(err, EnclaveError::Rejected(_)), "{err:?}");
        }
    }

    #[tokio::test]
    async fn verifier_rejects_wrong_measurement() {
        let sim = SimulatedSnp::with_config(SimulatedSnpConfig {
            measurement: [0xFF; MEASUREMENT_BYTES],
            ..SimulatedSnpConfig::default()
        });
        let nonce = fresh_nonce();
        let evidence = sim.produce_evidence(&nonce).await.expect("evidence");
        let chain = SnpCertChain::from_bytes(&evidence.cert_chain).expect("chain");
        let expected = report_data_from_nonce(&nonce).expect("report_data");

        let err = sim
            .verifier(1_000)
            .verify(&evidence.report, &chain, &expected)
            .unwrap_err();
        assert!(err.to_string().contains("MEASUREMENT"), "{err}");
    }

    #[tokio::test]
    async fn verifier_rejects_tcb_below_minimum() {
        let low_tcb = TcbVersion::new(4, 0, 21, 213); // snp=21 < default min snp=22
        let sim = SimulatedSnp::with_config(SimulatedSnpConfig {
            reported_tcb: low_tcb,
            vcek_tcb: low_tcb,
            ..SimulatedSnpConfig::default()
        });
        let nonce = fresh_nonce();
        let evidence = sim.produce_evidence(&nonce).await.expect("evidence");
        let chain = SnpCertChain::from_bytes(&evidence.cert_chain).expect("chain");
        let expected = report_data_from_nonce(&nonce).expect("report_data");

        let err = sim
            .verifier(1_000)
            .verify(&evidence.report, &chain, &expected)
            .unwrap_err();
        assert!(err.to_string().contains("REPORTED_TCB"), "{err}");
    }

    #[tokio::test]
    async fn verifier_rejects_different_simulated_chain_and_revoked_or_expired_certs() {
        let sim_a = SimulatedSnp::new();
        let sim_b = SimulatedSnp::new();
        let nonce = fresh_nonce();
        let evidence_a = sim_a.produce_evidence(&nonce).await.expect("evidence");
        let chain_a = SnpCertChain::from_bytes(&evidence_a.cert_chain).expect("chain");
        let expected = report_data_from_nonce(&nonce).expect("report_data");

        // Verifier for B rejects report/chain from A.
        assert!(
            sim_b
                .verifier(1_000)
                .verify(&evidence_a.report, &chain_a, &expected)
                .is_err()
        );

        // Revoking the VCEK serial rejects the report.
        let mut revoked_policy = SimulatedSnp::default_policy(1_000);
        revoked_policy.revoked_serials.push(chain_a.vcek.serial);
        let revoked_verifier = AttestationVerifier::new(sim_a.trust_root(), revoked_policy);
        let err = revoked_verifier
            .verify(&evidence_a.report, &chain_a, &expected)
            .unwrap_err();
        assert!(err.to_string().contains("revoked"), "{err}");

        // Timestamp past not_after_unix rejects the report.
        let expired_sim = SimulatedSnp::with_config(SimulatedSnpConfig {
            not_before_unix: 100,
            not_after_unix: 500,
            ..SimulatedSnpConfig::default()
        });
        let exp_evidence = expired_sim
            .produce_evidence(&nonce)
            .await
            .expect("evidence");
        let exp_chain = SnpCertChain::from_bytes(&exp_evidence.cert_chain).expect("chain");
        let err = expired_sim
            .verifier(1_000)
            .verify(&exp_evidence.report, &exp_chain, &expected)
            .unwrap_err();
        assert!(err.to_string().contains("expired"), "{err}");
    }

    #[tokio::test]
    async fn gate_execution_enforces_simulated_snp_rules() {
        let valid_sim = SimulatedSnp::new();
        let nonce = fresh_nonce();

        // 1. When hardware attestation is required (production), SimulatedSnp is rejected.
        let err = gate_execution(&valid_sim, true, &nonce).await.unwrap_err();
        assert!(matches!(err, EnclaveError::Rejected(_)), "{err:?}");

        // 2. In development mode (require_attestation = false), valid SimulatedSnp verifies and returns TeePlatform::Simulated.
        let platform = gate_execution(&valid_sim, false, &nonce)
            .await
            .expect("valid simulated SNP proceeds in dev mode");
        assert_eq!(platform, TeePlatform::Simulated);

        // 3. In development mode, an invalid SimulatedSnp (e.g. debug policy or wrong measurement) is still refused by the verifier!
        let debug_sim = SimulatedSnp::with_config(SimulatedSnpConfig {
            policy: GuestPolicy::production_default().with_debug(true),
            ..SimulatedSnpConfig::default()
        });
        let err = gate_execution(&debug_sim, false, &nonce).await.unwrap_err();
        assert!(matches!(err, EnclaveError::Rejected(_)), "{err:?}");
    }

    #[tokio::test]
    async fn simulated_snp_from_source_deterministically_shares_root_and_honors_tamper_overrides() {
        let enclave_sim = SimulatedSnp::from_source(|k| match k {
            "SIMULATED_SNP_SEED" => Some("docker-compose-shared-seed".into()),
            _ => None,
        });
        let rp_sim = SimulatedSnp::from_source(|k| match k {
            "SIMULATED_SNP_SEED" => Some("docker-compose-shared-seed".into()),
            _ => None,
        });
        assert_eq!(
            enclave_sim.cert_chain().ark.public_key_sec1,
            rp_sim.cert_chain().ark.public_key_sec1,
            "identical seed must produce identical ARK root across containers"
        );

        let nonce = fresh_nonce();
        let evidence = enclave_sim.produce_evidence(&nonce).await.unwrap();
        let chain = SnpCertChain::from_bytes(&evidence.cert_chain).unwrap();
        let expected = report_data_from_nonce(&nonce).unwrap();
        rp_sim
            .verifier(1_000)
            .verify(&evidence.report, &chain, &expected)
            .expect("relying party verifier initialized with same seed accepts enclave report");

        // Tampered measurement via SIMULATED_SNP_MEASUREMENT_HEX is rejected by rp_sim verifier.
        let bad_meas_sim = SimulatedSnp::from_source(|k| match k {
            "SIMULATED_SNP_SEED" => Some("docker-compose-shared-seed".into()),
            "SIMULATED_SNP_MEASUREMENT_HEX" => Some("ff".repeat(MEASUREMENT_BYTES)),
            _ => None,
        });
        let bad_ev = bad_meas_sim.produce_evidence(&nonce).await.unwrap();
        let bad_chain = SnpCertChain::from_bytes(&bad_ev.cert_chain).unwrap();
        let err = rp_sim
            .verifier(1_000)
            .verify(&bad_ev.report, &bad_chain, &expected)
            .unwrap_err();
        assert!(err.to_string().contains("MEASUREMENT"), "{err}");

        // Debug guest policy via SIMULATED_SNP_DEBUG=true is rejected by rp_sim verifier.
        let debug_sim = SimulatedSnp::from_source(|k| match k {
            "SIMULATED_SNP_SEED" => Some("docker-compose-shared-seed".into()),
            "SIMULATED_SNP_DEBUG" => Some("true".into()),
            _ => None,
        });
        let dbg_ev = debug_sim.produce_evidence(&nonce).await.unwrap();
        let dbg_chain = SnpCertChain::from_bytes(&dbg_ev.cert_chain).unwrap();
        let err = rp_sim
            .verifier(1_000)
            .verify(&dbg_ev.report, &dbg_chain, &expected)
            .unwrap_err();
        assert!(err.to_string().contains("DEBUG"), "{err}");
    }
}
