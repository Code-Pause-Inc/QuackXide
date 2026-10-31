//! Portable AMD SEV-SNP `ARK -> ASK -> VCEK` certificate-chain and report
//! verifier (`P47`).
//!
//! Designed for both the key-release relying party (`P50`) and in-process /
//! browser verification (`P48`, `P85`). Production verifiers pin AMD root
//! keys only and reject any report signed by a [`SimulatedSnp`](crate::SimulatedSnp)
//! chain.

use p384::ecdsa::signature::Verifier as _;
use p384::ecdsa::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::binding::REPORT_DATA_BYTES;
use crate::report::{
    CHIP_ID_BYTES, MEASUREMENT_BYTES, P384_SCALAR_BYTES, SNP_REPORT_SIGNED_BYTES,
    SNP_REPORT_VERSION, SNP_SIG_ALGO_ECDSA_P384_SHA384, SnpReport, TcbVersion,
};
use crate::{EnclaveError, TeePlatform};

pub(crate) const ARK_CERT_DOMAIN: &[u8] = b"quackxide-snp-ark-cert-v1";
pub(crate) const ASK_CERT_DOMAIN: &[u8] = b"quackxide-snp-ask-cert-v1";
pub(crate) const VCEK_CERT_DOMAIN: &[u8] = b"quackxide-snp-vcek-cert-v1";

/// AMD Root Key (ARK) self-signed root certificate in the SEV-SNP endorsement
/// hierarchy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArkCertificate {
    pub serial: [u8; 16],
    pub public_key_sec1: Vec<u8>,
    pub not_before_unix: u64,
    pub not_after_unix: u64,
    pub signature: Vec<u8>,
}

impl ArkCertificate {
    pub(crate) fn tbs_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128);
        out.extend_from_slice(ARK_CERT_DOMAIN);
        out.extend_from_slice(&self.serial);
        out.extend_from_slice(&(self.public_key_sec1.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.public_key_sec1);
        out.extend_from_slice(&self.not_before_unix.to_le_bytes());
        out.extend_from_slice(&self.not_after_unix.to_le_bytes());
        out
    }
}

/// AMD SEV Signing Key (ASK) intermediate certificate signed by the ARK.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AskCertificate {
    pub serial: [u8; 16],
    pub issuer_serial: [u8; 16],
    pub public_key_sec1: Vec<u8>,
    pub not_before_unix: u64,
    pub not_after_unix: u64,
    pub signature: Vec<u8>,
}

impl AskCertificate {
    pub(crate) fn tbs_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(144);
        out.extend_from_slice(ASK_CERT_DOMAIN);
        out.extend_from_slice(&self.serial);
        out.extend_from_slice(&self.issuer_serial);
        out.extend_from_slice(&(self.public_key_sec1.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.public_key_sec1);
        out.extend_from_slice(&self.not_before_unix.to_le_bytes());
        out.extend_from_slice(&self.not_after_unix.to_le_bytes());
        out
    }
}

/// Versioned Chip Endorsement Key (VCEK) leaf certificate signed by the ASK.
/// Binds the physical CPU's `chip_id` and endorsed `tcb` version (matching AMD
/// KDS X.509 OIDs `1.3.6.1.4.1.3704.1.3.*` and `1.3.6.1.4.1.3704.1.4`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VcekCertificate {
    pub serial: [u8; 16],
    pub issuer_serial: [u8; 16],
    pub public_key_sec1: Vec<u8>,
    #[serde(with = "chip_id_serde")]
    pub chip_id: [u8; CHIP_ID_BYTES],
    pub tcb: TcbVersion,
    pub not_before_unix: u64,
    pub not_after_unix: u64,
    pub signature: Vec<u8>,
}

mod chip_id_serde {
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use crate::report::CHIP_ID_BYTES;

    pub fn serialize<S: Serializer>(bytes: &[u8; CHIP_ID_BYTES], s: S) -> Result<S::Ok, S::Error> {
        bytes.as_slice().serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; CHIP_ID_BYTES], D::Error> {
        let vec = Vec::<u8>::deserialize(d)?;
        vec.try_into()
            .map_err(|_| D::Error::custom("chip_id must be 64 bytes"))
    }
}

impl VcekCertificate {
    pub(crate) fn tbs_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(216);
        out.extend_from_slice(VCEK_CERT_DOMAIN);
        out.extend_from_slice(&self.serial);
        out.extend_from_slice(&self.issuer_serial);
        out.extend_from_slice(&(self.public_key_sec1.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.public_key_sec1);
        out.extend_from_slice(&self.chip_id);
        out.extend_from_slice(&self.tcb.to_u64().to_le_bytes());
        out.extend_from_slice(&self.not_before_unix.to_le_bytes());
        out.extend_from_slice(&self.not_after_unix.to_le_bytes());
        out
    }
}

/// Complete `ARK -> ASK -> VCEK` endorsement certificate chain accompanying an
/// SEV-SNP attestation report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnpCertChain {
    pub ark: ArkCertificate,
    pub ask: AskCertificate,
    pub vcek: VcekCertificate,
}

impl SnpCertChain {
    pub fn to_bytes(&self) -> Result<Vec<u8>, EnclaveError> {
        serde_json::to_vec(self)
            .map_err(|e| EnclaveError::Rejected(format!("failed to serialize cert chain: {e}")))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EnclaveError> {
        if bytes.is_empty() {
            return Err(EnclaveError::Rejected(
                "missing SEV-SNP certificate chain".into(),
            ));
        }
        serde_json::from_slice(bytes).map_err(|e| {
            EnclaveError::Rejected(format!("malformed SEV-SNP certificate chain: {e}"))
        })
    }
}

/// Pinned root of trust for [`AttestationVerifier`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustRoot {
    /// Production hardware root: accepts only pinned AMD root public keys and
    /// marks verified reports as [`TeePlatform::SevSnp`].
    ProductionAmd { ark_public_keys_sec1: Vec<Vec<u8>> },
    /// Development/CI simulated root: accepts only the specific synthetic ARK
    /// root key and marks verified reports as [`TeePlatform::Simulated`].
    Simulated { ark_public_key_sec1: Vec<u8> },
}

/// Policy enforced by [`AttestationVerifier::verify`].
#[derive(Debug, Clone)]
pub struct VerificationPolicy {
    /// Allowed 48-byte `MEASUREMENT` launch digests. An empty allowlist fails
    /// closed on every report.
    pub expected_measurements: Vec<[u8; MEASUREMENT_BYTES]>,
    /// Minimum acceptable `REPORTED_TCB` component versions.
    pub min_tcb: TcbVersion,
    /// Revoked certificate serial numbers (CRL enforcement).
    pub revoked_serials: Vec<[u8; 16]>,
    /// Current Unix timestamp (seconds) for certificate validity checks.
    pub now_unix: u64,
}

/// Proof of a cryptographically verified SEV-SNP attestation report.
///
/// Fields are private so only [`AttestationVerifier::verify`] can construct an
/// instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedReport {
    platform: TeePlatform,
    measurement: [u8; MEASUREMENT_BYTES],
    reported_tcb: TcbVersion,
    report_data: [u8; REPORT_DATA_BYTES],
    chip_id: [u8; CHIP_ID_BYTES],
}

impl VerifiedReport {
    pub fn platform(&self) -> TeePlatform {
        self.platform
    }

    pub fn measurement(&self) -> &[u8; MEASUREMENT_BYTES] {
        &self.measurement
    }

    pub fn reported_tcb(&self) -> TcbVersion {
        self.reported_tcb
    }

    pub fn report_data(&self) -> &[u8; REPORT_DATA_BYTES] {
        &self.report_data
    }

    pub fn chip_id(&self) -> &[u8; CHIP_ID_BYTES] {
        &self.chip_id
    }
}

/// Portable SEV-SNP report and certificate-chain verifier.
#[derive(Debug, Clone)]
pub struct AttestationVerifier {
    trust_root: TrustRoot,
    policy: VerificationPolicy,
}

impl AttestationVerifier {
    pub fn new(trust_root: TrustRoot, policy: VerificationPolicy) -> Self {
        Self { trust_root, policy }
    }

    pub fn trust_root(&self) -> &TrustRoot {
        &self.trust_root
    }

    pub fn policy(&self) -> &VerificationPolicy {
        &self.policy
    }

    /// Verify a 1184-byte binary SEV-SNP `report_bytes`, its `ARK -> ASK -> VCEK`
    /// `cert_chain`, and the expected 64-byte `expected_report_data` (or nonce
    /// mapped via [`crate::report::report_data_from_nonce`]).
    pub fn verify(
        &self,
        report_bytes: &[u8],
        cert_chain: &SnpCertChain,
        expected_report_data: &[u8; REPORT_DATA_BYTES],
    ) -> Result<VerifiedReport, EnclaveError> {
        if self.policy.expected_measurements.is_empty() {
            return Err(EnclaveError::Rejected(
                "verification policy has no allowed measurements (fail closed)".into(),
            ));
        }

        // 1. Validate ARK against pinned TrustRoot.
        let platform = self.verify_ark_root(&cert_chain.ark)?;

        // 2. Check certificate validity windows and CRL revocations across all 3 certs.
        self.check_validity_and_revocation(
            "ARK",
            &cert_chain.ark.serial,
            cert_chain.ark.not_before_unix,
            cert_chain.ark.not_after_unix,
        )?;
        self.check_validity_and_revocation(
            "ASK",
            &cert_chain.ask.serial,
            cert_chain.ask.not_before_unix,
            cert_chain.ask.not_after_unix,
        )?;
        self.check_validity_and_revocation(
            "VCEK",
            &cert_chain.vcek.serial,
            cert_chain.vcek.not_before_unix,
            cert_chain.vcek.not_after_unix,
        )?;

        // 3. Verify ARK -> ASK -> VCEK signatures and issuer serial linkage.
        if !bool::from(cert_chain.ask.issuer_serial.ct_eq(&cert_chain.ark.serial)) {
            return Err(EnclaveError::Rejected(
                "ASK issuer serial does not match ARK serial".into(),
            ));
        }
        if !bool::from(cert_chain.vcek.issuer_serial.ct_eq(&cert_chain.ask.serial)) {
            return Err(EnclaveError::Rejected(
                "VCEK issuer serial does not match ASK serial".into(),
            ));
        }

        let ark_vk = parse_p384_key("ARK", &cert_chain.ark.public_key_sec1)?;
        let ask_vk = parse_p384_key("ASK", &cert_chain.ask.public_key_sec1)?;
        let vcek_vk = parse_p384_key("VCEK", &cert_chain.vcek.public_key_sec1)?;

        verify_p384_sig(
            "ARK self-signature",
            &ark_vk,
            &cert_chain.ark.tbs_bytes(),
            &cert_chain.ark.signature,
        )?;
        verify_p384_sig(
            "ASK signature",
            &ark_vk,
            &cert_chain.ask.tbs_bytes(),
            &cert_chain.ask.signature,
        )?;
        verify_p384_sig(
            "VCEK signature",
            &ask_vk,
            &cert_chain.vcek.tbs_bytes(),
            &cert_chain.vcek.signature,
        )?;

        // 4. Parse binary 1184-byte SEV-SNP report and verify VCEK signature over bytes 0x000..0x2A0.
        let report = SnpReport::from_bytes(report_bytes)?;
        let report_sig = parse_snp_report_signature(&report)?;
        vcek_vk
            .verify(&report_bytes[..SNP_REPORT_SIGNED_BYTES], &report_sig)
            .map_err(|_| {
                EnclaveError::Rejected("SEV-SNP report signature verification failed".into())
            })?;

        // 5. Verify report structural invariants (version, VMPL0, signature algorithm).
        if report.version != SNP_REPORT_VERSION {
            return Err(EnclaveError::Rejected(format!(
                "unsupported SEV-SNP report version: {}",
                report.version
            )));
        }
        if report.vmpl != 0 {
            return Err(EnclaveError::Rejected(format!(
                "SEV-SNP report must originate from VMPL 0, got VMPL {}",
                report.vmpl
            )));
        }
        if report.signature_algo != SNP_SIG_ALGO_ECDSA_P384_SHA384 {
            return Err(EnclaveError::Rejected(format!(
                "unsupported SEV-SNP signature algorithm: {}",
                report.signature_algo
            )));
        }

        // 6. Verify VCEK hardware extensions match the report's CHIP_ID and REPORTED_TCB.
        if !bool::from(cert_chain.vcek.chip_id.ct_eq(&report.chip_id)) {
            return Err(EnclaveError::Rejected(
                "VCEK chip_id extension does not match report CHIP_ID".into(),
            ));
        }
        if cert_chain.vcek.tcb != report.reported_tcb {
            return Err(EnclaveError::Rejected(
                "VCEK TCB extension does not match report REPORTED_TCB".into(),
            ));
        }

        // 7. Enforce guest policy: debug mode and migration agent must be disabled.
        if report.policy.debug_enabled() {
            return Err(EnclaveError::Rejected(
                "SEV-SNP guest policy has DEBUG enabled".into(),
            ));
        }
        if report.policy.migration_agent_enabled() {
            return Err(EnclaveError::Rejected(
                "SEV-SNP guest policy has MIGRATE_MA enabled".into(),
            ));
        }

        // 8. Enforce minimum TCB version.
        if !report.reported_tcb.meets_minimum(&self.policy.min_tcb) {
            return Err(EnclaveError::Rejected(
                "SEV-SNP report REPORTED_TCB is below policy minimum".into(),
            ));
        }

        // 9. Enforce measurement allowlist in constant time.
        let measurement_allowed = self
            .policy
            .expected_measurements
            .iter()
            .fold(subtle::Choice::from(0u8), |acc, allowed| {
                acc | report.measurement.ct_eq(allowed)
            });
        if !bool::from(measurement_allowed) {
            return Err(EnclaveError::Rejected(
                "SEV-SNP launch MEASUREMENT is not in the allowlist".into(),
            ));
        }

        // 10. Enforce 64-byte REPORT_DATA binding in constant time.
        if !bool::from(report.report_data.ct_eq(expected_report_data)) {
            return Err(EnclaveError::Rejected(
                "SEV-SNP REPORT_DATA does not match expected nonce/binding".into(),
            ));
        }

        Ok(VerifiedReport {
            platform,
            measurement: report.measurement,
            reported_tcb: report.reported_tcb,
            report_data: report.report_data,
            chip_id: report.chip_id,
        })
    }

    fn verify_ark_root(&self, ark: &ArkCertificate) -> Result<TeePlatform, EnclaveError> {
        match &self.trust_root {
            TrustRoot::ProductionAmd {
                ark_public_keys_sec1,
            } => {
                if ark_public_keys_sec1.is_empty() {
                    return Err(EnclaveError::Rejected(
                        "production trust root has no pinned AMD ARK keys".into(),
                    ));
                }
                let matched = ark_public_keys_sec1.iter().any(|pinned| {
                    pinned.len() == ark.public_key_sec1.len()
                        && bool::from(pinned.as_slice().ct_eq(ark.public_key_sec1.as_slice()))
                });
                if !matched {
                    return Err(EnclaveError::Rejected(
                        "ARK certificate is not signed by a pinned production AMD root".into(),
                    ));
                }
                Ok(TeePlatform::SevSnp)
            }
            TrustRoot::Simulated {
                ark_public_key_sec1,
            } => {
                let matched = ark_public_key_sec1.len() == ark.public_key_sec1.len()
                    && bool::from(
                        ark_public_key_sec1
                            .as_slice()
                            .ct_eq(ark.public_key_sec1.as_slice()),
                    );
                if !matched {
                    return Err(EnclaveError::Rejected(
                        "ARK certificate does not match configured simulated trust root".into(),
                    ));
                }
                Ok(TeePlatform::Simulated)
            }
        }
    }

    fn check_validity_and_revocation(
        &self,
        label: &str,
        serial: &[u8; 16],
        not_before: u64,
        not_after: u64,
    ) -> Result<(), EnclaveError> {
        if self.policy.now_unix < not_before || self.policy.now_unix > not_after {
            return Err(EnclaveError::Rejected(format!(
                "{label} certificate is expired or not yet valid"
            )));
        }
        let revoked = self
            .policy
            .revoked_serials
            .iter()
            .fold(subtle::Choice::from(0u8), |acc, rev| {
                acc | serial.ct_eq(rev)
            });
        if bool::from(revoked) {
            return Err(EnclaveError::Rejected(format!(
                "{label} certificate serial is revoked"
            )));
        }
        Ok(())
    }
}

fn parse_p384_key(label: &str, sec1: &[u8]) -> Result<VerifyingKey, EnclaveError> {
    VerifyingKey::from_sec1_bytes(sec1)
        .map_err(|_| EnclaveError::Rejected(format!("invalid {label} P-384 public key")))
}

fn verify_p384_sig(
    label: &str,
    vk: &VerifyingKey,
    tbs: &[u8],
    sig_bytes: &[u8],
) -> Result<(), EnclaveError> {
    let sig = Signature::from_slice(sig_bytes)
        .map_err(|_| EnclaveError::Rejected(format!("malformed {label} P-384 signature")))?;
    vk.verify(tbs, &sig)
        .map_err(|_| EnclaveError::Rejected(format!("{label} verification failed")))
}

/// Convert the little-endian 72-byte padded `R` and `S` fields of an AMD
/// SEV-SNP binary report into a big-endian P-384 ECDSA [`Signature`].
fn parse_snp_report_signature(report: &SnpReport) -> Result<Signature, EnclaveError> {
    let mut sig_be = [0u8; P384_SCALAR_BYTES * 2];
    for i in 0..P384_SCALAR_BYTES {
        sig_be[i] = report.signature_r[P384_SCALAR_BYTES - 1 - i];
        sig_be[P384_SCALAR_BYTES + i] = report.signature_s[P384_SCALAR_BYTES - 1 - i];
    }
    Signature::from_slice(&sig_be)
        .map_err(|_| EnclaveError::Rejected("invalid P-384 scalars in SEV-SNP report".into()))
}
