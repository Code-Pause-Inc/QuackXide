//! Simulated AMD SEV-SNP provider (`P84` / Issue `#49`) and synthetic
//! `ARK -> ASK -> VCEK` P-384 chain generator (`P47`).
//!
//! Produces protocol-faithful 1184-byte binary SEV-SNP reports signed by a
//! throwaway P-384 endorsement chain generated in process memory. Simulates
//! the cryptographic protocol, not hardware memory isolation: never valid when
//! `require_attestation` is `true` or against a [`TrustRoot::ProductionAmd`]
//! verifier.

use async_trait::async_trait;
use p384::ecdsa::signature::Signer as _;
use p384::ecdsa::{Signature, SigningKey};
use rand::Rng as _;
use rand::rngs::OsRng;

use crate::report::{
    CHIP_ID_BYTES, GuestPolicy, MEASUREMENT_BYTES, P384_SCALAR_BYTES,
    P384_SIGNATURE_COMPONENT_PADDED_BYTES, REPORT_DATA_BYTES, ReportDataBinding,
    SNP_REPORT_SIGNED_BYTES, SNP_REPORT_VERSION, SNP_SIG_ALGO_ECDSA_P384_SHA384, SnpReport,
    TcbVersion, report_data_from_nonce,
};
use crate::verifier::{
    ArkCertificate, AskCertificate, AttestationVerifier, SnpCertChain, TrustRoot, VcekCertificate,
    VerificationPolicy,
};
use crate::{AttestationEvidence, AttestationProvider, EnclaveError, TeePlatform};

/// Default synthetic launch measurement (`SHA-384("quackxide-simulated-enclave-v1")`).
pub const DEFAULT_SIMULATED_MEASUREMENT: [u8; MEASUREMENT_BYTES] = [
    0x71, 0x75, 0x61, 0x63, 0x6b, 0x78, 0x69, 0x64, 0x65, 0x2d, 0x73, 0x69, 0x6d, 0x2d, 0x73, 0x6e,
    0x70, 0x2d, 0x6d, 0x65, 0x61, 0x73, 0x75, 0x72, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x2d, 0x76, 0x31,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
];

/// Default synthetic hardware `CHIP_ID`.
pub const DEFAULT_SIMULATED_CHIP_ID: [u8; CHIP_ID_BYTES] = [0x42; CHIP_ID_BYTES];

/// Default simulated Genoa/Milan TCB version (`boot_loader=4, tee=0, snp=22, microcode=213`).
pub const DEFAULT_SIMULATED_TCB: TcbVersion = TcbVersion::new(4, 0, 22, 213);

/// Configuration for [`SimulatedSnp`].
///
/// Allows tests and local Docker simulation to override `measurement`, guest
/// `policy`, `reported_tcb`, `vmpl`, certificate validity windows, or
/// `report_data` to exercise every negative verification path.
#[derive(Debug, Clone)]
pub struct SimulatedSnpConfig {
    pub measurement: [u8; MEASUREMENT_BYTES],
    pub policy: GuestPolicy,
    pub reported_tcb: TcbVersion,
    pub vcek_tcb: TcbVersion,
    pub chip_id: [u8; CHIP_ID_BYTES],
    pub vcek_chip_id: [u8; CHIP_ID_BYTES],
    pub vmpl: u32,
    pub not_before_unix: u64,
    pub not_after_unix: u64,
    pub report_data_override: Option<[u8; REPORT_DATA_BYTES]>,
}

impl Default for SimulatedSnpConfig {
    fn default() -> Self {
        Self {
            measurement: DEFAULT_SIMULATED_MEASUREMENT,
            policy: GuestPolicy::production_default(),
            reported_tcb: DEFAULT_SIMULATED_TCB,
            vcek_tcb: DEFAULT_SIMULATED_TCB,
            chip_id: DEFAULT_SIMULATED_CHIP_ID,
            vcek_chip_id: DEFAULT_SIMULATED_CHIP_ID,
            vmpl: 0,
            not_before_unix: 0,
            not_after_unix: u64::MAX / 2,
            report_data_override: None,
        }
    }
}

/// Protocol-faithful simulated AMD SEV-SNP provider for development and CI.
pub struct SimulatedSnp {
    config: SimulatedSnpConfig,
    vcek_signing_key: SigningKey,
    cert_chain: SnpCertChain,
}

impl SimulatedSnp {
    /// Generate a fresh throwaway `ARK -> ASK -> VCEK` P-384 chain with default
    /// simulated parameters.
    pub fn new() -> Self {
        Self::with_config(SimulatedSnpConfig::default())
    }

    /// Construct [`SimulatedSnp`] from process environment variables:
    /// - `SIMULATED_SNP_SEED`: deterministic seed for the synthetic `ARK -> ASK -> VCEK`
    ///   chain so separate containers (`enclave-api` and `key-release-service`) share
    ///   the same simulated root of trust in local Docker.
    /// - `SIMULATED_SNP_MEASUREMENT_HEX`: 96-character hex (48-byte) override for
    ///   `MEASUREMENT` (used to test tampered-image refusal).
    /// - `SIMULATED_SNP_DEBUG`: when `true`/`1`, sets `GuestPolicy::DEBUG = 1`
    ///   (used to test debug-policy refusal).
    pub fn from_env() -> Self {
        Self::from_source(|k| std::env::var(k).ok())
    }

    /// Testable constructor reading [`SimulatedSnp`] overrides from `get`.
    pub fn from_source<F>(get: F) -> Self
    where
        F: Fn(&str) -> Option<String>,
    {
        let mut config = SimulatedSnpConfig::default();
        if let Some(raw_hex) = get("SIMULATED_SNP_MEASUREMENT_HEX") {
            let trimmed = raw_hex.trim();
            if !trimmed.is_empty()
                && let Some(bytes) = decode_hex_array::<MEASUREMENT_BYTES>(trimmed)
            {
                config.measurement = bytes;
            }
        }
        if let Some(raw_debug) = get("SIMULATED_SNP_DEBUG")
            && matches!(
                raw_debug.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        {
            config.policy = config.policy.with_debug(true);
        }
        if let Some(seed) = get("SIMULATED_SNP_SEED") {
            let trimmed = seed.trim();
            if !trimmed.is_empty() {
                return Self::with_seed_and_config(trimmed.as_bytes(), config);
            }
        }
        Self::with_config(config)
    }

    /// Generate a fresh throwaway `ARK -> ASK -> VCEK` P-384 chain with custom
    /// configuration.
    pub fn with_config(config: SimulatedSnpConfig) -> Self {
        let ark_sk = SigningKey::random(&mut OsRng);
        let ask_sk = SigningKey::random(&mut OsRng);
        let vcek_sk = SigningKey::random(&mut OsRng);
        let ark_serial: [u8; 16] = OsRng.r#gen();
        let ask_serial: [u8; 16] = OsRng.r#gen();
        let vcek_serial: [u8; 16] = OsRng.r#gen();
        Self::build_chain(
            config,
            ark_sk,
            ask_sk,
            vcek_sk,
            ark_serial,
            ask_serial,
            vcek_serial,
        )
    }

    /// Deterministically derive a synthetic `ARK -> ASK -> VCEK` P-384 chain from
    /// `seed` for multi-container local Docker simulation.
    pub fn with_seed_and_config(seed: &[u8], config: SimulatedSnpConfig) -> Self {
        let ark_sk = derive_p384_signing_key(seed, b"ark");
        let ask_sk = derive_p384_signing_key(seed, b"ask");
        let vcek_sk = derive_p384_signing_key(seed, b"vcek");
        let ark_serial = derive_serial(seed, b"ark-serial");
        let ask_serial = derive_serial(seed, b"ask-serial");
        let vcek_serial = derive_serial(seed, b"vcek-serial");
        Self::build_chain(
            config,
            ark_sk,
            ask_sk,
            vcek_sk,
            ark_serial,
            ask_serial,
            vcek_serial,
        )
    }

    fn build_chain(
        config: SimulatedSnpConfig,
        ark_sk: SigningKey,
        ask_sk: SigningKey,
        vcek_sk: SigningKey,
        ark_serial: [u8; 16],
        ask_serial: [u8; 16],
        vcek_serial: [u8; 16],
    ) -> Self {
        tracing::warn!(
            "SimulatedSnp active — protocol simulation only; host memory is NOT hardware-encrypted"
        );

        let ark_pk_sec1 = ark_sk
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let ask_pk_sec1 = ask_sk
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let vcek_pk_sec1 = vcek_sk
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();

        let mut ark = ArkCertificate {
            serial: ark_serial,
            public_key_sec1: ark_pk_sec1,
            not_before_unix: config.not_before_unix,
            not_after_unix: config.not_after_unix,
            signature: Vec::new(),
        };
        let ark_sig: Signature = ark_sk.sign(&ark.tbs_bytes());
        ark.signature = ark_sig.to_bytes().to_vec();

        let mut ask = AskCertificate {
            serial: ask_serial,
            issuer_serial: ark_serial,
            public_key_sec1: ask_pk_sec1,
            not_before_unix: config.not_before_unix,
            not_after_unix: config.not_after_unix,
            signature: Vec::new(),
        };
        let ask_sig: Signature = ark_sk.sign(&ask.tbs_bytes());
        ask.signature = ask_sig.to_bytes().to_vec();

        let mut vcek = VcekCertificate {
            serial: vcek_serial,
            issuer_serial: ask_serial,
            public_key_sec1: vcek_pk_sec1,
            chip_id: config.vcek_chip_id,
            tcb: config.vcek_tcb,
            not_before_unix: config.not_before_unix,
            not_after_unix: config.not_after_unix,
            signature: Vec::new(),
        };
        let vcek_sig: Signature = ask_sk.sign(&vcek.tbs_bytes());
        vcek.signature = vcek_sig.to_bytes().to_vec();

        Self {
            config,
            vcek_signing_key: vcek_sk,
            cert_chain: SnpCertChain { ark, ask, vcek },
        }
    }

    pub fn cert_chain(&self) -> &SnpCertChain {
        &self.cert_chain
    }

    pub fn config(&self) -> &SimulatedSnpConfig {
        &self.config
    }

    /// Trust root pinned to this instance's synthetic ARK public key.
    pub fn trust_root(&self) -> TrustRoot {
        TrustRoot::Simulated {
            ark_public_key_sec1: self.cert_chain.ark.public_key_sec1.clone(),
        }
    }

    /// Default verification policy matching [`DEFAULT_SIMULATED_MEASUREMENT`]
    /// and [`DEFAULT_SIMULATED_TCB`].
    pub fn default_policy(now_unix: u64) -> VerificationPolicy {
        VerificationPolicy {
            expected_measurements: vec![DEFAULT_SIMULATED_MEASUREMENT],
            min_tcb: DEFAULT_SIMULATED_TCB,
            revoked_serials: Vec::new(),
            now_unix,
        }
    }

    /// Construct a real [`AttestationVerifier`] configured with this instance's
    /// simulated [`TrustRoot`] and default policy.
    pub fn verifier(&self, now_unix: u64) -> AttestationVerifier {
        AttestationVerifier::new(self.trust_root(), Self::default_policy(now_unix))
    }

    /// Sign a binary 1184-byte [`SnpReport`] binding `report_data` with the
    /// synthetic VCEK P-384 key.
    pub fn sign_report(&self, report_data: [u8; REPORT_DATA_BYTES]) -> [u8; 1184] {
        let effective_report_data = self.config.report_data_override.unwrap_or(report_data);
        let mut report = SnpReport {
            version: SNP_REPORT_VERSION,
            guest_svn: 1,
            policy: self.config.policy,
            family_id: [0u8; 16],
            image_id: [0u8; 16],
            vmpl: self.config.vmpl,
            signature_algo: SNP_SIG_ALGO_ECDSA_P384_SHA384,
            current_tcb: self.config.reported_tcb,
            platform_info: 1, // SMT_EN = 1
            author_key_en: 0,
            report_data: effective_report_data,
            measurement: self.config.measurement,
            host_data: [0u8; 32],
            report_id: [0xAA; 32],
            reported_tcb: self.config.reported_tcb,
            chip_id: self.config.chip_id,
            committed_tcb: self.config.reported_tcb,
            launch_tcb: self.config.reported_tcb,
            signature_r: [0u8; P384_SIGNATURE_COMPONENT_PADDED_BYTES],
            signature_s: [0u8; P384_SIGNATURE_COMPONENT_PADDED_BYTES],
        };

        let body = report.signed_body_bytes();
        let sig: Signature = self.vcek_signing_key.sign(&body[..SNP_REPORT_SIGNED_BYTES]);
        let sig_be = sig.to_bytes();

        // AMD SEV-SNP stores R and S as 72-byte little-endian integers (first 48 bytes reversed).
        for i in 0..P384_SCALAR_BYTES {
            report.signature_r[i] = sig_be[P384_SCALAR_BYTES - 1 - i];
            report.signature_s[i] = sig_be[P384_SCALAR_BYTES * 2 - 1 - i];
        }

        report.to_bytes()
    }

    /// Produce evidence binding a full 64-byte [`ReportDataBinding`] payload.
    pub fn produce_bound_evidence(
        &self,
        binding: &ReportDataBinding,
    ) -> Result<AttestationEvidence, EnclaveError> {
        let report_data = binding.to_report_data();
        let report = self.sign_report(report_data);
        let cert_chain = self.cert_chain.to_bytes()?;
        Ok(AttestationEvidence {
            platform: TeePlatform::Simulated,
            nonce: binding.nonce.to_vec(),
            report: report.to_vec(),
            cert_chain,
        })
    }
}

impl Default for SimulatedSnp {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AttestationProvider for SimulatedSnp {
    async fn produce_evidence(&self, nonce: &[u8]) -> Result<AttestationEvidence, EnclaveError> {
        let report_data = report_data_from_nonce(nonce)?;
        let report = self.sign_report(report_data);
        let cert_chain = self.cert_chain.to_bytes()?;
        Ok(AttestationEvidence {
            platform: TeePlatform::Simulated,
            nonce: nonce.to_vec(),
            report: report.to_vec(),
            cert_chain,
        })
    }

    fn verify_evidence(
        &self,
        evidence: &AttestationEvidence,
        expected_nonce: &[u8],
    ) -> Result<(), EnclaveError> {
        let expected_report_data = report_data_from_nonce(expected_nonce)?;
        let chain = SnpCertChain::from_bytes(&evidence.cert_chain)?;
        self.verifier(1_000)
            .verify(&evidence.report, &chain, &expected_report_data)?;
        Ok(())
    }
}

fn derive_p384_signing_key(seed: &[u8], label: &[u8]) -> SigningKey {
    use sha2::{Digest as _, Sha384};
    for counter in 0u32..256 {
        let mut h = Sha384::new();
        h.update(b"quackxide-sim-snp-key-v1|");
        h.update(label);
        h.update(b"|");
        h.update(seed);
        h.update(counter.to_le_bytes());
        let digest = h.finalize();
        if let Ok(sk) = SigningKey::from_slice(&digest) {
            return sk;
        }
    }
    unreachable!("SHA-384 counter loop always finds a valid P-384 scalar")
}

fn derive_serial(seed: &[u8], label: &[u8]) -> [u8; 16] {
    use sha2::{Digest as _, Sha256};
    let mut h = Sha256::new();
    h.update(b"quackxide-sim-snp-serial-v1|");
    h.update(label);
    h.update(b"|");
    h.update(seed);
    let digest = h.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
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
