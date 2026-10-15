//! Binary AMD SEV-SNP `ATTESTATION_REPORT` wire format (ABI v1.55, Chapter 7,
//! Table 22) and canonical 64-byte `REPORT_DATA` binding.
//!
//! Layout summary (1184 bytes total):
//! - `0x000..0x2A0` (672 bytes): signed report body.
//! - `0x2A0..0x4A0` (512 bytes): ECDSA P-384 with SHA-384 signature (`R` at
//!   `0x2A0..0x2E8`, `S` at `0x2E8..0x330`, little-endian zero-padded to 72
//!   bytes each; `0x330..0x4A0` reserved zero).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::EnclaveError;

/// Total size of an AMD SEV-SNP binary `ATTESTATION_REPORT`.
pub const SNP_REPORT_BYTES: usize = 1184;
/// Signed prefix (`0x000..0x2A0`) covered by the VCEK ECDSA P-384 signature.
pub const SNP_REPORT_SIGNED_BYTES: usize = 0x2A0;
/// `ATTESTATION_REPORT.VERSION` for AMD SEV-SNP ABI v1.51+.
pub const SNP_REPORT_VERSION: u32 = 2;
/// `ATTESTATION_REPORT.SIGNATURE_ALGO` value for ECDSA P-384 with SHA-384.
pub const SNP_SIG_ALGO_ECDSA_P384_SHA384: u32 = 1;
/// Size of `REPORT_DATA` in bytes.
pub const REPORT_DATA_BYTES: usize = 64;
/// Size of `MEASUREMENT` (SHA-384 launch digest) in bytes.
pub const MEASUREMENT_BYTES: usize = 48;
/// Size of `CHIP_ID` in bytes.
pub const CHIP_ID_BYTES: usize = 64;
/// Size of each padded ECDSA component (`R` and `S`) in the signature block.
pub const P384_SIGNATURE_COMPONENT_PADDED_BYTES: usize = 72;
/// Size of an unpadded P-384 scalar (384 bits = 48 bytes).
pub const P384_SCALAR_BYTES: usize = 48;

const REPORT_DATA_DOMAIN_TAG: &[u8] = b"quackxide-snp-report-data-v1";

// Field offsets within the 1184-byte report (AMD SEV-SNP ABI Table 22).
const OFF_VERSION: usize = 0x000;
const OFF_GUEST_SVN: usize = 0x004;
const OFF_POLICY: usize = 0x008;
const OFF_FAMILY_ID: usize = 0x010;
const OFF_IMAGE_ID: usize = 0x020;
const OFF_VMPL: usize = 0x030;
const OFF_SIGNATURE_ALGO: usize = 0x034;
const OFF_CURRENT_TCB: usize = 0x038;
const OFF_PLATFORM_INFO: usize = 0x040;
const OFF_AUTHOR_KEY_EN: usize = 0x048;
const OFF_REPORT_DATA: usize = 0x050;
const OFF_MEASUREMENT: usize = 0x090;
const OFF_HOST_DATA: usize = 0x0C0;
const OFF_REPORT_ID: usize = 0x140;
const OFF_REPORTED_TCB: usize = 0x180;
const OFF_CHIP_ID: usize = 0x1A0;
const OFF_COMMITTED_TCB: usize = 0x1E0;
const OFF_LAUNCH_TCB: usize = 0x1F0;
const OFF_SIG_R: usize = 0x2A0;
const OFF_SIG_S: usize = 0x2E8;
const OFF_SIG_RESERVED: usize = 0x330;

/// AMD SEV-SNP `GUEST_POLICY` 64-bit bitfield (ABI Table 9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestPolicy(pub u64);

impl GuestPolicy {
    pub const SMT_BIT: u64 = 1 << 16;
    pub const MIGRATE_MA_BIT: u64 = 1 << 18;
    pub const DEBUG_BIT: u64 = 1 << 19;
    pub const SINGLE_SOCKET_BIT: u64 = 1 << 20;

    /// Hardened production guest policy: ABI 1.55, SMT permitted, debug and
    /// migration agent disabled.
    pub const fn production_default() -> Self {
        let abi_minor: u64 = 55;
        let abi_major: u64 = 1 << 8;
        Self(abi_minor | abi_major | Self::SMT_BIT)
    }

    pub const fn debug_enabled(self) -> bool {
        (self.0 & Self::DEBUG_BIT) != 0
    }

    pub const fn migration_agent_enabled(self) -> bool {
        (self.0 & Self::MIGRATE_MA_BIT) != 0
    }

    pub const fn with_debug(self, enabled: bool) -> Self {
        if enabled {
            Self(self.0 | Self::DEBUG_BIT)
        } else {
            Self(self.0 & !Self::DEBUG_BIT)
        }
    }

    pub const fn with_migration_agent(self, enabled: bool) -> Self {
        if enabled {
            Self(self.0 | Self::MIGRATE_MA_BIT)
        } else {
            Self(self.0 & !Self::MIGRATE_MA_BIT)
        }
    }
}

/// AMD SEV-SNP `TCB_VERSION` 64-bit structure (ABI Table 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcbVersion {
    pub boot_loader: u8,
    pub tee: u8,
    pub snp: u8,
    pub microcode: u8,
}

impl TcbVersion {
    pub const fn new(boot_loader: u8, tee: u8, snp: u8, microcode: u8) -> Self {
        Self {
            boot_loader,
            tee,
            snp,
            microcode,
        }
    }

    /// Component-wise TCB comparison: every component of `self` must be at
    /// least the minimum required by `min`.
    pub const fn meets_minimum(&self, min: &Self) -> bool {
        self.boot_loader >= min.boot_loader
            && self.tee >= min.tee
            && self.snp >= min.snp
            && self.microcode >= min.microcode
    }

    pub const fn to_u64(self) -> u64 {
        (self.boot_loader as u64)
            | ((self.tee as u64) << 8)
            | ((self.snp as u64) << 48)
            | ((self.microcode as u64) << 56)
    }

    pub const fn from_u64(raw: u64) -> Self {
        Self {
            boot_loader: (raw & 0xFF) as u8,
            tee: ((raw >> 8) & 0xFF) as u8,
            snp: ((raw >> 48) & 0xFF) as u8,
            microcode: ((raw >> 56) & 0xFF) as u8,
        }
    }
}

/// Canonical 64-byte `REPORT_DATA` binding for key release and browser
/// attestation verification.
///
/// - `bytes[0..32]`: 32-byte freshness `nonce` supplied by the relying party.
/// - `bytes[32..64]`: SHA-256 digest binding the enclave's ephemeral HPKE
///   public key, result-signing public key, TLS certificate SPKI SHA-256, and
///   deployment configuration digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportDataBinding {
    pub nonce: [u8; 32],
    pub enclave_hpke_public_key: [u8; 32],
    pub result_signing_public_key: [u8; 32],
    pub tls_cert_sha256: [u8; 32],
    pub config_digest: [u8; 32],
}

impl ReportDataBinding {
    /// Compute the 64-byte `REPORT_DATA` field that goes into `/dev/sev-guest`
    /// (or `SimulatedSnp`).
    pub fn to_report_data(&self) -> [u8; REPORT_DATA_BYTES] {
        let mut hasher = Sha256::new();
        hasher.update(REPORT_DATA_DOMAIN_TAG);
        hasher.update(self.enclave_hpke_public_key);
        hasher.update(self.result_signing_public_key);
        hasher.update(self.tls_cert_sha256);
        hasher.update(self.config_digest);
        let binding_hash = hasher.finalize();

        let mut out = [0u8; REPORT_DATA_BYTES];
        out[..32].copy_from_slice(&self.nonce);
        out[32..64].copy_from_slice(&binding_hash);
        out
    }
}

/// Map a caller-supplied freshness `nonce` (1..=32 bytes, or a full 64-byte
/// pre-computed `REPORT_DATA` buffer) into the 64-byte `REPORT_DATA` slot.
pub fn report_data_from_nonce(nonce: &[u8]) -> Result<[u8; REPORT_DATA_BYTES], EnclaveError> {
    if nonce.is_empty() {
        return Err(EnclaveError::Rejected(
            "attestation nonce must not be empty".into(),
        ));
    }
    if nonce.len() == REPORT_DATA_BYTES {
        let mut out = [0u8; REPORT_DATA_BYTES];
        out.copy_from_slice(nonce);
        return Ok(out);
    }
    if nonce.len() > 32 {
        return Err(EnclaveError::Rejected(
            "attestation nonce must be 1..=32 bytes or a 64-byte REPORT_DATA buffer".into(),
        ));
    }
    let mut out = [0u8; REPORT_DATA_BYTES];
    out[..nonce.len()].copy_from_slice(nonce);
    Ok(out)
}

/// Parsed representation of the 1184-byte AMD SEV-SNP `ATTESTATION_REPORT`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnpReport {
    pub version: u32,
    pub guest_svn: u32,
    pub policy: GuestPolicy,
    pub family_id: [u8; 16],
    pub image_id: [u8; 16],
    pub vmpl: u32,
    pub signature_algo: u32,
    pub current_tcb: TcbVersion,
    pub platform_info: u64,
    pub author_key_en: u32,
    pub report_data: [u8; REPORT_DATA_BYTES],
    pub measurement: [u8; MEASUREMENT_BYTES],
    pub host_data: [u8; 32],
    pub report_id: [u8; 32],
    pub reported_tcb: TcbVersion,
    pub chip_id: [u8; CHIP_ID_BYTES],
    pub committed_tcb: TcbVersion,
    pub launch_tcb: TcbVersion,
    /// Little-endian P-384 `R` component zero-padded to 72 bytes.
    pub signature_r: [u8; P384_SIGNATURE_COMPONENT_PADDED_BYTES],
    /// Little-endian P-384 `S` component zero-padded to 72 bytes.
    pub signature_s: [u8; P384_SIGNATURE_COMPONENT_PADDED_BYTES],
}

impl SnpReport {
    /// Serialize the unsigned 672-byte body (`0x000..0x2A0`) covered by the
    /// VCEK ECDSA P-384 signature.
    pub fn signed_body_bytes(&self) -> [u8; SNP_REPORT_SIGNED_BYTES] {
        let full = self.to_bytes();
        let mut body = [0u8; SNP_REPORT_SIGNED_BYTES];
        body.copy_from_slice(&full[..SNP_REPORT_SIGNED_BYTES]);
        body
    }

    /// Serialize to the exact 1184-byte AMD SEV-SNP binary wire format.
    pub fn to_bytes(&self) -> [u8; SNP_REPORT_BYTES] {
        let mut buf = [0u8; SNP_REPORT_BYTES];
        buf[OFF_VERSION..OFF_VERSION + 4].copy_from_slice(&self.version.to_le_bytes());
        buf[OFF_GUEST_SVN..OFF_GUEST_SVN + 4].copy_from_slice(&self.guest_svn.to_le_bytes());
        buf[OFF_POLICY..OFF_POLICY + 8].copy_from_slice(&self.policy.0.to_le_bytes());
        buf[OFF_FAMILY_ID..OFF_FAMILY_ID + 16].copy_from_slice(&self.family_id);
        buf[OFF_IMAGE_ID..OFF_IMAGE_ID + 16].copy_from_slice(&self.image_id);
        buf[OFF_VMPL..OFF_VMPL + 4].copy_from_slice(&self.vmpl.to_le_bytes());
        buf[OFF_SIGNATURE_ALGO..OFF_SIGNATURE_ALGO + 4]
            .copy_from_slice(&self.signature_algo.to_le_bytes());
        buf[OFF_CURRENT_TCB..OFF_CURRENT_TCB + 8]
            .copy_from_slice(&self.current_tcb.to_u64().to_le_bytes());
        buf[OFF_PLATFORM_INFO..OFF_PLATFORM_INFO + 8]
            .copy_from_slice(&self.platform_info.to_le_bytes());
        buf[OFF_AUTHOR_KEY_EN..OFF_AUTHOR_KEY_EN + 4]
            .copy_from_slice(&self.author_key_en.to_le_bytes());
        buf[OFF_REPORT_DATA..OFF_REPORT_DATA + REPORT_DATA_BYTES]
            .copy_from_slice(&self.report_data);
        buf[OFF_MEASUREMENT..OFF_MEASUREMENT + MEASUREMENT_BYTES]
            .copy_from_slice(&self.measurement);
        buf[OFF_HOST_DATA..OFF_HOST_DATA + 32].copy_from_slice(&self.host_data);
        buf[OFF_REPORT_ID..OFF_REPORT_ID + 32].copy_from_slice(&self.report_id);
        buf[OFF_REPORTED_TCB..OFF_REPORTED_TCB + 8]
            .copy_from_slice(&self.reported_tcb.to_u64().to_le_bytes());
        buf[OFF_CHIP_ID..OFF_CHIP_ID + CHIP_ID_BYTES].copy_from_slice(&self.chip_id);
        buf[OFF_COMMITTED_TCB..OFF_COMMITTED_TCB + 8]
            .copy_from_slice(&self.committed_tcb.to_u64().to_le_bytes());
        buf[OFF_LAUNCH_TCB..OFF_LAUNCH_TCB + 8]
            .copy_from_slice(&self.launch_tcb.to_u64().to_le_bytes());
        buf[OFF_SIG_R..OFF_SIG_R + P384_SIGNATURE_COMPONENT_PADDED_BYTES]
            .copy_from_slice(&self.signature_r);
        buf[OFF_SIG_S..OFF_SIG_S + P384_SIGNATURE_COMPONENT_PADDED_BYTES]
            .copy_from_slice(&self.signature_s);
        buf
    }

    /// Parse a 1184-byte AMD SEV-SNP binary `ATTESTATION_REPORT`.
    pub fn from_bytes(raw: &[u8]) -> Result<Self, EnclaveError> {
        if raw.len() != SNP_REPORT_BYTES {
            return Err(EnclaveError::Rejected(format!(
                "invalid SEV-SNP report length: expected {SNP_REPORT_BYTES} bytes, got {}",
                raw.len()
            )));
        }

        // Reserved bytes after S (0x330..0x4A0) and padding bytes 48..72 of R and S must be zero.
        let r_pad =
            &raw[OFF_SIG_R + P384_SCALAR_BYTES..OFF_SIG_R + P384_SIGNATURE_COMPONENT_PADDED_BYTES];
        let s_pad =
            &raw[OFF_SIG_S + P384_SCALAR_BYTES..OFF_SIG_S + P384_SIGNATURE_COMPONENT_PADDED_BYTES];
        let sig_reserved = &raw[OFF_SIG_RESERVED..SNP_REPORT_BYTES];
        if r_pad.iter().any(|&b| b != 0)
            || s_pad.iter().any(|&b| b != 0)
            || sig_reserved.iter().any(|&b| b != 0)
        {
            return Err(EnclaveError::Rejected(
                "non-zero reserved bytes in SEV-SNP signature block".into(),
            ));
        }

        let version = u32::from_le_bytes(raw[OFF_VERSION..OFF_VERSION + 4].try_into().unwrap());
        let guest_svn =
            u32::from_le_bytes(raw[OFF_GUEST_SVN..OFF_GUEST_SVN + 4].try_into().unwrap());
        let policy = GuestPolicy(u64::from_le_bytes(
            raw[OFF_POLICY..OFF_POLICY + 8].try_into().unwrap(),
        ));
        let family_id = raw[OFF_FAMILY_ID..OFF_FAMILY_ID + 16].try_into().unwrap();
        let image_id = raw[OFF_IMAGE_ID..OFF_IMAGE_ID + 16].try_into().unwrap();
        let vmpl = u32::from_le_bytes(raw[OFF_VMPL..OFF_VMPL + 4].try_into().unwrap());
        let signature_algo = u32::from_le_bytes(
            raw[OFF_SIGNATURE_ALGO..OFF_SIGNATURE_ALGO + 4]
                .try_into()
                .unwrap(),
        );
        let current_tcb = TcbVersion::from_u64(u64::from_le_bytes(
            raw[OFF_CURRENT_TCB..OFF_CURRENT_TCB + 8]
                .try_into()
                .unwrap(),
        ));
        let platform_info = u64::from_le_bytes(
            raw[OFF_PLATFORM_INFO..OFF_PLATFORM_INFO + 8]
                .try_into()
                .unwrap(),
        );
        let author_key_en = u32::from_le_bytes(
            raw[OFF_AUTHOR_KEY_EN..OFF_AUTHOR_KEY_EN + 4]
                .try_into()
                .unwrap(),
        );
        let report_data = raw[OFF_REPORT_DATA..OFF_REPORT_DATA + REPORT_DATA_BYTES]
            .try_into()
            .unwrap();
        let measurement = raw[OFF_MEASUREMENT..OFF_MEASUREMENT + MEASUREMENT_BYTES]
            .try_into()
            .unwrap();
        let host_data = raw[OFF_HOST_DATA..OFF_HOST_DATA + 32].try_into().unwrap();
        let report_id = raw[OFF_REPORT_ID..OFF_REPORT_ID + 32].try_into().unwrap();
        let reported_tcb = TcbVersion::from_u64(u64::from_le_bytes(
            raw[OFF_REPORTED_TCB..OFF_REPORTED_TCB + 8]
                .try_into()
                .unwrap(),
        ));
        let chip_id = raw[OFF_CHIP_ID..OFF_CHIP_ID + CHIP_ID_BYTES]
            .try_into()
            .unwrap();
        let committed_tcb = TcbVersion::from_u64(u64::from_le_bytes(
            raw[OFF_COMMITTED_TCB..OFF_COMMITTED_TCB + 8]
                .try_into()
                .unwrap(),
        ));
        let launch_tcb = TcbVersion::from_u64(u64::from_le_bytes(
            raw[OFF_LAUNCH_TCB..OFF_LAUNCH_TCB + 8].try_into().unwrap(),
        ));
        let signature_r = raw[OFF_SIG_R..OFF_SIG_R + P384_SIGNATURE_COMPONENT_PADDED_BYTES]
            .try_into()
            .unwrap();
        let signature_s = raw[OFF_SIG_S..OFF_SIG_S + P384_SIGNATURE_COMPONENT_PADDED_BYTES]
            .try_into()
            .unwrap();

        Ok(Self {
            version,
            guest_svn,
            policy,
            family_id,
            image_id,
            vmpl,
            signature_algo,
            current_tcb,
            platform_info,
            author_key_en,
            report_data,
            measurement,
            host_data,
            report_id,
            reported_tcb,
            chip_id,
            committed_tcb,
            launch_tcb,
            signature_r,
            signature_s,
        })
    }
}
