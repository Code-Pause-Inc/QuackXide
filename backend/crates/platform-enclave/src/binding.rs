//! The binding between attestation evidence and the enclave's keys: a
//! freshness nonce plus a digest of the enclave's public keys and deployment
//! configuration (ADR 0004, "Freshness and binding").

use sha2::{Digest, Sha256};

/// Size of the binding in bytes: a 32-byte nonce and a 32-byte digest.
pub const REPORT_DATA_BYTES: usize = 64;

const REPORT_DATA_DOMAIN_TAG: &[u8] = b"quackxide-snp-report-data-v1";

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
    /// The 64 bytes bound into attestation evidence: an SNP report's
    /// `REPORT_DATA`, or an attestation token's two nonces.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> ReportDataBinding {
        ReportDataBinding {
            nonce: [0x11; 32],
            enclave_hpke_public_key: [0x22; 32],
            result_signing_public_key: [0x33; 32],
            tls_cert_sha256: [0x44; 32],
            config_digest: [0x55; 32],
        }
    }

    #[test]
    fn binding_carries_the_nonce_and_commits_every_enclave_key() {
        let base = binding().to_report_data();
        assert_eq!(base[..32], [0x11; 32]);
        // A swapped key (for example a MITM's HPKE key) changes the digest half.
        let mutations: [fn(&mut ReportDataBinding); 4] = [
            |b| b.enclave_hpke_public_key[0] ^= 1,
            |b| b.result_signing_public_key[0] ^= 1,
            |b| b.tls_cert_sha256[0] ^= 1,
            |b| b.config_digest[0] ^= 1,
        ];
        for mutate in mutations {
            let mut changed = binding();
            mutate(&mut changed);
            let data = changed.to_report_data();
            assert_eq!(data[..32], base[..32]);
            assert_ne!(data[32..], base[32..]);
        }
    }
}
