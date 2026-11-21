//! Binding v2 (ADR 0010): the digest that ties an attestation token to the
//! enclave's keys and configuration. The token's two nonces are the relying
//! party's 32-byte challenge, then this digest.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};

/// Size of the bound data in bytes: a 32-byte nonce, then the 32-byte digest.
pub const REPORT_DATA_BYTES: usize = 64;

const DOMAIN_TAG: &[u8] = b"attestation-binding-v2";

/// The values an enclave key set binds, in ADR 0010's order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnclaveKeyBinding {
    /// The request key's suite magic, then its raw public key.
    pub request_key: Vec<u8>,
    pub signing_ed25519: [u8; 32],
    pub signing_ml_dsa_65: Vec<u8>,
    /// Empty until P50.
    pub kms_public_key: Vec<u8>,
    /// `None` (bound as an empty value) until P67.
    pub tls_spki_sha256: Option<[u8; 32]>,
    pub config_digest: [u8; 32],
}

impl EnclaveKeyBinding {
    /// SHA-256 over the domain tag and, for each value in order, `u16 len(label)
    /// ‖ label ‖ u32 len(value) ‖ value`, all lengths big-endian.
    pub fn digest(&self) -> [u8; 32] {
        let tls: &[u8] = self.tls_spki_sha256.as_ref().map_or(&[], |d| d);
        let entries: [(&[u8], &[u8]); 6] = [
            (b"request-key", &self.request_key),
            (b"signing-ed25519", &self.signing_ed25519),
            (b"signing-ml-dsa-65", &self.signing_ml_dsa_65),
            (b"kms-public-key", &self.kms_public_key),
            (b"tls-spki-sha256", tls),
            (b"config-digest", &self.config_digest),
        ];
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN_TAG);
        for (label, value) in entries {
            let label_len = u16::try_from(label.len()).expect("labels are short");
            let value_len = u32::try_from(value.len()).expect("bound values are under 4 GiB");
            hasher.update(label_len.to_be_bytes());
            hasher.update(label);
            hasher.update(value_len.to_be_bytes());
            hasher.update(value);
        }
        hasher.finalize().into()
    }

    /// The key set's id: [`digest`](Self::digest), base64url without padding.
    pub fn key_id(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.digest())
    }

    /// The 64 bytes an attestation token carries as its two nonces.
    pub fn report_data(&self, nonce: &[u8; 32]) -> [u8; REPORT_DATA_BYTES] {
        let mut out = [0u8; REPORT_DATA_BYTES];
        out[..32].copy_from_slice(nonce);
        out[32..].copy_from_slice(&self.digest());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> EnclaveKeyBinding {
        EnclaveKeyBinding {
            request_key: [&b"HPK2"[..], &[0x22; 1216]].concat(),
            signing_ed25519: [0x33; 32],
            signing_ml_dsa_65: vec![0x44; 1952],
            kms_public_key: Vec::new(),
            tls_spki_sha256: None,
            config_digest: [0x55; 32],
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn digest_is_pinned() {
        // ADR 0010's layout, computed independently of this code.
        let binding = binding();
        assert_eq!(
            hex(&binding.digest()),
            "8e82168aab1e839d70cf3ea422bc329492c56164b9cad2e85d3f75c19be44d9d"
        );
        assert_eq!(
            binding.key_id(),
            "joIWiqseg51wzz6kIrwylJLFYWS5ytLoXT91wZvkTZ0"
        );
    }

    #[test]
    fn report_data_is_nonce_then_digest() {
        let binding = binding();
        let data = binding.report_data(&[0x11; 32]);
        assert_eq!(data.len(), REPORT_DATA_BYTES);
        assert_eq!(data[..32], [0x11; 32]);
        assert_eq!(data[32..], binding.digest());
    }

    #[test]
    fn every_value_changes_the_digest() {
        let base = binding().digest();
        let mutations: [fn(&mut EnclaveKeyBinding); 6] = [
            |b| b.request_key[0] ^= 1,
            |b| b.signing_ed25519[0] ^= 1,
            |b| b.signing_ml_dsa_65[0] ^= 1,
            |b| b.kms_public_key.push(0),
            |b| b.tls_spki_sha256 = Some([0; 32]),
            |b| b.config_digest[0] ^= 1,
        ];
        for mutate in mutations {
            let mut changed = binding();
            mutate(&mut changed);
            assert_ne!(changed.digest(), base);
        }
    }

    #[test]
    fn a_byte_moved_between_values_changes_the_digest() {
        let base = binding();
        let mut moved = binding();
        let last = moved.signing_ml_dsa_65.pop().expect("non-empty");
        moved.kms_public_key.insert(0, last);
        assert_ne!(moved.digest(), base.digest());
    }
}
