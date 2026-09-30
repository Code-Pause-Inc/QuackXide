//! Server- and enclave-side cryptography, wire-compatible with the browser
//! client.
//!
//! Drive master keys are generated in the browser and never exist here; the
//! server cannot decrypt drive content. This crate provides only AEAD sealing
//! for data transiently held in enclave RAM, HPKE envelopes to a tenant
//! public key, keyed blind indexes, and TOTP.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hmac::{Hmac, Mac};
use hpke::aead::AesGcm256;
use hpke::kdf::HkdfSha256;
use hpke::{Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

mod totp;
pub use totp::{TOTP_DIGITS, TOTP_SECRET_BYTES, TOTP_STEP_SECS, TotpSecret};

/// AES-256-GCM parameter sizes, kept in lockstep with the browser client
/// (`frontend/src/lib/crypto/`).
pub const AES_KEY_BYTES: usize = 32;
pub const GCM_NONCE_BYTES: usize = 12;
pub const GCM_TAG_BYTES: usize = 16;
pub const BLIND_INDEX_BYTES: usize = 16;

/// HPKE KEM for tenant envelopes. Together with [`TenantKdf`] and
/// [`TenantAead`] this pins the wire suite for every producer and consumer.
pub type TenantKem = hpke::kem::X25519HkdfSha256;
type TenantKdf = HkdfSha256;
type TenantAead = AesGcm256;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("invalid key length")]
    InvalidKeyLength,
    #[error("invalid public key")]
    InvalidPublicKey,
    #[error("invalid envelope framing")]
    InvalidEnvelope,
    // Content-free by design: never carry key material or data fragments.
    #[error("seal failed")]
    SealFailed,
    #[error("open failed (ciphertext rejected)")]
    OpenFailed,
}

/// Heap bytes wiped on drop, with a redacted `Debug`. Use for every transient
/// secret in enclave RAM.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretBytes(<{} bytes redacted>)", self.0.len())
    }
}

/// AEAD-seal `plaintext` under a 256-bit key with the given 96-bit nonce and
/// additional authenticated data. Nonces MUST be unique per key.
pub fn aead_seal(
    key: &[u8; AES_KEY_BYTES],
    nonce: &[u8; GCM_NONCE_BYTES],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::InvalidKeyLength)?;
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::SealFailed)
}

/// Open an AEAD-sealed message. Returns zeroize-on-drop plaintext.
pub fn aead_open(
    key: &[u8; AES_KEY_BYTES],
    nonce: &[u8; GCM_NONCE_BYTES],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<SecretBytes, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::InvalidKeyLength)?;
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map(SecretBytes::new)
        .map_err(|_| CryptoError::OpenFailed)
}

/// Deterministic blind index keyed per tenant and field (HMAC-SHA256
/// truncated to 128 bits), for equality lookups over ciphertext.
pub fn blind_index(index_key: &[u8], value: &[u8]) -> [u8; BLIND_INDEX_BYTES] {
    // Fully qualified: both `Mac` and the AEAD `KeyInit` traits are in scope
    // and provide `new_from_slice`.
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(index_key).expect("HMAC accepts any key length");
    mac.update(value);
    let digest = mac.finalize().into_bytes();
    let mut out = [0u8; BLIND_INDEX_BYTES];
    out.copy_from_slice(&digest[..BLIND_INDEX_BYTES]);
    out
}

// ── HPKE tenant envelopes ───────────────────────────────────────────────────
//
// Enclave pipelines seal output to the tenant's public key before anything
// leaves enclave RAM (single-shot base mode). Framing:
// `b"HPK1" || encapped_key(32) || ciphertext`. Binding context travels in
// HPKE `info`, so an envelope replayed under another object fails to open.

pub const HPKE_ENVELOPE_MAGIC: [u8; 4] = *b"HPK1";
pub const X25519_PUBLIC_KEY_BYTES: usize = 32;
const MAGIC_BYTES: usize = HPKE_ENVELOPE_MAGIC.len();
const ENCAPPED_KEY_BYTES: usize = 32;

type KemPublicKey = <TenantKem as KemTrait>::PublicKey;
type KemPrivateKey = <TenantKem as KemTrait>::PrivateKey;
type KemEncappedKey = <TenantKem as KemTrait>::EncappedKey;

/// A tenant's HPKE public key — raw X25519 bytes enrolled from the browser.
#[derive(Clone)]
pub struct TenantPublicKey(KemPublicKey);

impl TenantPublicKey {
    pub fn from_raw(raw: &[u8]) -> Result<Self, CryptoError> {
        KemPublicKey::from_bytes(raw)
            .map(Self)
            .map_err(|_| CryptoError::InvalidPublicKey)
    }

    pub fn to_raw(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }
}

impl std::fmt::Debug for TenantPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TenantPublicKey(x25519)")
    }
}

/// Envelope-seal `plaintext` to a tenant public key. Returns the framed
/// envelope (`HPK1 || encapped_key || ciphertext`) ready for the vault.
pub fn hpke_seal_to_tenant(
    recipient: &TenantPublicKey,
    info: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let (encapped, ciphertext) = hpke::single_shot_seal::<TenantAead, TenantKdf, TenantKem, _>(
        &OpModeS::Base,
        &recipient.0,
        info,
        plaintext,
        b"",
        &mut rand::rngs::OsRng,
    )
    .map_err(|_| CryptoError::SealFailed)?;

    let mut envelope = Vec::with_capacity(MAGIC_BYTES + ENCAPPED_KEY_BYTES + ciphertext.len());
    envelope.extend_from_slice(&HPKE_ENVELOPE_MAGIC);
    envelope.extend_from_slice(&encapped.to_bytes());
    envelope.extend_from_slice(&ciphertext);
    Ok(envelope)
}

fn parse_envelope(envelope: &[u8]) -> Result<(&[u8], &[u8]), CryptoError> {
    if envelope.len() < MAGIC_BYTES + ENCAPPED_KEY_BYTES + GCM_TAG_BYTES
        || envelope[..MAGIC_BYTES] != HPKE_ENVELOPE_MAGIC
    {
        return Err(CryptoError::InvalidEnvelope);
    }
    Ok(envelope[MAGIC_BYTES..].split_at(ENCAPPED_KEY_BYTES))
}

/// Test/dev-only tenant keypair. Production tenant private keys are
/// generated non-extractable in the browser and never exist server-side.
pub struct TenantKeypair {
    private_key: KemPrivateKey,
    public_key: KemPublicKey,
}

impl TenantKeypair {
    pub fn generate() -> Self {
        let (private_key, public_key) = TenantKem::gen_keypair(&mut rand::rngs::OsRng);
        Self {
            private_key,
            public_key,
        }
    }

    pub fn public_key(&self) -> TenantPublicKey {
        TenantPublicKey(self.public_key.clone())
    }

    /// Open a framed envelope. Fails on tamper, wrong recipient, or a
    /// mismatched `info` binding.
    pub fn open_envelope(&self, info: &[u8], envelope: &[u8]) -> Result<SecretBytes, CryptoError> {
        let (encapped_raw, ciphertext) = parse_envelope(envelope)?;
        let encapped =
            KemEncappedKey::from_bytes(encapped_raw).map_err(|_| CryptoError::InvalidEnvelope)?;
        hpke::single_shot_open::<TenantAead, TenantKdf, TenantKem>(
            &OpModeR::Base,
            &self.private_key,
            &encapped,
            info,
            ciphertext,
            b"",
        )
        .map(SecretBytes::new)
        .map_err(|_| CryptoError::OpenFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; AES_KEY_BYTES] = [7u8; AES_KEY_BYTES];
    const NONCE: [u8; GCM_NONCE_BYTES] = [3u8; GCM_NONCE_BYTES];

    #[test]
    fn seal_open_round_trip() {
        let sealed = aead_seal(&KEY, &NONCE, b"tenant:a", b"ledger row").expect("seal");
        assert_ne!(&sealed[..], b"ledger row");
        let opened = aead_open(&KEY, &NONCE, b"tenant:a", &sealed).expect("open");
        assert_eq!(opened.expose(), b"ledger row");
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let mut sealed = aead_seal(&KEY, &NONCE, b"aad", b"payload").expect("seal");
        sealed[0] ^= 0xFF;
        assert!(matches!(
            aead_open(&KEY, &NONCE, b"aad", &sealed),
            Err(CryptoError::OpenFailed)
        ));
    }

    #[test]
    fn wrong_aad_is_rejected() {
        let sealed = aead_seal(&KEY, &NONCE, b"tenant:a", b"payload").expect("seal");
        assert!(matches!(
            aead_open(&KEY, &NONCE, b"tenant:b", &sealed),
            Err(CryptoError::OpenFailed)
        ));
    }

    #[test]
    fn blind_index_is_deterministic_and_key_separated() {
        let a1 = blind_index(b"tenant-key-1", b"acme corp");
        let a2 = blind_index(b"tenant-key-1", b"acme corp");
        let b = blind_index(b"tenant-key-2", b"acme corp");
        let c = blind_index(b"tenant-key-1", b"other corp");
        assert_eq!(a1, a2);
        assert_ne!(a1, b, "different index keys must not collide");
        assert_ne!(a1, c, "different values must not collide");
    }

    #[test]
    fn secret_bytes_debug_is_redacted() {
        let secret = SecretBytes::new(b"super secret".to_vec());
        let debugged = format!("{secret:?}");
        assert!(!debugged.contains("super secret"));
        assert!(debugged.contains("redacted"));
    }

    #[test]
    fn hpke_envelope_round_trips() {
        let keypair = TenantKeypair::generate();
        let envelope = hpke_seal_to_tenant(&keypair.public_key(), b"info|a|b", b"parquet bytes")
            .expect("seal");
        assert_eq!(&envelope[..4], b"HPK1");
        let opened = keypair.open_envelope(b"info|a|b", &envelope).expect("open");
        assert_eq!(opened.expose(), b"parquet bytes");
    }

    #[test]
    fn hpke_envelope_rejects_wrong_info_binding() {
        let keypair = TenantKeypair::generate();
        let envelope =
            hpke_seal_to_tenant(&keypair.public_key(), b"tenant|obj-1", b"data").expect("seal");
        assert!(matches!(
            keypair.open_envelope(b"tenant|obj-2", &envelope),
            Err(CryptoError::OpenFailed)
        ));
    }

    #[test]
    fn hpke_envelope_rejects_wrong_recipient_and_tamper() {
        let alice = TenantKeypair::generate();
        let mallory = TenantKeypair::generate();
        let mut envelope =
            hpke_seal_to_tenant(&alice.public_key(), b"info", b"data").expect("seal");

        assert!(matches!(
            mallory.open_envelope(b"info", &envelope),
            Err(CryptoError::OpenFailed)
        ));

        let last = envelope.len() - 1;
        envelope[last] ^= 0xFF;
        assert!(matches!(
            alice.open_envelope(b"info", &envelope),
            Err(CryptoError::OpenFailed)
        ));
    }

    #[test]
    fn hpke_envelope_rejects_bad_framing() {
        let keypair = TenantKeypair::generate();
        assert!(matches!(
            keypair.open_envelope(b"info", b"XXXXtooshort"),
            Err(CryptoError::InvalidEnvelope)
        ));
    }

    #[test]
    fn tenant_public_key_raw_round_trip() {
        let keypair = TenantKeypair::generate();
        let raw = keypair.public_key().to_raw();
        assert_eq!(raw.len(), X25519_PUBLIC_KEY_BYTES);
        let restored = TenantPublicKey::from_raw(&raw).expect("valid raw key");
        let envelope = hpke_seal_to_tenant(&restored, b"i", b"x").expect("seal");
        assert_eq!(
            keypair
                .open_envelope(b"i", &envelope)
                .expect("open")
                .expose(),
            b"x"
        );
    }

    #[test]
    fn tenant_public_key_rejects_bad_raw() {
        assert!(TenantPublicKey::from_raw(&[0u8; 5]).is_err());
    }

    mod props {
        use super::*;
        use proptest::prelude::*;
        use std::sync::LazyLock;

        static KEYPAIR: LazyLock<TenantKeypair> = LazyLock::new(TenantKeypair::generate);

        fn bytes(max: usize) -> impl Strategy<Value = Vec<u8>> {
            prop::collection::vec(any::<u8>(), 0..max)
        }

        fn seal(info: &[u8], plaintext: &[u8]) -> Vec<u8> {
            hpke_seal_to_tenant(&KEYPAIR.public_key(), info, plaintext).unwrap()
        }

        proptest! {
            // Debug-build X25519 is slow; each case costs several scalar mults.
            #![proptest_config(ProptestConfig::with_cases(32))]

            #[test]
            fn arbitrary_envelopes_never_open(
                info in bytes(64),
                envelope in bytes(512),
                framed: bool,
            ) {
                let envelope = if framed {
                    [&HPKE_ENVELOPE_MAGIC[..], &envelope].concat()
                } else {
                    envelope
                };
                prop_assert!(KEYPAIR.open_envelope(&info, &envelope).is_err());
            }

            #[test]
            fn envelope_round_trips(info in bytes(64), plaintext in bytes(2048)) {
                let opened = KEYPAIR.open_envelope(&info, &seal(&info, &plaintext)).unwrap();
                prop_assert_eq!(opened.expose(), &plaintext[..]);
            }

            #[test]
            fn envelope_mutation_or_truncation_fails(
                info in bytes(64),
                plaintext in bytes(256),
                pick: usize,
                flip in 1..=u8::MAX,
            ) {
                let envelope = seal(&info, &plaintext);
                let mut tampered = envelope.clone();
                tampered[pick % envelope.len()] ^= flip;
                prop_assert!(KEYPAIR.open_envelope(&info, &tampered).is_err());
                let truncated = &envelope[..pick % envelope.len()];
                prop_assert!(KEYPAIR.open_envelope(&info, truncated).is_err());
            }

            #[test]
            fn envelope_with_other_info_fails(
                info in bytes(64),
                other in bytes(64),
                plaintext in bytes(256),
            ) {
                prop_assume!(info != other);
                prop_assert!(matches!(
                    KEYPAIR.open_envelope(&other, &seal(&info, &plaintext)),
                    Err(CryptoError::OpenFailed)
                ));
            }
        }

        proptest! {
            #[test]
            fn arbitrary_public_keys_never_panic(raw in bytes(64)) {
                let parsed = TenantPublicKey::from_raw(&raw);
                prop_assert_eq!(parsed.is_ok(), raw.len() == X25519_PUBLIC_KEY_BYTES);
            }

            #[test]
            fn aead_round_trips_and_rejects_tamper(
                key: [u8; AES_KEY_BYTES],
                nonce: [u8; GCM_NONCE_BYTES],
                aad in bytes(64),
                other_aad in bytes(64),
                plaintext in bytes(2048),
                pick: usize,
                flip in 1..=u8::MAX,
            ) {
                let mut sealed = aead_seal(&key, &nonce, &aad, &plaintext).unwrap();
                prop_assert_eq!(sealed.len(), plaintext.len() + GCM_TAG_BYTES);
                let opened = aead_open(&key, &nonce, &aad, &sealed).unwrap();
                prop_assert_eq!(opened.expose(), &plaintext[..]);
                if other_aad != aad {
                    prop_assert!(aead_open(&key, &nonce, &other_aad, &sealed).is_err());
                }
                let at = pick % sealed.len();
                sealed[at] ^= flip;
                prop_assert!(aead_open(&key, &nonce, &aad, &sealed).is_err());
            }

            #[test]
            fn arbitrary_aead_ciphertexts_never_open(
                key: [u8; AES_KEY_BYTES],
                nonce: [u8; GCM_NONCE_BYTES],
                aad in bytes(64),
                ciphertext in bytes(512),
            ) {
                prop_assert!(aead_open(&key, &nonce, &aad, &ciphertext).is_err());
            }
        }
    }
}
