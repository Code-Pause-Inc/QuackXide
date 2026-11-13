//! Server- and enclave-side cryptography, wire-compatible with the browser
//! client.
//!
//! Drive master keys are generated in the browser and never exist here; the
//! server cannot decrypt drive content. This crate provides only AEAD sealing
//! for data transiently held in enclave RAM, HPKE envelopes to a tenant
//! public key, keyed blind indexes, and TOTP.
//!
//! The `server` feature (on by default) carries AEAD sealing, blind indexes
//! and TOTP. Without it the crate is the HPKE envelope code and its `info`
//! strings alone, which is what the browser's wasm build (`envelope-wasm`)
//! compiles.

#[cfg(feature = "server")]
use aes_gcm::aead::{Aead, KeyInit, Payload};
#[cfg(feature = "server")]
use aes_gcm::{Aes256Gcm, Nonce};
#[cfg(feature = "server")]
use hmac::{Hmac, Mac};
use hpke::aead::AesGcm256;
use hpke::kdf::HkdfSha256;
use hpke::rand_core::CryptoRng;
use hpke::{Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable};
#[cfg(feature = "server")]
use sha2::Sha256;
use std::io::{self, Write};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub mod info;
#[cfg(feature = "server")]
mod totp;
#[cfg(feature = "server")]
pub use totp::{TOTP_DIGITS, TOTP_SECRET_BYTES, TOTP_STEP_SECS, TotpSecret};

/// AES-256-GCM parameter sizes, kept in lockstep with the browser client
/// (`frontend/src/lib/crypto/`).
pub const AES_KEY_BYTES: usize = 32;
pub const GCM_NONCE_BYTES: usize = 12;
pub const GCM_TAG_BYTES: usize = 16;
pub const BLIND_INDEX_BYTES: usize = 16;

/// HPKE KEM of the current suite ([`EnvelopeSuite::CURRENT`], `HPK2`).
/// Together with [`TenantKdf`] and [`TenantAead`] this pins the wire suite
/// for every producer and consumer.
pub type TenantKem = hpke::kem::XWing;
/// HPKE KEM of the `HPK1` suite, accepted only in development until P36.
type Hpk1Kem = hpke::kem::X25519HkdfSha256;
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
    #[error("invalid envelope info field")]
    InvalidInfoField,
    // Content-free by design: never carry key material or data fragments.
    #[error("seal failed")]
    SealFailed,
    #[error("open failed (ciphertext rejected)")]
    OpenFailed,
    /// The suite policy does not accept this key's or envelope's suite.
    #[error("envelope suite not accepted")]
    SuiteRefused,
    /// The envelope's suite is not the suite of the key opening it.
    #[error("envelope suite does not match the key")]
    SuiteMismatch,
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

/// In-memory sink that never leaves plaintext in freed memory: growth moves
/// into a fresh allocation and zeroizes the old one, and drop zeroizes.
pub struct ZeroizingWriter {
    buf: Vec<u8>,
}

impl ZeroizingWriter {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: Vec::with_capacity(capacity),
        }
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn into_secret(mut self) -> SecretBytes {
        SecretBytes::new(std::mem::take(&mut self.buf))
    }
}

impl Write for ZeroizingWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let needed = self
            .buf
            .len()
            .checked_add(data.len())
            .ok_or_else(|| io::Error::other("zeroizing buffer overflow"))?;
        if needed > self.buf.capacity() {
            let mut next = Vec::with_capacity(needed.max(self.buf.capacity().saturating_mul(2)));
            next.extend_from_slice(&self.buf);
            // Zeroizes the full capacity of the old allocation before it is freed.
            self.buf.zeroize();
            self.buf = next;
        }
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for ZeroizingWriter {
    fn drop(&mut self) {
        self.buf.zeroize();
    }
}

#[cfg(feature = "server")]
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

#[cfg(feature = "server")]
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

#[cfg(feature = "server")]
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
// Enclave pipelines and the steward's browser seal to a tenant's public key
// (single-shot base mode). Framing: `magic || encapped_key || ciphertext`,
// where the magic names exactly one suite ([`EnvelopeSuite`]). Binding
// context travels in HPKE `info` ([`info`]), so an envelope replayed under
// another object fails to open.

const MAGIC_BYTES: usize = 4;

/// An envelope suite, named on the wire by its frame magic. Readers choose
/// the suite from the magic and refuse any magic they do not know.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeSuite {
    /// `HPK1`: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM.
    /// Development only, until the browser moves to `HPK2` (P36).
    Hpk1,
    /// `HPK2`: X-Wing (draft-connolly-cfrg-xwing-kem-06), HKDF-SHA256,
    /// AES-256-GCM (ADR 0007).
    Hpk2,
}

impl EnvelopeSuite {
    /// The suite new keys and envelopes use.
    pub const CURRENT: Self = Self::Hpk2;

    pub fn magic(self) -> [u8; MAGIC_BYTES] {
        match self {
            Self::Hpk1 => *b"HPK1",
            Self::Hpk2 => *b"HPK2",
        }
    }

    /// The suite's stable name in stored plaintext records: its frame magic
    /// as text, which names exactly one suite.
    pub fn id(self) -> &'static str {
        match self {
            Self::Hpk1 => "HPK1",
            Self::Hpk2 => "HPK2",
        }
    }

    /// The suite a stored name refers to; unknown names are refused.
    pub fn from_id(id: &str) -> Result<Self, CryptoError> {
        match id {
            "HPK1" => Ok(Self::Hpk1),
            "HPK2" => Ok(Self::Hpk2),
            _ => Err(CryptoError::InvalidEnvelope),
        }
    }

    /// The shortest complete frame: magic, encapsulated key and AEAD tag
    /// (an empty plaintext).
    pub fn min_frame_bytes(self) -> usize {
        MAGIC_BYTES + self.encapped_len() + GCM_TAG_BYTES
    }

    /// The suite a framed envelope or private key declares. Unknown magic is
    /// refused. This reads only the magic; [`check_envelope_frame`] also
    /// checks length.
    pub fn of_envelope(envelope: &[u8]) -> Result<Self, CryptoError> {
        match envelope.get(..MAGIC_BYTES) {
            Some(b"HPK1") => Ok(Self::Hpk1),
            Some(b"HPK2") => Ok(Self::Hpk2),
            _ => Err(CryptoError::InvalidEnvelope),
        }
    }

    /// The name an enrollment record stores for the suite.
    pub fn name(self) -> &'static str {
        match self {
            Self::Hpk1 => "DHKEM(X25519,HKDF-SHA256)+AES-256-GCM",
            Self::Hpk2 => "X-Wing+HKDF-SHA256+AES-256-GCM",
        }
    }

    pub fn public_key_len(self) -> usize {
        match self {
            Self::Hpk1 => 32,
            Self::Hpk2 => 1216,
        }
    }

    pub fn encapped_len(self) -> usize {
        match self {
            Self::Hpk1 => 32,
            Self::Hpk2 => 1120,
        }
    }

    /// The suite whose public keys have this length; the only suite signal a
    /// raw public key carries.
    fn of_public_key_len(len: usize) -> Option<Self> {
        [Self::Hpk1, Self::Hpk2]
            .into_iter()
            .find(|suite| suite.public_key_len() == len)
    }
}

/// The suites a deployment accepts when it loads a key. Every key loader
/// takes one, so no caller can load a key without deciding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SuitePolicy {
    hpk1: bool,
    hpk2: bool,
}

impl SuitePolicy {
    /// Production (ADR 0009's default): `HPK2` only.
    pub const PRODUCTION: Self = Self {
        hpk1: false,
        hpk2: true,
    };
    /// Development: also `HPK1`, so the browser works until P36.
    pub const DEVELOPMENT: Self = Self {
        hpk1: true,
        hpk2: true,
    };
    /// The browser build until P36: `HPK1` only.
    pub const HPK1_ONLY: Self = Self {
        hpk1: true,
        hpk2: false,
    };

    pub fn for_env(production: bool) -> Self {
        if production {
            Self::PRODUCTION
        } else {
            Self::DEVELOPMENT
        }
    }

    pub fn check(self, suite: EnvelopeSuite) -> Result<(), CryptoError> {
        let accepted = match suite {
            EnvelopeSuite::Hpk1 => self.hpk1,
            EnvelopeSuite::Hpk2 => self.hpk2,
        };
        if accepted {
            Ok(())
        } else {
            Err(CryptoError::SuiteRefused)
        }
    }
}

/// Check that `envelope` is a complete frame of a suite this build reads: a
/// known magic, and at least that suite's encapsulated key and tag. Returns
/// the suite. Only opening authenticates an envelope; this lets a party that
/// holds no key for it (the upload route, for a browser-sealed upload)
/// refuse anything that could never open.
pub fn check_envelope_frame(envelope: &[u8]) -> Result<EnvelopeSuite, CryptoError> {
    let suite = EnvelopeSuite::of_envelope(envelope)?;
    if envelope.len() < suite.min_frame_bytes() {
        return Err(CryptoError::InvalidEnvelope);
    }
    Ok(suite)
}

#[derive(Clone)]
enum PublicKeyInner {
    Hpk1(<Hpk1Kem as KemTrait>::PublicKey),
    // Boxed: an X-Wing public key is about 1.6 KB in memory.
    Hpk2(Box<<TenantKem as KemTrait>::PublicKey>),
}

/// A tenant's HPKE public key, raw bytes as enrolled.
#[derive(Clone)]
pub struct TenantPublicKey(PublicKeyInner);

impl TenantPublicKey {
    /// Parse a raw public key. Its length names the suite (32 bytes `HPK1`,
    /// 1216 bytes `HPK2`); `policy` decides whether that suite is accepted.
    pub fn from_raw(raw: &[u8], policy: SuitePolicy) -> Result<Self, CryptoError> {
        let suite =
            EnvelopeSuite::of_public_key_len(raw.len()).ok_or(CryptoError::InvalidPublicKey)?;
        policy.check(suite)?;
        let inner = match suite {
            EnvelopeSuite::Hpk1 => Deserializable::from_bytes(raw).map(PublicKeyInner::Hpk1),
            EnvelopeSuite::Hpk2 => {
                Deserializable::from_bytes(raw).map(|pk| PublicKeyInner::Hpk2(Box::new(pk)))
            }
        };
        inner.map(Self).map_err(|_| CryptoError::InvalidPublicKey)
    }

    pub fn suite(&self) -> EnvelopeSuite {
        match self.0 {
            PublicKeyInner::Hpk1(_) => EnvelopeSuite::Hpk1,
            PublicKeyInner::Hpk2(_) => EnvelopeSuite::Hpk2,
        }
    }

    pub fn to_raw(&self) -> Vec<u8> {
        match &self.0 {
            PublicKeyInner::Hpk1(pk) => pk.to_bytes().to_vec(),
            PublicKeyInner::Hpk2(pk) => pk.to_bytes().to_vec(),
        }
    }
}

impl std::fmt::Debug for TenantPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TenantPublicKey({:?})", self.suite())
    }
}

/// Envelope-seal `plaintext` to a tenant public key, in the key's suite.
/// Returns the framed envelope (`magic || encapped_key || ciphertext`).
pub fn hpke_seal_to_tenant(
    recipient: &TenantPublicKey,
    info: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    fn seal<K: KemTrait>(
        suite: EnvelopeSuite,
        pk: &K::PublicKey,
        info: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let (encapped, ciphertext) = hpke::single_shot_seal::<TenantAead, TenantKdf, K>(
            &OpModeS::Base,
            pk,
            info,
            plaintext,
            b"",
        )
        .map_err(|_| CryptoError::SealFailed)?;
        Ok(frame(suite, &encapped.to_bytes(), &ciphertext))
    }
    match &recipient.0 {
        PublicKeyInner::Hpk1(pk) => seal::<Hpk1Kem>(EnvelopeSuite::Hpk1, pk, info, plaintext),
        PublicKeyInner::Hpk2(pk) => seal::<TenantKem>(EnvelopeSuite::Hpk2, pk, info, plaintext),
    }
}

/// [`hpke_seal_to_tenant`] with the ephemeral key drawn from `rng`. Only the
/// committed test-vector generator passes a seeded RNG; everything else
/// calls [`hpke_seal_to_tenant`].
pub fn hpke_seal_to_tenant_with_rng(
    recipient: &TenantPublicKey,
    info: &[u8],
    plaintext: &[u8],
    rng: &mut impl CryptoRng,
) -> Result<Vec<u8>, CryptoError> {
    fn seal<K: KemTrait>(
        suite: EnvelopeSuite,
        pk: &K::PublicKey,
        info: &[u8],
        plaintext: &[u8],
        rng: &mut impl CryptoRng,
    ) -> Result<Vec<u8>, CryptoError> {
        let (encapped, ciphertext) = hpke::single_shot_seal_with_rng::<TenantAead, TenantKdf, K>(
            &OpModeS::Base,
            pk,
            info,
            plaintext,
            b"",
            rng,
        )
        .map_err(|_| CryptoError::SealFailed)?;
        Ok(frame(suite, &encapped.to_bytes(), &ciphertext))
    }
    match &recipient.0 {
        PublicKeyInner::Hpk1(pk) => seal::<Hpk1Kem>(EnvelopeSuite::Hpk1, pk, info, plaintext, rng),
        PublicKeyInner::Hpk2(pk) => {
            seal::<TenantKem>(EnvelopeSuite::Hpk2, pk, info, plaintext, rng)
        }
    }
}

fn frame(suite: EnvelopeSuite, encapped: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let mut envelope = Vec::with_capacity(MAGIC_BYTES + encapped.len() + ciphertext.len());
    envelope.extend_from_slice(&suite.magic());
    envelope.extend_from_slice(encapped);
    envelope.extend_from_slice(ciphertext);
    envelope
}

enum KeypairInner {
    Hpk1 {
        private_key: <Hpk1Kem as KemTrait>::PrivateKey,
        public_key: <Hpk1Kem as KemTrait>::PublicKey,
    },
    // Boxed for the same reason as `PublicKeyInner::Hpk2`.
    Hpk2(Box<Hpk2Keypair>),
}

struct Hpk2Keypair {
    private_key: <TenantKem as KemTrait>::PrivateKey,
    public_key: <TenantKem as KemTrait>::PublicKey,
}

/// Test/dev-only tenant keypair. Both suites' private keys zeroize on drop
/// (`x25519-dalek` and `x-wing`).
pub struct TenantKeypair(KeypairInner);

impl TenantKeypair {
    pub fn generate(suite: EnvelopeSuite) -> Self {
        Self(match suite {
            EnvelopeSuite::Hpk1 => {
                let (private_key, public_key) = Hpk1Kem::gen_keypair();
                KeypairInner::Hpk1 {
                    private_key,
                    public_key,
                }
            }
            EnvelopeSuite::Hpk2 => {
                let (private_key, public_key) = TenantKem::gen_keypair();
                KeypairInner::Hpk2(Box::new(Hpk2Keypair {
                    private_key,
                    public_key,
                }))
            }
        })
    }

    /// RFC 9180 `DeriveKeyPair` from input keying material. Used only for
    /// the test-only recipients of the committed vectors, whose seeds are
    /// public.
    pub fn derive(suite: EnvelopeSuite, ikm: &[u8]) -> Self {
        Self(match suite {
            EnvelopeSuite::Hpk1 => {
                let (private_key, public_key) = Hpk1Kem::derive_keypair(ikm);
                KeypairInner::Hpk1 {
                    private_key,
                    public_key,
                }
            }
            EnvelopeSuite::Hpk2 => {
                let (private_key, public_key) = TenantKem::derive_keypair(ikm);
                KeypairInner::Hpk2(Box::new(Hpk2Keypair {
                    private_key,
                    public_key,
                }))
            }
        })
    }

    pub fn suite(&self) -> EnvelopeSuite {
        match self.0 {
            KeypairInner::Hpk1 { .. } => EnvelopeSuite::Hpk1,
            KeypairInner::Hpk2(_) => EnvelopeSuite::Hpk2,
        }
    }

    pub fn public_key(&self) -> TenantPublicKey {
        TenantPublicKey(match &self.0 {
            KeypairInner::Hpk1 { public_key, .. } => PublicKeyInner::Hpk1(public_key.clone()),
            KeypairInner::Hpk2(kp) => PublicKeyInner::Hpk2(Box::new(kp.public_key.clone())),
        })
    }

    /// Export the private key as `magic || raw key` (an X25519 scalar or an
    /// X-Wing seed, both 32 bytes, so the magic is what names the suite),
    /// zeroized on drop. The key-release service HPKE-wraps this to an
    /// attested enclave's public key.
    pub fn to_private_key_bytes(&self) -> SecretBytes {
        // Both suites' private keys are 32 bytes; each temporary copy is
        // wiped before it is dropped.
        let mut framed = Vec::with_capacity(MAGIC_BYTES + 32);
        framed.extend_from_slice(&self.suite().magic());
        match &self.0 {
            KeypairInner::Hpk1 { private_key, .. } => {
                let mut raw = private_key.to_bytes();
                framed.extend_from_slice(&raw);
                raw.as_mut_slice().zeroize();
            }
            KeypairInner::Hpk2(kp) => {
                let mut raw = kp.private_key.to_bytes();
                framed.extend_from_slice(&raw);
                raw.as_mut_slice().zeroize();
            }
        }
        SecretBytes::new(framed)
    }

    /// Reconstruct a keypair from [`Self::to_private_key_bytes`] output.
    /// Unframed or unknown-magic input is refused; `policy` decides whether
    /// the named suite is accepted.
    pub fn from_private_key_bytes(framed: &[u8], policy: SuitePolicy) -> Result<Self, CryptoError> {
        let suite =
            EnvelopeSuite::of_envelope(framed).map_err(|_| CryptoError::InvalidKeyLength)?;
        policy.check(suite)?;
        let raw = &framed[MAGIC_BYTES..];
        let inner = match suite {
            EnvelopeSuite::Hpk1 => {
                let private_key = <Hpk1Kem as KemTrait>::PrivateKey::from_bytes(raw)
                    .map_err(|_| CryptoError::InvalidKeyLength)?;
                let public_key = Hpk1Kem::sk_to_pk(&private_key);
                KeypairInner::Hpk1 {
                    private_key,
                    public_key,
                }
            }
            EnvelopeSuite::Hpk2 => {
                let private_key = <TenantKem as KemTrait>::PrivateKey::from_bytes(raw)
                    .map_err(|_| CryptoError::InvalidKeyLength)?;
                let public_key = TenantKem::sk_to_pk(&private_key);
                KeypairInner::Hpk2(Box::new(Hpk2Keypair {
                    private_key,
                    public_key,
                }))
            }
        };
        Ok(Self(inner))
    }

    /// Open a framed envelope of this key's suite. Fails on a frame of
    /// another suite, tamper, wrong recipient, or a mismatched `info`.
    pub fn open_envelope(&self, info: &[u8], envelope: &[u8]) -> Result<SecretBytes, CryptoError> {
        fn open<K: KemTrait>(
            sk: &K::PrivateKey,
            encapped: &[u8],
            info: &[u8],
            ciphertext: &[u8],
        ) -> Result<SecretBytes, CryptoError> {
            let encapped =
                K::EncappedKey::from_bytes(encapped).map_err(|_| CryptoError::InvalidEnvelope)?;
            hpke::single_shot_open::<TenantAead, TenantKdf, K>(
                &OpModeR::Base,
                sk,
                &encapped,
                info,
                ciphertext,
                b"",
            )
            .map(SecretBytes::new)
            .map_err(|_| CryptoError::OpenFailed)
        }

        let suite = EnvelopeSuite::of_envelope(envelope)?;
        if suite != self.suite() {
            return Err(CryptoError::SuiteMismatch);
        }
        if envelope.len() < suite.min_frame_bytes() {
            return Err(CryptoError::InvalidEnvelope);
        }
        let (encapped, ciphertext) = envelope[MAGIC_BYTES..].split_at(suite.encapped_len());
        match &self.0 {
            KeypairInner::Hpk1 { private_key, .. } => {
                open::<Hpk1Kem>(private_key, encapped, info, ciphertext)
            }
            KeypairInner::Hpk2(kp) => {
                open::<TenantKem>(&kp.private_key, encapped, info, ciphertext)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "server")]
    const KEY: [u8; AES_KEY_BYTES] = [7u8; AES_KEY_BYTES];
    #[cfg(feature = "server")]
    const NONCE: [u8; GCM_NONCE_BYTES] = [3u8; GCM_NONCE_BYTES];

    #[cfg(feature = "server")]
    #[test]
    fn seal_open_round_trip() {
        let sealed = aead_seal(&KEY, &NONCE, b"tenant:a", b"ledger row").expect("seal");
        assert_ne!(&sealed[..], b"ledger row");
        let opened = aead_open(&KEY, &NONCE, b"tenant:a", &sealed).expect("open");
        assert_eq!(opened.expose(), b"ledger row");
    }

    #[cfg(feature = "server")]
    #[test]
    fn tampered_ciphertext_is_rejected() {
        let mut sealed = aead_seal(&KEY, &NONCE, b"aad", b"payload").expect("seal");
        sealed[0] ^= 0xFF;
        assert!(matches!(
            aead_open(&KEY, &NONCE, b"aad", &sealed),
            Err(CryptoError::OpenFailed)
        ));
    }

    #[cfg(feature = "server")]
    #[test]
    fn wrong_aad_is_rejected() {
        let sealed = aead_seal(&KEY, &NONCE, b"tenant:a", b"payload").expect("seal");
        assert!(matches!(
            aead_open(&KEY, &NONCE, b"tenant:b", &sealed),
            Err(CryptoError::OpenFailed)
        ));
    }

    #[cfg(feature = "server")]
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
    fn zeroizing_writer_grows_without_losing_bytes() {
        let mut writer = ZeroizingWriter::with_capacity(4);
        let mut expected = Vec::new();
        for chunk in [
            &b"ab"[..],
            b"cdefg",
            b"",
            b"hijklmnopqrstuvwxyz",
            b"0123456789",
        ] {
            writer.write_all(chunk).expect("write");
            expected.extend_from_slice(chunk);
        }
        assert!(writer.buf.capacity() > 4, "growth must have occurred");
        assert_eq!(writer.into_secret().expose(), expected.as_slice());
    }

    const SUITES: [EnvelopeSuite; 2] = [EnvelopeSuite::Hpk1, EnvelopeSuite::Hpk2];

    #[test]
    fn hpke_envelope_round_trips() {
        for suite in SUITES {
            let keypair = TenantKeypair::generate(suite);
            let envelope =
                hpke_seal_to_tenant(&keypair.public_key(), b"info|a|b", b"parquet bytes")
                    .expect("seal");
            assert_eq!(&envelope[..4], &suite.magic());
            let opened = keypair.open_envelope(b"info|a|b", &envelope).expect("open");
            assert_eq!(opened.expose(), b"parquet bytes");
        }
    }

    #[test]
    fn hpk2_is_current() {
        assert_eq!(EnvelopeSuite::CURRENT, EnvelopeSuite::Hpk2);
        assert_eq!(EnvelopeSuite::Hpk2.magic(), *b"HPK2");
        assert_eq!(EnvelopeSuite::Hpk1.magic(), *b"HPK1");
    }

    #[test]
    fn hpke_envelope_rejects_wrong_info_binding() {
        for suite in SUITES {
            let keypair = TenantKeypair::generate(suite);
            let envelope =
                hpke_seal_to_tenant(&keypair.public_key(), b"tenant|obj-1", b"data").expect("seal");
            assert!(matches!(
                keypair.open_envelope(b"tenant|obj-2", &envelope),
                Err(CryptoError::OpenFailed)
            ));
        }
    }

    #[test]
    fn hpke_envelope_rejects_wrong_recipient_and_tamper() {
        for suite in SUITES {
            let alice = TenantKeypair::generate(suite);
            let mallory = TenantKeypair::generate(suite);
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
    }

    #[test]
    fn hpke_envelope_rejects_bad_framing() {
        for suite in SUITES {
            let keypair = TenantKeypair::generate(suite);
            for bad in [&b"XXXXtooshort"[..], b"HPK1short", b"HPK2short", b""] {
                assert!(keypair.open_envelope(b"info", bad).is_err(), "{bad:?}");
            }
        }
    }

    #[test]
    fn envelope_overhead_per_suite() {
        // Magic (4) + encapsulated key (X25519 32, X-Wing 1120) + AES-GCM tag (16).
        // docs/BENCHMARKS.md records these sizes.
        for (suite, overhead) in [(EnvelopeSuite::Hpk1, 52), (EnvelopeSuite::Hpk2, 1140)] {
            let recipient = TenantKeypair::generate(suite).public_key();
            for len in [0usize, 32, 4096] {
                let envelope =
                    hpke_seal_to_tenant(&recipient, b"size", &vec![0u8; len]).expect("seal");
                assert_eq!(envelope.len(), len + overhead, "{suite:?}");
            }
        }
    }

    #[test]
    fn envelope_suite_comes_from_the_frame_magic() {
        for suite in SUITES {
            let keypair = TenantKeypair::generate(suite);
            let envelope = hpke_seal_to_tenant(&keypair.public_key(), b"i", b"x").expect("seal");
            assert_eq!(EnvelopeSuite::of_envelope(&envelope).expect("suite"), suite);
        }
        for unknown in [&b"HPK3"[..], b"hpk1", b"hpk2", b"HPK", b""] {
            assert!(matches!(
                EnvelopeSuite::of_envelope(unknown),
                Err(CryptoError::InvalidEnvelope)
            ));
        }
    }

    #[test]
    fn open_refuses_other_suite_frame() {
        let hpk1 = TenantKeypair::generate(EnvelopeSuite::Hpk1);
        let hpk2 = TenantKeypair::generate(EnvelopeSuite::Hpk2);
        let to_hpk1 = hpke_seal_to_tenant(&hpk1.public_key(), b"i", b"x").expect("seal");
        let to_hpk2 = hpke_seal_to_tenant(&hpk2.public_key(), b"i", b"x").expect("seal");
        assert!(matches!(
            hpk2.open_envelope(b"i", &to_hpk1),
            Err(CryptoError::SuiteMismatch)
        ));
        assert!(matches!(
            hpk1.open_envelope(b"i", &to_hpk2),
            Err(CryptoError::SuiteMismatch)
        ));
        // A relabelled frame is refused, not reinterpreted under the other suite.
        let mut relabelled = to_hpk1.clone();
        relabelled[..4].copy_from_slice(b"HPK2");
        assert!(hpk1.open_envelope(b"i", &relabelled).is_err());
        assert!(hpk2.open_envelope(b"i", &relabelled).is_err());
    }

    #[test]
    fn from_raw_accepts_only_suite_lengths() {
        for suite in SUITES {
            let raw = TenantKeypair::generate(suite).public_key().to_raw();
            assert_eq!(raw.len(), suite.public_key_len());
            let parsed = TenantPublicKey::from_raw(&raw, SuitePolicy::DEVELOPMENT).expect("raw");
            assert_eq!(parsed.suite(), suite);
        }
        assert_eq!(EnvelopeSuite::Hpk1.public_key_len(), 32);
        assert_eq!(EnvelopeSuite::Hpk2.public_key_len(), 1216);
        for len in [0usize, 31, 33, 1215, 1217, 2432] {
            assert!(matches!(
                TenantPublicKey::from_raw(&vec![7u8; len], SuitePolicy::DEVELOPMENT),
                Err(CryptoError::InvalidPublicKey)
            ));
        }
    }

    #[test]
    fn production_policy_refuses_hpk1() {
        let hpk1 = TenantKeypair::generate(EnvelopeSuite::Hpk1);
        let hpk2 = TenantKeypair::generate(EnvelopeSuite::Hpk2);
        let hpk1_raw = hpk1.public_key().to_raw();
        let hpk2_raw = hpk2.public_key().to_raw();
        assert!(matches!(
            TenantPublicKey::from_raw(&hpk1_raw, SuitePolicy::PRODUCTION),
            Err(CryptoError::SuiteRefused)
        ));
        assert!(matches!(
            TenantKeypair::from_private_key_bytes(
                hpk1.to_private_key_bytes().expose(),
                SuitePolicy::PRODUCTION
            ),
            Err(CryptoError::SuiteRefused)
        ));
        assert!(TenantPublicKey::from_raw(&hpk2_raw, SuitePolicy::PRODUCTION).is_ok());
        assert!(matches!(
            TenantPublicKey::from_raw(&hpk2_raw, SuitePolicy::HPK1_ONLY),
            Err(CryptoError::SuiteRefused)
        ));
        assert!(TenantPublicKey::from_raw(&hpk1_raw, SuitePolicy::HPK1_ONLY).is_ok());
        assert_eq!(SuitePolicy::for_env(true), SuitePolicy::PRODUCTION);
        assert_eq!(SuitePolicy::for_env(false), SuitePolicy::DEVELOPMENT);
    }

    #[test]
    fn private_keys_are_framed() {
        for suite in SUITES {
            let keypair = TenantKeypair::generate(suite);
            let framed = keypair.to_private_key_bytes();
            assert_eq!(&framed.expose()[..4], &suite.magic());
            assert_eq!(framed.expose().len(), 36);
            let restored =
                TenantKeypair::from_private_key_bytes(framed.expose(), SuitePolicy::DEVELOPMENT)
                    .expect("framed key");
            assert_eq!(restored.suite(), suite);
            assert_eq!(
                restored.public_key().to_raw(),
                keypair.public_key().to_raw()
            );
            for bad in [
                &framed.expose()[4..],
                &[b"HPK3".as_slice(), &framed.expose()[4..]].concat()[..],
            ] {
                assert!(matches!(
                    TenantKeypair::from_private_key_bytes(bad, SuitePolicy::DEVELOPMENT),
                    Err(CryptoError::InvalidKeyLength)
                ));
            }
        }
    }

    #[test]
    fn info_kind_follows_suite() {
        use EnvelopeSuite::{Hpk1, Hpk2};
        type Builder = fn(EnvelopeSuite) -> Vec<u8>;
        let cases: [(Builder, &str); 4] = [
            (
                |s| info::connector_object(s, "t", "c", "o"),
                "tenant-envelope",
            ),
            (
                |s| info::snapshot_manifest(s, "t", "c", "v"),
                "tenant-snapshot-manifest",
            ),
            (|s| info::steward_upload(s, "t", "d", "o"), "steward-upload"),
            (|s| info::research_result(s, "t", "q"), "research-result"),
        ];
        for (build, kind) in cases {
            assert!(
                build(Hpk1).starts_with(format!("{kind}-v1|").as_bytes()),
                "{kind}"
            );
            assert!(
                build(Hpk2).starts_with(format!("{kind}-v2|").as_bytes()),
                "{kind}"
            );
        }
    }

    #[test]
    fn suite_names() {
        assert_eq!(
            EnvelopeSuite::Hpk1.name(),
            "DHKEM(X25519,HKDF-SHA256)+AES-256-GCM"
        );
        assert_eq!(EnvelopeSuite::Hpk2.name(), "X-Wing+HKDF-SHA256+AES-256-GCM");
    }

    #[test]
    fn frame_check_refuses_unknown_magic_and_truncated_frames() {
        for suite in SUITES {
            let keypair = TenantKeypair::generate(suite);
            let empty = hpke_seal_to_tenant(&keypair.public_key(), b"i", b"").expect("seal");
            assert_eq!(empty.len(), suite.min_frame_bytes());
            assert_eq!(check_envelope_frame(&empty).expect("complete frame"), suite);
            // A known magic alone does not make a frame: the committed
            // "truncated frame" vector is 20 bytes starting `HPK1`.
            for short in [&empty[..4], &empty[..20], &empty[..empty.len() - 1]] {
                assert!(EnvelopeSuite::of_envelope(short).is_ok());
                assert!(matches!(
                    check_envelope_frame(short),
                    Err(CryptoError::InvalidEnvelope)
                ));
            }
            let mut unknown = empty.clone();
            unknown[..4].copy_from_slice(b"HPK9");
            assert!(check_envelope_frame(&unknown).is_err());
        }
        // An HPK1 frame relabelled HPK2 is too short to be one.
        let keypair = TenantKeypair::generate(EnvelopeSuite::Hpk1);
        let mut relabelled = hpke_seal_to_tenant(&keypair.public_key(), b"i", b"").expect("seal");
        relabelled[..4].copy_from_slice(b"HPK2");
        assert!(check_envelope_frame(&relabelled).is_err());
    }

    #[test]
    fn suite_ids_are_stable_and_round_trip() {
        assert_eq!(EnvelopeSuite::Hpk1.id(), "HPK1");
        assert_eq!(EnvelopeSuite::Hpk2.id(), "HPK2");
        for suite in SUITES {
            assert_eq!(suite.id().as_bytes(), suite.magic());
            assert_eq!(EnvelopeSuite::from_id(suite.id()).expect("known"), suite);
        }
        for unknown in ["", "hpk1", "HPK3", "HPK1 "] {
            assert!(EnvelopeSuite::from_id(unknown).is_err(), "{unknown:?}");
        }
    }

    #[test]
    fn derived_keypairs_are_deterministic_and_seed_separated() {
        for suite in SUITES {
            let a1 = TenantKeypair::derive(suite, b"seed a")
                .public_key()
                .to_raw();
            let a2 = TenantKeypair::derive(suite, b"seed a")
                .public_key()
                .to_raw();
            let b = TenantKeypair::derive(suite, b"seed b")
                .public_key()
                .to_raw();
            assert_eq!(a1, a2);
            assert_ne!(a1, b);
        }
    }

    #[test]
    fn tenant_public_key_raw_round_trip() {
        for suite in SUITES {
            let keypair = TenantKeypair::generate(suite);
            let raw = keypair.public_key().to_raw();
            let restored =
                TenantPublicKey::from_raw(&raw, SuitePolicy::DEVELOPMENT).expect("valid raw key");
            let envelope = hpke_seal_to_tenant(&restored, b"i", b"x").expect("seal");
            assert_eq!(
                keypair
                    .open_envelope(b"i", &envelope)
                    .expect("open")
                    .expose(),
                b"x"
            );
        }
    }

    mod props {
        use super::*;
        use proptest::prelude::*;
        use std::sync::LazyLock;

        static KEYPAIR: LazyLock<TenantKeypair> =
            LazyLock::new(|| TenantKeypair::generate(EnvelopeSuite::CURRENT));

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
                    [&EnvelopeSuite::CURRENT.magic()[..], &envelope].concat()
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
            fn arbitrary_public_keys_never_panic(raw in bytes(1300)) {
                let parsed = TenantPublicKey::from_raw(&raw, SuitePolicy::DEVELOPMENT);
                prop_assert!(parsed.is_err() || raw.len() == 32 || raw.len() == 1216);
                if raw.len() == 32 {
                    prop_assert!(parsed.is_ok());
                }
            }

            #[cfg(feature = "server")]
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

            #[cfg(feature = "server")]
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
