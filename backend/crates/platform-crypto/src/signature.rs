//! Attestation-bound result signatures (ADR 0007 "Signatures in v1", ADR
//! 0010 "Sealed and signed result"): every result is signed with Ed25519 and
//! ML-DSA-65, and a verifier accepts it only if both signatures verify over
//! the same domain-separated message.
//!
//! Signing happens only in the enclave; verification also ships in the
//! browser module, so nothing here needs the `server` feature.

use ed25519_dalek::Signer as _;
use ml_dsa::{EncodedVerifyingKey, Keypair as _, MlDsa65};
use zeroize::Zeroizing;

use crate::CryptoError;

pub const ED25519_PUBLIC_KEY_BYTES: usize = 32;
pub const ML_DSA_65_PUBLIC_KEY_BYTES: usize = 1952;
pub const ED25519_SIGNATURE_BYTES: usize = 64;
pub const ML_DSA_65_SIGNATURE_BYTES: usize = 3309;

const MESSAGE_TAG: &[u8] = b"research-result-signature-v1";

/// The bytes both schemes sign: the tag, then `info` and the sealed frame,
/// each after its `u32` big-endian length.
pub fn result_signature_message(info: &[u8], frame: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(MESSAGE_TAG.len() + 8 + info.len() + frame.len());
    message.extend_from_slice(MESSAGE_TAG);
    for part in [info, frame] {
        let len = u32::try_from(part.len()).expect("a signed part is under 4 GiB");
        message.extend_from_slice(&len.to_be_bytes());
        message.extend_from_slice(part);
    }
    message
}

/// The enclave's result-signing key pair. Both private keys live only in
/// memory and are wiped on drop; `Debug` prints neither.
pub struct ResultSigningKey {
    ed25519: ed25519_dalek::SigningKey,
    ml_dsa_65: ml_dsa::SigningKey<MlDsa65>,
}

impl ResultSigningKey {
    /// A fresh key pair. Each scheme's key comes from its own 32-byte seed
    /// drawn from the OS RNG. Panics if the OS RNG is unavailable, so the
    /// enclave never starts with weak keys.
    pub fn generate() -> Self {
        let mut ed_seed = Zeroizing::new([0u8; 32]);
        let mut ml_seed = Zeroizing::new(ml_dsa::B32::default());
        getrandom::fill(ed_seed.as_mut()).expect("OS RNG available");
        getrandom::fill(ml_seed.as_mut_slice()).expect("OS RNG available");
        Self {
            ed25519: ed25519_dalek::SigningKey::from_bytes(&ed_seed),
            ml_dsa_65: ml_dsa::SigningKey::from_seed(&ml_seed),
        }
    }

    pub fn verifying_keys(&self) -> ResultVerifyingKeys {
        ResultVerifyingKeys {
            ed25519: self.ed25519.verifying_key(),
            ml_dsa_65: self.ml_dsa_65.verifying_key(),
        }
    }

    /// Sign `frame` under `info`. ML-DSA-65 uses its deterministic variant
    /// with an empty context string.
    pub fn sign(&self, info: &[u8], frame: &[u8]) -> ResultSignature {
        let message = result_signature_message(info, frame);
        let ml_dsa_65 = self.ml_dsa_65.sign(&message);
        ResultSignature {
            ed25519: self.ed25519.sign(&message).to_bytes(),
            ml_dsa_65: ml_dsa_65.encode().to_vec(),
        }
    }
}

impl std::fmt::Debug for ResultSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ResultSigningKey(..)")
    }
}

/// The public half of a [`ResultSigningKey`], as bound into the attestation
/// token.
#[derive(Clone)]
pub struct ResultVerifyingKeys {
    ed25519: ed25519_dalek::VerifyingKey,
    ml_dsa_65: ml_dsa::VerifyingKey<MlDsa65>,
}

impl ResultVerifyingKeys {
    /// Parse the two encoded public keys. A wrong length is
    /// `InvalidKeyLength`; an Ed25519 key that is not a valid point is
    /// `InvalidPublicKey`.
    pub fn from_bytes(ed25519: &[u8], ml_dsa_65: &[u8]) -> Result<Self, CryptoError> {
        let ed25519: [u8; ED25519_PUBLIC_KEY_BYTES] = ed25519
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyLength)?;
        let ml_dsa_65 = EncodedVerifyingKey::<MlDsa65>::try_from(ml_dsa_65)
            .map_err(|_| CryptoError::InvalidKeyLength)?;
        Ok(Self {
            ed25519: ed25519_dalek::VerifyingKey::from_bytes(&ed25519)
                .map_err(|_| CryptoError::InvalidPublicKey)?,
            ml_dsa_65: ml_dsa::VerifyingKey::decode(&ml_dsa_65),
        })
    }

    pub fn ed25519_bytes(&self) -> [u8; ED25519_PUBLIC_KEY_BYTES] {
        self.ed25519.to_bytes()
    }

    pub fn ml_dsa_65_bytes(&self) -> Vec<u8> {
        self.ml_dsa_65.encode().to_vec()
    }

    /// Accept `signature` only if both schemes verify it over `info` and
    /// `frame`. Ed25519 uses strict verification.
    pub fn verify(
        &self,
        info: &[u8],
        frame: &[u8],
        signature: &ResultSignature,
    ) -> Result<(), CryptoError> {
        let message = result_signature_message(info, frame);
        let ed25519 = ed25519_dalek::Signature::from_bytes(&signature.ed25519);
        let ed25519_ok = self.ed25519.verify_strict(&message, &ed25519).is_ok();
        let ml_dsa_ok = ml_dsa::Signature::<MlDsa65>::try_from(signature.ml_dsa_65.as_slice())
            .is_ok_and(|sig| self.ml_dsa_65.verify_with_context(&message, &[], &sig));
        if ed25519_ok && ml_dsa_ok {
            Ok(())
        } else {
            Err(CryptoError::SignatureInvalid)
        }
    }
}

/// Both signatures over one result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResultSignature {
    pub ed25519: [u8; ED25519_SIGNATURE_BYTES],
    pub ml_dsa_65: Vec<u8>,
}

impl ResultSignature {
    /// Take the two encoded signatures; a wrong length is
    /// `SignatureInvalid`. Their contents are checked by
    /// [`ResultVerifyingKeys::verify`].
    pub fn from_bytes(ed25519: &[u8], ml_dsa_65: &[u8]) -> Result<Self, CryptoError> {
        if ml_dsa_65.len() != ML_DSA_65_SIGNATURE_BYTES {
            return Err(CryptoError::SignatureInvalid);
        }
        Ok(Self {
            ed25519: ed25519
                .try_into()
                .map_err(|_| CryptoError::SignatureInvalid)?,
            ml_dsa_65: ml_dsa_65.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CryptoError;

    #[test]
    fn message_layout_is_pinned() {
        // ADR 0010: tag ‖ u32 len(info) ‖ info ‖ u32 len(frame) ‖ frame,
        // computed independently of this code.
        let expected =
            "72657365617263682d726573756c742d7369676e61747572652d763100000001690000000166";
        let message = result_signature_message(b"i", b"f");
        let hex: String = message.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, expected);
    }

    #[test]
    fn a_signature_verifies_under_its_keys() {
        let key = ResultSigningKey::generate();
        let signature = key.sign(b"info", b"frame");
        let keys = key.verifying_keys();
        keys.verify(b"info", b"frame", &signature)
            .expect("verifies");

        let parsed =
            ResultVerifyingKeys::from_bytes(&keys.ed25519_bytes(), &keys.ml_dsa_65_bytes())
                .expect("parses");
        parsed
            .verify(b"info", b"frame", &signature)
            .expect("verifies after parsing");
        let parsed_signature =
            ResultSignature::from_bytes(&signature.ed25519, &signature.ml_dsa_65).expect("parses");
        keys.verify(b"info", b"frame", &parsed_signature)
            .expect("verifies");
    }

    #[test]
    fn either_signature_alone_is_refused() {
        let key = ResultSigningKey::generate();
        let keys = key.verifying_keys();
        let signature = key.sign(b"info", b"frame");

        let mut bad_ed25519 = signature.clone();
        bad_ed25519.ed25519[0] ^= 1;
        let mut bad_ml_dsa = signature.clone();
        bad_ml_dsa.ml_dsa_65[0] ^= 1;
        // A valid ML-DSA signature by the same key, over another message.
        let other = key.sign(b"info", b"other frame");
        let mismatched = ResultSignature {
            ed25519: signature.ed25519,
            ml_dsa_65: other.ml_dsa_65,
        };
        for bad in [bad_ed25519, bad_ml_dsa, mismatched] {
            assert!(matches!(
                keys.verify(b"info", b"frame", &bad),
                Err(CryptoError::SignatureInvalid)
            ));
        }
    }

    #[test]
    fn a_byte_moved_between_info_and_frame_is_refused() {
        let key = ResultSigningKey::generate();
        let signature = key.sign(b"ab", b"c");
        assert!(matches!(
            key.verifying_keys().verify(b"a", b"bc", &signature),
            Err(CryptoError::SignatureInvalid)
        ));
    }

    #[test]
    fn another_keys_signature_is_refused() {
        let signature = ResultSigningKey::generate().sign(b"info", b"frame");
        let other = ResultSigningKey::generate().verifying_keys();
        assert!(matches!(
            other.verify(b"info", b"frame", &signature),
            Err(CryptoError::SignatureInvalid)
        ));
    }

    #[test]
    fn wrong_lengths_are_refused() {
        let keys = ResultSigningKey::generate().verifying_keys();
        let ed = keys.ed25519_bytes();
        let ml = keys.ml_dsa_65_bytes();
        assert!(matches!(
            ResultVerifyingKeys::from_bytes(&ed[..31], &ml),
            Err(CryptoError::InvalidKeyLength)
        ));
        assert!(matches!(
            ResultVerifyingKeys::from_bytes(&ed, &ml[..ML_DSA_65_PUBLIC_KEY_BYTES - 1]),
            Err(CryptoError::InvalidKeyLength)
        ));
        let signature = ResultSigningKey::generate().sign(b"i", b"f");
        assert!(matches!(
            ResultSignature::from_bytes(&signature.ed25519[..63], &signature.ml_dsa_65),
            Err(CryptoError::SignatureInvalid)
        ));
        assert!(matches!(
            ResultSignature::from_bytes(
                &signature.ed25519,
                &signature.ml_dsa_65[..ML_DSA_65_SIGNATURE_BYTES - 1]
            ),
            Err(CryptoError::SignatureInvalid)
        ));
    }

    #[test]
    fn debug_does_not_print_keys() {
        assert_eq!(
            format!("{:?}", ResultSigningKey::generate()),
            "ResultSigningKey(..)"
        );
    }
}
