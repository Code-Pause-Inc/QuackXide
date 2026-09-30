//! RS256 keypair and matching JWKS generation, used by the `keygen` binary
//! and by tests that need real keys.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rsa::RsaPrivateKey;
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::pkcs1::LineEnding;
use rsa::traits::PublicKeyParts;

use crate::AuthError;

/// A generated RS256 keypair. `private_pem` belongs only to the signer
/// process ([`crate::TokenSigner::rs256_from_pem`]); `jwks_json` goes to
/// every verifier ([`crate::JwtVerifier::rs256_from_jwks`]); `kid` binds
/// minted tokens to the JWKS entry.
#[derive(Debug)]
pub struct GeneratedKeypair {
    pub private_pem: String,
    pub jwks_json: String,
    pub kid: String,
}

/// Minimum accepted modulus size (the NIST/IETF floor for RSA).
pub const MIN_RSA_BITS: usize = 2048;

/// Generate an RSA keypair and its JWKS. Refuses `bits` below
/// [`MIN_RSA_BITS`].
pub fn generate_rs256_keypair(bits: usize) -> Result<GeneratedKeypair, AuthError> {
    if bits < MIN_RSA_BITS {
        return Err(AuthError::MintFailed);
    }
    let mut rng = rand::rngs::OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, bits).map_err(|_| AuthError::MintFailed)?;
    let public_key = private_key.to_public_key();

    let private_pem = private_key
        .to_pkcs1_pem(LineEnding::LF)
        .map_err(|_| AuthError::MintFailed)?
        .to_string();

    let n_b64 = URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
    let e_b64 = URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());
    let kid = random_kid();

    let jwks_json = serde_json::json!({
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": kid,
            "n": n_b64,
            "e": e_b64,
        }]
    })
    .to_string();

    Ok(GeneratedKeypair {
        private_pem,
        jwks_json,
        kid,
    })
}

/// A `kid` need only be unique within a JWKS document; it is not secret and
/// not derived from the key material.
fn random_kid() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Shared pool of real, distinct keypairs: RSA generation dominates this
/// crate's test time, so tests draw from here instead of generating their own.
#[cfg(test)]
pub(crate) mod fixtures {
    use super::{GeneratedKeypair, MIN_RSA_BITS, generate_rs256_keypair};
    use std::sync::OnceLock;

    static POOL: OnceLock<Vec<GeneratedKeypair>> = OnceLock::new();

    pub(crate) fn keypair(i: usize) -> &'static GeneratedKeypair {
        &POOL.get_or_init(|| {
            (0..2)
                .map(|_| generate_rs256_keypair(MIN_RSA_BITS).expect("keygen"))
                .collect()
        })[i]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_a_usable_keypair() {
        let keypair = generate_rs256_keypair(MIN_RSA_BITS).expect("keygen");
        assert!(keypair.private_pem.contains("BEGIN RSA PRIVATE KEY"));
        assert_eq!(keypair.kid.len(), 16);

        let jwks: serde_json::Value = serde_json::from_str(&keypair.jwks_json).expect("valid json");
        let keys = jwks["keys"].as_array().expect("keys array");
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["kid"], keypair.kid);
        assert_eq!(keys[0]["kty"], "RSA");
        assert_eq!(keys[0]["alg"], "RS256");
    }

    #[test]
    fn fixture_pool_keys_are_distinct() {
        let a = fixtures::keypair(0);
        let b = fixtures::keypair(1);
        assert_ne!(a.kid, b.kid);
        assert_ne!(a.private_pem, b.private_pem);
    }

    #[test]
    fn undersized_keys_are_refused() {
        assert!(matches!(
            generate_rs256_keypair(1024),
            Err(AuthError::MintFailed)
        ));
    }
}
