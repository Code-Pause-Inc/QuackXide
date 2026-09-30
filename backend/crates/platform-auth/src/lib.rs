//! JWT minting and verification for tenant-scoped API access.
//!
//! * **`hs256`** — shared secret; dev and CI only. Anyone who compromises
//!   the API host can mint tokens for any tenant.
//! * **`rs256_from_jwks`** — production. API replicas hold only the public
//!   JWKS; the private key stays with a [`TokenSigner`] on the identity
//!   service, so host compromise yields no mint capability.
//!
//! The tenant claim (`tid`) is the only source of tenant identity in the
//! API. Handlers never accept a tenant id from a path, query, or body.

mod jwks;
pub mod keygen;
mod sign;
mod verify;

pub use keygen::{GeneratedKeypair, generate_rs256_keypair};
pub use sign::{TokenSigner, mint_admin_token, mint_token};
pub use verify::JwtVerifier;

use platform_core::TenantId;
use serde::{Deserialize, Serialize};

/// What a token authorizes its bearer to do. Kept separate from `adm` (a
/// tenant privilege) so a pre-MFA or refresh token is never accepted where
/// an access token is expected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenType {
    /// Ordinary API access; the only type the dev HS256 helpers mint.
    Access,
    /// Issued after IdP sign-in, before the TOTP challenge is satisfied.
    /// Useless against data routes.
    Preauth,
    /// Exchanged for a fresh access token; rotates on use.
    Refresh,
}

impl TokenType {
    pub fn as_str(self) -> &'static str {
        match self {
            TokenType::Access => "access",
            TokenType::Preauth => "preauth",
            TokenType::Refresh => "refresh",
        }
    }
}

impl std::str::FromStr for TokenType {
    type Err = AuthError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "access" => Ok(TokenType::Access),
            "preauth" => Ok(TokenType::Preauth),
            "refresh" => Ok(TokenType::Refresh),
            _ => Err(AuthError::TokenRejected),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RawClaims {
    sub: String,
    tid: String,
    iss: String,
    aud: String,
    exp: u64,
    /// Admin flag. Absent ⇒ non-admin (the safe default).
    #[serde(default)]
    adm: bool,
    /// Token type. Absent ⇒ `access`.
    #[serde(default = "default_typ")]
    typ: String,
}

fn default_typ() -> String {
    TokenType::Access.as_str().to_owned()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedClaims {
    pub subject: String,
    pub tenant: TenantId,
    pub expires_at_unix: u64,
    /// True only when the token carries an explicit admin claim.
    pub admin: bool,
    pub token_type: TokenType,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthError {
    /// Deliberately unspecific: callers learn only that the token was
    /// rejected, not which check failed.
    #[error("token rejected")]
    TokenRejected,
    #[error("token minting failed")]
    MintFailed,
    /// A JWKS document was malformed, empty, or contained no usable RSA key.
    #[error("invalid JWKS document")]
    InvalidJwks,
    /// An RS256 private key PEM failed to parse.
    #[error("invalid private key")]
    InvalidPrivateKey,
}

pub(crate) fn unix_now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_type_round_trips_through_str() {
        for t in [TokenType::Access, TokenType::Preauth, TokenType::Refresh] {
            assert_eq!(t.as_str().parse::<TokenType>().expect("parse"), t);
        }
    }

    #[test]
    fn unknown_token_type_string_is_rejected() {
        assert_eq!("bogus".parse::<TokenType>(), Err(AuthError::TokenRejected));
    }
}
