//! Token minting. [`TokenSigner`] is the production RS256 path and the only
//! code here that touches a private key; it runs on the identity-service
//! signer, never on an API replica. `mint_token`/`mint_admin_token` are the
//! dev-only HS256 path.

use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use platform_core::TenantId;

use crate::{AuthError, RawClaims, TokenType, unix_now};

/// Mints RS256 tokens. Holding one means holding the private key.
pub struct TokenSigner {
    key: EncodingKey,
    kid: String,
    issuer: String,
    audience: String,
}

impl TokenSigner {
    /// Load a signer from a PEM-encoded RSA private key (PKCS#1 or PKCS#8).
    /// `kid` must match this key's entry in the verifiers' JWKS, or every
    /// minted token will be unverifiable.
    pub fn rs256_from_pem(
        private_pem: &str,
        kid: &str,
        issuer: &str,
        audience: &str,
    ) -> Result<Self, AuthError> {
        let key = EncodingKey::from_rsa_pem(private_pem.as_bytes())
            .map_err(|_| AuthError::InvalidPrivateKey)?;
        Ok(Self {
            key,
            kid: kid.to_owned(),
            issuer: issuer.to_owned(),
            audience: audience.to_owned(),
        })
    }

    /// Mint a token. `ttl_secs` may be negative to mint an already-expired
    /// token (test/tooling use only).
    pub fn mint(
        &self,
        tenant: TenantId,
        subject: &str,
        token_type: TokenType,
        ttl_secs: i64,
        admin: bool,
    ) -> Result<String, AuthError> {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.kid.clone());
        let claims = raw_claims(
            &self.issuer,
            &self.audience,
            tenant,
            subject,
            ttl_secs,
            token_type,
            admin,
        );
        encode(&header, &claims, &self.key).map_err(|_| AuthError::MintFailed)
    }
}

/// Mint a non-admin `Access` HS256 token (tests and the dev `devtoken`
/// binary only). `ttl_secs` may be negative to mint an expired token.
pub fn mint_token(
    secret: &str,
    issuer: &str,
    audience: &str,
    tenant: TenantId,
    subject: &str,
    ttl_secs: i64,
) -> Result<String, AuthError> {
    let claims = raw_claims(
        issuer,
        audience,
        tenant,
        subject,
        ttl_secs,
        TokenType::Access,
        false,
    );
    mint_hs256(secret, &claims)
}

/// Mint an HS256 token carrying the admin claim (dev/test tooling only).
pub fn mint_admin_token(
    secret: &str,
    issuer: &str,
    audience: &str,
    tenant: TenantId,
    subject: &str,
    ttl_secs: i64,
) -> Result<String, AuthError> {
    let claims = raw_claims(
        issuer,
        audience,
        tenant,
        subject,
        ttl_secs,
        TokenType::Access,
        true,
    );
    mint_hs256(secret, &claims)
}

fn mint_hs256(secret: &str, claims: &RawClaims) -> Result<String, AuthError> {
    encode(
        &Header::new(Algorithm::HS256),
        claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|_| AuthError::MintFailed)
}

fn raw_claims(
    issuer: &str,
    audience: &str,
    tenant: TenantId,
    subject: &str,
    ttl_secs: i64,
    token_type: TokenType,
    admin: bool,
) -> RawClaims {
    RawClaims {
        sub: subject.to_owned(),
        tid: tenant.to_string(),
        iss: issuer.to_owned(),
        aud: audience.to_owned(),
        exp: (unix_now() as i64 + ttl_secs).max(0) as u64,
        adm: admin,
        typ: token_type.as_str().to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rs256_signer_rejects_a_malformed_pem() {
        assert!(matches!(
            TokenSigner::rs256_from_pem("not a pem", "kid1", "iss", "aud"),
            Err(AuthError::InvalidPrivateKey)
        ));
    }

    #[test]
    fn rs256_signer_loads_a_generated_key() {
        let keypair = crate::keygen::fixtures::keypair(0);
        let signer = TokenSigner::rs256_from_pem(&keypair.private_pem, &keypair.kid, "iss", "aud")
            .expect("signer");
        let token = signer
            .mint(
                platform_core::TenantId::generate(),
                "user-1",
                TokenType::Access,
                3600,
                false,
            )
            .expect("mint");
        assert!(!token.is_empty());
    }
}
