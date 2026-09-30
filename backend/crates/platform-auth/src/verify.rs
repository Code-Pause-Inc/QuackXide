//! Token verification behind one [`JwtVerifier::verify`] surface for both
//! modes.

use std::collections::HashMap;

use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use platform_core::TenantId;

use crate::{AuthError, RawClaims, TokenType, VerifiedClaims, jwks};

enum VerifyKey {
    /// HS256 dev mode: one shared secret, no `kid` lookup needed.
    Shared(DecodingKey),
    /// RS256 production mode: the token's `kid` selects among trusted keys
    /// only; an unknown `kid` fails the lookup.
    ByKid(HashMap<String, DecodingKey>),
}

pub struct JwtVerifier {
    keys: VerifyKey,
    validation: Validation,
}

impl JwtVerifier {
    /// Dev/self-hosted only: the server holds the signing secret, so host
    /// compromise yields mint-any-tenant capability.
    pub fn hs256(secret: &str, issuer: &str, audience: &str) -> Self {
        Self {
            keys: VerifyKey::Shared(DecodingKey::from_secret(secret.as_bytes())),
            validation: validation_for(Algorithm::HS256, issuer, audience),
        }
    }

    /// Production: verify against a JWKS document's public keys only. During
    /// rotation the document carries both keys and both verify.
    pub fn rs256_from_jwks(
        jwks_json: &str,
        issuer: &str,
        audience: &str,
    ) -> Result<Self, AuthError> {
        let keys = jwks::decoding_keys_from_jwks(jwks_json)?;
        Ok(Self {
            keys: VerifyKey::ByKid(keys),
            validation: validation_for(Algorithm::RS256, issuer, audience),
        })
    }

    pub fn verify(&self, token: &str) -> Result<VerifiedClaims, AuthError> {
        let key = match &self.keys {
            VerifyKey::Shared(key) => key,
            VerifyKey::ByKid(map) => {
                let header = decode_header(token).map_err(|_| AuthError::TokenRejected)?;
                let kid = header.kid.as_deref().ok_or(AuthError::TokenRejected)?;
                map.get(kid).ok_or(AuthError::TokenRejected)?
            }
        };
        // The algorithm allowlist is fixed at construction, never taken from
        // the token, so an HS256 forgery keyed with the public JWKS bytes is
        // refused before signature verification (alg-confusion defense).
        let data = decode::<RawClaims>(token, key, &self.validation)
            .map_err(|_| AuthError::TokenRejected)?;
        let tenant: TenantId = data
            .claims
            .tid
            .parse()
            .map_err(|_| AuthError::TokenRejected)?;
        let token_type: TokenType = data
            .claims
            .typ
            .parse()
            .map_err(|_| AuthError::TokenRejected)?;
        Ok(VerifiedClaims {
            subject: data.claims.sub,
            tenant,
            expires_at_unix: data.claims.exp,
            admin: data.claims.adm,
            token_type,
        })
    }
}

fn validation_for(alg: Algorithm, issuer: &str, audience: &str) -> Validation {
    let mut validation = Validation::new(alg);
    validation.set_issuer(&[issuer]);
    validation.set_audience(&[audience]);
    validation.set_required_spec_claims(&["exp", "iss", "aud"]);
    validation.validate_nbf = true;
    validation
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TokenSigner;
    use crate::keygen::fixtures::keypair;
    use crate::sign::{mint_admin_token, mint_token};
    use jsonwebtoken::{EncodingKey, Header, encode};
    use serde_json::json;

    const ISS: &str = "urn:platform:auth";
    const AUD: &str = "urn:platform:drive";

    fn rs256_verifier(jwks_json: &str) -> JwtVerifier {
        JwtVerifier::rs256_from_jwks(jwks_json, ISS, AUD).expect("verifier")
    }

    // ── HS256 (dev) ──────────────────────────────────────────────────────

    #[test]
    fn hs256_valid_token_round_trips_tenant_and_subject() {
        let tenant = TenantId::generate();
        let token = mint_token("secret", ISS, AUD, tenant, "user-1", 3600).expect("mint");
        let claims = JwtVerifier::hs256("secret", ISS, AUD)
            .verify(&token)
            .expect("verify");
        assert_eq!(claims.tenant, tenant);
        assert_eq!(claims.subject, "user-1");
        assert!(!claims.admin);
        assert_eq!(claims.token_type, TokenType::Access);
    }

    #[test]
    fn hs256_admin_claim_round_trips_and_defaults_off() {
        let tenant = TenantId::generate();
        let verifier = JwtVerifier::hs256("secret", ISS, AUD);
        let admin = mint_admin_token("secret", ISS, AUD, tenant, "root", 3600).expect("mint");
        assert!(verifier.verify(&admin).expect("verify").admin);

        let regular = mint_token("secret", ISS, AUD, tenant, "user", 3600).expect("mint");
        assert!(!verifier.verify(&regular).expect("verify").admin);
    }

    #[test]
    fn hs256_wrong_secret_is_rejected() {
        let token =
            mint_token("secret-a", ISS, AUD, TenantId::generate(), "u", 3600).expect("mint");
        assert_eq!(
            JwtVerifier::hs256("secret-b", ISS, AUD).verify(&token),
            Err(AuthError::TokenRejected)
        );
    }

    #[test]
    fn hs256_expired_token_is_rejected() {
        let token = mint_token("secret", ISS, AUD, TenantId::generate(), "u", -3600).expect("mint");
        assert_eq!(
            JwtVerifier::hs256("secret", ISS, AUD).verify(&token),
            Err(AuthError::TokenRejected)
        );
    }

    #[test]
    fn hs256_wrong_audience_or_issuer_is_rejected() {
        let verifier = JwtVerifier::hs256("secret", ISS, AUD);
        let wrong_aud = mint_token(
            "secret",
            ISS,
            "urn:other:aud",
            TenantId::generate(),
            "u",
            3600,
        )
        .expect("mint");
        assert_eq!(verifier.verify(&wrong_aud), Err(AuthError::TokenRejected));

        let wrong_iss = mint_token(
            "secret",
            "urn:other:iss",
            AUD,
            TenantId::generate(),
            "u",
            3600,
        )
        .expect("mint");
        assert_eq!(verifier.verify(&wrong_iss), Err(AuthError::TokenRejected));
    }

    #[test]
    fn hs256_malformed_tenant_claim_is_rejected() {
        let claims = json!({
            "sub": "u", "tid": "not-a-uuid", "iss": ISS, "aud": AUD,
            "exp": crate::unix_now() + 3600, "adm": false, "typ": "access",
        });
        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(b"secret"),
        )
        .expect("encode");
        assert_eq!(
            JwtVerifier::hs256("secret", ISS, AUD).verify(&token),
            Err(AuthError::TokenRejected)
        );
    }

    fn hs256_token(claims: serde_json::Value) -> String {
        encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(b"secret"),
        )
        .expect("encode")
    }

    #[test]
    fn hs256_mistyped_time_claims_are_rejected() {
        let tenant = TenantId::generate().to_string();
        let far = crate::unix_now() + 3600;
        let cases = [
            json!({ "sub": "u", "tid": tenant, "iss": ISS, "aud": AUD, "exp": far.to_string() }),
            json!({ "sub": "u", "tid": tenant, "iss": ISS, "aud": AUD, "exp": far, "nbf": far.to_string() }),
        ];
        let verifier = JwtVerifier::hs256("secret", ISS, AUD);
        for claims in cases {
            assert_eq!(
                verifier.verify(&hs256_token(claims.clone())),
                Err(AuthError::TokenRejected),
                "{claims}"
            );
        }
    }

    #[test]
    fn hs256_not_yet_valid_token_is_rejected() {
        let far = crate::unix_now() + 3600;
        let claims = json!({
            "sub": "u", "tid": TenantId::generate().to_string(), "iss": ISS, "aud": AUD,
            "exp": far + 3600, "nbf": far,
        });
        assert_eq!(
            JwtVerifier::hs256("secret", ISS, AUD).verify(&hs256_token(claims)),
            Err(AuthError::TokenRejected)
        );
    }

    #[test]
    fn garbage_is_rejected() {
        assert_eq!(
            JwtVerifier::hs256("secret", ISS, AUD).verify("not.a.jwt"),
            Err(AuthError::TokenRejected)
        );
    }

    // ── RS256 / JWKS (production) ───────────────────────────────────────

    #[test]
    fn rs256_valid_token_round_trips_and_carries_token_type() {
        let keypair = keypair(0);
        let signer = TokenSigner::rs256_from_pem(&keypair.private_pem, &keypair.kid, ISS, AUD)
            .expect("signer");
        let tenant = TenantId::generate();

        for token_type in [TokenType::Access, TokenType::Preauth, TokenType::Refresh] {
            let token = signer
                .mint(tenant, "user-1", token_type, 900, false)
                .expect("mint");
            let claims = rs256_verifier(&keypair.jwks_json)
                .verify(&token)
                .expect("verify");
            assert_eq!(claims.tenant, tenant);
            assert_eq!(claims.token_type, token_type);
        }
    }

    #[test]
    fn rs256_expired_and_wrong_audience_are_rejected() {
        let keypair = keypair(0);
        let signer = TokenSigner::rs256_from_pem(&keypair.private_pem, &keypair.kid, ISS, AUD)
            .expect("signer");
        let verifier = rs256_verifier(&keypair.jwks_json);

        // Well outside jsonwebtoken's default 60s leeway.
        let expired = signer
            .mint(TenantId::generate(), "u", TokenType::Access, -3600, false)
            .expect("mint");
        assert_eq!(verifier.verify(&expired), Err(AuthError::TokenRejected));

        let other_signer =
            TokenSigner::rs256_from_pem(&keypair.private_pem, &keypair.kid, ISS, "urn:other:aud")
                .expect("signer");
        let wrong_aud = other_signer
            .mint(TenantId::generate(), "u", TokenType::Access, 900, false)
            .expect("mint");
        assert_eq!(verifier.verify(&wrong_aud), Err(AuthError::TokenRejected));
    }

    #[test]
    fn rs256_unknown_kid_is_rejected() {
        let signer_key = keypair(0);
        let other_key = keypair(1);
        let signer =
            TokenSigner::rs256_from_pem(&signer_key.private_pem, &signer_key.kid, ISS, AUD)
                .expect("signer");
        let token = signer
            .mint(TenantId::generate(), "u", TokenType::Access, 900, false)
            .expect("mint");

        // Verifier only trusts `other_key`'s JWKS — signer's kid is absent.
        assert_eq!(
            rs256_verifier(&other_key.jwks_json).verify(&token),
            Err(AuthError::TokenRejected)
        );
    }

    #[test]
    fn rs256_key_rotation_both_keys_verify_during_overlap() {
        let old_key = keypair(0);
        let new_key = keypair(1);

        let mut merged: serde_json::Value =
            serde_json::from_str(&old_key.jwks_json).expect("parse");
        let new_entry = serde_json::from_str::<serde_json::Value>(&new_key.jwks_json)
            .expect("parse")["keys"][0]
            .clone();
        merged["keys"].as_array_mut().expect("keys").push(new_entry);
        let verifier = rs256_verifier(&merged.to_string());

        let old_signer = TokenSigner::rs256_from_pem(&old_key.private_pem, &old_key.kid, ISS, AUD)
            .expect("signer");
        let new_signer = TokenSigner::rs256_from_pem(&new_key.private_pem, &new_key.kid, ISS, AUD)
            .expect("signer");

        let tenant = TenantId::generate();
        let old_token = old_signer
            .mint(tenant, "u", TokenType::Access, 900, false)
            .expect("mint");
        let new_token = new_signer
            .mint(tenant, "u", TokenType::Access, 900, false)
            .expect("mint");

        assert_eq!(verifier.verify(&old_token).expect("verify").tenant, tenant);
        assert_eq!(verifier.verify(&new_token).expect("verify").tenant, tenant);

        let published_only_new: serde_json::Value =
            serde_json::from_str(&new_key.jwks_json).expect("parse");
        let post_rotation = rs256_verifier(&published_only_new.to_string());
        assert_eq!(
            post_rotation.verify(&old_token),
            Err(AuthError::TokenRejected)
        );
        assert!(post_rotation.verify(&new_token).is_ok());
    }

    /// Asymmetric-to-symmetric downgrade: an HS256 token keyed with the
    /// public RSA modulus must be refused by an RS256 verifier.
    #[test]
    fn alg_confusion_hs256_forgery_against_rs256_verifier_is_rejected() {
        let keypair = keypair(0);
        let verifier = rs256_verifier(&keypair.jwks_json);

        let jwks: serde_json::Value = serde_json::from_str(&keypair.jwks_json).expect("parse");
        let n_b64 = jwks["keys"][0]["n"].as_str().expect("n");

        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(keypair.kid.clone());
        let claims = json!({
            "sub": "attacker", "tid": TenantId::generate().to_string(),
            "iss": ISS, "aud": AUD, "exp": crate::unix_now() + 3600,
            "adm": true, "typ": "access",
        });
        let forged = encode(
            &header,
            &claims,
            &EncodingKey::from_secret(n_b64.as_bytes()),
        )
        .expect("encode");

        assert_eq!(verifier.verify(&forged), Err(AuthError::TokenRejected));
    }

    #[test]
    fn hs256_verifier_rejects_an_rs256_token_and_vice_versa() {
        let keypair = keypair(0);
        let rs_signer = TokenSigner::rs256_from_pem(&keypair.private_pem, &keypair.kid, ISS, AUD)
            .expect("signer");
        let rs_token = rs_signer
            .mint(TenantId::generate(), "u", TokenType::Access, 900, false)
            .expect("mint");
        assert_eq!(
            JwtVerifier::hs256("secret", ISS, AUD).verify(&rs_token),
            Err(AuthError::TokenRejected)
        );

        let hs_token =
            mint_token("secret", ISS, AUD, TenantId::generate(), "u", 900).expect("mint");
        assert_eq!(
            rs256_verifier(&keypair.jwks_json).verify(&hs_token),
            Err(AuthError::TokenRejected)
        );
    }

    #[test]
    fn tampered_rs256_signature_is_rejected() {
        let keypair = keypair(0);
        let signer = TokenSigner::rs256_from_pem(&keypair.private_pem, &keypair.kid, ISS, AUD)
            .expect("signer");
        let token = signer
            .mint(TenantId::generate(), "u", TokenType::Access, 900, false)
            .expect("mint");
        let mut parts: Vec<String> = token.split('.').map(str::to_owned).collect();
        // Swap in a different valid base64url char so the input stays UTF-8.
        let first = parts[2].chars().next().expect("non-empty signature");
        let replacement = if first == 'A' { 'B' } else { 'A' };
        parts[2].replace_range(0..1, &replacement.to_string());
        let tampered = parts.join(".");

        assert_eq!(
            rs256_verifier(&keypair.jwks_json).verify(&tampered),
            Err(AuthError::TokenRejected)
        );
    }

    mod props {
        use super::*;
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use proptest::prelude::*;

        fn verifiers() -> [JwtVerifier; 2] {
            [
                JwtVerifier::hs256("secret", ISS, AUD),
                rs256_verifier(&keypair(0).jwks_json),
            ]
        }

        fn b64(bytes: &[u8]) -> String {
            URL_SAFE_NO_PAD.encode(bytes)
        }

        proptest! {
            #[test]
            fn arbitrary_strings_never_verify(token in any::<String>()) {
                for verifier in verifiers() {
                    prop_assert_eq!(verifier.verify(&token), Err(AuthError::TokenRejected));
                }
            }

            #[test]
            fn jwt_shaped_strings_never_verify(
                token in "[A-Za-z0-9_=-]{0,96}\\.[A-Za-z0-9_=-]{0,192}\\.[A-Za-z0-9_=-]{0,96}",
            ) {
                for verifier in verifiers() {
                    prop_assert_eq!(verifier.verify(&token), Err(AuthError::TokenRejected));
                }
            }

            #[test]
            fn well_formed_claims_with_forged_signature_never_verify(
                alg in prop::sample::select(vec!["HS256", "RS256", "none", "ES256", "hs256", ""]),
                kid in prop_oneof![Just(keypair(0).kid.clone()), "[a-z0-9]{0,16}"],
                adm: bool,
                signature in prop::collection::vec(any::<u8>(), 0..300),
            ) {
                let header = json!({ "alg": alg, "typ": "JWT", "kid": kid });
                let claims = json!({
                    "sub": "attacker", "tid": TenantId::generate().to_string(),
                    "iss": ISS, "aud": AUD, "exp": crate::unix_now() + 3600,
                    "adm": adm, "typ": "access",
                });
                let token = format!(
                    "{}.{}.{}",
                    b64(header.to_string().as_bytes()),
                    b64(claims.to_string().as_bytes()),
                    b64(&signature),
                );
                for verifier in verifiers() {
                    prop_assert_eq!(verifier.verify(&token), Err(AuthError::TokenRejected));
                }
            }
        }
    }
}
