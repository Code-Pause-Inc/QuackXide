//! JWKS (RFC 7517) parsing into a `kid → DecodingKey` map: the entire trust
//! input for [`crate::JwtVerifier::rs256_from_jwks`].

use std::collections::HashMap;

use jsonwebtoken::DecodingKey;
use serde::Deserialize;

use crate::AuthError;

#[derive(Debug, Deserialize)]
struct Jwk {
    kid: String,
    kty: String,
    /// Base64url modulus / exponent (RFC 7518 §6.3.1). Absent for non-RSA
    /// key types, which are skipped so they cannot break RSA verification.
    n: Option<String>,
    e: Option<String>,
}

#[derive(Debug, Deserialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

/// Parse every usable RSA verification key, keyed by `kid`. Duplicate
/// `kid`s keep the last entry; the operator controls the document, so this
/// is a tiebreak, not a security boundary.
pub(crate) fn decoding_keys_from_jwks(
    jwks_json: &str,
) -> Result<HashMap<String, DecodingKey>, AuthError> {
    let set: JwkSet = serde_json::from_str(jwks_json).map_err(|_| AuthError::InvalidJwks)?;
    let mut out = HashMap::new();
    for jwk in set.keys {
        if jwk.kty != "RSA" {
            continue;
        }
        let (Some(n), Some(e)) = (jwk.n.as_deref(), jwk.e.as_deref()) else {
            continue;
        };
        let key = DecodingKey::from_rsa_components(n, e).map_err(|_| AuthError::InvalidJwks)?;
        out.insert(jwk.kid, key);
    }
    if out.is_empty() {
        return Err(AuthError::InvalidJwks);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_document_is_rejected() {
        assert!(matches!(
            decoding_keys_from_jwks(r#"{"keys":[]}"#),
            Err(AuthError::InvalidJwks)
        ));
    }

    #[test]
    fn garbage_json_is_rejected() {
        assert!(matches!(
            decoding_keys_from_jwks("not json"),
            Err(AuthError::InvalidJwks)
        ));
    }

    #[test]
    fn non_rsa_keys_are_skipped_not_errored() {
        let doc = r#"{"keys":[{"kid":"ec1","kty":"EC","crv":"P-256","x":"a","y":"b"}]}"#;
        assert!(matches!(
            decoding_keys_from_jwks(doc),
            Err(AuthError::InvalidJwks)
        ));
    }

    #[test]
    fn mixed_document_keeps_only_rsa_keys() {
        let keypair = crate::keygen::fixtures::keypair(0);
        let mut doc: serde_json::Value = serde_json::from_str(&keypair.jwks_json).expect("parse");
        doc["keys"].as_array_mut().expect("keys").push(
            serde_json::json!({"kid": "ec1", "kty": "EC", "crv": "P-256", "x": "a", "y": "b"}),
        );
        let keys = decoding_keys_from_jwks(&doc.to_string()).expect("parse");
        assert_eq!(keys.len(), 1);
        assert!(keys.contains_key(&keypair.kid));
    }
}
