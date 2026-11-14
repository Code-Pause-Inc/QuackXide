//! Wire types for sealed research queries and results (ADR 0010 "Sealed
//! request" and "Sealed and signed result"). Byte fields are base64url
//! without padding, and unknown fields are refused. P85 and P55 give them
//! behaviour; nothing routes to them yet.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use crate::ApiError;
use crate::key_release::{KeyWire, SigningKeysWire};

/// `POST /api/v1/research/query`'s sealed body. `grant_id` is in the clear,
/// because the enclave needs `info` before it can open `envelope`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedQueryRequest {
    pub version: u32,
    pub key_id: String,
    pub grant_id: String,
    pub envelope: String,
}

/// What `envelope` opens to inside the enclave.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedQueryPlaintext {
    pub steward_tenant: String,
    pub connector: String,
    pub sql: String,
    pub request_nonce: String,
    pub recipient_key: KeyWire,
}

impl SealedQueryPlaintext {
    /// The request nonce's 32 bytes; anything else is a 400.
    pub fn request_nonce_bytes(&self) -> Result<[u8; 32], ApiError> {
        URL_SAFE_NO_PAD
            .decode(&self.request_nonce)
            .ok()
            .and_then(|raw| raw.try_into().ok())
            .ok_or(ApiError::BadRequest(
                "request nonce must be 32 bytes of base64url",
            ))
    }
}

/// A successful sealed research response: the sealed result and both
/// signatures over it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedQueryResponse {
    pub version: u32,
    pub key_id: String,
    pub sealed_result: String,
    pub signature: SigningKeysWire,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn recipient() -> Value {
        json!({ "suite": "HPK2", "public_key": "cGs" })
    }

    #[test]
    fn each_type_round_trips_as_adr_0010_shows_it() {
        let request = json!({ "version": 1, "key_id": "k", "grant_id": "g", "envelope": "e" });
        let plaintext = json!({
            "steward_tenant": "s", "connector": "upload_cohorts", "sql": "SELECT 1",
            "request_nonce": "bm9uY2U", "recipient_key": recipient(),
        });
        let response = json!({
            "version": 1, "key_id": "k", "sealed_result": "r",
            "signature": { "ed25519": "a", "ml_dsa_65": "b" },
        });
        let r: SealedQueryRequest = serde_json::from_value(request.clone()).expect("request");
        assert_eq!(serde_json::to_value(&r).unwrap(), request);
        let p: SealedQueryPlaintext = serde_json::from_value(plaintext.clone()).expect("plaintext");
        assert_eq!(serde_json::to_value(&p).unwrap(), plaintext);
        let s: SealedQueryResponse = serde_json::from_value(response.clone()).expect("response");
        assert_eq!(serde_json::to_value(&s).unwrap(), response);
    }

    #[test]
    fn each_type_refuses_an_unknown_field() {
        let with_extra = |mut v: Value| {
            v["extra"] = json!(1);
            v
        };
        let request = json!({ "version": 1, "key_id": "k", "grant_id": "g", "envelope": "e" });
        assert!(serde_json::from_value::<SealedQueryRequest>(with_extra(request)).is_err());
        let plaintext = json!({
            "steward_tenant": "s", "connector": "c", "sql": "q",
            "request_nonce": "n", "recipient_key": recipient(),
        });
        assert!(serde_json::from_value::<SealedQueryPlaintext>(with_extra(plaintext)).is_err());
        let response = json!({
            "version": 1, "key_id": "k", "sealed_result": "r",
            "signature": { "ed25519": "a", "ml_dsa_65": "b" },
        });
        assert!(serde_json::from_value::<SealedQueryResponse>(with_extra(response)).is_err());
    }

    #[test]
    fn the_request_nonce_must_be_32_bytes_of_base64url() {
        let plaintext = |nonce: &str| SealedQueryPlaintext {
            steward_tenant: "s".to_owned(),
            connector: "c".to_owned(),
            sql: "q".to_owned(),
            request_nonce: nonce.to_owned(),
            recipient_key: serde_json::from_value(recipient()).unwrap(),
        };
        let ok = URL_SAFE_NO_PAD.encode([7u8; 32]);
        assert!(matches!(
            plaintext(&ok).request_nonce_bytes(),
            Ok(nonce) if nonce == [7u8; 32]
        ));
        let short = URL_SAFE_NO_PAD.encode([7u8; 31]);
        let padded = base64::engine::general_purpose::URL_SAFE.encode([7u8; 32]);
        for bad in [short.as_str(), padded.as_str(), "not base64!"] {
            assert!(matches!(
                plaintext(bad).request_nonce_bytes(),
                Err(ApiError::BadRequest(_))
            ));
        }
    }
}
