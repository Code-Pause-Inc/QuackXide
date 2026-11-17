//! Wire types for sealed research queries and results (ADR 0010 "Sealed
//! request" and "Sealed and signed result"). Byte fields are base64url
//! without padding, and unknown fields are refused. P85 and P55 give them
//! behaviour; nothing routes to them yet.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

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

/// Longest sealed query plaintext the enclave parses (ADR 0010).
pub const MAX_SEALED_QUERY_PLAINTEXT_BYTES: usize = 64 * 1024;

/// What `envelope` opens to inside the enclave. The SQL text is plaintext
/// only here (ADR 0010): `Debug` redacts it, and it is wiped on drop, also
/// when a later field fails to parse.
#[derive(PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedQueryPlaintext {
    pub steward_tenant: String,
    pub connector: String,
    pub sql: Zeroizing<String>,
    pub request_nonce: String,
    pub recipient_key: KeyWire,
}

impl std::fmt::Debug for SealedQueryPlaintext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedQueryPlaintext")
            .field("steward_tenant", &self.steward_tenant)
            .field("connector", &self.connector)
            .field("sql", &"[redacted]")
            .field("recipient_key", &self.recipient_key)
            .finish_non_exhaustive()
    }
}

impl SealedQueryPlaintext {
    /// Parse the opened plaintext. Input over
    /// [`MAX_SEALED_QUERY_PLAINTEXT_BYTES`] is a 400 before any parsing.
    pub fn parse(bytes: &[u8]) -> Result<Self, ApiError> {
        if bytes.len() > MAX_SEALED_QUERY_PLAINTEXT_BYTES {
            return Err(ApiError::BadRequest("sealed query is too large"));
        }
        serde_json::from_slice(bytes).map_err(|_| ApiError::BadRequest("sealed query is malformed"))
    }

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
        assert_eq!(p.steward_tenant, "s");
        assert_eq!(p.connector, "upload_cohorts");
        assert_eq!(p.sql.as_str(), "SELECT 1");
        assert_eq!(p.request_nonce, "bm9uY2U");
        assert_eq!(
            p.recipient_key,
            serde_json::from_value(recipient()).unwrap()
        );
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
    fn debug_does_not_print_the_sql() {
        let plaintext = SealedQueryPlaintext {
            steward_tenant: "s".to_owned(),
            connector: "c".to_owned(),
            sql: Zeroizing::new("SELECT secret_column FROM t".to_owned()),
            request_nonce: "n".to_owned(),
            recipient_key: serde_json::from_value(recipient()).unwrap(),
        };
        let printed = format!("{plaintext:?}");
        assert!(!printed.contains("secret_column"), "{printed}");
    }

    /// A plaintext of exactly `len` bytes, padded through the SQL text.
    fn plaintext_of_len(len: usize) -> Vec<u8> {
        let with_sql = |sql: &str| {
            json!({
                "steward_tenant": "s", "connector": "c", "sql": sql,
                "request_nonce": "n", "recipient_key": recipient(),
            })
            .to_string()
        };
        let base = with_sql("").len();
        with_sql(&" ".repeat(len - base)).into_bytes()
    }

    #[test]
    fn a_plaintext_over_the_cap_is_refused_before_parsing() {
        let at_cap = plaintext_of_len(MAX_SEALED_QUERY_PLAINTEXT_BYTES);
        assert_eq!(at_cap.len(), MAX_SEALED_QUERY_PLAINTEXT_BYTES);
        assert!(SealedQueryPlaintext::parse(&at_cap).is_ok());

        // Valid JSON, one byte over: only the cap refuses it.
        let over = plaintext_of_len(MAX_SEALED_QUERY_PLAINTEXT_BYTES + 1);
        assert!(matches!(
            SealedQueryPlaintext::parse(&over),
            Err(ApiError::BadRequest(_))
        ));
    }

    #[test]
    fn a_malformed_plaintext_is_a_bad_request() {
        for bad in [&b"not json"[..], b"{}", b""] {
            assert!(matches!(
                SealedQueryPlaintext::parse(bad),
                Err(ApiError::BadRequest(_))
            ));
        }
    }

    #[test]
    fn the_request_nonce_must_be_32_bytes_of_base64url() {
        let plaintext = |nonce: &str| SealedQueryPlaintext {
            steward_tenant: "s".to_owned(),
            connector: "c".to_owned(),
            sql: Zeroizing::new("q".to_owned()),
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
