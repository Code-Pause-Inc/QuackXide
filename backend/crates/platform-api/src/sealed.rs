//! Wire types for sealed research queries and results (ADR 0010 "Sealed
//! request" and "Sealed and signed result"). Byte fields are base64url
//! without padding, and unknown fields are refused. [`open_sealed`] opens a
//! sealed query inside the enclave; the sealed result is P55's.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use platform_core::{ConnectorSlug, TenantId};
use platform_crypto::{CryptoError, EnvelopeSuite, ResultSignature, SuitePolicy, info};
use platform_telemetry::{AuditKind, security_audit_event};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::ApiError;
use crate::key_release::{EnclaveIdentity, KeyWire, decode_b64url_32};

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
/// when a later field fails to parse. Best-effort: serde_json's scratch copy
/// of a string with JSON escapes is freed without wiping.
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
        decode_b64url_32(&self.request_nonce).ok_or(ApiError::BadRequest(
            "request nonce must be 32 bytes of base64url",
        ))
    }
}

/// A sealed query, opened and parsed inside the enclave.
pub(crate) struct OpenedQuery {
    pub steward: TenantId,
    pub connector: ConnectorSlug,
    pub sql: Zeroizing<String>,
    pub request_nonce: [u8; 32],
    pub grant_id: String,
    /// SHA-256 of the sealed frame, which the replay store records.
    pub envelope_digest: [u8; 32],
}

/// Open `request` as `researcher` sent it, in ADR 0010's order: the version,
/// then the key set (409 `reattest`), then the frame under
/// `research_query(suite, researcher, grant_id)`, then its plaintext. Every
/// failure after the key set is a 400. Each refusal is an `auth.decision`
/// denial naming its reason, never the request's content.
pub(crate) fn open_sealed(
    identity: &EnclaveIdentity,
    researcher: TenantId,
    request: &SealedQueryRequest,
) -> Result<OpenedQuery, ApiError> {
    open_checked(identity, researcher, request).map_err(|(reason, err)| {
        security_audit_event(
            AuditKind::AuthDecision,
            Some(researcher),
            "denied",
            &format!("sealed research query refused reason={reason}"),
        );
        err
    })
}

/// [`open_sealed`]'s checks; a refusal carries its audit reason.
fn open_checked(
    identity: &EnclaveIdentity,
    researcher: TenantId,
    request: &SealedQueryRequest,
) -> Result<OpenedQuery, (&'static str, ApiError)> {
    let does_not_open = |_| {
        (
            "does_not_open",
            ApiError::BadRequest("sealed query does not open"),
        )
    };
    let malformed = |err| ("malformed", err);
    if request.version != 1 {
        return Err((
            "unsupported_version",
            ApiError::BadRequest("unsupported sealed query version"),
        ));
    }
    if request.key_id != identity.key_id() {
        return Err(("unknown_key_id", ApiError::Reattest));
    }
    let frame = URL_SAFE_NO_PAD
        .decode(&request.envelope)
        .map_err(|_| does_not_open(()))?;
    let suite = EnvelopeSuite::of_envelope(&frame).map_err(|_| does_not_open(()))?;
    let info = info::research_query(suite, &researcher.to_string(), &request.grant_id)
        .map_err(|_| does_not_open(()))?;
    let opened = identity
        .open_request(&info, &frame)
        .map_err(|_| does_not_open(()))?;
    let plaintext = SealedQueryPlaintext::parse(opened.expose()).map_err(malformed)?;
    let request_nonce = plaintext.request_nonce_bytes().map_err(malformed)?;
    // Only checked here: P55 keeps it, matches it to the enrolled key and
    // seals the result to it. Either suite until the browser seals with HPK2
    // (P36; ADR 0010 "Recipient key", "No downgrade").
    plaintext
        .recipient_key
        .to_public_key(SuitePolicy::DEVELOPMENT)
        .map_err(|_| malformed(ApiError::BadRequest("malformed recipient key")))?;
    let steward = plaintext
        .steward_tenant
        .parse()
        .map_err(|_| malformed(ApiError::BadRequest("invalid steward tenant id")))?;
    let connector = ConnectorSlug::new(&plaintext.connector)
        .map_err(|_| malformed(ApiError::BadRequest("invalid connector slug")))?;
    Ok(OpenedQuery {
        steward,
        connector,
        sql: plaintext.sql,
        request_nonce,
        grant_id: request.grant_id.clone(),
        envelope_digest: Sha256::digest(&frame).into(),
    })
}

/// A successful sealed research response: the sealed result and both
/// signatures over it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedQueryResponse {
    pub version: u32,
    pub key_id: String,
    pub sealed_result: String,
    pub signature: SignatureWire,
}

/// Both signatures over a sealed result, base64url without padding (ADR
/// 0010). A type of its own, so a signature cannot be passed where keys are
/// expected (`SigningKeysWire`), nor keys where a signature is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureWire {
    pub ed25519: String,
    pub ml_dsa_65: String,
}

impl SignatureWire {
    pub fn from_signature(signature: &ResultSignature) -> Self {
        Self {
            ed25519: URL_SAFE_NO_PAD.encode(signature.ed25519),
            ml_dsa_65: URL_SAFE_NO_PAD.encode(&signature.ml_dsa_65),
        }
    }

    /// Malformed base64url or a wrong length is `SignatureInvalid`.
    pub fn to_signature(&self) -> Result<ResultSignature, CryptoError> {
        let decode = |b64: &str| {
            URL_SAFE_NO_PAD
                .decode(b64)
                .map_err(|_| CryptoError::SignatureInvalid)
        };
        ResultSignature::from_bytes(&decode(&self.ed25519)?, &decode(&self.ml_dsa_65)?)
    }
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
    fn a_signature_round_trips_and_a_malformed_one_is_refused() {
        let signature = platform_crypto::ResultSigningKey::generate().sign(b"info", b"frame");
        let wire = SignatureWire::from_signature(&signature);
        assert_eq!(wire.to_signature().expect("parses"), signature);
        let padded = SignatureWire {
            ed25519: base64::engine::general_purpose::URL_SAFE.encode(signature.ed25519),
            ..wire.clone()
        };
        let short = SignatureWire {
            ml_dsa_65: URL_SAFE_NO_PAD.encode(&signature.ml_dsa_65[1..]),
            ..wire
        };
        for bad in [padded, short] {
            assert!(matches!(
                bad.to_signature(),
                Err(CryptoError::SignatureInvalid)
            ));
        }
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

    mod open {
        use platform_core::TenantId;
        use platform_crypto::{EnvelopeSuite, TenantKeypair, hpke_seal_to_tenant, info};
        use sha2::{Digest, Sha256};

        use super::*;
        use crate::key_release::EnclaveIdentity;

        const GRANT: &str = "11111111-2222-4333-8444-555555555555";

        fn plaintext(steward: TenantId) -> Value {
            let recipient = TenantKeypair::generate(EnvelopeSuite::Hpk2).public_key();
            json!({
                "steward_tenant": steward.to_string(),
                "connector": "health",
                "sql": "SELECT condition, COUNT(*) AS n FROM health GROUP BY condition",
                "request_nonce": URL_SAFE_NO_PAD.encode([6u8; 32]),
                "recipient_key": KeyWire::from_public_key(&recipient),
            })
        }

        /// `body` sealed to `identity` as `researcher` would seal it under
        /// `grant`.
        fn seal(
            identity: &EnclaveIdentity,
            researcher: TenantId,
            grant: &str,
            body: &Value,
        ) -> SealedQueryRequest {
            let info = info::research_query(EnvelopeSuite::Hpk2, &researcher.to_string(), grant)
                .expect("info");
            let frame = hpke_seal_to_tenant(
                &identity.request_public_key(),
                &info,
                &serde_json::to_vec(body).expect("json"),
            )
            .expect("seal");
            SealedQueryRequest {
                version: 1,
                key_id: identity.key_id().to_owned(),
                grant_id: grant.to_owned(),
                envelope: URL_SAFE_NO_PAD.encode(frame),
            }
        }

        fn bad_request(result: Result<OpenedQuery, ApiError>) -> bool {
            matches!(result, Err(ApiError::BadRequest(_)))
        }

        #[test]
        fn a_sealed_query_opens() {
            let identity = EnclaveIdentity::generate();
            let (researcher, steward) = (TenantId::generate(), TenantId::generate());
            let request = seal(&identity, researcher, GRANT, &plaintext(steward));
            let opened = open_sealed(&identity, researcher, &request)
                .ok()
                .expect("opens");
            assert_eq!(opened.steward, steward);
            assert_eq!(opened.connector.as_str(), "health");
            assert!(opened.sql.starts_with("SELECT condition"));
            assert_eq!(opened.request_nonce, [6u8; 32]);
            assert_eq!(opened.grant_id, GRANT);
            let frame = URL_SAFE_NO_PAD.decode(&request.envelope).unwrap();
            assert_eq!(
                opened.envelope_digest,
                <[u8; 32]>::from(Sha256::digest(frame))
            );
        }

        #[test]
        fn an_unknown_key_id_asks_to_reattest() {
            let identity = EnclaveIdentity::generate();
            let researcher = TenantId::generate();
            let stale = SealedQueryRequest {
                key_id: "stale".to_owned(),
                envelope: "!!".to_owned(),
                ..seal(
                    &identity,
                    researcher,
                    GRANT,
                    &plaintext(TenantId::generate()),
                )
            };
            assert!(matches!(
                open_sealed(&identity, researcher, &stale),
                Err(ApiError::Reattest)
            ));
        }

        #[test]
        fn version_2_is_refused() {
            let identity = EnclaveIdentity::generate();
            let researcher = TenantId::generate();
            let request = SealedQueryRequest {
                version: 2,
                ..seal(
                    &identity,
                    researcher,
                    GRANT,
                    &plaintext(TenantId::generate()),
                )
            };
            assert!(bad_request(open_sealed(&identity, researcher, &request)));
        }

        #[test]
        fn another_enclaves_frame_does_not_open() {
            let (identity, other) = (EnclaveIdentity::generate(), EnclaveIdentity::generate());
            let researcher = TenantId::generate();
            let request = SealedQueryRequest {
                key_id: identity.key_id().to_owned(),
                ..seal(&other, researcher, GRANT, &plaintext(TenantId::generate()))
            };
            assert!(bad_request(open_sealed(&identity, researcher, &request)));
        }

        #[test]
        fn another_researchers_envelope_does_not_open() {
            let identity = EnclaveIdentity::generate();
            let request = seal(
                &identity,
                TenantId::generate(),
                GRANT,
                &plaintext(TenantId::generate()),
            );
            assert!(bad_request(open_sealed(
                &identity,
                TenantId::generate(),
                &request
            )));
        }

        #[test]
        fn another_grant_id_does_not_open() {
            let identity = EnclaveIdentity::generate();
            let researcher = TenantId::generate();
            let request = SealedQueryRequest {
                grant_id: "66666666-7777-4888-9999-000000000000".to_owned(),
                ..seal(
                    &identity,
                    researcher,
                    GRANT,
                    &plaintext(TenantId::generate()),
                )
            };
            assert!(bad_request(open_sealed(&identity, researcher, &request)));
        }

        #[test]
        fn nonce_must_be_32_bytes() {
            let identity = EnclaveIdentity::generate();
            let researcher = TenantId::generate();
            for len in [31, 33] {
                let mut body = plaintext(TenantId::generate());
                body["request_nonce"] = json!(URL_SAFE_NO_PAD.encode(vec![6u8; len]));
                let request = seal(&identity, researcher, GRANT, &body);
                assert!(
                    bad_request(open_sealed(&identity, researcher, &request)),
                    "{len}"
                );
            }
        }

        #[test]
        fn malformed_fields_are_refused() {
            let identity = EnclaveIdentity::generate();
            let researcher = TenantId::generate();
            let hpk1 = TenantKeypair::generate(EnvelopeSuite::Hpk1).public_key();
            let mislabelled = json!({
                "suite": "HPK2",
                "public_key": URL_SAFE_NO_PAD.encode(hpk1.to_raw()),
            });
            let cases = [
                (
                    "recipient_key",
                    json!({ "suite": "HPK3", "public_key": "cGs" }),
                ),
                (
                    "recipient_key",
                    json!({ "suite": "HPK2", "public_key": "cGs" }),
                ),
                ("recipient_key", mislabelled),
                ("steward_tenant", json!("not-a-tenant")),
                ("connector", json!("Not A Slug")),
                ("extra", json!(1)),
            ];
            for (field, value) in cases {
                let mut body = plaintext(TenantId::generate());
                body[field] = value;
                let request = seal(&identity, researcher, GRANT, &body);
                assert!(
                    bad_request(open_sealed(&identity, researcher, &request)),
                    "{field}"
                );
            }
        }
    }
}
