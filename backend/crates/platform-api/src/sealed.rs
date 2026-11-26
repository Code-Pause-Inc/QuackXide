//! Sealed research queries and results (ADR 0010 "Sealed request",
//! "Recipient key" and "Sealed and signed result"): the wire types, opening a
//! sealed query inside the enclave ([`open_sealed`]), the recipient-key check
//! and the result's seal and signature. Byte fields are base64url without
//! padding, and unknown fields are refused.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use platform_core::{ConnectorSlug, TenantId};
use platform_crypto::{
    CryptoError, EnvelopeSuite, ResultSignature, SuitePolicy, TenantPublicKey, hpke_seal_to_tenant,
    info,
};
use platform_storage::VaultStore;
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
#[derive(PartialEq, Eq, Serialize, Deserialize)]
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

/// `plaintext` sealed to the enclave's `request_key` as `researcher` sends
/// it under `grant_id`: the client's side of [`open_sealed`]. The serialized
/// plaintext, SQL included, is wiped once sealed.
pub fn seal_query(
    request_key: &TenantPublicKey,
    key_id: &str,
    researcher: TenantId,
    grant_id: &str,
    plaintext: &SealedQueryPlaintext,
) -> Result<SealedQueryRequest, CryptoError> {
    let info = info::research_query(request_key.suite(), &researcher.to_string(), grant_id)?;
    let bytes =
        Zeroizing::new(serde_json::to_vec(plaintext).map_err(|_| CryptoError::InvalidEnvelope)?);
    let frame = hpke_seal_to_tenant(request_key, &info, &bytes)?;
    Ok(SealedQueryRequest {
        version: 1,
        key_id: key_id.to_owned(),
        grant_id: grant_id.to_owned(),
        envelope: URL_SAFE_NO_PAD.encode(frame),
    })
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

/// Version of [`SealedQueryResponse`] this enclave produces.
pub const SEALED_RESPONSE_VERSION: u32 = 1;

const RECIPIENT_FINGERPRINT_TAG: &[u8] = b"recipient-key-v1";

/// A recipient key's fingerprint for audit records (ADR 0010 "Recipient
/// key"): base64url of `SHA-256("recipient-key-v1" ‖ suite ‖ public key)`,
/// where the suite is its 4-byte frame magic and the key its raw bytes.
pub fn recipient_key_fingerprint(key: &TenantPublicKey) -> String {
    let mut hasher = Sha256::new();
    hasher.update(RECIPIENT_FINGERPRINT_TAG);
    hasher.update(key.suite().magic());
    hasher.update(key.to_raw());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

/// Refuses sealed research queries with 503 unless `dev_build`: until
/// create-once enrollment (P33) lands, the enrolled key a result is sealed
/// to can be overwritten through the API, so only `dev` builds, which run
/// on the simulated TEE, accept them (ADR 0010 "Recipient key"). Only
/// [`verify_recipient`] calls it, so no recipient is checked without it.
fn sealed_research_gate(dev_build: bool, researcher: TenantId) -> Result<(), ApiError> {
    if dev_build {
        return Ok(());
    }
    security_audit_event(
        AuditKind::AuthDecision,
        Some(researcher),
        "denied",
        "sealed research query refused: create-once enrollment (P33) is not built",
    );
    Err(ApiError::ResearchUnavailable)
}

/// A recipient key equal, by suite and bytes, to the key enrolled for its
/// researcher. Only [`verify_recipient`] builds one, after the release-build
/// gate and with the enrolled key it read itself, so a result can be sealed
/// only to a checked key.
#[derive(Clone)]
pub struct VerifiedRecipient {
    researcher: TenantId,
    key: TenantPublicKey,
    fingerprint: String,
}

impl VerifiedRecipient {
    pub fn researcher(&self) -> TenantId {
        self.researcher
    }

    pub fn key(&self) -> &TenantPublicKey {
        &self.key
    }

    /// [`recipient_key_fingerprint`] of the key.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
}

impl std::fmt::Debug for VerifiedRecipient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedRecipient")
            .field("researcher", &self.researcher)
            .field("fingerprint", &self.fingerprint)
            .finish_non_exhaustive()
    }
}

/// Check a sealed request's `recipient_key` against the key enrolled for
/// `researcher` in `vault` (ADR 0010 "Recipient key"). The release-build
/// gate, the enrollment read and the compare run here together, so no
/// caller can supply the enrolled key or skip the gate. `dev_build` is
/// `cfg!(feature = "dev")` outside tests; it is a parameter so the release
/// branch is tested.
///
/// A release build is a 503 before anything is read. An enrollment record
/// that fails [`crate::verify_enrollment_record`] is a 500. Otherwise see
/// [`check_recipient`]. Every refusal is audited once.
pub async fn verify_recipient(
    dev_build: bool,
    vault: &dyn VaultStore,
    researcher: TenantId,
    presented: &TenantPublicKey,
) -> Result<VerifiedRecipient, ApiError> {
    sealed_research_gate(dev_build, researcher)?;
    let enrolled = crate::enrolled_key(vault, researcher)
        .await
        .inspect_err(|_| {
            security_audit_event(
                AuditKind::AuthDecision,
                Some(researcher),
                "failed",
                "sealed research query refused: enrollment record unreadable",
            );
        })?;
    check_recipient(researcher, presented, enrolled.as_ref())
}

/// Compare `key` with `enrolled`, the key enrolled for `researcher`. No
/// enrolled key, or one that differs by suite or bytes, is a 403. Every
/// refusal is audited with the presented key's fingerprint, never the key.
/// Private to this module: only [`verify_recipient`] calls it, with the key
/// it read.
///
/// `key` was parsed by [`open_sealed`] under the development policy: it must
/// equal the enrolled key, which enrollment already checked under the
/// deployment's policy, so a production deployment accepts only the suite
/// it enrolls.
fn check_recipient(
    researcher: TenantId,
    key: &TenantPublicKey,
    enrolled: Option<&TenantPublicKey>,
) -> Result<VerifiedRecipient, ApiError> {
    let fingerprint = recipient_key_fingerprint(key);
    let Some(enrolled) = enrolled else {
        security_audit_event(
            AuditKind::AuthDecision,
            Some(researcher),
            "denied",
            &format!(
                "sealed research query refused: no enrolled key \
                 recipient_fingerprint={fingerprint}"
            ),
        );
        return Err(ApiError::Forbidden);
    };
    if key.suite() != enrolled.suite() || key.to_raw() != enrolled.to_raw() {
        security_audit_event(
            AuditKind::AuthDecision,
            Some(researcher),
            "denied",
            &format!(
                "sealed research query refused: recipient key is not the enrolled key \
                 recipient_fingerprint={fingerprint} enrolled_fingerprint={}",
                recipient_key_fingerprint(enrolled)
            ),
        );
        return Err(ApiError::Forbidden);
    }
    Ok(VerifiedRecipient {
        researcher,
        key: key.clone(),
        fingerprint,
    })
}

/// What a sealed result answers: the fields of the request it is bound to
/// through `research_query_binding` (ADR 0010 "Sealed and signed result").
#[derive(Clone, Copy)]
pub struct ResultBinding<'a> {
    pub grant_id: &'a str,
    pub request_nonce: &'a [u8; 32],
    pub sql: &'a str,
    /// The result schema version (P54); `None` until the result contract
    /// names one.
    pub schema_version: Option<&'a str>,
}

impl std::fmt::Debug for ResultBinding<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResultBinding")
            .field("grant_id", &self.grant_id)
            .field("sql", &"[redacted]")
            .field("schema_version", &self.schema_version)
            .finish_non_exhaustive()
    }
}

/// The HPKE `info` a result for `researcher` is sealed and signed under:
/// `research_result(suite, researcher, research_query_binding(…))`, in the
/// recipient key's suite. The browser recomputes it from its own request.
pub fn result_info(
    suite: EnvelopeSuite,
    researcher: TenantId,
    binding: &ResultBinding<'_>,
) -> Result<Vec<u8>, platform_crypto::CryptoError> {
    let query = platform_crypto::info::research_query_binding(
        binding.grant_id,
        binding.request_nonce,
        binding.sql,
        binding.schema_version,
    )?;
    Ok(platform_crypto::info::research_result(
        suite, researcher, query,
    ))
}

/// Seal `payload` (the whole serialized result, counts and
/// `budget_remaining` included) to `recipient` under [`result_info`], then
/// sign the frame with the key set's result-signing key. A failure here is
/// the enclave's own fault (502); the caller returns it unsealed, with no
/// result data.
pub(crate) fn seal_and_sign(
    identity: &EnclaveIdentity,
    recipient: &VerifiedRecipient,
    binding: &ResultBinding<'_>,
    payload: &[u8],
) -> Result<SealedQueryResponse, ApiError> {
    let info = result_info(recipient.key.suite(), recipient.researcher, binding)
        .map_err(|_| ApiError::Backend)?;
    let frame =
        hpke_seal_to_tenant(&recipient.key, &info, payload).map_err(|_| ApiError::Backend)?;
    let signature = identity.sign_result(&info, &frame);
    Ok(SealedQueryResponse {
        version: SEALED_RESPONSE_VERSION,
        key_id: identity.key_id().to_owned(),
        sealed_result: URL_SAFE_NO_PAD.encode(&frame),
        signature: SignatureWire::from_signature(&signature),
    })
}

/// Serialize `value` as JSON into a buffer wiped on drop, leaving no unwiped
/// copy behind. `serde_json::to_vec` grows its buffer as it writes, and each
/// outgrown allocation is freed without being wiped; this measures the
/// output first, then writes it into a buffer of exactly that size, which
/// never reallocates (a longer second pass fails instead of growing it).
/// For results and other secret JSON.
pub(crate) fn to_json_zeroizing<T: Serialize + ?Sized>(
    value: &T,
) -> Result<Zeroizing<Vec<u8>>, serde_json::Error> {
    struct Count(usize);
    impl std::io::Write for Count {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 += bytes.len();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count(0);
    serde_json::to_writer(&mut count, value)?;
    let mut buf = Zeroizing::new(vec![0u8; count.0]);
    let mut rest: &mut [u8] = &mut buf;
    serde_json::to_writer(&mut rest, value)?;
    if !rest.is_empty() {
        return Err(serde::ser::Error::custom("serialized length changed"));
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use platform_crypto::{CryptoError, ResultVerifyingKeys, TenantKeypair};
    use platform_storage::{ObjectStoreVault, TenantPaths};
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

        /// What `seal_query` seals, the enclave opens: one sealing path for
        /// `enclave-check` and the tests.
        #[test]
        fn seal_query_round_trips() {
            let identity = EnclaveIdentity::generate();
            let (researcher, steward) = (TenantId::generate(), TenantId::generate());
            let recipient = TenantKeypair::generate(EnvelopeSuite::Hpk2).public_key();
            let plaintext = SealedQueryPlaintext {
                steward_tenant: steward.to_string(),
                connector: "health".to_owned(),
                sql: Zeroizing::new("SELECT 1".to_owned()),
                request_nonce: URL_SAFE_NO_PAD.encode([6u8; 32]),
                recipient_key: KeyWire::from_public_key(&recipient),
            };
            let request = seal_query(
                &identity.request_public_key(),
                identity.key_id(),
                researcher,
                GRANT,
                &plaintext,
            )
            .expect("seals");
            assert_eq!((request.version, request.grant_id.as_str()), (1, GRANT));
            let opened = open_sealed(&identity, researcher, &request)
                .ok()
                .expect("opens");
            assert_eq!(opened.steward, steward);
            assert_eq!(opened.sql.as_str(), "SELECT 1");
            assert_eq!(opened.request_nonce, [6u8; 32]);
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

    // ── Recipient key and sealed result (ADR 0010) ──

    #[test]
    fn the_recipient_fingerprint_layout_is_pinned() {
        // SHA-256("recipient-key-v1" ‖ "HPK1" ‖ [7; 32]), base64url,
        // computed independently of this code.
        let key = TenantPublicKey::from_raw(&[7u8; 32], SuitePolicy::DEVELOPMENT).expect("key");
        assert_eq!(
            recipient_key_fingerprint(&key),
            "zUsitw3vqqA36QOhEF-0LIgPekLiEmtU4jopNucDBBo"
        );
    }

    /// An in-memory vault with `key` enrolled for `researcher`, written as
    /// enrollment writes it.
    async fn enrolled_vault(researcher: TenantId, key: &TenantPublicKey) -> ObjectStoreVault {
        let vault = ObjectStoreVault::new_in_memory();
        let record = crate::EnrollmentRecord {
            hpke_public_key_b64: crate::B64.encode(key.to_raw()),
            key_id: key.fingerprint(),
            suite: key.suite().name().to_owned(),
            created_at_unix: 1,
        };
        vault
            .put(
                &TenantPaths::tenant_enrollment(researcher),
                Bytes::from(serde_json::to_vec(&record).expect("json")),
            )
            .await
            .expect("put");
        vault
    }

    #[tokio::test]
    async fn a_release_build_refuses_even_the_enrolled_key_with_503() {
        let researcher = TenantId::generate();
        let enrolled = TenantKeypair::generate(EnvelopeSuite::Hpk2).public_key();
        let vault = enrolled_vault(researcher, &enrolled).await;
        assert!(matches!(
            verify_recipient(false, &vault, researcher, &enrolled).await,
            Err(ApiError::ResearchUnavailable)
        ));
        // The same request in a `dev` build is accepted, so the refusal
        // above is the gate.
        let verified = verify_recipient(true, &vault, researcher, &enrolled)
            .await
            .unwrap_or_else(|_| panic!("enrolled"));
        assert_eq!(verified.key().to_raw(), enrolled.to_raw());
    }

    #[tokio::test]
    async fn verify_recipient_reads_the_enrolled_key_itself() {
        let researcher = TenantId::generate();
        let enrolled = TenantKeypair::generate(EnvelopeSuite::Hpk2).public_key();
        let other = TenantKeypair::generate(EnvelopeSuite::Hpk2).public_key();
        let vault = enrolled_vault(researcher, &enrolled).await;
        assert!(matches!(
            verify_recipient(true, &vault, researcher, &other).await,
            Err(ApiError::Forbidden)
        ));
        // Not enrolled, and an enrollment record that does not parse.
        let empty = ObjectStoreVault::new_in_memory();
        assert!(matches!(
            verify_recipient(true, &empty, researcher, &enrolled).await,
            Err(ApiError::Forbidden)
        ));
        vault
            .put(
                &TenantPaths::tenant_enrollment(researcher),
                Bytes::from_static(b"not a record"),
            )
            .await
            .expect("put");
        assert!(matches!(
            verify_recipient(true, &vault, researcher, &enrolled).await,
            Err(ApiError::Internal)
        ));
    }

    #[test]
    fn json_is_written_into_an_exactly_sized_buffer() {
        // Forty rows outgrow `to_vec`'s buffer several times.
        let rows: Vec<Value> = (0..40)
            .map(|i| json!({ "condition": format!("condition-{i}"), "n": i }))
            .collect();
        for value in [
            json!({ "rows": rows, "row_count": 40 }),
            json!(null),
            json!(""),
        ] {
            let buf = to_json_zeroizing(&value).expect("json");
            assert_eq!(buf.as_slice(), serde_json::to_vec(&value).expect("json"));
            assert_eq!(buf.capacity(), buf.len(), "never grown");
        }
    }

    #[test]
    fn only_the_enrolled_key_is_a_recipient() {
        let researcher = TenantId::generate();
        for suite in [EnvelopeSuite::Hpk1, EnvelopeSuite::Hpk2] {
            let enrolled = TenantKeypair::generate(suite).public_key();
            let verified = check_recipient(researcher, &enrolled, Some(&enrolled))
                .unwrap_or_else(|_| panic!("enrolled"));
            assert_eq!(verified.researcher(), researcher);
            assert_eq!(verified.key().to_raw(), enrolled.to_raw());
            assert_eq!(verified.fingerprint(), recipient_key_fingerprint(&enrolled));
        }

        let enrolled = TenantKeypair::generate(EnvelopeSuite::Hpk2).public_key();
        // Another key of the same suite, a key of the other suite, and no
        // enrolled key at all are each a 403.
        for other in [
            TenantKeypair::generate(EnvelopeSuite::Hpk2).public_key(),
            TenantKeypair::generate(EnvelopeSuite::Hpk1).public_key(),
        ] {
            assert!(matches!(
                check_recipient(researcher, &other, Some(&enrolled)),
                Err(ApiError::Forbidden)
            ));
        }
        assert!(matches!(
            check_recipient(researcher, &enrolled, None),
            Err(ApiError::Forbidden)
        ));
    }

    const SQL: &str = "SELECT condition, COUNT(*) AS n FROM health GROUP BY condition";

    fn binding<'a>(nonce: &'a [u8; 32], sql: &'a str) -> ResultBinding<'a> {
        ResultBinding {
            grant_id: "grant-1",
            request_nonce: nonce,
            sql,
            schema_version: None,
        }
    }

    fn payload() -> Value {
        json!({
            "rows": [{ "condition": "flu", "n": 6 }],
            "row_count": 1, "suppressed_rows": 1, "budget_remaining": 99,
        })
    }

    /// What the browser does with a response (ADR 0010): check both
    /// signatures against the key set it verified, recompute `info` from its
    /// own request, and only then open the frame.
    fn accept(
        response: &SealedQueryResponse,
        verified: &ResultVerifyingKeys,
        recipient: &TenantKeypair,
        researcher: TenantId,
        binding: &ResultBinding<'_>,
    ) -> Result<Value, CryptoError> {
        let frame = URL_SAFE_NO_PAD
            .decode(&response.sealed_result)
            .map_err(|_| CryptoError::InvalidEnvelope)?;
        let info = result_info(recipient.suite(), researcher, binding)?;
        verified.verify(&info, &frame, &response.signature.to_signature()?)?;
        let opened = recipient.open_envelope(&info, &frame)?;
        serde_json::from_slice(opened.expose()).map_err(|_| CryptoError::InvalidEnvelope)
    }

    struct Sealed {
        identity: EnclaveIdentity,
        recipient: TenantKeypair,
        researcher: TenantId,
        nonce: [u8; 32],
        response: SealedQueryResponse,
    }

    fn sealed(suite: EnvelopeSuite) -> Sealed {
        let identity = EnclaveIdentity::generate();
        let recipient = TenantKeypair::generate(suite);
        let researcher = TenantId::generate();
        let public = recipient.public_key();
        let verified = check_recipient(researcher, &public, Some(&public))
            .unwrap_or_else(|_| panic!("enrolled"));
        let nonce = [9u8; 32];
        let body = serde_json::to_vec(&payload()).expect("json");
        let response = seal_and_sign(&identity, &verified, &binding(&nonce, SQL), &body)
            .unwrap_or_else(|_| panic!("seal"));
        Sealed {
            identity,
            recipient,
            researcher,
            nonce,
            response,
        }
    }

    #[test]
    fn a_sealed_result_opens_only_with_the_intended_key() {
        for suite in [EnvelopeSuite::Hpk1, EnvelopeSuite::Hpk2] {
            let s = sealed(suite);
            assert_eq!(s.response.version, SEALED_RESPONSE_VERSION);
            assert_eq!(s.response.key_id, s.identity.key_id());
            let frame = URL_SAFE_NO_PAD
                .decode(&s.response.sealed_result)
                .expect("b64");
            assert_eq!(
                &frame[..4],
                &suite.magic(),
                "sealed in the recipient's suite"
            );
            // Nothing of the result is readable on the wire. Quoted, so a
            // match cannot come from inside a base64url value.
            let wire = serde_json::to_string(&s.response).expect("json");
            for value in [r#""flu""#, r#""suppressed_rows""#, r#""budget_remaining""#] {
                assert!(!wire.contains(value), "{value} in {wire}");
            }

            let keys = s.identity.verifying_keys();
            let opened = accept(
                &s.response,
                &keys,
                &s.recipient,
                s.researcher,
                &binding(&s.nonce, SQL),
            )
            .expect("accepted");
            assert_eq!(opened, payload());

            // Another recipient key of the same suite cannot open it, even
            // with the signature checked under the right `info`.
            let other = TenantKeypair::generate(suite);
            assert!(
                accept(
                    &s.response,
                    &keys,
                    &other,
                    s.researcher,
                    &binding(&s.nonce, SQL)
                )
                .is_err()
            );
        }
    }

    #[test]
    fn a_flipped_byte_anywhere_in_the_frame_is_refused() {
        let s = sealed(EnvelopeSuite::Hpk2);
        let keys = s.identity.verifying_keys();
        let frame = URL_SAFE_NO_PAD
            .decode(&s.response.sealed_result)
            .expect("b64");
        for at in [0, 4, frame.len() / 2, frame.len() - 1] {
            let mut flipped = frame.clone();
            flipped[at] ^= 0x01;
            let response = SealedQueryResponse {
                sealed_result: URL_SAFE_NO_PAD.encode(&flipped),
                ..s.response.clone()
            };
            assert!(
                matches!(
                    accept(
                        &response,
                        &keys,
                        &s.recipient,
                        s.researcher,
                        &binding(&s.nonce, SQL)
                    ),
                    Err(CryptoError::SignatureInvalid)
                ),
                "byte {at}"
            );
        }
    }

    #[test]
    fn a_result_signed_by_any_other_key_is_refused() {
        let s = sealed(EnvelopeSuite::Hpk2);
        let frame = URL_SAFE_NO_PAD
            .decode(&s.response.sealed_result)
            .expect("b64");
        let info =
            result_info(EnvelopeSuite::Hpk2, s.researcher, &binding(&s.nonce, SQL)).expect("info");
        // An operator seals its own result to the researcher and signs it
        // with a key set it holds: the browser checks against the key set
        // it verified, so the signature fails.
        let forger = EnclaveIdentity::generate();
        let forged = SealedQueryResponse {
            signature: SignatureWire::from_signature(&forger.sign_result(&info, &frame)),
            ..s.response.clone()
        };
        let verified = s.identity.verifying_keys();
        assert!(matches!(
            accept(
                &forged,
                &verified,
                &s.recipient,
                s.researcher,
                &binding(&s.nonce, SQL)
            ),
            Err(CryptoError::SignatureInvalid)
        ));
        // The forger's own keys do verify it, so the refusal above is the
        // key check and not a malformed signature.
        assert!(
            accept(
                &forged,
                &forger.verifying_keys(),
                &s.recipient,
                s.researcher,
                &binding(&s.nonce, SQL)
            )
            .is_ok()
        );

        // A signature that does not decode is refused the same way.
        let garbled = SealedQueryResponse {
            signature: SignatureWire {
                ed25519: "AAAA".to_owned(),
                ..s.response.signature.clone()
            },
            ..s.response.clone()
        };
        assert!(matches!(
            accept(
                &garbled,
                &verified,
                &s.recipient,
                s.researcher,
                &binding(&s.nonce, SQL)
            ),
            Err(CryptoError::SignatureInvalid)
        ));
    }

    #[test]
    fn a_result_replayed_against_another_request_is_refused() {
        let s = sealed(EnvelopeSuite::Hpk2);
        let keys = s.identity.verifying_keys();
        let other_nonce = [10u8; 32];
        let other_sql = "SELECT COUNT(*) AS n FROM health";
        let requests = [
            // Another request nonce: the replay ADR 0010 binds against.
            binding(&other_nonce, SQL),
            // Another SQL text, grant or schema version.
            binding(&s.nonce, other_sql),
            ResultBinding {
                grant_id: "grant-2",
                ..binding(&s.nonce, SQL)
            },
            ResultBinding {
                schema_version: Some("1"),
                ..binding(&s.nonce, SQL)
            },
        ];
        for request in requests {
            assert!(
                matches!(
                    accept(&s.response, &keys, &s.recipient, s.researcher, &request),
                    Err(CryptoError::SignatureInvalid)
                ),
                "{request:?}"
            );
        }
        // Another researcher's session recomputes another `info` too.
        assert!(matches!(
            accept(
                &s.response,
                &keys,
                &s.recipient,
                TenantId::generate(),
                &binding(&s.nonce, SQL)
            ),
            Err(CryptoError::SignatureInvalid)
        ));
    }

    #[test]
    fn the_result_info_carries_the_role_label_and_researcher() {
        let researcher = TenantId::generate();
        let nonce = [9u8; 32];
        let b = binding(&nonce, SQL);
        let query = platform_crypto::info::research_query_binding("grant-1", &nonce, SQL, None)
            .expect("binding");
        for (suite, kind) in [
            (EnvelopeSuite::Hpk1, "research-result-v1"),
            (EnvelopeSuite::Hpk2, "research-result-v2"),
        ] {
            assert_eq!(
                result_info(suite, researcher, &b).expect("info"),
                format!("{kind}|{researcher}|{query}").into_bytes()
            );
        }
        // An empty schema version is refused, never read as absent.
        let empty = ResultBinding {
            schema_version: Some(""),
            ..b
        };
        assert!(result_info(EnvelopeSuite::Hpk2, researcher, &empty).is_err());
    }

    #[test]
    fn debug_does_not_print_the_bound_sql_or_the_recipient_key() {
        let nonce = [9u8; 32];
        let printed = format!("{:?}", binding(&nonce, "SELECT secret_column FROM t"));
        assert!(!printed.contains("secret_column"), "{printed}");
        let s = sealed(EnvelopeSuite::Hpk2);
        let public = s.recipient.public_key();
        let verified = check_recipient(s.researcher, &public, Some(&public))
            .unwrap_or_else(|_| panic!("enrolled"));
        let printed = format!("{verified:?}");
        assert!(
            !printed.contains(&URL_SAFE_NO_PAD.encode(public.to_raw())),
            "{printed}"
        );
    }
}
