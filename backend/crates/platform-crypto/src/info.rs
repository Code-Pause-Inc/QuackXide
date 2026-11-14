//! HPKE `info` strings: the binding context every envelope is sealed under.
//!
//! Each string is a kind with a version, then its fields, joined with `|`.
//! The version follows the envelope suite (`-v1` for `HPK1`, `-v2` for
//! `HPK2`, ADR 0007), so every builder takes the suite it seals under.
//! They are defined only here and pinned by the committed vectors
//! (`fixtures/envelope/`), so the enclave and the browser cannot drift.
//!
//! The backend passes typed identifiers that cannot contain `|`. Fields that
//! arrive from JavaScript go through [`check_field`] first, so two different
//! field lists can never produce the same string.

use std::fmt::Display;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};

use crate::{CryptoError, EnvelopeSuite};

const SEPARATOR: char = '|';

fn version(suite: EnvelopeSuite) -> &'static str {
    match suite {
        EnvelopeSuite::Hpk1 => "v1",
        EnvelopeSuite::Hpk2 => "v2",
    }
}

/// A connector object written by an enclave pipeline.
pub fn connector_object(
    suite: EnvelopeSuite,
    tenant: impl Display,
    connector: impl Display,
    object: impl Display,
) -> Vec<u8> {
    format!(
        "tenant-envelope-{}|{tenant}|{connector}|{object}",
        version(suite)
    )
    .into_bytes()
}

/// A connector snapshot manifest (ADR 0003).
pub fn snapshot_manifest(
    suite: EnvelopeSuite,
    tenant: impl Display,
    connector: impl Display,
    version: impl Display,
) -> Vec<u8> {
    format!(
        "tenant-snapshot-manifest-{}|{tenant}|{connector}|{version}",
        self::version(suite)
    )
    .into_bytes()
}

/// An object of a dataset a steward uploads from the browser (ADR 0012):
/// `{tenant}` is the steward's tenant id, `{dataset}` the dataset's slug in
/// the upload namespace (`upload_…`), and `{object}` the object id the
/// browser chose before sealing. The snapshot's manifest uses
/// [`snapshot_manifest`] with the same slug.
pub fn steward_upload(
    suite: EnvelopeSuite,
    tenant: impl Display,
    dataset: impl Display,
    object: impl Display,
) -> Vec<u8> {
    format!(
        "steward-upload-{}|{tenant}|{dataset}|{object}",
        version(suite)
    )
    .into_bytes()
}

/// A query result sealed to a researcher: `{query}` is
/// [`research_query_binding`] of the request it answers (ADR 0010).
pub fn research_result(
    suite: EnvelopeSuite,
    researcher_tenant: impl Display,
    query: impl Display,
) -> Vec<u8> {
    format!(
        "research-result-{}|{researcher_tenant}|{query}",
        version(suite)
    )
    .into_bytes()
}

/// A research query sealed to the enclave's request key (ADR 0010 "Sealed
/// request"): `{tenant}` is the session's tenant, `{grant_id}` the grant the
/// query runs under, sent in the clear beside the frame.
pub fn research_query(
    suite: EnvelopeSuite,
    tenant: impl Display,
    grant_id: impl Display,
) -> Vec<u8> {
    format!("research-query-{}|{tenant}|{grant_id}", version(suite)).into_bytes()
}

const QUERY_BINDING_TAG: &[u8] = b"research-query-binding-v1";

/// The `{query}` field of [`research_result`]: base64url, without padding,
/// of SHA-256 over the tag and, each after its `u32` big-endian length, the
/// grant id, the request nonce, SHA-256 of the SQL text and the result
/// schema version (ADR 0010). An absent schema version is the empty field,
/// so a present one must not be empty.
pub fn research_query_binding(
    grant_id: &str,
    request_nonce: &[u8; 32],
    sql: &str,
    schema_version: Option<&str>,
) -> Result<String, CryptoError> {
    if schema_version == Some("") {
        return Err(CryptoError::InvalidInfoField);
    }
    let sql_digest = Sha256::digest(sql.as_bytes());
    let fields: [&[u8]; 4] = [
        grant_id.as_bytes(),
        request_nonce,
        &sql_digest,
        schema_version.unwrap_or("").as_bytes(),
    ];
    let mut hasher = Sha256::new();
    hasher.update(QUERY_BINDING_TAG);
    for field in fields {
        let len = u32::try_from(field.len()).map_err(|_| CryptoError::InvalidInfoField)?;
        hasher.update(len.to_be_bytes());
        hasher.update(field);
    }
    Ok(URL_SAFE_NO_PAD.encode(hasher.finalize()))
}

/// Refuse a field that is empty or contains the separator.
pub fn check_field(field: &str) -> Result<&str, CryptoError> {
    if field.is_empty() || field.contains(SEPARATOR) {
        return Err(CryptoError::InvalidInfoField);
    }
    Ok(field)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strings_have_the_pinned_layout() {
        use EnvelopeSuite::{Hpk1, Hpk2};
        assert_eq!(
            connector_object(Hpk1, "t", "c", "o"),
            b"tenant-envelope-v1|t|c|o"
        );
        assert_eq!(
            connector_object(Hpk2, "t", "c", "o"),
            b"tenant-envelope-v2|t|c|o"
        );
        assert_eq!(
            snapshot_manifest(Hpk2, "t", "c", "v"),
            b"tenant-snapshot-manifest-v2|t|c|v"
        );
        assert_eq!(
            steward_upload(Hpk2, "t", "d", "o"),
            b"steward-upload-v2|t|d|o"
        );
        assert_eq!(research_result(Hpk2, "t", "q"), b"research-result-v2|t|q");
        assert_eq!(research_query(Hpk1, "t", "g"), b"research-query-v1|t|g");
        assert_eq!(research_query(Hpk2, "t", "g"), b"research-query-v2|t|g");
    }

    const GRANT: &str = "11111111-2222-4333-8444-555555555555";
    const SQL: &str = "SELECT condition, COUNT(*) AS n FROM upload_cohorts GROUP BY condition";

    #[test]
    fn query_binding_is_pinned() {
        // ADR 0010's layout, computed independently of this code.
        let nonce = [0x66; 32];
        assert_eq!(
            research_query_binding(GRANT, &nonce, SQL, Some("1")).expect("binding"),
            "GrChwe4FHyeJ7D4VAW7eTPWLBvh7qmVyNwuTnbO_y9I"
        );
        assert_eq!(
            research_query_binding(GRANT, &nonce, SQL, None).expect("binding"),
            "RrAaM53KoifkboFugVTgwANY9D0l8ewR2MERgev1yOo"
        );
    }

    #[test]
    fn an_empty_schema_version_is_refused() {
        // It would bind the same as an absent one.
        assert!(matches!(
            research_query_binding(GRANT, &[0x66; 32], SQL, Some("")),
            Err(CryptoError::InvalidInfoField)
        ));
    }

    #[test]
    fn check_field_refuses_empty_and_separator() {
        assert_eq!(check_field("abc-123").expect("valid"), "abc-123");
        for bad in ["", "|", "a|b", "a|"] {
            assert!(matches!(
                check_field(bad),
                Err(CryptoError::InvalidInfoField)
            ));
        }
    }
}
