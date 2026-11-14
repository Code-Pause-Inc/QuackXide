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

/// A query result sealed to a researcher. P55 fixes the identifiers that
/// fill the fields.
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
