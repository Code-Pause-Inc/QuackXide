//! HPKE `info` strings: the binding context every envelope is sealed under.
//!
//! Each string is a kind with a version, then its fields, joined with `|`.
//! They are defined only here and pinned by the committed vectors
//! (`fixtures/envelope/`), so the enclave and the browser cannot drift.
//!
//! The backend passes typed identifiers that cannot contain `|`. Fields that
//! arrive from JavaScript go through [`check_field`] first, so two different
//! field lists can never produce the same string.

use std::fmt::Display;

use crate::CryptoError;

const SEPARATOR: char = '|';

/// A connector object written by an enclave pipeline.
pub fn connector_object(
    tenant: impl Display,
    connector: impl Display,
    object: impl Display,
) -> Vec<u8> {
    format!("tenant-envelope-v1|{tenant}|{connector}|{object}").into_bytes()
}

/// A connector snapshot manifest (ADR 0003).
pub fn snapshot_manifest(
    tenant: impl Display,
    connector: impl Display,
    version: impl Display,
) -> Vec<u8> {
    format!("tenant-snapshot-manifest-v1|{tenant}|{connector}|{version}").into_bytes()
}

/// An object of a dataset a steward uploads from the browser. P38 fixes the
/// identifiers that fill the fields.
pub fn steward_upload(
    tenant: impl Display,
    dataset: impl Display,
    object: impl Display,
) -> Vec<u8> {
    format!("steward-upload-v1|{tenant}|{dataset}|{object}").into_bytes()
}

/// A query result sealed to a researcher. P55 fixes the identifiers that
/// fill the fields.
pub fn research_result(researcher_tenant: impl Display, query: impl Display) -> Vec<u8> {
    format!("research-result-v1|{researcher_tenant}|{query}").into_bytes()
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
        assert_eq!(connector_object("t", "c", "o"), b"tenant-envelope-v1|t|c|o");
        assert_eq!(
            snapshot_manifest("t", "c", "v"),
            b"tenant-snapshot-manifest-v1|t|c|v"
        );
        assert_eq!(steward_upload("t", "d", "o"), b"steward-upload-v1|t|d|o");
        assert_eq!(research_result("t", "q"), b"research-result-v1|t|q");
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
