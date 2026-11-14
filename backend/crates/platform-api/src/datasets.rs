//! Steward datasets (ADR 0012): `PUT /api/v1/datasets/{dataset}` uploads
//! one, and `GET /api/v1/datasets` lists the caller's.
//!
//! The steward's browser seals a Parquet file and the snapshot manifest
//! that lists it to the steward's key and sends both in one body
//! (`platform_connectors::upload`). The upload route cannot open either. It
//! checks the dataset id, the size, the framing and the declared header,
//! then stores the upload as the dataset's new snapshot, for the tenant in
//! the token only. The first upload creates the dataset; a re-upload
//! replaces it (ADR 0003).
//!
//! The listing describes each dataset the tenant holds, connectors' and
//! uploads' alike, from storage paths, sizes and the current snapshot's
//! plaintext record: what the operator can already see. It opens nothing.
//!
//! Both routes need only the vault and the configuration, not the query
//! service, so they work where research queries are not configured. Every
//! upload refusal is audited as `data.access` `denied`, a storage failure
//! as `failed`; the stored object and the commit are audited by the writer.
//! A listing is audited `ok`, or `denied` over its cap.

use std::time::SystemTime;

use axum::Json;
use axum::extract::rejection::BytesRejection;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use bytes::Bytes;
use futures::{StreamExt, TryStreamExt};
use platform_config::PlatformConfig;
use platform_connectors::snapshot::{self, HeldDataset};
use platform_connectors::upload::{self, UploadCommitError, UploadError};
use platform_core::{ConnectorSlug, DatasetKind, ObjectId, SnapshotVersion, TenantId};
use platform_crypto::EnvelopeSuite;
use platform_storage::StorageError;
use platform_telemetry::{AuditKind, security_audit_event};
use serde::Serialize;
use serde_json::{Value, json};

use crate::{ApiError, AppState, AuthedTenant, LIST_READ_CONCURRENCY, MAX_LISTED_OBJECTS};

/// The request body limit for uploads: the dataset size limit
/// (`DATASET_MAX_MIB`) plus the most a body holds besides its object.
pub(crate) fn body_limit(config: &PlatformConfig) -> usize {
    usize::try_from(config.datasets.max_bytes)
        .unwrap_or(usize::MAX)
        .saturating_add(upload::MAX_BODY_OVERHEAD)
}

/// Audit an upload that did not complete: `denied` for a refusal, `failed`
/// for a storage or record failure. Identifiers and a fixed reason only.
fn audit_refusal(steward: TenantId, dataset: &str, outcome: &str, reason: &str) {
    let stopped = if outcome == "denied" {
        "refused"
    } else {
        "failed"
    };
    security_audit_event(
        AuditKind::DataAccess,
        Some(steward),
        outcome,
        &format!("upload {stopped} dataset={dataset} reason={reason}"),
    );
}

/// `PUT /api/v1/datasets/{dataset}` — store a browser-sealed upload as the
/// steward's dataset `{dataset}`, which must be in the upload namespace.
pub(crate) async fn put_dataset(
    State(state): State<AppState>,
    Extension(AuthedTenant(steward)): Extension<AuthedTenant>,
    Path(dataset): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<Value>, ApiError> {
    let dataset =
        ConnectorSlug::new(&dataset).map_err(|_| ApiError::BadRequest("invalid dataset id"))?;
    // Only upload datasets are written here; any other id names no dataset
    // this steward can upload to.
    if dataset.kind() != DatasetKind::Upload {
        audit_refusal(steward, dataset.as_str(), "denied", "not_upload_dataset");
        return Err(ApiError::NotFound);
    }
    let body = match body {
        Ok(body) => body,
        Err(rejection) if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE => {
            audit_refusal(
                steward,
                dataset.as_str(),
                "denied",
                UploadError::TooLarge.reason(),
            );
            return Err(ApiError::PayloadTooLarge);
        }
        Err(_) => return Err(ApiError::BadRequest("could not read the request body")),
    };

    let upload =
        upload::parse_upload_body(body, state.config.datasets.max_bytes).map_err(|err| {
            audit_refusal(steward, dataset.as_str(), "denied", err.reason());
            match err {
                UploadError::TooLarge => ApiError::PayloadTooLarge,
                other => ApiError::MalformedUpload(other.message()),
            }
        })?;

    let report = upload::commit_upload(&*state.vault, steward, &dataset, upload, SystemTime::now())
        .await
        .map_err(|err| {
            let reason = err.reason();
            let (outcome, refusal) = match err {
                UploadCommitError::NotUploadDataset => ("denied", ApiError::NotFound),
                UploadCommitError::VersionAhead => (
                    "denied",
                    ApiError::MalformedUpload("snapshot version is ahead of the server clock"),
                ),
                UploadCommitError::StaleVersion => ("denied", ApiError::StaleSnapshot),
                UploadCommitError::SchemaMismatch => ("denied", ApiError::SchemaMismatch),
                // The recorded schema is unknown, so nothing can be compared.
                UploadCommitError::RecordUnreadable => ("failed", ApiError::Backend),
                // The manifest is written last, so a failure before it leaves
                // the current snapshot in place.
                UploadCommitError::Storage(storage) => ("failed", ApiError::from(storage)),
            };
            audit_refusal(steward, dataset.as_str(), outcome, reason);
            refusal
        })?;

    Ok(Json(json!({
        "dataset": dataset,
        "version": report.version,
        "object": report.object,
        "suite": report.suite.id(),
        "ciphertext_bytes": report.ciphertext_bytes,
    })))
}

/// The body of `GET /api/v1/datasets`.
#[derive(Debug, Serialize)]
pub(crate) struct DatasetListing {
    datasets: Vec<DatasetEntry>,
}

/// One dataset in `GET /api/v1/datasets`: its current snapshot, as storage
/// describes it.
#[derive(Debug, Serialize)]
struct DatasetEntry {
    dataset: ConnectorSlug,
    /// The current snapshot: the newest committed one.
    version: SnapshotVersion,
    /// When the current snapshot was written ([`written_at`]).
    written_at: String,
    /// The suite the snapshot's record names, or `None` if the record is
    /// missing, malformed, or names a suite this build does not read, as a
    /// query would refuse it.
    suite: Option<&'static str>,
    object_count: usize,
    /// Total size of the current snapshot's objects as stored.
    ciphertext_bytes: u64,
    objects: Vec<ObjectId>,
}

impl DatasetEntry {
    fn new(held: HeldDataset, suite: Option<EnvelopeSuite>) -> Self {
        Self {
            written_at: written_at(&held.version),
            suite: suite.map(EnvelopeSuite::id),
            object_count: held.objects.len(),
            ciphertext_bytes: held.objects.iter().fold(0, |total, stored| {
                total.saturating_add(stored.ciphertext_bytes)
            }),
            objects: held
                .objects
                .into_iter()
                .map(|stored| stored.object)
                .collect(),
            dataset: held.slug,
            version: held.version,
        }
    }
}

/// A snapshot's write time, from its version: RFC 3339 in UTC, to the
/// millisecond, which a browser's `Date` parses. The version keeps the
/// nanoseconds.
fn written_at(version: &SnapshotVersion) -> String {
    let nanos = version.unix_nanos();
    // A version has 20 digits of nanoseconds, so at most 10^11 seconds: an
    // `i64`, and inside chrono's range (to year 262142).
    let secs = i64::try_from(nanos / 1_000_000_000).expect("at most 10^11 seconds");
    let subsec = u32::try_from(nanos % 1_000_000_000).expect("below 10^9");
    chrono::DateTime::from_timestamp(secs, subsec)
        .expect("at most 10^11 seconds is inside chrono's range")
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// `GET /api/v1/datasets` — every research dataset the caller's tenant
/// holds, by id: the datasets `snapshot::holds` is true for, which is the
/// check publishing a listing makes. Each entry describes the current
/// snapshot only: its version and write time, the objects stored at that
/// version with their total ciphertext size, and the suite its record
/// names. Nothing is opened, and objects of superseded snapshots or of
/// uploads that have not committed are not counted. More than
/// [`MAX_LISTED_OBJECTS`] datasets, or as many objects across them, is
/// refused with 422 rather than listed in part. A storage failure is an
/// error, never an empty list.
pub(crate) async fn list_datasets(
    State(state): State<AppState>,
    Extension(AuthedTenant(steward)): Extension<AuthedTenant>,
) -> Result<Json<DatasetListing>, ApiError> {
    let held = snapshot::held_datasets(&*state.vault, steward).await?;
    let objects: usize = held.iter().map(|dataset| dataset.objects.len()).sum();
    if held.len() > MAX_LISTED_OBJECTS || objects > MAX_LISTED_OBJECTS {
        security_audit_event(
            AuditKind::DataAccess,
            Some(steward),
            "denied",
            &format!(
                "list_datasets datasets={} objects={objects} exceeds cap={MAX_LISTED_OBJECTS}",
                held.len()
            ),
        );
        return Err(ApiError::ListTooLarge);
    }

    let vault = &*state.vault;
    let datasets: Vec<DatasetEntry> = futures::stream::iter(held)
        .map(|held| async move {
            let suite = snapshot::recorded_suite(vault, steward, &held.slug, &held.version).await?;
            Ok::<_, StorageError>(DatasetEntry::new(held, suite))
        })
        .buffered(LIST_READ_CONCURRENCY)
        .try_collect()
        .await?;
    security_audit_event(
        AuditKind::DataAccess,
        Some(steward),
        "ok",
        &format!("list_datasets count={}", datasets.len()),
    );
    Ok(Json(DatasetListing { datasets }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_times_cover_every_version() {
        for (version, expected) in [
            (
                "00000000000000000000-0123456789abcdef0123456789abcdef",
                "1970-01-01T00:00:00.000Z",
            ),
            (
                "00000000001763116830-0123456789abcdef0123456789abcdef",
                "1970-01-01T00:00:01.763Z",
            ),
            (
                "01763116830123456789-0123456789abcdef0123456789abcdef",
                "2025-11-14T10:40:30.123Z",
            ),
            (
                "99999999999999999999-0123456789abcdef0123456789abcdef",
                "5138-11-16T09:46:39.999Z",
            ),
        ] {
            let version: SnapshotVersion = version.parse().expect("version");
            assert_eq!(written_at(&version), expected, "{version}");
        }
    }
}
