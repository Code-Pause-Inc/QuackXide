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
//! plaintext record (its suite and, for an upload, the declared row cap and
//! schema): what the operator can already see. It opens nothing.
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
use base64::Engine as _;
use bytes::Bytes;
use futures::{StreamExt, TryStreamExt};
use platform_config::PlatformConfig;
use platform_connectors::snapshot::{self, HeldDataset, KnownRecord, Recorded};
use platform_connectors::upload::{self, UploadCommitError, UploadError};
use platform_core::{
    ConnectorSlug, DatasetKind, DeclaredSchema, ObjectId, SnapshotVersion, TenantId,
};
use platform_crypto::{EnvelopeSuite, SuitePolicy, TenantPublicKey};
use platform_storage::{StorageError, TenantPaths, VaultStore};
use platform_telemetry::{AuditKind, security_audit_event};
use serde::Serialize;
use serde_json::{Value, json};

use crate::{
    ApiError, AppState, AuthedTenant, B64, EnrollmentBody, LIST_READ_CONCURRENCY,
    MAX_LISTED_OBJECTS,
};

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

/// The suite of the steward's enrolled key, or `None` when no key is
/// enrolled. Enrollment is the only writer of the record and validates the
/// key first, so a record that does not parse is a backend fault.
async fn enrolled_suite(
    state: &AppState,
    steward: TenantId,
) -> Result<Option<EnvelopeSuite>, ApiError> {
    let stored = match state
        .vault
        .get(&TenantPaths::tenant_enrollment(steward))
        .await
    {
        Ok(stored) => stored,
        Err(StorageError::NotFound) => return Ok(None),
        Err(err) => return Err(err.into()),
    };
    let key = serde_json::from_slice::<EnrollmentBody>(&stored)
        .ok()
        .and_then(|record| B64.decode(record.hpke_public_key_b64).ok())
        .and_then(|raw| TenantPublicKey::from_raw(&raw, SuitePolicy::DEVELOPMENT).ok())
        .ok_or(ApiError::Backend)?;
    Ok(Some(key.suite()))
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
            return Err(ApiError::PayloadTooLarge(UploadError::TooLarge.message()));
        }
        Err(_) => return Err(ApiError::BadRequest("could not read the request body")),
    };

    let upload =
        upload::parse_upload_body(body, state.config.datasets.max_bytes).map_err(|err| {
            audit_refusal(steward, dataset.as_str(), "denied", err.reason());
            match err {
                UploadError::TooLarge => ApiError::PayloadTooLarge(err.message()),
                other => ApiError::MalformedUpload(other.message()),
            }
        })?;
    // A frame of a suite this deployment refuses (HPK1 in production) could
    // never be opened, so it is refused here rather than stored.
    if SuitePolicy::for_env(state.config.env.is_production())
        .check(upload.suite)
        .is_err()
    {
        security_audit_event(
            AuditKind::SuiteRefused,
            Some(steward),
            "denied",
            "refused an upload sealed in a suite this deployment does not accept",
        );
        audit_refusal(steward, dataset.as_str(), "denied", "suite_refused");
        return Err(ApiError::MalformedUpload("upload suite not accepted"));
    }
    // Neither does an upload in another suite than the enrolled key's open:
    // every query would fail, and the commit would prune the snapshot that
    // does. Without an enrollment, `commit_upload` compares with the current
    // snapshot's suite instead. In
    // development an HPK1 upload also needs a test key provider
    // (`DevKeyProvider`, `MultiTenantDevKeyProvider`) to open: development
    // key release (`key_release.rs`, `stand_in.rs`) is HPK2-only.
    let enrolled = enrolled_suite(&state, steward).await.inspect_err(|_| {
        audit_refusal(steward, dataset.as_str(), "failed", "enrollment_unreadable");
    })?;
    if enrolled.is_some_and(|suite| suite != upload.suite) {
        security_audit_event(
            AuditKind::SuiteRefused,
            Some(steward),
            "denied",
            "refused an upload sealed in a suite other than the enrolled key's",
        );
        audit_refusal(
            steward,
            dataset.as_str(),
            "denied",
            "enrolled_suite_mismatch",
        );
        return Err(ApiError::MalformedUpload(
            "upload suite does not match the enrolled key",
        ));
    }

    let report = upload::commit_upload(
        &*state.vault,
        steward,
        &dataset,
        upload,
        enrolled.is_some(),
        SystemTime::now(),
    )
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
            UploadCommitError::SuiteMismatch => {
                security_audit_event(
                    AuditKind::SuiteRefused,
                    Some(steward),
                    "denied",
                    "refused an upload sealed in a suite other than the dataset's current snapshot",
                );
                (
                    "denied",
                    ApiError::MalformedUpload("upload suite does not match the dataset"),
                )
            }
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
    /// The largest object an upload may store, in ciphertext bytes
    /// (`DATASET_MAX_MIB`), so the steward's browser can refuse a file too
    /// large to upload before it seals anything. The upload route enforces
    /// it either way.
    dataset_max_bytes: u64,
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
    /// missing at the current version, malformed, or names a suite this
    /// build does not read, as a query would refuse it.
    suite: Option<&'static str>,
    /// For an upload, the row cap the steward declared, from the same
    /// record; `None` for a connector's dataset, or when `suite` is.
    row_cap: Option<u64>,
    /// For an upload, the schema the steward declared, from the same
    /// record: the schema a re-upload must declare (ADR 0012). `None` for a
    /// connector's dataset, or when `suite` is.
    schema: Option<DeclaredSchema>,
    object_count: usize,
    /// Total size of the current snapshot's objects as stored.
    ciphertext_bytes: u64,
    objects: Vec<ObjectId>,
}

impl DatasetEntry {
    fn new(held: HeldDataset, record: Option<KnownRecord>) -> Self {
        let (suite, row_cap, schema) = match record {
            Some(record) => (Some(record.suite.id()), record.row_cap, record.schema),
            None => (None, None, None),
        };
        Self {
            written_at: written_at(&held.version),
            suite,
            row_cap,
            schema,
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

/// `held`, a dataset as listed, with what its record says. A missing
/// record can mean that an upload or sync committed after the listing and
/// pruned this snapshot, so the dataset is read again, once, with one
/// listing of its own paths, and described as it is now: a newer snapshot
/// with its record, or at the same version, with none. `None` if the
/// dataset is no longer held, so the listing still shows exactly the
/// datasets held.
async fn describe(
    vault: &dyn VaultStore,
    steward: TenantId,
    held: HeldDataset,
) -> Result<Option<DatasetEntry>, StorageError> {
    match snapshot::read_record(vault, steward, &held.slug, &held.version).await? {
        Recorded::Missing => {}
        recorded => return Ok(Some(DatasetEntry::new(held, recorded.known()))),
    }
    let Some(current) = snapshot::held_dataset(vault, steward, &held.slug).await? else {
        return Ok(None);
    };
    let record = if current.version == held.version {
        None
    } else {
        snapshot::read_record(vault, steward, &current.slug, &current.version)
            .await?
            .known()
    };
    Ok(Some(DatasetEntry::new(current, record)))
}

/// `GET /api/v1/datasets` — every research dataset the caller's tenant
/// holds, by id: the datasets `snapshot::holds` is true for, which is the
/// check publishing a listing makes. Each entry describes the current
/// snapshot only: its version and write time, the objects stored at that
/// version with their total ciphertext size, the suite its record names
/// and, for an upload, the row cap and schema the record declares, which
/// the browser checks a re-upload against before sealing it. The response
/// also gives the upload size limit. Nothing is opened, and objects of
/// superseded snapshots or of uploads that have not committed are not
/// counted. A snapshot replaced while the listing runs is described as the
/// newer one ([`describe`]). More than [`MAX_LISTED_OBJECTS`] datasets, or
/// as many objects across them, is refused with 422 rather than listed in
/// part. A storage failure is an error, never an empty list.
pub(crate) async fn list_datasets(
    State(state): State<AppState>,
    Extension(AuthedTenant(steward)): Extension<AuthedTenant>,
) -> Result<Json<DatasetListing>, ApiError> {
    // This lists every path under the tenant's datasets, superseded
    // snapshots awaiting pruning included, before the cap is checked: the
    // cap bounds the response and the record reads, not that listing. The
    // drive listing does the same; v1 has no pagination.
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
        .map(|held| describe(vault, steward, held))
        .buffered(LIST_READ_CONCURRENCY)
        .try_filter_map(|entry| async move { Ok(entry) })
        .try_collect()
        .await?;
    security_audit_event(
        AuditKind::DataAccess,
        Some(steward),
        "ok",
        &format!("list_datasets count={}", datasets.len()),
    );
    Ok(Json(DatasetListing {
        datasets,
        dataset_max_bytes: state.config.datasets.max_bytes,
    }))
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
