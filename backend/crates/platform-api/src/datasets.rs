//! Steward dataset uploads (ADR 0011): `PUT /api/v1/datasets/{dataset}`.
//!
//! The steward's browser seals a Parquet file and the snapshot manifest
//! that lists it to the steward's key and sends both in one body
//! (`platform_connectors::upload`). This route cannot open either. It
//! checks the dataset id, the size, the framing and the declared header,
//! then stores the upload as the dataset's new snapshot, for the tenant in
//! the token only. The first upload creates the dataset; a re-upload
//! replaces it (ADR 0003).
//!
//! The route needs only the vault and the configuration, not the query
//! service, so uploads work where research queries are not configured.
//! Every refusal is audited as `data.access` `denied`, a storage failure as
//! `failed`; the stored object and the commit are audited by the writer.

use std::time::SystemTime;

use axum::Json;
use axum::extract::rejection::BytesRejection;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use bytes::Bytes;
use platform_config::PlatformConfig;
use platform_connectors::upload::{self, UploadCommitError, UploadError};
use platform_core::{ConnectorSlug, DatasetKind, TenantId};
use platform_telemetry::{AuditKind, security_audit_event};
use serde_json::{Value, json};

use crate::{ApiError, AppState, AuthedTenant};

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
