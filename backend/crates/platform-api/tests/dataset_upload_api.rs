//! Steward dataset uploads (`PUT /api/v1/datasets/{dataset}`, ADR 0012): a
//! browser-sealed upload is stored as the dataset's new snapshot and is
//! queryable in the enclave; a re-upload replaces it; an upload that fails
//! partway is never visible. Refusals: no or non-access token (401), a
//! malformed body (422), an oversized one (413), a declared schema that
//! differs from the recorded one (422), a stale version (409), a dataset id
//! outside the upload namespace (404), a storage outage (503), and data
//! that does not match its declaration (502, in the enclave).
//!
//! The dataset listing (`GET /api/v1/datasets`): each dataset the caller
//! holds, uploaded, synced or seeded, exactly when publishing it is
//! allowed, described by its current snapshot alone; never a write that
//! has not committed, a superseded snapshot's objects, or another tenant's
//! dataset. Refusals: no or non-access token (401), more datasets or
//! objects than the cap (422), and a storage failure (503 or 502, never an
//! empty list).

mod common;

use std::sync::Arc;
use std::sync::atomic::Ordering::SeqCst;

use async_trait::async_trait;
use axum::Router;
use axum::http::{HeaderMap, StatusCode, header};
use bytes::Bytes;
use platform_api::{AppState, build_app};
use platform_auth::TokenType;
use platform_config::PlatformConfig;
use platform_core::{ColumnType, ConnectorSlug, ObjectId, SnapshotVersion, TenantId};
use platform_crypto::{TenantKeypair, TenantPublicKey};
use platform_storage::{
    ObjectStoreVault, SnapshotRecord, StorageError, StorageUsage, TenantPaths, VaultEntry,
    VaultPath, VaultStore,
};

use common::{
    Faults, SealedUpload, app_state, cohorts_schema, cohorts_upload, declared, flaky_vault,
    next_version, put_upload, sealed_upload, send_with_headers, upload_research_app,
};

const SECRET: &str = "dataset-upload-itest-secret";
const DATASET: &str = "upload_cohorts";
const COUNT_SQL: &str = "SELECT condition, COUNT(*) AS n FROM upload_cohorts \
                         GROUP BY condition ORDER BY condition";

fn token_for(tenant: TenantId) -> String {
    common::token_for(SECRET, tenant)
}

/// A steward with a fresh key, and the app holding that key.
struct Steward {
    tenant: TenantId,
    key: TenantPublicKey,
    token: String,
}

fn steward() -> (Steward, TenantKeypair) {
    let tenant = TenantId::generate();
    let keypair = TenantKeypair::generate();
    let steward = Steward {
        tenant,
        key: keypair.public_key(),
        token: token_for(tenant),
    };
    (steward, keypair)
}

fn in_memory() -> Arc<dyn VaultStore> {
    Arc::new(ObjectStoreVault::new_in_memory())
}

/// An app over `vault` holding the steward's key for queries.
fn app_over(vault: Arc<dyn VaultStore>) -> (Router, Steward) {
    let (steward, keypair) = steward();
    let app = upload_research_app(SECRET, vec![(steward.tenant, keypair)], vault);
    (app, steward)
}

async fn upload(app: &Router, steward: &Steward, upload: &SealedUpload) -> StatusCode {
    put_upload(app, Some(&steward.token), DATASET, upload.body.clone())
        .await
        .0
}

/// The steward's own aggregate query over the uploaded dataset.
async fn count(app: &Router, steward: &Steward) -> (StatusCode, serde_json::Value) {
    let body = serde_json::json!({ "connector": DATASET, "sql": COUNT_SQL }).to_string();
    common::post_query(app, Some(&steward.token), &body).await
}

/// Everything stored under the steward's tenant.
async fn stored(vault: &dyn VaultStore, tenant: TenantId) -> Vec<VaultPath> {
    vault
        .list(&TenantPaths::tenant_root(tenant))
        .await
        .expect("list")
}

fn slug() -> ConnectorSlug {
    ConnectorSlug::new(DATASET).expect("slug")
}

/// The current snapshot's manifest, record and object paths.
async fn snapshot_paths(vault: &dyn VaultStore, tenant: TenantId) -> (usize, usize, usize) {
    let slug = slug();
    let count = |prefix: VaultPath| async move { vault.list(&prefix).await.expect("list").len() };
    (
        count(TenantPaths::connector_manifests_prefix(tenant, &slug)).await,
        count(TenantPaths::connector_records_prefix(tenant, &slug)).await,
        count(TenantPaths::connector_snapshots_prefix(tenant, &slug)).await,
    )
}

#[tokio::test]
async fn an_upload_is_stored_sealed_and_queryable() {
    let vault = in_memory();
    let (app, steward) = app_over(vault.clone());
    let sealed = cohorts_upload(steward.tenant, &steward.key, DATASET, None);

    let (status, body) = put_upload(&app, Some(&steward.token), DATASET, sealed.body.clone()).await;
    assert_eq!(status, StatusCode::OK, "upload: {body}");
    assert_eq!(body["dataset"], DATASET);
    assert_eq!(body["version"], sealed.version.as_str());
    assert_eq!(body["object"], sealed.object.to_string());
    assert_eq!(body["suite"], "HPK1");

    // Stored at the snapshot layout: object, record, manifest; the object
    // is the ciphertext the browser sent, never Parquet.
    assert_eq!(snapshot_paths(&*vault, steward.tenant).await, (1, 1, 1));
    let object = vault
        .get(&TenantPaths::connector_snapshot_object(
            steward.tenant,
            &slug(),
            &sealed.version,
            sealed.object,
        ))
        .await
        .expect("object");
    assert_eq!(&object[..4], b"HPK1");
    assert!(
        !object.windows(4).any(|w| w == b"PAR1"),
        "plaintext Parquet stored"
    );
    assert_eq!(body["ciphertext_bytes"], object.len());

    // The enclave opens it under the upload binding: 6 "flu", the single
    // "rare_disease" row suppressed below k=5.
    let (status, rows) = count(&app, &steward).await;
    assert_eq!(status, StatusCode::OK, "query: {rows}");
    assert_eq!(rows["object_count"], 1);
    assert_eq!(rows["rows"][0]["condition"], "flu");
    assert_eq!(rows["rows"][0]["n"], 6);
    assert_eq!(rows["suppressed_rows"], 1);
}

/// The body `seal-upload` writes for `scripts/test-simulated-tee.sh`: a
/// synthetic cohort declared as the enclave finds it.
#[tokio::test]
async fn the_seal_upload_tools_cohort_is_stored_and_queryable() {
    let vault = in_memory();
    let (app, steward) = app_over(vault.clone());
    let sealed = platform_api::dev::seal_cohort_upload(steward.tenant, &steward.key, &slug(), 5)
        .expect("seal");
    assert_eq!(upload(&app, &steward, &sealed).await, StatusCode::OK);

    // The record holds the declaration: the cohort's columns and its 9k + 1
    // rows.
    let record = vault
        .get(&TenantPaths::connector_record(
            steward.tenant,
            &slug(),
            &sealed.version,
        ))
        .await
        .expect("record");
    let record = SnapshotRecord::parse(&record, &sealed.version).expect("record");
    assert_eq!(record.row_cap, Some(46));
    assert_eq!(
        record.schema,
        Some(declared(&[
            ("person_id", ColumnType::String),
            ("email", ColumnType::String),
            ("condition", ColumnType::String),
            ("age", ColumnType::Int64),
            ("cost_cents", ColumnType::Int64),
        ]))
    );

    // The enclave opens it and finds it as declared. With k = 5, the group
    // of k - 1 rows and the single-row group are suppressed.
    let (status, rows) = count(&app, &steward).await;
    assert_eq!(status, StatusCode::OK, "{rows}");
    assert_eq!(rows["rows"].as_array().map(Vec::len), Some(7), "{rows}");
    assert_eq!(rows["suppressed_rows"], 2, "{rows}");
}

#[tokio::test]
async fn uploads_without_an_access_token_are_401() {
    let vault = in_memory();
    let app = build_app(AppState {
        jwt: Some(Arc::new(common::rs256_verifier())),
        ..app_state(SECRET, vault.clone())
    });
    let tenant = TenantId::generate();
    let keypair = TenantKeypair::generate();
    let sealed = cohorts_upload(tenant, &keypair.public_key(), DATASET, None);

    let (status, _) = put_upload(&app, None, DATASET, sealed.body.clone()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    for token_type in [TokenType::Preauth, TokenType::Refresh] {
        let token = common::rs256_token(token_type, false);
        let (status, _) = put_upload(&app, Some(&token), DATASET, sealed.body.clone()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{token_type:?}");
    }
    // An access token passes the same route.
    let token = common::rs256_token(TokenType::Access, false);
    let (status, body) = put_upload(&app, Some(&token), DATASET, sealed.body).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn malformed_upload_bodies_are_422() {
    let vault = in_memory();
    let (app, steward) = app_over(vault.clone());
    let sealed = cohorts_upload(steward.tenant, &steward.key, DATASET, None);
    let body = &sealed.body;
    let relabelled = {
        let mut out = body.clone();
        let object_at = object_offset(body);
        out[object_at..object_at + 4].copy_from_slice(b"HPK2");
        out
    };
    for (name, bad) in [
        ("empty body", Vec::new()),
        ("not an upload", b"PAR1 plaintext parquet".to_vec()),
        ("truncated after the magic", body[..6].to_vec()),
        ("truncated in the header", body[..40].to_vec()),
        (
            "object cut to 20 bytes",
            body[..object_offset(body) + 20].to_vec(),
        ),
        ("object of an unknown suite", relabelled),
    ] {
        let (status, response) = put_upload(&app, Some(&steward.token), DATASET, bad).await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{name}: {response}"
        );
    }
    assert!(stored(&*vault, steward.tenant).await.is_empty());
}

/// Where the object envelope starts in an upload body.
fn object_offset(body: &[u8]) -> usize {
    let header = u32::from_be_bytes(body[4..8].try_into().expect("4 bytes")) as usize;
    let at = 8 + header;
    let manifest = u32::from_be_bytes(body[at..at + 4].try_into().expect("4 bytes")) as usize;
    at + 4 + manifest
}

fn config_with_max_mib(mib: u64) -> PlatformConfig {
    PlatformConfig::from_source(|key| match key {
        "DATASET_MAX_MIB" => Some(mib.to_string()),
        _ => None,
    })
    .expect("config")
}

#[tokio::test]
async fn an_upload_over_the_size_limit_is_413() {
    let vault = in_memory();
    let app = build_app(AppState {
        config: Arc::new(config_with_max_mib(1)),
        ..app_state(SECRET, vault.clone())
    });
    let (steward, _) = steward();
    let limit = 1024 * 1024;
    // Within the request limit, but the object is one byte over the
    // dataset limit; then a body over the request limit itself.
    for object_bytes in [
        limit + 1,
        limit + platform_connectors::upload::MAX_BODY_OVERHEAD + 1,
    ] {
        let mut object = b"HPK1".to_vec();
        object.resize(object_bytes, 0);
        let sealed = sealed_upload(
            steward.tenant,
            &steward.key,
            DATASET,
            next_version(None),
            b"x",
            cohorts_schema(),
            7,
        );
        let mut body = sealed.body[..object_offset(&sealed.body)].to_vec();
        body.extend_from_slice(&object);
        let (status, response) = put_upload(&app, Some(&steward.token), DATASET, body).await;
        assert_eq!(
            status,
            StatusCode::PAYLOAD_TOO_LARGE,
            "{object_bytes}: {response}"
        );
    }
    assert!(stored(&*vault, steward.tenant).await.is_empty());
}

#[tokio::test]
async fn a_declared_schema_unlike_the_recorded_one_is_422() {
    let vault = in_memory();
    let (app, steward) = app_over(vault.clone());
    let first = cohorts_upload(steward.tenant, &steward.key, DATASET, None);
    assert_eq!(upload(&app, &steward, &first).await, StatusCode::OK);

    let renamed = sealed_upload(
        steward.tenant,
        &steward.key,
        DATASET,
        next_version(Some(&first.version)),
        &common::cohorts_parquet(),
        declared(&[
            ("diagnosis", ColumnType::String),
            ("age", ColumnType::Int64),
        ]),
        7,
    );
    let (status, body) = put_upload(&app, Some(&steward.token), DATASET, renamed.body).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(
        body["error"],
        "declared schema does not match the dataset's recorded schema"
    );
    // The first upload stays current.
    assert_eq!(snapshot_paths(&*vault, steward.tenant).await, (1, 1, 1));
    let (status, rows) = count(&app, &steward).await;
    assert_eq!(status, StatusCode::OK, "{rows}");
    assert_eq!(rows["rows"][0]["n"], 6);
}

#[tokio::test]
async fn a_version_that_cannot_become_current_is_refused() {
    let vault = in_memory();
    let (app, steward) = app_over(vault.clone());
    let first = cohorts_upload(steward.tenant, &steward.key, DATASET, None);
    assert_eq!(upload(&app, &steward, &first).await, StatusCode::OK);

    // The same body again, as a retry after a lost response: 409.
    let (status, body) = put_upload(&app, Some(&steward.token), DATASET, first.body.clone()).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");

    // A version an hour ahead of the server's clock: 422.
    let ahead: SnapshotVersion = format!(
        "{:020}-{}",
        first.version.unix_nanos() + 3_600_000_000_000,
        "0".repeat(32)
    )
    .parse()
    .expect("version");
    let sealed = sealed_upload(
        steward.tenant,
        &steward.key,
        DATASET,
        ahead,
        &common::cohorts_parquet(),
        cohorts_schema(),
        7,
    );
    let (status, body) = put_upload(&app, Some(&steward.token), DATASET, sealed.body).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(snapshot_paths(&*vault, steward.tenant).await, (1, 1, 1));
}

#[tokio::test]
async fn uploading_outside_the_upload_namespace_is_refused() {
    let vault = in_memory();
    let (app, steward) = app_over(vault.clone());
    // Connector datasets are written only by connector syncs: the steward
    // holds no upload dataset by these ids (404).
    for dataset in ["quickbooks", "research_extract", "health", "uploads"] {
        let sealed = cohorts_upload(steward.tenant, &steward.key, dataset, None);
        let (status, body) = put_upload(&app, Some(&steward.token), dataset, sealed.body).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{dataset}: {body}");
    }
    // Not a dataset id at all (400).
    for dataset in ["Upload_cohorts", "upload.cohorts", "upload_%2e%2e"] {
        let sealed = cohorts_upload(steward.tenant, &steward.key, DATASET, None);
        let (status, _) = put_upload(&app, Some(&steward.token), dataset, sealed.body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{dataset}");
    }
    assert!(stored(&*vault, steward.tenant).await.is_empty());
}

#[tokio::test]
async fn a_re_upload_replaces_the_current_snapshot() {
    let vault = in_memory();
    let (app, steward) = app_over(vault.clone());
    let first = cohorts_upload(steward.tenant, &steward.key, DATASET, None);
    assert_eq!(upload(&app, &steward, &first).await, StatusCode::OK);

    // The same rows again: counts stay the same, never doubled.
    let second = cohorts_upload(steward.tenant, &steward.key, DATASET, Some(&first.version));
    assert_eq!(upload(&app, &steward, &second).await, StatusCode::OK);
    assert_eq!(snapshot_paths(&*vault, steward.tenant).await, (1, 1, 1));
    let (status, rows) = count(&app, &steward).await;
    assert_eq!(status, StatusCode::OK, "{rows}");
    assert_eq!(rows["rows"][0]["n"], 6);

    // Only the newest snapshot's object remains.
    let object = TenantPaths::connector_snapshot_object(
        steward.tenant,
        &slug(),
        &second.version,
        second.object,
    );
    assert!(vault.get(&object).await.is_ok());
    let old = TenantPaths::connector_snapshot_object(
        steward.tenant,
        &slug(),
        &first.version,
        first.object,
    );
    assert!(matches!(vault.get(&old).await, Err(StorageError::NotFound)));
}

/// An in-memory vault whose manifest writes fail while `fail` is set: an
/// upload that stops after its object and record. Manifests are written
/// create-only, so both write methods fail.
struct FailingManifests {
    inner: ObjectStoreVault,
    fail: std::sync::atomic::AtomicBool,
}

impl FailingManifests {
    fn failing(&self, path: &VaultPath) -> bool {
        self.fail.load(std::sync::atomic::Ordering::SeqCst) && path.as_str().ends_with(".manifest")
    }
}

#[async_trait]
impl VaultStore for FailingManifests {
    async fn put(&self, path: &VaultPath, ciphertext: Bytes) -> Result<(), StorageError> {
        if self.failing(path) {
            return Err(common::outage());
        }
        self.inner.put(path, ciphertext).await
    }
    async fn put_if_absent(&self, path: &VaultPath, ciphertext: Bytes) -> Result<(), StorageError> {
        if self.failing(path) {
            return Err(common::outage());
        }
        self.inner.put_if_absent(path, ciphertext).await
    }
    async fn get(&self, path: &VaultPath) -> Result<Bytes, StorageError> {
        self.inner.get(path).await
    }
    async fn delete(&self, path: &VaultPath) -> Result<(), StorageError> {
        self.inner.delete(path).await
    }
    async fn list(&self, prefix: &VaultPath) -> Result<Vec<VaultPath>, StorageError> {
        self.inner.list(prefix).await
    }
    async fn list_entries(&self, prefix: &VaultPath) -> Result<Vec<VaultEntry>, StorageError> {
        self.inner.list_entries(prefix).await
    }
    async fn usage(&self, prefix: &VaultPath) -> Result<StorageUsage, StorageError> {
        self.inner.usage(prefix).await
    }
}

#[tokio::test]
async fn a_partial_upload_is_never_visible() {
    let vault = Arc::new(FailingManifests {
        inner: ObjectStoreVault::new_in_memory(),
        fail: false.into(),
    });
    let (app, steward) = app_over(vault.clone());
    let first = cohorts_upload(steward.tenant, &steward.key, DATASET, None);
    assert_eq!(upload(&app, &steward, &first).await, StatusCode::OK);

    // A second upload of other rows stops before its manifest.
    vault.fail.store(true, std::sync::atomic::Ordering::SeqCst);
    let rows = synth_cohort(3);
    let partial = sealed_upload(
        steward.tenant,
        &steward.key,
        DATASET,
        next_version(Some(&first.version)),
        &rows,
        cohorts_schema(),
        3,
    );
    assert_eq!(
        upload(&app, &steward, &partial).await,
        StatusCode::SERVICE_UNAVAILABLE
    );
    // Its object and record are stored, but queries read the first upload.
    assert_eq!(snapshot_paths(&*vault, steward.tenant).await, (1, 2, 2));
    let (status, counted) = count(&app, &steward).await;
    assert_eq!(status, StatusCode::OK, "{counted}");
    assert_eq!(counted["rows"][0]["n"], 6);

    // The retry with a newer version commits and prunes the leftovers.
    vault.fail.store(false, std::sync::atomic::Ordering::SeqCst);
    let retry = sealed_upload(
        steward.tenant,
        &steward.key,
        DATASET,
        next_version(Some(&partial.version)),
        &rows,
        cohorts_schema(),
        3,
    );
    assert_eq!(upload(&app, &steward, &retry).await, StatusCode::OK);
    assert_eq!(snapshot_paths(&*vault, steward.tenant).await, (1, 1, 1));
}

#[tokio::test]
async fn a_retry_at_the_same_version_replaces_the_failed_attempt() {
    let vault = Arc::new(FailingManifests {
        inner: ObjectStoreVault::new_in_memory(),
        fail: true.into(),
    });
    let (app, steward) = app_over(vault.clone());
    let version = next_version(None);
    let attempt = |parquet: &[u8], row_cap: u64| {
        sealed_upload(
            steward.tenant,
            &steward.key,
            DATASET,
            version.clone(),
            parquet,
            cohorts_schema(),
            row_cap,
        )
    };

    // The first attempt stores its object and its record (row cap 8), and
    // stops before its manifest.
    let failed = attempt(&common::cohorts_parquet(), 8);
    assert_eq!(
        upload(&app, &steward, &failed).await,
        StatusCode::SERVICE_UNAVAILABLE
    );
    vault.fail.store(false, std::sync::atomic::Ordering::SeqCst);

    // A body at that version declaring another row cap is stale, and the
    // stored record is kept.
    let rows = synth_cohort(8);
    assert_eq!(
        upload(&app, &steward, &attempt(&rows, 9)).await,
        StatusCode::CONFLICT
    );
    let record = vault
        .get(&TenantPaths::connector_record(
            steward.tenant,
            &slug(),
            &version,
        ))
        .await
        .expect("record");
    let record = SnapshotRecord::parse(&record, &version).expect("parse");
    assert_eq!(record.row_cap, Some(8));

    // The retry declares the same record and seals other rows under a new
    // object id. It commits, and both earlier objects are pruned.
    let retry = attempt(&rows, 8);
    assert_ne!(retry.object, failed.object);
    assert_eq!(upload(&app, &steward, &retry).await, StatusCode::OK);
    assert_eq!(snapshot_paths(&*vault, steward.tenant).await, (1, 1, 1));
    let (status, counted) = count(&app, &steward).await;
    assert_eq!(status, StatusCode::OK, "{counted}");
    assert_eq!(counted["rows"][0]["n"], 8);

    // The version is committed once: sending it again is stale.
    assert_eq!(upload(&app, &steward, &retry).await, StatusCode::CONFLICT);
}

/// `rows` "flu" cohorts rows in the [`common::cohorts_schema`] shape.
fn synth_cohort(rows: usize) -> Vec<u8> {
    use arrow::array::{Int64Array, StringArray};
    use arrow::datatypes::{DataType, Field, Schema};
    use arrow::record_batch::RecordBatch;
    let schema = Arc::new(Schema::new(vec![
        Field::new("condition", DataType::Utf8, false),
        Field::new("age", DataType::Int64, false),
    ]));
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(StringArray::from_iter_values(std::iter::repeat_n(
                "flu", rows,
            ))),
            Arc::new(Int64Array::from_iter_values(0..rows as i64)),
        ],
    )
    .expect("batch");
    let mut buf = Vec::new();
    let mut writer = parquet::arrow::ArrowWriter::try_new(&mut buf, schema, None).expect("writer");
    writer.write(&batch).expect("write");
    writer.close().expect("close");
    buf
}

#[tokio::test]
async fn a_storage_outage_fails_the_upload_with_503() {
    for faults in [
        Faults {
            put: true,
            ..Faults::default()
        },
        Faults {
            list: true,
            ..Faults::default()
        },
    ] {
        let vault = flaky_vault(faults);
        let app = build_app(app_state(SECRET, vault.clone()));
        let (steward, _) = steward();
        let sealed = cohorts_upload(steward.tenant, &steward.key, DATASET, None);
        let (status, headers, _) = send_with_headers(
            &app,
            "PUT",
            &format!("/api/v1/datasets/{DATASET}"),
            &[common::bearer(&steward.token)],
            sealed.body,
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{faults:?}");
        assert!(headers.contains_key(header::RETRY_AFTER), "{faults:?}");
    }
}

#[tokio::test]
async fn uploads_are_tenant_isolated() {
    let vault = in_memory();
    let (a, a_keypair) = steward();
    let (b, b_keypair) = steward();
    let app = upload_research_app(
        SECRET,
        vec![(a.tenant, a_keypair), (b.tenant, b_keypair)],
        vault.clone(),
    );
    let a_upload = cohorts_upload(a.tenant, &a.key, DATASET, None);
    assert_eq!(upload(&app, &a, &a_upload).await, StatusCode::OK);

    // B uploads a dataset of the same name: it lands under B's tenant only,
    // and A's snapshot is untouched.
    let b_upload = sealed_upload(
        b.tenant,
        &b.key,
        DATASET,
        next_version(None),
        &synth_cohort(3),
        cohorts_schema(),
        3,
    );
    assert_eq!(upload(&app, &b, &b_upload).await, StatusCode::OK);
    assert_eq!(snapshot_paths(&*vault, a.tenant).await, (1, 1, 1));
    assert_eq!(snapshot_paths(&*vault, b.tenant).await, (1, 1, 1));
    assert!(
        vault
            .get(&TenantPaths::connector_snapshot_object(
                a.tenant,
                &slug(),
                &a_upload.version,
                a_upload.object
            ))
            .await
            .is_ok()
    );

    // A body sealed for A, sent with B's token, is stored as B's but can
    // never open under B's binding: B's query fails closed.
    let replay = cohorts_upload(a.tenant, &a.key, DATASET, Some(&b_upload.version));
    assert_eq!(upload(&app, &b, &replay).await, StatusCode::OK);
    let (status, _) = count(&app, &b).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    // A's own data still opens.
    let (status, rows) = count(&app, &a).await;
    assert_eq!(status, StatusCode::OK, "{rows}");
    assert_eq!(rows["rows"][0]["n"], 6);
}

#[tokio::test]
async fn data_unlike_its_declaration_is_refused_in_the_enclave() {
    // The API cannot see inside the upload, so a declaration that is wrong
    // about the sealed Parquet is accepted at upload and refused at query.
    for (schema, row_cap) in [
        (
            declared(&[
                ("condition", ColumnType::String),
                ("age", ColumnType::Int32),
            ]),
            7,
        ),
        (cohorts_schema(), 3),
    ] {
        let vault = in_memory();
        let (app, steward) = app_over(vault.clone());
        let sealed = sealed_upload(
            steward.tenant,
            &steward.key,
            DATASET,
            next_version(None),
            &common::cohorts_parquet(),
            schema,
            row_cap,
        );
        assert_eq!(upload(&app, &steward, &sealed).await, StatusCode::OK);
        let (status, body) = count(&app, &steward).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
        assert_eq!(
            body["error"],
            "stored dataset does not match its declared schema or row cap"
        );
    }
}

#[tokio::test]
async fn a_manifest_listing_an_object_that_was_not_uploaded_fails_closed() {
    let vault = in_memory();
    let (app, steward) = app_over(vault.clone());
    let sealed = cohorts_upload(steward.tenant, &steward.key, DATASET, None);
    assert_eq!(upload(&app, &steward, &sealed).await, StatusCode::OK);
    // Move the object to another id: the manifest now lists a missing one.
    let slug = slug();
    let path = |object| {
        TenantPaths::connector_snapshot_object(steward.tenant, &slug, &sealed.version, object)
    };
    let bytes = vault.get(&path(sealed.object)).await.expect("object");
    vault.delete(&path(sealed.object)).await.expect("delete");
    vault
        .put(&path(platform_core::ObjectId::generate()), bytes)
        .await
        .expect("put");
    let (status, body) = count(&app, &steward).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
}

// ── The dataset listing ──

/// What a tenant that holds no dataset is sent.
const EMPTY_LISTING: &[u8] = br#"{"datasets":[]}"#;

/// `GET /api/v1/datasets`, as `token` if given.
async fn list_datasets(app: &Router, token: Option<&str>) -> (StatusCode, HeaderMap, Vec<u8>) {
    let headers: Vec<_> = token.map(common::bearer).into_iter().collect();
    send_with_headers(app, "GET", "/api/v1/datasets", &headers, Vec::new()).await
}

/// The datasets a listing that succeeds returns.
async fn listed(app: &Router, token: &str) -> Vec<serde_json::Value> {
    let (status, _, body) = list_datasets(app, Some(token)).await;
    let body: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(status, StatusCode::OK, "{body}");
    body["datasets"].as_array().expect("a list").clone()
}

/// Whether the steward may publish a listing for `dataset`: the "holds"
/// check.
async fn publishable(app: &Router, steward: &Steward, dataset: &str) -> bool {
    let body = serde_json::json!({
        "connector": dataset,
        "title": "Cohorts",
        "license_fee_cents": 0,
        "compute_rate_cents": 0,
    })
    .to_string();
    let (status, response) = common::post(app, "/api/v1/catalog", &steward.token, &body).await;
    match status {
        StatusCode::OK => true,
        StatusCode::NOT_FOUND => false,
        other => panic!("publishing {dataset}: {other} {response}"),
    }
}

fn object_ids(objects: &[ObjectId]) -> serde_json::Value {
    serde_json::json!(objects.iter().map(ToString::to_string).collect::<Vec<_>>())
}

#[tokio::test]
async fn the_listing_shows_each_upload_as_the_current_snapshot() {
    let vault = in_memory();
    let (app, steward) = app_over(vault.clone());
    let (status, _, body) = list_datasets(&app, Some(&steward.token)).await;
    assert_eq!((status, body.as_slice()), (StatusCode::OK, EMPTY_LISTING));

    let first = cohorts_upload(steward.tenant, &steward.key, DATASET, None);
    let (status, uploaded) =
        put_upload(&app, Some(&steward.token), DATASET, first.body.clone()).await;
    assert_eq!(status, StatusCode::OK, "{uploaded}");
    let entries = listed(&app, &steward.token).await;
    assert_eq!(entries.len(), 1, "{entries:?}");
    let entry = &entries[0];
    assert_eq!(entry["dataset"], DATASET);
    assert_eq!(entry["version"], first.version.as_str());
    assert_eq!(entry["suite"], "HPK1");
    assert_eq!(entry["object_count"], 1);
    assert_eq!(entry["objects"], object_ids(&[first.object]));
    assert_eq!(entry["ciphertext_bytes"], uploaded["ciphertext_bytes"]);
    let written_at = entry["written_at"].as_str().expect("a time");
    let written_at = chrono::DateTime::parse_from_rfc3339(written_at).expect("RFC 3339");
    assert_eq!(
        u128::try_from(written_at.timestamp_millis()).expect("after 1970"),
        first.version.unix_nanos() / 1_000_000
    );
    // Nothing else, such as the declared schema from the record.
    assert_eq!(entry.as_object().expect("an object").len(), 7, "{entry}");
    assert!(!entry.to_string().contains("condition"), "{entry}");

    // A re-upload replaces it: still one dataset, at the new snapshot.
    let second = cohorts_upload(steward.tenant, &steward.key, DATASET, Some(&first.version));
    assert_eq!(upload(&app, &steward, &second).await, StatusCode::OK);
    let entries = listed(&app, &steward.token).await;
    assert_eq!(entries.len(), 1, "{entries:?}");
    assert_eq!(entries[0]["version"], second.version.as_str());
    assert_eq!(entries[0]["object_count"], 1);
    assert_eq!(entries[0]["objects"], object_ids(&[second.object]));
}

#[tokio::test]
async fn a_partial_upload_is_never_listed() {
    let vault = Arc::new(FailingManifests {
        inner: ObjectStoreVault::new_in_memory(),
        fail: true.into(),
    });
    let (app, steward) = app_over(vault.clone());

    // A first upload that stops before its manifest creates no dataset, and
    // publishing agrees.
    let stopped = cohorts_upload(steward.tenant, &steward.key, DATASET, None);
    assert_eq!(
        upload(&app, &steward, &stopped).await,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(snapshot_paths(&*vault, steward.tenant).await, (0, 1, 1));
    let (status, _, body) = list_datasets(&app, Some(&steward.token)).await;
    assert_eq!((status, body.as_slice()), (StatusCode::OK, EMPTY_LISTING));
    assert!(!publishable(&app, &steward, DATASET).await);

    // After an upload commits, a newer one that stops changes nothing listed.
    vault.fail.store(false, SeqCst);
    let first = cohorts_upload(
        steward.tenant,
        &steward.key,
        DATASET,
        Some(&stopped.version),
    );
    assert_eq!(upload(&app, &steward, &first).await, StatusCode::OK);
    vault.fail.store(true, SeqCst);
    let partial = sealed_upload(
        steward.tenant,
        &steward.key,
        DATASET,
        next_version(Some(&first.version)),
        &synth_cohort(3),
        cohorts_schema(),
        3,
    );
    assert_eq!(
        upload(&app, &steward, &partial).await,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(snapshot_paths(&*vault, steward.tenant).await, (1, 2, 2));
    let entries = listed(&app, &steward.token).await;
    assert_eq!(entries.len(), 1, "{entries:?}");
    assert_eq!(entries[0]["version"], first.version.as_str());
    assert_eq!(entries[0]["objects"], object_ids(&[first.object]));
    assert!(publishable(&app, &steward, DATASET).await);
}

#[tokio::test]
async fn a_superseded_snapshots_objects_are_not_counted() {
    let vault = in_memory();
    let (app, steward) = app_over(vault.clone());
    let first = cohorts_upload(steward.tenant, &steward.key, DATASET, None);
    assert_eq!(upload(&app, &steward, &first).await, StatusCode::OK);
    let current = cohorts_upload(steward.tenant, &steward.key, DATASET, Some(&first.version));
    let (status, uploaded) =
        put_upload(&app, Some(&steward.token), DATASET, current.body.clone()).await;
    assert_eq!(status, StatusCode::OK, "{uploaded}");

    // The first snapshot back in storage, as if pruning it had failed: its
    // manifest and a larger object.
    let slug = slug();
    for (path, bytes) in [
        (
            TenantPaths::connector_manifest(steward.tenant, &slug, &first.version),
            vec![1u8; 64],
        ),
        (
            TenantPaths::connector_snapshot_object(
                steward.tenant,
                &slug,
                &first.version,
                first.object,
            ),
            vec![2u8; 4096],
        ),
    ] {
        vault.put(&path, bytes.into()).await.expect("put");
    }
    assert_eq!(snapshot_paths(&*vault, steward.tenant).await, (2, 1, 2));

    let entries = listed(&app, &steward.token).await;
    assert_eq!(entries.len(), 1, "{entries:?}");
    assert_eq!(entries[0]["version"], current.version.as_str());
    assert_eq!(entries[0]["object_count"], 1);
    assert_eq!(entries[0]["objects"], object_ids(&[current.object]));
    assert_eq!(entries[0]["ciphertext_bytes"], uploaded["ciphertext_bytes"]);
}

#[tokio::test]
async fn another_tenants_datasets_are_never_listed() {
    let vault = in_memory();
    let (a, a_keypair) = steward();
    let (b, b_keypair) = steward();
    let app = upload_research_app(
        SECRET,
        vec![(a.tenant, a_keypair), (b.tenant, b_keypair)],
        vault.clone(),
    );
    let a_upload = cohorts_upload(a.tenant, &a.key, DATASET, None);
    assert_eq!(upload(&app, &a, &a_upload).await, StatusCode::OK);

    // B is sent exactly what a tenant that never stored anything is sent.
    let (b_status, _, b_body) = list_datasets(&app, Some(&b.token)).await;
    assert_eq!(
        (b_status, b_body.as_slice()),
        (StatusCode::OK, EMPTY_LISTING)
    );
    let nobody = token_for(TenantId::generate());
    let (status, _, body) = list_datasets(&app, Some(&nobody)).await;
    assert_eq!((status, body), (b_status, b_body));

    // A dataset of the same name under each tenant: each sees its own.
    let b_upload = cohorts_upload(b.tenant, &b.key, DATASET, None);
    assert_eq!(upload(&app, &b, &b_upload).await, StatusCode::OK);
    for (steward, sealed) in [(&a, &a_upload), (&b, &b_upload)] {
        let entries = listed(&app, &steward.token).await;
        assert_eq!(entries.len(), 1, "{entries:?}");
        assert_eq!(entries[0]["version"], sealed.version.as_str());
        assert_eq!(entries[0]["objects"], object_ids(&[sealed.object]));
    }
}

#[tokio::test]
async fn synced_and_seeded_datasets_are_listed_as_publishing_sees_them() {
    // The `health` dataset `devstack` seeds, committed the same way, which
    // its README has the steward publish.
    let seeded = TenantId::generate();
    let app = common::research_app(
        SECRET,
        seeded,
        TenantKeypair::generate(),
        common::dev_attestation(),
        false,
    )
    .await;
    let entries = listed(&app, &token_for(seeded)).await;
    assert_eq!(entries.len(), 1, "{entries:?}");
    assert_eq!(entries[0]["dataset"], "health");
    assert_eq!(entries[0]["suite"], "HPK1");
    assert_eq!(entries[0]["object_count"], 1);

    // Two connector syncs, the second superseding the first, then an upload.
    let (steward, keypair) = steward();
    let vault = common::synced_vault(steward.tenant, &keypair, 2).await;
    let app = upload_research_app(SECRET, vec![(steward.tenant, keypair)], vault.clone());
    let sealed = cohorts_upload(steward.tenant, &steward.key, DATASET, None);
    assert_eq!(upload(&app, &steward, &sealed).await, StatusCode::OK);
    let entries = listed(&app, &steward.token).await;
    let ids: Vec<&str> = entries
        .iter()
        .map(|entry| entry["dataset"].as_str().expect("an id"))
        .collect();
    assert_eq!(ids, ["quickbooks", DATASET]);

    // The connector's entry is its newest sync, sized from storage.
    let quickbooks = ConnectorSlug::new("quickbooks").expect("slug");
    let (version, _) =
        platform_connectors::snapshot::newest_manifest(&*vault, steward.tenant, &quickbooks)
            .await
            .expect("list")
            .expect("committed");
    let stored = vault
        .usage(&TenantPaths::connector_snapshot_prefix(
            steward.tenant,
            &quickbooks,
            &version,
        ))
        .await
        .expect("usage");
    assert_eq!(entries[0]["version"], version.as_str());
    assert_eq!(entries[0]["suite"], "HPK1");
    assert_eq!(entries[0]["object_count"], stored.object_count);
    assert_eq!(entries[0]["ciphertext_bytes"], stored.total_bytes);

    // Every listed dataset is one its steward may publish, and no other.
    for id in ids {
        assert!(publishable(&app, &steward, id).await, "{id}");
    }
    assert!(!publishable(&app, &steward, "upload_other").await);
}

#[tokio::test]
async fn a_dataset_whose_record_is_unreadable_is_listed_without_a_suite() {
    let vault = in_memory();
    let (app, steward) = app_over(vault.clone());
    let sealed = cohorts_upload(steward.tenant, &steward.key, DATASET, None);
    assert_eq!(upload(&app, &steward, &sealed).await, StatusCode::OK);

    // Malformed, then missing: still held, so still listed and publishable,
    // though queries refuse the snapshot.
    let record = TenantPaths::connector_record(steward.tenant, &slug(), &sealed.version);
    vault
        .put(&record, Bytes::from_static(b"not a record"))
        .await
        .expect("put");
    for missing in [false, true] {
        if missing {
            vault.delete(&record).await.expect("delete");
        }
        let entries = listed(&app, &steward.token).await;
        assert_eq!(entries.len(), 1, "{entries:?}");
        assert_eq!(entries[0]["suite"], serde_json::Value::Null);
        assert_eq!(entries[0]["version"], sealed.version.as_str());
        assert_eq!(entries[0]["objects"], object_ids(&[sealed.object]));
        assert!(publishable(&app, &steward, DATASET).await);
        assert_eq!(count(&app, &steward).await.0, StatusCode::BAD_GATEWAY);
    }
}

#[tokio::test]
async fn listing_without_an_access_token_is_401() {
    let app = build_app(AppState {
        jwt: Some(Arc::new(common::rs256_verifier())),
        ..app_state(SECRET, in_memory())
    });
    let (status, _, _) = list_datasets(&app, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    for token_type in [TokenType::Preauth, TokenType::Refresh] {
        let token = common::rs256_token(token_type, false);
        let (status, _, _) = list_datasets(&app, Some(&token)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{token_type:?}");
    }
    let token = common::rs256_token(TokenType::Access, false);
    let (status, _, body) = list_datasets(&app, Some(&token)).await;
    assert_eq!((status, body.as_slice()), (StatusCode::OK, EMPTY_LISTING));
}

#[tokio::test]
async fn a_listing_over_the_cap_is_422() {
    let cap = platform_api::MAX_LISTED_OBJECTS;
    let (steward, _) = steward();
    let version = next_version(None);
    let manifest = |dataset: &ConnectorSlug| {
        TenantPaths::connector_manifest(steward.tenant, dataset, &version)
    };
    let datasets = |count: usize| -> Vec<VaultPath> {
        (0..count)
            .map(|i| manifest(&ConnectorSlug::new(&format!("upload_{i}")).expect("slug")))
            .collect()
    };
    let one_dataset_with = |objects: usize| -> Vec<VaultPath> {
        std::iter::once(manifest(&slug()))
            .chain((0..objects).map(|_| {
                TenantPaths::connector_snapshot_object(
                    steward.tenant,
                    &slug(),
                    &version,
                    ObjectId::generate(),
                )
            }))
            .collect()
    };
    // At the cap it lists; one dataset or one object more is refused.
    for (stored, listing) in [
        (datasets(cap), Some((cap, 0))),
        (one_dataset_with(cap), Some((1, cap))),
        (datasets(cap + 1), None),
        (one_dataset_with(cap + 1), None),
    ] {
        let vault = in_memory();
        for path in &stored {
            vault
                .put(path, Bytes::from_static(b"sealed"))
                .await
                .expect("put");
        }
        let app = build_app(app_state(SECRET, vault));
        let (status, _, body) = list_datasets(&app, Some(&steward.token)).await;
        let body: serde_json::Value = serde_json::from_slice(&body).expect("json");
        match listing {
            Some((want_datasets, want_objects)) => {
                assert_eq!(status, StatusCode::OK, "{} stored", stored.len());
                let entries = body["datasets"].as_array().expect("a list");
                let objects: usize = entries
                    .iter()
                    .map(|entry| entry["objects"].as_array().expect("ids").len())
                    .sum();
                assert_eq!((entries.len(), objects), (want_datasets, want_objects));
            }
            None => {
                assert_eq!(
                    status,
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "{} stored: {body}",
                    stored.len()
                );
                assert_eq!(body["error"], "too many objects to list");
            }
        }
    }
}

#[tokio::test]
async fn a_storage_failure_fails_the_listing() {
    // Listing the tenant's datasets fails, or reading a held dataset's
    // record does, transiently (503) or not (502): an error status, never an
    // empty or partial list.
    let listing = Faults {
        list: true,
        ..Faults::default()
    };
    let record_read = Faults {
        get: true,
        ..Faults::default()
    };
    for (faults, transient) in [
        (listing, true),
        (listing, false),
        (record_read, true),
        (record_read, false),
    ] {
        let (error, expected): (fn() -> StorageError, _) = if transient {
            (common::outage, StatusCode::SERVICE_UNAVAILABLE)
        } else {
            (common::misconfigured, StatusCode::BAD_GATEWAY)
        };
        let vault = Arc::new(common::FlakyVault::new(faults, error));
        let (steward, _) = steward();
        // A committed upload, stored before the failure began.
        let slug = slug();
        let version = next_version(None);
        let record = SnapshotRecord {
            version: version.clone(),
            suite: "HPK1".to_owned(),
            row_cap: Some(7),
            schema: Some(cohorts_schema()),
        };
        for (path, bytes) in [
            (
                TenantPaths::connector_snapshot_object(
                    steward.tenant,
                    &slug,
                    &version,
                    ObjectId::generate(),
                ),
                Bytes::from_static(b"HPK1 sealed object"),
            ),
            (
                TenantPaths::connector_record(steward.tenant, &slug, &version),
                record.to_bytes(),
            ),
            (
                TenantPaths::connector_manifest(steward.tenant, &slug, &version),
                Bytes::from_static(b"HPK1 sealed manifest"),
            ),
        ] {
            vault.seed(&path, bytes).await;
        }
        let app = build_app(app_state(SECRET, vault));
        let (status, headers, body) = list_datasets(&app, Some(&steward.token)).await;
        assert_eq!(
            status,
            expected,
            "{faults:?}: {}",
            String::from_utf8_lossy(&body)
        );
        assert_eq!(
            headers.contains_key(header::RETRY_AFTER),
            expected == StatusCode::SERVICE_UNAVAILABLE,
            "{faults:?}"
        );
    }
}
