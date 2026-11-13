//! Steward dataset uploads (`PUT /api/v1/datasets/{dataset}`, ADR 0012): a
//! browser-sealed upload is stored as the dataset's new snapshot and is
//! queryable in the enclave; a re-upload replaces it; an upload that fails
//! partway is never visible. Refusals: no or non-access token (401), a
//! malformed body (422), an oversized one (413), a declared schema that
//! differs from the recorded one (422), a stale version (409), a dataset id
//! outside the upload namespace (404), a storage outage (503), and data
//! that does not match its declaration (502, in the enclave).

mod common;

use std::sync::Arc;

use async_trait::async_trait;
use axum::Router;
use axum::http::{StatusCode, header};
use bytes::Bytes;
use platform_api::{AppState, build_app};
use platform_auth::TokenType;
use platform_config::PlatformConfig;
use platform_core::{ColumnType, ConnectorSlug, SnapshotVersion, TenantId};
use platform_crypto::{TenantKeypair, TenantPublicKey};
use platform_storage::{
    ObjectStoreVault, StorageError, StorageUsage, TenantPaths, VaultEntry, VaultPath, VaultStore,
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

    // The first attempt stops before its manifest.
    let failed = sealed_upload(
        steward.tenant,
        &steward.key,
        DATASET,
        version.clone(),
        &common::cohorts_parquet(),
        cohorts_schema(),
        7,
    );
    assert_eq!(
        upload(&app, &steward, &failed).await,
        StatusCode::SERVICE_UNAVAILABLE
    );

    // The retry at the same version seals other rows under a new object id.
    // It commits, and the failed attempt's object is pruned.
    vault.fail.store(false, std::sync::atomic::Ordering::SeqCst);
    let rows = synth_cohort(8);
    let retry = sealed_upload(
        steward.tenant,
        &steward.key,
        DATASET,
        version,
        &rows,
        cohorts_schema(),
        8,
    );
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
