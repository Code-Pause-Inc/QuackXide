//! Drive orphan sweep: chunks without a manifest are deleted once they are
//! older than `ORPHAN_MIN_AGE`, and nothing else is touched.

mod common;

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use bytes::Bytes;
use chrono::{DateTime, TimeDelta, Utc};
use platform_api::sweep::{ORPHAN_MIN_AGE, SweepReport, sweep_orphaned_chunks};
use platform_core::{ConnectorSlug, ObjectId, SnapshotVersion, TenantId};
use platform_storage::{
    ObjectStoreVault, StorageError, StorageUsage, TenantPaths, VaultEntry, VaultPath, VaultStore,
};

/// In-memory vault that reports chosen last-modified times. It can also
/// hide manifests from listings (as a listing taken just before a manifest
/// was written would), list chunks that are already gone (as another
/// replica's sweep leaves them), mark a chunk freshly written right after
/// the first listing, and fail every delete of one object.
struct AgedVault {
    inner: ObjectStoreVault,
    ages: Mutex<HashMap<VaultPath, DateTime<Utc>>>,
    hide_manifests: bool,
    phantoms: Vec<VaultEntry>,
    rewrite_after_first_listing: Mutex<Option<VaultPath>>,
    failing_object: Option<ObjectId>,
}

impl AgedVault {
    fn new() -> Self {
        Self {
            inner: ObjectStoreVault::new_in_memory(),
            ages: Mutex::new(HashMap::new()),
            hide_manifests: false,
            phantoms: Vec::new(),
            rewrite_after_first_listing: Mutex::new(None),
            failing_object: None,
        }
    }

    /// Store `path`, reported as last modified `age` ago.
    async fn put_aged(&self, path: VaultPath, age: TimeDelta) {
        self.inner
            .put(&path, Bytes::from_static(b"ciphertext"))
            .await
            .expect("put");
        self.ages
            .lock()
            .expect("lock")
            .insert(path, Utc::now() - age);
    }

    async fn chunks(&self, tenant: TenantId, object: ObjectId, indexes: &[u32], age: TimeDelta) {
        for &index in indexes {
            self.put_aged(TenantPaths::drive_chunk(tenant, object, index), age)
                .await;
        }
    }

    async fn manifest(&self, tenant: TenantId, object: ObjectId) {
        self.put_aged(
            TenantPaths::drive_manifest(tenant, object),
            TimeDelta::zero(),
        )
        .await;
    }

    async fn left(&self, tenant: TenantId, object: ObjectId) -> usize {
        self.inner
            .list(&TenantPaths::drive_object_prefix(tenant, object))
            .await
            .expect("list")
            .len()
    }
}

#[async_trait]
impl VaultStore for AgedVault {
    async fn put(&self, path: &VaultPath, ciphertext: Bytes) -> Result<(), StorageError> {
        self.inner.put(path, ciphertext).await
    }
    async fn put_if_absent(&self, path: &VaultPath, ciphertext: Bytes) -> Result<(), StorageError> {
        self.inner.put_if_absent(path, ciphertext).await
    }
    async fn get(&self, path: &VaultPath) -> Result<Bytes, StorageError> {
        self.inner.get(path).await
    }
    async fn delete(&self, path: &VaultPath) -> Result<(), StorageError> {
        if self
            .failing_object
            .is_some_and(|o| TenantPaths::drive_chunk_parts(path).is_some_and(|(_, p)| p == o))
        {
            return Err(common::outage());
        }
        // The in-memory store deletes a missing key without error; GCS
        // reports it, as here.
        if self.phantoms.iter().any(|e| &e.path == path) {
            return Err(StorageError::NotFound);
        }
        self.inner.delete(path).await
    }
    async fn list(&self, prefix: &VaultPath) -> Result<Vec<VaultPath>, StorageError> {
        self.inner.list(prefix).await
    }
    async fn list_entries(&self, prefix: &VaultPath) -> Result<Vec<VaultEntry>, StorageError> {
        let ages = self.ages.lock().expect("lock").clone();
        let phantoms = self
            .phantoms
            .iter()
            .filter(|e| e.path.as_str().starts_with(prefix.as_str()))
            .cloned();
        let listed = self
            .inner
            .list_entries(prefix)
            .await?
            .into_iter()
            .filter(|e| {
                !(self.hide_manifests && TenantPaths::drive_manifest_parts(&e.path).is_some())
            })
            .map(|mut e| {
                if let Some(at) = ages.get(&e.path) {
                    e.last_modified = *at;
                }
                e
            })
            .chain(phantoms)
            .collect();
        if let Some(path) = self
            .rewrite_after_first_listing
            .lock()
            .expect("lock")
            .take()
        {
            self.ages.lock().expect("lock").insert(path, Utc::now());
        }
        Ok(listed)
    }
    async fn usage(&self, prefix: &VaultPath) -> Result<StorageUsage, StorageError> {
        self.inner.usage(prefix).await
    }
}

fn old() -> TimeDelta {
    ORPHAN_MIN_AGE + TimeDelta::hours(1)
}

fn recent() -> TimeDelta {
    TimeDelta::hours(1)
}

async fn sweep(vault: &dyn VaultStore) -> SweepReport {
    sweep_orphaned_chunks(vault, Utc::now())
        .await
        .expect("sweep")
}

#[tokio::test]
async fn aborted_upload_is_swept() {
    let vault = AgedVault::new();
    let (tenant, object) = (TenantId::generate(), ObjectId::generate());
    vault.chunks(tenant, object, &[0, 1, 2], old()).await;

    let report = sweep(&vault).await;
    assert_eq!(
        report,
        SweepReport {
            objects: 1,
            chunks: 3,
            recent: 0
        }
    );
    assert_eq!(vault.left(tenant, object).await, 0);
}

#[tokio::test]
async fn recent_upload_is_left_alone() {
    let vault = AgedVault::new();
    let (tenant, object) = (TenantId::generate(), ObjectId::generate());
    vault.chunks(tenant, object, &[0, 1], recent()).await;

    let report = sweep(&vault).await;
    assert_eq!(report.recent, 1);
    assert_eq!(report.objects, 0);
    assert_eq!(vault.left(tenant, object).await, 2);
}

#[tokio::test]
async fn the_newest_chunk_decides_an_objects_age() {
    // An upload still adding chunks: its first chunk is old, its last is not.
    let vault = AgedVault::new();
    let (tenant, object) = (TenantId::generate(), ObjectId::generate());
    vault.chunks(tenant, object, &[0], old()).await;
    vault.chunks(tenant, object, &[1], recent()).await;

    assert_eq!(sweep(&vault).await.recent, 1);
    assert_eq!(vault.left(tenant, object).await, 2);
}

#[tokio::test]
async fn complete_objects_are_never_swept() {
    let vault = AgedVault::new();
    let (tenant, object) = (TenantId::generate(), ObjectId::generate());
    vault.chunks(tenant, object, &[0, 1], old()).await;
    vault.manifest(tenant, object).await;

    assert_eq!(sweep(&vault).await, SweepReport::default());
    assert_eq!(vault.left(tenant, object).await, 2);
}

#[tokio::test]
async fn delete_that_failed_partway_is_finished_by_the_sweep_only_without_a_manifest() {
    let vault = AgedVault::new();
    let tenant = TenantId::generate();
    // `delete_object` deletes chunks first: a failure partway leaves the
    // manifest, so the object is the client's to retry, not the sweep's.
    let retried = ObjectId::generate();
    vault.chunks(tenant, retried, &[2], old()).await;
    vault.manifest(tenant, retried).await;
    // A delete that lost its manifest (as the manifest-first order could)
    // leaves chunks nothing points to.
    let stranded = ObjectId::generate();
    vault.chunks(tenant, stranded, &[1, 2], old()).await;

    let report = sweep(&vault).await;
    assert_eq!((report.objects, report.chunks), (1, 2));
    assert_eq!(vault.left(tenant, retried).await, 1);
    assert_eq!(vault.left(tenant, stranded).await, 0);
}

#[tokio::test]
async fn a_manifest_is_matched_only_within_its_own_tenant() {
    let vault = AgedVault::new();
    let (a, b, object) = (
        TenantId::generate(),
        TenantId::generate(),
        ObjectId::generate(),
    );
    vault.chunks(a, object, &[0], old()).await;
    vault.manifest(a, object).await;
    vault.chunks(b, object, &[0], old()).await;

    assert_eq!(sweep(&vault).await.objects, 1);
    assert_eq!(vault.left(a, object).await, 1);
    assert_eq!(vault.left(b, object).await, 0);
}

#[tokio::test]
async fn a_manifest_written_after_the_listing_saves_the_object() {
    let mut vault = AgedVault::new();
    vault.hide_manifests = true;
    let (tenant, object) = (TenantId::generate(), ObjectId::generate());
    vault.chunks(tenant, object, &[0], old()).await;
    vault.manifest(tenant, object).await;

    assert_eq!(sweep(&vault).await.objects, 0);
    assert_eq!(vault.left(tenant, object).await, 1);
}

#[tokio::test]
async fn other_tenant_data_is_ignored() {
    let vault = AgedVault::new();
    let tenant = TenantId::generate();
    let slug = ConnectorSlug::new("lab-results").expect("slug");
    let connector = TenantPaths::connector_snapshot_object(
        tenant,
        &slug,
        &SnapshotVersion::generate(),
        ObjectId::generate(),
    );
    vault.put_aged(connector.clone(), old()).await;

    assert_eq!(sweep(&vault).await, SweepReport::default());
    assert!(vault.get(&connector).await.is_ok());
}

#[tokio::test]
async fn a_listing_outage_fails_the_sweep_and_deletes_nothing() {
    let vault = common::FlakyVault::new(
        common::Faults {
            list: true,
            ..Default::default()
        },
        common::outage,
    );
    let err = sweep_orphaned_chunks(&vault, Utc::now() + old())
        .await
        .expect_err("listing fails");
    assert!(err.is_retryable());
}

#[tokio::test]
async fn a_chunk_rewritten_after_the_listing_saves_the_object() {
    let vault = AgedVault::new();
    let (tenant, object) = (TenantId::generate(), ObjectId::generate());
    vault.chunks(tenant, object, &[0, 1], old()).await;
    // The upload resumes and re-sends chunk 1 between the sweep's first
    // listing and its deletes.
    *vault.rewrite_after_first_listing.lock().expect("lock") =
        Some(TenantPaths::drive_chunk(tenant, object, 1));

    let report = sweep(&vault).await;
    assert_eq!((report.objects, report.recent), (0, 1));
    assert_eq!(vault.left(tenant, object).await, 2);
}

#[tokio::test]
async fn chunks_already_deleted_are_not_counted() {
    // Another replica swept the object between this run's listing and its
    // deletes: nothing is deleted, so nothing is reported.
    let tenant = TenantId::generate();
    let object = ObjectId::generate();
    let mut vault = AgedVault::new();
    vault.phantoms = (0..2)
        .map(|i| VaultEntry {
            path: TenantPaths::drive_chunk(tenant, object, i),
            size: 10,
            last_modified: Utc::now() - old(),
        })
        .collect();

    assert_eq!(sweep(&vault).await, SweepReport::default());
}

#[tokio::test]
async fn one_failing_object_does_not_stop_the_others() {
    let tenant = TenantId::generate();
    let (stuck, other) = (ObjectId::generate(), ObjectId::generate());
    let mut vault = AgedVault::new();
    vault.failing_object = Some(stuck);
    vault.chunks(tenant, stuck, &[0], old()).await;
    vault.chunks(tenant, other, &[0, 1], old()).await;

    let err = sweep_orphaned_chunks(&vault, Utc::now())
        .await
        .expect_err("the stuck object's error is returned");
    assert!(err.is_retryable());
    assert_eq!(vault.left(tenant, other).await, 0);
    assert_eq!(vault.left(tenant, stuck).await, 1);
}

/// An upload that paused past `ORPHAN_MIN_AGE` had its first chunks swept.
/// When it resumes, its manifest is refused instead of committing a file
/// that cannot be downloaded.
#[tokio::test]
async fn a_swept_upload_cannot_commit_its_manifest() {
    use axum::http::StatusCode;
    const SECRET: &str = "sweep-test-secret";

    let vault = std::sync::Arc::new(AgedVault::new());
    let app = platform_api::build_app(common::app_state(SECRET, vault.clone()));
    let tenant = TenantId::generate();
    let object = ObjectId::generate();
    let token = common::token_for(SECRET, tenant);

    vault.chunks(tenant, object, &[0, 1], old()).await;
    assert_eq!(sweep(vault.as_ref()).await.chunks, 2);

    // The tab wakes, sends the last chunk, then the manifest.
    let chunk = vec![0u8; 28];
    let (status, _) = common::send(
        &app,
        "PUT",
        &format!("/api/v1/drive/objects/{object}/chunks/2"),
        &[
            common::bearer(&token),
            common::content_type("application/octet-stream"),
        ],
        chunk,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let manifest = serde_json::json!({
        "wrapped_key": { "iv_b64": "AAAAAAAAAAAAAAAA", "data_b64": "d3JhcHBlZC1rZXk=" },
        "manifest":    { "iv_b64": "AAAAAAAAAAAAAAAA", "data_b64": "bWFuaWZlc3QtY3Q=" },
        "chunk_count": 3,
        "encrypted_size_bytes": 84,
        "created_at_iso": "2026-07-30T12:00:00.000Z"
    });
    let (status, _) = common::send(
        &app,
        "PUT",
        &format!("/api/v1/drive/objects/{object}/manifest"),
        &[common::bearer(&token), common::json_header()],
        manifest.to_string().into_bytes(),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    let (status, body) = common::send(
        &app,
        "GET",
        "/api/v1/drive/objects",
        &[common::bearer(&token)],
        Vec::new(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"[]".to_vec(), "a refused manifest is not listed");
}
