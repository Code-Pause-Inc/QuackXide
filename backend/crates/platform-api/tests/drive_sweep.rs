//! Drive orphan sweep: chunks without a manifest are deleted once they are
//! older than `ORPHAN_MIN_AGE`, and nothing else is touched. A manifest is
//! never committed over chunks the sweep deleted, whichever of the two runs
//! first.

mod common;

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

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
/// the first listing, and fail every delete of one object. A [`Hook`] runs
/// other work at a chosen point inside one call, to interleave an upload
/// with a sweep.
struct AgedVault {
    inner: ObjectStoreVault,
    ages: Mutex<HashMap<VaultPath, DateTime<Utc>>>,
    hide_manifests: bool,
    phantoms: Vec<VaultEntry>,
    rewrite_after_first_listing: Mutex<Option<VaultPath>>,
    failing_object: Option<ObjectId>,
    /// Runs once, before the first chunk delete.
    before_chunk_delete: Hook,
    /// Runs once, before the first create-only manifest write.
    before_manifest_write: Hook,
    /// Runs once, after the first create-only manifest write.
    after_manifest_write: Hook,
}

type Hook = Mutex<Option<Pin<Box<dyn Future<Output = ()> + Send>>>>;

fn set(hook: &Hook, work: impl Future<Output = ()> + Send + 'static) {
    *hook.lock().expect("lock") = Some(Box::pin(work));
}

async fn run(hook: &Hook) {
    let work = hook.lock().expect("lock").take();
    if let Some(work) = work {
        work.await;
    }
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
            before_chunk_delete: Mutex::new(None),
            before_manifest_write: Mutex::new(None),
            after_manifest_write: Mutex::new(None),
        }
    }

    async fn marker_held(&self, tenant: TenantId, object: ObjectId) -> bool {
        self.inner
            .get(&TenantPaths::drive_sweep_marker(tenant, object))
            .await
            .is_ok()
    }

    async fn has_manifest(&self, tenant: TenantId, object: ObjectId) -> bool {
        self.inner
            .get(&TenantPaths::drive_manifest(tenant, object))
            .await
            .is_ok()
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
        if TenantPaths::drive_manifest_parts(path).is_none() {
            return self.inner.put_if_absent(path, ciphertext).await;
        }
        run(&self.before_manifest_write).await;
        let written = self.inner.put_if_absent(path, ciphertext).await;
        run(&self.after_manifest_write).await;
        written
    }
    async fn get(&self, path: &VaultPath) -> Result<Bytes, StorageError> {
        self.inner.get(path).await
    }
    async fn delete(&self, path: &VaultPath) -> Result<(), StorageError> {
        if TenantPaths::drive_chunk_parts(path).is_some() {
            run(&self.before_chunk_delete).await;
        }
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
    assert!(!vault.marker_held(tenant, object).await);
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
    assert!(!vault.marker_held(tenant, object).await);
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
    assert!(!vault.marker_held(tenant, object).await);
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
    // A failed object is released, so the next run can try it again.
    assert!(!vault.marker_held(tenant, stuck).await);
}

const SECRET: &str = "sweep-test-secret";

fn app(vault: &Arc<AgedVault>) -> axum::Router {
    platform_api::build_app(common::app_state(SECRET, vault.clone()))
}

/// Commit a manifest for `chunk_count` chunks through the API.
async fn put_manifest(
    app: &axum::Router,
    tenant: TenantId,
    object: ObjectId,
    chunk_count: u32,
) -> axum::http::StatusCode {
    let manifest = serde_json::json!({
        "wrapped_key": { "iv_b64": "AAAAAAAAAAAAAAAA", "data_b64": "d3JhcHBlZC1rZXk=" },
        "manifest":    { "iv_b64": "AAAAAAAAAAAAAAAA", "data_b64": "bWFuaWZlc3QtY3Q=" },
        "chunk_count": chunk_count,
        "encrypted_size_bytes": 28 * u64::from(chunk_count),
        "created_at_iso": "2026-07-30T12:00:00.000Z"
    });
    let (status, _) = common::send(
        app,
        "PUT",
        &format!("/api/v1/drive/objects/{object}/manifest"),
        &[
            common::bearer(&common::token_for(SECRET, tenant)),
            common::json_header(),
        ],
        manifest.to_string().into_bytes(),
    )
    .await;
    status
}

async fn listing(app: &axum::Router, tenant: TenantId) -> Vec<u8> {
    let (status, body) = common::send(
        app,
        "GET",
        "/api/v1/drive/objects",
        &[common::bearer(&common::token_for(SECRET, tenant))],
        Vec::new(),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK);
    body
}

/// An upload that paused past `ORPHAN_MIN_AGE` had its first chunks swept.
/// When it resumes, its manifest is refused instead of committing a file
/// that cannot be downloaded.
#[tokio::test]
async fn a_swept_upload_cannot_commit_its_manifest() {
    use axum::http::StatusCode;

    let vault = Arc::new(AgedVault::new());
    let app = app(&vault);
    let tenant = TenantId::generate();
    let object = ObjectId::generate();

    vault.chunks(tenant, object, &[0, 1], old()).await;
    assert_eq!(sweep(vault.as_ref()).await.chunks, 2);

    // The tab wakes, sends the last chunk, then the manifest.
    let (status, _) = common::send(
        &app,
        "PUT",
        &format!("/api/v1/drive/objects/{object}/chunks/2"),
        &[
            common::bearer(&common::token_for(SECRET, tenant)),
            common::content_type("application/octet-stream"),
        ],
        vec![0u8; 28],
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        put_manifest(&app, tenant, object, 3).await,
        StatusCode::CONFLICT
    );
    assert_eq!(
        listing(&app, tenant).await,
        b"[]".to_vec(),
        "a refused manifest is not listed"
    );
}

/// The manifest arrives while the sweep is deleting the object's chunks:
/// after the sweep's manifest check, before its first delete. The sweep
/// holds the object, so the manifest is refused.
#[tokio::test]
async fn a_manifest_sent_while_the_sweep_deletes_is_refused() {
    use axum::http::StatusCode;

    let vault = Arc::new(AgedVault::new());
    let app = app(&vault);
    let (tenant, object) = (TenantId::generate(), ObjectId::generate());
    vault.chunks(tenant, object, &[0, 1], old()).await;

    let status = Arc::new(Mutex::new(None));
    let seen = status.clone();
    let upload = app.clone();
    set(&vault.before_chunk_delete, async move {
        let status = put_manifest(&upload, tenant, object, 2).await;
        *seen.lock().expect("lock") = Some(status);
    });

    let report = sweep(vault.as_ref()).await;
    assert_eq!((report.objects, report.chunks), (1, 2));
    assert_eq!(*status.lock().expect("lock"), Some(StatusCode::CONFLICT));
    assert!(!vault.has_manifest(tenant, object).await);
    assert!(!vault.marker_held(tenant, object).await);
    assert_eq!(listing(&app, tenant).await, b"[]".to_vec());
}

/// A whole sweep runs between the manifest handler's first check and its
/// write. The handler's second check finds the chunks gone and takes the
/// manifest back.
#[tokio::test]
async fn a_manifest_written_over_swept_chunks_is_taken_back() {
    use axum::http::StatusCode;

    let vault = Arc::new(AgedVault::new());
    let app = app(&vault);
    let (tenant, object) = (TenantId::generate(), ObjectId::generate());
    vault.chunks(tenant, object, &[0, 1], old()).await;

    let swept = Arc::new(Mutex::new(None));
    let seen = swept.clone();
    let sweeper = vault.clone();
    set(&vault.before_manifest_write, async move {
        let report = sweep(sweeper.as_ref()).await;
        *seen.lock().expect("lock") = Some(report.chunks);
    });

    assert_eq!(
        put_manifest(&app, tenant, object, 2).await,
        StatusCode::CONFLICT
    );
    assert_eq!(*swept.lock().expect("lock"), Some(2));
    assert!(!vault.has_manifest(tenant, object).await);
    assert_eq!(listing(&app, tenant).await, b"[]".to_vec());
}

/// The sweep has claimed the object and found no manifest, and is still
/// deleting when the manifest is written. The handler's second check finds
/// the claim and takes the manifest back, although every chunk it names is
/// still stored at that moment.
#[tokio::test]
async fn a_manifest_written_under_a_claim_is_taken_back() {
    use axum::http::StatusCode;

    let vault = Arc::new(AgedVault::new());
    let app = app(&vault);
    let (tenant, object) = (TenantId::generate(), ObjectId::generate());
    vault.chunks(tenant, object, &[0, 1], old()).await;

    let claimer = vault.clone();
    set(&vault.before_manifest_write, async move {
        claimer
            .put_if_absent(
                &TenantPaths::drive_sweep_marker(tenant, object),
                Bytes::from_static(b"sweeping"),
            )
            .await
            .expect("claim");
    });

    assert_eq!(
        put_manifest(&app, tenant, object, 2).await,
        StatusCode::CONFLICT
    );
    assert!(!vault.has_manifest(tenant, object).await);
    assert_eq!(vault.left(tenant, object).await, 2);
}

/// The sweep starts just after the manifest is written. It claims the
/// object, finds the manifest and deletes nothing, so the upload commits.
#[tokio::test]
async fn a_sweep_that_starts_after_the_manifest_is_written_deletes_nothing() {
    use axum::http::StatusCode;

    // The sweep's listing predates the manifest.
    let mut vault = AgedVault::new();
    vault.hide_manifests = true;
    let vault = Arc::new(vault);
    let app = app(&vault);
    let (tenant, object) = (TenantId::generate(), ObjectId::generate());
    vault.chunks(tenant, object, &[0, 1], old()).await;

    let swept = Arc::new(Mutex::new(None));
    let seen = swept.clone();
    let sweeper = vault.clone();
    set(&vault.after_manifest_write, async move {
        *seen.lock().expect("lock") = Some(sweep(sweeper.as_ref()).await);
    });

    assert_eq!(
        put_manifest(&app, tenant, object, 2).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(*swept.lock().expect("lock"), Some(SweepReport::default()));
    assert_eq!(vault.left(tenant, object).await, 2);
    assert!(vault.has_manifest(tenant, object).await);
    assert!(!vault.marker_held(tenant, object).await);
}

#[tokio::test]
async fn a_claimed_object_is_left_to_the_run_that_holds_it() {
    use axum::http::StatusCode;

    let vault = Arc::new(AgedVault::new());
    let app = app(&vault);
    let (tenant, object) = (TenantId::generate(), ObjectId::generate());
    vault.chunks(tenant, object, &[0, 1], old()).await;
    vault
        .put_aged(TenantPaths::drive_sweep_marker(tenant, object), recent())
        .await;

    assert_eq!(sweep(vault.as_ref()).await, SweepReport::default());
    assert_eq!(vault.left(tenant, object).await, 2);
    assert!(vault.marker_held(tenant, object).await);
    assert_eq!(
        put_manifest(&app, tenant, object, 2).await,
        StatusCode::CONFLICT
    );
    assert!(!vault.has_manifest(tenant, object).await);
}

/// A run that stopped partway left its marker. Once the marker is older
/// than `ORPHAN_MIN_AGE` the next run removes it and sweeps the object.
#[tokio::test]
async fn a_stale_marker_is_removed_and_its_object_swept() {
    let vault = AgedVault::new();
    let (tenant, object) = (TenantId::generate(), ObjectId::generate());
    vault.chunks(tenant, object, &[0, 1], old()).await;
    vault
        .put_aged(TenantPaths::drive_sweep_marker(tenant, object), old())
        .await;

    let report = sweep(&vault).await;
    assert_eq!((report.objects, report.chunks), (1, 2));
    assert_eq!(vault.left(tenant, object).await, 0);
    assert!(!vault.marker_held(tenant, object).await);
}

/// A stale marker whose object has nothing left to sweep is still removed,
/// so a new upload of that object is not refused for ever.
#[tokio::test]
async fn a_stale_marker_without_chunks_is_removed() {
    let vault = AgedVault::new();
    let (tenant, object) = (TenantId::generate(), ObjectId::generate());
    vault
        .put_aged(TenantPaths::drive_sweep_marker(tenant, object), old())
        .await;

    assert_eq!(sweep(&vault).await, SweepReport::default());
    assert!(!vault.marker_held(tenant, object).await);
}
