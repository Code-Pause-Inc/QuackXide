//! Tenant-isolated ciphertext vault over object storage.
//!
//! Layout inside `gs://{STORAGE_BUCKET}/`:
//!
//! ```text
//! tenants/{tenant_id}/drive/manifests/{object_id}.json
//! tenants/{tenant_id}/drive/objects/{object_id}/{chunk_index:08}
//! tenants/{tenant_id}/connectors/{connector_slug}/{object_id}.parquet
//! ```
//!
//! Invariants:
//! 1. Every path is built through [`TenantPaths`] from typed, validated ids;
//!    the vault never accepts a raw string path.
//! 2. The vault stores ciphertext only. Object names are opaque UUIDs; user
//!    filenames live inside the client-encrypted manifest.
//! 3. `object_store` matches list prefixes by whole path parts, so a prefix
//!    for tenant `abc…` can never match tenant `abcd…`.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use futures::TryStreamExt;
use object_store::gcp::GoogleCloudStorageBuilder;
use object_store::memory::InMemory;
use object_store::path::Path as StorePath;
use object_store::{
    BackoffConfig, ClientOptions, ObjectStore, ObjectStoreExt, PutMode, PutOptions, PutPayload,
    RetryConfig,
};
use platform_config::StorageClientConfig;
use platform_core::{ConnectorSlug, ObjectId, SnapshotVersion, TenantId};

/// A storage path that can only be constructed through [`TenantPaths`] (or
/// returned from a listing).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VaultPath(String);

impl VaultPath {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for VaultPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The only factory for [`VaultPath`]s — the type-level tenant boundary.
pub struct TenantPaths;

impl TenantPaths {
    /// Prefix owning everything a tenant stores (provisioning/teardown).
    pub fn tenant_root(tenant: TenantId) -> VaultPath {
        VaultPath(format!("tenants/{tenant}"))
    }

    /// Encrypted manifest of one drive object.
    pub fn drive_manifest(tenant: TenantId, object: ObjectId) -> VaultPath {
        VaultPath(format!("tenants/{tenant}/drive/manifests/{object}.json"))
    }

    /// Prefix of all drive manifests for a tenant (listing).
    pub fn drive_manifest_prefix(tenant: TenantId) -> VaultPath {
        VaultPath(format!("tenants/{tenant}/drive/manifests"))
    }

    /// One encrypted chunk of a drive object.
    pub fn drive_chunk(tenant: TenantId, object: ObjectId, chunk_index: u32) -> VaultPath {
        VaultPath(format!(
            "tenants/{tenant}/drive/objects/{object}/{chunk_index:08}"
        ))
    }

    /// Prefix of all chunks of one drive object (deletion).
    pub fn drive_object_prefix(tenant: TenantId, object: ObjectId) -> VaultPath {
        VaultPath(format!("tenants/{tenant}/drive/objects/{object}"))
    }

    /// An enclave-encrypted Parquet object produced by a connector sync.
    /// One sealed object of a connector snapshot. A snapshot is complete
    /// only once its manifest exists.
    pub fn connector_snapshot_object(
        tenant: TenantId,
        connector: &ConnectorSlug,
        version: &SnapshotVersion,
        object: ObjectId,
    ) -> VaultPath {
        VaultPath(format!(
            "tenants/{tenant}/connectors/{connector}/snapshots/{version}/{object}.parquet"
        ))
    }

    /// Every snapshot's objects for one tenant-connector pair.
    pub fn connector_snapshots_prefix(tenant: TenantId, connector: &ConnectorSlug) -> VaultPath {
        VaultPath(format!("tenants/{tenant}/connectors/{connector}/snapshots"))
    }

    /// The sealed manifest that commits a snapshot, written last.
    pub fn connector_manifest(
        tenant: TenantId,
        connector: &ConnectorSlug,
        version: &SnapshotVersion,
    ) -> VaultPath {
        VaultPath(format!(
            "tenants/{tenant}/connectors/{connector}/manifests/{version}.manifest"
        ))
    }

    /// Every committed snapshot's manifest for one tenant-connector pair.
    pub fn connector_manifests_prefix(tenant: TenantId, connector: &ConnectorSlug) -> VaultPath {
        VaultPath(format!("tenants/{tenant}/connectors/{connector}/manifests"))
    }

    /// Prefix of all objects for one tenant-connector pair (query listing).
    pub fn connector_prefix(tenant: TenantId, connector: &ConnectorSlug) -> VaultPath {
        VaultPath(format!("tenants/{tenant}/connectors/{connector}"))
    }

    /// Control-plane provisioning marker. Lives outside the tenant's data
    /// prefix, so it never counts toward usage and no tenant-scoped
    /// operation reaches it.
    pub fn control_marker(tenant: TenantId) -> VaultPath {
        VaultPath(format!("control/tenants/{tenant}.json"))
    }

    /// Prefix that holds nothing. Readiness lists it to check the store is
    /// reachable without listing anything real.
    pub fn readiness_probe() -> VaultPath {
        VaultPath("control/readiness".to_owned())
    }

    /// A tenant's enrolled HPKE public key, read by enclave pipelines to seal
    /// connector data to the tenant.
    pub fn tenant_enrollment(tenant: TenantId) -> VaultPath {
        VaultPath(format!("control/enrollments/{tenant}.json"))
    }

    /// Recover the snapshot version from a
    /// [`connector_manifest`](Self::connector_manifest) path; `None` if it is
    /// not one for this tenant and connector.
    pub fn connector_manifest_version(
        tenant: TenantId,
        connector: &ConnectorSlug,
        path: &VaultPath,
    ) -> Option<SnapshotVersion> {
        let prefix = Self::connector_manifests_prefix(tenant, connector);
        path.as_str()
            .strip_prefix(prefix.as_str())?
            .strip_prefix('/')?
            .strip_suffix(".manifest")?
            .parse()
            .ok()
    }

    /// Recover the snapshot version and object of a
    /// [`connector_snapshot_object`](Self::connector_snapshot_object) path.
    pub fn connector_snapshot_object_parts(
        tenant: TenantId,
        connector: &ConnectorSlug,
        path: &VaultPath,
    ) -> Option<(SnapshotVersion, ObjectId)> {
        let prefix = Self::connector_snapshots_prefix(tenant, connector);
        let (version, object) = path
            .as_str()
            .strip_prefix(prefix.as_str())?
            .strip_prefix('/')?
            .strip_suffix(".parquet")?
            .split_once('/')?;
        Some((version.parse().ok()?, object.parse().ok()?))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("object not found")]
    NotFound,
    /// A create-only write found an object already at the path.
    #[error("object already exists")]
    AlreadyExists,
    /// A conditional write's precondition did not hold.
    #[error("storage precondition failed")]
    PreconditionFailed,
    /// Transient: the backend failed or could not be reached after the
    /// client's own retries. The same request may succeed later.
    #[error("storage backend unavailable: {0}")]
    Unavailable(String),
    /// Permanent until an operator acts: credentials, permissions, an
    /// invalid path, an unsupported operation or configuration. Retrying
    /// the same request does not help.
    #[error("storage backend failed: {0}")]
    Fatal(String),
}

impl StorageError {
    /// Whether the same request may succeed if retried later.
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Unavailable(_))
    }
}

/// Aggregate ciphertext footprint under a prefix (admin storage reporting).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StorageUsage {
    pub object_count: u64,
    pub total_bytes: u64,
}

/// Ciphertext-only vault operations. Implementations treat payloads as
/// opaque bytes: no inspection, no decryption, no plaintext spill to disk.
#[async_trait]
pub trait VaultStore: Send + Sync {
    async fn put(&self, path: &VaultPath, ciphertext: Bytes) -> Result<(), StorageError>;
    /// Create-only write: stores `ciphertext` only if nothing exists at
    /// `path`, and otherwise fails with [`StorageError::AlreadyExists`]
    /// without touching the stored object. The check and the write are one
    /// atomic backend operation.
    async fn put_if_absent(&self, path: &VaultPath, ciphertext: Bytes) -> Result<(), StorageError>;
    async fn get(&self, path: &VaultPath) -> Result<Bytes, StorageError>;
    async fn delete(&self, path: &VaultPath) -> Result<(), StorageError>;
    async fn list(&self, prefix: &VaultPath) -> Result<Vec<VaultPath>, StorageError>;
    /// Object count and total ciphertext bytes under `prefix`.
    async fn usage(&self, prefix: &VaultPath) -> Result<StorageUsage, StorageError>;
}

/// [`VaultStore`] over any `object_store` backend: GCS in production,
/// in-memory for local dev and tests.
pub struct ObjectStoreVault {
    store: Arc<dyn ObjectStore>,
}

impl ObjectStoreVault {
    /// Vault over an already-built `object_store` backend.
    pub fn new(store: Arc<dyn ObjectStore>) -> Self {
        Self { store }
    }

    /// Dev/test backend; contents vanish on process exit.
    pub fn new_in_memory() -> Self {
        Self::new(Arc::new(InMemory::new()))
    }

    /// Google Cloud Storage backend. Credentials resolve from the environment
    /// or the GCE metadata server unless `STORAGE_EMULATOR_HOST` points at a
    /// local GCS emulator (`fsouza/fake-gcs-server`). Timeouts and retries
    /// come from `client`, never from `object_store`'s defaults.
    pub fn new_gcs(bucket: &str, client: &StorageClientConfig) -> Result<Self, StorageError> {
        let emulator = std::env::var("STORAGE_EMULATOR_HOST").ok();
        Self::new_gcs_with_emulator(bucket, emulator.as_deref(), client)
    }

    /// Construct a GCS-backed vault with an optional local emulator host
    /// override. Plain HTTP is allowed only to an emulator.
    pub fn new_gcs_with_emulator(
        bucket: &str,
        emulator_host: Option<&str>,
        client: &StorageClientConfig,
    ) -> Result<Self, StorageError> {
        let mut options = ClientOptions::new()
            .with_timeout(client.request_timeout)
            .with_connect_timeout(client.connect_timeout)
            .with_allow_http(false);
        let mut builder = GoogleCloudStorageBuilder::from_env()
            .with_bucket_name(bucket)
            .with_retry(RetryConfig {
                backoff: BackoffConfig {
                    max_backoff: client.max_backoff(),
                    ..BackoffConfig::default()
                },
                max_retries: client.max_retries as usize,
                retry_timeout: client.retry_timeout,
            });
        if let Some(raw_host) = emulator_host {
            let trimmed = raw_host.trim().trim_end_matches('/');
            if !trimmed.is_empty() {
                let base_url = if trimmed.starts_with("http://") || trimmed.starts_with("https://")
                {
                    trimmed.to_owned()
                } else {
                    format!("http://{trimmed}")
                };
                options = options.with_allow_http(base_url.starts_with("http://"));
                builder = builder.with_base_url(&base_url).with_skip_signature(true);
            }
        }
        let builder = builder.with_client_options(options);
        let store = builder
            .build()
            .map_err(|e| StorageError::Fatal(e.to_string()))?;
        Ok(Self::new(Arc::new(store)))
    }

    async fn list_meta(
        &self,
        prefix: &VaultPath,
    ) -> Result<Vec<object_store::ObjectMeta>, StorageError> {
        self.store
            .list(Some(&store_path(prefix)))
            .try_collect()
            .await
            .map_err(map_err)
    }
}

fn store_path(path: &VaultPath) -> StorePath {
    StorePath::from(path.as_str())
}

/// Classify an `object_store` error. Its HTTP client has already retried
/// 5xx, 429 and timeouts and turns 401, 403, 404, 409 and 412 into their own
/// variants, so `Generic` is a failure that outlasted those retries.
/// Anything not known to be transient is fatal.
fn map_err(err: object_store::Error) -> StorageError {
    use object_store::Error as E;
    match err {
        E::NotFound { .. } => StorageError::NotFound,
        E::AlreadyExists { .. } => StorageError::AlreadyExists,
        E::Precondition { .. } => StorageError::PreconditionFailed,
        E::Generic { .. } | E::JoinError { .. } => StorageError::Unavailable(err.to_string()),
        other => StorageError::Fatal(other.to_string()),
    }
}

#[async_trait]
impl VaultStore for ObjectStoreVault {
    async fn put(&self, path: &VaultPath, ciphertext: Bytes) -> Result<(), StorageError> {
        self.store
            .put(&store_path(path), PutPayload::from(ciphertext))
            .await
            .map(|_| ())
            .map_err(map_err)
    }

    /// `PutMode::Create`: `InMemory` checks natively; GCS sends
    /// `x-goog-if-generation-match: 0`.
    async fn put_if_absent(&self, path: &VaultPath, ciphertext: Bytes) -> Result<(), StorageError> {
        self.store
            .put_opts(
                &store_path(path),
                PutPayload::from(ciphertext),
                PutOptions::from(PutMode::Create),
            )
            .await
            .map(|_| ())
            .map_err(map_err)
    }

    async fn get(&self, path: &VaultPath) -> Result<Bytes, StorageError> {
        self.store
            .get(&store_path(path))
            .await
            .map_err(map_err)?
            .bytes()
            .await
            .map_err(map_err)
    }

    async fn delete(&self, path: &VaultPath) -> Result<(), StorageError> {
        self.store.delete(&store_path(path)).await.map_err(map_err)
    }

    async fn list(&self, prefix: &VaultPath) -> Result<Vec<VaultPath>, StorageError> {
        Ok(self
            .list_meta(prefix)
            .await?
            .into_iter()
            .map(|meta| VaultPath(meta.location.to_string()))
            .collect())
    }

    async fn usage(&self, prefix: &VaultPath) -> Result<StorageUsage, StorageError> {
        let metas = self.list_meta(prefix).await?;
        Ok(StorageUsage {
            object_count: metas.len() as u64,
            total_bytes: metas.iter().map(|m| m.size).sum(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;
    use std::str::FromStr;

    fn tenant_a() -> TenantId {
        TenantId::from_str("6f2c8a2e-1111-4222-8333-444455556666").expect("valid uuid")
    }

    fn tenant_b() -> TenantId {
        TenantId::from_str("0d9e7c66-2222-4333-8444-555566667777").expect("valid uuid")
    }

    fn object_1() -> ObjectId {
        ObjectId::from_str("00000000-aaaa-4bbb-8ccc-000000000001").expect("valid uuid")
    }

    #[test]
    fn drive_paths_are_tenant_scoped_and_canonical() {
        assert_eq!(
            TenantPaths::drive_manifest(tenant_a(), object_1()).as_str(),
            "tenants/6f2c8a2e-1111-4222-8333-444455556666/drive/manifests/00000000-aaaa-4bbb-8ccc-000000000001.json"
        );
        assert_eq!(
            TenantPaths::drive_chunk(tenant_a(), object_1(), 3).as_str(),
            "tenants/6f2c8a2e-1111-4222-8333-444455556666/drive/objects/00000000-aaaa-4bbb-8ccc-000000000001/00000003"
        );
    }

    fn version_1() -> SnapshotVersion {
        "00000000000000000001-0123456789abcdef0123456789abcdef"
            .parse()
            .expect("valid version")
    }

    #[test]
    fn connector_snapshot_paths_are_canonical_and_round_trip() {
        let slug = ConnectorSlug::new("quickbooks").expect("valid slug");
        let object =
            TenantPaths::connector_snapshot_object(tenant_a(), &slug, &version_1(), object_1());
        assert_eq!(
            object.as_str(),
            "tenants/6f2c8a2e-1111-4222-8333-444455556666/connectors/quickbooks/snapshots/00000000000000000001-0123456789abcdef0123456789abcdef/00000000-aaaa-4bbb-8ccc-000000000001.parquet"
        );
        assert_eq!(
            TenantPaths::connector_snapshot_object_parts(tenant_a(), &slug, &object),
            Some((version_1(), object_1()))
        );
        let manifest = TenantPaths::connector_manifest(tenant_a(), &slug, &version_1());
        assert_eq!(
            manifest.as_str(),
            "tenants/6f2c8a2e-1111-4222-8333-444455556666/connectors/quickbooks/manifests/00000000000000000001-0123456789abcdef0123456789abcdef.manifest"
        );
        assert_eq!(
            TenantPaths::connector_manifest_version(tenant_a(), &slug, &manifest),
            Some(version_1())
        );
        for path in [&object, &manifest] {
            assert!(
                path.as_str()
                    .starts_with(TenantPaths::connector_prefix(tenant_a(), &slug).as_str())
            );
        }
    }

    #[test]
    fn foreign_or_malformed_connector_paths_do_not_parse() {
        let slug = ConnectorSlug::new("quickbooks").expect("valid slug");
        let other = ConnectorSlug::new("stripe").expect("valid slug");
        let object =
            TenantPaths::connector_snapshot_object(tenant_a(), &slug, &version_1(), object_1());
        let manifest = TenantPaths::connector_manifest(tenant_a(), &slug, &version_1());
        assert_eq!(
            TenantPaths::connector_snapshot_object_parts(tenant_a(), &other, &object),
            None
        );
        assert_eq!(
            TenantPaths::connector_manifest_version(tenant_a(), &other, &manifest),
            None
        );
        assert_eq!(
            TenantPaths::connector_manifest_version(tenant_a(), &slug, &object),
            None
        );
        assert_eq!(
            TenantPaths::connector_snapshot_object_parts(tenant_a(), &slug, &manifest),
            None
        );
    }

    #[test]
    fn tenant_root_is_a_prefix_of_every_tenant_path() {
        let root = TenantPaths::tenant_root(tenant_a());
        for path in [
            TenantPaths::drive_manifest(tenant_a(), object_1()),
            TenantPaths::drive_chunk(tenant_a(), object_1(), 0),
            TenantPaths::drive_object_prefix(tenant_a(), object_1()),
        ] {
            assert!(path.as_str().starts_with(root.as_str()));
        }
    }

    #[tokio::test]
    async fn vault_round_trips_and_maps_not_found() {
        let vault = ObjectStoreVault::new_in_memory();
        let path = TenantPaths::drive_chunk(tenant_a(), object_1(), 0);

        assert!(matches!(
            vault.get(&path).await,
            Err(StorageError::NotFound)
        ));

        vault
            .put(&path, Bytes::from_static(b"ciphertext"))
            .await
            .expect("put");
        assert_eq!(
            vault.get(&path).await.expect("get"),
            Bytes::from_static(b"ciphertext")
        );

        vault.delete(&path).await.expect("delete");
        assert!(matches!(
            vault.get(&path).await,
            Err(StorageError::NotFound)
        ));
    }

    #[tokio::test]
    async fn usage_counts_objects_and_bytes_under_prefix() {
        let vault = ObjectStoreVault::new_in_memory();
        vault
            .put(
                &TenantPaths::drive_chunk(tenant_a(), object_1(), 0),
                Bytes::from_static(b"0123456789"),
            )
            .await
            .expect("put");
        vault
            .put(
                &TenantPaths::drive_chunk(tenant_a(), object_1(), 1),
                Bytes::from_static(b"abc"),
            )
            .await
            .expect("put");

        let usage = vault
            .usage(&TenantPaths::tenant_root(tenant_a()))
            .await
            .expect("usage");
        assert_eq!(usage.object_count, 2);
        assert_eq!(usage.total_bytes, 13);

        let empty = vault
            .usage(&TenantPaths::tenant_root(tenant_b()))
            .await
            .expect("usage");
        assert_eq!(empty, StorageUsage::default());
    }

    #[tokio::test]
    async fn listing_is_isolated_per_tenant_prefix() {
        let vault = ObjectStoreVault::new_in_memory();
        let a_path = TenantPaths::drive_manifest(tenant_a(), object_1());
        let b_path = TenantPaths::drive_manifest(tenant_b(), object_1());
        vault
            .put(&a_path, Bytes::from_static(b"a"))
            .await
            .expect("put a");
        vault
            .put(&b_path, Bytes::from_static(b"b"))
            .await
            .expect("put b");

        let a_list = vault
            .list(&TenantPaths::drive_manifest_prefix(tenant_a()))
            .await
            .expect("list a");
        assert_eq!(a_list.len(), 1);
        assert_eq!(a_list[0], a_path);

        let b_list = vault
            .list(&TenantPaths::drive_manifest_prefix(tenant_b()))
            .await
            .expect("list b");
        assert_eq!(b_list.len(), 1);
        assert_eq!(b_list[0], b_path);
    }

    #[tokio::test]
    async fn put_if_absent_creates_once_and_never_overwrites() {
        let vault = ObjectStoreVault::new_in_memory();
        let path = TenantPaths::tenant_enrollment(tenant_a());

        vault
            .put_if_absent(&path, Bytes::from_static(b"first"))
            .await
            .expect("first create");
        assert!(matches!(
            vault
                .put_if_absent(&path, Bytes::from_static(b"second"))
                .await,
            Err(StorageError::AlreadyExists)
        ));
        assert_eq!(
            vault.get(&path).await.expect("get"),
            Bytes::from_static(b"first")
        );

        let other = TenantPaths::tenant_enrollment(tenant_b());
        vault
            .put(&other, Bytes::from_static(b"plain put"))
            .await
            .expect("put");
        assert!(matches!(
            vault.put_if_absent(&other, Bytes::from_static(b"x")).await,
            Err(StorageError::AlreadyExists)
        ));
        assert_eq!(
            vault.get(&other).await.expect("get"),
            Bytes::from_static(b"plain put")
        );
    }

    /// Store on which every operation fails with a chosen `object_store`
    /// error, as GCS reports a failed generation match or an outage.
    #[derive(Debug)]
    struct FaultyStore {
        error: fn() -> object_store::Error,
    }

    impl std::fmt::Display for FaultyStore {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("FaultyStore")
        }
    }

    #[async_trait]
    impl ObjectStore for FaultyStore {
        async fn put_opts(
            &self,
            _: &StorePath,
            _: PutPayload,
            _: PutOptions,
        ) -> object_store::Result<object_store::PutResult> {
            Err((self.error)())
        }
        async fn put_multipart_opts(
            &self,
            _: &StorePath,
            _: object_store::PutMultipartOptions,
        ) -> object_store::Result<Box<dyn object_store::MultipartUpload>> {
            Err((self.error)())
        }
        async fn get_opts(
            &self,
            _: &StorePath,
            _: object_store::GetOptions,
        ) -> object_store::Result<object_store::GetResult> {
            Err((self.error)())
        }
        fn delete_stream(
            &self,
            locations: futures::stream::BoxStream<'static, object_store::Result<StorePath>>,
        ) -> futures::stream::BoxStream<'static, object_store::Result<StorePath>> {
            let error = self.error;
            Box::pin(locations.map(move |_| Err(error())))
        }
        fn list(
            &self,
            _: Option<&StorePath>,
        ) -> futures::stream::BoxStream<'static, object_store::Result<object_store::ObjectMeta>>
        {
            Box::pin(futures::stream::once(std::future::ready(Err(
                (self.error)(),
            ))))
        }
        async fn list_with_delimiter(
            &self,
            _: Option<&StorePath>,
        ) -> object_store::Result<object_store::ListResult> {
            Err((self.error)())
        }
        async fn copy_opts(
            &self,
            _: &StorePath,
            _: &StorePath,
            _: object_store::CopyOptions,
        ) -> object_store::Result<()> {
            Err((self.error)())
        }
    }

    fn faulty(error: fn() -> object_store::Error) -> ObjectStoreVault {
        ObjectStoreVault::new(Arc::new(FaultyStore { error }))
    }

    /// Every vault operation's error, on a store that fails them all.
    async fn every_operation_fails(error: fn() -> object_store::Error) -> Vec<StorageError> {
        let vault = faulty(error);
        let path = TenantPaths::drive_manifest(tenant_a(), object_1());
        let prefix = TenantPaths::tenant_root(tenant_a());
        let bytes = || Bytes::from_static(b"ciphertext");
        vec![
            vault.put(&path, bytes()).await.expect_err("put"),
            vault
                .put_if_absent(&path, bytes())
                .await
                .expect_err("put_if_absent"),
            vault.get(&path).await.expect_err("get"),
            vault.delete(&path).await.expect_err("delete"),
            vault.list(&prefix).await.expect_err("list"),
            vault.usage(&prefix).await.expect_err("usage"),
        ]
    }

    fn generic() -> object_store::Error {
        object_store::Error::Generic {
            store: "test",
            source: "503 after retries".into(),
        }
    }

    fn permission_denied() -> object_store::Error {
        object_store::Error::PermissionDenied {
            path: "p".into(),
            source: "403".into(),
        }
    }

    #[tokio::test]
    async fn every_operation_classifies_backend_errors() {
        for err in every_operation_fails(generic).await {
            assert!(matches!(err, StorageError::Unavailable(_)), "{err:?}");
            assert!(err.is_retryable());
        }
        for err in every_operation_fails(permission_denied).await {
            assert!(matches!(err, StorageError::Fatal(_)), "{err:?}");
            assert!(!err.is_retryable());
        }
    }

    #[tokio::test]
    async fn conditional_write_errors_are_classified() {
        let vault = faulty(|| object_store::Error::AlreadyExists {
            path: "p".into(),
            source: "generation mismatch".into(),
        });
        let path = TenantPaths::tenant_enrollment(tenant_a());
        assert!(matches!(
            vault.put_if_absent(&path, Bytes::from_static(b"key")).await,
            Err(StorageError::AlreadyExists)
        ));
        let vault = faulty(|| object_store::Error::Precondition {
            path: "p".into(),
            source: "etag mismatch".into(),
        });
        assert!(matches!(
            vault.put_if_absent(&path, Bytes::from_static(b"key")).await,
            Err(StorageError::PreconditionFailed)
        ));
    }

    #[tokio::test]
    async fn map_err_classifies_every_object_store_error() {
        use object_store::Error as E;
        let source = || -> Box<dyn std::error::Error + Send + Sync> { "cause".into() };
        let aborted = tokio::spawn(std::future::pending::<()>());
        aborted.abort();
        let join_error = aborted.await.expect_err("aborted task");

        let cases: Vec<(E, &str)> = vec![
            (
                E::NotFound {
                    path: "p".into(),
                    source: source(),
                },
                "not_found",
            ),
            (
                E::AlreadyExists {
                    path: "p".into(),
                    source: source(),
                },
                "already_exists",
            ),
            (
                E::Precondition {
                    path: "p".into(),
                    source: source(),
                },
                "precondition_failed",
            ),
            (
                E::Generic {
                    store: "s",
                    source: source(),
                },
                "unavailable",
            ),
            (E::JoinError { source: join_error }, "unavailable"),
            (
                E::PermissionDenied {
                    path: "p".into(),
                    source: source(),
                },
                "fatal",
            ),
            (
                E::Unauthenticated {
                    path: "p".into(),
                    source: source(),
                },
                "fatal",
            ),
            (E::NotSupported { source: source() }, "fatal"),
            (
                E::NotModified {
                    path: "p".into(),
                    source: source(),
                },
                "fatal",
            ),
            (
                E::NotImplemented {
                    operation: "op".into(),
                    implementer: "s".into(),
                },
                "fatal",
            ),
            (
                E::UnknownConfigurationKey {
                    store: "s",
                    key: "k".into(),
                },
                "fatal",
            ),
            (
                E::InvalidPath {
                    source: object_store::path::Error::EmptySegment {
                        path: "a//b".into(),
                    },
                },
                "fatal",
            ),
        ];
        for (err, expected) in cases {
            let shown = format!("{err:?}");
            let class = match map_err(err) {
                StorageError::NotFound => "not_found",
                StorageError::AlreadyExists => "already_exists",
                StorageError::PreconditionFailed => "precondition_failed",
                StorageError::Unavailable(_) => "unavailable",
                StorageError::Fatal(_) => "fatal",
            };
            assert_eq!(class, expected, "{shown}");
        }
    }

    /// A local "GCS" that holds every connection open and never answers, or
    /// answers every request with 503. Returns its address and a count of
    /// the requests it received.
    async fn fake_gcs(answer_503: bool) -> (String, Arc<std::sync::atomic::AtomicUsize>) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let requests = Arc::new(AtomicUsize::new(0));
        let counter = requests.clone();
        tokio::spawn(async move {
            let mut held = Vec::new();
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let counter = counter.clone();
                if !answer_503 {
                    counter.fetch_add(1, Ordering::SeqCst);
                    held.push(stream);
                    continue;
                }
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let mut buf = [0u8; 1024];
                    while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                        if stream.readable().await.is_err() {
                            return;
                        }
                        match stream.try_read(&mut buf) {
                            Ok(0) => return,
                            Ok(n) => request.extend_from_slice(&buf[..n]),
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                            Err(_) => return,
                        }
                    }
                    counter.fetch_add(1, Ordering::SeqCst);
                    let reply = b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";
                    let _ = stream.writable().await;
                    let _ = stream.try_write(reply);
                });
            }
        });
        (format!("http://{addr}"), requests)
    }

    fn client(request_secs: u64, max_retries: u32, retry_secs: u64) -> StorageClientConfig {
        StorageClientConfig {
            request_timeout: std::time::Duration::from_secs(request_secs),
            connect_timeout: std::time::Duration::from_secs(1),
            max_retries,
            retry_timeout: std::time::Duration::from_secs(retry_secs),
        }
    }

    #[tokio::test]
    async fn stalled_backend_fails_within_the_configured_bound() {
        let (url, _) = fake_gcs(false).await;
        let settings = client(1, 1, 1);
        let vault = ObjectStoreVault::new_gcs_with_emulator("bucket", Some(&url), &settings)
            .expect("vault");
        let started = std::time::Instant::now();
        let err = vault
            .get(&TenantPaths::drive_manifest(tenant_a(), object_1()))
            .await
            .expect_err("a stalled backend never answers");
        let elapsed = started.elapsed();
        assert!(matches!(err, StorageError::Unavailable(_)), "{err:?}");
        assert!(elapsed >= settings.request_timeout, "{elapsed:?}");
        // One second of slack for scheduling.
        assert!(
            elapsed <= settings.worst_case() + std::time::Duration::from_secs(1),
            "{elapsed:?} exceeds {:?}",
            settings.worst_case()
        );
    }

    #[tokio::test]
    async fn server_errors_are_retried_exactly_max_retries_times() {
        use std::sync::atomic::Ordering;
        for max_retries in [0, 2] {
            let (url, requests) = fake_gcs(true).await;
            let vault = ObjectStoreVault::new_gcs_with_emulator(
                "bucket",
                Some(&url),
                &client(5, max_retries, 30),
            )
            .expect("vault");
            let err = vault
                .get(&TenantPaths::drive_manifest(tenant_a(), object_1()))
                .await
                .expect_err("every answer is a 503");
            assert!(matches!(err, StorageError::Unavailable(_)), "{err:?}");
            assert_eq!(requests.load(Ordering::SeqCst), max_retries as usize + 1);
        }
    }

    #[test]
    fn gcs_vault_accepts_storage_emulator_host_override() {
        for host in [
            "http://fake-gcs:4443",
            "fake-gcs:4443",
            "http://127.0.0.1:4443/",
        ] {
            ObjectStoreVault::new_gcs_with_emulator(
                "quackxide-vault",
                Some(host),
                &StorageClientConfig::default(),
            )
            .expect("emulator-backed GCS client builds without GCP credentials");
        }
    }
}
