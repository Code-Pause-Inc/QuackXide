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
use object_store::{ObjectStore, PutPayload};
use platform_core::{ConnectorSlug, ObjectId, TenantId};

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
    pub fn connector_object(
        tenant: TenantId,
        connector: &ConnectorSlug,
        object: ObjectId,
    ) -> VaultPath {
        VaultPath(format!(
            "tenants/{tenant}/connectors/{connector}/{object}.parquet"
        ))
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

    /// A tenant's enrolled HPKE public key, read by enclave pipelines to seal
    /// connector data to the tenant.
    pub fn tenant_enrollment(tenant: TenantId) -> VaultPath {
        VaultPath(format!("control/enrollments/{tenant}.json"))
    }

    /// Recover the `ObjectId` from a [`connector_object`](Self::connector_object)
    /// path; `None` if it is not one for this tenant and connector.
    pub fn connector_object_id(
        tenant: TenantId,
        connector: &ConnectorSlug,
        path: &VaultPath,
    ) -> Option<ObjectId> {
        let prefix = Self::connector_prefix(tenant, connector);
        path.as_str()
            .strip_prefix(prefix.as_str())?
            .strip_prefix('/')?
            .strip_suffix(".parquet")?
            .parse()
            .ok()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("object not found")]
    NotFound,
    #[error("storage backend unavailable: {0}")]
    Backend(String),
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
    /// Dev/test backend; contents vanish on process exit.
    pub fn new_in_memory() -> Self {
        Self {
            store: Arc::new(InMemory::new()),
        }
    }

    /// Google Cloud Storage backend. Credentials resolve from the environment
    /// or the GCE metadata server.
    pub fn new_gcs(bucket: &str) -> Result<Self, StorageError> {
        let store = GoogleCloudStorageBuilder::from_env()
            .with_bucket_name(bucket)
            .build()
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(Self {
            store: Arc::new(store),
        })
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

fn map_err(err: object_store::Error) -> StorageError {
    match err {
        object_store::Error::NotFound { .. } => StorageError::NotFound,
        other => StorageError::Backend(other.to_string()),
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

    #[test]
    fn connector_paths_include_validated_slug_and_parquet_suffix() {
        let slug = ConnectorSlug::new("quickbooks").expect("valid slug");
        assert_eq!(
            TenantPaths::connector_object(tenant_a(), &slug, object_1()).as_str(),
            "tenants/6f2c8a2e-1111-4222-8333-444455556666/connectors/quickbooks/00000000-aaaa-4bbb-8ccc-000000000001.parquet"
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
}
