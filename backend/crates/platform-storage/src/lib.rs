//! Tenant-isolated ciphertext vault over object storage.
//!
//! Layout inside `gs://{STORAGE_BUCKET}/`:
//!
//! ```text
//! tenants/{tenant_id}/drive/manifests/{object_id}.json
//! tenants/{tenant_id}/drive/objects/{object_id}/{chunk_index:08}
//! tenants/{tenant_id}/drive/sweeping/{object_id}
//! tenants/{tenant_id}/connectors/{slug}/snapshots/{version}/{object_id}.parquet
//! tenants/{tenant_id}/connectors/{slug}/records/{version}.json
//! tenants/{tenant_id}/connectors/{slug}/manifests/{version}.manifest
//! control/enrollments/{tenant_id}.json
//! control/tenants/{tenant_id}.json
//! ```
//!
//! `{slug}` names a research dataset: a connector's, or one a steward
//! uploads, in the `upload_` namespace (ADR 0012). Each version is one
//! complete snapshot (ADR 0003): its sealed objects, then its plaintext
//! [`SnapshotRecord`], then the sealed manifest that commits it.
//! `connectors/{slug}/keys/{version}/` is reserved for the snapshot's wrapped
//! data keys (ADR 0004); nothing writes there yet.
//!
//! Invariants:
//! 1. Every path is built through [`TenantPaths`] from typed, validated ids;
//!    the vault never accepts a raw string path.
//! 2. The vault stores ciphertext, except the small plaintext records named
//!    above, whose contents are listed in `docs/THREAT_MODEL.md` ("Metadata").
//!    Object names are opaque UUIDs; user filenames live inside the
//!    client-encrypted manifest.
//! 3. `object_store` matches list prefixes by whole path parts, so a prefix
//!    for tenant `abc…` can never match tenant `abcd…`.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use futures::TryStreamExt;
use object_store::StaticCredentialProvider;
use object_store::gcp::{GcpCredential, GoogleCloudStorageBuilder};
use object_store::memory::InMemory;
use object_store::path::Path as StorePath;
use object_store::{
    BackoffConfig, ClientOptions, ObjectStore, ObjectStoreExt, PutMode, PutOptions, PutPayload,
    RetryConfig,
};
use platform_config::StorageClientConfig;
use platform_core::{ConnectorSlug, DeclaredSchema, ObjectId, SnapshotVersion, TenantId};
use serde::{Deserialize, Serialize};

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

    /// Every tenant's data. Private: the only cross-tenant read is
    /// [`list_drive_entries_all_tenants`], so no path spanning tenants
    /// leaves this crate.
    fn all_tenants() -> VaultPath {
        VaultPath("tenants".to_owned())
    }

    /// The tenant and object of a [`drive_chunk`](Self::drive_chunk) path.
    pub fn drive_chunk_parts(path: &VaultPath) -> Option<(TenantId, ObjectId)> {
        let rest = path.as_str().strip_prefix("tenants/")?;
        let (tenant, rest) = rest.split_once('/')?;
        let (object, index) = rest.strip_prefix("drive/objects/")?.split_once('/')?;
        if index.len() != 8 || !index.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        Some((tenant.parse().ok()?, object.parse().ok()?))
    }

    /// The tenant and object of a [`drive_manifest`](Self::drive_manifest)
    /// path.
    pub fn drive_manifest_parts(path: &VaultPath) -> Option<(TenantId, ObjectId)> {
        let rest = path.as_str().strip_prefix("tenants/")?;
        let (tenant, rest) = rest.split_once('/')?;
        let object = rest
            .strip_prefix("drive/manifests/")?
            .strip_suffix(".json")?;
        Some((tenant.parse().ok()?, object.parse().ok()?))
    }

    /// Prefix of all chunks of one drive object (deletion).
    pub fn drive_object_prefix(tenant: TenantId, object: ObjectId) -> VaultPath {
        VaultPath(format!("tenants/{tenant}/drive/objects/{object}"))
    }

    /// Marker the orphan sweep holds while it deletes one object's chunks.
    /// It sits outside [`drive_object_prefix`](Self::drive_object_prefix)
    /// and [`drive_manifest_prefix`](Self::drive_manifest_prefix), so chunk
    /// and manifest listings never return it.
    pub fn drive_sweep_marker(tenant: TenantId, object: ObjectId) -> VaultPath {
        VaultPath(format!("tenants/{tenant}/drive/sweeping/{object}"))
    }

    /// The tenant and object of a
    /// [`drive_sweep_marker`](Self::drive_sweep_marker) path.
    pub fn drive_sweep_marker_parts(path: &VaultPath) -> Option<(TenantId, ObjectId)> {
        let rest = path.as_str().strip_prefix("tenants/")?;
        let (tenant, rest) = rest.split_once('/')?;
        let object = rest.strip_prefix("drive/sweeping/")?;
        Some((tenant.parse().ok()?, object.parse().ok()?))
    }

    /// One sealed Parquet object of a dataset snapshot: sealed in the enclave
    /// by a connector sync, or in the steward's browser for an upload. A
    /// snapshot is complete only once its manifest exists.
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

    /// Every object stored at one snapshot `version`, whether or not its
    /// manifest lists it (a query sizes its input from this before any key
    /// is released).
    pub fn connector_snapshot_prefix(
        tenant: TenantId,
        connector: &ConnectorSlug,
        version: &SnapshotVersion,
    ) -> VaultPath {
        VaultPath(format!(
            "tenants/{tenant}/connectors/{connector}/snapshots/{version}"
        ))
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

    /// The plaintext [`SnapshotRecord`] of one snapshot, written after its
    /// objects and before its manifest.
    pub fn connector_record(
        tenant: TenantId,
        connector: &ConnectorSlug,
        version: &SnapshotVersion,
    ) -> VaultPath {
        VaultPath(format!(
            "tenants/{tenant}/connectors/{connector}/records/{version}.json"
        ))
    }

    /// Every snapshot's record for one tenant-connector pair (pruning).
    pub fn connector_records_prefix(tenant: TenantId, connector: &ConnectorSlug) -> VaultPath {
        VaultPath(format!("tenants/{tenant}/connectors/{connector}/records"))
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

    /// Recover the snapshot version from a
    /// [`connector_record`](Self::connector_record) path; `None` if it is
    /// not one for this tenant and connector.
    pub fn connector_record_version(
        tenant: TenantId,
        connector: &ConnectorSlug,
        path: &VaultPath,
    ) -> Option<SnapshotVersion> {
        let prefix = Self::connector_records_prefix(tenant, connector);
        path.as_str()
            .strip_prefix(prefix.as_str())?
            .strip_prefix('/')?
            .strip_suffix(".json")?
            .parse()
            .ok()
    }
}

/// The plaintext record of one dataset snapshot (ADR 0012), stored at
/// [`TenantPaths::connector_record`]. The operator can read it, so it holds
/// only what the API needs without key release: the envelope suite, and for
/// an upload the row cap and schema the steward declared. Connector
/// snapshots record their suite only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotRecord {
    /// The snapshot this record describes; a record naming another is
    /// refused.
    pub version: SnapshotVersion,
    /// The envelope suite of the snapshot's objects and manifest, by its
    /// stable name (`platform_crypto::EnvelopeSuite::id`, for example
    /// `HPK1`).
    pub suite: String,
    /// The most rows the steward declared the upload holds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub row_cap: Option<u64>,
    /// The columns the steward declared the upload holds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<DeclaredSchema>,
}

/// Why a stored [`SnapshotRecord`] was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RecordError {
    #[error("snapshot record is malformed")]
    Malformed,
    #[error("snapshot record names another snapshot")]
    WrongVersion,
}

impl SnapshotRecord {
    /// Largest stored record read; a declared schema at its limits fits.
    pub const MAX_BYTES: usize = 256 * 1024;
    /// Longest suite name.
    const MAX_SUITE_BYTES: usize = 16;

    pub fn to_bytes(&self) -> Bytes {
        serde_json::to_vec(self)
            .expect("a record of validated fields always serializes")
            .into()
    }

    /// Parse the record stored for `version`, refusing one that is
    /// oversized, malformed, or written for another snapshot.
    pub fn parse(bytes: &[u8], version: &SnapshotVersion) -> Result<Self, RecordError> {
        if bytes.len() > Self::MAX_BYTES {
            return Err(RecordError::Malformed);
        }
        let record: Self = serde_json::from_slice(bytes).map_err(|_| RecordError::Malformed)?;
        let suite_ok = (1..=Self::MAX_SUITE_BYTES).contains(&record.suite.len())
            && record.suite.bytes().all(|b| b.is_ascii_alphanumeric());
        if !suite_ok {
            return Err(RecordError::Malformed);
        }
        if record.version != *version {
            return Err(RecordError::WrongVersion);
        }
        Ok(record)
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

/// One stored object as a listing reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultEntry {
    pub path: VaultPath,
    pub size: u64,
    pub last_modified: chrono::DateTime<chrono::Utc>,
}

/// What a drive path holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriveEntryKind {
    Manifest,
    Chunk,
    /// A [`TenantPaths::drive_sweep_marker`].
    SweepMarker,
}

/// One drive manifest or chunk found by [`list_drive_entries_all_tenants`].
/// `entry.path` is the single-tenant path of that manifest or chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriveEntry {
    pub tenant: TenantId,
    pub object: ObjectId,
    pub kind: DriveEntryKind,
    pub entry: VaultEntry,
}

/// Every drive manifest and chunk of every tenant, with size and
/// last-modified time. Control plane only: the drive orphan sweep uses it.
/// It returns only parsed drive entries, each with its own tenant's path;
/// connector data, enrollments and anything unparsable are left out.
pub async fn list_drive_entries_all_tenants(
    vault: &dyn VaultStore,
) -> Result<Vec<DriveEntry>, StorageError> {
    Ok(vault
        .list_entries(&TenantPaths::all_tenants())
        .await?
        .into_iter()
        .filter_map(|entry| {
            let (kind, (tenant, object)) =
                if let Some(parts) = TenantPaths::drive_manifest_parts(&entry.path) {
                    (DriveEntryKind::Manifest, parts)
                } else if let Some(parts) = TenantPaths::drive_sweep_marker_parts(&entry.path) {
                    (DriveEntryKind::SweepMarker, parts)
                } else {
                    (
                        DriveEntryKind::Chunk,
                        TenantPaths::drive_chunk_parts(&entry.path)?,
                    )
                };
            Some(DriveEntry {
                tenant,
                object,
                kind,
                entry,
            })
        })
        .collect())
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
    /// As [`list`](Self::list), with each object's size and last-modified
    /// time.
    async fn list_entries(&self, prefix: &VaultPath) -> Result<Vec<VaultEntry>, StorageError>;
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

    /// DEV ONLY: each object is a file under `dir`, at its vault path. The
    /// simulated TEE stack uses it because no GCS emulator accepts
    /// `object_store`'s uploads (#153). `dir` must already exist.
    #[cfg(feature = "dev")]
    pub fn new_local_dir(dir: &std::path::Path) -> Result<Self, StorageError> {
        let store = object_store::local::LocalFileSystem::new_with_prefix(dir)
            .map_err(|e| StorageError::Fatal(e.to_string()))?;
        Ok(Self::new(Arc::new(store)))
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
                // object_store 0.13 skips signing on reads only; writes still ask
                // for a credential, which would fall back to the GCE metadata server.
                let placeholder = GcpCredential {
                    bearer: "emulator".to_owned(),
                };
                builder = builder
                    .with_base_url(&base_url)
                    .with_skip_signature(true)
                    .with_credentials(Arc::new(StaticCredentialProvider::new(placeholder)));
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

    async fn list_entries(&self, prefix: &VaultPath) -> Result<Vec<VaultEntry>, StorageError> {
        Ok(self
            .list_meta(prefix)
            .await?
            .into_iter()
            .map(|meta| VaultEntry {
                path: VaultPath(meta.location.to_string()),
                size: meta.size,
                last_modified: meta.last_modified,
            })
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
        let record = TenantPaths::connector_record(tenant_a(), &slug, &version_1());
        assert_eq!(
            record.as_str(),
            "tenants/6f2c8a2e-1111-4222-8333-444455556666/connectors/quickbooks/records/00000000000000000001-0123456789abcdef0123456789abcdef.json"
        );
        assert_eq!(
            TenantPaths::connector_record_version(tenant_a(), &slug, &record),
            Some(version_1())
        );
        for path in [&object, &manifest, &record] {
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
        let record = TenantPaths::connector_record(tenant_a(), &slug, &version_1());
        assert_eq!(
            TenantPaths::connector_record_version(tenant_a(), &other, &record),
            None
        );
        assert_eq!(
            TenantPaths::connector_record_version(tenant_b(), &slug, &record),
            None
        );
        for not_a_record in [&object, &manifest] {
            assert_eq!(
                TenantPaths::connector_record_version(tenant_a(), &slug, not_a_record),
                None
            );
        }
        assert_eq!(
            TenantPaths::connector_snapshot_object_parts(tenant_a(), &slug, &record),
            None
        );
    }

    fn upload_record() -> SnapshotRecord {
        use platform_core::{ColumnType, DeclaredColumn};
        SnapshotRecord {
            version: version_1(),
            suite: "HPK1".into(),
            row_cap: Some(7),
            schema: Some(
                DeclaredSchema::new(vec![
                    DeclaredColumn {
                        name: "condition".into(),
                        column_type: ColumnType::String,
                    },
                    DeclaredColumn {
                        name: "age".into(),
                        column_type: ColumnType::Int64,
                    },
                ])
                .expect("schema"),
            ),
        }
    }

    #[test]
    fn snapshot_records_round_trip() {
        let record = upload_record();
        let bytes = record.to_bytes();
        assert_eq!(
            SnapshotRecord::parse(&bytes, &version_1()).expect("parse"),
            record
        );
        // A connector snapshot records its suite only.
        let connector = SnapshotRecord {
            row_cap: None,
            schema: None,
            ..upload_record()
        };
        let bytes = connector.to_bytes();
        assert_eq!(
            std::str::from_utf8(&bytes).expect("utf-8"),
            r#"{"version":"00000000000000000001-0123456789abcdef0123456789abcdef","suite":"HPK1"}"#
        );
        assert_eq!(
            SnapshotRecord::parse(&bytes, &version_1()).expect("parse"),
            connector
        );
    }

    #[test]
    fn malformed_or_misplaced_records_are_refused() {
        let other: SnapshotVersion = "00000000000000000002-0123456789abcdef0123456789abcdef"
            .parse()
            .expect("valid");
        assert_eq!(
            SnapshotRecord::parse(&upload_record().to_bytes(), &other),
            Err(RecordError::WrongVersion)
        );
        let version = version_1();
        let with = |field: &str| {
            format!(r#"{{"version":"{version}","suite":"HPK1"{field}}}"#).into_bytes()
        };
        for bad in [
            b"".to_vec(),
            b"not json".to_vec(),
            format!(r#"{{"version":"{version}"}}"#).into_bytes(),
            format!(r#"{{"version":"{version}","suite":""}}"#).into_bytes(),
            format!(r#"{{"version":"{version}","suite":"HPK 1"}}"#).into_bytes(),
            format!(r#"{{"version":"{version}","suite":"HPK1HPK1HPK1HPK1X"}}"#).into_bytes(),
            format!(r#"{{"version":"../{version}","suite":"HPK1"}}"#).into_bytes(),
            with(r#","objects":[]"#),
            with(r#","row_cap":-1"#),
            with(r#","schema":[]"#),
            vec![b' '; SnapshotRecord::MAX_BYTES + 1],
        ] {
            assert_eq!(
                SnapshotRecord::parse(&bad, &version),
                Err(RecordError::Malformed),
                "{}",
                String::from_utf8_lossy(&bad[..bad.len().min(80)])
            );
        }
    }

    #[test]
    fn drive_paths_parse_back_to_tenant_and_object() {
        let chunk = TenantPaths::drive_chunk(tenant_a(), object_1(), 7);
        assert_eq!(
            TenantPaths::drive_chunk_parts(&chunk),
            Some((tenant_a(), object_1()))
        );
        let manifest = TenantPaths::drive_manifest(tenant_a(), object_1());
        assert_eq!(
            TenantPaths::drive_manifest_parts(&manifest),
            Some((tenant_a(), object_1()))
        );
        let marker = TenantPaths::drive_sweep_marker(tenant_a(), object_1());
        assert_eq!(
            TenantPaths::drive_sweep_marker_parts(&marker),
            Some((tenant_a(), object_1()))
        );
        // Each parser accepts only its own kind of path.
        assert_eq!(TenantPaths::drive_chunk_parts(&manifest), None);
        assert_eq!(TenantPaths::drive_manifest_parts(&chunk), None);
        assert_eq!(TenantPaths::drive_chunk_parts(&marker), None);
        assert_eq!(TenantPaths::drive_manifest_parts(&marker), None);
        assert_eq!(TenantPaths::drive_sweep_marker_parts(&chunk), None);
        assert_eq!(TenantPaths::drive_sweep_marker_parts(&manifest), None);
        // A marker is outside the prefixes that chunk and manifest listings use.
        let chunks = TenantPaths::drive_object_prefix(tenant_a(), object_1());
        let manifests = TenantPaths::drive_manifest_prefix(tenant_a());
        assert!(!marker.as_str().starts_with(chunks.as_str()));
        assert!(!marker.as_str().starts_with(manifests.as_str()));
        let t = tenant_a();
        let o = object_1();
        for raw in [
            format!("tenants/{t}/drive/objects/{o}"),
            format!("tenants/{t}/drive/objects/{o}/7"),
            format!("tenants/{t}/drive/objects/{o}/0000000x"),
            format!("tenants/{t}/drive/objects/not-a-uuid/00000001"),
            format!("tenants/not-a-uuid/drive/objects/{o}/00000001"),
            format!("tenants/{t}/connectors/x/{o}.parquet"),
            format!("control/tenants/{t}.json"),
        ] {
            assert_eq!(
                TenantPaths::drive_chunk_parts(&VaultPath(raw.clone())),
                None,
                "{raw}"
            );
            assert_eq!(
                TenantPaths::drive_manifest_parts(&VaultPath(raw.clone())),
                None,
                "{raw}"
            );
            assert_eq!(
                TenantPaths::drive_sweep_marker_parts(&VaultPath(raw.clone())),
                None,
                "{raw}"
            );
        }
        assert!(
            chunk
                .as_str()
                .starts_with(TenantPaths::all_tenants().as_str())
        );
    }

    #[tokio::test]
    async fn list_entries_reports_size_and_last_modified() {
        let vault = ObjectStoreVault::new_in_memory();
        let before = chrono::Utc::now();
        let path = TenantPaths::drive_chunk(tenant_a(), object_1(), 0);
        vault
            .put(&path, Bytes::from_static(b"12345"))
            .await
            .expect("put");
        let entries = vault
            .list_entries(&TenantPaths::tenant_root(tenant_a()))
            .await
            .expect("list");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, path);
        assert_eq!(entries[0].size, 5);
        assert!(entries[0].last_modified >= before - chrono::Duration::seconds(1));
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
    async fn one_snapshot_version_is_sized_alone() {
        let vault = ObjectStoreVault::new_in_memory();
        let slug = ConnectorSlug::new("quickbooks").expect("slug");
        let version_2: SnapshotVersion = "00000000000000000002-0123456789abcdef0123456789abcdef"
            .parse()
            .expect("version");
        for (version, bytes) in [
            (version_1(), &b"0123456789"[..]),
            (version_1(), &b"abc"[..]),
            (version_2.clone(), &b"not this one"[..]),
        ] {
            let object = ObjectId::generate();
            let path = TenantPaths::connector_snapshot_object(tenant_a(), &slug, &version, object);
            vault
                .put(&path, Bytes::copy_from_slice(bytes))
                .await
                .expect("put");
        }
        let prefix = TenantPaths::connector_snapshot_prefix(tenant_a(), &slug, &version_1());
        assert!(
            prefix
                .as_str()
                .starts_with(TenantPaths::connector_snapshots_prefix(tenant_a(), &slug).as_str())
        );
        let usage = vault.usage(&prefix).await.expect("usage");
        assert_eq!(usage.object_count, 2);
        assert_eq!(usage.total_bytes, 13);
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

    /// A fresh directory for one test; the caller removes it.
    #[cfg(feature = "dev")]
    fn scratch_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("vault-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create scratch dir");
        dir
    }

    #[cfg(feature = "dev")]
    #[tokio::test]
    async fn local_dir_vault_stores_each_object_as_a_file_at_its_path() {
        let dir = scratch_dir("local-layout");
        let vault = ObjectStoreVault::new_local_dir(&dir).expect("vault");
        let path = TenantPaths::drive_manifest(tenant_a(), object_1());

        vault
            .put(&path, Bytes::from_static(b"sealed"))
            .await
            .expect("put");
        assert_eq!(
            vault.get(&path).await.expect("get"),
            Bytes::from_static(b"sealed")
        );
        assert_eq!(
            vault
                .list(&TenantPaths::drive_manifest_prefix(tenant_a()))
                .await
                .expect("list"),
            vec![path.clone()]
        );
        // The simulated TEE's e2e script reads these files to check them.
        assert_eq!(
            std::fs::read(dir.join(path.as_str())).expect("file at the vault path"),
            b"sealed"
        );
        assert!(matches!(
            vault
                .put_if_absent(&path, Bytes::from_static(b"other"))
                .await,
            Err(StorageError::AlreadyExists)
        ));
        vault.delete(&path).await.expect("delete");
        assert!(matches!(
            vault.get(&path).await,
            Err(StorageError::NotFound)
        ));

        std::fs::remove_dir_all(&dir).expect("remove scratch dir");
    }

    #[cfg(feature = "dev")]
    #[test]
    fn local_dir_vault_refuses_a_missing_directory() {
        let dir = std::env::temp_dir().join(format!("vault-missing-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(ObjectStoreVault::new_local_dir(&dir).is_err());
        assert!(!dir.exists(), "the vault must not create its own directory");
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
            vault.list_entries(&prefix).await.expect_err("list_entries"),
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

    /// A local server answering every request with 200 and an ETag, as an
    /// emulator does to a successful write.
    async fn accepting_gcs() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let mut buf = [0u8; 4096];
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
                    let reply = b"HTTP/1.1 200 OK\r\netag: \"1\"\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";
                    let _ = stream.writable().await;
                    let _ = stream.try_write(reply);
                });
            }
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn emulator_writes_need_no_cloud_credentials() {
        let url = accepting_gcs().await;
        let vault = ObjectStoreVault::new_gcs_with_emulator("bucket", Some(&url), &client(2, 0, 2))
            .expect("vault");
        vault
            .put(
                &TenantPaths::drive_manifest(tenant_a(), object_1()),
                Bytes::from_static(b"ciphertext"),
            )
            .await
            .expect("a write to the emulator must not ask a metadata server for credentials");
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
