//! Research datasets as complete, versioned snapshots (ADR 0003).
//!
//! A snapshot's sealed objects are written under a new [`SnapshotVersion`],
//! then its plaintext [`SnapshotRecord`], then a sealed manifest listing the
//! objects. Queries read only the newest snapshot that has a manifest, so a
//! write that stops partway changes nothing they see, and repeated writes
//! never stack copies of the same rows. Superseded snapshots are deleted
//! after the commit.
//!
//! Two writers share the layout: [`SnapshotWriter`] seals a connector
//! sync's Parquet in the enclave, and [`crate::upload::commit_upload`]
//! stores what a steward's browser already sealed (ADR 0012). Which one
//! wrote a dataset follows from its slug ([`DatasetKind`]), and fixes the
//! `info` string its objects open under ([`object_info`]).
//!
//! The manifest is sealed to the tenant and bound to tenant, dataset and
//! version, so it cannot be moved between them. HPKE seals to a public key,
//! so this binds but does not authenticate: an operator holding the
//! tenant's public key can still forge a whole snapshot, as with any
//! connector object (`docs/THREAT_MODEL.md`).

use std::collections::BTreeMap;

use bytes::Bytes;
use platform_core::{ConnectorSlug, DatasetKind, ObjectId, SnapshotVersion, TenantId};
use platform_crypto::{EnvelopeSuite, TenantPublicKey, hpke_seal_to_tenant};
use platform_storage::{SnapshotRecord, StorageError, TenantPaths, VaultPath, VaultStore};
use platform_telemetry::{AuditKind, security_audit_event};
use serde::{Deserialize, Serialize};

use crate::pipeline::{PipelineError, WrittenObject, envelope_info};

/// What a manifest commits: the objects of one snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotManifest {
    pub version: SnapshotVersion,
    pub objects: Vec<ObjectId>,
}

/// HPKE `info` binding for a snapshot manifest
/// ([`platform_crypto::info::snapshot_manifest`]), for both dataset kinds.
pub fn manifest_info(
    tenant: &TenantId,
    slug: &ConnectorSlug,
    version: &SnapshotVersion,
) -> Vec<u8> {
    platform_crypto::info::snapshot_manifest(tenant, slug, version)
}

/// HPKE `info` binding for one object of `slug`'s snapshots: a connector's
/// objects are sealed under [`platform_crypto::info::connector_object`], an
/// upload's under [`platform_crypto::info::steward_upload`].
pub fn object_info(tenant: &TenantId, slug: &ConnectorSlug, object: &ObjectId) -> Vec<u8> {
    match slug.kind() {
        DatasetKind::Connector => envelope_info(tenant, slug, object),
        DatasetKind::Upload => platform_crypto::info::steward_upload(tenant, slug, object),
    }
}

/// The newest committed snapshot of `tenant`'s `slug`: its version and the
/// path of its manifest, found from the manifest paths alone (nothing is
/// opened). `None` if no snapshot was ever committed.
pub async fn newest_manifest(
    vault: &dyn VaultStore,
    tenant: TenantId,
    slug: &ConnectorSlug,
) -> Result<Option<(SnapshotVersion, VaultPath)>, StorageError> {
    let manifests = vault
        .list(&TenantPaths::connector_manifests_prefix(tenant, slug))
        .await?;
    Ok(manifests
        .into_iter()
        .filter_map(|path| {
            TenantPaths::connector_manifest_version(tenant, slug, &path).map(|v| (v, path))
        })
        .max_by(|a, b| a.0.cmp(&b.0)))
}

/// Whether `tenant` holds the dataset `slug`: it has a committed snapshot.
/// This is the one definition of "holds" (publishing a listing refuses a
/// dataset the steward does not hold). A storage failure is an error, never
/// `false`.
pub async fn holds(
    vault: &dyn VaultStore,
    tenant: TenantId,
    slug: &ConnectorSlug,
) -> Result<bool, StorageError> {
    Ok(newest_manifest(vault, tenant, slug).await?.is_some())
}

/// Writes one connector snapshot. Nothing it writes is visible to queries
/// until [`commit`](Self::commit) stores the manifest. It refuses a slug in
/// the upload namespace: those datasets are written only by uploads.
pub struct SnapshotWriter<'a> {
    vault: &'a dyn VaultStore,
    tenant: TenantId,
    key: &'a TenantPublicKey,
    slug: ConnectorSlug,
    version: SnapshotVersion,
    objects: Vec<ObjectId>,
}

impl<'a> SnapshotWriter<'a> {
    pub fn begin(
        vault: &'a dyn VaultStore,
        tenant: TenantId,
        key: &'a TenantPublicKey,
        slug: ConnectorSlug,
    ) -> Self {
        Self {
            vault,
            tenant,
            key,
            slug,
            version: SnapshotVersion::generate(),
            objects: Vec::new(),
        }
    }

    pub fn version(&self) -> &SnapshotVersion {
        &self.version
    }

    fn connector_only(&self) -> Result<(), PipelineError> {
        match self.slug.kind() {
            DatasetKind::Connector => Ok(()),
            DatasetKind::Upload => Err(PipelineError::UploadNamespace),
        }
    }

    /// Seal one dataset's Parquet into the snapshot.
    pub async fn put(
        &mut self,
        dataset: &str,
        parquet: &[u8],
    ) -> Result<WrittenObject, PipelineError> {
        self.connector_only()?;
        let object = ObjectId::generate();
        let info = envelope_info(&self.tenant, &self.slug, &object);
        let envelope =
            hpke_seal_to_tenant(self.key, &info, parquet).map_err(|_| PipelineError::Seal)?;
        let ciphertext_bytes = envelope.len();
        let path =
            TenantPaths::connector_snapshot_object(self.tenant, &self.slug, &self.version, object);
        self.vault
            .put(&path, envelope.into())
            .await
            .map_err(|e| PipelineError::Storage(e.to_string()))?;
        self.objects.push(object);
        Ok(WrittenObject {
            dataset: dataset.to_owned(),
            object,
            path: path.as_str().to_owned(),
            ciphertext_bytes,
        })
    }

    /// Store the record and then the manifest, which makes this the
    /// snapshot queries read, then delete superseded snapshots.
    pub async fn commit(self) -> Result<SnapshotVersion, PipelineError> {
        self.connector_only()?;
        let manifest = SnapshotManifest {
            version: self.version.clone(),
            objects: self.objects,
        };
        let plaintext = serde_json::to_vec(&manifest).map_err(|_| PipelineError::Seal)?;
        let info = manifest_info(&self.tenant, &self.slug, &self.version);
        let envelope =
            hpke_seal_to_tenant(self.key, &info, &plaintext).map_err(|_| PipelineError::Seal)?;
        let record = SnapshotRecord {
            version: self.version.clone(),
            suite: EnvelopeSuite::CURRENT.id().to_owned(),
            row_cap: None,
            schema: None,
        };
        commit_snapshot(
            self.vault,
            self.tenant,
            &self.slug,
            &record,
            envelope.into(),
            manifest.objects.len(),
        )
        .await
        .map_err(|e| PipelineError::Storage(e.to_string()))?;
        Ok(self.version)
    }
}

/// The audit kind and the detail label for `slug`'s snapshot events: a
/// connector's are part of its sync, an upload's are vault writes.
fn audit_labels(slug: &ConnectorSlug) -> (AuditKind, &'static str) {
    match slug.kind() {
        DatasetKind::Connector => (AuditKind::ConnectorSync, "connector"),
        DatasetKind::Upload => (AuditKind::DataAccess, "dataset"),
    }
}

/// Commit a snapshot whose objects are already stored: write its plaintext
/// `record`, then the sealed `manifest` (the commit), then prune superseded
/// snapshots. Shared by both writers, so the order cannot drift.
pub(crate) async fn commit_snapshot(
    vault: &dyn VaultStore,
    tenant: TenantId,
    slug: &ConnectorSlug,
    record: &SnapshotRecord,
    manifest: Bytes,
    objects: usize,
) -> Result<(), StorageError> {
    let version = &record.version;
    vault
        .put(
            &TenantPaths::connector_record(tenant, slug, version),
            record.to_bytes(),
        )
        .await?;
    vault
        .put(
            &TenantPaths::connector_manifest(tenant, slug, version),
            manifest,
        )
        .await?;
    let (kind, label) = audit_labels(slug);
    security_audit_event(
        kind,
        Some(tenant),
        "committed",
        &format!("{label}={slug} snapshot={version} objects={objects}"),
    );
    prune_superseded(vault, tenant, slug, version).await;
    Ok(())
}

/// Delete every snapshot older than `current`: manifests first, so an old
/// snapshot leaves the read path before its objects go, then objects and
/// records, including those of writes that never committed. Failures leave
/// stale snapshots behind, which queries never read; the next commit
/// retries.
pub async fn prune_superseded(
    vault: &dyn VaultStore,
    tenant: TenantId,
    slug: &ConnectorSlug,
    current: &SnapshotVersion,
) {
    let (kind, label) = audit_labels(slug);
    let mut failed = false;
    match vault
        .list(&TenantPaths::connector_manifests_prefix(tenant, slug))
        .await
    {
        Ok(paths) => {
            for path in paths {
                let stale = TenantPaths::connector_manifest_version(tenant, slug, &path)
                    .is_some_and(|version| version < *current);
                if stale && vault.delete(&path).await.is_err() {
                    failed = true;
                }
            }
        }
        Err(_) => failed = true,
    }

    // Objects pruned per superseded version.
    let mut pruned: BTreeMap<SnapshotVersion, usize> = BTreeMap::new();
    match vault
        .list(&TenantPaths::connector_snapshots_prefix(tenant, slug))
        .await
    {
        Ok(paths) => {
            for path in paths {
                let Some((version, _)) =
                    TenantPaths::connector_snapshot_object_parts(tenant, slug, &path)
                else {
                    continue;
                };
                if version >= *current {
                    continue;
                }
                if vault.delete(&path).await.is_ok() {
                    *pruned.entry(version).or_default() += 1;
                } else {
                    failed = true;
                }
            }
        }
        Err(_) => failed = true,
    }
    match vault
        .list(&TenantPaths::connector_records_prefix(tenant, slug))
        .await
    {
        Ok(paths) => {
            for path in paths {
                let Some(version) = TenantPaths::connector_record_version(tenant, slug, &path)
                else {
                    continue;
                };
                if version >= *current {
                    continue;
                }
                if vault.delete(&path).await.is_ok() {
                    pruned.entry(version).or_default();
                } else {
                    failed = true;
                }
            }
        }
        Err(_) => failed = true,
    }

    for (version, objects) in pruned {
        security_audit_event(
            kind,
            Some(tenant),
            "pruned",
            &format!("{label}={slug} superseded_snapshot={version} objects={objects}"),
        );
    }
    if failed {
        security_audit_event(
            kind,
            Some(tenant),
            "prune_failed",
            &format!("{label}={slug} stale snapshots remain; queries read only the newest"),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use platform_crypto::TenantKeypair;
    use platform_storage::ObjectStoreVault;

    fn slug(raw: &str) -> ConnectorSlug {
        ConnectorSlug::new(raw).expect("slug")
    }

    #[test]
    fn objects_open_under_the_info_of_their_dataset_kind() {
        let tenant = TenantId::generate();
        let object = ObjectId::generate();
        let connector = slug("quickbooks");
        let upload = slug("upload_cohorts");
        assert_eq!(
            object_info(&tenant, &connector, &object),
            platform_crypto::info::connector_object(tenant, &connector, object)
        );
        assert_eq!(
            object_info(&tenant, &upload, &object),
            platform_crypto::info::steward_upload(tenant, &upload, object)
        );
    }

    #[tokio::test]
    async fn connector_writer_refuses_the_upload_namespace() {
        let vault = ObjectStoreVault::new_in_memory();
        let keypair = TenantKeypair::generate();
        let key = keypair.public_key();
        let tenant = TenantId::generate();
        let mut writer = SnapshotWriter::begin(&vault, tenant, &key, slug("upload_cohorts"));
        assert!(matches!(
            writer.put("rows", b"parquet").await,
            Err(PipelineError::UploadNamespace)
        ));
        assert!(matches!(
            writer.commit().await,
            Err(PipelineError::UploadNamespace)
        ));
        let stored = vault
            .list(&TenantPaths::tenant_root(tenant))
            .await
            .expect("list");
        assert!(stored.is_empty(), "nothing may be written: {stored:?}");
    }

    #[tokio::test]
    async fn a_commit_writes_a_record_and_holds_follows_the_manifest() {
        let vault = ObjectStoreVault::new_in_memory();
        let keypair = TenantKeypair::generate();
        let key = keypair.public_key();
        let tenant = TenantId::generate();
        let health = slug("health");
        assert!(!holds(&vault, tenant, &health).await.expect("holds"));

        let mut writer = SnapshotWriter::begin(&vault, tenant, &key, health.clone());
        writer.put("rows", b"parquet").await.expect("put");
        // Objects alone are not a snapshot.
        assert!(!holds(&vault, tenant, &health).await.expect("holds"));
        let version = writer.commit().await.expect("commit");
        assert!(holds(&vault, tenant, &health).await.expect("holds"));
        assert!(
            !holds(&vault, TenantId::generate(), &health)
                .await
                .expect("holds"),
            "another tenant holds nothing"
        );
        assert_eq!(
            newest_manifest(&vault, tenant, &health)
                .await
                .expect("newest")
                .map(|(v, _)| v),
            Some(version.clone())
        );

        let record = vault
            .get(&TenantPaths::connector_record(tenant, &health, &version))
            .await
            .expect("record");
        let record = SnapshotRecord::parse(&record, &version).expect("parse");
        assert_eq!(record.suite, "HPK1");
        assert_eq!((record.row_cap, record.schema), (None, None));
    }

    #[tokio::test]
    async fn pruning_removes_superseded_records_with_their_snapshots() {
        let vault = ObjectStoreVault::new_in_memory();
        let keypair = TenantKeypair::generate();
        let key = keypair.public_key();
        let tenant = TenantId::generate();
        let health = slug("health");
        for _ in 0..3 {
            let mut writer = SnapshotWriter::begin(&vault, tenant, &key, health.clone());
            writer.put("rows", b"parquet").await.expect("put");
            writer.commit().await.expect("commit");
        }
        for prefix in [
            TenantPaths::connector_manifests_prefix(tenant, &health),
            TenantPaths::connector_snapshots_prefix(tenant, &health),
            TenantPaths::connector_records_prefix(tenant, &health),
        ] {
            assert_eq!(
                vault.list(&prefix).await.expect("list").len(),
                1,
                "{prefix}"
            );
        }
    }
}
