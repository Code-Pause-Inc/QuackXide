//! Research datasets as complete, versioned snapshots (ADR 0003).
//!
//! A snapshot's sealed objects are written under a new [`SnapshotVersion`],
//! then its plaintext [`SnapshotRecord`], then a sealed manifest listing the
//! objects. Queries read only the newest snapshot that has a manifest, so a
//! write that stops partway changes nothing they see, and repeated writes
//! never stack copies of the same rows. The record and the manifest are
//! written create-only, so a version keeps the first record stored for it
//! and commits once. After the commit, everything the new snapshot does not
//! list is deleted.
//!
//! Two writers share the layout: [`SnapshotWriter`] seals a connector
//! sync's Parquet in the enclave, and [`crate::upload::commit_upload`]
//! stores what a steward's browser already sealed (ADR 0012). Which one
//! wrote a dataset follows from its slug ([`DatasetKind`]), and fixes the
//! `info` string its objects open under ([`object_info`]).
//!
//! Readers find the current snapshot from manifest paths alone, without
//! opening anything: [`holds`] for one dataset and [`held_datasets`] for
//! every dataset of a tenant decide it with one function, and
//! [`recorded_suite`] reads a snapshot's plaintext record.
//!
//! The manifest is sealed to the tenant and bound to tenant, dataset and
//! version, so it cannot be moved between them. HPKE seals to a public key,
//! so this binds but does not authenticate: an operator holding the
//! tenant's public key can still forge a whole snapshot, as with any
//! connector object (`docs/THREAT_MODEL.md`).

use std::collections::{BTreeMap, HashMap};

use bytes::Bytes;
use platform_core::{ConnectorSlug, DatasetKind, ObjectId, SnapshotVersion, TenantId};
use platform_crypto::{EnvelopeSuite, TenantPublicKey, hpke_seal_to_tenant};
use platform_storage::{
    SnapshotRecord, StorageError, TenantPaths, VaultEntry, VaultPath, VaultStore,
};
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

/// The newest committed snapshot of `tenant`'s `slug` among `paths`: the
/// newest version with a manifest there, and that manifest's path. Paths
/// that are not one of its manifests are ignored. [`newest_manifest`], and
/// through it [`holds`], and [`held_datasets`] all decide with this, so the
/// dataset listing and "holds" cannot disagree.
fn newest_committed<'a>(
    tenant: TenantId,
    slug: &ConnectorSlug,
    paths: impl IntoIterator<Item = &'a VaultPath>,
) -> Option<(SnapshotVersion, &'a VaultPath)> {
    paths
        .into_iter()
        .filter_map(|path| {
            TenantPaths::connector_manifest_version(tenant, slug, path).map(|v| (v, path))
        })
        .max_by(|a, b| a.0.cmp(&b.0))
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
    Ok(newest_committed(tenant, slug, &manifests).map(|(version, path)| (version, path.clone())))
}

/// Whether `tenant` holds the dataset `slug`: it has a committed snapshot.
/// This is the one definition of "holds" (publishing a listing refuses a
/// dataset the steward does not hold, and [`held_datasets`] lists exactly
/// the datasets held). A storage failure is an error, never `false`.
pub async fn holds(
    vault: &dyn VaultStore,
    tenant: TenantId,
    slug: &ConnectorSlug,
) -> Result<bool, StorageError> {
    Ok(newest_manifest(vault, tenant, slug).await?.is_some())
}

/// One object stored under a dataset's current snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredObject {
    pub object: ObjectId,
    /// Its size as stored: the sealed envelope's length.
    pub ciphertext_bytes: u64,
}

/// A dataset its tenant holds, as storage describes it: nothing is opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldDataset {
    pub slug: ConnectorSlug,
    /// The current snapshot: the newest committed one.
    pub version: SnapshotVersion,
    /// The objects stored at the current snapshot's version, by id. The
    /// manifest is sealed, so these are the objects stored there, not the
    /// ones it lists. The commit's pruning makes them the same, except for
    /// an object stored at the version after the commit or one whose
    /// deletion failed (both unlisted), or a listed object that is missing,
    /// on which queries fail closed (ADR 0012). Objects of superseded
    /// snapshots and of writes not yet committed are left out.
    pub objects: Vec<StoredObject>,
}

/// Every dataset `tenant` holds, connectors' and uploads' alike, by slug,
/// from one listing of the tenant's datasets (nothing is opened). A dataset
/// is here exactly when [`holds`] is true for it: both decide with the same
/// function on the same manifest paths. A storage failure is an error,
/// never an empty list.
pub async fn held_datasets(
    vault: &dyn VaultStore,
    tenant: TenantId,
) -> Result<Vec<HeldDataset>, StorageError> {
    let mut by_dataset: HashMap<ConnectorSlug, Vec<VaultEntry>> = HashMap::new();
    for entry in vault
        .list_entries(&TenantPaths::connectors_root(tenant))
        .await?
    {
        if let Some(slug) = TenantPaths::connector_of(tenant, &entry.path) {
            by_dataset.entry(slug).or_default().push(entry);
        }
    }
    let mut held: Vec<HeldDataset> = by_dataset
        .into_iter()
        .filter_map(|(slug, entries)| {
            let (version, _) =
                newest_committed(tenant, &slug, entries.iter().map(|entry| &entry.path))?;
            let mut objects: Vec<StoredObject> = entries
                .iter()
                .filter_map(|entry| {
                    let (at, object) =
                        TenantPaths::connector_snapshot_object_parts(tenant, &slug, &entry.path)?;
                    (at == version).then_some(StoredObject {
                        object,
                        ciphertext_bytes: entry.size,
                    })
                })
                .collect();
            objects.sort_by_key(|stored| stored.object);
            Some(HeldDataset {
                slug,
                version,
                objects,
            })
        })
        .collect();
    held.sort_by(|a, b| a.slug.as_str().cmp(b.slug.as_str()));
    Ok(held)
}

/// The envelope suite that the record of `tenant`'s snapshot `version` of
/// `slug` names, if that record is valid (ADR 0012): stored, well formed,
/// written for this snapshot, and naming a suite this build reads. `None`
/// otherwise, as a query would refuse the snapshot. Reads only the record;
/// a storage failure is an error.
pub async fn recorded_suite(
    vault: &dyn VaultStore,
    tenant: TenantId,
    slug: &ConnectorSlug,
    version: &SnapshotVersion,
) -> Result<Option<EnvelopeSuite>, StorageError> {
    match vault
        .get(&TenantPaths::connector_record(tenant, slug, version))
        .await
    {
        Ok(bytes) => Ok(SnapshotRecord::parse(&bytes, version)
            .ok()
            .and_then(|record| EnvelopeSuite::from_id(&record.suite).ok())),
        Err(StorageError::NotFound) => Ok(None),
        Err(err) => Err(err),
    }
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
            &manifest.objects,
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

/// Commit a snapshot whose `objects` are already stored: write its
/// plaintext `record`, then the sealed `manifest` (the commit), then prune
/// what the snapshot does not list. Shared by both writers, so the order
/// cannot drift.
///
/// Both writes are create-only. A record already stored at the version is
/// kept if it equals `record`: an earlier attempt at the version stored it
/// and stopped before its manifest, and this is its retry. If the stored
/// record differs, or the version is already committed, this fails with
/// [`StorageError::AlreadyExists`] and prunes nothing, so a second write at
/// one version replaces neither the snapshot nor its record, and deletes
/// none of its objects.
pub(crate) async fn commit_snapshot(
    vault: &dyn VaultStore,
    tenant: TenantId,
    slug: &ConnectorSlug,
    record: &SnapshotRecord,
    manifest: Bytes,
    objects: &[ObjectId],
) -> Result<(), StorageError> {
    let version = &record.version;
    write_record(vault, tenant, slug, record).await?;
    vault
        .put_if_absent(
            &TenantPaths::connector_manifest(tenant, slug, version),
            manifest,
        )
        .await?;
    let (kind, label) = audit_labels(slug);
    security_audit_event(
        kind,
        Some(tenant),
        "committed",
        &format!(
            "{label}={slug} snapshot={version} objects={}",
            objects.len()
        ),
    );
    prune_superseded(vault, tenant, slug, version, objects).await;
    Ok(())
}

/// Store `record` create-only, or keep the record already stored at its
/// version if that one is equal. A stored record that differs, cannot be
/// parsed, or is gone again (a newer commit pruned it) fails with
/// [`StorageError::AlreadyExists`].
async fn write_record(
    vault: &dyn VaultStore,
    tenant: TenantId,
    slug: &ConnectorSlug,
    record: &SnapshotRecord,
) -> Result<(), StorageError> {
    let path = TenantPaths::connector_record(tenant, slug, &record.version);
    match vault.put_if_absent(&path, record.to_bytes()).await {
        Err(StorageError::AlreadyExists) => {}
        written => return written,
    }
    match vault.get(&path).await {
        Ok(stored)
            if SnapshotRecord::parse(&stored, &record.version)
                .is_ok_and(|stored| stored == *record) =>
        {
            Ok(())
        }
        Ok(_) | Err(StorageError::NotFound) => Err(StorageError::AlreadyExists),
        Err(err) => Err(err),
    }
}

/// Delete everything outside the `current` snapshot, whose objects are
/// `current_objects`. Older manifests go first, so an old snapshot leaves
/// the read path before its objects go. Then older objects and records go,
/// including those of writes that never committed, and so do objects at
/// `current` that it does not list: an earlier attempt at the same version
/// left them when it stopped before its manifest. Newer versions may be in
/// progress and are left alone. Failures leave stale objects behind, which
/// queries never read; the next commit retries.
pub async fn prune_superseded(
    vault: &dyn VaultStore,
    tenant: TenantId,
    slug: &ConnectorSlug,
    current: &SnapshotVersion,
    current_objects: &[ObjectId],
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

    // Objects pruned per superseded version, and at `current` those it does
    // not list.
    let mut pruned: BTreeMap<SnapshotVersion, usize> = BTreeMap::new();
    let mut uncommitted = 0usize;
    match vault
        .list(&TenantPaths::connector_snapshots_prefix(tenant, slug))
        .await
    {
        Ok(paths) => {
            for path in paths {
                let Some((version, object)) =
                    TenantPaths::connector_snapshot_object_parts(tenant, slug, &path)
                else {
                    continue;
                };
                let superseded = version < *current;
                let unlisted = version == *current && !current_objects.contains(&object);
                if !superseded && !unlisted {
                    continue;
                }
                if vault.delete(&path).await.is_err() {
                    failed = true;
                } else if superseded {
                    *pruned.entry(version).or_default() += 1;
                } else {
                    uncommitted += 1;
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
    if uncommitted > 0 {
        security_audit_event(
            kind,
            Some(tenant),
            "pruned",
            &format!("{label}={slug} snapshot={current} uncommitted_objects={uncommitted}"),
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
    use platform_storage::{ObjectStoreVault, StorageUsage, VaultEntry};

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

    /// The datasets [`held_datasets`] lists, by slug.
    async fn listed(vault: &dyn VaultStore, tenant: TenantId) -> Vec<String> {
        held_datasets(vault, tenant)
            .await
            .expect("list")
            .into_iter()
            .map(|held| held.slug.to_string())
            .collect()
    }

    #[tokio::test]
    async fn held_datasets_lists_exactly_the_datasets_held() {
        let vault = ObjectStoreVault::new_in_memory();
        let keypair = TenantKeypair::generate();
        let key = keypair.public_key();
        let tenant = TenantId::generate();
        assert!(listed(&vault, tenant).await.is_empty());

        // A committed snapshot of two objects.
        let health = slug("health");
        let mut writer = SnapshotWriter::begin(&vault, tenant, &key, health.clone());
        let rows = writer.put("rows", b"parquet").await.expect("put");
        let more = writer.put("more", b"more parquet").await.expect("put");
        let version = writer.commit().await.expect("commit");
        // Objects and a record without a manifest: a write that stopped.
        let stopped = slug("upload_stopped");
        let stopped_version = SnapshotVersion::generate();
        vault
            .put(
                &TenantPaths::connector_snapshot_object(
                    tenant,
                    &stopped,
                    &stopped_version,
                    ObjectId::generate(),
                ),
                Bytes::from_static(b"sealed"),
            )
            .await
            .expect("put");
        let record = SnapshotRecord {
            version: stopped_version.clone(),
            suite: EnvelopeSuite::CURRENT.id().to_owned(),
            row_cap: None,
            schema: None,
        };
        vault
            .put(
                &TenantPaths::connector_record(tenant, &stopped, &stopped_version),
                record.to_bytes(),
            )
            .await
            .expect("put");

        let held = held_datasets(&vault, tenant).await.expect("list");
        let mut expected = vec![
            StoredObject {
                object: rows.object,
                ciphertext_bytes: rows.ciphertext_bytes as u64,
            },
            StoredObject {
                object: more.object,
                ciphertext_bytes: more.ciphertext_bytes as u64,
            },
        ];
        expected.sort_by_key(|stored| stored.object);
        assert_eq!(
            held,
            vec![HeldDataset {
                slug: health.clone(),
                version,
                objects: expected,
            }]
        );
        for dataset in [&health, &stopped, &slug("never")] {
            assert_eq!(
                holds(&vault, tenant, dataset).await.expect("holds"),
                held.iter().any(|held| held.slug == *dataset),
                "{dataset}"
            );
        }
        assert!(
            listed(&vault, TenantId::generate()).await.is_empty(),
            "another tenant holds nothing"
        );
    }

    #[tokio::test]
    async fn held_datasets_describe_only_the_current_snapshot() {
        let vault = ObjectStoreVault::new_in_memory();
        let keypair = TenantKeypair::generate();
        let key = keypair.public_key();
        let tenant = TenantId::generate();
        let health = slug("health");
        let mut current = None;
        for _ in 0..2 {
            let mut writer = SnapshotWriter::begin(&vault, tenant, &key, health.clone());
            let written = writer.put("rows", b"parquet").await.expect("put");
            current = Some((writer.commit().await.expect("commit"), written));
        }
        let (version, written) = current.expect("committed");
        // An object a failed prune left at a superseded version, and one a
        // newer write stored before stopping.
        let superseded: SnapshotVersion = "00000000000000000001-0123456789abcdef0123456789abcdef"
            .parse()
            .expect("version");
        for at in [superseded, SnapshotVersion::generate()] {
            vault
                .put(
                    &TenantPaths::connector_snapshot_object(
                        tenant,
                        &health,
                        &at,
                        ObjectId::generate(),
                    ),
                    Bytes::from_static(b"not counted"),
                )
                .await
                .expect("put");
        }

        let held = held_datasets(&vault, tenant).await.expect("list");
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].version, version);
        assert_eq!(
            held[0].objects,
            vec![StoredObject {
                object: written.object,
                ciphertext_bytes: written.ciphertext_bytes as u64,
            }]
        );
    }

    #[tokio::test]
    async fn recorded_suite_reads_only_a_valid_record() {
        let vault = ObjectStoreVault::new_in_memory();
        let keypair = TenantKeypair::generate();
        let key = keypair.public_key();
        let tenant = TenantId::generate();
        let health = slug("health");
        let mut writer = SnapshotWriter::begin(&vault, tenant, &key, health.clone());
        writer.put("rows", b"parquet").await.expect("put");
        let version = writer.commit().await.expect("commit");
        assert_eq!(
            recorded_suite(&vault, tenant, &health, &version)
                .await
                .expect("read"),
            Some(EnvelopeSuite::Hpk1)
        );

        // A record that is malformed, written for another snapshot, or names
        // a suite this build does not read names no suite.
        let path = TenantPaths::connector_record(tenant, &health, &version);
        let other = SnapshotVersion::generate();
        for stored in [
            Bytes::from_static(b"not json"),
            Bytes::from(format!(r#"{{"version":"{other}","suite":"HPK1"}}"#)),
            Bytes::from(format!(r#"{{"version":"{version}","suite":"HPK9"}}"#)),
        ] {
            vault.put(&path, stored.clone()).await.expect("put");
            assert_eq!(
                recorded_suite(&vault, tenant, &health, &version)
                    .await
                    .expect("read"),
                None,
                "{stored:?}"
            );
        }
        // Nor does a missing one.
        vault.delete(&path).await.expect("delete");
        assert_eq!(
            recorded_suite(&vault, tenant, &health, &version)
                .await
                .expect("read"),
            None
        );
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

    /// A vault whose reads find nothing, as if a newer commit pruned what a
    /// create-only write had just found.
    struct PrunedOnRead(ObjectStoreVault);

    #[async_trait::async_trait]
    impl VaultStore for PrunedOnRead {
        async fn put(&self, path: &VaultPath, ciphertext: Bytes) -> Result<(), StorageError> {
            self.0.put(path, ciphertext).await
        }
        async fn put_if_absent(
            &self,
            path: &VaultPath,
            ciphertext: Bytes,
        ) -> Result<(), StorageError> {
            self.0.put_if_absent(path, ciphertext).await
        }
        async fn get(&self, _path: &VaultPath) -> Result<Bytes, StorageError> {
            Err(StorageError::NotFound)
        }
        async fn delete(&self, path: &VaultPath) -> Result<(), StorageError> {
            self.0.delete(path).await
        }
        async fn list(&self, prefix: &VaultPath) -> Result<Vec<VaultPath>, StorageError> {
            self.0.list(prefix).await
        }
        async fn list_entries(&self, prefix: &VaultPath) -> Result<Vec<VaultEntry>, StorageError> {
            self.0.list_entries(prefix).await
        }
        async fn usage(&self, prefix: &VaultPath) -> Result<StorageUsage, StorageError> {
            self.0.usage(prefix).await
        }
    }

    #[tokio::test]
    async fn a_record_unlike_the_one_stored_at_its_version_is_refused() {
        let vault = ObjectStoreVault::new_in_memory();
        let tenant = TenantId::generate();
        let health = slug("health");
        let record = SnapshotRecord {
            version: SnapshotVersion::generate(),
            suite: EnvelopeSuite::CURRENT.id().to_owned(),
            row_cap: None,
            schema: None,
        };
        let path = TenantPaths::connector_record(tenant, &health, &record.version);
        write_record(&vault, tenant, &health, &record)
            .await
            .expect("first write");
        // A retry storing the same record goes through.
        write_record(&vault, tenant, &health, &record)
            .await
            .expect("retry");

        // Another record is refused, and the stored one is kept.
        let other = SnapshotRecord {
            row_cap: Some(1),
            ..record.clone()
        };
        assert!(matches!(
            write_record(&vault, tenant, &health, &other).await,
            Err(StorageError::AlreadyExists)
        ));
        assert_eq!(vault.get(&path).await.expect("get"), record.to_bytes());

        // So is any record when the stored one cannot be parsed.
        vault
            .put(&path, Bytes::from_static(b"not json"))
            .await
            .expect("put");
        assert!(matches!(
            write_record(&vault, tenant, &health, &record).await,
            Err(StorageError::AlreadyExists)
        ));
        assert_eq!(
            vault.get(&path).await.expect("get"),
            Bytes::from_static(b"not json")
        );

        // And when the stored record is gone by the time it is read, even
        // though it was the same.
        vault.put(&path, record.to_bytes()).await.expect("put");
        assert!(matches!(
            write_record(&PrunedOnRead(vault), tenant, &health, &record).await,
            Err(StorageError::AlreadyExists)
        ));
    }
}
