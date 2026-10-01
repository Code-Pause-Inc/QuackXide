//! Connector data as complete, versioned snapshots (ADR 0003).
//!
//! A sync writes its sealed objects under a new [`SnapshotVersion`], then a
//! sealed manifest listing them. Queries read only the newest snapshot that
//! has a manifest, so a sync that stops partway changes nothing they see,
//! and repeated syncs never stack copies of the same rows. Superseded
//! snapshots are deleted after the commit.
//!
//! The manifest is sealed to the tenant and bound to tenant, connector and
//! version, so it cannot be moved between them. HPKE seals to a public key,
//! so this binds but does not authenticate: an operator holding the
//! tenant's public key can still forge a whole snapshot, as with any
//! connector object (`docs/THREAT_MODEL.md`).

use std::collections::BTreeMap;

use platform_core::{ConnectorSlug, ObjectId, SnapshotVersion, TenantId};
use platform_crypto::{TenantPublicKey, hpke_seal_to_tenant};
use platform_storage::{TenantPaths, VaultStore};
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

/// HPKE `info` binding for a snapshot manifest.
pub fn manifest_info(
    tenant: &TenantId,
    slug: &ConnectorSlug,
    version: &SnapshotVersion,
) -> Vec<u8> {
    format!("tenant-snapshot-manifest-v1|{tenant}|{slug}|{version}").into_bytes()
}

/// Writes one snapshot. Nothing it writes is visible to queries until
/// [`commit`](Self::commit) stores the manifest.
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

    /// Seal one dataset's Parquet into the snapshot.
    pub async fn put(
        &mut self,
        dataset: &str,
        parquet: &[u8],
    ) -> Result<WrittenObject, PipelineError> {
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

    /// Store the manifest, which makes this the snapshot queries read, then
    /// delete superseded snapshots.
    pub async fn commit(self) -> Result<SnapshotVersion, PipelineError> {
        let manifest = SnapshotManifest {
            version: self.version.clone(),
            objects: self.objects,
        };
        let plaintext = serde_json::to_vec(&manifest).map_err(|_| PipelineError::Seal)?;
        let info = manifest_info(&self.tenant, &self.slug, &self.version);
        let envelope =
            hpke_seal_to_tenant(self.key, &info, &plaintext).map_err(|_| PipelineError::Seal)?;
        self.vault
            .put(
                &TenantPaths::connector_manifest(self.tenant, &self.slug, &self.version),
                envelope.into(),
            )
            .await
            .map_err(|e| PipelineError::Storage(e.to_string()))?;
        security_audit_event(
            AuditKind::ConnectorSync,
            Some(self.tenant),
            "committed",
            &format!(
                "connector={} snapshot={} objects={}",
                self.slug,
                self.version,
                manifest.objects.len()
            ),
        );
        prune_superseded(self.vault, self.tenant, &self.slug, &self.version).await;
        Ok(self.version)
    }
}

/// Delete every snapshot older than `current`: manifests first, so an old
/// snapshot leaves the read path before its objects go, then objects,
/// including those of syncs that never committed. Failures leave stale
/// snapshots behind, which queries never read; the next sync retries.
pub async fn prune_superseded(
    vault: &dyn VaultStore,
    tenant: TenantId,
    slug: &ConnectorSlug,
    current: &SnapshotVersion,
) {
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

    for (version, objects) in pruned {
        security_audit_event(
            AuditKind::ConnectorSync,
            Some(tenant),
            "pruned",
            &format!("connector={slug} superseded_snapshot={version} objects={objects}"),
        );
    }
    if failed {
        security_audit_event(
            AuditKind::ConnectorSync,
            Some(tenant),
            "prune_failed",
            &format!("connector={slug} stale snapshots remain; queries read only the newest"),
        );
    }
}
