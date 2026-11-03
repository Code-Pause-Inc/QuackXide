//! Drive orphan sweep. A drive upload writes its chunks first and its
//! manifest last, so an upload that stops partway leaves chunks no manifest
//! points to. The sweep deletes them once they are older than any upload
//! may take ([`ORPHAN_MIN_AGE`]), so it never touches an upload in progress.
//!
//! An object is an orphan only when it has no manifest and its newest chunk
//! is older than the threshold. The manifest is checked again just before
//! the chunks are deleted. Ages come from the store's last-modified times,
//! so the API host's clock must be within hours of the store's.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use chrono::{DateTime, TimeDelta, Utc};
use platform_core::{ObjectId, TenantId};
use platform_storage::{StorageError, TenantPaths, VaultPath, VaultStore};
use platform_telemetry::{AuditKind, security_audit_event};

/// The longest a drive upload may take, from its first chunk to its
/// manifest. Chunks without a manifest that are older than this are
/// deleted.
pub const ORPHAN_MIN_AGE: TimeDelta = TimeDelta::hours(24);

/// How often `platform-api` runs the sweep.
pub const SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60 * 60);

/// What one sweep did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SweepReport {
    /// Orphaned objects whose chunks were deleted.
    pub objects: usize,
    /// Chunks deleted.
    pub chunks: usize,
    /// Objects without a manifest left alone because a chunk is too recent.
    pub recent: usize,
}

#[derive(Default)]
struct ChunkSet {
    paths: Vec<VaultPath>,
    newest: Option<DateTime<Utc>>,
}

/// Delete the chunks of every drive object, in every tenant, that has no
/// manifest and no chunk newer than [`ORPHAN_MIN_AGE`] before `now`. Stops
/// at the first storage error; the next sweep picks up where it left off.
pub async fn sweep_orphaned_chunks(
    vault: &dyn VaultStore,
    now: DateTime<Utc>,
) -> Result<SweepReport, StorageError> {
    let entries = vault.list_entries(&TenantPaths::all_tenants()).await?;

    let mut manifests: HashSet<(TenantId, ObjectId)> = HashSet::new();
    let mut chunks: HashMap<(TenantId, ObjectId), ChunkSet> = HashMap::new();
    for entry in entries {
        if let Some(key) = TenantPaths::drive_manifest_parts(&entry.path) {
            manifests.insert(key);
        } else if let Some(key) = TenantPaths::drive_chunk_parts(&entry.path) {
            let set = chunks.entry(key).or_default();
            set.newest = Some(
                set.newest
                    .map_or(entry.last_modified, |n| n.max(entry.last_modified)),
            );
            set.paths.push(entry.path);
        }
    }

    let mut report = SweepReport::default();
    for ((tenant, object), set) in chunks {
        if manifests.contains(&(tenant, object)) {
            continue;
        }
        if set
            .newest
            .is_some_and(|newest| now - newest < ORPHAN_MIN_AGE)
        {
            report.recent += 1;
            continue;
        }
        // The manifest may have been written since the listing.
        match vault
            .get(&TenantPaths::drive_manifest(tenant, object))
            .await
        {
            Ok(_) => continue,
            Err(StorageError::NotFound) => {}
            Err(err) => return Err(err),
        }
        let count = set.paths.len();
        for path in &set.paths {
            match vault.delete(path).await {
                Ok(()) | Err(StorageError::NotFound) => {}
                Err(err) => {
                    security_audit_event(
                        AuditKind::DataAccess,
                        Some(tenant),
                        "failed",
                        &format!("orphan_sweep object={object}"),
                    );
                    return Err(err);
                }
            }
        }
        security_audit_event(
            AuditKind::DataAccess,
            Some(tenant),
            "ok",
            &format!("orphan_sweep object={object} chunks={count}"),
        );
        report.objects += 1;
        report.chunks += count;
    }
    Ok(report)
}

/// Run [`sweep_orphaned_chunks`] every [`SWEEP_INTERVAL`], starting one
/// interval after the call. Failures are logged and retried next time.
pub fn spawn_sweeper(vault: Arc<dyn VaultStore>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let start = tokio::time::Instant::now() + SWEEP_INTERVAL;
        let mut interval = tokio::time::interval_at(start, SWEEP_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            match sweep_orphaned_chunks(vault.as_ref(), Utc::now()).await {
                Ok(report) => tracing::info!(
                    objects = report.objects,
                    chunks = report.chunks,
                    recent = report.recent,
                    "drive orphan sweep finished"
                ),
                Err(err) => tracing::warn!(error = %err, "drive orphan sweep failed"),
            }
        }
    })
}
