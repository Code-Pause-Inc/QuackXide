//! Drive orphan sweep. A drive upload writes its chunks first and its
//! manifest last, so an upload that stops partway leaves chunks no manifest
//! points to. The sweep deletes them once no chunk of the object has been
//! written for [`ORPHAN_MIN_AGE`].
//!
//! An object is an orphan only when it has no manifest and its newest chunk
//! is older than the threshold. Just before deleting, the sweep checks the
//! manifest again and re-lists the object's chunks, so a manifest or chunk
//! written since the first listing saves the object. An upload that resumes
//! after its chunks were swept cannot commit a broken file: `put_manifest`
//! refuses a manifest whose chunks are not all stored (409). Ages come from
//! the store's last-modified times, so the API host's clock must be within
//! hours of the store's.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use chrono::{DateTime, TimeDelta, Utc};
use platform_core::{ObjectId, TenantId};
use platform_storage::{
    DriveEntryKind, StorageError, TenantPaths, VaultEntry, VaultStore,
    list_drive_entries_all_tenants,
};
use platform_telemetry::{AuditKind, security_audit_event};

/// How long an object without a manifest must go with no chunk written
/// before its chunks are deleted. An upload that pauses longer than this
/// between chunks is swept, and its manifest is then refused.
pub const ORPHAN_MIN_AGE: TimeDelta = TimeDelta::hours(24);

/// How often `platform-api` runs the sweep.
pub const SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60 * 60);

/// What one sweep did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SweepReport {
    /// Orphaned objects this run deleted at least one chunk of.
    pub objects: usize,
    /// Chunks this run deleted. A chunk already gone (another replica swept
    /// it) is not counted.
    pub chunks: usize,
    /// Objects without a manifest left alone because a chunk is too recent.
    pub recent: usize,
}

fn newest(entries: &[VaultEntry]) -> Option<DateTime<Utc>> {
    entries.iter().map(|e| e.last_modified).max()
}

fn is_recent(entries: &[VaultEntry], now: DateTime<Utc>) -> bool {
    newest(entries).is_some_and(|newest| now - newest < ORPHAN_MIN_AGE)
}

enum Outcome {
    Saved,
    Recent,
    Deleted(usize),
}

/// Delete the chunks of every drive object, in every tenant, that has no
/// manifest and no chunk written in the [`ORPHAN_MIN_AGE`] before `now`.
/// A storage error on one object does not stop the run: the other objects
/// are still swept and the first error is returned at the end. Only a
/// failed listing deletes nothing.
pub async fn sweep_orphaned_chunks(
    vault: &dyn VaultStore,
    now: DateTime<Utc>,
) -> Result<SweepReport, StorageError> {
    let entries = list_drive_entries_all_tenants(vault).await?;

    let mut manifests: HashSet<(TenantId, ObjectId)> = HashSet::new();
    let mut chunks: HashMap<(TenantId, ObjectId), Vec<VaultEntry>> = HashMap::new();
    for e in entries {
        match e.kind {
            DriveEntryKind::Manifest => {
                manifests.insert((e.tenant, e.object));
            }
            DriveEntryKind::Chunk => chunks
                .entry((e.tenant, e.object))
                .or_default()
                .push(e.entry),
        }
    }

    let mut report = SweepReport::default();
    let mut first_err = None;
    for ((tenant, object), listed) in chunks {
        if manifests.contains(&(tenant, object)) {
            continue;
        }
        if is_recent(&listed, now) {
            report.recent += 1;
            continue;
        }
        match sweep_object(vault, tenant, object, now).await {
            Ok(Outcome::Saved) | Ok(Outcome::Deleted(0)) => {}
            Ok(Outcome::Recent) => report.recent += 1,
            Ok(Outcome::Deleted(count)) => {
                security_audit_event(
                    AuditKind::DataAccess,
                    Some(tenant),
                    "ok",
                    &format!("orphan_sweep object={object} chunks={count}"),
                );
                report.objects += 1;
                report.chunks += count;
            }
            Err((deleted, err)) => {
                security_audit_event(
                    AuditKind::DataAccess,
                    Some(tenant),
                    "failed",
                    &format!("orphan_sweep object={object} chunks={deleted}"),
                );
                report.chunks += deleted;
                first_err.get_or_insert(err);
            }
        }
    }
    match first_err {
        Some(err) => Err(err),
        None => Ok(report),
    }
}

/// Re-check one candidate and delete its chunks. On error, also returns how
/// many chunks were deleted before it.
async fn sweep_object(
    vault: &dyn VaultStore,
    tenant: TenantId,
    object: ObjectId,
    now: DateTime<Utc>,
) -> Result<Outcome, (usize, StorageError)> {
    // A manifest or chunk may have been written since the listing.
    match vault
        .get(&TenantPaths::drive_manifest(tenant, object))
        .await
    {
        Ok(_) => return Ok(Outcome::Saved),
        Err(StorageError::NotFound) => {}
        Err(err) => return Err((0, err)),
    }
    let current = vault
        .list_entries(&TenantPaths::drive_object_prefix(tenant, object))
        .await
        .map_err(|err| (0, err))?;
    if is_recent(&current, now) {
        return Ok(Outcome::Recent);
    }
    let mut deleted = 0;
    for entry in &current {
        match vault.delete(&entry.path).await {
            Ok(()) => deleted += 1,
            Err(StorageError::NotFound) => {}
            Err(err) => return Err((deleted, err)),
        }
    }
    Ok(Outcome::Deleted(deleted))
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
