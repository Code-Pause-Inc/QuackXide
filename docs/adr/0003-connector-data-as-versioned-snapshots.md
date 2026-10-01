# 0003. Connector data as versioned snapshots

* Status: Accepted
* Date: 2026-10-01

## Context

Every connector sync is a full sync. Each one sealed its datasets as new
objects under `tenants/{t}/connectors/{slug}/` and deleted nothing, and a
query decrypted every object under that prefix into one table. After N
syncs every row appeared N times. With the default 15-minute schedule, a
cohort of 3 passes a threshold of *k* = 11 within an hour, releasing
its `MIN`, `MAX` and `SUM`: a disclosure bypass through storage rather
than through SQL. A sync that failed partway also left a partial copy that
queries would read.

## Decision

Connector data is stored as complete, versioned snapshots:

* A sync generates a `SnapshotVersion`: `{unix_nanos:020}-{32 hex}`,
  fixed width so string order is time order, with a random suffix to keep
  concurrent writers apart. It is parsed strictly, since it is a path
  segment.
* Objects are written to
  `tenants/{t}/connectors/{slug}/snapshots/{version}/{object}.parquet`,
  sealed as before (`tenant-envelope-v1|{tenant}|{slug}|{object}`).
* The sync then writes a manifest listing the snapshot's object ids to
  `tenants/{t}/connectors/{slug}/manifests/{version}.manifest`, sealed to
  the tenant with `info` `tenant-snapshot-manifest-v1|{tenant}|{slug}|{version}`.
  Writing the manifest is the commit.
* A query opens only the newest manifest, checks that it names its own
  version and lists no object twice, and decrypts exactly the objects it
  lists. Anything else fails closed (502). With no manifest, the
  connector has no data.
* After committing, the sync deletes every older snapshot: manifests
  first, so an old snapshot leaves the read path before its objects go,
  then objects, including those of syncs that never committed. A deletion
  failure is audited and retried by the next sync; queries never read
  stale snapshots.

No migration is provided: nothing is deployed, and objects in the old flat
layout are no longer read.

## Consequences

* `COUNT(*)` is the same after one sync or many, and an interrupted sync
  leaves the previous snapshot in use (tested).
* Each query opens one extra small envelope (the manifest).
* The newest snapshot is chosen by the writer's clock. Workers with skewed
  clocks could leave an older snapshot current; every committed snapshot
  is a complete copy, so this changes freshness, not counts.
* A query that began before a commit may fail (502) if pruning removes
  its snapshot mid-read. It fails closed and can be retried.
* Sealing binds a manifest to its tenant, connector and version but does
  not authenticate it: an operator holding the tenant's public key can
  forge a snapshot or roll back to an older one by deleting the newest
  manifest. Both are recorded as residual risks in
  `docs/THREAT_MODEL.md`; closing them needs an attested enclave signing
  key.
* A steward-upload path for research datasets should reuse this layout,
  so a re-upload replaces rather than adds.
