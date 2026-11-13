# 0012. Steward dataset upload

* Status: Proposed
* Date: 2026-11-08

## Context

A steward needs to upload a research dataset from the browser and have a
granted researcher query it (definition-of-done item 1). Drive cannot
carry it: drive files are AES-GCM chunks under keys wrapped by a
browser-only key-encryption key, so no enclave can open them. The query
path reads only HPKE envelopes of Parquet listed by the newest committed
snapshot manifest under `tenants/{t}/connectors/{slug}/` (ADR 0003). The
browser can seal HPKE envelopes (`envelope-wasm`), and
`platform_crypto::info::steward_upload` already defines the binding
`steward-upload-v1|{tenant}|{dataset}|{object}` without fixing what fills
its fields.

The API sees only ciphertext, so it can refuse only what it can check
without opening anything. Several things follow from the code as it is:

* Grants, listings and access requests are keyed by a connector slug, and
  the slug is also the SQL table name. An identifier that is not a valid
  unquoted SQL name has to be double-quoted in every query.
* The snapshot manifest is bound to its version, and the browser seals
  what the steward uploads. Whoever seals the manifest needs the version
  first.
* "The dataset has a committed snapshot" is false before the first upload.
* Under ADR 0004, each dataset gets its own data key, wrapped to Cloud KMS
  and, for uploads, to the steward's browser key, and manifests move to
  that data key under a new frame. Sealers must not trust the enrollment
  record, which the operator controls.
* No measured bound for the dataset size exists yet: the browser seal is
  single-shot, and `docs/BENCHMARKS.md` does not exist (P34, P40).

## Decision

### Dataset identity: a reserved slug namespace

An uploaded dataset is named by a `ConnectorSlug` that starts with
`upload_` (`platform_core::UPLOAD_DATASET_PREFIX`), for example
`upload_cohorts`. No connector's slug may start with it (a test checks
the built-in catalog), and `SnapshotWriter`, the connector writer,
refuses one. The slug alone decides the dataset's kind
(`ConnectorSlug::kind`), so it is never read from stored state.

The steward chooses the name. It is the dataset id everywhere: the
storage path segment, the grant, listing and request key, the research
query's `connector` field, and the SQL table name (`FROM upload_cohorts`,
unquoted when the name uses only `[a-z0-9_]`). Grants, listings, the
request types and the frontend client are unchanged.

A new UUID dataset id was rejected: every query would need a quoted table
name, and grants, listings, requests, the frontend client and P39's path
assumption would all change.

### Storage layout

Uploads reuse ADR 0003's snapshots under the same prefix:

```text
tenants/{t}/connectors/{slug}/snapshots/{version}/{object}.parquet   sealed by the browser
tenants/{t}/connectors/{slug}/records/{version}.json                 plaintext record
tenants/{t}/connectors/{slug}/manifests/{version}.manifest           sealed by the browser; the commit
tenants/{t}/connectors/{slug}/keys/{version}/                        reserved: wrapped data keys
```

The upload is written in that order: the object, then the record, then
the manifest. Writing the manifest is the commit. Superseded snapshots are
then pruned, manifests first, then objects and records, including those of
uploads that never committed. A re-upload replaces the dataset rather than
adding to it, and an upload that stops before its manifest changes nothing
a query reads.

`keys/{version}/` is reserved for the snapshot's wrapped data keys under
ADR 0004: one wrapped to the KMS key, and for an upload one wrapped to the
steward's browser key. Nothing writes there under `HPK1`. When the data
keys are built, they are written before the record and pruned with the
snapshot.

### The per-snapshot record

Every committed snapshot, a connector's or an upload's, has a plaintext
record (`platform_storage::SnapshotRecord`), so the API can describe it
without key release:

* `version`: the snapshot it describes; a record naming another is
  refused;
* `suite`: the envelope suite of its objects and manifest, by a stable
  name (`EnvelopeSuite::id`, today `HPK1`);
* for an upload only, `row_cap` and `schema`: what the steward declared.

A query refuses a snapshot without a valid record (502). P39 reads the
suite from the record and the write time from the version, without
opening anything.

### Input format and declared schema

Input is Parquet only in v1. CSV needs a Parquet writer in the browser or
an attested conversion step, and is proposed outside v1.

The declared schema is an ordered list of columns, each a name and a type
family (`platform_core::DeclaredSchema`): `boolean`, the signed and
unsigned integer widths, `float32`, `float64`, `string` (any string
encoding, dictionary-encoded included), `date`, `timestamp` (any unit or
time zone) and `decimal` (any precision and scale). It has 1 to 512
columns, with names of 1 to 128 bytes, no control characters, and no name
twice. Nullability is not declared, so re-exporting the same data with
another writer does not change it.

The schema is kept in plaintext in the record, where the operator can
see it. The alternative, sealing it with the dataset and keeping only a
digest, was rejected for v1:

* the enclave needs the declared schema itself to check the decrypted
  data, and a digest would make the browser and the enclave produce one
  canonical encoding from different sources (the Parquet footer and the
  Arrow schema);
* column names and types are low-entropy, so a digest of them hides
  little from an operator who guesses;
* a plaintext schema lets later work gate a query's plan before any key is
  released.

When manifests move to the data key (ADR 0004), the schema can move into
the sealed manifest. P40 tells the steward, in one line before the upload,
that column names and types are visible to the operator.

### One object per upload

An upload is one sealed object. Several same-schema objects under a
per-object cap would bound memory per request, but the seal is single-shot
today, so the browser holds the whole file anyway. A later format version
can carry several objects.

### Bindings, and who chooses each id

| Envelope | Sealed by | `info` |
| --- | --- | --- |
| Object | Browser | `steward-upload-v1\|{tenant}\|{slug}\|{object}` |
| Manifest | Browser | `tenant-snapshot-manifest-v1\|{tenant}\|{slug}\|{version}` |

Under the hybrid suite these become `-v2` (ADR 0007).

* **Tenant:** the session's verified `tid`. The route stores the upload
  only under the tenant in the token, so a body sealed for another tenant
  is stored and never opens.
* **Object id:** a random UUID the browser draws before sealing, sent in
  canonical form. Any other spelling is refused, since the browser sealed
  under its own spelling.
* **Version:** chosen by the browser in `SnapshotVersion` form, because
  the manifest binds it. The API refuses a version not newer than the
  dataset's current one (409), or more than five minutes ahead of the
  server's clock (422), which would keep later uploads from replacing it.
  The browser takes its own clock, or the current version plus one
  nanosecond if that is later. The write time P39 shows is therefore the
  browser's, bounded by the server's clock.
* **Manifest:** sealed by the browser. The server would otherwise need the
  tenant key from the enrollment record, which sealers must not trust
  (ADR 0004). Under the data-key model only the browser can seal it, so
  the format does not change when that lands.

The upload route holds no key and opens neither envelope, so it cannot
check that the manifest lists the stored object or that the bindings
match. Only a query opens them, inside the enclave, and a mismatch fails
closed there (502). The steward controls the content either way.

### The route

`PUT /api/v1/datasets/{dataset}`, behind the same access-token middleware
as other data routes. It uses only the vault and the configuration, so it
works where the query service is not configured. The body:

| Field | Bytes | Contents |
| --- | --- | --- |
| magic | 4 | `DSU1` |
| header length | 4 | big-endian, 1 to 128 KiB |
| header | header length | JSON: `version`, `object`, `row_cap`, `schema`; unknown fields refused |
| manifest length | 4 | big-endian, 1 to 16 KiB |
| manifest | manifest length | sealed manifest envelope |
| object | the rest | sealed Parquet envelope |

`platform_connectors::upload::parse_upload_body` checks each length
against the bytes left before reading past it. Both envelopes must be
complete frames of one suite this build reads
(`platform_crypto::check_envelope_frame`: a known magic and at least the
encapsulated key and tag). The parser lives outside `platform-api`, so
the `upload_body` fuzz target does not build DataFusion.

The route has its own body limit: `DATASET_MAX_MIB` plus the most a body
holds besides its object. `DATASET_MAX_MIB` (`platform-config`) is the
largest dataset, in ciphertext bytes, that an upload may store. It
defaults to 64 and accepts 1 to 512; any other value refuses startup.
The default is a placeholder, not a measured bound: P34's and P40's
browser benchmarks confirm or lower it. P52's cap on decrypted input
reuses it.

The declared row cap is from 1 to 2^53 − 1, the largest integer a
browser's JSON numbers hold exactly. It bounds what the enclave decodes,
not what the API stores.

| Refusal | Status | Audit (`data.access`) |
| --- | --- | --- |
| No token, or a token that is not `access` | 401 | `auth.decision` denied |
| Dataset id is not a slug | 400 | — |
| Dataset id outside the upload namespace | 404 | denied, `not_upload_dataset` |
| Body or object over the limit | 413 | denied, `too_large` |
| Malformed body, header, or envelope frame | 422 | denied, with the reason |
| Version more than five minutes ahead | 422 | denied, `version_ahead` |
| Declared schema unlike the recorded one | 422 | denied, `schema_mismatch` |
| Version not newer than the current one | 409 | denied, `stale_version` |
| Current record unreadable | 502 | failed, `record_unreadable` |
| Storage failure | 503 or 502 | failed, `storage` |

The stored object is audited `ok`, and the commit and pruning are audited
`committed` and `pruned`, as connector snapshots are under
`connector.sync`. Details carry identifiers and fixed reasons only, never
column names.

### "Holds"

A steward holds a dataset when it has a committed snapshot under the
steward's tenant (`platform_connectors::snapshot::holds`). That is the one
definition. `ResearchService::publish_listing` refuses a dataset the
steward does not hold (404, `research.catalog` denied); the service holds
the app's vault for this check only, and opens nothing. P39's listing
uses the same function.

The upload route does not need "holds". Inside the upload namespace, the
first upload creates the dataset, and the tenant comes from the token, so
a steward can write only their own datasets. A separate create step (for
example a `put_if_absent` dataset record) was rejected: it would add a
second notion of existence and a second request to protect only the
first schema against two concurrent first uploads. If that race happens,
the newer upload becomes current and its schema is the recorded one.

### Query

The query path picks each object's `info` by the dataset's kind
(`snapshot::object_info`), reads the record before any key is released,
and for an upload passes the declared schema and row cap to the engine.
`QueryScope::register_parquet_declared` checks each object's schema and
the rows its footer reports before decoding, and the decoded rows after.
A mismatch is `QueryError::DeclarationMismatch`, which names the check and
never a column, and the API returns 502. The research budget is charged
before decryption, so a mismatch is charged today; P54 decides whether
that stays.

A manifest that lists an object that is not stored fails closed with 502,
not 404.

### Untrusted Parquet

Steward-supplied Parquet is decoded only in the enclave, after the
DataFusion 55 upgrade (ADR 0008), which removed the `thrift` exception
that assumed the platform read only Parquet it wrote. The `zstd`
exceptions in `backend/deny.toml` still hold: they rest on which `zstd`
APIs and features are built (no `with_context` streams, no `seekable`, no
`legacy`), not on who wrote the compressed pages.

## Consequences

* A steward can upload a dataset and a granted researcher can query it,
  through the same grant, budget and disclosure gates as connector data
  (tested in `research_api.rs` and `dataset_upload_api.rs`).
* The operator sees more for each uploaded dataset, published or not: its
  name, its snapshot versions and write times, the object id and
  ciphertext size, the suite, the declared row cap and the declared
  schema. `docs/THREAT_MODEL.md` ("Metadata") records this.
* Connector snapshots store one more small object each, the record.
* An upload is buffered whole in memory, up to the body limit. Uploads are
  not limited in number; availability is not a v1 goal.
* A steward cannot change a dataset's schema by re-uploading. Deleting the
  dataset (P42) and uploading again is the path.
* A retry of an upload that committed but lost its response gets 409. The
  browser checks the current version through P39 before retrying.
* P39 lists over this layout. P40 builds the browser half: the header, the
  version choice, both seals, and the plaintext-schema notice. P42 deletes
  the whole dataset prefix, records included. P52 reuses
  `DATASET_MAX_MIB`. P53 keeps the declared check when it rewrites
  `register_parquet_many`. P54 decides whether a mismatch is charged.
* The committed `steward_upload` envelope vectors put a UUID in the
  dataset field. The `info` format allows it, but it is not an upload id.
  P40's browser vectors should use an `upload_` name.

## Open questions

1. 0009 to 0011 are taken on `main` and no open branch uses 0012, so
   this record uses 0012. The maintainer reserves numbers and may renumber
   it.
2. Are 64 MiB as the default and 512 MiB as the ceiling acceptable until
   P34 and P40 measure the browser seal and upload?
3. Should the declared schema move into the sealed manifest when manifests
   move to the data key, leaving only a digest in plaintext?
4. 404 or 403 for an upload outside the upload namespace? 404 is chosen,
   since the steward holds no upload dataset by that name.
