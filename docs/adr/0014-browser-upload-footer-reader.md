# 0014. Steward upload in the browser: the Parquet footer reader and the seal

* Status: Proposed
* Date: 2026-11-21

## Context

ADR 0012 decided the steward upload: its route, storage layout, body and
bindings. P40 (#221) builds the browser half. Before it seals a file, the
browser reads the Parquet footer to declare the upload's schema and row cap
and to check them against the limits and the dataset's recorded schema; then
the crypto worker seals the file and the snapshot manifest and sends the
body. `docs/adr/README.md` requires a record for a dependency that handles
plaintext, and the footer holds the file's schema and its column
statistics, whose minimum and maximum values are plaintext data.

Three facts shape the reader:

* **The declaration must be the enclave's.** The enclave checks the
  decrypted Parquet against the declaration
  (`QueryScope::register_parquet_declared`): parquet-rs turns the footer's
  schema into Arrow types, refined by the Arrow schema that Arrow writers
  embed in the footer (`ARROW:schema`), and `column_type_of` maps each to a
  family. A declaration they disagree on makes every query of the dataset
  fail (502), and since a dataset keeps its first upload's schema
  (ADR 0012), only deleting it (P42) undoes that. The embedded schema
  changes some families: arrow-rs stores `Timestamp(Second)` and `Date64`
  as plain `INT64` and names their types only there, and a duration is a
  plain `INT64` with no family.
* **The recorded schema was not readable.** `GET /api/v1/datasets` (P39)
  described a snapshot without the declared schema the record holds, so
  the browser could not refuse a mismatch before sealing.
* **The recipient key.** Under ADR 0004 an upload is wrapped to the
  steward's own browser key, and sealers must not trust the enrollment
  record. Until data keys exist, an `HPK1` upload is sealed directly to the
  device's HPKE key, which is what a query's key release opens with only
  when it is the enrolled key. P33 (#175) makes enrollment verifiable; it
  is not built.

## Decision

### The reader: hyparquet's Thrift decoder, interpreted here

The footer is decoded by the compact-protocol Thrift decoder of
[hyparquet](https://github.com/hyparam/hyparquet) 1.33.1 (MIT, no runtime
dependencies; MIT is on the allow list in `backend/deny.toml` and not on
dependency review's deny list), pinned exactly in `frontend/package.json`.
Only `hyparquet/src/thrift.js` is imported. `frontend/src/lib/datasets/footer.ts`
interprets the decoded `FileMetaData` itself and reads only the schema, the
row counts and the key-value metadata. The decoder parses the whole footer,
column statistics included, but nothing reads, keeps or sends them.

Rejected:

* hyparquet's `parquetMetadata`, which decodes every column's statistics
  into JavaScript values: plaintext the declaration does not need.
* The `parquet` crate's metadata reader built for wasm. Without its `arrow`
  feature it yields the same raw schema, so the type mapping would still
  be written again; with it, the module carries Arrow's schema and IPC code
  for one function. Either way it is a second wasm build to maintain.
* A Thrift decoder of our own: a parser of untrusted input that an
  established one already provides.

### Where it runs: a worker of its own

`footer.worker.ts` reads one file and is terminated after one answer, or
after 30 seconds. It reads only the file's tail with `Blob.slice`: the
8-byte trailer, then the footer it points to, at most `FOOTER_MAX_BYTES`
(1 MiB). A real file's footer grows with its row groups and columns and
stays in the hundreds of kilobytes even at the 512 MiB ceiling of
`DATASET_MAX_MIB`. The decoder parses the whole footer, so a crafted one
within the cap costs the worker at most about 64 MiB of heap, and the
timeout bounds its time. The worker returns the declaration (column names,
type families, row count) or a refusal code. The footer is parsed only
there: the UI thread gets the declaration, and the key-holding crypto
worker reads the file only to seal it. Terminating the worker discards
everything it read.

### The enclave's rules, refusing where they cannot be followed

`footer.ts` follows parquet-rs 59 (the version `backend/Cargo.lock` pins):

* the structural checks it makes when it reads the schema list (one root,
  every child present, repetition on every non-root element) and when it
  builds each primitive column (`PrimitiveTypeBuilder::build`: annotations
  against physical types, a logical type consistent with the converted
  type, decimal and fixed-length bounds);
* its type conversion (`from_int32`, `from_int64`, `from_byte_array`,
  `from_fixed_len_byte_array`), reduced to the family of the Arrow type it
  returns;
* the refinements of `apply_hint` that change a family: a `Timestamp` in
  the embedded schema makes an `INT32` or `INT64` column a timestamp, a
  `Date64` makes an `INT64` a date, a `Utf8` (or `LargeUtf8`, `Utf8View`)
  makes a plain `BYTE_ARRAY` a string, and a `Time` or `Duration` gives an
  integer column no family. A dictionary-encoded field refines as its value
  type does. Like parquet-rs, the last `ARROW:schema` entry counts;
* `column_type_of`'s families, and the row count the engine checks: the
  larger of the file's count and its row groups' sum;
* its strings: UTF-8, with a leading byte-order mark kept as part of a
  name, so a column named `\uFEFFid` is declared with it.

The embedded schema is read by `frontend/src/lib/datasets/arrowSchema.ts`,
which decodes the base64 Arrow IPC message and its Schema flatbuffer as far
as the top-level fields' names and types, with every offset bounds- and
alignment-checked. parquet-rs refuses a file whose embedded schema does not
decode or does not name the same columns in the same order, and so does
the browser. It also refuses a flat column whose embedded type is nested
(a list, struct, map, union or run-end encoding) or has child fields: no
writer makes one, and the enclave's Arrow reader can panic on it (a list
without its child field).

The browser refuses whatever parquet-rs would refuse or map to no family:
a nested or repeated column, a binary, time-of-day, duration, interval,
`Float16`, UUID or null column, a malformed footer, and an encrypted file.
It also refuses what an upload cannot declare: no columns, more than 512,
a column name of more than 128 bytes or with a control character, a name
twice, no rows, or more rows than 2^53 − 1.

`fixtures/parquet/` holds small synthetic files, and `schema-vectors.json`
what each side does with each. The generator in
`backend/crates/quackxide-engine/tests/parquet_schema_vectors.rs` writes
them with parquet-rs, and that test runs the enclave's own check
(`register_parquet_declared`) on every file the browser declares;
`frontend/src/lib/datasets/footer.test.ts` checks the browser against the
same files. The browser may refuse a file the enclave could read, never
declare one differently.

The check is advisory: the enclave checks the decrypted data again.

### The listing gives what the browser checks against

`GET /api/v1/datasets` gives, for each uploaded dataset, the `row_cap` and
`schema` its current record declares (null for a connector's dataset or an
unreadable record), and the response gives `dataset_max_bytes`, the upload
size limit (`DATASET_MAX_MIB`). Both are already visible to the operator
(ADR 0012). Before sealing, the browser refuses a schema unlike the
recorded one, a re-upload whose recorded schema is unreadable (the route
would refuse it), and a file whose sealed object would exceed the limit.
The publish form also starts an upload's data dictionary from the recorded
schema, the columns undescribed, for the steward to edit.

### The seal

The crypto worker's `uploadDataset` operation:

1. loads the device's stored keys and never creates any, so key setup stays
   behind the drive's first-run acknowledgement;
2. reads the tenant's enrollment and refuses unless the enrolled public key
   is, byte for byte, the device's own key: key release opens with the
   enrolled key, so an upload sealed to another could never be queried.
   The seal uses the key held in the browser, never the enrolled bytes.
   P33 replaces this comparison with its enrollment check;
3. draws the object id (a random UUID) and the snapshot version (the clock
   in nanoseconds, or one nanosecond after the current version if that is
   later, with 128 random bits), and binds the session's `tid`, which must
   be a canonical UUID, into the `info` strings the wasm module builds;
4. seals the Parquet object, zeroes its own copy of the plaintext, seals
   the manifest (`{version, objects: [object]}`), and sends the `DSU1` body
   under the session's token.

Every refusal before step 4 happens before the file is read. The suite is
`HPK1`, the browser's until P36 (#186).

## Consequences

* The reader costs the bundle one worker chunk of 14.9 KB minified
  (4.9 KB gzip), of which hyparquet's decoder is 1.3 KB (0.6 KB gzip). The
  UI and crypto worker chunks hold none of it (`docs/BENCHMARKS.md`).
* A new runtime dependency parses the steward's own file. Its updates
  arrive through Dependabot; a change to `thrift.js` needs a reviewer's
  reading, since it parses untrusted bytes.
* A change to parquet-rs's type conversion can make the two sides
  disagree. The shared vectors fail when the enclave's side changes, and a
  new writer behaviour needs a new vector.
* Some files the enclave could read are refused, for example one whose
  embedded schema the browser cannot decode, or a flat column with a
  nested embedded type. The steward re-exports them.
* hyparquet reads each Thrift field by its wire type, where parquet-rs
  reads it by the schema's type. A crafted footer that re-encodes a field
  (an `INT32` column's `type` as a byte, a value as an overlong varint) can
  therefore be declared differently from what the enclave reads. No writer
  emits such encodings, the enclave refuses the data, and only the
  steward's own dataset is affected. A decoder of our own for just the
  fields read would close this and drop the dependency.
* The listing shows the steward their datasets' declared row caps and
  schemas.
* The browser holds the whole file, its envelope and the wasm module's
  copies in memory at once, since the seal is single-shot. P34's benchmark
  (#255) measures the module's peak at about three times the payload.
* At `DATASET_MAX_MIB` (64 MiB) the seal is most of the browser's work
  (a recorded manual run; `docs/BENCHMARKS.md` has the method). The
  browser envelope seal benchmark tracks the seal, and its target, 100 MiB
  in under 3 s, leaves room at 64 MiB, so the default stands.
* Production refuses `HPK1` keys and uploads, so until P36 a browser upload
  is stored and listed only in development, and it opens only under the
  test key providers (`DevKeyProvider`, `MultiTenantDevKeyProvider`),
  since development key release is `HPK2`-only (ADR 0012). Until P32, the
  research portal's pasted development token is the crypto worker's
  session for the upload.

## Open questions

1. The proposed target for the upload benchmark in `docs/BENCHMARKS.md`,
   to agree with @AxolDad.
