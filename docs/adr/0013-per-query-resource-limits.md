# 0013. Per-query resource limits

* Status: Proposed
* Date: 2026-11-14

## Context

A query decrypts every object of the dataset's current snapshot, decodes
it into a `MemTable`, and runs on a DataFusion `SessionContext`. Before
this record, that context's `RuntimeEnv` replaced only the object-store
registry (`NoObjectStores`) and kept DataFusion's defaults otherwise: an
unbounded memory pool, and a disk manager that spills to the operating
system's temporary directory. A memory limit alone would make sorts and
aggregations spill decrypted rows to the host's disk, against "Plaintext
never persisted" (`docs/THREAT_MODEL.md`, A2).

Nothing else was bounded per query: how long it waited for one of the
`QUERY_MAX_CONCURRENT` plaintext slots, how long it held plaintext, how
much it decrypted or decoded, or how large its result was. Every
DataFusion failure, running out of memory included, was reported as 400
"query could not be executed", the caller's SQL.

Three facts shape the decision:

* Decoded Arrow arrays are not zeroized (the "Unzeroized working memory"
  residual), and clearing them would need `unsafe`. Bounding how much is
  decoded, and for how long, is what can be done.
* `register_parquet_many` decodes synchronously, so a timer cannot
  interrupt decoding.
* The budget charge order is P54's decision. Today a research query is
  charged after the attestation gate and before it waits for a slot.

## Decision

**One set of limits.** `platform_core::QueryLimits` holds them;
`platform-config` reads them from the environment into
`EnclaveConfig::query_limits`, and `EngineSettings::limits` carries them
to the query service and the engine. `platform_api::wiring::engine_settings`
builds the settings from configuration. Every value is bounded, there is
no value that turns a limit off, and an invalid value refuses startup.
The defaults are placeholders until the query benchmarks measure them.

| Limit | Key | Range | Default | Where it is checked |
| --- | --- | --- | --- | --- |
| Slot wait | `QUERY_SLOT_WAIT_SECS` | 0–120 | 10 | Waiting for a plaintext slot |
| Time | `QUERY_TIMEOUT_SECS` | 1–600 | 60 | From taking the slot through decryption, decoding, execution and serialization |
| Input bytes | `DATASET_MAX_MIB` | 1–512 | 64 | Ciphertext of the objects stored at the snapshot's version, before any key is released; again on what the manifest lists, before each object is opened |
| Input objects | `QUERY_MAX_INPUT_OBJECTS` | 1–256 | 64 | The same two points |
| Decoded rows | `QUERY_MAX_DECODED_ROWS` | 1–10⁹ | 10⁷ | Every Parquet footer before any batch is decoded; decoded rows counted again |
| Decoded bytes | `QUERY_MAX_DECODED_MIB` | 1–65536 | 1024 | Uncompressed sizes in every footer, before any batch is decoded; the Arrow memory of the decoded batches counted again |
| Memory | `QUERY_MEMORY_MIB` | 1–16384 | 256 | DataFusion's memory pool for the query's operators |
| Result rows | `QUERY_MAX_RESULT_ROWS` | 1–10⁶ | 10⁴ | Rows left after disclosure control; without a disclosure policy, as the result streams |
| Result bytes | `QUERY_MAX_RESULT_MIB` | 1–256 | 4 | The result's JSON, as it is written |
| Total memory | `QUERY_TOTAL_MEMORY_MIB` | 1–1048576 | 8192 | At startup: `QUERY_MAX_CONCURRENT` times one query's worst case |

The input cap is the upload limit (ADR 0012), so every dataset an upload
stores can be queried. A sealed manifest over the upload route's 16 KiB
bound fails closed (502) before any key is released: at most 256 objects,
the input-object ceiling, fit in it.

Each limit is bounded on its own, so together they could promise more
memory than any machine has. One query's worst case,
`QueryLimits::worst_case_bytes`, is its pool, its decoded table up to
`QUERY_MAX_DECODED_MIB`, three copies of its input (the ciphertext, the
plaintext the query service keeps, and the engine's copy for the decoder)
and two of its result (the JSON and the rows parsed from it). Startup is
refused when that, times `QUERY_MAX_CONCURRENT`, exceeds
`QUERY_TOTAL_MEMORY_MIB`. The default total fits the default limits on
the default four slots (4 × 1480 MiB).

**No disk.** Each query scope gets its own `RuntimeEnv`: the empty
object-store registry, a `GreedyMemoryPool` of `QUERY_MEMORY_MIB`, and
`DiskManagerMode::Disabled`. DataFusion's operators check
`tmp_files_enabled()` before spilling, so one that runs out of the pool
fails with `ResourcesExhausted` instead of writing a temporary file. The
engine reports that, wherever it is in the error chain, as the memory
limit. `SET` on a runtime key (`datafusion.runtime.temp_directory`,
`max_temp_directory_size`, `memory_limit`) would change the runtime; the
engine refuses every statement before it runs, and tests pin these three.

**Streaming results.** The pool does not track the rows a query collects
for its result. Without a disclosure policy those rows are the result, so
the engine reads them as a stream and stops at the first row over
`QUERY_MAX_RESULT_ROWS`. A disclosure policy has to see the whole
aggregate, and a refusal that counted rows it withholds would tell the
caller about them, so a gated query counts its rows after suppression.
Its rows are at most the groups the pool held while computing them.

**Yielding.** A time limit stops a query by dropping its future, which
takes effect only when the plan returns to the runtime, and the tasks
running a plan's partitions stop the same way when they are aborted.
DataFusion consumes a task's cooperative budget only at scans and
exchanges, so a join that reads each input once could run to its end with
the time limit long past and its slot released. The engine adds a
physical optimizer rule, `YieldEveryBatch`, that wraps every operator not
already cooperative in DataFusion's `CooperativeExec`: each batch any
operator produces consumes budget, so the plan stops at its next batch
boundary.

**Responses.** A limit refusal is `ApiError::QueryLimit(QueryLimit)`;
`QueryUnavailable` stays the refusal for missing wiring. A gated query's
memory and time refusals differ, as "Gated queries" below says.

| Limit | Status | Metrics kind |
| --- | --- | --- |
| Slot wait | 503 with `Retry-After: 5` | `query_busy` |
| Time | 503 | `query_timed_out` |
| Every size limit | 422, with a fixed message per limit | `query_limit` |

A result over a limit is refused, never truncated: a partial result would
look whole. Each refusal emits one `engine.query` "denied" event naming
the limit (`limit=<name>`), with no SQL text.

**Gated queries.** A ZK own-data query or a research query can run out of
its memory pool or its time on rows that suppression withholds. One
aggregate over one scan holds a hash-table entry for every group,
suppressed ones included, and scans every row its filter reads. With
their own statuses and messages, two queries over two cohorts would tell
the caller which limit, if any, a withheld cohort tripped. So in gated
mode both refusals are `ApiError::GatedQueryLimit(QueryLimit)`, whose
response is exactly a disclosure-control refusal's: 422, "query rejected
by disclosure control (see cohort-size rules)", with the same headers.
The audit event is written before the swap and still names the limit.
The metrics keep `query_limit` and `query_timed_out`, because they are
served only on the operator's loopback listener. The other limits keep
their responses in gated mode. The slot wait reads no data. The input
and decode limits depend only on the dataset, the same for every query
over it. The result limits count only the rows released.

| Limit | Ungated | Gated (ZK or research) |
| --- | --- | --- |
| Memory | 422, "query exceeds its memory limit" | 422, the disclosure-control refusal |
| Time | 503, "query exceeded its time limit" | 422, the disclosure-control refusal |
| Every other limit | As above | As above |

**Budget.** Every limit refusal of a research query comes after the
charge, so each costs one unit, the slot-wait refusal included. Tests pin
this order; if P54 moves the charge, they move with it.

**Exit paths.** The time limit wraps everything that holds plaintext, so
on expiry the work is dropped, the plan with it. The slot permit and the
decrypted blobs belong to that work, so they are released and zeroized
on every way out:
a result, an error, the time limit, the caller going away, or a panic
unwinding (the release profile unwinds).

Rejected:

* Decoding on `spawn_blocking`. After a timeout the blocking thread would
  go on decoding plaintext with its slot already released, unless the
  permit moved into the thread. The decode limits bound decoding instead,
  and P53 moves it into the scan.
* A separate input-size key. One value cannot drift from the upload
  limit.
* 422 for the time limit of an ungated query. A query can time out because
  storage or key release is slow, not only because of its SQL. A gated
  query gets 422 anyway, because hiding which limit tripped is worth more
  there than a hint to retry.
* A plan-gate restriction instead of the gated response. A plan's memory
  and running time depend on how many groups and rows match its filter,
  which no check before execution can know.
* A 503 for a gated query's time limit only when it passes before the
  engine runs, while the query waits on storage or key release. Both
  cases come from one timer. Telling them apart would add a branch and
  reveal how far the query got.
* A gated response of its own. Every other refusal of a gated query
  depends only on its SQL and the dataset's schema, so a response of its
  own would name the cause just as the limit's message does.
* Counting a gated query's rows before suppression as they stream. The
  refusal would depend on the cohorts suppression withholds.
* Measuring the machine's memory at startup instead of
  `QUERY_TOTAL_MEMORY_MIB`. A configured total behaves the same on every
  host and can be tested.

## Consequences

* A query that needs more memory than its pool is refused with 422
  instead of spilling; a gated one, as a disclosure-control refusal. Operators set `QUERY_TOTAL_MEMORY_MIB` below the
  machine's memory, and startup checks the other limits against it. With
  the other defaults, a `DATASET_MAX_MIB` over 253 or a
  `QUERY_MAX_CONCURRENT` over 5 needs a larger total.
* The time limit takes effect at batch boundaries. One operator step can
  outlast it: a nested-loop join compares a probe batch with its whole
  build side before it next reads or produces a batch. The pool bounds
  the build side, so it bounds the step.
* A footer's uncompressed sizes understate columns that dictionary or
  run-length encoding shrinks, so the decoded batches are counted too, as
  the Arrow memory they hold. Top-level string and binary columns,
  including those the file's Arrow schema declares as dictionaries, decode
  as view arrays. A plain column is measured from its views' lengths
  before it expands, so a value the file repeats is refused before it is
  copied once per row; a dictionary column is rebuilt from the views, each
  distinct value once. Views point into the pages and dictionaries they
  came from; a dictionary array would not do, since the reader expands one
  inside a batch that crosses into another row group or from
  dictionary-encoded pages to plain ones. Fixed-width columns are checked
  from their widths before each batch of 1024 rows decodes. The table can
  pass `QUERY_MAX_DECODED_MIB` only by the batch's list columns, and its
  strings or binary inside a struct, which are counted only after they
  expand; one page decompresses whole, to the size its own header states,
  before any count sees it, and a `DELTA_BYTE_ARRAY` page, which rebuilds
  each value from the one before it, can copy up to its own size once per
  row of the batch. Arrow memory exceeds a footer's sizes for most
  dictionary-encoded columns, so a dataset near the limit by its footers
  can be refused. A column the file's own Arrow schema declares as a view
  type, or as a dictionary of anything but strings or binary, shares
  buffers across batches, and each batch counts them again, so such a
  dataset can be refused below the limit.
* Whether a query runs out of memory or time depends on the rows it
  reads, including suppressed ones. In gated mode the response no longer
  says which limit tripped, but it still shows that a query was refused.
  Every other refusal of a gated query depends only on its SQL and the
  schema, which the caller knows, so a refused query that otherwise
  passes still answers one question about the rows it read. A time
  refusal also arrives only after the time limit, while a
  disclosure-control refusal arrives at once. Each probe costs a research
  query one unit, and own-data queries have no budget. This channel is
  recorded as a residual risk in `docs/THREAT_MODEL.md`. The input,
  decode and result limits do not depend on the query's suppressed rows.
* In gated mode a query that times out on slow storage or key release
  looks like a disclosure refusal, and a research query that is retried
  is charged again. Operators see the time limit in the audit record and
  in `query_timed_out`.
* Rate limiting and per-tenant fairness stay outside v1: one tenant's
  queries can hold every slot while others are refused with 503.
* A new limit needs a `QueryLimits` field, a configuration key, a
  `QueryLimit` variant and its response.
