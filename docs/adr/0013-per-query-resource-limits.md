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
| Decoded bytes | `QUERY_MAX_DECODED_MIB` | 1–65536 | 1024 | Uncompressed sizes in every footer, before any batch is decoded |
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
`QueryLimits::worst_case_bytes`, is its pool, its decoded table as the
footers report it, three copies of its input (the ciphertext, the
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
`QueryUnavailable` stays the refusal for missing wiring.

| Limit | Status | Metrics kind |
| --- | --- | --- |
| Slot wait | 503 with `Retry-After: 5` | `query_busy` |
| Time | 503 | `query_timed_out` |
| Every size limit | 422, with a fixed message per limit | `query_limit` |

A result over a limit is refused, never truncated: a partial result would
look whole. Each refusal emits one `engine.query` "denied" event naming
the limit (`limit=<name>`), with no SQL text.

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
* 422 for the time limit. A query can time out because storage or key
  release is slow, not only because of its SQL.
* Counting decoded Arrow memory while decoding. Batches share buffers
  (dictionary values, view data), and per-batch sizes count each shared
  buffer once per batch, which would refuse honest data.
* Counting a gated query's rows before suppression as they stream. The
  refusal would depend on the cohorts suppression withholds.
* Measuring the machine's memory at startup instead of
  `QUERY_TOTAL_MEMORY_MIB`. A configured total behaves the same on every
  host and can be tested.

## Consequences

* A query that needs more memory than its pool is refused with 422
  instead of spilling. Operators set `QUERY_TOTAL_MEMORY_MIB` below the
  machine's memory, and startup checks the other limits against it. With
  the other defaults, a `DATASET_MAX_MIB` over 253 or a
  `QUERY_MAX_CONCURRENT` over 5 needs a larger total.
* The time limit takes effect at batch boundaries. One operator step can
  outlast it: a nested-loop join compares a probe batch with its whole
  build side before it next reads or produces a batch. The pool bounds
  the build side, so it bounds the step.
* A footer's uncompressed sizes understate columns that dictionary or
  run-length encoding shrinks, so a decoded table can take more memory
  than `QUERY_MAX_DECODED_MIB`; the row limit holds regardless.
* Whether a query runs out of memory or time depends on the rows it
  reads, including suppressed ones, so these refusals are a coarse side
  channel, recorded as a residual risk in `docs/THREAT_MODEL.md`. The
  input, decode and result limits do not depend on the query's
  suppressed rows.
* Rate limiting and per-tenant fairness stay outside v1: one tenant's
  queries can hold every slot while others are refused with 503.
* A new limit needs a `QueryLimits` field, a configuration key, a
  `QueryLimit` variant and its response.
