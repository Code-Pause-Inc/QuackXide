# 0008. Upgrade DataFusion, Arrow, Parquet, and `object_store`

* Status: Accepted
* Date: 2026-10-15

## Context

`quackxide-engine`, `platform-connectors`, `platform-storage`, and `synth-data`
decode and encode plaintext Arrow record batches and Parquet bytes inside the
attested execution boundary, and `platform-storage` talks to the ciphertext
object store through `object_store`. Those four crates (`datafusion`, `arrow`,
`parquet`, and `object_store`) must move as a mutually compatible set so
`cargo tree -d` carries a single major version of each and types (`RecordBatch`,
`SchemaRef`, `ObjectStore`) match across crate boundaries.

On DataFusion 49 (`arrow` 55, `parquet` 55, `object_store` 0.12), two transitive
advisories required exceptions:

* `GHSA-2f9f-gq7v-9h6m` (`RUSTSEC-2026-0196`, `CVE-2026-43868`) in `thrift`
  0.17.0 via `parquet` 55, allowed in `.github/workflows/dependency-review.yml`.
* `RUSTSEC-2026-0194` and `RUSTSEC-2026-0195` in `quick-xml` 0.38.4 via
  `object_store` 0.12, ignored in `backend/deny.toml`.

Two unmaintained-crate warnings (`RUSTSEC-2024-0436` for `paste` and
`RUSTSEC-2025-0134` for `rustls-pemfile`) were also carried in
`backend/deny.toml` pending the upgrade.

(ADR numbers 0006 and 0007 are reserved in `docs/V1_PLAN.md` for sign-in/token
signatures and hybrid post-quantum construction.)

## Decision

Upgrade the workspace and `backend/fuzz/Cargo.lock` to the current stable
DataFusion release and the matching Arrow, Parquet, and `object_store` lines:

| Crate | Previous | Upgraded (`Cargo.toml`) | Resolved in `Cargo.lock` |
| --- | --- | --- | --- |
| `datafusion` | `49` (`49.0.2`) | `55` | `55.2.0` |
| `arrow` | `55` (`55.2.0`) | `59` | `59.3.1` |
| `parquet` | `55` (`55.2.0`) | `59` | `59.3.1` |
| `object_store` | `0.12` (`0.12.5`) | `0.13` | `0.13.2` |

`rust-version` in `backend/Cargo.toml` is raised from `1.85` to `1.94` to match
`datafusion` 55.2.0's `rust-version = "1.94.0"` (`rust-toolchain.toml` pins
`1.94.1`).

### Default-function diff (`SessionContext::new().state()`)

* **Table functions (2 → 2, unchanged):** `generate_series`, `range`. No new
  table functions.
* **Window functions (11 → 11, unchanged):** `cume_dist`, `dense_rank`,
  `first_value`, `lag`, `last_value`, `lead`, `nth_value`, `ntile`,
  `percent_rank`, `rank`, `row_number`.
* **Aggregate functions (43 → 46, +3 added, 0 removed):** added `any_value`,
  `percentile_cont`, `quantile_cont`. All three are refused in zero-knowledge
  and research modes because `policy::PERMITTED_AGGREGATES` is an allowlist
  (`count`, `sum`, `avg`, `min`, `max`).
* **Scalar functions (229 → 261, +32 added, 0 removed):** added `array_add`,
  `array_avg`, `array_compact`, `array_normalize`, `array_product`,
  `array_scale`, `array_subtract`, `array_sum`, `arrays_zip`, `arrow_field`,
  `arrow_metadata`, `arrow_try_cast`, `cast_to_type`, `cosine_distance`,
  `dot_product`, `file_row_index`, `inner_product`, `input_file_name`,
  `list_add`, `list_avg`, `list_compact`, `list_normalize`, `list_product`,
  `list_scale`, `list_subtract`, `list_sum`, `list_zip`, `make_time`, `rand`,
  `to_time`, `try_cast_to_type`, `with_metadata`. None performs external I/O;
  `file_row_index` and `input_file_name` read file-scan metadata that is absent
  on `QueryScope`'s in-memory `MemTable`s (and `NoObjectStores` refuses any
  object-store lookup), while `policy::is_aggregate_only` continues to require
  plain columns or non-null literals as aggregate arguments and plain column
  projections below the aggregate.

### Disclosure gate and `tests/bypass.rs`

`policy::PERMITTED_AGGREGATES`, `policy::is_aggregate_only`, and
`disclosure::verify_count_column` are unchanged. Every SQL case in
`quackxide-engine/tests/{bypass.rs,disclosure.rs,engine_query.rs}` keeps the
same SQL text and `Rows(n)` count. Two refusal cases in `tests/bypass.rs`
(`count_filter` and `filter_on_value`) move from `Unplannable` to `Rejected`:
`sqlparser` 0.62 (up from 0.55) now parses `FILTER (WHERE …)` on aggregates,
and `policy::is_aggregate_only` refuses them at `agg.params.filter.is_none()`.

## Consequences

* `parquet` 59 removes the external `thrift` dependency in favour of its own
  bounded compact-protocol reader, eliminating `GHSA-2f9f-gq7v-9h6m`
  (`CVE-2026-43868`) from both `backend/Cargo.lock` and
  `backend/fuzz/Cargo.lock`. The `allow-ghsas` exception in
  `.github/workflows/dependency-review.yml` is removed.
* `paste` (`RUSTSEC-2024-0436`) and `rustls-pemfile` (`RUSTSEC-2025-0134`) are
  no longer in the dependency graph and are removed from `backend/deny.toml`.
* `object_store` 0.13 moves `quick-xml` from `0.38.4` to `0.39.4`, while
  `RUSTSEC-2026-0194` and `RUSTSEC-2026-0195` require `quick-xml >= 0.41.0`.
  Those two entries remain in `backend/deny.toml` (scoped to operator
  object-store XML responses only) until `object_store` adopts `quick-xml`
  0.41+.
* `platform-storage` imports `object_store::ObjectStoreExt` for the `put`,
  `get`, and `delete` convenience methods moved off the `ObjectStore` trait in
  `object_store` 0.13.
* `cargo tree -d` in `backend/` and `backend/fuzz/` shows a single version each
  of `datafusion`, `arrow`, `parquet`, and `object_store`.
