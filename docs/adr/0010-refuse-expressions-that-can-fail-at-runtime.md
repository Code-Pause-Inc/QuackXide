# 0010. Refuse expressions that can fail at runtime in the disclosure gate

* Status: Proposed
* Date: 2026-11-04

## Context

`policy::is_aggregate_only` constrains the plan's shape and the
aggregate arguments, but accepts any scalar expression in `WHERE`,
`GROUP BY`, `HAVING`, the outer `SELECT` and `ORDER BY` above the
aggregate. `QueryScope::sql` runs the whole plan before
`MinCountThreshold` drops cohorts below *k*. An expression that fails on
some rows aborts the query, and the API returns 400 instead of 200. The
failure is a one-bit answer about rows that suppression would have
hidden.

On the `tests/bypass.rs` fixture with *k* = 5, each probe below fails
only when `id = 'p15' AND salary > 9000` (the single `ceo` row) holds:

| Position | Failing probe |
| --- | --- |
| `WHERE` | `salary / CASE WHEN … THEN 0 ELSE 1 END`, `%`, `CAST('x' AS BIGINT)`, `abs` of `i64::MIN`, `to_timestamp('bad')`, `substr` with a negative length, `repeat` or `lpad` to 2^31 characters |
| `WHERE`, implicit | `CASE WHEN … THEN id ELSE '1' END = 5`: type coercion casts the string to `Int64` |
| `GROUP BY` | `salary / CASE WHEN … THEN 0 ELSE 1 END` |
| `HAVING` | `1 / CASE WHEN MAX(salary) > 9000 AND COUNT(*) = 1 THEN 0 ELSE 1 END`, on a cohort of one |
| Outer `SELECT` | `/` or `CAST` over `MAX(salary)` |

The same probes do not fail on integer `+`, `-`, `*` or unary minus
(they wrap), float division, `TRY_CAST`, `COALESCE`, `NULLIF`, `||`,
`lower`, `BETWEEN`, `IN`, `LIKE`, or integer-to-float comparison.
`lpad(dept, 2147483647)` panics inside Arrow; DataFusion turns the panic
into an error, so it is the same oracle, and also a way to exhaust
memory.

An expression with only literal arguments still leaks: `substr(dept, 1,
-1)` or `salary / 0` fails only if some row reaches it, which answers
whether any row matches the `WHERE` clause. So "no data-dependent
argument" is not enough; the operation itself must not be able to fail.

Two facts decide the shape of the fix:

* The gate checks the plan before type coercion. `df.logical_plan()`
  holds `CASE … END = Int64(5)`; the analyzer turns it into
  `CAST(CASE … END AS Int64) = Int64(5)` before execution. A check on
  the uncoerced plan cannot see implicit casts.
* The set of failing operations is open: parsing, size arguments,
  overflow checks and domain checks, across the 261 scalar functions
  DataFusion 55 ships (ADR 0008). Only an allowlist is complete.

The oracle leaks one bit per query, about the rate of the accepted
`suppressed_rows` and differencing residuals (P54, ADR 0002), and each
probe spends budget. It is closed anyway: it is a separate route, and
it would stay open if those residuals are closed later.

Connector datasets reach the engine through the connector Parquet
writer (`platform-connectors/src/parquet_out.rs`), whose column types
are `Utf8`, `Int64`, `Float64` and `Boolean`. Steward uploads
(Code-Pause-Inc/QuackXide#174) will bring steward-declared schemas, so
decimal, date and timestamp columns can arrive later.

## Decision

In zero-knowledge and research mode, after the shape and count checks,
`QueryScope::sql` runs the session's analyzer on the plan and checks
every expression in every node of the analyzed plan. An expression
outside the allowlist refuses the query with `ZkPolicy` before
execution, so the refusal depends only on the SQL text. The shape and
count checks keep running on the plan before analysis, as today.

Allowed expressions, each with allowed operands:

| Expression | Condition |
| --- | --- |
| Column, literal, alias | none |
| `=`, `<>`, `<`, `<=`, `>`, `>=`, `IS [NOT] DISTINCT FROM` | none |
| `AND`, `OR`, `NOT`, `IS [NOT] NULL`, `IS [NOT] TRUE`/`FALSE`/`UNKNOWN`, `BETWEEN` | none |
| `+`, `-`, `*`, unary minus | every operand `Int64`, or every operand `Float64` |
| `/`, `%` | both operands `Float64`; or both `Int64` with a literal divisor other than 0 and −1 (`i64::MIN / -1` overflows) |
| `\|\|` | none |
| `IN (…)` | every list element a literal, or an allowed `CAST` of one |
| `LIKE`, `ILIKE` | pattern and escape are literals |
| `CASE`, `COALESCE`, `NULLIF`, `lower`, `upper` | none |
| `TRY_CAST` | none |
| `CAST` | the input is a literal and the gate's own cast of that value succeeds (so the result does not depend on the data or the optimizer); or `Int64` to `Float64`; or `Boolean`, `Int64`, `Float64` or `Utf8` to `Utf8`; or a cast to the input's own type |
| Aggregate call | already checked by `is_permitted_aggregate` |

Everything else is refused: every other scalar function, arithmetic on
any other type (decimals among them), division by a column or an
aggregate, casts from `Utf8` to any other type, and casts of a column to
a decimal, date or timestamp type. Expression kinds the check does not
know, including any a DataFusion upgrade adds, are refused. The rule
applies to every node, so it also covers the filters and column
projections below the aggregate.

Adding an expression to the allowlist takes a later record and a
`tests/bypass.rs` case showing that it cannot fail on any input of its
allowed types.

## Alternatives considered

* **Record the oracle as residual.** One sentence in
  `docs/THREAT_MODEL.md` and a test pinning it. Smallest change and in
  line with the accepted one-bit residuals, but it leaves a route open
  that this record closes at moderate cost, and it would be the last
  route left if differencing is closed.
* **Suppress small cohorts before `HAVING` and the outer `SELECT`.**
  Covers only failures above the aggregate. `WHERE` and `GROUP BY`
  failures happen row by row before any cohort exists, so it does not
  close the oracle.
* **Refuse known failing functions (denylist).** Incomplete by
  construction: the failing set spans hundreds of functions and grows
  with every DataFusion release.
* **Rewrite failing operations into total ones** (`CAST` to `TRY_CAST`,
  `x / y` to `CASE WHEN y = 0 THEN NULL …`). Keeps more SQL working, but
  needs a correct rewrite for every function, changes query semantics
  silently, and fails open for any function the rewrite misses.

## Consequences

* None of the probes above can reach execution, in research mode or on
  the own-data endpoint with ZK mode on. Ungated queries (ZK mode off)
  are unchanged.
* Refusing `repeat`, `lpad` and the other size-taking functions also
  closes the memory exhaustion they allowed.
* The check relies on two things the tests pin: the analyzer inserts
  every cast that execution evaluates, and the optimizer adds no
  expression that can fail on data. A DataFusion upgrade re-runs the
  bypass suite, and its record lists any change to the allowlisted
  functions.
* `SUM` over a decimal column could overflow on the data. Its result
  type adds ten digits of precision, so overflow needs more than 10^10
  maximal values; this is recorded as residual, not refused.

### Trade-offs for researchers and stewards

* **Less SQL works.** Researchers lose division and modulo by a column
  or an aggregate, string-to-number casts, and every function
  outside the list (`substr`, `round`, `abs`, `date_trunc`, regular
  expressions and the rest). Comparisons, `BETWEEN`, `IN`, `LIKE`,
  `CASE`, grouping, and `COUNT`, `SUM`, `AVG`, `MIN` and `MAX` stay.
* **Two accepted queries become refused.** `SUM(salary) / COUNT(*)`
  (`count_arithmetic`): without `GROUP BY`, `COUNT(*)` is 0 when no row
  matches, so the division is the oracle again; `AVG` gives the mean,
  and other ratios are computed by the client from the released
  aggregates. This also settles P58's question of how that derived
  column is handled. `SUBSTR(id, 2, 2)` (`group_by_substr_id`) is
  refused with the other functions; it already released no rows.
* **Refusals cost budget and give no reason** until P60. A refused query
  is a plan refusal, charged under the order P54 decides, and returns
  the same `ZkPolicy` error as every other plan refusal. Researchers
  will spend units learning the rules, which raises the value of P60's
  typed reasons and researcher guide; P60 adds one reason for this
  refusal.
* **Steward datasets with richer types are restricted first.** Decimal,
  date and timestamp columns from #174 can be filtered, grouped and
  aggregated (`date_col > '2026-01-01'` casts only the literal), but not
  computed on. `CAST(x AS DOUBLE)` makes a decimal usable in arithmetic.
  If #174 needs more, it extends the allowlist with its own record.
* **It does not prevent re-identification from aggregates.** The
  differencing residual in `docs/THREAT_MODEL.md` stays, bounded by the
  budget. This record closes one route to it.
* **Cost per query** is one more analyzer pass and a walk over the plan's
  expressions, linear in the plan's size. It is measured on the bypass
  suite before and after.

### What else changes

* `tests/bypass.rs` gets a case for each probe above, run with its
  condition true and false in research and ZK mode, each refused both
  times; and cases showing that ordinary filters keep working
  (`salary > 3.5`, `salary > '3'`, `dept IN ('eng', 'ops')`,
  `dept LIKE 'e%'`, `salary / 100`).
* `docs/THREAT_MODEL.md` A1 gains a row for the error oracle, the
  plan-level description in `docs/ARCHITECTURE.md` lists the expression
  allowlist, and `CHANGELOG.md` records the refused SQL under Security.
