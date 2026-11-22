# 0015. Refuse `MIN` and `MAX`, and mask dominated sums, in the disclosure gate

* Status: Proposed
* Date: 2026-11-21

## Context

`MinCountThreshold` drops every result row whose cohort is below *k*, so
no released row describes fewer than *k* rows. A value in a released row
can still be one person's. On the `tests/bypass.rs` fixture with *k* = 5
(`eng` and `ops` six rows each, `legal` two, `ceo` one), the gate
accepts each of these queries, every one with `COUNT(*) AS n`:

| Query | Released | What it gives away |
| --- | --- | --- |
| `MAX(salary)` over `people` | n = 15, 9001 | the salary of `p15`, the one `ceo` |
| `MAX(salary)` with `WHERE salary < 9001`, then `< 7002`, and so on; `MIN(salary)` the same way from the bottom | 7002, 7001, 205, … | one salary per query, until all fifteen are out |
| `MAX(salary)` with `WHERE id BETWEEN 'p10' AND 'p14'`, then `'p11' AND 'p15'` | 7002, then 9001 | that 9001 is `p15`'s |
| `MAX(id)` over `people` | n = 15, `p15` | an identifier, verbatim |
| `GROUP BY dept HAVING MAX(salary) > 104`, then `> 105` | `eng` present, then absent | the top `eng` salary, by bisection |
| `SUM(salary)` with `WHERE dept IN ('ceo', 'eng')` | n = 7, 9616 | 94% of it is `p15`'s salary |
| `SUM(salary)` with `WHERE dept IN ('legal', 'eng')` | n = 8, 14618 | anyone who knows one `legal` salary learns the other to within 9% |

`MIN` and `MAX` return one row's value by definition, whatever the
cohort size, and on a text column that value can be an identifier.
Filtering below the previous answer walks a column one value per query,
the walk ADR 0002 left open, and an id-range filter says whose value
each one is. `HAVING` and `ORDER BY` use the same aggregates without
releasing them. A `SUM` is close to one person's value when one or two
people hold most of the total, and `AVG` is `SUM / n` with `n` always
released. `docs/THREAT_MODEL.md` records this as the "Extreme values"
residual and calls the fix a policy decision.

`DisclosurePolicy::apply` (`disclosure.rs:39-41`) sees only the output
batches, after execution, under the caller's aliases. A rule about
contributions needs per-group values that the output does not hold: the
largest contributions to each sum. `verify_count_column` traces an
output column to its aggregate by plan position, which says which
columns are sums but not what each group's rows contributed to them.

## Decision

### `MIN` and `MAX`

`min` and `max` leave `PERMITTED_AGGREGATES` (`policy.rs:37`). A plan
that uses either anywhere in its aggregate (the select list, `HAVING` or
`ORDER BY`, which DataFusion plans into the same `Aggregate`) is refused
with `ZkPolicy` before execution, like every other aggregate outside the
list, in research and ZK mode alike. Ungated queries (ZK mode off) keep
them.

### `SUM` and `AVG`: the p% rule

P58 (#281) applies this part; until it lands, dominated sums stay a
residual.

* **Rule.** For each released `SUM(x)` or `AVG(x)` and each group, let
  *T* be the sum of the absolute values of the group's non-null `x`, and
  *x*₁ ≥ *x*₂ the two largest absolute values. The cell is sensitive
  when *T* − *x*₁ − *x*₂ < (*p* / 100) · *x*₁: anyone who knows the
  second-largest value, subtracting it from the total, learns the
  largest to within *p* percent. A sum over fewer than three non-null
  values is therefore sensitive, whatever *n* is, unless every value is
  0.
* **Parameter.** *p* is an integer percent, 10 when unset: anyone who
  knows the second-largest value is still at least 10% off the largest.
  It comes from configuration beside `RESEARCH_MIN_COHORT_SIZE` (P58
  names it), and research and ZK mode share it. An unparseable value
  refuses startup, and 0 refuses every gated query, as *k* = 0 does.
* **Unit of contribution.** One row. The engine has no notion of a
  person, and the cohort threshold already counts rows.
* **Negative values.** The rule uses absolute values, for the total and
  for the largest contributions, so offsetting gains and losses cannot
  hide a large one.
* **Values that are not finite numbers.** If *T*, *x*₁ or *x*₂ is not
  finite (a `Float64` column holding NaN or infinity), the cell is
  sensitive.
* **`AVG`.** `AVG(x)` takes the decision of `SUM(x)` over the same
  group, since `SUM = AVG × n`.
* **`DISTINCT`.** `SUM(DISTINCT x)` and `AVG(DISTINCT x)` are refused:
  their contributions would be distinct values, not rows.
* **The cell, not the row.** A sensitive cell is released as null, and
  the row keeps `n` and its other cells. `suppressed_rows` keeps
  counting only rows that the cohort threshold withholds. A null sum
  beside a non-zero `COUNT(x)` can only be a masked one.
* **Where it runs.** After the plan passes the gate, `QueryScope::sql`
  adds hidden auxiliary aggregates to the plan's one `Aggregate`: for
  each argument column of a `SUM` or `AVG`, *T*, *x*₁ and *x*₂, computed
  so that they cannot fail at runtime (ADR 0011). A projection placed
  directly above the `Aggregate` replaces each sensitive `SUM` or `AVG`
  with null and drops the auxiliary columns. Every operator above it
  (`HAVING`, derived columns, `ORDER BY`, `LIMIT`, outer queries) reads
  the masked value, and no auxiliary value reaches egress.
* **Derived columns** follow: `SUM(salary) * 2`, or a `CASE` over
  `SUM(salary)`, reads null for a masked cell. `SUM(salary) / COUNT(*)`
  (`count_arithmetic`) stays refused under ADR 0011.

### Both modes

Research and own-data ZK queries share one gate, as for grouping sets
(ADR 0002) and failing expressions (ADR 0011), and *p* reaches both
through the query service, as *k* does (`threshold()`). ZK mode exists
to stop one query from disclosing records of the tenant's own data.
Differencing on own data is unbounded (`docs/THREAT_MODEL.md`), but that
is no reason to leave a single-query disclosure open.

## Alternatives considered

* **Release `MIN` and `MAX` only when at least *t* rows share the
  extreme.** Keeps them for coarse columns (age in years, a score),
  where `GROUP BY` with `COUNT(*)` already shows the common values; on
  continuous or identifying columns it almost never releases. It needs
  an accumulator of the engine's own that returns the extreme and how
  many rows hold it, for every comparable type, and the in-plan mask
  above, or `HAVING` and `ORDER BY` would still read the unmasked value.
  Whether the extreme is masked still depends on the rare values above
  it, so `WHERE x < T` finds a masked maximum by bisection, as counts
  already allow (#173). A later record can add it once P58's mask
  exists.
* **Top- and bottom-coding** (release the extreme capped at a bound).
  Needs a bound per column, which the engine does not have. A bound
  computed from the data is itself an order statistic to protect, and
  capping means nothing for text columns.
* **Keep `MIN` and `MAX` and record the residual.** Leaves a one-query
  disclosure that needs no differencing, at one budget unit per value.
* **(*n*, *k*) dominance** (sensitive when the *n* largest contributions
  exceed *k* percent of the total). With *n* = 1 it needs only the
  largest contribution, which DataFusion's own `max` computes, but it
  releases the `legal` row above, where each of two people learns the
  other's value: 7002 is 48% of 14618. With *n* = 2 it needs the same two
  values as the p% rule, but its threshold is a share of the total, not
  the error left to someone who knows one contribution, which is the
  question the p% rule asks directly.
* **Apply the rule at egress,** carrying the auxiliary values up through
  every operator above the `Aggregate`, as #281's text sketches.
  `HAVING`, `ORDER BY` with `LIMIT` and derived columns would run on the
  unmasked total first: `HAVING SUM(salary) > T` would answer, through
  `suppressed_rows`, whether a dominated total exceeds *T*, and
  `ORDER BY SUM(salary) DESC LIMIT 1` would choose a row by it.
* **Suppress the whole row.** Withholds `n` and every other cell for one
  dominated column, and needs the same auxiliary values carried to
  egress.
* **Count contributions per person through an identifier column.** Needs
  the steward to declare that column, for which ADR 0012's declaration
  has no place, and a second level of aggregation in the gate. Left for
  later.

## Consequences

* No query in research or ZK mode returns a value through `MIN` or
  `MAX`. The walk, id-range and `HAVING` probes above are refused at
  planning, so the refusal depends only on the SQL text.
* After P58, a released sum or mean no longer approximates its largest
  contributors. Differencing is unchanged: the total over a cohort with
  one extra person, minus the total without them, is that person's value
  in two queries, bounded by the research budget and unbounded on
  own-data queries (`docs/THREAT_MODEL.md`). A masked total can also be
  the difference of released totals over other groups or columns. The
  rule protects one released cell at a time.
* **Rows, not people.** The cohort threshold and the rule both count
  rows. A dataset in which one person has several rows (visits,
  transactions) must be prepared one row per person, or both count that
  person more than once. `docs/THREAT_MODEL.md` records this.
* The cohort threshold still applies at egress, after `HAVING`, so its
  one-bit `suppressed_rows` residual (#173) is unchanged.

### Trade-offs for researchers and stewards

* **No `MIN` or `MAX` in gated queries.** A range comes from counts over
  bands (`salary / 1000 AS band`, each band suppressed below *k*), and
  `AVG` gives the centre. On own data, a check such as the newest
  timestamp needs ZK mode off, which removes the no-naked-data guarantee
  for that deployment, as before.
* **After P58, a sum or mean can be null** in a released row; #173's
  result contract records why.
* **Refusals cost budget and give no reason** until P60, as for every
  plan refusal.
* **Cost per query** (P58): three auxiliary aggregates per summed column,
  in the same pass, with constant state per group. P58 measures it on
  the bypass suite.

### What else changes

* `tests/bypass.rs`: cases that released rows with `MIN` or `MAX` keep
  their purpose with `SUM` or `AVG` (`sum_avg`, `group_by_id`,
  `having_value`, the two ordering cases, and in ZK mode
  `rare_cohort_suppressed`); `group_by_id_per_column`, which released
  `MAX(dept)` per id, is now refused. Refused cases that were the only
  ones to reach a check (`FILTER` on a value aggregate, a computed column
  below the aggregate, sorts and limits below it, and the error probes in
  `HAVING`, the outer `SELECT` and `ORDER BY`) switch to `SUM` or `AVG`,
  so they still reach it instead of stopping at the aggregate allowlist.
  `AVG(salary)` exceeds 9000 for the `ceo` group and 9500 for none, as
  `MAX` did in ADR 0011's probes. New cases refuse `MIN` and `MAX` in the
  select list, `HAVING`, `ORDER BY`, subqueries and CTEs, on numbers and
  text, with `DISTINCT`, and in the walk and id-range shapes above.
* `query_api.rs` keeps its unique-key and missing-`n` checks with `SUM`
  and adds `MAX` to the refused queries; `research_api.rs` sends `MAX`
  through the research endpoint.
* `docs/THREAT_MODEL.md` moves `MIN` and `MAX` from the "Extreme values"
  residual to a built control and keeps dominated sums there until P58.
  `docs/ARCHITECTURE.md` lists `COUNT`, `SUM` and `AVG` as the permitted
  aggregates, `docs/PROJECT_SCOPE.md` narrows its "Dominance rule" row to
  P58, and `CHANGELOG.md` records the refusal under Security.
* P58 (#281) implements the p% rule as decided here. Where its issue
  text carries the auxiliary values to egress and composes the rule with
  `MinCountThreshold`, this record masks directly above the `Aggregate`
  instead.
