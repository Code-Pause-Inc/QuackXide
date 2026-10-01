# 0002. Refuse grouping sets and positional subsets in the disclosure gate

* Status: Accepted
* Date: 2026-10-01

## Context

`MinCountThreshold` suppresses each result row whose cohort is below *k*,
one row at a time. That is sound only if every input row belongs to
exactly one released group. `ROLLUP`, `CUBE` and `GROUPING SETS` break
that: they return subtotal rows beside the group rows in one result. On
the `tests/bypass.rs` fixture with *k* = 5,

```sql
SELECT dept, COUNT(*) AS n, SUM(salary) AS s
FROM people WHERE dept <> 'legal' GROUP BY ROLLUP(dept)
```

returns eng (6, 615), ops (6, 1215) and a total (13, 10831). Every row
passes the threshold, yet the total minus the two groups is n = 1 and
s = 9001: the one suppressed person's salary, from a single query costing
one budget unit.

Separately, the allowlist accepted `Sort` and `Limit` below the aggregate,
while `docs/ARCHITECTURE.md` describes the plan as a table scan,
optionally filtered or column-renamed, feeding the aggregate. `LIMIT` and
`OFFSET` there choose rows by position rather than by a predicate on
their values. No legitimate aggregate needs them.

## Decision

The plan allowlist (`policy::is_aggregate_only`) refuses:

* an `Aggregate` whose `GROUP BY` contains a grouping set (`ROLLUP`,
  `CUBE`, `GROUPING SETS`), in every position, including inside a
  subquery or CTE;
* any `Sort` or `Limit` below the `Aggregate`. Only filters, column
  renames and aliases may sit below it. Sort and limit above it stay
  allowed.

Refusals return the same `ZkPolicy` error as every other plan refusal.
Complementary (secondary) suppression, which would let grouping sets be
allowed again, is not attempted.

## Consequences

* Each input row is counted in exactly one released group, so the
  single-query claim in `disclosure.rs` holds.
* Researchers needing a total and a breakdown run two queries, paying two
  budget units. Differencing those two results is the existing
  overlapping-query residual in `docs/THREAT_MODEL.md`, bounded by the
  budget.
* Refusing sort and limit below the aggregate aligns the gate with its
  documented shape. It does not narrow the extreme-values residual:
  accepted filtered queries can still reveal `MIN`/`MAX` one query at a
  time. That needs its own decision (a dominance rule or removing
  `MIN`/`MAX`).
* `tests/bypass.rs` covers each refused shape in research and ZK mode.
  Because its leak check inspects one row at a time, any newly accepted
  shape whose groups overlap must be treated as a defect.
