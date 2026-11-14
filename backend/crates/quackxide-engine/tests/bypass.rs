//! Adversarial bypass suite for the zero-knowledge disclosure gate.
//!
//! Zero-knowledge mode (own-data queries) and research mode share one gate:
//! the aggregate-only plan allowlist, the genuine-count check, and
//! `MinCountThreshold`. Cases run over a table with a unique `id`, two small
//! cohorts (`ceo` = 1 row, `legal` = 2 rows) and two common ones, and must be
//! refused or return only rows with `n >= K` that carry no id, small-cohort
//! label, or small-cohort salary. `CASES` target the research gate,
//! `ZK_CASES` the own-data query endpoint.
//!
//! `leak()` checks each released row on its own, so it cannot see a leak
//! that needs two rows of one result (a subtotal beside its parts). Any
//! accepted shape whose groups overlap is therefore a defect; grouping sets
//! are refused for that reason.
//!
//! Only read-only queries run: DDL, DML, `COPY` and session statements are
//! refused in every mode before anything executes.
//!
//! Differencing across overlapping queries is out of scope; the per-grant
//! budget bounds it.

use std::sync::Arc;

use arrow::array::{Array, make_array};
use arrow::array::{Int64Array, LargeStringArray, StringArray, StringViewArray};
use arrow::datatypes::{Field, Schema};
use arrow::record_batch::RecordBatch;
use parquet::arrow::ArrowWriter;
use platform_core::ZkMode;
use quackxide_engine::{EngineSettings, MinCountThreshold, QueryError, QueryLimits, QueryScope};
use serde_json::Value;

const K: i64 = 5;

const ROWS: &[(&str, &str, i64)] = &[
    ("p01", "eng", 100),
    ("p02", "eng", 101),
    ("p03", "eng", 102),
    ("p04", "eng", 103),
    ("p05", "eng", 104),
    ("p06", "eng", 105),
    ("p07", "ops", 200),
    ("p08", "ops", 201),
    ("p09", "ops", 202),
    ("p10", "ops", 203),
    ("p11", "ops", 204),
    ("p12", "ops", 205),
    ("p13", "legal", 7001),
    ("p14", "legal", 7002),
    ("p15", "ceo", 9001),
];

const SMALL_COHORTS: &[&str] = &["legal", "ceo"];

#[derive(Debug, Clone, Copy)]
enum Expect {
    /// Refused by the plan or disclosure gate.
    Rejected,
    /// Refused by the SQL front end before the gate sees a plan.
    Unplannable,
    /// Accepted; this many rows survive suppression.
    Rows(usize),
}

use Expect::{Rejected, Rows, Unplannable};

#[rustfmt::skip]
const CASES: &[(&str, &str, Expect)] = &[
    // Baseline shapes that must keep working.
    ("group_count", "SELECT dept, COUNT(*) AS n FROM people GROUP BY dept", Rows(2)),
    ("count_one", "SELECT dept, COUNT(1) AS n FROM people GROUP BY dept", Rows(2)),
    ("total_count", "SELECT COUNT(*) AS n FROM people", Rows(1)),
    ("sum_avg_min_max", "SELECT dept, COUNT(*) AS n, SUM(salary) AS s, AVG(salary) AS a, MIN(salary) AS lo, MAX(salary) AS hi FROM people GROUP BY dept", Rows(2)),
    ("where", "SELECT dept, COUNT(*) AS n FROM people WHERE salary < 9000 GROUP BY dept", Rows(2)),
    ("having", "SELECT dept, COUNT(*) AS n FROM people GROUP BY dept HAVING COUNT(*) > 0", Rows(2)),
    ("order_limit", "SELECT dept, COUNT(*) AS n FROM people GROUP BY dept ORDER BY n DESC, dept LIMIT 1", Rows(1)),
    ("subquery_alias", "SELECT dept, n FROM (SELECT dept, COUNT(*) AS n FROM people GROUP BY dept) t WHERE n > 0", Rows(2)),
    ("from_subquery_columns", "SELECT dept, COUNT(*) AS n FROM (SELECT dept, salary FROM people) t GROUP BY dept", Rows(2)),
    ("cte_aggregate", "WITH c AS (SELECT dept, COUNT(*) AS n FROM people GROUP BY dept) SELECT dept, n FROM c", Rows(2)),
    ("group_by_expression", "SELECT salary / 100 AS band, COUNT(*) AS n FROM people GROUP BY salary / 100", Rows(2)),
    ("count_ratio", "SELECT dept, COUNT(*) AS n, COUNT(*) * 100 / 15 AS pct FROM people GROUP BY dept", Rows(2)),
    // Expressions that cannot fail at runtime (ADR 0011).
    ("float_compare", "SELECT dept, COUNT(*) AS n FROM people WHERE salary > 3.5 GROUP BY dept", Rows(2)),
    ("string_literal_compare", "SELECT dept, COUNT(*) AS n FROM people WHERE salary > '3' GROUP BY dept", Rows(2)),
    ("in_list", "SELECT dept, COUNT(*) AS n FROM people WHERE dept IN ('eng', 'ops') GROUP BY dept", Rows(2)),
    ("not_in_list", "SELECT dept, COUNT(*) AS n FROM people WHERE dept NOT IN ('ceo') GROUP BY dept", Rows(2)),
    ("between", "SELECT dept, COUNT(*) AS n FROM people WHERE salary BETWEEN 100 AND 205 GROUP BY dept", Rows(2)),
    ("not_between", "SELECT dept, COUNT(*) AS n FROM people WHERE salary NOT BETWEEN 7000 AND 9999 GROUP BY dept", Rows(2)),
    ("coalesce", "SELECT dept, COUNT(*) AS n FROM people WHERE COALESCE(salary, 0) > 0 GROUP BY dept", Rows(2)),
    ("try_cast", "SELECT dept, COUNT(*) AS n FROM people WHERE TRY_CAST(id AS BIGINT) IS NULL GROUP BY dept", Rows(2)),
    ("cast_to_double", "SELECT dept, COUNT(*) AS n FROM people WHERE CAST(salary AS DOUBLE) > 0 GROUP BY dept", Rows(2)),
    // Float division by zero gives infinity or NaN, never an error. NaN is
    // unequal to every number; its order against them depends on its sign,
    // which for `0.0 / 0.0` differs by CPU, so the NaN case uses `<>`.
    ("float_div_by_zero", "SELECT dept, COUNT(*) AS n FROM people WHERE CAST(salary AS DOUBLE) / 0.0 > 0 GROUP BY dept", Rows(2)),
    ("float_nan_compare", "SELECT dept, COUNT(*) AS n FROM people WHERE (CAST(salary AS DOUBLE) - CAST(salary AS DOUBLE)) / 0.0 <> 0 GROUP BY dept", Rows(2)),
    ("add_one", "SELECT dept, COUNT(*) AS n FROM people WHERE salary + 1 > 0 GROUP BY dept", Rows(2)),
    ("add_null", "SELECT dept, COUNT(*) AS n FROM people WHERE salary + NULL IS NULL GROUP BY dept", Rows(2)),
    // Unary minus only on floats; `0 - x` is the integer form, and wraps.
    ("zero_minus_int", "SELECT dept, COUNT(*) AS n FROM people WHERE 0 - salary < 0 GROUP BY dept", Rows(2)),
    ("negate_float", "SELECT dept, COUNT(*) AS n FROM people WHERE -CAST(salary AS DOUBLE) < 0 GROUP BY dept", Rows(2)),
    ("negate_int", "SELECT dept, COUNT(*) AS n FROM people WHERE -salary < 0 GROUP BY dept", Rejected),
    ("is_null", "SELECT dept, COUNT(*) AS n FROM people WHERE salary IS NOT NULL GROUP BY dept", Rows(2)),
    ("not", "SELECT dept, COUNT(*) AS n FROM people WHERE NOT (dept = 'ceo') GROUP BY dept", Rows(2)),
    ("order_by_ordinal_having_alias", "SELECT dept, COUNT(*) AS n FROM people GROUP BY dept HAVING n > 5 ORDER BY 2", Rows(2)),
    ("lower_eq", "SELECT dept, COUNT(*) AS n FROM people WHERE lower(dept) = 'eng' GROUP BY dept", Rows(1)),
    ("cast_dept_to_varchar", "SELECT dept, COUNT(*) AS n FROM people WHERE CAST(dept AS VARCHAR) = 'eng' GROUP BY dept", Rows(1)),
    ("like", "SELECT dept, COUNT(*) AS n FROM people WHERE dept LIKE 'e%' GROUP BY dept", Rows(1)),
    ("not_like", "SELECT dept, COUNT(*) AS n FROM people WHERE dept NOT LIKE 'e%' GROUP BY dept", Rows(1)),
    // Expressions that can fail on some rows, refused whatever the data
    // (ADR 0011). `SUM / COUNT` divides by zero when no row matches.
    ("count_arithmetic", "SELECT dept, COUNT(*) AS n, SUM(salary) / COUNT(*) AS mean FROM people GROUP BY dept", Rejected),
    ("literal_cast_fails", "SELECT dept, COUNT(*) AS n FROM people WHERE CAST('x' AS BIGINT) > 0 GROUP BY dept", Rejected),
    ("div_by_null", "SELECT dept, COUNT(*) AS n FROM people WHERE salary / NULL IS NULL GROUP BY dept", Rejected),
    ("div_by_column", "SELECT dept, COUNT(*) AS n FROM people WHERE salary / salary > 0 GROUP BY dept", Rejected),
    // Row-level egress.
    ("select_star", "SELECT * FROM people", Rejected),
    ("bare_columns", "SELECT id, salary FROM people", Rejected),
    ("bare_with_count_alias", "SELECT id, salary AS n FROM people", Rejected),
    ("distinct", "SELECT DISTINCT dept, salary FROM people", Rejected),
    ("limit_raw", "SELECT id FROM people LIMIT 1", Rejected),
    ("subquery_rows", "SELECT * FROM (SELECT id, salary FROM people) t", Rejected),
    ("values", "VALUES ('ceo', 9001)", Rejected),
    ("values_aggregate", "SELECT column1, COUNT(*) AS n FROM (VALUES ('a'), ('a'), ('a'), ('a'), ('a')) v GROUP BY column1", Rejected),
    // Set operations.
    ("union_raw", "SELECT dept, COUNT(*) AS n FROM people GROUP BY dept UNION SELECT dept, salary FROM people", Rejected),
    ("union_all_raw", "SELECT dept, COUNT(*) AS n FROM people GROUP BY dept UNION ALL SELECT id, salary FROM people", Rejected),
    ("union_all_aggregates", "SELECT dept, COUNT(*) AS n FROM people GROUP BY dept UNION ALL SELECT dept, COUNT(*) AS n FROM people GROUP BY dept", Rejected),
    ("union_inflation", "SELECT dept, COUNT(*) AS n FROM (SELECT * FROM people UNION ALL SELECT * FROM people UNION ALL SELECT * FROM people UNION ALL SELECT * FROM people UNION ALL SELECT * FROM people) t GROUP BY dept", Rejected),
    ("intersect", "SELECT dept, COUNT(*) AS n FROM people GROUP BY dept INTERSECT SELECT dept, COUNT(*) AS n FROM people GROUP BY dept", Rejected),
    ("except", "SELECT dept, COUNT(*) AS n FROM people GROUP BY dept EXCEPT SELECT 'x', 0", Rejected),
    ("intersect_below", "SELECT dept, COUNT(*) AS n FROM (SELECT dept FROM people INTERSECT SELECT dept FROM people) t GROUP BY dept", Rejected),
    // Window functions.
    ("row_number", "SELECT id, ROW_NUMBER() OVER (ORDER BY id) AS n FROM people", Rejected),
    ("count_over", "SELECT id, dept, COUNT(*) OVER () AS n FROM people", Rejected),
    ("window_over_aggregate", "SELECT dept, COUNT(*) AS n, LAG(MAX(salary)) OVER (ORDER BY dept) AS prev FROM people GROUP BY dept", Rejected),
    ("window_below_aggregate", "SELECT dept, COUNT(*) AS n FROM (SELECT dept, COUNT(*) OVER () AS c FROM people) t GROUP BY dept", Rejected),
    // Grouping that isolates individuals.
    ("group_by_id", "SELECT id, COUNT(*) AS n, MAX(salary) AS s FROM people GROUP BY id", Rows(0)),
    ("group_by_unique_expr", "SELECT id || dept AS k, COUNT(*) AS n FROM people GROUP BY id || dept", Rows(0)),
    ("group_by_salary", "SELECT salary, COUNT(*) AS n FROM people GROUP BY salary", Rows(0)),
    ("group_by_substr_id", "SELECT SUBSTR(id, 2, 2) AS k, COUNT(*) AS n FROM people GROUP BY SUBSTR(id, 2, 2)", Rejected),
    ("group_by_case_isolates", "SELECT CASE WHEN dept = 'ceo' THEN salary ELSE 0 END AS s, COUNT(*) AS n FROM people GROUP BY 1", Rows(1)),
    // Grouping sets: subtotal rows beside group rows let one query subtract
    // published groups from a total and recover a suppressed cohort.
    ("rollup", "SELECT dept, COUNT(*) AS n FROM people GROUP BY ROLLUP(dept)", Rejected),
    ("rollup_complement", "SELECT dept, COUNT(*) AS n, SUM(salary) AS s FROM people WHERE dept <> 'legal' GROUP BY ROLLUP(dept)", Rejected),
    ("cube_with_id", "SELECT dept, id, COUNT(*) AS n FROM people GROUP BY CUBE(dept, id)", Rejected),
    ("grouping_sets", "SELECT dept, COUNT(*) AS n, SUM(salary) AS s FROM people GROUP BY GROUPING SETS ((dept), ())", Rejected),
    ("grouping_sets_in_subquery", "SELECT dept, n FROM (SELECT dept, COUNT(*) AS n FROM people GROUP BY ROLLUP(dept)) t", Rejected),
    ("grouping_sets_in_cte", "WITH c AS (SELECT dept, COUNT(*) AS n, SUM(salary) AS s FROM people GROUP BY CUBE(dept)) SELECT dept, n, s FROM c", Rejected),
    // COUNT variants as n.
    ("count_case", "SELECT dept, COUNT(CASE WHEN dept <> 'ceo' THEN 1 END) AS n FROM people GROUP BY dept", Rejected),
    ("count_distinct", "SELECT dept, COUNT(DISTINCT id) AS n FROM people GROUP BY dept", Rejected),
    ("count_filter", "SELECT dept, COUNT(*) FILTER (WHERE salary > 0) AS n FROM people GROUP BY dept", Rejected),
    ("count_column", "SELECT dept, COUNT(salary) AS n FROM people GROUP BY dept", Rejected),
    // Sub-cohort isolation inside a large group.
    ("case_in_sum", "SELECT COUNT(*) AS n, SUM(CASE WHEN id = 'p15' THEN salary ELSE 0 END) AS s FROM people", Rejected),
    ("case_in_max", "SELECT COUNT(*) AS n, MAX(CASE WHEN dept = 'legal' THEN salary END) AS s FROM people", Rejected),
    ("filter_on_value", "SELECT COUNT(*) AS n, MAX(salary) FILTER (WHERE dept = 'ceo') AS s FROM people", Rejected),
    ("arith_isolation", "SELECT COUNT(*) AS n, SUM(salary * CAST(id = 'p15' AS BIGINT)) AS s FROM people", Rejected),
    ("computed_below", "SELECT COUNT(*) AS n, MAX(s) AS s FROM (SELECT CASE WHEN id = 'p15' THEN salary END AS s FROM people) t", Rejected),
    ("computed_label_below", "SELECT COUNT(*) AS n, MAX(d) AS d FROM (SELECT CASE WHEN dept = 'ceo' THEN dept END AS d FROM people) t", Rejected),
    ("array_agg", "SELECT dept, COUNT(*) AS n, ARRAY_AGG(id) AS ids FROM people GROUP BY dept", Rejected),
    ("string_agg", "SELECT COUNT(*) AS n, STRING_AGG(dept, ',') AS d FROM people", Rejected),
    ("first_value", "SELECT COUNT(*) AS n, FIRST_VALUE(dept ORDER BY salary DESC) AS d FROM people", Rejected),
    // HAVING tricks.
    ("having_small", "SELECT dept, COUNT(*) AS n FROM people GROUP BY dept HAVING COUNT(*) < 5", Rows(0)),
    ("having_value", "SELECT dept, COUNT(*) AS n, MAX(salary) AS s FROM people GROUP BY dept HAVING MAX(salary) > 5000", Rows(0)),
    ("having_subquery", "SELECT dept, COUNT(*) AS n FROM people GROUP BY dept HAVING (SELECT MAX(salary) FROM people WHERE dept = 'ceo') > 9000", Rejected),
    // Spoofed n.
    ("literal_n", "SELECT dept, 9999 AS n FROM people GROUP BY dept", Rejected),
    ("cast_n", "SELECT dept, CAST(9999 AS BIGINT) AS n FROM people GROUP BY dept", Rejected),
    ("cast_count_n", "SELECT dept, CAST(COUNT(*) * 10 AS BIGINT) AS n FROM people GROUP BY dept", Rejected),
    ("sum_n", "SELECT dept, SUM(salary) AS n FROM people GROUP BY dept", Rejected),
    ("max_n", "SELECT dept, MAX(salary) AS n FROM people GROUP BY dept", Rejected),
    ("count_plus", "SELECT dept, COUNT(*) + 10 AS n FROM people GROUP BY dept", Rejected),
    ("count_times", "SELECT dept, COUNT(*) * 10 AS n FROM people GROUP BY dept", Rejected),
    ("count_div", "SELECT dept, n / 1 AS n FROM (SELECT dept, COUNT(*) AS n FROM people GROUP BY dept) t", Rejected),
    ("count_named_source", r#"SELECT dept, "count(x)" AS n FROM spoof GROUP BY dept, "count(x)""#, Rejected),
    ("count_named_nested", r#"SELECT dept, n FROM (SELECT dept, "count(x)" AS n FROM spoof GROUP BY dept, "count(x)") t"#, Rejected),
    ("two_n_columns", r#"SELECT dept, COUNT(*) AS n, MAX(salary) AS "n" FROM people GROUP BY dept"#, Unplannable),
    ("qualified_n", "SELECT t.dept, t.n, u.n FROM (SELECT dept, COUNT(*) AS n FROM people GROUP BY dept) t, (SELECT dept, MAX(salary) AS n FROM people GROUP BY dept) u", Rejected),
    ("scalar_subquery_n", "SELECT dept, (SELECT COUNT(*) FROM people) AS n FROM people GROUP BY dept", Rejected),
    ("scalar_subquery_value", "SELECT dept, COUNT(*) AS n, (SELECT salary FROM people WHERE dept = 'ceo') AS s FROM people GROUP BY dept", Rejected),
    ("in_subquery", "SELECT dept, COUNT(*) AS n FROM people WHERE dept IN (SELECT dept FROM people WHERE salary > 9000) GROUP BY dept", Rejected),
    ("exists_subquery", "SELECT COUNT(*) AS n FROM people WHERE EXISTS (SELECT 1 FROM people WHERE id = 'p15' AND salary > 9000)", Rejected),
    // Joins that inflate a small cohort.
    ("self_join", "SELECT a.dept, COUNT(*) AS n FROM people a JOIN people b ON a.dept = b.dept GROUP BY a.dept", Rejected),
    ("cross_join", "SELECT a.dept, COUNT(*) AS n, MAX(a.salary) AS s FROM people a CROSS JOIN people b GROUP BY a.dept", Rejected),
    ("comma_join", "SELECT a.dept, COUNT(*) AS n FROM people a, people b GROUP BY a.dept", Rejected),
    ("series_join", "SELECT dept, COUNT(*) AS n FROM people, generate_series(1, 10) GROUP BY dept", Rejected),
    ("unnest_inflation", "SELECT dept, COUNT(*) AS n FROM (SELECT dept, UNNEST(make_array(1, 2, 3, 4, 5)) AS x FROM people) t GROUP BY dept", Rejected),
    ("join_of_aggregates", "SELECT t.dept, u.n FROM (SELECT dept FROM people GROUP BY dept) t JOIN (SELECT dept, COUNT(*) AS n FROM people GROUP BY dept) u ON t.dept = u.dept", Rejected),
    // Nested aggregates.
    ("aggregate_over_aggregate", "SELECT COUNT(*) AS n, MAX(dept) AS d FROM (SELECT dept, COUNT(*) AS c FROM people GROUP BY dept) t", Rejected),
    ("regroup_counts", "SELECT c, COUNT(*) AS n FROM (SELECT id, COUNT(*) AS c FROM people GROUP BY id) t GROUP BY c", Rejected),
    ("inner_group_by_id", "SELECT d, COUNT(*) AS n FROM (SELECT id, MAX(dept) AS d FROM people GROUP BY id) t GROUP BY d", Rejected),
    // Sort or limit below the aggregate: only filters and column renames may
    // sit under it, so the aggregate always reads every matching row.
    ("limit_below_min", "SELECT COUNT(*) AS n, MIN(salary) AS lo FROM (SELECT * FROM people ORDER BY salary DESC LIMIT 5) t", Rejected),
    ("limit_below_cte", "WITH top AS (SELECT * FROM people ORDER BY salary DESC LIMIT 5) SELECT COUNT(*) AS n, MIN(salary) AS lo FROM top", Rejected),
    ("offset_below_max", "SELECT COUNT(*) AS n, MAX(salary) AS hi FROM (SELECT * FROM people ORDER BY id LIMIT 5 OFFSET 10) t", Rejected),
    ("plain_limit_below", "SELECT COUNT(*) AS n, MAX(salary) AS hi FROM (SELECT * FROM people LIMIT 5) t", Rejected),
    // A sort with no limit selects no rows; DataFusion drops it while planning.
    ("sort_only_below", "SELECT dept, COUNT(*) AS n FROM (SELECT * FROM people ORDER BY salary) t GROUP BY dept", Rows(2)),
    // Min/max leakage via ordering.
    ("min_rare_first", "SELECT dept, COUNT(*) AS n, MIN(salary) AS lo FROM people GROUP BY dept ORDER BY lo DESC LIMIT 1", Rows(0)),
    ("max_rare_first", "SELECT dept, COUNT(*) AS n, MAX(salary) AS hi FROM people GROUP BY dept ORDER BY n ASC LIMIT 2", Rows(0)),
    // CTEs.
    ("cte_rows", "WITH r AS (SELECT id, salary FROM people) SELECT * FROM r", Rejected),
    ("cte_join", "WITH r AS (SELECT dept FROM people) SELECT a.dept, COUNT(*) AS n FROM r a CROSS JOIN r b GROUP BY a.dept", Rejected),
    ("cte_union", "WITH r AS (SELECT dept FROM people UNION ALL SELECT dept FROM people UNION ALL SELECT dept FROM people) SELECT dept, COUNT(*) AS n FROM r GROUP BY dept", Rejected),
    // No table at all.
    ("no_from", "SELECT 9999 AS n", Rejected),
    ("count_no_from", "SELECT COUNT(*) AS n", Rejected),
];

#[rustfmt::skip]
const ZK_CASES: &[(&str, &str, Expect)] = &[
    ("group_sum", "SELECT dept, COUNT(*) AS n, SUM(salary) AS s FROM people GROUP BY dept", Rows(2)),
    ("total", "SELECT COUNT(*) AS n, AVG(salary) AS a FROM people", Rows(1)),
    ("where_having_order_limit", "SELECT dept, COUNT(*) AS n FROM people WHERE salary > 0 GROUP BY dept HAVING COUNT(*) > 1 ORDER BY n DESC LIMIT 2", Rows(2)),
    ("subquery_alias", "SELECT dept, n, s FROM (SELECT dept, COUNT(*) AS n, SUM(salary) AS s FROM people GROUP BY dept) t WHERE s > 0", Rows(2)),
    ("count_distinct", "SELECT COUNT(*) AS n, COUNT(DISTINCT dept) AS d FROM people", Rows(1)),
    ("rare_cohort_suppressed", "SELECT dept, COUNT(*) AS n, MAX(salary) AS hi FROM people WHERE dept IN ('ceo', 'legal') GROUP BY dept", Rows(0)),
    ("group_by_id", "SELECT id, COUNT(*) AS n, MAX(salary) AS s FROM people GROUP BY id", Rows(0)),
    ("group_by_id_per_column", "SELECT id, COUNT(*) AS n, MAX(dept) AS d FROM people GROUP BY id", Rows(0)),
    ("group_by_unique_expr", "SELECT id || '/' || dept AS k, COUNT(*) AS n FROM people GROUP BY id || '/' || dept", Rows(0)),
    ("group_by_id_and_value", "SELECT id, salary, COUNT(*) AS n FROM people GROUP BY id, salary", Rows(0)),
    ("rollup_complement", "SELECT dept, COUNT(*) AS n, SUM(salary) AS s FROM people WHERE dept <> 'legal' GROUP BY ROLLUP(dept)", Rejected),
    ("grouping_sets", "SELECT dept, COUNT(*) AS n, MAX(salary) AS hi FROM people GROUP BY GROUPING SETS ((dept), ())", Rejected),
    ("cube_in_subquery", "SELECT dept, n FROM (SELECT dept, COUNT(*) AS n FROM people GROUP BY CUBE(dept)) t", Rejected),
    ("limit_below_max", "SELECT COUNT(*) AS n, MAX(salary) AS hi FROM (SELECT * FROM people ORDER BY id LIMIT 5) t", Rejected),
    ("offset_below_min", "WITH w AS (SELECT * FROM people ORDER BY salary LIMIT 5 OFFSET 10) SELECT COUNT(*) AS n, MIN(salary) AS lo FROM w", Rejected),
    ("missing_n", "SELECT dept, SUM(salary) AS s FROM people GROUP BY dept", Rejected),
    ("missing_n_by_id", "SELECT id, MAX(salary) AS s FROM people GROUP BY id", Rejected),
    ("spoofed_n", "SELECT id, 9999 AS n, MAX(salary) AS s FROM people GROUP BY id", Rejected),
    ("spoofed_n_from_sum", "SELECT id, SUM(salary) AS n FROM people GROUP BY id", Rejected),
    ("spoofed_n_arithmetic", "SELECT id, COUNT(*) * 10 AS n FROM people GROUP BY id", Rejected),
    ("select_star", "SELECT * FROM people", Rejected),
    ("bare_columns", "SELECT id, salary FROM people WHERE dept = 'ceo'", Rejected),
    ("distinct", "SELECT DISTINCT id FROM people", Rejected),
    ("values", "VALUES ('p15', 9001)", Rejected),
    ("cte_rows", "WITH r AS (SELECT id FROM people) SELECT * FROM r", Rejected),
    ("union_raw", "SELECT dept, COUNT(*) AS n FROM people GROUP BY dept UNION ALL SELECT id, salary FROM people", Rejected),
    ("union_aggregates", "SELECT COUNT(*) AS n FROM people UNION ALL SELECT SUM(salary) FROM people", Rejected),
    ("intersect", "SELECT dept FROM people GROUP BY dept INTERSECT SELECT dept FROM people", Rejected),
    ("except", "SELECT dept FROM people GROUP BY dept EXCEPT SELECT 'x'", Rejected),
    ("row_number", "SELECT id, ROW_NUMBER() OVER (ORDER BY id) AS n FROM people", Rejected),
    ("window_over_aggregate", "SELECT dept, COUNT(*) AS n, LAG(MAX(id)) OVER (ORDER BY dept) AS prev FROM people GROUP BY dept", Rejected),
    ("array_agg", "SELECT dept, COUNT(*) AS n, ARRAY_AGG(id) AS ids FROM people GROUP BY dept", Rejected),
    ("string_agg", "SELECT COUNT(*) AS n, STRING_AGG(id, ',') AS ids FROM people", Rejected),
    ("first_value", "SELECT COUNT(*) AS n, FIRST_VALUE(id ORDER BY salary DESC) AS top FROM people", Rejected),
    ("max_of_id", "SELECT COUNT(*) AS n, MAX(CASE WHEN salary > 9000 THEN id END) AS top FROM people", Rejected),
    ("computed_below", "SELECT COUNT(*) AS n, MAX(i) AS top FROM (SELECT CASE WHEN dept = 'ceo' THEN id END AS i FROM people) t", Rejected),
    ("scalar_subquery", "SELECT COUNT(*) AS n, (SELECT id FROM people WHERE dept = 'ceo') AS who FROM people", Rejected),
    ("scalar_subquery_filter", "SELECT COUNT(*) AS n FROM people WHERE salary = (SELECT MAX(salary) FROM people)", Rejected),
    ("in_subquery", "SELECT COUNT(*) AS n FROM people WHERE id IN (SELECT id FROM people WHERE salary > 9000)", Rejected),
    ("exists_subquery", "SELECT COUNT(*) AS n FROM people WHERE EXISTS (SELECT 1 FROM people WHERE id = 'p15')", Rejected),
    ("cross_join", "SELECT a.dept, COUNT(*) AS n FROM people a CROSS JOIN people b GROUP BY a.dept", Rejected),
    ("join_raw", "SELECT a.id, b.salary FROM people a JOIN people b ON a.id = b.id", Rejected),
    ("aggregate_over_aggregate", "SELECT COUNT(*) AS n, MAX(d) AS d FROM (SELECT dept AS d, COUNT(*) AS c FROM people GROUP BY dept) t", Rejected),
    ("no_from", "SELECT 'p15' AS id", Rejected),
    ("count_no_from", "SELECT COUNT(*) AS n", Rejected),
];

#[tokio::test]
async fn research_gate_withstands_bypass_attempts() {
    run(&scope(Some(K)), CASES).await;
}

#[tokio::test]
async fn zk_gate_withstands_bypass_attempts() {
    run(&scope(Some(K)), ZK_CASES).await;
}

#[tokio::test]
async fn zk_mode_without_a_cohort_threshold_refuses_every_query() {
    let group = "SELECT dept, COUNT(*) AS n FROM people GROUP BY dept";
    let unconfigured = scope(None).sql(group).await;
    assert!(
        matches!(unconfigured, Err(QueryError::Disclosure(_))),
        "{unconfigured:?}"
    );
    let zero = scope(Some(0)).sql(group).await;
    assert!(matches!(zero, Err(QueryError::Disclosure(_))), "{zero:?}");
}

/// Queries whose expressions fail only on some rows: `{P}` holds only for
/// the single `ceo` row when `{T}` is 9000, and for no row at 9500. Each
/// must be refused at planning both times, so the outcome says nothing
/// about the data (ADR 0011).
#[rustfmt::skip]
const ERROR_PROBES: &[(&str, &str)] = &[
    ("where_div", "SELECT dept, COUNT(*) AS n FROM people WHERE salary / (CASE WHEN {P} THEN 0 ELSE 1 END) > 0 GROUP BY dept"),
    ("where_mod", "SELECT dept, COUNT(*) AS n FROM people WHERE salary % (CASE WHEN {P} THEN 0 ELSE 7 END) >= 0 GROUP BY dept"),
    ("where_cast_str_to_int", "SELECT dept, COUNT(*) AS n FROM people WHERE CAST(CASE WHEN {P} THEN 'x' ELSE '1' END AS BIGINT) > 0 GROUP BY dept"),
    ("where_implicit_eq", "SELECT dept, COUNT(*) AS n FROM people WHERE (CASE WHEN {P} THEN id ELSE '1' END) = 5 GROUP BY dept"),
    ("where_implicit_gt", "SELECT dept, COUNT(*) AS n FROM people WHERE (CASE WHEN {P} THEN id ELSE '7' END) > 3 GROUP BY dept"),
    ("where_abs", "SELECT dept, COUNT(*) AS n FROM people WHERE abs(CASE WHEN {P} THEN salary - 9001 - 9223372036854775807 - 1 ELSE 0 END) >= 0 GROUP BY dept"),
    ("where_to_timestamp", "SELECT dept, COUNT(*) AS n FROM people WHERE to_timestamp(CASE WHEN {P} THEN 'bad' ELSE '2020-01-01T00:00:00' END) IS NOT NULL GROUP BY dept"),
    ("where_substr", "SELECT dept, COUNT(*) AS n FROM people WHERE substr(dept, 1, CASE WHEN {P} THEN -1 ELSE 1 END) IS NOT NULL GROUP BY dept"),
    ("where_repeat", "SELECT dept, COUNT(*) AS n FROM people WHERE length(repeat(dept, CASE WHEN {P} THEN 2147483647 ELSE 1 END)) > 0 GROUP BY dept"),
    ("where_lpad", "SELECT dept, COUNT(*) AS n FROM people WHERE length(lpad(dept, CASE WHEN {P} THEN 2147483647 ELSE 1 END)) > 0 GROUP BY dept"),
    ("where_literal_div_zero", "SELECT dept, COUNT(*) AS n FROM people WHERE {P} AND salary / 0 > 0 GROUP BY dept"),
    ("where_float_to_int", "SELECT dept, COUNT(*) AS n FROM people WHERE CAST(CAST(salary AS DOUBLE) / (CASE WHEN {P} THEN 0.0 ELSE 1.0 END) AS BIGINT) > 0 GROUP BY dept"),
    ("where_to_decimal", "SELECT dept, COUNT(*) AS n FROM people WHERE CAST(CASE WHEN {P} THEN salary ELSE 1 END AS DECIMAL(3,0)) > 0 GROUP BY dept"),
    ("group_by_div", "SELECT dept, COUNT(*) AS n FROM people GROUP BY dept, salary / (CASE WHEN {P} THEN 0 ELSE 1 END)"),
    ("having_div", "SELECT dept, COUNT(*) AS n FROM people GROUP BY dept HAVING 1 / (CASE WHEN MAX(salary) > {T} AND COUNT(*) = 1 THEN 0 ELSE 1 END) > 0"),
    ("outer_div", "SELECT dept, COUNT(*) AS n, 1 / (CASE WHEN MAX(salary) > {T} THEN 0 ELSE 1 END) AS x FROM people GROUP BY dept"),
    ("outer_cast", "SELECT dept, COUNT(*) AS n, CAST(CASE WHEN MAX(salary) > {T} THEN 'x' ELSE '1' END AS BIGINT) AS x FROM people GROUP BY dept"),
    ("order_by_div", "SELECT dept, COUNT(*) AS n FROM people GROUP BY dept ORDER BY 1 / (CASE WHEN MAX(salary) > {T} THEN 0 ELSE 1 END)"),
    ("ratio_over_zero_rows", "SELECT COUNT(*) AS n, SUM(salary) / COUNT(*) AS m FROM people WHERE {P}"),
    // A constant is evaluated as a scalar, where negating i64::MIN fails.
    ("where_negate_min_literal", "SELECT dept, COUNT(*) AS n FROM people WHERE CASE WHEN {P} THEN -(-9223372036854775807 - 1) ELSE 0 END > 0 GROUP BY dept"),
    ("outer_negate_min_literal", "SELECT dept, COUNT(*) AS n, CASE WHEN MAX(salary) > {T} THEN -(-9223372036854775807 - 1) ELSE 0 END AS x FROM people GROUP BY dept"),
    // Merging projections puts the inner literal under the outer minus, so
    // `-m` runs on i64::MIN as a scalar, and only for groups that exist.
    ("subquery_negate_min", "SELECT dept, n, -m AS x FROM (SELECT dept, COUNT(*) AS n, -9223372036854775807 - 1 AS m FROM people WHERE {P} GROUP BY dept) t"),
    ("cte_negate_min", "WITH t AS (SELECT dept, COUNT(*) AS n, -9223372036854775807 - 1 AS m FROM people WHERE {P} GROUP BY dept) SELECT dept, n, -m AS x FROM t"),
    // Table statistics replace COUNT with a literal, so this negates
    // i64::MIN only when exactly 15 salaries are non-null.
    ("count_statistics_negate", "SELECT COUNT(*) AS n, -(COUNT(salary) + 9223372036854775793) AS x FROM people"),
    // A LIKE pattern compiles to a regex when some row reaches it; a long
    // one exceeds the regex size limit.
    ("where_like_long_pattern", "SELECT dept, COUNT(*) AS n FROM people WHERE {P} AND dept LIKE '{LONG}' GROUP BY dept"),
    ("where_ilike_long_pattern", "SELECT dept, COUNT(*) AS n FROM people WHERE {P} AND dept ILIKE '{LONG}' GROUP BY dept"),
];

#[tokio::test]
async fn error_probes_are_refused_whatever_the_data() {
    let scope = scope(Some(K));
    let mut failures = Vec::new();
    for &(name, template) in ERROR_PROBES {
        for threshold in ["9000", "9500"] {
            let sql = template
                .replace("{P}", &format!("id = 'p15' AND salary > {threshold}"))
                .replace("{T}", threshold)
                .replace("{LONG}", &"_".repeat(50_000));
            match scope.sql(&sql).await {
                Err(QueryError::ZkPolicy) => {}
                Err(err) => failures.push(format!("{name} at {threshold}: {err}")),
                Ok(_) => failures.push(format!("{name} at {threshold}: accepted")),
            }
        }
    }
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

/// Every string type accepts the same text expressions. `texts` holds the
/// `people` departments as `Utf8` (`dept`), `LargeUtf8` (`ldept`) and
/// `Utf8View` (`vdept`).
#[rustfmt::skip]
const TEXT_CASES: &[(&str, &str, Expect)] = &[
    ("like_utf8", "SELECT dept, COUNT(*) AS n FROM texts WHERE dept LIKE 'e%' GROUP BY dept", Rows(1)),
    ("like_large_utf8", "SELECT dept, COUNT(*) AS n FROM texts WHERE ldept LIKE 'e%' GROUP BY dept", Rows(1)),
    ("like_utf8_view", "SELECT dept, COUNT(*) AS n FROM texts WHERE vdept LIKE 'e%' GROUP BY dept", Rows(1)),
    ("not_like_utf8_view", "SELECT dept, COUNT(*) AS n FROM texts WHERE vdept NOT LIKE 'e%' GROUP BY dept", Rows(1)),
    ("ilike_large_utf8", "SELECT dept, COUNT(*) AS n FROM texts WHERE ldept ILIKE 'E%' GROUP BY dept", Rows(1)),
    ("like_cast_to_varchar", "SELECT dept, COUNT(*) AS n FROM texts WHERE CAST(dept AS VARCHAR) LIKE 'e%' GROUP BY dept", Rows(1)),
    ("concat_large_utf8", "SELECT dept, COUNT(*) AS n FROM texts WHERE ldept || '' = 'eng' GROUP BY dept", Rows(1)),
    ("cast_large_utf8_to_varchar", "SELECT dept, COUNT(*) AS n FROM texts WHERE CAST(ldept AS VARCHAR) = 'eng' GROUP BY dept", Rows(1)),
    ("lower_utf8_view", "SELECT dept, COUNT(*) AS n FROM texts WHERE lower(vdept) = 'eng' GROUP BY dept", Rows(1)),
    ("in_list_utf8_view", "SELECT dept, COUNT(*) AS n FROM texts WHERE vdept IN ('eng', 'ops') GROUP BY dept", Rows(2)),
];

#[tokio::test]
async fn text_expressions_work_on_every_string_type() {
    run(&text_scope(), TEXT_CASES).await;
}

#[tokio::test]
async fn like_patterns_up_to_the_cap_run_and_longer_ones_are_refused() {
    let cap = quackxide_engine::policy::MAX_LIKE_PATTERN_CHARS;
    let scope = text_scope();
    for column in ["dept", "ldept", "vdept"] {
        for op in ["LIKE", "ILIKE"] {
            let at_cap = format!("e{}", "%".repeat(cap - 1));
            let sql = format!(
                "SELECT dept, COUNT(*) AS n FROM texts WHERE {column} {op} '{at_cap}' GROUP BY dept"
            );
            check(&scope, &sql, Rows(1))
                .await
                .unwrap_or_else(|why| panic!("{column} {op} at cap: {why}"));
            let over = "_".repeat(cap + 1);
            let sql = format!(
                "SELECT dept, COUNT(*) AS n FROM texts WHERE {column} {op} '{over}' GROUP BY dept"
            );
            check(&scope, &sql, Rejected)
                .await
                .unwrap_or_else(|why| panic!("{column} {op} over cap: {why}"));
        }
    }
}

/// The cap leaves room under the regex size limit even for the costliest
/// pattern characters, and on non-ASCII data, which takes the regex path.
#[test]
fn like_patterns_at_the_cap_always_compile() {
    use arrow::array::Scalar;
    use arrow::compute::kernels::comparison::{ilike, like};
    let cap = quackxide_engine::policy::MAX_LIKE_PATTERN_CHARS;
    let data = StringArray::from(vec!["é", "ǅ", "k"]);
    for unit in ["_", "%_", "ǅ", "k", "é_"] {
        let pattern: String = unit.chars().cycle().take(cap).collect();
        let pattern = Scalar::new(StringArray::from(vec![pattern]));
        assert!(like(&data, &pattern).is_ok(), "LIKE {unit:?}");
        assert!(ilike(&data, &pattern).is_ok(), "ILIKE {unit:?}");
    }
}

#[tokio::test]
async fn ungated_queries_are_not_checked() {
    let rows = ungated_scope()
        .sql("SELECT salary / 2 AS h FROM people")
        .await
        .expect("ungated query runs");
    assert_eq!(rows.iter().map(RecordBatch::num_rows).sum::<usize>(), 15);
}

/// Statements other than a read-only query. `{dir}` is a scratch directory.
#[rustfmt::skip]
const STATEMENTS: &[(&str, &str)] = &[
    ("create_external_table", "CREATE EXTERNAL TABLE ext (id VARCHAR) STORED AS CSV LOCATION '{dir}/ext.csv'"),
    ("create_table_as", "CREATE TABLE ctas AS SELECT * FROM people"),
    ("create_view", "CREATE VIEW v AS SELECT * FROM people"),
    ("drop_table", "DROP TABLE people"),
    ("copy_to", "COPY (SELECT * FROM people) TO '{dir}/out.csv' STORED AS CSV"),
    ("insert", "INSERT INTO people VALUES ('p99', 'eng', 1)"),
    ("set", "SET datafusion.execution.batch_size = 1"),
    ("prepare", "PREPARE p AS SELECT COUNT(*) AS n FROM people"),
];

/// DDL, DML, `COPY` and session statements are refused before anything
/// runs, with or without the disclosure gate, and leave no trace.
#[tokio::test]
async fn only_read_only_queries_run_in_every_mode() {
    let dir = std::env::temp_dir().join(format!("qx-statements-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let mut failures = Vec::new();
    for &(name, template) in STATEMENTS {
        for gated in [false, true] {
            let mode = if gated { "gated" } else { "ungated" };
            let scope = if gated {
                scope(Some(K))
            } else {
                ungated_scope()
            };
            let sql = template.replace("{dir}", &dir.display().to_string());
            let result = scope.sql(&sql).await;
            if !matches!(result, Err(QueryError::StatementNotAllowed)) {
                failures.push(format!("{mode}/{name}: {result:?}"));
            }
            let total = scope.sql_json("SELECT COUNT(*) AS n FROM people").await;
            if total.as_ref().ok().map(|rows| rows[0]["n"].clone()) != Some(Value::from(15)) {
                failures.push(format!("{mode}/{name}: people changed: {total:?}"));
            }
            for created in ["ext", "ctas", "v"] {
                let probe = format!("SELECT COUNT(*) AS n FROM {created}");
                if scope.sql(&probe).await.is_ok() {
                    failures.push(format!("{mode}/{name}: created table {created}"));
                }
            }
        }
    }
    if dir.join("out.csv").exists() {
        failures.push("COPY wrote decrypted rows to disk".into());
    }
    let _ = std::fs::remove_dir_all(&dir);
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

async fn run(scope: &QueryScope, cases: &[(&str, &str, Expect)]) {
    let mut failures = Vec::new();
    for &(name, sql, expect) in cases {
        if let Err(why) = check(scope, sql, expect).await {
            failures.push(format!("{name}: {why}\n    {sql}"));
        }
    }
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

async fn check(scope: &QueryScope, sql: &str, expect: Expect) -> Result<(), String> {
    let result = scope.sql_json(sql).await;
    match (expect, result) {
        (Rejected, Err(QueryError::ZkPolicy | QueryError::Disclosure(_))) => Ok(()),
        (Unplannable, Err(QueryError::Execution(_))) => Ok(()),
        (_, Err(err)) => Err(format!("unexpected error {err}")),
        (Rejected | Unplannable, Ok(rows)) => Err(format!("accepted, returned {rows}")),
        (Rows(expected), Ok(rows)) => {
            let rows = rows.as_array().cloned().unwrap_or_default();
            if let Some(leak) = rows.iter().find_map(leak) {
                return Err(format!("leaked {leak}"));
            }
            if rows.len() != expected {
                return Err(format!("expected {expected} rows, got {}", rows.len()));
            }
            Ok(())
        }
    }
}

fn is_id(s: &str) -> bool {
    ROWS.iter().any(|(id, _, _)| *id == s)
}

fn leak(row: &Value) -> Option<String> {
    let cells = row.as_object()?;
    match cells.get("n").and_then(Value::as_i64) {
        Some(n) if n >= K => {}
        other => return Some(format!("n = {other:?} in {row}")),
    }
    cells
        .values()
        .find(|cell| is_sensitive(cell))
        .map(|cell| format!("{cell} in {row}"))
}

fn is_sensitive(cell: &Value) -> bool {
    let small = |dept: &&str| SMALL_COHORTS.contains(dept);
    match cell {
        Value::String(s) => SMALL_COHORTS.contains(&s.as_str()) || is_id(s),
        Value::Number(v) => ROWS
            .iter()
            .any(|(_, dept, salary)| small(dept) && v.as_i64() == Some(*salary)),
        Value::Array(items) => items.iter().any(is_sensitive),
        _ => false,
    }
}

/// A scope without the disclosure gate (own-data queries with ZK off).
fn ungated_scope() -> QueryScope {
    let mut scope = QueryScope::new(EngineSettings {
        zk: ZkMode::Disabled,
        max_concurrent_queries: 1,
        limits: QueryLimits::default(),
    });
    let ids = StringArray::from_iter_values(ROWS.iter().map(|r| r.0));
    let depts = StringArray::from_iter_values(ROWS.iter().map(|r| r.1));
    let salaries = Int64Array::from_iter_values(ROWS.iter().map(|r| r.2));
    scope
        .register_parquet(
            "people",
            &parquet(&[("id", &ids), ("dept", &depts), ("salary", &salaries)]),
        )
        .expect("register people");
    scope
}

/// A zero-knowledge scope (k = `K`) whose `texts` table holds each `people`
/// department as `Utf8`, `LargeUtf8` and `Utf8View`.
fn text_scope() -> QueryScope {
    let mut scope = QueryScope::new(EngineSettings {
        zk: ZkMode::Enabled,
        max_concurrent_queries: 1,
        limits: QueryLimits::default(),
    });
    let depts = || ROWS.iter().map(|r| r.1);
    let utf8 = StringArray::from_iter_values(depts());
    let large = LargeStringArray::from_iter_values(depts());
    let view = StringViewArray::from_iter_values(depts());
    scope
        .register_parquet(
            "texts",
            &parquet(&[("dept", &utf8), ("ldept", &large), ("vdept", &view)]),
        )
        .expect("register texts");
    scope.set_disclosure(Arc::new(MinCountThreshold { k: K }));
    scope
}

/// A zero-knowledge scope with a `MinCountThreshold` of `k`, if given.
fn scope(k: Option<i64>) -> QueryScope {
    let mut scope = QueryScope::new(EngineSettings {
        zk: ZkMode::Enabled,
        max_concurrent_queries: 1,
        limits: QueryLimits::default(),
    });
    let ids = StringArray::from_iter_values(ROWS.iter().map(|r| r.0));
    let depts = StringArray::from_iter_values(ROWS.iter().map(|r| r.1));
    let salaries = Int64Array::from_iter_values(ROWS.iter().map(|r| r.2));
    scope
        .register_parquet(
            "people",
            &parquet(&[("id", &ids), ("dept", &depts), ("salary", &salaries)]),
        )
        .expect("register people");

    let depts = StringArray::from_iter_values(["ceo"]);
    let fake = Int64Array::from_iter_values([9999]);
    scope
        .register_parquet("spoof", &parquet(&[("dept", &depts), ("count(x)", &fake)]))
        .expect("register spoof");

    if let Some(k) = k {
        scope.set_disclosure(Arc::new(MinCountThreshold { k }));
    }
    scope
}

fn parquet(columns: &[(&str, &dyn Array)]) -> Vec<u8> {
    let schema = Arc::new(Schema::new(
        columns
            .iter()
            .map(|(name, array)| Field::new(*name, array.data_type().clone(), false))
            .collect::<Vec<_>>(),
    ));
    let arrays = columns
        .iter()
        .map(|(_, array)| make_array(array.to_data()))
        .collect();
    let batch = RecordBatch::try_new(schema.clone(), arrays).expect("batch");
    let mut buf = Vec::new();
    let mut writer = ArrowWriter::try_new(&mut buf, schema, None).expect("writer");
    writer.write(&batch).expect("write");
    writer.close().expect("close");
    buf
}
