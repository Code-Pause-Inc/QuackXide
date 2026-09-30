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
//! Differencing across overlapping queries is out of scope; the per-grant
//! budget bounds it.

use std::sync::Arc;

use arrow::array::{Array, make_array};
use arrow::array::{Int64Array, StringArray};
use arrow::datatypes::{Field, Schema};
use arrow::record_batch::RecordBatch;
use parquet::arrow::ArrowWriter;
use platform_core::ZkMode;
use quackxide_engine::{EngineSettings, MinCountThreshold, QueryError, QueryScope};
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
    ("rollup", "SELECT dept, COUNT(*) AS n FROM people GROUP BY ROLLUP(dept)", Rows(3)),
    ("count_arithmetic", "SELECT dept, COUNT(*) AS n, SUM(salary) / COUNT(*) AS mean FROM people GROUP BY dept", Rows(2)),
    ("count_ratio", "SELECT dept, COUNT(*) AS n, COUNT(*) * 100 / 15 AS pct FROM people GROUP BY dept", Rows(2)),
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
    ("group_by_substr_id", "SELECT SUBSTR(id, 2, 2) AS k, COUNT(*) AS n FROM people GROUP BY SUBSTR(id, 2, 2)", Rows(0)),
    ("group_by_case_isolates", "SELECT CASE WHEN dept = 'ceo' THEN salary ELSE 0 END AS s, COUNT(*) AS n FROM people GROUP BY 1", Rows(1)),
    ("cube_with_id", "SELECT dept, id, COUNT(*) AS n FROM people GROUP BY CUBE(dept, id)", Rows(3)),
    // COUNT variants as n.
    ("count_case", "SELECT dept, COUNT(CASE WHEN dept <> 'ceo' THEN 1 END) AS n FROM people GROUP BY dept", Rejected),
    ("count_distinct", "SELECT dept, COUNT(DISTINCT id) AS n FROM people GROUP BY dept", Rejected),
    ("count_filter", "SELECT dept, COUNT(*) FILTER (WHERE salary > 0) AS n FROM people GROUP BY dept", Unplannable),
    ("count_column", "SELECT dept, COUNT(salary) AS n FROM people GROUP BY dept", Rejected),
    // Sub-cohort isolation inside a large group.
    ("case_in_sum", "SELECT COUNT(*) AS n, SUM(CASE WHEN id = 'p15' THEN salary ELSE 0 END) AS s FROM people", Rejected),
    ("case_in_max", "SELECT COUNT(*) AS n, MAX(CASE WHEN dept = 'legal' THEN salary END) AS s FROM people", Rejected),
    ("filter_on_value", "SELECT COUNT(*) AS n, MAX(salary) FILTER (WHERE dept = 'ceo') AS s FROM people", Unplannable),
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

/// A zero-knowledge scope with a `MinCountThreshold` of `k`, if given.
fn scope(k: Option<i64>) -> QueryScope {
    let mut scope = QueryScope::new(EngineSettings {
        zk: ZkMode::Enabled,
        max_concurrent_queries: 1,
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
