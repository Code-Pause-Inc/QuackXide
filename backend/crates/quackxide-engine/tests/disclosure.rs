//! Disclosure-control tests: min-count threshold suppression, the
//! COUNT(*) AS n requirement, and rejection of a spoofed count column.

use std::sync::Arc;

use arrow::array::{Int64Array, StringArray};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatch;
use parquet::arrow::ArrowWriter;
use platform_core::ZkMode;
use quackxide_engine::{EngineSettings, MinCountThreshold, QueryError, QueryScope};

/// A cohort table: 6 "flu" patients, 1 "rare_disease" patient.
fn cohorts_parquet() -> Vec<u8> {
    let schema = Arc::new(Schema::new(vec![
        Field::new("condition", DataType::Utf8, false),
        Field::new("age", DataType::Int64, false),
    ]));
    let condition =
        StringArray::from_iter_values(["flu", "flu", "flu", "flu", "flu", "flu", "rare_disease"]);
    let age = Int64Array::from(vec![30, 40, 50, 33, 44, 55, 61]);
    let batch = RecordBatch::try_new(schema.clone(), vec![Arc::new(condition), Arc::new(age)])
        .expect("batch");
    let mut buf = Vec::new();
    let mut writer = ArrowWriter::try_new(&mut buf, schema, None).expect("writer");
    writer.write(&batch).expect("write");
    writer.close().expect("close");
    buf
}

fn research_scope(k: i64) -> QueryScope {
    let mut scope = QueryScope::new(EngineSettings {
        zk: ZkMode::Enabled,
        max_concurrent_queries: 4,
    });
    scope
        .register_parquet("cohorts", &cohorts_parquet())
        .expect("register");
    scope.set_disclosure(Arc::new(MinCountThreshold { k }));
    scope
}

#[tokio::test]
async fn small_cohorts_are_suppressed_below_threshold() {
    let scope = research_scope(5);
    let rows = scope
        .sql_json(
            "SELECT condition, COUNT(*) AS n FROM cohorts GROUP BY condition ORDER BY condition",
        )
        .await
        .expect("query");

    // "flu" (6) survives; "rare_disease" (1) is suppressed.
    let arr = rows.as_array().expect("array");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["condition"], "flu");
    assert_eq!(arr[0]["n"], 6);
    assert_eq!(scope.last_suppressed_rows(), 1);
}

#[tokio::test]
async fn everything_survives_when_all_cohorts_meet_threshold() {
    let scope = research_scope(1);
    let rows = scope
        .sql_json("SELECT condition, COUNT(*) AS n FROM cohorts GROUP BY condition")
        .await
        .expect("query");
    assert_eq!(rows.as_array().expect("array").len(), 2);
    assert_eq!(scope.last_suppressed_rows(), 0);
}

#[tokio::test]
async fn research_query_without_count_n_is_rejected() {
    let scope = research_scope(5);
    // Aggregate, so it passes the ZK gate, but has no `n` cohort column.
    let err = scope
        .sql("SELECT condition, AVG(age) AS avg_age FROM cohorts GROUP BY condition")
        .await
        .expect_err("must be rejected");
    assert!(matches!(err, QueryError::Disclosure(_)), "got {err:?}");
}

#[tokio::test]
async fn spoofed_count_column_is_rejected() {
    let scope = research_scope(5);
    // A literal masquerading as the cohort size must not slip past.
    let err = scope
        .sql("SELECT condition, 9999 AS n FROM cohorts GROUP BY condition")
        .await
        .expect_err("must be rejected");
    assert!(matches!(err, QueryError::Disclosure(_)), "got {err:?}");
}

#[tokio::test]
async fn row_egress_still_blocked_under_research_mode() {
    let scope = research_scope(5);
    // ZK gate fires before disclosure — raw rows never reach the threshold.
    let err = scope
        .sql("SELECT condition, age FROM cohorts")
        .await
        .expect_err("must be rejected");
    assert!(matches!(err, QueryError::ZkPolicy), "got {err:?}");
}

/// A table whose source column is literally named `count(x)`, holding
/// arbitrary large values.
fn count_named_column_parquet() -> Vec<u8> {
    let schema = Arc::new(Schema::new(vec![
        Field::new("condition", DataType::Utf8, false),
        Field::new("count(x)", DataType::Int64, false),
    ]));
    let condition = StringArray::from_iter_values(["rare_disease"]);
    let fake = Int64Array::from(vec![9999]);
    let batch = RecordBatch::try_new(schema.clone(), vec![Arc::new(condition), Arc::new(fake)])
        .expect("batch");
    let mut buf = Vec::new();
    let mut writer = ArrowWriter::try_new(&mut buf, schema, None).expect("writer");
    writer.write(&batch).expect("write");
    writer.close().expect("close");
    buf
}

#[tokio::test]
async fn source_column_named_like_count_is_rejected() {
    let mut scope = research_scope(5);
    scope
        .register_parquet("spoof", &count_named_column_parquet())
        .expect("register");
    // Grouping by the column keeps the plan aggregate-shaped, but `n` is the
    // stored value, not a COUNT output.
    for sql in [
        r#"SELECT condition, "count(x)" AS n FROM spoof GROUP BY condition, "count(x)""#,
        r#"SELECT condition, n FROM (SELECT condition, "count(x)" AS n FROM spoof GROUP BY condition, "count(x)") t"#,
    ] {
        let err = scope.sql(sql).await.expect_err("must be rejected");
        assert!(
            matches!(err, QueryError::Disclosure(_)),
            "{sql}: got {err:?}"
        );
    }
}

#[tokio::test]
async fn count_through_subquery_and_filter_is_accepted() {
    let scope = research_scope(5);
    let rows = scope
        .sql_json(
            "SELECT condition, n FROM (SELECT condition, COUNT(*) AS n FROM cohorts \
             GROUP BY condition) t WHERE n > 0 ORDER BY condition",
        )
        .await
        .expect("query");
    let arr = rows.as_array().expect("array");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["n"], 6);

    let rows = scope
        .sql_json(
            "SELECT condition, COUNT(*) AS n FROM cohorts GROUP BY condition \
             HAVING COUNT(*) > 0 ORDER BY n DESC LIMIT 5",
        )
        .await
        .expect("query");
    assert_eq!(rows.as_array().expect("array").len(), 1);
}
