//! Decoding only what a query needs: registering a table reads only its
//! Parquet footers, a query the gates refuse decodes nothing, and an
//! accepted one decodes only the columns it reads, within the decode limits
//! as the footers report them for those columns.
//!
//! The test seam is a copy of a dataset with some column chunks
//! overwritten and its footer intact. Decoding an overwritten chunk fails,
//! so a query that answers, or is refused for another reason, over such a
//! copy decoded none of those chunks.

use std::sync::Arc;

use bytes::Bytes;
use parquet::file::metadata::{ParquetMetaData, ParquetMetaDataReader};
use platform_core::ZkMode;
use quackxide_engine::{
    EngineSettings, MinCountThreshold, QueryError, QueryLimit, QueryLimits, QueryScope,
};
use synth_data::{SchemaName, Spec};

/// The parsed footer of `parquet`.
fn footer(parquet: &[u8]) -> ParquetMetaData {
    ParquetMetaDataReader::new()
        .parse_and_finish(&Bytes::copy_from_slice(parquet))
        .expect("footer")
}

/// `parquet` with the column chunks of every column not named in `keep`
/// overwritten, from the first page of each through its last. The footer is
/// intact.
fn wipe_columns_except(parquet: &[u8], keep: &[&str]) -> Vec<u8> {
    let mut wiped = parquet.to_vec();
    for group in footer(parquet).row_groups() {
        for column in group.columns() {
            if !keep.contains(&column.column_path().string().as_str()) {
                let (start, len) = column.byte_range();
                let start = usize::try_from(start).expect("offset");
                let end = start + usize::try_from(len).expect("length");
                wiped[start..end].fill(0xA5);
            }
        }
    }
    wiped
}

/// Uncompressed bytes `parquet`'s footer reports for the columns named in
/// `names`, or for every column if `names` is empty.
fn footer_bytes(parquet: &[u8], names: &[&str]) -> u64 {
    footer(parquet)
        .row_groups()
        .iter()
        .flat_map(|group| group.columns())
        .filter(|column| {
            names.is_empty() || names.contains(&column.column_path().string().as_str())
        })
        .map(|column| u64::try_from(column.uncompressed_size()).expect("size"))
        .sum()
}

const K: i64 = synth_data::DEFAULT_K as i64;

fn scope(zk: ZkMode, limits: QueryLimits) -> QueryScope {
    let mut scope = QueryScope::new(EngineSettings {
        zk,
        max_concurrent_queries: 1,
        limits,
    });
    if zk.is_enabled() {
        scope.set_disclosure(Arc::new(MinCountThreshold { k: K }));
    }
    scope
}

fn cohort(seed: u64) -> Vec<u8> {
    synth_data::parquet_bytes(&Spec::new(SchemaName::Cohort, seed, 500)).expect("cohort")
}

/// Every column chunk overwritten: a query refused by the plan gate, the
/// count-column check, the runtime-failure check or the statement check
/// gets that refusal, so it decoded nothing. A query that reads a column
/// fails to decode it, and a count that reads none answers.
#[tokio::test]
async fn a_query_the_gates_refuse_decodes_no_column() {
    type Refused = fn(&QueryError) -> bool;
    let refusals: [(&str, Refused); 6] = [
        // The plan gate: row-level egress, and a join.
        ("SELECT email, age FROM cohort", |err| {
            matches!(err, QueryError::ZkPolicy)
        }),
        (
            "SELECT a.condition, COUNT(*) AS n FROM cohort a \
             JOIN cohort b ON a.person_id = b.person_id GROUP BY a.condition",
            |err| matches!(err, QueryError::ZkPolicy),
        ),
        // The count-column check: no `n`, and an `n` that is not a count.
        (
            "SELECT condition, SUM(cost_cents) AS total FROM cohort GROUP BY condition",
            |err| matches!(err, QueryError::Disclosure(_)),
        ),
        (
            "SELECT condition, MAX(age) AS n FROM cohort GROUP BY condition",
            |err| matches!(err, QueryError::Disclosure(_)),
        ),
        // An expression that can fail at runtime (ADR 0011).
        (
            "SELECT condition, COUNT(*) AS n FROM cohort \
             WHERE CAST(email AS BIGINT) > 0 GROUP BY condition",
            |err| matches!(err, QueryError::ZkPolicy),
        ),
        // A statement.
        ("SET datafusion.execution.batch_size = 1", |err| {
            matches!(err, QueryError::StatementNotAllowed)
        }),
    ];

    let wiped = wipe_columns_except(&cohort(3), &[]);
    let mut scope = scope(ZkMode::Enabled, QueryLimits::default());
    assert_eq!(
        scope.register_parquet("cohort", &wiped).expect("footer"),
        500
    );
    for (sql, refused) in refusals {
        let err = scope.sql(sql).await.expect_err(sql);
        assert!(refused(&err), "{sql}: {err:?}");
    }

    // Accepted, it decodes the columns it reads, which fail.
    let err = scope
        .sql("SELECT condition, COUNT(*) AS n, SUM(cost_cents) AS total FROM cohort GROUP BY condition")
        .await
        .expect_err("overwritten columns");
    assert!(matches!(err, QueryError::Parquet(_)), "{err:?}");
    // A count reads no column.
    let rows = scope
        .sql_json("SELECT COUNT(*) AS n FROM cohort")
        .await
        .expect("no column decoded");
    assert_eq!(rows, serde_json::json!([{ "n": 500 }]));
}

/// On the wide table (23 columns), an aggregate over `region` and `i00`
/// answers the same over a copy whose other 21 columns are overwritten, so
/// it decoded only those two. The byte limit holds it to those two columns,
/// a fraction of the table: a tenth of the table's footer bytes fits. One
/// byte under what the footers report for the two is refused before
/// anything is decoded, and exactly that is refused as they decode, since
/// they decode to more than their footers report.
#[tokio::test]
async fn a_two_column_aggregate_on_the_wide_table_decodes_only_those_columns() {
    const SQL: &str = "SELECT region, COUNT(*) AS n, SUM(i00) AS total FROM wide \
                       GROUP BY region ORDER BY region";
    let wide = synth_data::parquet_bytes(&Spec::new(SchemaName::Wide, 7, 20_000)).expect("wide");
    let wiped = wipe_columns_except(&wide, &["region", "i00"]);
    let two_columns = footer_bytes(&wide, &["region", "i00"]);
    let all_columns = footer_bytes(&wide, &[]);
    assert!(
        all_columns > 10 * two_columns,
        "{all_columns} vs {two_columns}"
    );

    let mut intact = scope(ZkMode::Enabled, QueryLimits::default());
    intact.register_parquet("wide", &wide).expect("register");
    let expected = intact.sql_json(SQL).await.expect("intact");
    assert_eq!(
        expected.as_array().expect("rows").len(),
        synth_data::wide::REGIONS.len()
    );

    let mut wiped_scope = scope(ZkMode::Enabled, QueryLimits::default());
    wiped_scope
        .register_parquet("wide", &wiped)
        .expect("footer");
    assert_eq!(
        wiped_scope.sql_json(SQL).await.expect("two columns"),
        expected
    );
    // Any other column is overwritten, so reading it fails.
    let err = wiped_scope
        .sql("SELECT region, COUNT(*) AS n, SUM(i01) AS total FROM wide GROUP BY region")
        .await
        .expect_err("an overwritten column");
    assert!(matches!(err, QueryError::Parquet(_)), "{err:?}");

    let a_tenth = QueryLimits {
        max_decoded_bytes: all_columns / 10,
        ..QueryLimits::default()
    };
    let mut scope_a_tenth = scope(ZkMode::Enabled, a_tenth);
    scope_a_tenth
        .register_parquet("wide", &wiped)
        .expect("footer");
    assert_eq!(scope_a_tenth.sql_json(SQL).await.expect("fits"), expected);

    // Every column overwritten: a refusal rather than a Parquet failure
    // shows nothing was decoded.
    let all_wiped = wipe_columns_except(&wide, &[]);
    for (limit, table) in [(two_columns - 1, &all_wiped), (two_columns, &wide)] {
        let limits = QueryLimits {
            max_decoded_bytes: limit,
            ..QueryLimits::default()
        };
        let mut scope = scope(ZkMode::Enabled, limits);
        scope.register_parquet("wide", table).expect("footer");
        let err = scope.sql(SQL).await.expect_err("over the limit");
        assert!(
            matches!(err, QueryError::LimitExceeded(QueryLimit::DecodedBytes)),
            "{limit}: {err:?}"
        );
    }
}

/// An object with a valid footer and a corrupt data page fails, when a
/// query reads that column, as a Parquet failure: the stored data's fault
/// (5xx), never the caller's SQL (400). Queries over its other columns
/// answer.
#[tokio::test]
async fn a_corrupt_data_page_is_a_parquet_failure_not_the_callers_sql() {
    let parquet = cohort(5);
    let mut corrupt = parquet.clone();
    for group in footer(&parquet).row_groups() {
        for column in group.columns() {
            if column.column_path().string() == "age" {
                // The data pages, from the first one's header on; the
                // dictionary page before them is intact.
                let (start, len) = column.byte_range();
                let first = usize::try_from(column.data_page_offset()).expect("offset");
                let end = usize::try_from(start + len).expect("end");
                corrupt[first..end].fill(0xA5);
            }
        }
    }

    for zk in [ZkMode::Disabled, ZkMode::Enabled] {
        let mut scope = scope(zk, QueryLimits::default());
        scope.register_parquet("cohort", &corrupt).expect("footer");
        let err = scope
            .sql("SELECT condition, COUNT(*) AS n, AVG(age) AS mean_age FROM cohort GROUP BY condition")
            .await
            .expect_err("a corrupt page");
        assert!(matches!(err, QueryError::Parquet(_)), "{zk:?}: {err:?}");
        assert_eq!(
            err.to_string(),
            "parquet decode failed while decoding a batch"
        );

        let rows = scope
            .sql_json(
                "SELECT condition, COUNT(*) AS n, SUM(cost_cents) AS total FROM cohort \
                 GROUP BY condition",
            )
            .await
            .expect("the other columns");
        assert!(!rows.as_array().expect("rows").is_empty(), "{zk:?}");
    }
}
