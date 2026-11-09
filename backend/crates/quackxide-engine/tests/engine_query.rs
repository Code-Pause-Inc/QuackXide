//! Engine tests: DataFusion analytics over decrypted-in-RAM Parquet, the
//! blind-index ciphertext-equality scan, and the ZK-mode policy gate.

use std::sync::Arc;

use arrow::array::{Float64Array, StringArray};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatch;
use parquet::arrow::ArrowWriter;
use platform_core::ZkMode;
use quackxide_engine::{
    EngineSettings, MinCountThreshold, QueryError, QueryScope, blind_index_hex,
};

const CUSTOMER_KEY: &[u8] = b"tenant-42/customer/index-key";

/// A small invoices table with a blind-index column, as Parquet bytes.
fn invoices_parquet() -> Vec<u8> {
    let schema = Arc::new(Schema::new(vec![
        Field::new("id", DataType::Utf8, false),
        Field::new("currency", DataType::Utf8, false),
        Field::new("total", DataType::Float64, false),
        Field::new("customer_bidx", DataType::Utf8, false),
    ]));

    let ids = StringArray::from_iter_values(["1042", "1043", "1044"]);
    let currency = StringArray::from_iter_values(["USD", "USD", "EUR"]);
    let total = Float64Array::from(vec![1250.0, 480.25, 99.99]);
    let bidx = StringArray::from_iter_values([
        blind_index_hex(CUSTOMER_KEY, b"Sample Customer A"),
        blind_index_hex(CUSTOMER_KEY, b"Sample Customer B"),
        blind_index_hex(CUSTOMER_KEY, b"Sample Customer C"),
    ]);

    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(ids),
            Arc::new(currency),
            Arc::new(total),
            Arc::new(bidx),
        ],
    )
    .expect("batch");

    let mut buf = Vec::new();
    let mut writer = ArrowWriter::try_new(&mut buf, schema, None).expect("writer");
    writer.write(&batch).expect("write");
    writer.close().expect("close");
    buf
}

fn scope(zk: ZkMode) -> QueryScope {
    let mut scope = QueryScope::new(EngineSettings {
        zk,
        max_concurrent_queries: 4,
    });
    scope
        .register_parquet("invoices", &invoices_parquet())
        .expect("register");
    scope
}

#[tokio::test]
async fn analytics_aggregate_over_decrypted_frame() {
    let scope = scope(ZkMode::Disabled);
    let rows = scope
        .sql_json("SELECT currency, SUM(total) AS revenue FROM invoices GROUP BY currency ORDER BY currency")
        .await
        .expect("query");

    let arr = rows.as_array().expect("array");
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0]["currency"], "EUR");
    assert_eq!(arr[0]["revenue"], 99.99);
    assert_eq!(arr[1]["currency"], "USD");
    assert_eq!(arr[1]["revenue"], 1730.25);
}

#[tokio::test]
async fn blind_index_equality_finds_row_without_plaintext() {
    let scope = scope(ZkMode::Disabled);

    // Computed client-side; the engine sees only the HMAC image.
    let needle = blind_index_hex(CUSTOMER_KEY, b"Sample Customer B");
    let rows = scope
        .sql_json(&format!(
            "SELECT id, total FROM invoices WHERE customer_bidx = '{needle}'"
        ))
        .await
        .expect("query");

    let arr = rows.as_array().expect("array");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["id"], "1043");
    assert_eq!(arr[0]["total"], 480.25);
}

#[tokio::test]
async fn blind_index_miss_returns_nothing() {
    let scope = scope(ZkMode::Disabled);
    let needle = blind_index_hex(CUSTOMER_KEY, b"Nonexistent Customer");
    let rows = scope
        .sql_json(&format!(
            "SELECT id FROM invoices WHERE customer_bidx = '{needle}'"
        ))
        .await
        .expect("query");
    assert_eq!(rows.as_array().expect("array").len(), 0);
}

#[tokio::test]
async fn zk_mode_permits_aggregates_but_blocks_row_egress() {
    let mut scope = scope(ZkMode::Enabled);
    scope.set_disclosure(Arc::new(MinCountThreshold { k: 2 }));

    // Aggregate query is allowed.
    let ok = scope
        .sql_json("SELECT COUNT(*) AS n FROM invoices")
        .await
        .expect("aggregate allowed");
    assert_eq!(ok.as_array().expect("array")[0]["n"], 3);

    // The single-invoice EUR cohort is below k and withheld.
    let by_currency = scope
        .sql_json("SELECT currency, COUNT(*) AS n FROM invoices GROUP BY currency")
        .await
        .expect("grouped aggregate allowed");
    assert_eq!(
        by_currency,
        serde_json::json!([{ "currency": "USD", "n": 2 }])
    );
    assert_eq!(scope.last_suppressed_rows(), 1);

    // Raw-row egress is rejected at the plan level.
    for blocked in [
        "SELECT * FROM invoices",
        "SELECT id FROM invoices",
        "SELECT id, total FROM invoices WHERE currency = 'USD'",
    ] {
        let err = scope.sql(blocked).await.expect_err("must be rejected");
        assert!(matches!(err, QueryError::ZkPolicy), "query: {blocked}");
    }
}

#[tokio::test]
async fn disabled_zk_mode_allows_row_level_queries() {
    let scope = scope(ZkMode::Disabled);
    let rows = scope
        .sql_json("SELECT id FROM invoices ORDER BY id")
        .await
        .expect("row query allowed");
    assert_eq!(rows.as_array().expect("array").len(), 3);
}

#[tokio::test]
async fn querying_unregistered_table_errors() {
    let scope = scope(ZkMode::Disabled);
    assert!(scope.sql("SELECT * FROM missing").await.is_err());
}

#[tokio::test]
async fn empty_result_serializes_to_empty_array() {
    let scope = scope(ZkMode::Disabled);
    let rows = scope
        .sql_json("SELECT id FROM invoices WHERE id = 'nope'")
        .await
        .expect("query");
    assert_eq!(rows, serde_json::json!([]));
}

// ── Declared shapes (steward uploads, ADR 0011) ──

fn invoice_columns(types: &[(&str, platform_core::ColumnType)]) -> platform_core::DeclaredSchema {
    platform_core::DeclaredSchema::new(
        types
            .iter()
            .map(|(name, column_type)| platform_core::DeclaredColumn {
                name: (*name).to_owned(),
                column_type: *column_type,
            })
            .collect(),
    )
    .expect("schema")
}

fn declared_invoices() -> platform_core::DeclaredSchema {
    use platform_core::ColumnType::{Float64, String};
    invoice_columns(&[
        ("id", String),
        ("currency", String),
        ("total", Float64),
        ("customer_bidx", String),
    ])
}

fn register_declared(
    schema: &platform_core::DeclaredSchema,
    row_cap: u64,
) -> Result<usize, QueryError> {
    let mut scope = QueryScope::new(EngineSettings {
        zk: ZkMode::Disabled,
        max_concurrent_queries: 1,
    });
    let parquet = invoices_parquet();
    scope.register_parquet_declared("invoices", &[&parquet], schema, row_cap)
}

#[tokio::test]
async fn data_matching_its_declaration_registers() {
    assert_eq!(register_declared(&declared_invoices(), 3).expect("rows"), 3);
    assert_eq!(
        register_declared(&declared_invoices(), 100).expect("rows"),
        3
    );
}

#[test]
fn data_not_matching_its_declared_schema_is_refused() {
    use platform_core::ColumnType::{Float64, Int64, String};
    for schema in [
        // A renamed column.
        invoice_columns(&[
            ("id", String),
            ("ccy", String),
            ("total", Float64),
            ("customer_bidx", String),
        ]),
        // Another type family.
        invoice_columns(&[
            ("id", Int64),
            ("currency", String),
            ("total", Float64),
            ("customer_bidx", String),
        ]),
        // A column missing, one extra, and the right columns out of order.
        invoice_columns(&[("id", String), ("currency", String), ("total", Float64)]),
        invoice_columns(&[
            ("id", String),
            ("currency", String),
            ("total", Float64),
            ("customer_bidx", String),
            ("extra", Int64),
        ]),
        invoice_columns(&[
            ("currency", String),
            ("id", String),
            ("total", Float64),
            ("customer_bidx", String),
        ]),
    ] {
        let err = register_declared(&schema, 3).expect_err("mismatch");
        assert!(
            matches!(
                err,
                QueryError::DeclarationMismatch(quackxide_engine::Declaration::Schema)
            ),
            "{err:?}"
        );
        // The error names the check, never a column.
        let shown = err.to_string();
        assert_eq!(shown, "dataset does not match its declared schema");
    }
}

#[test]
fn data_over_its_declared_row_cap_is_refused() {
    let err = register_declared(&declared_invoices(), 2).expect_err("over the cap");
    assert!(
        matches!(
            err,
            QueryError::DeclarationMismatch(quackxide_engine::Declaration::RowCap)
        ),
        "{err:?}"
    );
    assert_eq!(
        err.to_string(),
        "dataset does not match its declared row cap"
    );
}

#[test]
fn string_encodings_share_the_declared_string_family() {
    use arrow::datatypes::{DataType, TimeUnit};
    use platform_core::ColumnType;
    use quackxide_engine::column_type_of;
    for data_type in [
        DataType::Utf8,
        DataType::LargeUtf8,
        DataType::Utf8View,
        DataType::Dictionary(Box::new(DataType::Int32), Box::new(DataType::Utf8)),
    ] {
        assert_eq!(column_type_of(&data_type), Some(ColumnType::String));
    }
    assert_eq!(
        column_type_of(&DataType::Timestamp(
            TimeUnit::Microsecond,
            Some("UTC".into())
        )),
        Some(ColumnType::Timestamp)
    );
    assert_eq!(
        column_type_of(&DataType::Decimal128(10, 2)),
        Some(ColumnType::Decimal)
    );
    assert_eq!(column_type_of(&DataType::Binary), None);
}
