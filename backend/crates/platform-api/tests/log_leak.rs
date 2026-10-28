//! Query content stays out of everything an operator can read. A research
//! query whose SQL carries a unique literal, over data holding a unique cell
//! value that the query fails to cast, leaves neither value in any log line,
//! audit record or HTTP response, with operational logging at `trace`.
//!
//! This file is its own test binary because it installs the production
//! subscriber process-wide, the way `platform_telemetry::init_from_env`
//! does, including a `log` bridge if one is ever compiled back in. Do not
//! use `AuditCapture` here: its thread-local subscriber would replace this
//! one, and the writer checked below would see nothing.

mod common;

use std::sync::{Arc, Mutex};

use arrow::array::StringArray;
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatch;
use axum::Router;
use axum::http::StatusCode;
use parquet::arrow::ArrowWriter;
use platform_api::dev::DevResearchStack;
use platform_api::{AppState, build_app};
use platform_core::{ConnectorSlug, TenantId, ZkMode};
use platform_crypto::TenantKeypair;
use quackxide_engine::EngineSettings;
use tracing_subscriber::util::SubscriberInitExt;

use common::{app_state, bearer, json_header, post, send, token_for};

const SECRET: &str = "log-leak-itest-secret";
const CONNECTOR: &str = "ledger";
/// Appears only in the researcher's SQL, as a string literal.
const SQL_SENTINEL: &str = "sqlsentinel7f3a9c";
/// Appears only in the steward's data, in the cell the query fails to cast.
const CELL_SENTINEL: &str = "cellsentinel4be21d";

#[tokio::test]
async fn query_literals_and_cell_values_never_reach_logs_or_responses() {
    let output = SharedBuffer::default();
    let sink = output.clone();
    platform_telemetry::build_subscriber("trace", move || sink.clone())
        .try_init()
        .expect("the only subscriber in this test binary");

    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let app = research_app(steward).await;

    let (status, grant) = post(
        &app,
        "/api/v1/grants",
        &token_for(SECRET, steward),
        &format!(r#"{{"researcher_tenant":"{researcher}","connector":"{CONNECTOR}"}}"#),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "grant: {grant}");

    let sql = format!(
        "SELECT COUNT(*) AS n FROM {CONNECTOR} \
         WHERE label = '{SQL_SENTINEL}' OR CAST(label AS BIGINT) > 0"
    );
    let request = serde_json::json!({
        "steward_tenant": steward.to_string(),
        "connector": CONNECTOR,
        "sql": sql,
    });
    let token = token_for(SECRET, researcher);
    let (status, body) = send(
        &app,
        "POST",
        "/api/v1/research/query",
        &[bearer(&token), json_header()],
        request.to_string().into_bytes(),
    )
    .await;
    let body = String::from_utf8_lossy(&body);
    // The cast fails on the sentinel cell, so the engine refuses the query.
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("could not be executed"), "{body}");

    let logs = output.contents();
    // Both prove the writer saw the run; without them, a dead capture
    // would pass the leak checks below.
    let audited_failure = logs.lines().any(|line| {
        line.contains(r#""audit_kind":"engine.query""#) && line.contains(r#""outcome":"failed""#)
    });
    assert!(
        audited_failure,
        "no failed engine.query audit record:\n{logs}"
    );
    assert!(
        logs.contains(r#""level":"DEBUG""#),
        "no debug-level logs:\n{logs}"
    );
    for sentinel in [SQL_SENTINEL, CELL_SENTINEL] {
        assert!(
            !logs.contains(sentinel),
            "{sentinel} reached the logs:\n{logs}"
        );
        assert!(
            !body.contains(sentinel),
            "{sentinel} reached the response: {body}"
        );
    }
}

/// The research app with `steward`'s sentinel dataset committed under
/// `CONNECTOR`, wired like `common::research_app` (k = 5, budget 100).
async fn research_app(steward: TenantId) -> Router {
    let connector = ConnectorSlug::new(CONNECTOR).expect("slug");
    let mut stack = DevResearchStack::new();
    stack
        .commit_snapshot(
            steward,
            TenantKeypair::generate(),
            &connector,
            "rows",
            &sentinel_parquet(),
        )
        .await
        .expect("commit");
    let vault = stack.vault();
    let settings = EngineSettings {
        zk: ZkMode::Disabled, // research mode forces ZK on regardless
        max_concurrent_queries: 4,
    };
    let service = stack.query_service(settings, 5, 100);
    build_app(AppState {
        query: Some(Arc::new(service)),
        ..app_state(SECRET, vault)
    })
}

/// One `label` column whose last cell is `CELL_SENTINEL`, so casting the
/// column to an integer fails on that cell.
fn sentinel_parquet() -> Vec<u8> {
    let field = Field::new("label", DataType::Utf8, false);
    let schema = Arc::new(Schema::new(vec![field]));
    let labels = StringArray::from_iter_values(["1", "2", "3", "4", "5", CELL_SENTINEL]);
    let batch = RecordBatch::try_new(schema.clone(), vec![Arc::new(labels)]).expect("batch");
    let mut buf = Vec::new();
    let mut writer = ArrowWriter::try_new(&mut buf, schema, None).expect("writer");
    writer.write(&batch).expect("write");
    writer.close().expect("close");
    buf
}

/// Everything the subscriber writes, kept for the assertions.
#[derive(Clone, Default)]
struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

impl SharedBuffer {
    fn contents(&self) -> String {
        let bytes = self.0.lock().expect("buffer lock").clone();
        String::from_utf8(bytes).expect("log output is UTF-8")
    }
}

impl std::io::Write for SharedBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let mut buffer = self.0.lock().expect("buffer lock");
        buffer.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
