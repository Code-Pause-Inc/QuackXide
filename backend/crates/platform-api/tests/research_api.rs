//! Research-access integration tests: a steward grants a researcher
//! aggregate access to a sealed dataset; the researcher runs
//! disclosure-controlled queries (small cohorts suppressed); ungranted and
//! revoked access is refused; and row-level egress is blocked.

use std::sync::Arc;

use arrow::array::{Int64Array, StringArray};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatch;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use parquet::arrow::ArrowWriter;
use platform_api::query::{ConnectorQueryService, MultiTenantDevKeyProvider};
use platform_api::research::ResearchStores;
use platform_api::{AppState, build_app};
use platform_auth::JwtVerifier;
use platform_config::PlatformConfig;
use platform_connectors::pipeline::envelope_info;
use platform_core::{ConnectorSlug, ObjectId, TenantId, ZkMode};
use platform_crypto::{TenantKeypair, hpke_seal_to_tenant};
use platform_enclave::DevAttestation;
use platform_storage::{ObjectStoreVault, TenantPaths, VaultStore};
use platform_tenancy::{InMemoryBudgetLedger, InMemoryCatalogRegistry, InMemoryGrantRegistry};
use quackxide_engine::EngineSettings;
use tower::ServiceExt;

const SECRET: &str = "research-itest-secret";
const ISS: &str = "urn:platform:auth";
const AUD: &str = "urn:platform:drive";

fn token_for(tenant: TenantId) -> String {
    platform_auth::mint_token(SECRET, ISS, AUD, tenant, "itest", 3600).expect("mint")
}

/// A cohort dataset: 6 "flu" rows, 1 "rare_disease" row.
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

/// Build an app where `steward` has a sealed `health` connector dataset,
/// queryable in research mode (cohort threshold k=5).
async fn research_app(steward: TenantId, steward_keypair: TenantKeypair) -> Router {
    let vault: Arc<dyn VaultStore> = Arc::new(ObjectStoreVault::new_in_memory());
    let connector = ConnectorSlug::new("health").expect("slug");
    let object = ObjectId::generate();

    // Seal the cohort dataset to the steward's key (as the pipeline would).
    let info = envelope_info(&steward, &connector, &object);
    let envelope = hpke_seal_to_tenant(&steward_keypair.public_key(), &info, &cohorts_parquet())
        .expect("seal");
    vault
        .put(
            &TenantPaths::connector_object(steward, &connector, object),
            envelope.into(),
        )
        .await
        .expect("put");

    let mut keys = MultiTenantDevKeyProvider::new();
    keys.insert(steward, steward_keypair);

    let stores = ResearchStores {
        grants: Arc::new(InMemoryGrantRegistry::default()),
        budgets: Arc::new(InMemoryBudgetLedger::default()),
        catalog: Arc::new(InMemoryCatalogRegistry::default()),
    };
    let service = ConnectorQueryService::new(
        vault.clone(),
        Arc::new(keys),
        Arc::new(DevAttestation::allow_insecure_dev()),
        EngineSettings {
            zk: ZkMode::Disabled, // research mode forces ZK on regardless
            max_concurrent_queries: 4,
        },
        false,
    )
    .with_research(stores, 5, 100);

    let config = PlatformConfig::from_source(|_| None).expect("config");
    build_app(AppState {
        config: Arc::new(config),
        vault,
        jwt: Some(Arc::new(JwtVerifier::hs256(SECRET, ISS, AUD))),
        query: Some(Arc::new(service)),
        provisioning: None,
    })
}

async fn post(app: &Router, uri: &str, token: &str, body: &str) -> (StatusCode, serde_json::Value) {
    call(app, "POST", uri, token, Some(body)).await
}

async fn call(
    app: &Router,
    method: &str,
    uri: &str,
    token: &str,
    body: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body(
            body.map(|b| Body::from(b.to_owned()))
                .unwrap_or(Body::empty()),
        )
        .expect("request");
    let response = app.clone().oneshot(request).await.expect("response");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

const AGG_SQL: &str =
    "SELECT condition, COUNT(*) AS n FROM health GROUP BY condition ORDER BY condition";

#[tokio::test]
async fn granted_researcher_gets_disclosure_controlled_aggregates() {
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let app = research_app(steward, TenantKeypair::generate()).await;

    // Steward grants the researcher access to the health connector.
    let (status, grant) = post(
        &app,
        "/api/v1/grants",
        &token_for(steward),
        &format!(r#"{{"researcher_tenant":"{researcher}","connector":"health"}}"#),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "grant: {grant}");

    // Researcher queries: "flu" cohort (6) survives, "rare_disease" (1) is
    // suppressed below the k=5 threshold.
    let (status, body) = post(
        &app,
        "/api/v1/research/query",
        &token_for(researcher),
        &format!(r#"{{"steward_tenant":"{steward}","connector":"health","sql":"{AGG_SQL}"}}"#),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "query: {body}");
    assert_eq!(body["mode"], "research");
    assert_eq!(body["suppressed_rows"], 1);
    let rows = body["rows"].as_array().expect("rows");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["condition"], "flu");
    assert_eq!(rows[0]["n"], 6);
    // One unit of the default allocation (100) consumed.
    assert_eq!(body["budget_remaining"], 99);
}

#[tokio::test]
async fn budget_exhausts_and_steward_top_up_restores_access() {
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let app = research_app(steward, TenantKeypair::generate()).await;

    // Explicit two-query allocation.
    let (status, grant) = post(
        &app,
        "/api/v1/grants",
        &token_for(steward),
        &format!(r#"{{"researcher_tenant":"{researcher}","connector":"health","query_budget":2}}"#),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "grant: {grant}");
    assert_eq!(grant["budget"]["limit"], 2);
    assert_eq!(grant["budget"]["remaining"], 2);
    let grant_id = grant["grant_id"].as_str().expect("grant id").to_owned();

    let research_body =
        format!(r#"{{"steward_tenant":"{steward}","connector":"health","sql":"{AGG_SQL}"}}"#);
    let rtoken = token_for(researcher);

    let (status, body) = post(&app, "/api/v1/research/query", &rtoken, &research_body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["budget_remaining"], 1);
    let (status, body) = post(&app, "/api/v1/research/query", &rtoken, &research_body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["budget_remaining"], 0);

    // Third query: allocation spent → refused, nothing decrypted.
    let (status, _) = post(&app, "/api/v1/research/query", &rtoken, &research_body).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);

    // Steward tops up; access resumes with the raised allocation.
    let (status, topped) = post(
        &app,
        &format!("/api/v1/grants/{grant_id}/budget"),
        &token_for(steward),
        r#"{"additional":3}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "top up: {topped}");
    assert_eq!(topped["limit"], 5);
    assert_eq!(topped["remaining"], 3);

    let (status, body) = post(&app, "/api/v1/research/query", &rtoken, &research_body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["budget_remaining"], 2);
}

#[tokio::test]
async fn rejected_queries_still_consume_budget() {
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let app = research_app(steward, TenantKeypair::generate()).await;

    let (_, grant) = post(
        &app,
        "/api/v1/grants",
        &token_for(steward),
        &format!(r#"{{"researcher_tenant":"{researcher}","connector":"health","query_budget":1}}"#),
    )
    .await;
    assert_eq!(grant["budget"]["limit"], 1);
    let rtoken = token_for(researcher);

    // A raw-row probe is rejected by the plan gate (422) — but it spends the
    // only unit: probing the aggregate-only boundary is never free.
    let (status, _) = post(
        &app,
        "/api/v1/research/query",
        &rtoken,
        &format!(
            r#"{{"steward_tenant":"{steward}","connector":"health","sql":"SELECT condition, age FROM health"}}"#
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    // The compliant query now finds the budget spent.
    let (status, _) = post(
        &app,
        "/api/v1/research/query",
        &rtoken,
        &format!(r#"{{"steward_tenant":"{steward}","connector":"health","sql":"{AGG_SQL}"}}"#),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn budget_is_visible_to_parties_only_and_steward_controls_top_up() {
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let outsider = TenantId::generate();
    let app = research_app(steward, TenantKeypair::generate()).await;

    let (_, grant) = post(
        &app,
        "/api/v1/grants",
        &token_for(steward),
        &format!(r#"{{"researcher_tenant":"{researcher}","connector":"health"}}"#),
    )
    .await;
    let grant_id = grant["grant_id"].as_str().expect("grant id").to_owned();
    let budget_uri = format!("/api/v1/grants/{grant_id}/budget");

    // Both parties can read the standing.
    let (status, body) = call(&app, "GET", &budget_uri, &token_for(steward), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["remaining"], 100);
    let (status, _) = call(&app, "GET", &budget_uri, &token_for(researcher), None).await;
    assert_eq!(status, StatusCode::OK);

    // A third tenant learns nothing — not even that the grant exists.
    let (status, _) = call(&app, "GET", &budget_uri, &token_for(outsider), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Allocation is steward-only: the researcher cannot raise their own
    // budget, and gets the same answer as an unknown id.
    let (status, _) = post(
        &app,
        &budget_uri,
        &token_for(researcher),
        r#"{"additional":9}"#,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = post(
        &app,
        &budget_uri,
        &token_for(outsider),
        r#"{"additional":9}"#,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Zero top-up is meaningless and refused before any lookup.
    let (status, _) = post(
        &app,
        &budget_uri,
        &token_for(steward),
        r#"{"additional":0}"#,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn ungranted_research_query_is_forbidden() {
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let app = research_app(steward, TenantKeypair::generate()).await;

    // No grant created.
    let (status, _) = post(
        &app,
        "/api/v1/research/query",
        &token_for(researcher),
        &format!(r#"{{"steward_tenant":"{steward}","connector":"health","sql":"{AGG_SQL}"}}"#),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn revoked_grant_blocks_further_queries() {
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let app = research_app(steward, TenantKeypair::generate()).await;

    let (_, grant) = post(
        &app,
        "/api/v1/grants",
        &token_for(steward),
        &format!(r#"{{"researcher_tenant":"{researcher}","connector":"health"}}"#),
    )
    .await;
    let grant_id = grant["grant_id"].as_str().expect("grant id");

    // Works while granted.
    let (status, _) = post(
        &app,
        "/api/v1/research/query",
        &token_for(researcher),
        &format!(r#"{{"steward_tenant":"{steward}","connector":"health","sql":"{AGG_SQL}"}}"#),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Steward revokes.
    let (status, _) = call(
        &app,
        "DELETE",
        &format!("/api/v1/grants/{grant_id}"),
        &token_for(steward),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Now forbidden.
    let (status, _) = post(
        &app,
        "/api/v1/research/query",
        &token_for(researcher),
        &format!(r#"{{"steward_tenant":"{steward}","connector":"health","sql":"{AGG_SQL}"}}"#),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn researcher_cannot_egress_raw_rows_or_skip_count() {
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let app = research_app(steward, TenantKeypair::generate()).await;
    post(
        &app,
        "/api/v1/grants",
        &token_for(steward),
        &format!(r#"{{"researcher_tenant":"{researcher}","connector":"health"}}"#),
    )
    .await;
    let rtoken = token_for(researcher);

    // Raw-row egress → 422 (ZK aggregate-only gate).
    let (status, _) = post(
        &app,
        "/api/v1/research/query",
        &rtoken,
        &format!(
            r#"{{"steward_tenant":"{steward}","connector":"health","sql":"SELECT condition, age FROM health"}}"#
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    // Aggregate without the cohort-size column → 422 (disclosure control).
    let (status, _) = post(
        &app,
        "/api/v1/research/query",
        &rtoken,
        &format!(
            r#"{{"steward_tenant":"{steward}","connector":"health","sql":"SELECT condition, AVG(age) AS a FROM health GROUP BY condition"}}"#
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn cannot_grant_to_self() {
    let steward = TenantId::generate();
    let app = research_app(steward, TenantKeypair::generate()).await;
    let (status, _) = post(
        &app,
        "/api/v1/grants",
        &token_for(steward),
        &format!(r#"{{"researcher_tenant":"{steward}","connector":"health"}}"#),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}
