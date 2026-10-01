//! Dataset catalog: a steward publishes a priced listing; a researcher
//! browses, requests access, and after approval runs disclosure-controlled
//! queries against the included budget. Also covers denial, withdrawal,
//! scoping, and input bounds.

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
use platform_connectors::snapshot::SnapshotWriter;
use platform_core::{ConnectorSlug, TenantId, ZkMode};
use platform_crypto::TenantKeypair;
use platform_enclave::DevAttestation;
use platform_storage::{ObjectStoreVault, VaultStore};
use platform_tenancy::{InMemoryBudgetLedger, InMemoryCatalogRegistry, InMemoryGrantRegistry};
use quackxide_engine::EngineSettings;
use tower::ServiceExt;

const SECRET: &str = "catalog-itest-secret";
const ISS: &str = "urn:platform:auth";
const AUD: &str = "urn:platform:drive";

fn token_for(tenant: TenantId) -> String {
    platform_auth::mint_token(SECRET, ISS, AUD, tenant, "itest", 3600).expect("mint")
}

/// Same cohort fixture as research_api: 6 "flu" rows, 1 "rare_disease" row.
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

/// App where `steward` has a sealed `health` dataset and the research layer
/// (catalog + grants + budgets, k=5, default budget 100) is enabled.
async fn marketplace_app(steward: TenantId, steward_keypair: TenantKeypair) -> Router {
    let vault: Arc<dyn VaultStore> = Arc::new(ObjectStoreVault::new_in_memory());
    let connector = ConnectorSlug::new("health").expect("slug");
    // Commit the cohort dataset as a snapshot sealed to the steward's key
    // (as the pipeline would).
    let steward_public_key = steward_keypair.public_key();
    let mut snapshot =
        SnapshotWriter::begin(&*vault, steward, &steward_public_key, connector.clone());
    snapshot
        .put("cohorts", &cohorts_parquet())
        .await
        .expect("put");
    snapshot.commit().await.expect("commit");

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
            zk: ZkMode::Disabled,
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

async fn post(app: &Router, uri: &str, token: &str, body: &str) -> (StatusCode, serde_json::Value) {
    call(app, "POST", uri, token, Some(body)).await
}

const PUBLISH_BODY: &str = r#"{
    "connector": "health",
    "title": "De-identified respiratory cohort extracts",
    "description": "Quarterly condition-level extracts. Aggregate queries only; k-suppression enforced.",
    "license_fee_cents": 120000,
    "compute_rate_cents": 40,
    "grant_budget": 25
}"#;

const AGG_SQL: &str =
    "SELECT condition, COUNT(*) AS n FROM health GROUP BY condition ORDER BY condition";

#[tokio::test]
async fn publish_browse_request_approve_query_lifecycle() {
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let app = marketplace_app(steward, TenantKeypair::generate()).await;

    // Steward publishes a priced listing.
    let (status, listing) = post(&app, "/api/v1/catalog", &token_for(steward), PUBLISH_BODY).await;
    assert_eq!(status, StatusCode::OK, "publish: {listing}");
    assert_eq!(listing["license_fee_cents"], 120000);
    assert_eq!(listing["compute_rate_cents"], 40);
    assert_eq!(listing["grant_budget"], 25);
    let listing_id = listing["listing_id"].as_str().expect("id").to_owned();

    // Researcher browses the catalog: pricing + platform currency visible.
    let (status, catalog) =
        call(&app, "GET", "/api/v1/catalog", &token_for(researcher), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(catalog["currency"], "USD");
    let listings = catalog["listings"].as_array().expect("listings");
    assert_eq!(listings.len(), 1);
    assert_eq!(
        listings[0]["title"],
        "De-identified respiratory cohort extracts"
    );

    // Researcher requests access with a stated purpose.
    let (status, request) = post(
        &app,
        &format!("/api/v1/catalog/{listing_id}/request"),
        &token_for(researcher),
        r#"{"note":"IRB protocol 44-A, respiratory outcomes study"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "request: {request}");
    assert_eq!(request["status"], "pending");
    let request_id = request["request_id"].as_str().expect("id").to_owned();

    // Repeat request while pending is idempotent.
    let (_, again) = post(
        &app,
        &format!("/api/v1/catalog/{listing_id}/request"),
        &token_for(researcher),
        r#"{"note":"duplicate click"}"#,
    )
    .await;
    assert_eq!(again["request_id"].as_str().expect("id"), request_id);

    // Steward sees the pending request.
    let (status, inbox) = call(
        &app,
        "GET",
        "/api/v1/research/requests",
        &token_for(steward),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(inbox["requests"].as_array().expect("requests").len(), 1);

    // Approval mints the grant with the listing's included budget.
    let (status, resolved) = post(
        &app,
        &format!("/api/v1/research/requests/{request_id}/approve"),
        &token_for(steward),
        "{}",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "approve: {resolved}");
    assert_eq!(resolved["request"]["status"], "approved");
    assert_eq!(resolved["grant"]["budget"]["limit"], 25);

    // Researcher sees the approval and can now run metered research queries.
    let (_, mine) = call(
        &app,
        "GET",
        "/api/v1/research/requests",
        &token_for(researcher),
        None,
    )
    .await;
    assert_eq!(mine["requests"][0]["status"], "approved");

    let (status, body) = post(
        &app,
        "/api/v1/research/query",
        &token_for(researcher),
        &format!(r#"{{"steward_tenant":"{steward}","connector":"health","sql":"{AGG_SQL}"}}"#),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "query: {body}");
    assert_eq!(body["budget_remaining"], 24);
    assert_eq!(body["suppressed_rows"], 1);
}

#[tokio::test]
async fn denial_records_outcome_and_leaves_no_access() {
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let app = marketplace_app(steward, TenantKeypair::generate()).await;

    let (_, listing) = post(&app, "/api/v1/catalog", &token_for(steward), PUBLISH_BODY).await;
    let listing_id = listing["listing_id"].as_str().expect("id").to_owned();

    let (_, request) = post(
        &app,
        &format!("/api/v1/catalog/{listing_id}/request"),
        &token_for(researcher),
        "{}",
    )
    .await;
    let request_id = request["request_id"].as_str().expect("id").to_owned();

    let (status, resolved) = post(
        &app,
        &format!("/api/v1/research/requests/{request_id}/deny"),
        &token_for(steward),
        "{}",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(resolved["request"]["status"], "denied");

    // No grant was minted: research queries stay forbidden.
    let (status, _) = post(
        &app,
        "/api/v1/research/query",
        &token_for(researcher),
        &format!(r#"{{"steward_tenant":"{steward}","connector":"health","sql":"{AGG_SQL}"}}"#),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Denial doesn't block a fresh request (a new pending is created).
    let (status, fresh) = post(
        &app,
        &format!("/api/v1/catalog/{listing_id}/request"),
        &token_for(researcher),
        r#"{"note":"revised protocol"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(fresh["status"], "pending");
    assert_ne!(fresh["request_id"].as_str().expect("id"), request_id);
}

#[tokio::test]
async fn catalog_scoping_and_input_bounds() {
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let outsider = TenantId::generate();
    let app = marketplace_app(steward, TenantKeypair::generate()).await;

    let (_, listing) = post(&app, "/api/v1/catalog", &token_for(steward), PUBLISH_BODY).await;
    let listing_id = listing["listing_id"].as_str().expect("id").to_owned();

    // Steward cannot request access to their own listing.
    let (status, _) = post(
        &app,
        &format!("/api/v1/catalog/{listing_id}/request"),
        &token_for(steward),
        "{}",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Only the steward can withdraw; others learn nothing.
    let (status, _) = call(
        &app,
        "DELETE",
        &format!("/api/v1/catalog/{listing_id}"),
        &token_for(outsider),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = call(
        &app,
        "DELETE",
        &format!("/api/v1/catalog/{listing_id}"),
        &token_for(steward),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Withdrawn ⇒ invisible in the catalog and unrequestable (same 404 as
    // an id that never existed).
    let (_, catalog) = call(&app, "GET", "/api/v1/catalog", &token_for(researcher), None).await;
    assert!(catalog["listings"].as_array().expect("listings").is_empty());
    let (status, _) = post(
        &app,
        &format!("/api/v1/catalog/{listing_id}/request"),
        &token_for(researcher),
        "{}",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Input bounds: oversize title and note are refused, not truncated.
    let long_title = "t".repeat(121);
    let (status, _) = post(
        &app,
        "/api/v1/catalog",
        &token_for(steward),
        &format!(
            r#"{{"connector":"health","title":"{long_title}","license_fee_cents":0,"compute_rate_cents":0}}"#
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Republish, then an oversize request note is refused.
    post(&app, "/api/v1/catalog", &token_for(steward), PUBLISH_BODY).await;
    let long_note = "n".repeat(1001);
    let (status, _) = post(
        &app,
        &format!("/api/v1/catalog/{listing_id}/request"),
        &token_for(researcher),
        &format!(r#"{{"note":"{long_note}"}}"#),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Only the listing's steward can approve a request; others (including
    // the researcher) get the same not-found as an unknown id.
    let (_, request) = post(
        &app,
        &format!("/api/v1/catalog/{listing_id}/request"),
        &token_for(researcher),
        "{}",
    )
    .await;
    let request_id = request["request_id"].as_str().expect("id");
    for who in [researcher, outsider] {
        let (status, _) = post(
            &app,
            &format!("/api/v1/research/requests/{request_id}/approve"),
            &token_for(who),
            "{}",
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
}
