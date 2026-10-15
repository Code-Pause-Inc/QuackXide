//! Operational metrics: served only by the metrics router, labelled by
//! route pattern and refusal kind, and never carrying paths, tenant ids,
//! error messages, SQL or the engine name.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use http_body_util::BodyExt;
use platform_api::query::{ConnectorQueryService, DevKeyProvider};
use platform_api::{AppState, build_apps};
use platform_auth::JwtVerifier;
use platform_config::PlatformConfig;
use platform_connectors::pipeline::{EnclavePipeline, SyncJob};
use platform_connectors::source::FixtureSource;
use platform_core::{TenantId, ZkMode};
use platform_crypto::TenantKeypair;
use platform_enclave::DevAttestation;
use platform_storage::{ObjectStoreVault, VaultStore};
use quackxide_engine::EngineSettings;
use tower::ServiceExt;

const SECRET: &str = "metrics-itest-secret";
const ISS: &str = "urn:platform:auth";
const AUD: &str = "urn:platform:drive";

fn token_for(tenant: TenantId) -> String {
    platform_auth::mint_token(SECRET, ISS, AUD, tenant, "itest", 3600).expect("mint")
}

/// The API and metrics routers over a QuickBooks sync sealed to `tenant`.
async fn apps(tenant: TenantId) -> (Router, Router) {
    let vault: Arc<dyn VaultStore> = Arc::new(ObjectStoreVault::new_in_memory());
    let keypair = TenantKeypair::generate();
    let pipeline = EnclavePipeline::new(
        Arc::new(DevAttestation::allow_insecure_dev()),
        vault.clone(),
        false,
    );
    pipeline
        .run_sync(&SyncJob {
            tenant,
            tenant_public_key: keypair.public_key(),
            source: Arc::new(FixtureSource::quickbooks_demo().expect("fixture")),
        })
        .await
        .expect("seal sync");
    let query = ConnectorQueryService::new(
        vault.clone(),
        Arc::new(DevKeyProvider::new(tenant, keypair)),
        Arc::new(DevAttestation::allow_insecure_dev()),
        EngineSettings {
            zk: ZkMode::Disabled,
            max_concurrent_queries: 4,
        },
        false,
    );
    let config = PlatformConfig::from_source(|_| None).expect("config");
    build_apps(AppState {
        config: Arc::new(config),
        vault,
        jwt: Some(Arc::new(JwtVerifier::hs256(SECRET, ISS, AUD))),
        query: Some(Arc::new(query)),
        provisioning: None,
    })
}

async fn send(app: &Router, request: Request<Body>) -> (StatusCode, String) {
    let response = app.clone().oneshot(request).await.expect("response");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    (status, String::from_utf8(bytes.to_vec()).expect("utf-8"))
}

fn get(uri: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .body(Body::empty())
        .expect("request")
}

async fn scrape(metrics: &Router) -> String {
    let (status, body) = send(metrics, get("/metrics")).await;
    assert_eq!(status, StatusCode::OK);
    body
}

#[tokio::test]
async fn only_the_metrics_router_serves_metrics() {
    let (api, metrics) = apps(TenantId::generate()).await;
    assert_eq!(send(&api, get("/metrics")).await.0, StatusCode::NOT_FOUND);

    let response = metrics
        .clone()
        .oneshot(get("/metrics"))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers()[header::CONTENT_TYPE]
            .to_str()
            .expect("header")
            .starts_with("application/openmetrics-text")
    );
}

#[tokio::test]
async fn requests_are_labelled_by_route_pattern_never_path() {
    let (api, metrics) = apps(TenantId::generate()).await;
    let object_id = "0b6f3c1e-2f4a-4d55-9a8e-7c1d2e3f4a5b";
    let (status, _) = send(
        &api,
        get(&format!("/api/v1/drive/objects/{object_id}/chunks/0")),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    send(&api, get("/no-such-route/private-looking-segment")).await;

    let body = scrape(&metrics).await;
    assert!(
        body.contains(
            r#"http_requests_total{method="GET",route="/api/v1/drive/objects/{object_id}/chunks/{chunk_index}",status="401"} 1"#
        ),
        "{body}"
    );
    assert!(
        body.contains(r#"http_requests_total{method="GET",route="unmatched",status="404"} 1"#),
        "{body}"
    );
    assert!(
        body.contains(r#"api_refusals_total{reason="unauthorized"} 1"#),
        "{body}"
    );
    assert!(!body.contains(object_id), "{body}");
    assert!(!body.contains("private-looking-segment"), "{body}");
}

#[tokio::test]
async fn refusals_carry_the_kind_never_the_message_or_tenant() {
    let tenant = TenantId::generate();
    let (api, metrics) = apps(tenant).await;
    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/query")
        .header(
            header::AUTHORIZATION,
            format!("Bearer {}", token_for(tenant)),
        )
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            r#"{"connector":"quickbooks","sql":"SELECT marker_column_xyz FROM quickbooks"}"#,
        ))
        .expect("request");
    let (status, error) = send(&api, request).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let message: serde_json::Value = serde_json::from_str(&error).expect("json");
    let message = message["error"].as_str().expect("message").to_owned();

    let body = scrape(&metrics).await;
    assert!(
        body.contains(r#"api_refusals_total{reason="bad_request"} 1"#),
        "{body}"
    );
    assert!(!body.contains("marker_column_xyz"), "{body}");
    assert!(!body.contains(&message), "{body}");
    assert!(!body.contains(&tenant.to_string()), "{body}");
}

#[tokio::test]
async fn framework_rejections_count_as_other_refusals() {
    let tenant = TenantId::generate();
    let (api, metrics) = apps(tenant).await;
    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/query")
        .header(
            header::AUTHORIZATION,
            format!("Bearer {}", token_for(tenant)),
        )
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("{not json"))
        .expect("request");
    assert!(send(&api, request).await.0.is_client_error());

    let body = scrape(&metrics).await;
    assert!(
        body.contains(r#"api_refusals_total{reason="other"} 1"#),
        "{body}"
    );
}

#[tokio::test]
async fn queries_record_their_plaintext_slot_wait() {
    let tenant = TenantId::generate();
    let (api, metrics) = apps(tenant).await;
    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/query")
        .header(
            header::AUTHORIZATION,
            format!("Bearer {}", token_for(tenant)),
        )
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            r#"{"connector":"quickbooks","sql":"SELECT COUNT(*) AS n FROM quickbooks"}"#,
        ))
        .expect("request");
    assert_eq!(send(&api, request).await.0, StatusCode::OK);

    let body = scrape(&metrics).await;
    assert!(
        body.contains("query_plaintext_slot_wait_seconds_count 1"),
        "{body}"
    );
}

#[tokio::test]
async fn unusual_methods_share_one_label() {
    let (api, metrics) = apps(TenantId::generate()).await;
    let request = Request::builder()
        .method(Method::from_bytes(b"BREWCOFFEE").expect("method"))
        .uri("/healthz")
        .body(Body::empty())
        .expect("request");
    send(&api, request).await;

    let body = scrape(&metrics).await;
    assert!(body.contains(r#"method="other""#), "{body}");
    assert!(!body.contains("BREWCOFFEE"), "{body}");
}

#[tokio::test]
async fn metrics_never_name_the_engine() {
    let (api, metrics) = apps(TenantId::generate()).await;
    send(&api, get("/healthz")).await;
    assert!(!scrape(&metrics).await.to_lowercase().contains("quackxide"));
}
