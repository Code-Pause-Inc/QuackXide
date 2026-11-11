//! Research access in the binary's own wiring
//! (`platform_api::wiring::build_state`), independent of key release.
//!
//! With only a token secret configured, the catalog, access-request, grant
//! and budget routes answer, while the confidential query routes still
//! refuse with 503 and charge nothing. Without a research layer, the
//! research routes refuse with 503.

mod common;

use std::sync::Arc;

use axum::Router;
use axum::http::StatusCode;
use platform_api::build_app;
use platform_api::wiring::build_state;
use platform_config::PlatformConfig;
use platform_core::TenantId;
use platform_storage::ObjectStoreVault;

use common::{call, post};

const SECRET: &str = "research-wiring-itest-secret";

/// A listing whose approval grants 25 query units.
const PUBLISH_BODY: &str = r#"{
    "connector": "health",
    "title": "Synthetic respiratory cohort",
    "license_fee_cents": 0,
    "compute_rate_cents": 0,
    "grant_budget": 25
}"#;

fn token_for(tenant: TenantId) -> String {
    common::token_for(SECRET, tenant)
}

/// What the binary sees in development mode with only a token secret set:
/// every other key at its default, so an in-memory vault, no
/// `KEY_RELEASE_URL` and attestation required. Without the secret every
/// authenticated route answers 503. The HS256 secret and the in-memory vault
/// are development paths, which production mode refuses (ADR 0009).
fn binary_config() -> PlatformConfig {
    PlatformConfig::from_source(|key| match key {
        "APP_ENV" => Some("development".to_owned()),
        "JWT_HS256_SECRET" => Some(SECRET.to_owned()),
        _ => None,
    })
    .expect("config")
}

/// The router exactly as the `platform-api` binary wires it.
async fn binary_app() -> Router {
    build_app(build_state(binary_config()).await.expect("state"))
}

#[tokio::test]
async fn the_binary_wires_research_access_without_a_query_service() {
    let state = build_state(binary_config()).await.expect("state");
    assert!(state.research.is_some(), "research access must be wired");
    assert!(state.query.is_none(), "no key release, so no query service");
}

#[tokio::test]
async fn research_routes_answer_while_queries_stay_fail_closed() {
    let app = binary_app().await;
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let other_researcher = TenantId::generate();

    // Publish: steward lists a dataset.
    let (status, listing) = post(&app, "/api/v1/catalog", &token_for(steward), PUBLISH_BODY).await;
    assert_eq!(status, StatusCode::OK, "publish: {listing}");
    let listing_id = listing["listing_id"]
        .as_str()
        .expect("listing id")
        .to_owned();

    // Catalog: researcher browses.
    let (status, catalog) =
        call(&app, "GET", "/api/v1/catalog", &token_for(researcher), None).await;
    assert_eq!(status, StatusCode::OK, "catalog: {catalog}");
    assert_eq!(catalog["listings"].as_array().expect("listings").len(), 1);

    // Request: researcher asks for access; steward sees it.
    let (status, request) = post(
        &app,
        &format!("/api/v1/catalog/{listing_id}/request"),
        &token_for(researcher),
        r#"{"note":"synthetic test"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "request: {request}");
    let request_id = request["request_id"]
        .as_str()
        .expect("request id")
        .to_owned();

    let (status, inbox) = call(
        &app,
        "GET",
        "/api/v1/research/requests",
        &token_for(steward),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "requests: {inbox}");

    // Approve: mints the grant with the listing's budget.
    let (status, resolved) = post(
        &app,
        &format!("/api/v1/research/requests/{request_id}/approve"),
        &token_for(steward),
        "{}",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "approve: {resolved}");
    assert_eq!(resolved["grant"]["budget"]["limit"], 25);
    let grant_id = resolved["grant"]["grant_id"]
        .as_str()
        .expect("grant id")
        .to_owned();

    // POST /api/v1/grants: a direct grant works too.
    let (status, grant) = post(
        &app,
        "/api/v1/grants",
        &token_for(steward),
        &format!(r#"{{"researcher_tenant":"{other_researcher}","connector":"health"}}"#),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "grant: {grant}");

    // Queries need released keys: still 503, even with an active grant.
    let (status, body) = post(
        &app,
        "/api/v1/research/query",
        &token_for(researcher),
        &format!(
            r#"{{"steward_tenant":"{steward}","connector":"health","sql":"SELECT condition, COUNT(*) AS n FROM health GROUP BY condition"}}"#
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "research query: {body}"
    );
    assert_eq!(body["error"], "confidential query not available");

    let (status, body) = post(
        &app,
        "/api/v1/query",
        &token_for(steward),
        r#"{"connector":"health","sql":"SELECT COUNT(*) AS n FROM health"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "query: {body}");
    assert_eq!(body["error"], "confidential query not available");

    // The refused research query charged nothing.
    let (status, budget) = call(
        &app,
        "GET",
        &format!("/api/v1/grants/{grant_id}/budget"),
        &token_for(researcher),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "budget: {budget}");
    assert_eq!(budget["spent"], 0);
}

#[tokio::test]
async fn research_routes_refuse_without_a_research_layer() {
    // `app_state` leaves `research` (and `query`) unset.
    let app = build_app(common::app_state(
        SECRET,
        Arc::new(ObjectStoreVault::new_in_memory()),
    ));
    let token = token_for(TenantId::generate());
    // Any well-formed ids: the handlers refuse before looking anything up.
    let some_id = TenantId::generate();
    let other = TenantId::generate();
    let grant_body = format!(r#"{{"researcher_tenant":"{other}","connector":"health"}}"#);

    // Every route that needs the research service: the catalog, access
    // requests, and grants with their budgets.
    let cases: [(&str, String, Option<&str>); 12] = [
        ("GET", "/api/v1/catalog".to_owned(), None),
        ("POST", "/api/v1/catalog".to_owned(), Some(PUBLISH_BODY)),
        ("DELETE", format!("/api/v1/catalog/{some_id}"), None),
        (
            "POST",
            format!("/api/v1/catalog/{some_id}/request"),
            Some("{}"),
        ),
        ("GET", "/api/v1/research/requests".to_owned(), None),
        (
            "POST",
            format!("/api/v1/research/requests/{some_id}/approve"),
            Some("{}"),
        ),
        (
            "POST",
            format!("/api/v1/research/requests/{some_id}/deny"),
            None,
        ),
        ("GET", "/api/v1/grants".to_owned(), None),
        (
            "POST",
            "/api/v1/grants".to_owned(),
            Some(grant_body.as_str()),
        ),
        ("DELETE", format!("/api/v1/grants/{some_id}"), None),
        ("GET", format!("/api/v1/grants/{some_id}/budget"), None),
        (
            "POST",
            format!("/api/v1/grants/{some_id}/budget"),
            Some(r#"{"additional":1}"#),
        ),
    ];
    for (method, uri, body) in cases {
        let (status, json) = call(&app, method, &uri, &token, body).await;
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "{method} {uri}: {json}"
        );
        assert_eq!(
            json["error"], "research access not configured",
            "{method} {uri}"
        );
    }
}
