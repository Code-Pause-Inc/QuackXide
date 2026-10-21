//! Dataset catalog: a steward publishes a priced listing; a researcher
//! browses, requests access, and after approval runs disclosure-controlled
//! queries against the included budget. Also covers denial, withdrawal,
//! scoping, and input bounds.

mod common;

use axum::Router;
use axum::http::StatusCode;
use platform_core::TenantId;
use platform_crypto::TenantKeypair;

use common::{call, dev_attestation, post};

const SECRET: &str = "catalog-itest-secret";

fn token_for(tenant: TenantId) -> String {
    common::token_for(SECRET, tenant)
}

/// App where `steward` has a sealed `health` dataset and the research layer
/// (catalog + grants + budgets, k=5, default budget 100) is enabled.
async fn marketplace_app(steward: TenantId, steward_keypair: TenantKeypair) -> Router {
    common::research_app(SECRET, steward, steward_keypair, dev_attestation(), false).await
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
