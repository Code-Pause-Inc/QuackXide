//! Research-access integration tests: a steward grants a researcher
//! aggregate access to a sealed dataset; the researcher runs
//! disclosure-controlled queries (small cohorts suppressed); ungranted and
//! revoked access is refused; and row-level egress is blocked.

mod common;

use std::sync::Arc;

use axum::Router;
use axum::http::StatusCode;
use platform_core::TenantId;
use platform_crypto::TenantKeypair;
use platform_enclave::{AttestationProvider, DevAttestation};

use common::{call, dev_attestation, post};

const SECRET: &str = "research-itest-secret";

fn token_for(tenant: TenantId) -> String {
    common::token_for(SECRET, tenant)
}

/// Build an app where `steward` has a sealed `health` connector dataset,
/// queryable in research mode (cohort threshold k=5).
async fn research_app(steward: TenantId, steward_keypair: TenantKeypair) -> Router {
    research_app_with_attestation(steward, steward_keypair, dev_attestation(), false).await
}

/// As [`research_app`], with the query gate's attestation.
async fn research_app_with_attestation(
    steward: TenantId,
    steward_keypair: TenantKeypair,
    attestation: Arc<dyn AttestationProvider>,
    require_attestation: bool,
) -> Router {
    common::research_app(
        SECRET,
        steward,
        steward_keypair,
        attestation,
        require_attestation,
    )
    .await
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
    assert_eq!(body["tee_platform"], "development");
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
async fn refused_attestation_charges_no_budget() {
    // No evidence at all, then development evidence where SEV-SNP is required.
    let providers: [Arc<dyn AttestationProvider>; 2] = [
        Arc::new(DevAttestation::strict()),
        Arc::new(DevAttestation::allow_insecure_dev()),
    ];
    for provider in providers {
        let steward = TenantId::generate();
        let researcher = TenantId::generate();
        let app =
            research_app_with_attestation(steward, TenantKeypair::generate(), provider, true).await;

        // The grant check runs before the gate, so the refusal needs a grant.
        let (status, grant) = post(
            &app,
            "/api/v1/grants",
            &token_for(steward),
            &format!(r#"{{"researcher_tenant":"{researcher}","connector":"health"}}"#),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "grant: {grant}");
        let grant_id = grant["grant_id"].as_str().expect("grant id").to_owned();

        let research_body =
            format!(r#"{{"steward_tenant":"{steward}","connector":"health","sql":"{AGG_SQL}"}}"#);
        let (status, body) = post(
            &app,
            "/api/v1/research/query",
            &token_for(researcher),
            &research_body,
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "body: {body}");
        assert_eq!(body["error"], "enclave attestation unavailable");

        let (status, budget) = call(
            &app,
            "GET",
            &format!("/api/v1/grants/{grant_id}/budget"),
            &token_for(researcher),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(budget["spent"], 0, "budget: {budget}");
    }
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

    // Statements other than a read-only query → 422, and nothing is written.
    let target = std::env::temp_dir().join(format!("qx-copy-research-{}.csv", std::process::id()));
    let sql = format!(
        "COPY (SELECT * FROM health) TO '{}' STORED AS CSV",
        target.display()
    );
    let body = serde_json::json!({ "steward_tenant": steward.to_string(), "connector": "health", "sql": sql });
    let (status, _) = post(&app, "/api/v1/research/query", &rtoken, &body.to_string()).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(!target.exists(), "COPY wrote decrypted rows to disk");

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
