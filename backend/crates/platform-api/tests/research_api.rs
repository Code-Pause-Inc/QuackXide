//! Research-access integration tests: a steward grants a researcher
//! aggregate access to a sealed dataset; the researcher runs
//! disclosure-controlled queries (small cohorts suppressed); ungranted and
//! revoked access is refused; row-level egress is blocked; and an approval
//! that fails part-way converges when the steward retries it.
mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;

use axum::Router;
use axum::http::StatusCode;
use platform_api::dev::DevResearchStack;
use platform_api::research::ResearchStores;
use platform_api::{AppState, build_app};
use platform_core::{ConnectorSlug, TenantId, ZkMode};

use platform_crypto::TenantKeypair;
use platform_enclave::{AttestationProvider, DevAttestation};
use platform_tenancy::{
    BudgetError, BudgetLedger, BudgetState, DatasetGrant, GrantRegistry, InMemoryBudgetLedger,
    InMemoryGrantRegistry, TenancyError,
};
use quackxide_engine::EngineSettings;

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

/// As [`research_app`], with the query gate's attestation. The wiring is
/// `platform_api::dev`, the same as the `devstack` server's.
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
// ── Approval after a partial failure ──

/// Fails the first call and passes every later one. The error is
/// `TenancyError::NotFound`, that enum's only variant; the API answers any
/// registry error with 502.
fn fail_once(failed: &AtomicBool) -> Result<(), TenancyError> {
    if failed.swap(true, Ordering::SeqCst) {
        Ok(())
    } else {
        Err(TenancyError::NotFound)
    }
}

/// The in-memory budget ledger, except that the first `open` fails.
#[derive(Default)]
struct FailFirstOpen {
    inner: InMemoryBudgetLedger,
    failed: AtomicBool,
}

#[async_trait]
impl BudgetLedger for FailFirstOpen {
    async fn open(&self, grant_id: &str, limit: u64) -> Result<BudgetState, TenancyError> {
        fail_once(&self.failed)?;
        self.inner.open(grant_id, limit).await
    }

    async fn charge(&self, grant_id: &str, cost: u64) -> Result<BudgetState, BudgetError> {
        self.inner.charge(grant_id, cost).await
    }

    async fn top_up(&self, grant_id: &str, additional: u64) -> Result<BudgetState, BudgetError> {
        self.inner.top_up(grant_id, additional).await
    }

    async fn state(&self, grant_id: &str) -> Result<Option<BudgetState>, TenancyError> {
        self.inner.state(grant_id).await
    }
}

/// The in-memory grant registry, except that the first `create` fails.
#[derive(Default)]
struct FailFirstCreate {
    inner: InMemoryGrantRegistry,
    failed: AtomicBool,
}

#[async_trait]
impl GrantRegistry for FailFirstCreate {
    async fn create(
        &self,
        steward: TenantId,
        researcher: TenantId,
        connector: &str,
    ) -> Result<DatasetGrant, TenancyError> {
        fail_once(&self.failed)?;
        self.inner.create(steward, researcher, connector).await
    }

    async fn find_active(
        &self,
        researcher: TenantId,
        steward: TenantId,
        connector: &str,
    ) -> Result<Option<DatasetGrant>, TenancyError> {
        self.inner.find_active(researcher, steward, connector).await
    }

    async fn revoke(
        &self,
        steward: TenantId,
        grant_id: &str,
    ) -> Result<Option<DatasetGrant>, TenancyError> {
        self.inner.revoke(steward, grant_id).await
    }

    async fn list_for(&self, tenant: TenantId) -> Result<Vec<DatasetGrant>, TenancyError> {
        self.inner.list_for(tenant).await
    }
}

/// As [`research_app`], with `stores` in place of the in-memory research
/// stores, so a test can make one registry call fail.
async fn research_app_with_stores(
    steward: TenantId,
    steward_keypair: TenantKeypair,
    stores: ResearchStores,
) -> Router {
    let connector = ConnectorSlug::new("health").expect("slug");
    let cohorts = common::cohorts_parquet();
    let mut stack = DevResearchStack::new();
    stack
        .commit_snapshot(steward, steward_keypair, &connector, "cohorts", &cohorts)
        .await
        .expect("commit");
    let vault = stack.vault();
    let settings = EngineSettings {
        zk: ZkMode::Disabled, // research mode forces ZK on regardless
        max_concurrent_queries: 4,
    };
    // `with_research` replaces the in-memory stores `query_service` installed.
    let service = stack
        .query_service(settings, 5, 100)
        .with_research(stores, 5, 100);
    build_app(AppState {
        query: Some(Arc::new(service)),
        ..common::app_state(SECRET, vault)
    })
}

const PUBLISH_BODY: &str = r#"{
    "connector": "health",
    "title": "De-identified respiratory cohort extracts",
    "license_fee_cents": 120000,
    "compute_rate_cents": 40,
    "grant_budget": 25
}"#;

/// Publishes the steward's `health` listing (25 query units on approval)
/// and files a request for it as `researcher`. Returns the request id.
async fn pending_request(app: &Router, steward: TenantId, researcher: TenantId) -> String {
    let (status, listing) = post(app, "/api/v1/catalog", &token_for(steward), PUBLISH_BODY).await;
    assert_eq!(status, StatusCode::OK, "publish: {listing}");
    let listing_id = listing["listing_id"].as_str().expect("id");
    let (status, request) = post(
        app,
        &format!("/api/v1/catalog/{listing_id}/request"),
        &token_for(researcher),
        "{}",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "request: {request}");
    request["request_id"].as_str().expect("id").to_owned()
}

/// The researcher's aggregate query over the steward's `health` dataset.
async fn research_query(
    app: &Router,
    researcher: TenantId,
    steward: TenantId,
) -> (StatusCode, serde_json::Value) {
    post(
        app,
        "/api/v1/research/query",
        &token_for(researcher),
        &format!(r#"{{"steward_tenant":"{steward}","connector":"health","sql":"{AGG_SQL}"}}"#),
    )
    .await
}

#[tokio::test]
async fn approval_retried_after_a_budget_failure_converges() {
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let stores = ResearchStores {
        budgets: Arc::new(FailFirstOpen::default()),
        ..ResearchStores::in_memory()
    };
    let app = research_app_with_stores(steward, TenantKeypair::generate(), stores).await;
    let stoken = token_for(steward);
    let request_id = pending_request(&app, steward, researcher).await;
    let approve = format!("/api/v1/research/requests/{request_id}/approve");

    // `create` succeeds and `open` fails: the request is Approved and the
    // grant exists, but with no budget entry it serves no queries.
    let (status, _) = post(&app, &approve, &stoken, "{}").await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    let (_, inbox) = call(&app, "GET", "/api/v1/research/requests", &stoken, None).await;
    assert_eq!(inbox["requests"][0]["status"], "approved");
    let (status, _) = research_query(&app, researcher, steward).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);

    // The steward's retry re-runs the grant and budget steps and converges.
    let (status, resolved) = post(&app, &approve, &stoken, "{}").await;
    assert_eq!(status, StatusCode::OK, "retry: {resolved}");
    assert_eq!(resolved["request"]["status"], "approved");
    assert_eq!(resolved["grant"]["revoked"], false);
    assert_eq!(resolved["grant"]["budget"]["limit"], 25);
    let (status, body) = research_query(&app, researcher, steward).await;
    assert_eq!(status, StatusCode::OK, "query: {body}");
    assert_eq!(body["budget_remaining"], 24);
}

#[tokio::test]
async fn deny_after_a_failed_approval_is_refused() {
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let stores = ResearchStores {
        grants: Arc::new(FailFirstCreate::default()),
        ..ResearchStores::in_memory()
    };
    let app = research_app_with_stores(steward, TenantKeypair::generate(), stores).await;
    let stoken = token_for(steward);
    let request_id = pending_request(&app, steward, researcher).await;
    let uri = |action: &str| format!("/api/v1/research/requests/{request_id}/{action}");

    // `create` fails: the request is Approved and no grant exists.
    let (status, _) = post(&app, &uri("approve"), &stoken, "{}").await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);

    // An Approved request cannot be denied. No grant is active, so the
    // researcher stays locked out.
    let (status, _) = post(&app, &uri("deny"), &stoken, "{}").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (_, grants) = call(&app, "GET", "/api/v1/grants", &stoken, None).await;
    assert!(
        grants["grants"].as_array().expect("grants").is_empty(),
        "grants: {grants}"
    );
    let (status, _) = research_query(&app, researcher, steward).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // The steward's retry mints the grant.
    let (status, resolved) = post(&app, &uri("approve"), &stoken, "{}").await;
    assert_eq!(status, StatusCode::OK, "retry: {resolved}");
    assert_eq!(resolved["grant"]["revoked"], false);
    let (status, _) = research_query(&app, researcher, steward).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn approval_retry_by_a_non_steward_is_404() {
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let outsider = TenantId::generate();
    let app = research_app(steward, TenantKeypair::generate()).await;
    let request_id = pending_request(&app, steward, researcher).await;
    let approve = format!("/api/v1/research/requests/{request_id}/approve");
    let (status, _) = post(&app, &approve, &token_for(steward), "{}").await;
    assert_eq!(status, StatusCode::OK);

    // Approved now: only the request's steward can retry. The researcher,
    // any other tenant and an unknown id all get the same 404.
    for who in [researcher, outsider] {
        let (status, _) = post(&app, &approve, &token_for(who), "{}").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
    let unknown_id = TenantId::generate();
    let unknown = format!("/api/v1/research/requests/{unknown_id}/approve");
    let (status, _) = post(&app, &unknown, &token_for(steward), "{}").await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // The steward's own retry is idempotent.
    let (status, _) = post(&app, &approve, &token_for(steward), "{}").await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn approving_a_denied_request_is_404() {
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let app = research_app(steward, TenantKeypair::generate()).await;
    let request_id = pending_request(&app, steward, researcher).await;
    let uri = |action: &str| format!("/api/v1/research/requests/{request_id}/{action}");

    let (status, _) = post(&app, &uri("deny"), &token_for(steward), "{}").await;
    assert_eq!(status, StatusCode::OK);

    // Denied is terminal: the approval finds nothing to act on and mints
    // nothing.
    let (status, _) = post(&app, &uri("approve"), &token_for(steward), "{}").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = research_query(&app, researcher, steward).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}
