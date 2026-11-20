//! Research-access integration tests: a steward grants a researcher
//! aggregate access to a sealed dataset, seeded directly or uploaded
//! through the steward upload route; the researcher runs
//! disclosure-controlled queries (small cohorts suppressed); ungranted and
//! revoked access, and access to another steward's or connector's dataset,
//! is refused with the same 403 whether or not the dataset exists; unknown
//! and foreign grant ids get the same 404; re-granting never resets spend;
//! row-level egress is blocked; an approval that fails part-way converges
//! when the steward retries it; and a retry never re-activates a grant the
//! steward has revoked, even when the revoke lands while the retry runs.
mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use async_trait::async_trait;

use axum::Router;
use axum::http::{HeaderMap, StatusCode};
use platform_api::dev::DevResearchStack;
use platform_api::research::{ResearchService, ResearchStores};
use platform_api::{AppState, build_app};
use platform_core::{ConnectorSlug, TenantId, ZkMode};

use platform_config::PlatformConfig;
use platform_crypto::{EnvelopeSuite, TenantKeypair};
use platform_enclave::{AttestationProvider, DevAttestation};
use platform_tenancy::{
    BudgetError, BudgetLedger, BudgetState, DatasetGrant, GrantOutcome, GrantRegistry,
    InMemoryBudgetLedger, InMemoryGrantRegistry, TenancyError,
};
use quackxide_engine::{EngineSettings, QueryLimits};

use common::{assert_event, call, dev_attestation, grant_body, post};

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
    let app = research_app(
        steward,
        TenantKeypair::generate(platform_crypto::EnvelopeSuite::CURRENT),
    )
    .await;

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

/// The steward uploads a cohort sealed in `suite` under `config`, and a
/// granted researcher queries it.
async fn researcher_queries_an_uploaded_dataset(suite: EnvelopeSuite, config: PlatformConfig) {
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let keypair = TenantKeypair::generate(suite);
    let key = keypair.public_key();
    let app = common::upload_research_app_with_config(
        SECRET,
        config,
        vec![(steward, keypair)],
        Arc::new(platform_storage::ObjectStoreVault::new_in_memory()),
    );

    // The steward seals the cohort and uploads it; nothing else seeds the
    // dataset.
    let upload = common::cohorts_upload(steward, &key, "upload_cohorts", None);
    let (status, body) = common::put_upload(
        &app,
        Some(&token_for(steward)),
        "upload_cohorts",
        upload.body,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "upload: {body}");

    let (status, grant) = post(
        &app,
        "/api/v1/grants",
        &token_for(steward),
        &format!(r#"{{"researcher_tenant":"{researcher}","connector":"upload_cohorts"}}"#),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "grant: {grant}");

    let sql = "SELECT condition, COUNT(*) AS n FROM upload_cohorts GROUP BY condition";
    let (status, body) = post(
        &app,
        "/api/v1/research/query",
        &token_for(researcher),
        &format!(r#"{{"steward_tenant":"{steward}","connector":"upload_cohorts","sql":"{sql}"}}"#),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "query: {body}");
    assert_eq!(body["mode"], "research");
    assert_eq!(body["suppressed_rows"], 1);
    let rows = body["rows"].as_array().expect("rows");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["condition"], "flu");
    assert_eq!(rows[0]["n"], 6);
    assert_eq!(body["budget_remaining"], 99);
}

#[tokio::test]
async fn granted_researcher_queries_a_dataset_uploaded_through_the_route() {
    researcher_queries_an_uploaded_dataset(EnvelopeSuite::CURRENT, common::default_config()).await;
}

/// The browser seals `HPK1` until P36, which only development accepts.
#[tokio::test]
async fn granted_researcher_queries_an_hpk1_dataset_uploaded_in_development() {
    researcher_queries_an_uploaded_dataset(EnvelopeSuite::Hpk1, common::development_config()).await;
}

/// Key release is `HPK2`-only: an `HPK1` key registered for it would make
/// every query fail after charging its budget, so building the service fails.
#[test]
#[should_panic(expected = "key release is HPK2-only")]
fn the_release_path_refuses_a_stack_holding_an_hpk1_key() {
    let mut stack = DevResearchStack::new();
    stack.register_key(
        TenantId::generate(),
        TenantKeypair::generate(EnvelopeSuite::Hpk1),
    );
    let vault = stack.vault();
    let research = Arc::new(ResearchService::new(
        ResearchStores::in_memory(),
        vault,
        5,
        100,
    ));
    let settings = EngineSettings {
        zk: ZkMode::Disabled,
        max_concurrent_queries: 4,
        limits: QueryLimits::default(),
    };
    stack.query_service(settings, research);
}

#[tokio::test]
async fn budget_exhausts_and_steward_top_up_restores_access() {
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let app = research_app(
        steward,
        TenantKeypair::generate(platform_crypto::EnvelopeSuite::CURRENT),
    )
    .await;

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
        let app = research_app_with_attestation(
            steward,
            TenantKeypair::generate(platform_crypto::EnvelopeSuite::CURRENT),
            provider,
            true,
        )
        .await;

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

/// A snapshot sealed before the steward's key moved to `HPK2` (record and
/// envelopes `HPK1`) can never open: the query is refused before its budget
/// is charged.
#[tokio::test]
async fn a_snapshot_the_key_cannot_open_charges_no_budget() {
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let vault: Arc<dyn platform_storage::VaultStore> =
        Arc::new(platform_storage::ObjectStoreVault::new_in_memory());
    let connector = ConnectorSlug::new("health").expect("slug");
    DevResearchStack::with_vault(vault.clone())
        .commit_snapshot(
            steward,
            TenantKeypair::generate(EnvelopeSuite::Hpk1),
            &connector,
            "cohorts",
            &common::cohorts_parquet(),
        )
        .await
        .expect("commit");
    let app = common::upload_research_app(
        SECRET,
        vec![(steward, TenantKeypair::generate(EnvelopeSuite::Hpk2))],
        vault,
    );

    let (status, grant) = post(
        &app,
        "/api/v1/grants",
        &token_for(steward),
        &format!(r#"{{"researcher_tenant":"{researcher}","connector":"health"}}"#),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "grant: {grant}");
    let grant_id = grant["grant_id"].as_str().expect("grant id").to_owned();

    let (status, body) = post(
        &app,
        "/api/v1/research/query",
        &token_for(researcher),
        &format!(r#"{{"steward_tenant":"{steward}","connector":"health","sql":"{AGG_SQL}"}}"#),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "body: {body}");

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

#[tokio::test]
async fn rejected_queries_still_consume_budget() {
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let app = research_app(
        steward,
        TenantKeypair::generate(platform_crypto::EnvelopeSuite::CURRENT),
    )
    .await;

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
    let app = research_app(
        steward,
        TenantKeypair::generate(platform_crypto::EnvelopeSuite::CURRENT),
    )
    .await;

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
    let app = research_app(
        steward,
        TenantKeypair::generate(platform_crypto::EnvelopeSuite::CURRENT),
    )
    .await;

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
    let app = research_app(
        steward,
        TenantKeypair::generate(platform_crypto::EnvelopeSuite::CURRENT),
    )
    .await;

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
    let app = research_app(
        steward,
        TenantKeypair::generate(platform_crypto::EnvelopeSuite::CURRENT),
    )
    .await;
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

/// A query whose expression fails only on the rare cohort's row gets the
/// same refusal whether or not that row matches (ADR 0011).
#[tokio::test]
async fn error_probe_gets_the_same_refusal_whatever_the_data() {
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let app = research_app(
        steward,
        TenantKeypair::generate(platform_crypto::EnvelopeSuite::CURRENT),
    )
    .await;
    post(
        &app,
        "/api/v1/grants",
        &token_for(steward),
        &format!(r#"{{"researcher_tenant":"{researcher}","connector":"health"}}"#),
    )
    .await;
    let rtoken = token_for(researcher);

    for threshold in [60, 70] {
        let sql = format!(
            "SELECT condition, COUNT(*) AS n FROM health WHERE age / (CASE WHEN condition = 'rare_disease' AND age > {threshold} THEN 0 ELSE 1 END) > 0 GROUP BY condition"
        );
        let body = serde_json::json!({ "steward_tenant": steward.to_string(), "connector": "health", "sql": sql });
        let (status, _) = post(&app, "/api/v1/research/query", &rtoken, &body.to_string()).await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "threshold {threshold}"
        );
    }
}

#[tokio::test]
async fn cannot_grant_to_self() {
    let steward = TenantId::generate();
    let app = research_app(
        steward,
        TenantKeypair::generate(platform_crypto::EnvelopeSuite::CURRENT),
    )
    .await;
    let (status, _) = post(
        &app,
        "/api/v1/grants",
        &token_for(steward),
        &format!(r#"{{"researcher_tenant":"{steward}","connector":"health"}}"#),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn re_granting_an_active_grant_is_refused_and_keeps_its_budget() {
    let capture = platform_telemetry::capture::AuditCapture::install();
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let app = research_app(steward, TenantKeypair::generate()).await;
    let stoken = token_for(steward);

    let (status, grant) = post(&app, "/api/v1/grants", &stoken, &grant_body(researcher, 28)).await;
    assert_eq!(status, StatusCode::OK, "grant: {grant}");
    let grant_id = grant["grant_id"].as_str().expect("grant id");

    // A second grant would silently keep the old budget: it is refused, and
    // the steward tops the grant up instead.
    let (status, body) = post(&app, "/api/v1/grants", &stoken, &grant_body(researcher, 50)).await;
    assert_eq!(status, StatusCode::CONFLICT, "re-grant: {body}");
    assert_eq!(body["error"], ALREADY_GRANTED);
    let budget = budget_of(&app, steward, grant_id).await;
    assert_eq!(budget["limit"], 28, "{budget}");
    assert_event(
        &capture,
        "tenant.provisioned",
        "denied",
        &format!(
            "grant refused researcher={researcher} connector=health grant={grant_id} reason=already_granted"
        ),
    );
}

#[tokio::test]
async fn re_granting_a_revoked_grant_adds_its_budget_once_per_revoke() {
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let app = research_app(steward, TenantKeypair::generate()).await;
    let stoken = token_for(steward);
    let (_, grant) = post(&app, "/api/v1/grants", &stoken, &grant_body(researcher, 28)).await;
    let grant_id = grant["grant_id"].as_str().expect("grant id");
    let budget_uri = format!("/api/v1/grants/{grant_id}/budget");

    for (added, limit) in [(50, 78), (10, 88)] {
        revoke(&app, steward, grant_id).await;
        // Re-granting re-activates the same grant and adds the new budget.
        let body = grant_body(researcher, added);
        let (status, regrant) = post(&app, "/api/v1/grants", &stoken, &body).await;
        assert_eq!(status, StatusCode::OK, "re-grant: {regrant}");
        assert_eq!(regrant["grant_id"], grant_id);
        assert_eq!(regrant["revoked"], false);
        assert_eq!(regrant["budget"]["limit"], limit, "{regrant}");
        // A retry finds the grant active: refused, and it adds nothing.
        let (status, _) = post(&app, "/api/v1/grants", &stoken, &body).await;
        assert_eq!(status, StatusCode::CONFLICT);
        let (_, budget) = call(&app, "GET", &budget_uri, &stoken, None).await;
        assert_eq!(budget["limit"], limit, "{budget}");
    }
}

#[tokio::test]
async fn direct_grant_retried_after_a_budget_failure_opens_its_budget() {
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let stores = ResearchStores {
        budgets: Arc::new(TestLedger {
            fail_open: armed(),
            ..TestLedger::default()
        }),
        ..ResearchStores::in_memory()
    };
    let app = research_app_with_stores(steward, TenantKeypair::generate(), stores).await;
    let stoken = token_for(steward);
    let body = grant_body(researcher, 28);
    let (status, _) = post(&app, "/api/v1/grants", &stoken, &body).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    // The grant exists without a budget, so the retry funds it.
    let (status, grant) = post(&app, "/api/v1/grants", &stoken, &body).await;
    assert_eq!(status, StatusCode::OK, "retry: {grant}");
    assert_eq!(grant["budget"]["limit"], 28, "{grant}");
}

/// A failed budget read is a 502 on every grant path, never read as "no
/// budget": a direct grant of a funded grant would then reopen it with its
/// old limit and drop the new amount with a 200, and a re-grant would do the
/// same to a re-activated grant.
#[tokio::test]
async fn a_failed_budget_read_fails_a_direct_grant_of_a_funded_grant() {
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let ledger = Arc::new(TestLedger::default());
    let stores = ResearchStores {
        budgets: ledger.clone(),
        ..ResearchStores::in_memory()
    };
    let app = research_app_with_stores(steward, TenantKeypair::generate(), stores).await;
    let stoken = token_for(steward);
    let (status, grant) = post(&app, "/api/v1/grants", &stoken, &grant_body(researcher, 28)).await;
    assert_eq!(status, StatusCode::OK, "grant: {grant}");
    let grant_id = grant["grant_id"].as_str().expect("grant id");

    ledger.fail_state.store(true, Ordering::SeqCst);
    let body = grant_body(researcher, 50);
    let (status, answer) = post(&app, "/api/v1/grants", &stoken, &body).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{answer}");
    let (status, _) = post(&app, "/api/v1/grants", &stoken, &body).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(budget_of(&app, steward, grant_id).await["limit"], 28);
}

#[tokio::test]
async fn a_failed_budget_read_fails_a_re_grant_after_re_activating() {
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let ledger = Arc::new(TestLedger::default());
    let stores = ResearchStores {
        budgets: ledger.clone(),
        ..ResearchStores::in_memory()
    };
    let app = research_app_with_stores(steward, TenantKeypair::generate(), stores).await;
    let grant_id = grant_and_revoke(&app, steward, researcher, 28).await;

    ledger.fail_state.store(true, Ordering::SeqCst);
    let body = grant_body(researcher, 50);
    let (status, answer) = post(&app, "/api/v1/grants", &token_for(steward), &body).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{answer}");
    // Re-activated (and audited) with its old budget, as when the top-up
    // itself fails.
    assert_eq!(budget_of(&app, steward, &grant_id).await["limit"], 28);
    let (status, _) = research_query(&app, researcher, steward).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn a_failed_budget_read_fails_an_approval_and_its_retry_converges() {
    let capture = platform_telemetry::capture::AuditCapture::install();
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let ledger = Arc::new(TestLedger::default());
    let (app, grant_id, request_id) =
        app_with_a_grant_and_a_request(steward, researcher, ledger.clone()).await;
    let stoken = token_for(steward);
    let approve = format!("/api/v1/research/requests/{request_id}/approve");

    ledger.fail_state.store(true, Ordering::SeqCst);
    let (status, answer) = post(&app, &approve, &stoken, "{}").await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{answer}");
    let (status, retry) = post(&app, &approve, &stoken, "{}").await;
    assert_eq!(status, StatusCode::OK, "retry: {retry}");
    assert_eq!(retry["grant"]["budget"]["limit"], 53, "{retry}");
    assert_eq!(
        budget_events(&capture),
        vec![format!("top_up grant={grant_id} added=25 limit=53")]
    );
}

/// What a refused direct grant tells the steward.
const ALREADY_GRANTED: &str =
    "grant already exists; raise its budget with POST /api/v1/grants/{grant_id}/budget";

/// Grant 28, revoke, then re-grant 50, whose first attempt fails before it
/// re-activates the grant: nothing was added, so the retry adds 50 once.
/// `revoke_between` revokes the still revoked grant again between the
/// attempts, as a stale tab would.
async fn re_grant_converges_after_a_failure(revoke_between: bool) {
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let registry = Arc::new(TestRegistry::default());
    let stores = ResearchStores {
        grants: registry.clone(),
        ..ResearchStores::in_memory()
    };
    let app = research_app_with_stores(steward, TenantKeypair::generate(), stores).await;
    let stoken = token_for(steward);
    let grant_id = &grant_and_revoke(&app, steward, researcher, 28).await;

    registry.fail_create.store(true, Ordering::SeqCst);
    let body = grant_body(researcher, 50);
    let (status, _) = post(&app, "/api/v1/grants", &stoken, &body).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    // The failed attempt left the grant revoked and its budget as it was.
    let (status, _) = research_query(&app, researcher, steward).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let budget = budget_of(&app, steward, grant_id).await;
    assert_eq!(budget["limit"], 28, "{budget}");
    if revoke_between {
        revoke(&app, steward, grant_id).await;
    }
    let (status, regrant) = post(&app, "/api/v1/grants", &stoken, &body).await;
    assert_eq!(status, StatusCode::OK, "retry: {regrant}");
    assert_eq!(regrant["revoked"], false);
    assert_eq!(regrant["budget"]["limit"], 78, "{regrant}");
}

#[tokio::test]
async fn re_grant_retried_after_a_failed_reactivation_adds_its_budget_once() {
    re_grant_converges_after_a_failure(false).await;
}

#[tokio::test]
async fn a_revoke_between_a_failed_re_grant_and_its_retry_adds_nothing_more() {
    re_grant_converges_after_a_failure(true).await;
}

#[tokio::test]
async fn re_grant_whose_funding_fails_leaves_the_grant_active_and_its_retry_is_refused() {
    let capture = platform_telemetry::capture::AuditCapture::install();
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let stores = ResearchStores {
        budgets: Arc::new(TestLedger {
            fail_top_up: armed(),
            ..TestLedger::default()
        }),
        ..ResearchStores::in_memory()
    };
    let app = research_app_with_stores(steward, TenantKeypair::generate(), stores).await;
    let stoken = token_for(steward);
    let grant_id = &grant_and_revoke(&app, steward, researcher, 28).await;

    // The grant is re-activated first, so the failed top-up leaves it active
    // with its old budget, and the re-activation is audited.
    let body = grant_body(researcher, 50);
    let (status, _) = post(&app, "/api/v1/grants", &stoken, &body).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_event(
        &capture,
        "tenant.provisioned",
        "ok",
        &format!("reactivated researcher={researcher} connector=health grant={grant_id}"),
    );
    let (status, answer) = research_query(&app, researcher, steward).await;
    assert_eq!(status, StatusCode::OK, "query: {answer}");
    assert_eq!(answer["budget_remaining"], 27);

    // The retry is refused, not applied a second time, and the steward
    // raises the budget as the refusal says.
    let (status, refused) = post(&app, "/api/v1/grants", &stoken, &body).await;
    assert_eq!(status, StatusCode::CONFLICT, "retry: {refused}");
    assert_eq!(refused["error"], ALREADY_GRANTED);
    let budget_uri = format!("/api/v1/grants/{grant_id}/budget");
    let (status, topped) = post(&app, &budget_uri, &stoken, r#"{"additional":50}"#).await;
    assert_eq!(status, StatusCode::OK, "top-up: {topped}");
    assert_eq!(topped["limit"], 78, "{topped}");
}

#[tokio::test]
async fn a_re_grant_after_a_failed_one_adds_its_own_amount() {
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let stores = ResearchStores {
        grants: Arc::new(TestRegistry {
            fail_create: armed(),
            ..TestRegistry::default()
        }),
        ..ResearchStores::in_memory()
    };
    let app = research_app_with_stores(steward, TenantKeypair::generate(), stores).await;
    let stoken = token_for(steward);
    grant_and_revoke(&app, steward, researcher, 28).await;

    let (status, _) = post(&app, "/api/v1/grants", &stoken, &grant_body(researcher, 50)).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    // A different amount on the retry is its own amount, not the failed 50.
    let (status, regrant) =
        post(&app, "/api/v1/grants", &stoken, &grant_body(researcher, 10)).await;
    assert_eq!(status, StatusCode::OK, "retry: {regrant}");
    assert_eq!(regrant["budget"]["limit"], 38, "{regrant}");
}

/// An approval re-activates a revoked grant before funding it, so a failed
/// funding leaves access restored: the re-activation is audited.
#[tokio::test]
async fn an_approval_that_re_activates_a_grant_audits_it_even_if_funding_fails() {
    let capture = platform_telemetry::capture::AuditCapture::install();
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let stores = ResearchStores {
        budgets: Arc::new(TestLedger {
            fail_top_up_once: armed(),
            ..TestLedger::default()
        }),
        ..ResearchStores::in_memory()
    };
    let app = research_app_with_stores(steward, TenantKeypair::generate(), stores).await;
    let grant_id = grant_and_revoke(&app, steward, researcher, 28).await;

    let request_id = pending_request(&app, steward, researcher).await;
    let approve = format!("/api/v1/research/requests/{request_id}/approve");
    let (status, _) = post(&app, &approve, &token_for(steward), "{}").await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    let (status, answer) = research_query(&app, researcher, steward).await;
    assert_eq!(status, StatusCode::OK, "query: {answer}");
    assert_event(
        &capture,
        "tenant.provisioned",
        "ok",
        &format!("reactivated researcher={researcher} connector=health grant={grant_id}"),
    );
}

/// A re-grant that names no budget restores the grant with the budget it
/// had: it adds nothing the steward did not name.
#[tokio::test]
async fn a_re_grant_without_a_budget_restores_the_old_one() {
    let capture = platform_telemetry::capture::AuditCapture::install();
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let app = research_app(steward, TenantKeypair::generate()).await;
    let stoken = token_for(steward);
    let (status, grant) = post(&app, "/api/v1/grants", &stoken, &grant_body(researcher, 25)).await;
    assert_eq!(status, StatusCode::OK, "grant: {grant}");
    let grant_id = grant["grant_id"].as_str().expect("grant id").to_owned();
    let (status, _) = research_query(&app, researcher, steward).await;
    assert_eq!(status, StatusCode::OK);
    revoke(&app, steward, &grant_id).await;

    let body = format!(r#"{{"researcher_tenant":"{researcher}","connector":"health"}}"#);
    let (status, regrant) = post(&app, "/api/v1/grants", &stoken, &body).await;
    assert_eq!(status, StatusCode::OK, "re-grant: {regrant}");
    assert_eq!(regrant["budget"]["limit"], 25, "{regrant}");
    assert_eq!(regrant["budget"]["remaining"], 24, "{regrant}");
    assert_eq!(budget_events(&capture), Vec::<String>::new());
}

/// A revoked grant that was never funded (its approval failed) opens its
/// budget when re-granted, as a new grant does.
#[tokio::test]
async fn re_granting_a_revoked_grant_with_no_budget_opens_one() {
    let capture = platform_telemetry::capture::AuditCapture::install();
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let stores = ResearchStores {
        budgets: Arc::new(TestLedger {
            fail_top_up_once: armed(),
            ..TestLedger::default()
        }),
        ..ResearchStores::in_memory()
    };
    let app = research_app_with_stores(steward, TenantKeypair::generate(), stores).await;
    let stoken = token_for(steward);
    let request_id = pending_request(&app, steward, researcher).await;
    let approve = format!("/api/v1/research/requests/{request_id}/approve");
    let (status, _) = post(&app, &approve, &stoken, "{}").await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    let (_, grants) = call(&app, "GET", "/api/v1/grants", &stoken, None).await;
    let grant_id = grants["grants"][0]["grant_id"].as_str().expect("grant id");
    revoke(&app, steward, grant_id).await;

    let (status, regrant) =
        post(&app, "/api/v1/grants", &stoken, &grant_body(researcher, 50)).await;
    assert_eq!(status, StatusCode::OK, "re-grant: {regrant}");
    assert_eq!(regrant["budget"]["limit"], 50, "{regrant}");
    assert_eq!(budget_events(&capture), Vec::<String>::new());
}

#[tokio::test]
async fn a_failed_re_grant_leaves_the_budget_for_a_later_approval_to_add_to() {
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let stores = ResearchStores {
        grants: Arc::new(TestRegistry {
            fail_create: armed(),
            ..TestRegistry::default()
        }),
        ..ResearchStores::in_memory()
    };
    let app = research_app_with_stores(steward, TenantKeypair::generate(), stores).await;
    let stoken = token_for(steward);
    let grant_id = &grant_and_revoke(&app, steward, researcher, 28).await;

    let (status, _) = post(
        &app,
        "/api/v1/grants",
        &stoken,
        &grant_body(researcher, 500),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    let budget = budget_of(&app, steward, grant_id).await;
    assert_eq!(budget["limit"], 28, "{budget}");
    let (_, grants) = call(&app, "GET", "/api/v1/grants", &stoken, None).await;
    assert_eq!(grants["grants"][0]["revoked"], true, "{grants}");

    // A later approval re-activates the grant and adds only its own 5.
    let request_id = pending_request(&app, steward, researcher).await;
    let approve = format!("/api/v1/research/requests/{request_id}/approve");
    let (status, resolved) = post(&app, &approve, &stoken, r#"{"query_budget":5}"#).await;
    assert_eq!(status, StatusCode::OK, "approve: {resolved}");
    assert_eq!(resolved["grant"]["budget"]["limit"], 33, "{resolved}");
}

#[tokio::test]
async fn a_second_revoke_still_refuses_a_stale_approval_retry() {
    let capture = platform_telemetry::capture::AuditCapture::install();
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    // The approval's `create` fails; the direct grant before it and the
    // re-grant after it succeed.
    let stores = ResearchStores {
        grants: Arc::new(TestRegistry {
            fail_create: armed(),
            ..TestRegistry::default()
        }),
        ..ResearchStores::in_memory()
    };
    let app = research_app_with_stores(steward, TenantKeypair::generate(), stores).await;
    let stoken = token_for(steward);
    let grant_id = &grant_and_revoke(&app, steward, researcher, 28).await;

    // Approval A is recorded after that revoke, then fails to re-activate.
    let a = pending_request(&app, steward, researcher).await;
    let approve = format!("/api/v1/research/requests/{a}/approve");
    let (status, _) = post(&app, &approve, &stoken, r#"{"query_budget":7}"#).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);

    // A later revoke and a re-grant: A's retry predates the revoke.
    revoke(&app, steward, grant_id).await;
    let (status, regrant) =
        post(&app, "/api/v1/grants", &stoken, &grant_body(researcher, 10)).await;
    assert_eq!(status, StatusCode::OK, "re-grant: {regrant}");
    let (status, _) = post(&app, &approve, &stoken, "{}").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let budget = budget_of(&app, steward, grant_id).await;
    assert_eq!(budget["limit"], 38, "{budget}");
    assert_event(
        &capture,
        "research.catalog",
        "denied",
        &format!("approve refused request={a} grant={grant_id} retry=true reason=revoked_since"),
    );
}

#[tokio::test]
async fn of_two_simultaneous_re_grants_of_a_revoked_grant_only_one_is_made() {
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    // Once armed, the next request to find the grant revoked yields before
    // re-activating it, so without the lock the other request would find it
    // revoked too, and both would add their budget.
    let registry = Arc::new(TestRegistry::default());
    let stores = ResearchStores {
        grants: registry.clone(),
        ..ResearchStores::in_memory()
    };
    let app = research_app_with_stores(steward, TenantKeypair::generate(), stores).await;
    let stoken = token_for(steward);
    let grant_id = &grant_and_revoke(&app, steward, researcher, 28).await;

    registry.yield_after_check.store(true, Ordering::SeqCst);
    let (body_a, body_b) = (grant_body(researcher, 50), grant_body(researcher, 10));
    let (first, second) = tokio::join!(
        post(&app, "/api/v1/grants", &stoken, &body_a),
        post(&app, "/api/v1/grants", &stoken, &body_b),
    );
    let mut statuses = [first.0, second.0];
    statuses.sort();
    assert_eq!(
        statuses,
        [StatusCode::OK, StatusCode::CONFLICT],
        "{first:?} {second:?}"
    );
    // The budget is the old one plus the amount of the request that got 200.
    let (made, added) = if first.0 == StatusCode::OK {
        (&first.1, 50)
    } else {
        (&second.1, 10)
    };
    let budget = budget_of(&app, steward, grant_id).await;
    assert_eq!(budget["limit"], 28 + added, "{budget} {made}");
    assert_eq!(budget["limit"], made["budget"]["limit"], "{budget} {made}");
}

#[tokio::test]
async fn a_revoke_racing_a_grant_lands_after_it() {
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let ledger = Arc::new(TestLedger {
        fail_top_up_once: armed(),
        ..TestLedger::default()
    });
    let stores = ResearchStores {
        budgets: ledger.clone(),
        ..ResearchStores::in_memory()
    };
    let app = research_app_with_stores(steward, TenantKeypair::generate(), stores).await;
    let stoken = token_for(steward);
    // A failed approval leaves an active grant with no budget entry.
    let request_id = pending_request(&app, steward, researcher).await;
    let approve = format!("/api/v1/research/requests/{request_id}/approve");
    let (status, _) = post(&app, &approve, &stoken, "{}").await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    let (_, grants) = call(&app, "GET", "/api/v1/grants", &stoken, None).await;
    let grant_id = grants["grants"][0]["grant_id"].as_str().expect("grant id");
    let revoke = format!("/api/v1/grants/{grant_id}");

    // The direct grant finds the grant and yields before funding it. A
    // revoke that ran now would answer 200 before the grant's own 200 for a
    // grant it is about to report as active, so it waits.
    ledger.yield_on_state.store(true, Ordering::SeqCst);
    let finished = AtomicUsize::new(0);
    let (grant_done, revoke_done) = tokio::join!(
        async {
            let answer = post(&app, "/api/v1/grants", &stoken, &grant_body(researcher, 28)).await;
            (answer, finished.fetch_add(1, Ordering::SeqCst))
        },
        async {
            let answer = call(&app, "DELETE", &revoke, &stoken, None).await;
            (answer, finished.fetch_add(1, Ordering::SeqCst))
        },
    );
    assert_eq!(
        grant_done.0.0,
        StatusCode::OK,
        "grant: {:?}",
        grant_done.0.1
    );
    assert_eq!(revoke_done.0.0, StatusCode::OK);
    assert!(grant_done.1 < revoke_done.1, "the revoke ran mid-grant");
    let (status, _) = research_query(&app, researcher, steward).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// The `research.budget` `ok` details captured so far.
fn budget_events(capture: &platform_telemetry::capture::AuditCapture) -> Vec<String> {
    capture
        .events()
        .iter()
        .filter(|e| e.audit_kind == "research.budget" && e.outcome == "ok")
        .map(|e| e.detail.clone())
        .collect()
}

/// An app over `ledger` with `researcher` holding a 28-unit grant, and a
/// pending request of `researcher`. Arm the ledger's switches after this
/// setup.
async fn app_with_a_grant_and_a_request(
    steward: TenantId,
    researcher: TenantId,
    ledger: Arc<TestLedger>,
) -> (Router, String, String) {
    let stores = ResearchStores {
        budgets: ledger,
        ..ResearchStores::in_memory()
    };
    let app = research_app_with_stores(steward, TenantKeypair::generate(), stores).await;
    let stoken = token_for(steward);
    let (status, grant) = post(&app, "/api/v1/grants", &stoken, &grant_body(researcher, 28)).await;
    assert_eq!(status, StatusCode::OK, "grant: {grant}");
    let grant_id = grant["grant_id"].as_str().expect("grant id").to_owned();
    let request_id = pending_request(&app, steward, researcher).await;
    (app, grant_id, request_id)
}

#[tokio::test]
async fn a_revoke_queued_before_an_approval_lands_before_its_decision() {
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let ledger = Arc::new(TestLedger {
        fail_top_up_once: armed(),
        ..TestLedger::default()
    });
    let (app, grant_id, request_id) =
        app_with_a_grant_and_a_request(steward, researcher, ledger.clone()).await;
    let stoken = token_for(steward);
    let revoke = format!("/api/v1/grants/{grant_id}");
    let approve = format!("/api/v1/research/requests/{request_id}/approve");

    // A direct grant holds the lock (it yields in `state`), a revoke queues
    // behind it, and then the approval arrives. The approval's decision
    // must come after the revoke, so its retry is not "revoked since".
    ledger.yield_on_state.store(true, Ordering::SeqCst);
    let direct = grant_body(researcher, 5);
    let (_, revoked, approved) = tokio::join!(
        post(&app, "/api/v1/grants", &stoken, &direct),
        call(&app, "DELETE", &revoke, &stoken, None),
        post(&app, &approve, &stoken, "{}"),
    );
    assert_eq!(revoked.0, StatusCode::OK);
    assert_eq!(
        approved.0,
        StatusCode::BAD_GATEWAY,
        "approve: {}",
        approved.1
    );
    let (status, retry) = post(&app, &approve, &stoken, "{}").await;
    assert_eq!(status, StatusCode::OK, "retry: {retry}");
    assert_eq!(retry["grant"]["revoked"], false);
    assert_eq!(retry["grant"]["budget"]["limit"], 53, "{retry}");
}

#[tokio::test]
async fn a_top_up_racing_a_follow_up_approval_is_not_counted_as_its_own() {
    let capture = platform_telemetry::capture::AuditCapture::install();
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let ledger = Arc::new(TestLedger::default());
    let (app, grant_id, request_id) =
        app_with_a_grant_and_a_request(steward, researcher, ledger.clone()).await;
    let stoken = token_for(steward);
    let approve = format!("/api/v1/research/requests/{request_id}/approve");
    let budget_uri = format!("/api/v1/grants/{grant_id}/budget");

    // The approval yields after reading the budget; the steward's top-up
    // arrives meanwhile.
    ledger.yield_on_state.store(true, Ordering::SeqCst);
    let (approved, topped) = tokio::join!(
        post(&app, &approve, &stoken, r#"{"query_budget":3}"#),
        post(&app, &budget_uri, &stoken, r#"{"additional":100}"#),
    );
    assert_eq!(approved.0, StatusCode::OK, "approve: {}", approved.1);
    assert_eq!(topped.0, StatusCode::OK, "top-up: {}", topped.1);
    // A retry alongside another top-up adds nothing and audits nothing. The
    // yield is armed again, so the top-up lands while the retry waits.
    ledger.yield_on_state.store(true, Ordering::SeqCst);
    let (retry, topped) = tokio::join!(
        post(&app, &approve, &stoken, "{}"),
        post(&app, &budget_uri, &stoken, r#"{"additional":7}"#),
    );
    assert_eq!(retry.0, StatusCode::OK, "retry: {}", retry.1);
    assert_eq!(topped.0, StatusCode::OK);
    let mut events = budget_events(&capture);
    events.sort();
    let mut expected = vec![
        format!("top_up grant={grant_id} added=100 limit=131"),
        format!("top_up grant={grant_id} added=3 limit=31"),
        format!("top_up grant={grant_id} added=7 limit=138"),
    ];
    expected.sort();
    assert_eq!(events, expected);
}

#[tokio::test]
async fn a_zero_budget_re_grant_audits_no_top_up() {
    let capture = platform_telemetry::capture::AuditCapture::install();
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let app = research_app(steward, TenantKeypair::generate()).await;
    let stoken = token_for(steward);
    grant_and_revoke(&app, steward, researcher, 28).await;

    let (status, regrant) = post(&app, "/api/v1/grants", &stoken, &grant_body(researcher, 0)).await;
    assert_eq!(status, StatusCode::OK, "re-grant: {regrant}");
    assert_eq!(regrant["budget"]["limit"], 28, "{regrant}");
    assert_eq!(budget_events(&capture), Vec::<String>::new());
}

#[tokio::test]
async fn a_failed_approval_leaves_no_budget_for_a_direct_grant_to_trip_over() {
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let stores = ResearchStores {
        budgets: Arc::new(TestLedger {
            fail_top_up_once: armed(),
            ..TestLedger::default()
        }),
        ..ResearchStores::in_memory()
    };
    let app = research_app_with_stores(steward, TenantKeypair::generate(), stores).await;
    let stoken = token_for(steward);
    let request_id = pending_request(&app, steward, researcher).await;
    let approve = format!("/api/v1/research/requests/{request_id}/approve");
    let (status, _) = post(&app, &approve, &stoken, "{}").await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);

    // The grant exists with no budget entry, so a direct grant funds it.
    let (status, grant) = post(&app, "/api/v1/grants", &stoken, &grant_body(researcher, 28)).await;
    assert_eq!(status, StatusCode::OK, "grant: {grant}");
    assert_eq!(grant["budget"]["limit"], 28, "{grant}");

    // The approval's retry then adds its own 25 once.
    for _ in 0..2 {
        let (status, resolved) = post(&app, &approve, &stoken, "{}").await;
        assert_eq!(status, StatusCode::OK, "retry: {resolved}");
        assert_eq!(resolved["grant"]["budget"]["limit"], 53, "{resolved}");
    }
}

#[tokio::test]
async fn a_zero_budget_grant_is_still_a_grant_a_direct_grant_cannot_replace() {
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let app = research_app(steward, TenantKeypair::generate()).await;
    let stoken = token_for(steward);
    let (status, grant) = post(&app, "/api/v1/grants", &stoken, &grant_body(researcher, 0)).await;
    assert_eq!(status, StatusCode::OK, "grant: {grant}");
    assert_eq!(grant["budget"]["limit"], 0, "{grant}");

    let (status, refused) =
        post(&app, "/api/v1/grants", &stoken, &grant_body(researcher, 50)).await;
    assert_eq!(status, StatusCode::CONFLICT, "re-grant: {refused}");
    assert_eq!(refused["error"], ALREADY_GRANTED);
    let grant_id = grant["grant_id"].as_str().expect("grant id");
    let budget = budget_of(&app, steward, grant_id).await;
    assert_eq!(budget["limit"], 0, "{budget}");
}

#[tokio::test]
async fn a_grant_and_an_approval_at_once_drop_no_budget() {
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    // The direct grant's first `state` yields, so the approval runs mid-grant.
    let stores = ResearchStores {
        budgets: Arc::new(TestLedger {
            yield_on_state: armed(),
            ..TestLedger::default()
        }),
        ..ResearchStores::in_memory()
    };
    let app = research_app_with_stores(steward, TenantKeypair::generate(), stores).await;
    let stoken = token_for(steward);
    let listing_id = publish(&app, steward).await;
    let request_id = request_listing(&app, &listing_id, researcher).await;
    let approve = format!("/api/v1/research/requests/{request_id}/approve");
    let grant = grant_body(researcher, 28);
    let ((grant_status, granted), (approve_status, approved)) = tokio::join!(
        post(&app, "/api/v1/grants", &stoken, &grant),
        post(&app, &approve, &stoken, r#"{"query_budget":50}"#),
    );
    assert_eq!(approve_status, StatusCode::OK, "approve: {approved}");
    let grant_id = approved["grant"]["grant_id"].as_str().expect("grant id");
    let budget = budget_of(&app, steward, grant_id).await;
    // A direct grant that got 200 has its 28 in the budget; one that came
    // second is refused, never silently dropped.
    let expected = match grant_status {
        StatusCode::OK => 78,
        StatusCode::CONFLICT => 50,
        other => panic!("grant: {other} {granted}"),
    };
    assert_eq!(budget["limit"], expected, "{budget} {granted}");
}

#[tokio::test]
async fn of_two_simultaneous_grants_only_one_is_made() {
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    // The first `state` yields, so the other request runs mid-grant.
    let stores = ResearchStores {
        budgets: Arc::new(TestLedger {
            yield_on_state: armed(),
            ..TestLedger::default()
        }),
        ..ResearchStores::in_memory()
    };
    let app = research_app_with_stores(steward, TenantKeypair::generate(), stores).await;
    let stoken = token_for(steward);
    let (body_a, body_b) = (grant_body(researcher, 28), grant_body(researcher, 50));
    let (first, second) = tokio::join!(
        post(&app, "/api/v1/grants", &stoken, &body_a),
        post(&app, "/api/v1/grants", &stoken, &body_b),
    );
    let mut statuses = [first.0, second.0];
    statuses.sort();
    assert_eq!(
        statuses,
        [StatusCode::OK, StatusCode::CONFLICT],
        "{first:?} {second:?}"
    );
    // The budget is the one the 200 reported.
    let made = if first.0 == StatusCode::OK {
        &first.1
    } else {
        &second.1
    };
    let grant_id = made["grant_id"].as_str().expect("grant id");
    let budget = budget_of(&app, steward, grant_id).await;
    assert_eq!(budget["limit"], made["budget"]["limit"], "{budget} {made}");
}

// ── What a grant covers, and refusals that reveal nothing ──

/// A whole response — status, headers and body — so two refusals can be
/// compared byte for byte.
type RawResponse = (StatusCode, HeaderMap, String);

/// An authenticated JSON request, answered as a [`RawResponse`].
async fn raw_call(app: &Router, method: &str, uri: &str, token: &str, body: &str) -> RawResponse {
    let (status, headers, bytes) = common::send_with_headers(
        app,
        method,
        uri,
        &[common::bearer(token), common::json_header()],
        body.as_bytes().to_vec(),
    )
    .await;
    (
        status,
        headers,
        String::from_utf8(bytes).expect("utf-8 body"),
    )
}

/// `researcher`'s count query over `steward`'s dataset `connector`, both as
/// sent, answered as a [`RawResponse`].
async fn raw_research_query(
    app: &Router,
    researcher: TenantId,
    steward: &str,
    connector: &str,
) -> RawResponse {
    let body = serde_json::json!({
        "steward_tenant": steward,
        "connector": connector,
        "sql": format!("SELECT COUNT(*) AS n FROM {connector}"),
    });
    raw_call(
        app,
        "POST",
        "/api/v1/research/query",
        &token_for(researcher),
        &body.to_string(),
    )
    .await
}

/// Grants `researcher` the `health` dataset with `units`, then revokes the
/// grant; returns its id.
async fn grant_and_revoke(
    app: &Router,
    steward: TenantId,
    researcher: TenantId,
    units: u64,
) -> String {
    let body = grant_body(researcher, units);
    let (status, grant) = post(app, "/api/v1/grants", &token_for(steward), &body).await;
    assert_eq!(status, StatusCode::OK, "grant: {grant}");
    let grant_id = grant["grant_id"].as_str().expect("grant id").to_owned();
    revoke(app, steward, &grant_id).await;
    grant_id
}

/// Revokes `grant_id` as `steward`.
async fn revoke(app: &Router, steward: TenantId, grant_id: &str) {
    let uri = format!("/api/v1/grants/{grant_id}");
    let (status, body) = call(app, "DELETE", &uri, &token_for(steward), None).await;
    assert_eq!(status, StatusCode::OK, "revoke: {body}");
}

/// The budget of `grant_id`, as its steward reads it.
async fn budget_of(app: &Router, steward: TenantId, grant_id: &str) -> serde_json::Value {
    let uri = format!("/api/v1/grants/{grant_id}/budget");
    let (status, budget) = call(app, "GET", &uri, &token_for(steward), None).await;
    assert_eq!(status, StatusCode::OK, "budget: {budget}");
    budget
}

/// Grants `researcher` the steward's `health` dataset; returns the grant id.
async fn grant_health(app: &Router, steward: TenantId, researcher: TenantId) -> String {
    let (status, grant) = post(
        app,
        "/api/v1/grants",
        &token_for(steward),
        &format!(r#"{{"researcher_tenant":"{researcher}","connector":"health"}}"#),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "grant: {grant}");
    grant["grant_id"].as_str().expect("grant id").to_owned()
}

/// A grant covers one dataset of one steward: any other is refused exactly
/// as if the researcher held no grant. The grant check runs before the
/// budget charge and any data access, so neither refused dataset needs
/// data, and neither refusal costs budget.
#[tokio::test]
async fn queries_outside_the_granted_dataset_are_forbidden() {
    let steward = TenantId::generate();
    let other_steward = TenantId::generate();
    let researcher = TenantId::generate();
    let app = research_app(steward, TenantKeypair::generate(EnvelopeSuite::CURRENT)).await;
    let grant_id = grant_health(&app, steward, researcher).await;
    let (status, body) = research_query(&app, researcher, steward).await;
    assert_eq!(status, StatusCode::OK, "query: {body}");
    let ungranted =
        raw_research_query(&app, TenantId::generate(), &steward.to_string(), "health").await;
    assert_eq!(ungranted.0, StatusCode::FORBIDDEN, "{}", ungranted.2);

    // Another steward's dataset under the same slug, and another of this
    // steward's datasets.
    for (owner, connector) in [(other_steward, "health"), (steward, "billing")] {
        let refused = raw_research_query(&app, researcher, &owner.to_string(), connector).await;
        assert_eq!(refused, ungranted, "{owner}/{connector}");
    }

    let (status, budget) = call(
        &app,
        "GET",
        &format!("/api/v1/grants/{grant_id}/budget"),
        &token_for(researcher),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(budget["spent"], 1, "budget: {budget}");
}

/// The 403 is the same, byte for byte, for an existing ungranted dataset,
/// a revoked grant, and a steward or dataset that does not exist, so it
/// reveals nothing about what exists. Malformed ids are refused with 400
/// before the grant check: that depends only on the request.
#[tokio::test]
async fn nonexistent_or_revoked_dataset_gets_the_same_refusal_as_an_ungranted_one() {
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let revoked_researcher = TenantId::generate();
    let app = research_app(steward, TenantKeypair::generate(EnvelopeSuite::CURRENT)).await;
    let revoked_id = grant_health(&app, steward, revoked_researcher).await;
    let (status, _) = call(
        &app,
        "DELETE",
        &format!("/api/v1/grants/{revoked_id}"),
        &token_for(steward),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let steward = steward.to_string();
    let nobody = TenantId::generate().to_string();

    let ungranted = raw_research_query(&app, researcher, &steward, "health").await;
    assert_eq!(ungranted.0, StatusCode::FORBIDDEN, "{}", ungranted.2);
    for (who, owner, connector) in [
        (revoked_researcher, steward.as_str(), "health"),
        (researcher, nobody.as_str(), "health"),
        (researcher, steward.as_str(), "billing"),
        (researcher, steward.as_str(), "upload_cohorts"),
        (researcher, nobody.as_str(), "billing"),
    ] {
        let refused = raw_research_query(&app, who, owner, connector).await;
        assert_eq!(refused, ungranted, "{owner}/{connector}");
    }

    for (owner, connector, error) in [
        ("not-a-tenant", "health", "invalid steward tenant id"),
        (steward.as_str(), "Health!", "invalid connector slug"),
    ] {
        let (status, _, body) = raw_research_query(&app, researcher, owner, connector).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{owner}/{connector}");
        assert_eq!(body, format!(r#"{{"error":"{error}"}}"#));
    }
}

/// `DELETE /api/v1/grants/{id}` and both budget routes answer a grant id
/// that does not exist and one the caller may not act on with the same
/// 404, byte for byte, and the refusals change nothing.
#[tokio::test]
async fn unknown_and_foreign_grant_ids_get_the_same_404() {
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let outsider = TenantId::generate();
    let app = research_app(steward, TenantKeypair::generate(EnvelopeSuite::CURRENT)).await;
    let grant_id = grant_health(&app, steward, researcher).await;
    let unknown_id = TenantId::generate().to_string();

    // Per route: the callers refused the existing grant. Its researcher may
    // read its budget, but not revoke it or top it up.
    let routes: [(&str, &str, &str, &[TenantId]); 3] = [
        ("DELETE", "", "", &[researcher, outsider]),
        ("GET", "/budget", "", &[outsider]),
        (
            "POST",
            "/budget",
            r#"{"additional":5}"#,
            &[researcher, outsider],
        ),
    ];
    for (method, suffix, body, refused) in routes {
        let unknown_uri = format!("/api/v1/grants/{unknown_id}{suffix}");
        let unknown = raw_call(&app, method, &unknown_uri, &token_for(steward), body).await;
        assert_eq!(unknown.0, StatusCode::NOT_FOUND, "{method} {unknown_uri}");
        let outsider_unknown =
            raw_call(&app, method, &unknown_uri, &token_for(outsider), body).await;
        assert_eq!(outsider_unknown, unknown, "{method} {unknown_uri}");

        let foreign_uri = format!("/api/v1/grants/{grant_id}{suffix}");
        for who in refused {
            let foreign = raw_call(&app, method, &foreign_uri, &token_for(*who), body).await;
            assert_eq!(foreign, unknown, "{method} {foreign_uri} as {who}");
        }
    }

    // The grant is still active, with its allocation untouched.
    let (status, budget) = call(
        &app,
        "GET",
        &format!("/api/v1/grants/{grant_id}/budget"),
        &token_for(steward),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(budget["limit"], 100, "budget: {budget}");
    let (status, _) = research_query(&app, researcher, steward).await;
    assert_eq!(status, StatusCode::OK);
}

/// A steward's revoked grant is still its own: revoking it again succeeds,
/// and its budget can still be read and topped up. None of that restores
/// access.
#[tokio::test]
async fn revoked_grant_still_answers_its_steward() {
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let app = research_app(steward, TenantKeypair::generate(EnvelopeSuite::CURRENT)).await;
    let stoken = token_for(steward);
    let grant_id = grant_health(&app, steward, researcher).await;

    let revoke = format!("/api/v1/grants/{grant_id}");
    for _ in 0..2 {
        let (status, revoked) = call(&app, "DELETE", &revoke, &stoken, None).await;
        assert_eq!(status, StatusCode::OK, "revoke: {revoked}");
        assert_eq!(revoked["grant_id"], grant_id.as_str());
        assert_eq!(revoked["revoked"], true);
    }

    let budget_uri = format!("/api/v1/grants/{grant_id}/budget");
    let (status, budget) = call(&app, "GET", &budget_uri, &stoken, None).await;
    assert_eq!(status, StatusCode::OK, "budget: {budget}");
    assert_eq!(budget["limit"], 100);
    let (status, topped) = post(&app, &budget_uri, &stoken, r#"{"additional":5}"#).await;
    assert_eq!(status, StatusCode::OK, "top up: {topped}");
    assert_eq!(topped["limit"], 105);
    let (status, _) = call(&app, "GET", &budget_uri, &token_for(researcher), None).await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = research_query(&app, researcher, steward).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// Revoking and re-granting reuses the grant id, and with it the budget
/// already spent: the re-grant's `query_budget` is added to the old limit,
/// and nothing resets the spend.
#[tokio::test]
async fn cannot_reset_budget_spend_by_regranting() {
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let app = research_app(steward, TenantKeypair::generate(EnvelopeSuite::CURRENT)).await;
    let stoken = token_for(steward);
    let grant = |budget: u64| grant_body(researcher, budget);

    let (status, granted) = post(&app, "/api/v1/grants", &stoken, &grant(2)).await;
    assert_eq!(status, StatusCode::OK, "grant: {granted}");
    let grant_id = granted["grant_id"].as_str().expect("grant id");
    let (status, body) = research_query(&app, researcher, steward).await;
    assert_eq!(status, StatusCode::OK, "query: {body}");
    assert_eq!(body["budget_remaining"], 1);

    revoke(&app, steward, grant_id).await;
    let (status, regranted) = post(&app, "/api/v1/grants", &stoken, &grant(100)).await;
    assert_eq!(status, StatusCode::OK, "re-grant: {regranted}");
    assert_eq!(regranted["grant_id"], grant_id);
    assert_eq!(regranted["revoked"], false);
    // The re-grant adds its 100 to the old limit; the spent unit stays spent.
    assert_eq!(regranted["budget"]["limit"], 102, "re-grant: {regranted}");
    assert_eq!(regranted["budget"]["spent"], 1, "re-grant: {regranted}");

    let (status, body) = research_query(&app, researcher, steward).await;
    assert_eq!(status, StatusCode::OK, "query: {body}");
    assert_eq!(body["budget_remaining"], 100);
}

// ── Approval after a partial failure ──

/// The in-memory budget ledger with one-shot faults. Each switch, while
/// armed (true), acts on the next call of its method and disarms itself:
/// `fail_*` fails that call before it changes anything, and
/// `yield_on_state` yields after the read, so a concurrent request runs
/// while the reader holds a stale answer. A test arms a switch when it
/// builds the ledger, or after its setup.
#[derive(Default)]
struct TestLedger {
    inner: InMemoryBudgetLedger,
    fail_open: AtomicBool,
    fail_top_up: AtomicBool,
    fail_top_up_once: AtomicBool,
    fail_state: AtomicBool,
    yield_on_state: AtomicBool,
}

/// Whether `switch` was armed; disarms it.
fn fires(switch: &AtomicBool) -> bool {
    switch.swap(false, Ordering::SeqCst)
}

/// An armed [`TestLedger`] switch.
fn armed() -> AtomicBool {
    AtomicBool::new(true)
}

#[async_trait]
impl BudgetLedger for TestLedger {
    async fn open(&self, grant_id: &str, limit: u64) -> Result<BudgetState, TenancyError> {
        if fires(&self.fail_open) {
            return Err(TenancyError::NotFound);
        }
        self.inner.open(grant_id, limit).await
    }

    async fn charge(&self, grant_id: &str, cost: u64) -> Result<BudgetState, BudgetError> {
        self.inner.charge(grant_id, cost).await
    }

    async fn top_up(&self, grant_id: &str, additional: u64) -> Result<BudgetState, BudgetError> {
        if fires(&self.fail_top_up) {
            return Err(BudgetError::UnknownGrant);
        }
        self.inner.top_up(grant_id, additional).await
    }

    async fn top_up_once(
        &self,
        grant_id: &str,
        key: &str,
        additional: u64,
    ) -> Result<BudgetState, BudgetError> {
        if fires(&self.fail_top_up_once) {
            return Err(BudgetError::UnknownGrant);
        }
        self.inner.top_up_once(grant_id, key, additional).await
    }

    async fn state(&self, grant_id: &str) -> Result<Option<BudgetState>, TenancyError> {
        if fires(&self.fail_state) {
            return Err(TenancyError::NotFound);
        }
        let state = self.inner.state(grant_id).await;
        if fires(&self.yield_on_state) {
            tokio::task::yield_now().await;
        }
        state
    }
}

/// The in-memory grant registry with one-shot switches, as on
/// [`TestLedger`]: `fail_create` and `fail_create_unless_revoked` fail that
/// call before it changes anything (with `TenancyError::NotFound`, that
/// enum's only variant; the API answers any registry error with 502), and
/// `yield_after_check` yields after `create_unless_revoked` answers, so a
/// concurrent request runs before this one acts on that answer.
#[derive(Default)]
struct TestRegistry {
    inner: InMemoryGrantRegistry,
    fail_create: AtomicBool,
    fail_create_unless_revoked: AtomicBool,
    yield_after_check: AtomicBool,
}

#[async_trait]
impl GrantRegistry for TestRegistry {
    async fn create(
        &self,
        steward: TenantId,
        researcher: TenantId,
        connector: &str,
    ) -> Result<DatasetGrant, TenancyError> {
        if fires(&self.fail_create) {
            return Err(TenancyError::NotFound);
        }
        self.inner.create(steward, researcher, connector).await
    }

    async fn create_unless_revoked(
        &self,
        steward: TenantId,
        researcher: TenantId,
        connector: &str,
    ) -> Result<GrantOutcome, TenancyError> {
        if fires(&self.fail_create_unless_revoked) {
            return Err(TenancyError::NotFound);
        }
        let outcome = self
            .inner
            .create_unless_revoked(steward, researcher, connector)
            .await;
        if fires(&self.yield_after_check) {
            tokio::task::yield_now().await;
        }
        outcome
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

/// The in-memory grant registry, except that `create_unless_revoked`, which
/// an approval retry and a direct grant call, first revokes the grant it is
/// about to check: a revoke that lands after the retry starts and before its grant
/// step, made deterministic instead of racing two tasks.
#[derive(Default)]
struct RevokeDuringRetry {
    inner: InMemoryGrantRegistry,
}

#[async_trait]
impl GrantRegistry for RevokeDuringRetry {
    async fn create(
        &self,
        steward: TenantId,
        researcher: TenantId,
        connector: &str,
    ) -> Result<DatasetGrant, TenancyError> {
        self.inner.create(steward, researcher, connector).await
    }

    async fn create_unless_revoked(
        &self,
        steward: TenantId,
        researcher: TenantId,
        connector: &str,
    ) -> Result<GrantOutcome, TenancyError> {
        // The steward's revoke lands here: the retry has started, and its
        // grant step has not run yet.
        let active = self
            .inner
            .find_active(researcher, steward, connector)
            .await?;
        if let Some(grant) = active {
            self.inner.revoke(steward, &grant.grant_id).await?;
        }
        self.inner
            .create_unless_revoked(steward, researcher, connector)
            .await
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
/// stores, so a test can make one registry call fail or revoke a grant
/// partway through a retry.
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
        limits: QueryLimits::default(),
    };
    let research = Arc::new(ResearchService::new(stores, vault.clone(), 5, 100));
    let service = stack.query_service(settings, research.clone());
    build_app(AppState {
        research: Some(research),
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
    let listing_id = publish(app, steward).await;
    request_listing(app, &listing_id, researcher).await
}

/// Publishes the steward's `health` listing; returns its id.
async fn publish(app: &Router, steward: TenantId) -> String {
    let (status, listing) = post(app, "/api/v1/catalog", &token_for(steward), PUBLISH_BODY).await;
    assert_eq!(status, StatusCode::OK, "publish: {listing}");
    listing["listing_id"].as_str().expect("id").to_owned()
}

/// Files `researcher`'s request for `listing_id`; returns the request id.
async fn request_listing(app: &Router, listing_id: &str, researcher: TenantId) -> String {
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
        budgets: Arc::new(TestLedger {
            fail_top_up_once: armed(),
            ..TestLedger::default()
        }),
        ..ResearchStores::in_memory()
    };
    let app = research_app_with_stores(
        steward,
        TenantKeypair::generate(platform_crypto::EnvelopeSuite::CURRENT),
        stores,
    )
    .await;
    let stoken = token_for(steward);
    let request_id = pending_request(&app, steward, researcher).await;
    let approve = format!("/api/v1/research/requests/{request_id}/approve");

    // `create` succeeds and `top_up_once` fails: the request is Approved and
    // the grant exists, but with no budget entry it serves no queries.
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
        grants: Arc::new(TestRegistry {
            fail_create_unless_revoked: armed(),
            ..TestRegistry::default()
        }),
        ..ResearchStores::in_memory()
    };
    let app = research_app_with_stores(
        steward,
        TenantKeypair::generate(platform_crypto::EnvelopeSuite::CURRENT),
        stores,
    )
    .await;
    let stoken = token_for(steward);
    let request_id = pending_request(&app, steward, researcher).await;
    let uri = |action: &str| format!("/api/v1/research/requests/{request_id}/{action}");

    // Minting the grant fails: the request is Approved and no grant exists.
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
    let app = research_app(
        steward,
        TenantKeypair::generate(platform_crypto::EnvelopeSuite::CURRENT),
    )
    .await;
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
async fn approval_retry_after_a_revoke_is_refused() {
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let app = research_app(
        steward,
        TenantKeypair::generate(platform_crypto::EnvelopeSuite::CURRENT),
    )
    .await;
    let stoken = token_for(steward);
    let request_id = pending_request(&app, steward, researcher).await;
    let approve = format!("/api/v1/research/requests/{request_id}/approve");

    // The steward approves and the researcher has access. Then the steward
    // revokes the grant the approval minted.
    let (status, resolved) = post(&app, &approve, &stoken, "{}").await;
    assert_eq!(status, StatusCode::OK, "approve: {resolved}");
    let grant_id = resolved["grant"]["grant_id"].as_str().expect("grant id");
    let (status, _) = research_query(&app, researcher, steward).await;
    assert_eq!(status, StatusCode::OK);
    revoke(&app, steward, grant_id).await;

    // The old approval arrives again (a retry, a double-click or a stale
    // tab). It is refused, and access stays revoked.
    let (status, body) = post(&app, &approve, &stoken, "{}").await;
    assert_eq!(status, StatusCode::NOT_FOUND, "stale approve: {body}");
    let (status, _) = research_query(&app, researcher, steward).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (_, grants) = call(&app, "GET", "/api/v1/grants", &stoken, None).await;
    assert_eq!(
        grants["grants"][0]["grant_id"], grant_id,
        "grants: {grants}"
    );
    assert_eq!(grants["grants"][0]["revoked"], true, "grants: {grants}");

    // An explicit re-grant still restores access by re-activating the same
    // grant.
    let (status, grant) = post(
        &app,
        "/api/v1/grants",
        &stoken,
        &format!(r#"{{"researcher_tenant":"{researcher}","connector":"health"}}"#),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "re-grant: {grant}");
    assert_eq!(grant["grant_id"], grant_id);
    assert_eq!(grant["revoked"], false);
    // It names no budget, so the grant keeps the approval's 25.
    assert_eq!(grant["budget"]["limit"], 25, "{grant}");
    let (status, body) = research_query(&app, researcher, steward).await;
    assert_eq!(status, StatusCode::OK, "query: {body}");
}

#[tokio::test]
async fn half_finished_approval_retry_after_a_revoke_is_refused() {
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let stores = ResearchStores {
        budgets: Arc::new(TestLedger {
            fail_top_up_once: armed(),
            ..TestLedger::default()
        }),
        ..ResearchStores::in_memory()
    };
    let app = research_app_with_stores(
        steward,
        TenantKeypair::generate(platform_crypto::EnvelopeSuite::CURRENT),
        stores,
    )
    .await;
    let stoken = token_for(steward);
    let request_id = pending_request(&app, steward, researcher).await;
    let approve = format!("/api/v1/research/requests/{request_id}/approve");

    // `create` succeeds and `top_up_once` fails: the request is Approved and
    // the grant exists without a budget. The steward revokes it instead of
    // retrying.
    let (status, _) = post(&app, &approve, &stoken, "{}").await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    let (_, grants) = call(&app, "GET", "/api/v1/grants", &stoken, None).await;
    let grant_id = grants["grants"][0]["grant_id"].as_str().expect("grant id");
    revoke(&app, steward, grant_id).await;

    // A late retry must not re-activate the revoked grant.
    let (status, body) = post(&app, &approve, &stoken, "{}").await;
    assert_eq!(status, StatusCode::NOT_FOUND, "late retry: {body}");
    let (status, _) = research_query(&app, researcher, steward).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn approval_retry_racing_a_revoke_is_refused() {
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let stores = ResearchStores {
        grants: Arc::new(RevokeDuringRetry::default()),
        ..ResearchStores::in_memory()
    };
    let app = research_app_with_stores(
        steward,
        TenantKeypair::generate(platform_crypto::EnvelopeSuite::CURRENT),
        stores,
    )
    .await;
    let stoken = token_for(steward);
    let request_id = pending_request(&app, steward, researcher).await;
    let approve = format!("/api/v1/research/requests/{request_id}/approve");

    // The first approval mints the grant through `create`, which the
    // wrapper leaves alone, and the researcher has access.
    let (status, resolved) = post(&app, &approve, &stoken, "{}").await;
    assert_eq!(status, StatusCode::OK, "approve: {resolved}");
    let grant_id = resolved["grant"]["grant_id"].as_str().expect("grant id");
    let (status, _) = research_query(&app, researcher, steward).await;
    assert_eq!(status, StatusCode::OK);

    // A retry starts, and the steward's revoke lands before its grant step.
    // The retry is refused, and the revoke stands.
    let (status, body) = post(&app, &approve, &stoken, "{}").await;
    assert_eq!(status, StatusCode::NOT_FOUND, "racing retry: {body}");
    let (_, listed) = call(&app, "GET", "/api/v1/grants", &stoken, None).await;
    let grants = listed["grants"].as_array().expect("grants");
    assert_eq!(grants.len(), 1, "grants: {listed}");
    assert_eq!(grants[0]["grant_id"], grant_id, "grants: {listed}");
    assert_eq!(grants[0]["revoked"], true, "grants: {listed}");
    let (status, _) = research_query(&app, researcher, steward).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn approval_retry_with_a_different_budget_is_refused() {
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let app = research_app(
        steward,
        TenantKeypair::generate(platform_crypto::EnvelopeSuite::CURRENT),
    )
    .await;
    let stoken = token_for(steward);
    let request_id = pending_request(&app, steward, researcher).await;
    let approve = format!("/api/v1/research/requests/{request_id}/approve");

    // The steward approves with 10 query units instead of the listing's 25.
    let (status, resolved) = post(&app, &approve, &stoken, r#"{"query_budget":10}"#).await;
    assert_eq!(status, StatusCode::OK, "approve: {resolved}");
    assert_eq!(resolved["request"]["approved_budget"], 10);
    assert_eq!(resolved["grant"]["budget"]["limit"], 10);
    let grant_id = resolved["grant"]["grant_id"].as_str().expect("grant id");

    // A retry cannot change the approved budget, and the budget is unchanged.
    let (status, body) = post(&app, &approve, &stoken, r#"{"query_budget":50}"#).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "retry: {body}");
    let budget = budget_of(&app, steward, grant_id).await;
    assert_eq!(budget["limit"], 10, "budget: {budget}");

    // A retry that repeats the approved budget, or leaves it out, converges.
    for retry_body in [r#"{"query_budget":10}"#, "{}"] {
        let (status, resolved) = post(&app, &approve, &stoken, retry_body).await;
        assert_eq!(status, StatusCode::OK, "retry {retry_body}: {resolved}");
        assert_eq!(resolved["grant"]["budget"]["limit"], 10);
    }
}

#[tokio::test]
async fn approval_retry_after_a_budget_failure_keeps_the_approved_budget() {
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let stores = ResearchStores {
        budgets: Arc::new(TestLedger {
            fail_top_up_once: armed(),
            ..TestLedger::default()
        }),
        ..ResearchStores::in_memory()
    };
    let app = research_app_with_stores(
        steward,
        TenantKeypair::generate(platform_crypto::EnvelopeSuite::CURRENT),
        stores,
    )
    .await;
    let stoken = token_for(steward);
    let request_id = pending_request(&app, steward, researcher).await;
    let approve = format!("/api/v1/research/requests/{request_id}/approve");

    // The approval asks for 10 query units and fails before its budget is added.
    let (status, _) = post(&app, &approve, &stoken, r#"{"query_budget":10}"#).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);

    // A retry with no body opens the approved 10, not the listing's 25.
    let (status, resolved) = post(&app, &approve, &stoken, "{}").await;
    assert_eq!(status, StatusCode::OK, "retry: {resolved}");
    assert_eq!(resolved["grant"]["budget"]["limit"], 10);
}

#[tokio::test]
async fn approving_a_denied_request_is_404() {
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let app = research_app(
        steward,
        TenantKeypair::generate(platform_crypto::EnvelopeSuite::CURRENT),
    )
    .await;
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

#[tokio::test]
async fn follow_up_approval_adds_its_budget_to_the_grant() {
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let app = research_app(steward, TenantKeypair::generate(EnvelopeSuite::CURRENT)).await;
    let stoken = token_for(steward);
    let listing_id = publish(&app, steward).await;

    // The first request is approved with 2 query units, and both are spent.
    let first = request_listing(&app, &listing_id, researcher).await;
    let approve = |id: &str| format!("/api/v1/research/requests/{id}/approve");
    let (status, _) = post(&app, &approve(&first), &stoken, r#"{"query_budget":2}"#).await;
    assert_eq!(status, StatusCode::OK);
    for _ in 0..2 {
        assert_eq!(
            research_query(&app, researcher, steward).await.0,
            StatusCode::OK
        );
    }
    assert_eq!(
        research_query(&app, researcher, steward).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );

    // A follow-up request approved with 3 units adds them to what is spent.
    let follow_up = request_listing(&app, &listing_id, researcher).await;
    assert_ne!(follow_up, first);
    let (status, resolved) =
        post(&app, &approve(&follow_up), &stoken, r#"{"query_budget":3}"#).await;
    assert_eq!(status, StatusCode::OK, "follow-up: {resolved}");
    assert_eq!(resolved["grant"]["budget"]["limit"], 5);
    assert_eq!(resolved["grant"]["budget"]["spent"], 2);
    let (status, body) = research_query(&app, researcher, steward).await;
    assert_eq!(status, StatusCode::OK, "query: {body}");
    assert_eq!(body["budget_remaining"], 2);

    // Retrying the follow-up approval adds nothing more.
    let (status, again) = post(&app, &approve(&follow_up), &stoken, "{}").await;
    assert_eq!(status, StatusCode::OK, "retry: {again}");
    assert_eq!(again["grant"]["budget"]["limit"], 5);
}

#[tokio::test]
async fn approving_a_request_for_an_unpublished_listing_is_404() {
    let capture = platform_telemetry::capture::AuditCapture::install();
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let app = research_app(steward, TenantKeypair::generate(EnvelopeSuite::CURRENT)).await;
    let stoken = token_for(steward);
    let listing_id = publish(&app, steward).await;
    let request_id = request_listing(&app, &listing_id, researcher).await;

    let (status, _) = call(
        &app,
        "DELETE",
        &format!("/api/v1/catalog/{listing_id}"),
        &stoken,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Approval is refused and mints nothing; the steward can still deny.
    let uri = |action: &str| format!("/api/v1/research/requests/{request_id}/{action}");
    let (status, _) = post(&app, &uri("approve"), &stoken, "{}").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(
        capture
            .events()
            .iter()
            .any(|e| e.audit_kind == "research.catalog"
                && e.outcome == "denied"
                && e.detail == format!(
                    "approve refused request={request_id} researcher={researcher} reason=unpublished"
                )),
        "{:?}",
        capture.events()
    );
    assert_eq!(
        research_query(&app, researcher, steward).await.0,
        StatusCode::FORBIDDEN
    );
    let (status, _) = post(&app, &uri("deny"), &stoken, "{}").await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn stale_approval_retry_after_a_revoke_and_regrant_adds_nothing() {
    let capture = platform_telemetry::capture::AuditCapture::install();
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let stores = ResearchStores {
        budgets: Arc::new(TestLedger {
            fail_top_up_once: armed(),
            ..TestLedger::default()
        }),
        ..ResearchStores::in_memory()
    };
    let app = research_app_with_stores(
        steward,
        TenantKeypair::generate(EnvelopeSuite::CURRENT),
        stores,
    )
    .await;
    let stoken = token_for(steward);
    let listing_id = publish(&app, steward).await;
    let approve = |id: &str| format!("/api/v1/research/requests/{id}/approve");

    // Approval A (7 units) mints the grant and fails before funding it.
    let a = request_listing(&app, &listing_id, researcher).await;
    let (status, _) = post(&app, &approve(&a), &stoken, r#"{"query_budget":7}"#).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);

    // The steward revokes instead of retrying, then approves request B.
    let (_, grants) = call(&app, "GET", "/api/v1/grants", &stoken, None).await;
    let grant_id = grants["grants"][0]["grant_id"]
        .as_str()
        .expect("grant id")
        .to_owned();
    let (status, _) = call(
        &app,
        "DELETE",
        &format!("/api/v1/grants/{grant_id}"),
        &stoken,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let b = request_listing(&app, &listing_id, researcher).await;
    let (status, resolved) = post(&app, &approve(&b), &stoken, r#"{"query_budget":2}"#).await;
    assert_eq!(status, StatusCode::OK, "approve B: {resolved}");
    assert_eq!(resolved["grant"]["budget"]["limit"], 2);

    // A stale retry of A predates the revoke: refused, and adds nothing.
    let (status, _) = post(&app, &approve(&a), &stoken, "{}").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let budget = budget_of(&app, steward, &grant_id).await;
    assert_eq!(budget["limit"], 2, "{budget}");
    assert_event(
        &capture,
        "research.catalog",
        "denied",
        &format!("approve refused request={a} grant={grant_id} retry=true reason=revoked_since"),
    );
}
