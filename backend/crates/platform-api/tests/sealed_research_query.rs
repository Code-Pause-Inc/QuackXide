//! Research queries sealed to the enclave (ADR 0010 "Sealed request"): the
//! researcher seals the query to the request key from the evidence bundle;
//! the enclave refuses a stale key set, a frame that does not open and a
//! grant id that is not the grant, without spending budget; and a replayed
//! envelope gets its stored response with no new charge, while another
//! envelope under a used nonce is refused.
mod common;

use std::sync::Arc;

use axum::Router;
use axum::http::StatusCode;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use platform_api::dev::DevResearchStack;
use platform_api::key_release::{AttestationBundle, KeyWire};
use platform_api::research::{ResearchService, ResearchStores};
use platform_api::{AppState, build_app};
use platform_core::{ConnectorSlug, TenantId, ZkMode};
use platform_crypto::{EnvelopeSuite, TenantKeypair, hpke_seal_to_tenant, info};
use quackxide_engine::{EngineSettings, QueryLimits};
use serde_json::{Value, json};

use common::{call, post};

const SECRET: &str = "sealed-research-itest-secret";
const AGG_SQL: &str =
    "SELECT condition, COUNT(*) AS n FROM health GROUP BY condition ORDER BY condition";

fn token_for(tenant: TenantId) -> String {
    common::token_for(SECRET, tenant)
}

/// The steward's sealed `health` dataset (k = 5) behind the simulated
/// enclave, whose evidence bundle carries the request key.
async fn app(steward: TenantId) -> Router {
    let connector = ConnectorSlug::new("health").expect("slug");
    let mut stack = DevResearchStack::new();
    stack
        .commit_snapshot(
            steward,
            TenantKeypair::generate(EnvelopeSuite::Hpk2),
            &connector,
            "cohorts",
            &common::cohorts_parquet(),
        )
        .await
        .expect("commit");
    let vault = stack.vault();
    let research = Arc::new(ResearchService::new(
        ResearchStores::in_memory(),
        vault.clone(),
        5,
        100,
    ));
    let settings = EngineSettings {
        zk: ZkMode::Disabled,
        max_concurrent_queries: 4,
        limits: QueryLimits::default(),
    };
    let service = stack.query_service(settings, research.clone());
    build_app(AppState {
        research: Some(research),
        query: Some(Arc::new(service)),
        ..common::app_state(SECRET, vault)
    })
}

/// A steward, a researcher granted `budget` units on `health`, the app and
/// the grant id.
async fn granted(budget: u64) -> (Router, TenantId, TenantId, String) {
    let (steward, researcher) = (TenantId::generate(), TenantId::generate());
    let app = app(steward).await;
    let (status, grant) = post(
        &app,
        "/api/v1/grants",
        &token_for(steward),
        &format!(
            r#"{{"researcher_tenant":"{researcher}","connector":"health","query_budget":{budget}}}"#
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "grant: {grant}");
    let grant_id = grant["grant_id"].as_str().expect("grant id").to_owned();
    (app, steward, researcher, grant_id)
}

async fn bundle(app: &Router) -> AttestationBundle {
    let (status, body) = call(
        app,
        "GET",
        &format!("/api/v1/attestation?nonce={}", B64URL.encode([5u8; 32])),
        "",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "bundle: {body}");
    serde_json::from_value(body).expect("bundle")
}

/// A sealed request body, as the researcher's browser builds it.
struct Sealer {
    bundle: AttestationBundle,
    researcher: TenantId,
    steward: TenantId,
}

impl Sealer {
    async fn new(app: &Router, researcher: TenantId, steward: TenantId) -> Self {
        Self {
            bundle: bundle(app).await,
            researcher,
            steward,
        }
    }

    fn body(&self, grant_id: &str, nonce: u8, sql: &str) -> String {
        let recipient = TenantKeypair::generate(EnvelopeSuite::Hpk2).public_key();
        let plaintext = json!({
            "steward_tenant": self.steward.to_string(),
            "connector": "health",
            "sql": sql,
            "request_nonce": B64URL.encode([nonce; 32]),
            "recipient_key": KeyWire::from_public_key(&recipient),
        });
        let request_key = self
            .bundle
            .request_key
            .to_public_key(platform_crypto::SuitePolicy::only(EnvelopeSuite::Hpk2))
            .expect("request key");
        let info =
            info::research_query(EnvelopeSuite::Hpk2, &self.researcher.to_string(), grant_id)
                .expect("info");
        let frame = hpke_seal_to_tenant(
            &request_key,
            &info,
            &serde_json::to_vec(&plaintext).expect("json"),
        )
        .expect("seal");
        json!({
            "version": 1,
            "key_id": self.bundle.key_id,
            "grant_id": grant_id,
            "envelope": B64URL.encode(frame),
        })
        .to_string()
    }
}

async fn query(app: &Router, researcher: TenantId, body: &str) -> (StatusCode, Value) {
    post(app, "/api/v1/research/query", &token_for(researcher), body).await
}

async fn remaining(app: &Router, steward: TenantId, grant_id: &str) -> u64 {
    let (status, budget) = call(
        app,
        "GET",
        &format!("/api/v1/grants/{grant_id}/budget"),
        &token_for(steward),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "budget: {budget}");
    budget["remaining"].as_u64().expect("remaining")
}

#[tokio::test]
async fn a_sealed_query_runs_and_charges_once() {
    let (app, steward, researcher, grant_id) = granted(100).await;
    let sealer = Sealer::new(&app, researcher, steward).await;
    let (status, body) = query(&app, researcher, &sealer.body(&grant_id, 1, AGG_SQL)).await;
    assert_eq!(status, StatusCode::OK, "query: {body}");
    assert_eq!(body["mode"], "research");
    assert_eq!(body["suppressed_rows"], 1);
    assert_eq!(body["rows"], json!([{ "condition": "flu", "n": 6 }]));
    assert_eq!(body["budget_remaining"], 99);
}

#[tokio::test]
async fn replaying_the_same_envelope_returns_the_stored_response() {
    let (app, steward, researcher, grant_id) = granted(100).await;
    let sealer = Sealer::new(&app, researcher, steward).await;
    let body = sealer.body(&grant_id, 1, AGG_SQL);
    let first = query(&app, researcher, &body).await;
    let again = query(&app, researcher, &body).await;
    assert_eq!(first.0, StatusCode::OK, "{}", first.1);
    assert_eq!(again, first);
    assert_eq!(remaining(&app, steward, &grant_id).await, 99);
}

#[tokio::test]
async fn the_same_nonce_with_another_envelope_is_refused() {
    let (app, steward, researcher, grant_id) = granted(100).await;
    let sealer = Sealer::new(&app, researcher, steward).await;
    let (status, _) = query(&app, researcher, &sealer.body(&grant_id, 1, AGG_SQL)).await;
    assert_eq!(status, StatusCode::OK);
    // Sealing again draws a new ephemeral key, so the frame differs.
    let (status, refusal) = query(&app, researcher, &sealer.body(&grant_id, 1, AGG_SQL)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(refusal, json!({ "error": "nonce_used" }));
    assert_eq!(remaining(&app, steward, &grant_id).await, 99);
}

#[tokio::test]
async fn a_stale_key_id_asks_to_reattest() {
    let (app, steward, researcher, grant_id) = granted(100).await;
    let sealer = Sealer::new(&app, researcher, steward).await;
    let mut body: Value = serde_json::from_str(&sealer.body(&grant_id, 1, AGG_SQL)).unwrap();
    body["key_id"] = json!(B64URL.encode([0u8; 32]));
    let (status, refusal) = query(&app, researcher, &body.to_string()).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(refusal, json!({ "error": "reattest" }));
    assert_eq!(remaining(&app, steward, &grant_id).await, 100);
}

#[tokio::test]
async fn a_frame_that_does_not_open_is_refused() {
    let (app, steward, researcher, grant_id) = granted(100).await;
    let sealer = Sealer::new(&app, researcher, steward).await;
    let mut body: Value = serde_json::from_str(&sealer.body(&grant_id, 1, AGG_SQL)).unwrap();
    let mut frame = B64URL.decode(body["envelope"].as_str().unwrap()).unwrap();
    *frame.last_mut().unwrap() ^= 1;
    body["envelope"] = json!(B64URL.encode(frame));
    let (status, _) = query(&app, researcher, &body.to_string()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(remaining(&app, steward, &grant_id).await, 100);
}

#[tokio::test]
async fn a_grant_id_that_is_not_the_grant_is_refused() {
    let (app, steward, researcher, grant_id) = granted(100).await;
    let sealer = Sealer::new(&app, researcher, steward).await;
    let other = "66666666-7777-4888-9999-000000000000";
    let (status, _) = query(&app, researcher, &sealer.body(other, 1, AGG_SQL)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(remaining(&app, steward, &grant_id).await, 100);
}

#[tokio::test]
async fn sealed_body_with_an_unknown_field_is_refused() {
    let (app, steward, researcher, grant_id) = granted(100).await;
    let sealer = Sealer::new(&app, researcher, steward).await;
    let mut body: Value = serde_json::from_str(&sealer.body(&grant_id, 1, AGG_SQL)).unwrap();
    body["sql"] = json!(AGG_SQL);
    let (status, _) = query(&app, researcher, &body.to_string()).await;
    assert!(status.is_client_error(), "{status}");
    assert_eq!(remaining(&app, steward, &grant_id).await, 100);
}

/// A sealed body that also carries the plaintext fields is neither shape:
/// it must not run as a plaintext query, unsealed and outside the replay
/// store.
#[tokio::test]
async fn a_sealed_body_with_the_plaintext_fields_does_not_run() {
    let (app, steward, researcher, grant_id) = granted(100).await;
    let sealer = Sealer::new(&app, researcher, steward).await;
    let mut body: Value = serde_json::from_str(&sealer.body(&grant_id, 1, AGG_SQL)).unwrap();
    body["steward_tenant"] = json!(steward.to_string());
    body["connector"] = json!("health");
    body["sql"] = json!(AGG_SQL);
    let (status, _) = query(&app, researcher, &body.to_string()).await;
    assert!(status.is_client_error(), "{status}");
    assert_eq!(remaining(&app, steward, &grant_id).await, 100);
}

#[tokio::test]
async fn replay_after_revoke_is_refused() {
    let (app, steward, researcher, grant_id) = granted(100).await;
    let sealer = Sealer::new(&app, researcher, steward).await;
    let body = sealer.body(&grant_id, 1, AGG_SQL);
    let (status, _) = query(&app, researcher, &body).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = call(
        &app,
        "DELETE",
        &format!("/api/v1/grants/{grant_id}"),
        &token_for(steward),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = query(&app, researcher, &body).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// A refused charge spends nothing, so its nonce is not kept: an exhausted
/// grant cannot grow the replay store, and after a top-up the same request
/// runs.
#[tokio::test]
async fn a_refused_charge_is_not_recorded() {
    let (app, steward, researcher, grant_id) = granted(1).await;
    let sealer = Sealer::new(&app, researcher, steward).await;
    let (status, _) = query(&app, researcher, &sealer.body(&grant_id, 1, AGG_SQL)).await;
    assert_eq!(status, StatusCode::OK);
    let refused = sealer.body(&grant_id, 2, AGG_SQL);
    let (status, _) = query(&app, researcher, &refused).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    let (status, _) = post(
        &app,
        &format!("/api/v1/grants/{grant_id}/budget"),
        &token_for(steward),
        r#"{"additional":1}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = query(&app, researcher, &refused).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(remaining(&app, steward, &grant_id).await, 0);
}
