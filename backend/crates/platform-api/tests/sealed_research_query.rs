//! Research queries sealed to the enclave (ADR 0010 "Sealed request"): the
//! researcher seals the query to the request key from the evidence bundle;
//! the enclave refuses a stale key set, a frame that does not open and a
//! grant id that is not the grant, without spending budget; and a replayed
//! envelope gets its stored response with no new charge, while another
//! envelope under a used nonce is refused.
mod common;

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::Router;
use axum::http::StatusCode;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use bytes::Bytes;
use platform_api::build_apps_with;
use platform_api::edge::EdgeTimeouts;
use platform_core::TenantId;
use platform_storage::{
    ObjectStoreVault, StorageError, StorageUsage, VaultEntry, VaultPath, VaultStore,
};
use serde_json::{Value, json};

use common::{Sealer, call, post};

const SECRET: &str = "sealed-research-itest-secret";
const AGG_SQL: &str =
    "SELECT condition, COUNT(*) AS n FROM health GROUP BY condition ORDER BY condition";

fn token_for(tenant: TenantId) -> String {
    common::token_for(SECRET, tenant)
}

/// A steward, a researcher granted `budget` units on `health`, the app and
/// the grant id.
async fn granted(budget: u64) -> (Router, TenantId, TenantId, String) {
    let (steward, researcher) = (TenantId::generate(), TenantId::generate());
    let app = common::sealed_research_app(SECRET, steward).await;
    let grant_id = grant(&app, steward, researcher, budget).await;
    (app, steward, researcher, grant_id)
}

/// The id of a new grant of `budget` units on `health` to `researcher`.
async fn grant(app: &Router, steward: TenantId, researcher: TenantId, budget: u64) -> String {
    let (status, grant) = post(
        app,
        "/api/v1/grants",
        &token_for(steward),
        &format!(
            r#"{{"researcher_tenant":"{researcher}","connector":"health","query_budget":{budget}}}"#
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "grant: {grant}");
    grant["grant_id"].as_str().expect("grant id").to_owned()
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

/// Delays every read of a snapshot's Parquet object by `delay`. Only the
/// query reads them, after the charge; the check before it reads only
/// manifests and records.
struct SlowSnapshotReads {
    inner: ObjectStoreVault,
    delay: Duration,
}

#[async_trait]
impl VaultStore for SlowSnapshotReads {
    async fn put(&self, path: &VaultPath, ciphertext: Bytes) -> Result<(), StorageError> {
        self.inner.put(path, ciphertext).await
    }
    async fn put_if_absent(&self, path: &VaultPath, ciphertext: Bytes) -> Result<(), StorageError> {
        self.inner.put_if_absent(path, ciphertext).await
    }
    async fn get(&self, path: &VaultPath) -> Result<Bytes, StorageError> {
        if path.as_str().ends_with(".parquet") {
            tokio::time::sleep(self.delay).await;
        }
        self.inner.get(path).await
    }
    async fn delete(&self, path: &VaultPath) -> Result<(), StorageError> {
        self.inner.delete(path).await
    }
    async fn list(&self, prefix: &VaultPath) -> Result<Vec<VaultPath>, StorageError> {
        self.inner.list(prefix).await
    }
    async fn list_entries(&self, prefix: &VaultPath) -> Result<Vec<VaultEntry>, StorageError> {
        self.inner.list_entries(prefix).await
    }
    async fn usage(&self, prefix: &VaultPath) -> Result<StorageUsage, StorageError> {
        self.inner.usage(prefix).await
    }
}

/// The edge's query timeout ends the request, not the charged query: the
/// query finishes in its own task, and the same envelope gets the stored
/// response with no second charge (ADR 0010 "Sealed request").
#[tokio::test]
async fn timed_out_sealed_query_is_retrievable() {
    let (steward, researcher) = (TenantId::generate(), TenantId::generate());
    let vault = Arc::new(SlowSnapshotReads {
        inner: ObjectStoreVault::new_in_memory(),
        delay: Duration::from_millis(500),
    });
    let (state, _) = common::sealed_research_state(SECRET, steward, vault).await;
    let timeouts = EdgeTimeouts {
        default: Duration::from_secs(10),
        query: Duration::from_millis(100),
        body_gap: Duration::from_secs(10),
    };
    let (app, _) = build_apps_with(state, timeouts);
    let grant_id = grant(&app, steward, researcher, 100).await;
    let sealer = Sealer::new(&app, researcher, steward).await;
    let body = sealer.body(&grant_id, 1, AGG_SQL);

    let (status, _) = query(&app, researcher, &body).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "cut by the edge");

    // Until the query finishes, the same envelope is told it still runs.
    let (status, stored) = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let (status, response) = query(&app, researcher, &body).await;
            if status == StatusCode::CONFLICT && response == json!({ "error": "query_running" }) {
                tokio::time::sleep(Duration::from_millis(20)).await;
                continue;
            }
            break (status, response);
        }
    })
    .await
    .expect("the query finished");
    assert_eq!(status, StatusCode::OK, "stored response: {stored}");
    assert_eq!(stored["rows"], json!([{ "condition": "flu", "n": 6 }]));
    assert_eq!(stored["budget_remaining"], 99);
    assert_eq!(
        remaining(&app, steward, &grant_id).await,
        99,
        "charged once"
    );
}
