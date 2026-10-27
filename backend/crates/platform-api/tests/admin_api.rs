//! Integration tests for the admin console + Paddle MoR webhook: a valid
//! signed webhook provisions a tenant, admin endpoints require the admin
//! claim, connector toggles work, and every failure mode fails closed.

mod common;

use std::sync::Arc;

use async_trait::async_trait;
use axum::Router;
use axum::http::StatusCode;
use bytes::Bytes;
use platform_api::admin::{ProvisioningService, default_connector_slugs};
use platform_api::{AppState, build_app};
use platform_core::TenantId;
use platform_storage::{ObjectStoreVault, StorageError, StorageUsage, VaultPath, VaultStore};
use platform_tenancy::{InMemoryTenantRegistry, TenantRegistry};

use common::{bearer, config_with_mor_secret, json_header, send_json};

const SECRET: &str = "jwt-secret";
const PADDLE_SECRET: &str = "pdl_ntfset_webhook_secret";

fn build(with_billing: bool) -> (Router, Arc<dyn TenantRegistry>) {
    build_with_vault(with_billing, Arc::new(ObjectStoreVault::new_in_memory()))
}

fn build_with_vault(
    with_billing: bool,
    vault: Arc<dyn VaultStore>,
) -> (Router, Arc<dyn TenantRegistry>) {
    let registry: Arc<dyn TenantRegistry> =
        Arc::new(InMemoryTenantRegistry::new(default_connector_slugs()));
    let provisioning = Some(Arc::new(ProvisioningService::new(
        registry.clone(),
        vault.clone(),
    )));
    let config = if with_billing {
        config_with_mor_secret(PADDLE_SECRET)
    } else {
        common::default_config()
    };
    let app = build_app(AppState {
        config: Arc::new(config),
        provisioning,
        ..common::app_state(SECRET, vault)
    });
    (app, registry)
}

/// Build a valid `Paddle-Signature` header for `body` at the current time.
fn paddle_signature(body: &[u8]) -> String {
    common::paddle_signature(PADDLE_SECRET, body)
}

const SUBSCRIPTION_CREATED: &str = r#"{"event_id":"evt_1","event_type":"subscription.created","occurred_at":"2026-07-30T12:00:00Z","data":{"id":"sub_abc","customer_id":"cus_xyz","status":"active","items":[{"price":{"id":"pri_pro"}}]}}"#;

#[tokio::test]
async fn valid_webhook_provisions_a_tenant() {
    let (app, registry) = build(true);
    let body = SUBSCRIPTION_CREATED.as_bytes().to_vec();
    let sig = paddle_signature(&body);

    let (status, json) = send_json(
        &app,
        "POST",
        "/admin/webhooks/mor",
        &[("Paddle-Signature", sig), json_header()],
        body,
    )
    .await;

    assert_eq!(status, StatusCode::OK, "json: {json}");
    assert_eq!(json["action"], "provisioned");

    // The tenant now exists with disabled connectors seeded.
    let record = registry
        .get_by_subscription("sub_abc")
        .await
        .expect("ok")
        .expect("provisioned");
    assert_eq!(record.plan, "pri_pro");
    assert_eq!(record.connectors.get("quickbooks"), Some(&false));
}

#[tokio::test]
async fn webhook_with_bad_signature_is_401_and_provisions_nothing() {
    let (app, registry) = build(true);
    let body = SUBSCRIPTION_CREATED.as_bytes().to_vec();

    let (status, _) = send_json(
        &app,
        "POST",
        "/admin/webhooks/mor",
        &[("Paddle-Signature", "ts=1700000000;h1=deadbeef".into())],
        body,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(registry.list().await.expect("list").is_empty());
}

#[tokio::test]
async fn webhook_without_signature_is_401() {
    let (app, _) = build(true);
    let (status, _) = send_json(
        &app,
        "POST",
        "/admin/webhooks/mor",
        &[],
        SUBSCRIPTION_CREATED.as_bytes().to_vec(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn webhook_without_configured_secret_fails_closed_503() {
    let (app, _) = build(false);
    let body = SUBSCRIPTION_CREATED.as_bytes().to_vec();
    let sig = paddle_signature(&body); // signature is valid, but no secret configured
    let (status, json) = send_json(
        &app,
        "POST",
        "/admin/webhooks/mor",
        &[("Paddle-Signature", sig)],
        body,
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(json["error"], "webhook secret not configured");
}

#[tokio::test]
async fn cancellation_webhook_suspends_the_tenant() {
    let (app, registry) = build(true);

    let create = SUBSCRIPTION_CREATED.as_bytes().to_vec();
    send_json(
        &app,
        "POST",
        "/admin/webhooks/mor",
        &[("Paddle-Signature", paddle_signature(&create))],
        create,
    )
    .await;

    let cancel = br#"{"event_type":"subscription.canceled","data":{"id":"sub_abc"}}"#.to_vec();
    let (status, json) = send_json(
        &app,
        "POST",
        "/admin/webhooks/mor",
        &[("Paddle-Signature", paddle_signature(&cancel))],
        cancel,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["action"], "suspended");

    let record = registry
        .get_by_subscription("sub_abc")
        .await
        .expect("ok")
        .expect("rec");
    assert_eq!(
        serde_json::to_value(record.status).unwrap(),
        serde_json::json!("suspended")
    );
}

#[tokio::test]
async fn admin_endpoints_require_admin_claim() {
    let (app, _) = build(true);
    let regular = common::token_for(SECRET, TenantId::generate());

    // No token → 401.
    let (status, _) = send_json(&app, "GET", "/admin/tenants", &[], Vec::new()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Valid non-admin token → 403.
    let (status, _) = send_json(
        &app,
        "GET",
        "/admin/tenants",
        &[bearer(&regular)],
        Vec::new(),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn admin_can_list_tenants_and_toggle_connectors() {
    let (app, registry) = build(true);
    let admin_token = common::admin_token(SECRET);

    // Provision one tenant via webhook.
    let body = SUBSCRIPTION_CREATED.as_bytes().to_vec();
    send_json(
        &app,
        "POST",
        "/admin/webhooks/mor",
        &[("Paddle-Signature", paddle_signature(&body))],
        body,
    )
    .await;
    let tenant = registry
        .get_by_subscription("sub_abc")
        .await
        .expect("ok")
        .expect("rec")
        .tenant_id;

    // List shows the tenant with (zero) storage usage.
    let (status, json) = send_json(
        &app,
        "GET",
        "/admin/tenants",
        &[bearer(&admin_token)],
        Vec::new(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let tenants = json["tenants"].as_array().expect("tenants");
    assert_eq!(tenants.len(), 1);
    assert_eq!(tenants[0]["storage_object_count"], 0);
    assert_eq!(tenants[0]["connectors"]["quickbooks"], false);

    // Toggle quickbooks on.
    let (status, json) = send_json(
        &app,
        "POST",
        &format!("/admin/tenants/{tenant}/connectors/quickbooks"),
        &[bearer(&admin_token), json_header()],
        br#"{"enabled":true}"#.to_vec(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "json: {json}");
    assert_eq!(json["connectors"]["quickbooks"], true);

    // Unknown connector is rejected.
    let (status, _) = send_json(
        &app,
        "POST",
        &format!("/admin/tenants/{tenant}/connectors/not_a_connector"),
        &[bearer(&admin_token), json_header()],
        br#"{"enabled":true}"#.to_vec(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// In-memory vault whose `put` and/or `usage` fail as a backend outage.
struct FlakyVault {
    inner: ObjectStoreVault,
    fail_put: bool,
    fail_usage: bool,
}

fn outage() -> StorageError {
    StorageError::Backend("simulated outage".into())
}

#[async_trait]
impl VaultStore for FlakyVault {
    async fn put(&self, path: &VaultPath, ciphertext: Bytes) -> Result<(), StorageError> {
        if self.fail_put {
            return Err(outage());
        }
        self.inner.put(path, ciphertext).await
    }
    async fn put_if_absent(&self, path: &VaultPath, ciphertext: Bytes) -> Result<(), StorageError> {
        if self.fail_put {
            return Err(outage());
        }
        self.inner.put_if_absent(path, ciphertext).await
    }
    async fn get(&self, path: &VaultPath) -> Result<Bytes, StorageError> {
        self.inner.get(path).await
    }
    async fn delete(&self, path: &VaultPath) -> Result<(), StorageError> {
        self.inner.delete(path).await
    }
    async fn list(&self, prefix: &VaultPath) -> Result<Vec<VaultPath>, StorageError> {
        self.inner.list(prefix).await
    }
    async fn usage(&self, prefix: &VaultPath) -> Result<StorageUsage, StorageError> {
        if self.fail_usage {
            return Err(outage());
        }
        self.inner.usage(prefix).await
    }
}

fn flaky(fail_put: bool, fail_usage: bool) -> Arc<dyn VaultStore> {
    Arc::new(FlakyVault {
        inner: ObjectStoreVault::new_in_memory(),
        fail_put,
        fail_usage,
    })
}

async fn provision_via_webhook(app: &Router) -> StatusCode {
    let body = SUBSCRIPTION_CREATED.as_bytes().to_vec();
    let (status, _) = send_json(
        app,
        "POST",
        "/admin/webhooks/mor",
        &[("Paddle-Signature", paddle_signature(&body))],
        body,
    )
    .await;
    status
}

fn admin_auth() -> (&'static str, String) {
    bearer(&common::admin_token(SECRET))
}

#[tokio::test]
async fn failed_usage_lookup_is_an_error_not_zero() {
    let (app, _) = build_with_vault(true, flaky(false, true));
    assert_eq!(provision_via_webhook(&app).await, StatusCode::OK);

    let (status, json) =
        send_json(&app, "GET", "/admin/tenants", &[admin_auth()], Vec::new()).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "json: {json}");
    assert!(json.get("tenants").is_none());
}

#[tokio::test]
async fn marker_write_failure_does_not_undo_provisioning() {
    let (app, registry) = build_with_vault(true, flaky(true, false));
    assert_eq!(provision_via_webhook(&app).await, StatusCode::OK);
    assert!(
        registry
            .get_by_subscription("sub_abc")
            .await
            .expect("ok")
            .is_some()
    );
}

#[tokio::test]
async fn toggling_connector_for_unknown_tenant_is_404() {
    let (app, _) = build(true);
    let (status, _) = send_json(
        &app,
        "POST",
        &format!(
            "/admin/tenants/{}/connectors/quickbooks",
            TenantId::generate()
        ),
        &[admin_auth(), json_header()],
        br#"{"enabled":true}"#.to_vec(),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn admin_routes_without_provisioning_report_provisioning_unavailable() {
    let app = build_app(AppState {
        config: Arc::new(config_with_mor_secret(PADDLE_SECRET)),
        ..common::app_state(SECRET, Arc::new(ObjectStoreVault::new_in_memory()))
    });
    let (status, json) =
        send_json(&app, "GET", "/admin/tenants", &[admin_auth()], Vec::new()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(json["error"], "provisioning not configured");

    let body = SUBSCRIPTION_CREATED.as_bytes().to_vec();
    let (status, json) = send_json(
        &app,
        "POST",
        "/admin/webhooks/mor",
        &[("Paddle-Signature", paddle_signature(&body))],
        body,
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(json["error"], "provisioning not configured");
}
