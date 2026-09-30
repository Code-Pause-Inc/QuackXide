//! Integration tests for the admin console + Paddle MoR webhook: a valid
//! signed webhook provisions a tenant, admin endpoints require the admin
//! claim, connector toggles work, and every failure mode fails closed.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use bytes::Bytes;
use hmac::{Hmac, Mac};
use http_body_util::BodyExt;
use platform_api::admin::{ProvisioningService, default_connector_slugs};
use platform_api::{AppState, build_app};
use platform_auth::JwtVerifier;
use platform_config::PlatformConfig;
use platform_core::TenantId;
use platform_storage::{ObjectStoreVault, StorageError, StorageUsage, VaultPath, VaultStore};
use platform_tenancy::{InMemoryTenantRegistry, TenantRegistry};
use sha2::Sha256;
use tower::ServiceExt;

const SECRET: &str = "jwt-secret";
const ISS: &str = "urn:platform:auth";
const AUD: &str = "urn:platform:drive";
const PADDLE_SECRET: &str = "pdl_ntfset_webhook_secret";

fn config_with_billing() -> PlatformConfig {
    PlatformConfig::from_source(|k| match k {
        "MOR_WEBHOOK_SECRET" => Some(PADDLE_SECRET.to_owned()),
        _ => None,
    })
    .expect("config")
}

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
        config_with_billing()
    } else {
        PlatformConfig::from_source(|_| None).expect("config")
    };
    let app = build_app(AppState {
        config: Arc::new(config),
        vault,
        jwt: Some(Arc::new(JwtVerifier::hs256(SECRET, ISS, AUD))),
        query: None,
        provisioning,
    });
    (app, registry)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Build a valid `Paddle-Signature` header for `body` at the current time.
fn paddle_signature(body: &[u8]) -> String {
    let ts = now();
    let mut mac = Hmac::<Sha256>::new_from_slice(PADDLE_SECRET.as_bytes()).unwrap();
    mac.update(ts.to_string().as_bytes());
    mac.update(b":");
    mac.update(body);
    let hex: String = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("ts={ts};h1={hex}")
}

async fn send(
    app: &Router,
    method: &str,
    uri: &str,
    headers: &[(&str, String)],
    body: Vec<u8>,
) -> (StatusCode, serde_json::Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        builder = builder.header(*name, value);
    }
    let request = builder.body(Body::from(body)).expect("request");
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

const SUBSCRIPTION_CREATED: &str = r#"{"event_id":"evt_1","event_type":"subscription.created","occurred_at":"2026-07-30T12:00:00Z","data":{"id":"sub_abc","customer_id":"cus_xyz","status":"active","items":[{"price":{"id":"pri_pro"}}]}}"#;

#[tokio::test]
async fn valid_webhook_provisions_a_tenant() {
    let (app, registry) = build(true);
    let body = SUBSCRIPTION_CREATED.as_bytes().to_vec();
    let sig = paddle_signature(&body);

    let (status, json) = send(
        &app,
        "POST",
        "/admin/webhooks/mor",
        &[
            ("Paddle-Signature", sig),
            (header::CONTENT_TYPE.as_str(), "application/json".into()),
        ],
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

    let (status, _) = send(
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
    let (status, _) = send(
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
    let (status, json) = send(
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
    send(
        &app,
        "POST",
        "/admin/webhooks/mor",
        &[("Paddle-Signature", paddle_signature(&create))],
        create,
    )
    .await;

    let cancel = br#"{"event_type":"subscription.canceled","data":{"id":"sub_abc"}}"#.to_vec();
    let (status, json) = send(
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
    let tenant = TenantId::generate();
    let regular = platform_auth::mint_token(SECRET, ISS, AUD, tenant, "user", 3600).expect("mint");

    // No token → 401.
    let (status, _) = send(&app, "GET", "/admin/tenants", &[], Vec::new()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Valid non-admin token → 403.
    let (status, _) = send(
        &app,
        "GET",
        "/admin/tenants",
        &[("Authorization", format!("Bearer {regular}"))],
        Vec::new(),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn admin_can_list_tenants_and_toggle_connectors() {
    let (app, registry) = build(true);
    let admin_token =
        platform_auth::mint_admin_token(SECRET, ISS, AUD, TenantId::generate(), "root", 3600)
            .expect("mint");

    // Provision one tenant via webhook.
    let body = SUBSCRIPTION_CREATED.as_bytes().to_vec();
    send(
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
    let (status, json) = send(
        &app,
        "GET",
        "/admin/tenants",
        &[("Authorization", format!("Bearer {admin_token}"))],
        Vec::new(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let tenants = json["tenants"].as_array().expect("tenants");
    assert_eq!(tenants.len(), 1);
    assert_eq!(tenants[0]["storage_object_count"], 0);
    assert_eq!(tenants[0]["connectors"]["quickbooks"], false);

    // Toggle quickbooks on.
    let (status, json) = send(
        &app,
        "POST",
        &format!("/admin/tenants/{tenant}/connectors/quickbooks"),
        &[
            ("Authorization", format!("Bearer {admin_token}")),
            (header::CONTENT_TYPE.as_str(), "application/json".into()),
        ],
        br#"{"enabled":true}"#.to_vec(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "json: {json}");
    assert_eq!(json["connectors"]["quickbooks"], true);

    // Unknown connector is rejected.
    let (status, _) = send(
        &app,
        "POST",
        &format!("/admin/tenants/{tenant}/connectors/not_a_connector"),
        &[
            ("Authorization", format!("Bearer {admin_token}")),
            (header::CONTENT_TYPE.as_str(), "application/json".into()),
        ],
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
    let (status, _) = send(
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
    let token =
        platform_auth::mint_admin_token(SECRET, ISS, AUD, TenantId::generate(), "root", 3600)
            .expect("mint");
    ("Authorization", format!("Bearer {token}"))
}

#[tokio::test]
async fn failed_usage_lookup_is_an_error_not_zero() {
    let (app, _) = build_with_vault(true, flaky(false, true));
    assert_eq!(provision_via_webhook(&app).await, StatusCode::OK);

    let (status, json) = send(&app, "GET", "/admin/tenants", &[admin_auth()], Vec::new()).await;
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
    let (status, _) = send(
        &app,
        "POST",
        &format!(
            "/admin/tenants/{}/connectors/quickbooks",
            TenantId::generate()
        ),
        &[
            admin_auth(),
            (header::CONTENT_TYPE.as_str(), "application/json".into()),
        ],
        br#"{"enabled":true}"#.to_vec(),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn admin_routes_without_provisioning_report_provisioning_unavailable() {
    let app = build_app(AppState {
        config: Arc::new(config_with_billing()),
        vault: Arc::new(ObjectStoreVault::new_in_memory()),
        jwt: Some(Arc::new(JwtVerifier::hs256(SECRET, ISS, AUD))),
        query: None,
        provisioning: None,
    });
    let (status, json) = send(&app, "GET", "/admin/tenants", &[admin_auth()], Vec::new()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(json["error"], "provisioning not configured");

    let body = SUBSCRIPTION_CREATED.as_bytes().to_vec();
    let (status, json) = send(
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
