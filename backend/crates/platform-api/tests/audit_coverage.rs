//! Audit-coverage contract: every security-relevant flow (key enrollment,
//! TEE attestation, provisioning, data access including misses and denials)
//! emits its SECURITY_AUDIT_EVENT record.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use hmac::{Hmac, Mac};
use http_body_util::BodyExt;
use platform_api::admin::{ProvisioningService, default_connector_slugs};
use platform_api::query::{ConnectorQueryService, DevKeyProvider};
use platform_api::{AppState, build_app};
use platform_auth::JwtVerifier;
use platform_config::PlatformConfig;
use platform_connectors::pipeline::{EnclavePipeline, SyncJob};
use platform_connectors::source::FixtureSource;
use platform_core::{TenantId, ZkMode};
use platform_crypto::TenantKeypair;
use platform_enclave::DevAttestation;
use platform_storage::{ObjectStoreVault, VaultStore};
use platform_telemetry::capture::AuditCapture;
use platform_tenancy::InMemoryTenantRegistry;
use quackxide_engine::EngineSettings;
use sha2::Sha256;
use tower::ServiceExt;

const SECRET: &str = "audit-itest-secret";
const ISS: &str = "urn:platform:auth";
const AUD: &str = "urn:platform:drive";
const PADDLE_SECRET: &str = "pdl_ntfset_audit_secret";

fn token_for(tenant: TenantId) -> String {
    platform_auth::mint_token(SECRET, ISS, AUD, tenant, "itest", 3600).expect("mint")
}

async fn send(
    app: &Router,
    method: &str,
    uri: &str,
    headers: &[(&str, String)],
    body: Vec<u8>,
) -> (StatusCode, Vec<u8>) {
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
    (status, bytes.to_vec())
}

fn auth(token: &str) -> (&'static str, String) {
    ("Authorization", format!("Bearer {token}"))
}

fn json_header() -> (&'static str, String) {
    ("Content-Type", "application/json".to_owned())
}

/// Full app: vault + jwt + provisioning + a query service with sealed
/// QuickBooks fixture data for `tenant`.
async fn full_app(tenant: TenantId, zk: ZkMode) -> Router {
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
        .expect("seal");

    let query = ConnectorQueryService::new(
        vault.clone(),
        Arc::new(DevKeyProvider::new(tenant, keypair)),
        Arc::new(DevAttestation::allow_insecure_dev()),
        EngineSettings {
            zk,
            max_concurrent_queries: 4,
        },
        false,
    );
    let provisioning = ProvisioningService::new(
        Arc::new(InMemoryTenantRegistry::new(default_connector_slugs())),
        vault.clone(),
    );

    let config = PlatformConfig::from_source(|k| match k {
        "MOR_WEBHOOK_SECRET" => Some(PADDLE_SECRET.to_owned()),
        _ => None,
    })
    .expect("config");

    build_app(AppState {
        config: Arc::new(config),
        vault,
        jwt: Some(Arc::new(JwtVerifier::hs256(SECRET, ISS, AUD))),
        query: Some(Arc::new(query)),
        provisioning: Some(Arc::new(provisioning)),
    })
}

#[tokio::test]
async fn data_access_hits_misses_and_auth_denials_are_audited() {
    let capture = AuditCapture::install();
    let tenant = TenantId::generate();
    let app = full_app(tenant, ZkMode::Disabled).await;
    let token = token_for(tenant);

    // Unauthenticated request → AuthDecision denied.
    let (status, _) = send(&app, "GET", "/api/v1/drive/objects", &[], Vec::new()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Read of a nonexistent object → DataAccess miss (probe visibility).
    let (status, _) = send(
        &app,
        "GET",
        "/api/v1/drive/objects/00000000-aaaa-4bbb-8ccc-000000000001/manifest",
        &[auth(&token)],
        Vec::new(),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Successful list → DataAccess ok.
    let (status, _) = send(
        &app,
        "GET",
        "/api/v1/drive/objects",
        &[auth(&token)],
        Vec::new(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    assert!(
        capture.contains("auth.decision", "denied"),
        "{:?}",
        capture.events()
    );
    assert!(
        capture.contains("data.access", "miss"),
        "{:?}",
        capture.events()
    );
    assert!(
        capture.contains("data.access", "ok"),
        "{:?}",
        capture.events()
    );
}

#[tokio::test]
async fn key_enrollment_handshake_is_audited_and_validated() {
    let capture = AuditCapture::install();
    let tenant = TenantId::generate();
    let app = full_app(tenant, ZkMode::Disabled).await;
    let token = token_for(tenant);

    // A real X25519 public key enrolls.
    let keypair = TenantKeypair::generate();
    let key_b64 = {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(keypair.public_key().to_raw())
    };
    let body = format!(r#"{{"hpke_public_key_b64":"{key_b64}"}}"#);
    let (status, _) = send(
        &app,
        "PUT",
        "/api/v1/drive/enrollment",
        &[auth(&token), json_header()],
        body.into_bytes(),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, stored) = send(
        &app,
        "GET",
        "/api/v1/drive/enrollment",
        &[auth(&token)],
        Vec::new(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let parsed: serde_json::Value = serde_json::from_slice(&stored).expect("json");
    assert_eq!(parsed["hpke_public_key_b64"], key_b64);

    // Malformed keys are rejected — and the rejection is audited.
    let (status, _) = send(
        &app,
        "PUT",
        "/api/v1/drive/enrollment",
        &[auth(&token), json_header()],
        br#"{"hpke_public_key_b64":"AAAA"}"#.to_vec(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    assert!(
        capture.contains("crypto.key_enrollment", "ok"),
        "{:?}",
        capture.events()
    );
    assert!(
        capture.contains("crypto.key_enrollment", "denied"),
        "{:?}",
        capture.events()
    );

    // Another tenant sees no enrollment (tenant-scoped) — audited as a miss.
    let other = token_for(TenantId::generate());
    let (status, _) = send(
        &app,
        "GET",
        "/api/v1/drive/enrollment",
        &[auth(&other)],
        Vec::new(),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn query_path_audits_attestation_and_execution_including_failure() {
    let capture = AuditCapture::install();
    let tenant = TenantId::generate();
    let app = full_app(tenant, ZkMode::Disabled).await;
    let token = token_for(tenant);

    // Successful aggregate query.
    let (status, _) = send(
        &app,
        "POST",
        "/api/v1/query",
        &[auth(&token), json_header()],
        br#"{"connector":"quickbooks","sql":"SELECT COUNT(*) AS n FROM quickbooks"}"#.to_vec(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Broken SQL → failed execution, still audited.
    let (status, _) = send(
        &app,
        "POST",
        "/api/v1/query",
        &[auth(&token), json_header()],
        br#"{"connector":"quickbooks","sql":"SELECT nope FROM nothing"}"#.to_vec(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    assert!(
        capture.contains("tee.attestation", "dev_insecure"),
        "{:?}",
        capture.events()
    );
    assert!(
        capture.contains("engine.query", "ok"),
        "{:?}",
        capture.events()
    );
    assert!(
        capture.contains("engine.query", "failed"),
        "{:?}",
        capture.events()
    );
}

#[tokio::test]
async fn provisioning_webhook_is_audited() {
    let capture = AuditCapture::install();
    let app = full_app(TenantId::generate(), ZkMode::Disabled).await;

    let body =
        br#"{"event_type":"subscription.created","data":{"id":"sub_a","customer_id":"cus_a","items":[{"price":{"id":"pri_x"}}]}}"#
            .to_vec();
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut mac = Hmac::<Sha256>::new_from_slice(PADDLE_SECRET.as_bytes()).unwrap();
    mac.update(ts.to_string().as_bytes());
    mac.update(b":");
    mac.update(&body);
    let hex: String = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    let (status, _) = send(
        &app,
        "POST",
        "/admin/webhooks/mor",
        &[
            ("Paddle-Signature", format!("ts={ts};h1={hex}")),
            json_header(),
        ],
        body,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        capture.contains("tenant.provisioned", "ok"),
        "{:?}",
        capture.events()
    );

    // Bad signature → AuthDecision denied in the audit stream.
    let (status, _) = send(
        &app,
        "POST",
        "/admin/webhooks/mor",
        &[("Paddle-Signature", "ts=1;h1=00".to_owned())],
        br#"{}"#.to_vec(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(
        capture.contains("auth.decision", "denied"),
        "{:?}",
        capture.events()
    );
}
