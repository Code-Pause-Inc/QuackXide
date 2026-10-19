//! Helpers shared by the `platform-api` integration tests: token minting,
//! request helpers, and app builders. Each test binary uses a subset.

#![allow(dead_code)]

use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use arrow::array::{Int64Array, StringArray};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatch;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use hmac::{Hmac, Mac};
use http_body_util::BodyExt;
use parquet::arrow::ArrowWriter;
use platform_api::query::{ConnectorQueryService, MultiTenantDevKeyProvider};
use platform_api::research::ResearchStores;
use platform_api::{AppState, build_app};
use platform_auth::{GeneratedKeypair, JwtVerifier, TokenSigner, TokenType};
use platform_config::PlatformConfig;
use platform_connectors::pipeline::{EnclavePipeline, SyncJob};
use platform_connectors::snapshot::SnapshotWriter;
use platform_connectors::source::FixtureSource;
use platform_core::{ConnectorSlug, TenantId, ZkMode};
use platform_crypto::TenantKeypair;
use platform_enclave::{AttestationProvider, DevAttestation};
use platform_storage::{ObjectStoreVault, VaultStore};
use platform_tenancy::{InMemoryBudgetLedger, InMemoryCatalogRegistry, InMemoryGrantRegistry};
use quackxide_engine::EngineSettings;
use sha2::Sha256;
use tower::ServiceExt;

pub const ISS: &str = "urn:platform:auth";
pub const AUD: &str = "urn:platform:drive";

// ── Tokens ──

/// An HS256 access token for `tenant`, signed with `secret`.
pub fn token_for(secret: &str, tenant: TenantId) -> String {
    platform_auth::mint_token(secret, ISS, AUD, tenant, "itest", 3600).expect("mint")
}

/// An HS256 access token carrying the admin claim, signed with `secret`.
pub fn admin_token(secret: &str) -> String {
    platform_auth::mint_admin_token(secret, ISS, AUD, TenantId::generate(), "root", 3600)
        .expect("mint")
}

/// The RS256 keypair for this test binary, generated once (RSA generation
/// is slow).
pub fn rs256_keypair() -> &'static GeneratedKeypair {
    static KEYPAIR: OnceLock<GeneratedKeypair> = OnceLock::new();
    KEYPAIR.get_or_init(|| platform_auth::generate_rs256_keypair(2048).expect("keypair"))
}

/// An RS256 token of `token_type` for a fresh tenant, signed with
/// [`rs256_keypair`].
pub fn rs256_token(token_type: TokenType, admin: bool) -> String {
    let keys = rs256_keypair();
    TokenSigner::rs256_from_pem(&keys.private_pem, &keys.kid, ISS, AUD)
        .expect("signer")
        .mint(TenantId::generate(), "user-1", token_type, 900, admin)
        .expect("mint")
}

/// A verifier for tokens from [`rs256_token`].
pub fn rs256_verifier() -> JwtVerifier {
    JwtVerifier::rs256_from_jwks(&rs256_keypair().jwks_json, ISS, AUD).expect("verifier")
}

/// A `Paddle-Signature` header value for `body` at the current time.
pub fn paddle_signature(secret: &str, body: &[u8]) -> String {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
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

// ── Requests ──

pub fn bearer(token: &str) -> (&'static str, String) {
    ("Authorization", format!("Bearer {token}"))
}

pub fn content_type(value: &str) -> (&'static str, String) {
    ("Content-Type", value.to_owned())
}

pub fn json_header() -> (&'static str, String) {
    content_type("application/json")
}

/// Send one request through the router; returns the status and raw body.
pub async fn send(
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

/// As [`send`], with the body parsed as JSON (`Null` if it is not).
pub async fn send_json(
    app: &Router,
    method: &str,
    uri: &str,
    headers: &[(&str, String)],
    body: Vec<u8>,
) -> (StatusCode, serde_json::Value) {
    let (status, bytes) = send(app, method, uri, headers, body).await;
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

/// An authenticated JSON request.
pub async fn call(
    app: &Router,
    method: &str,
    uri: &str,
    token: &str,
    body: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let body = body.map(|b| b.as_bytes().to_vec()).unwrap_or_default();
    send_json(app, method, uri, &[bearer(token), json_header()], body).await
}

pub async fn post(
    app: &Router,
    uri: &str,
    token: &str,
    body: &str,
) -> (StatusCode, serde_json::Value) {
    call(app, "POST", uri, token, Some(body)).await
}

/// `POST /api/v1/query`, with or without a token.
pub async fn post_query(
    app: &Router,
    token: Option<&str>,
    body: &str,
) -> (StatusCode, serde_json::Value) {
    let mut headers = vec![json_header()];
    if let Some(token) = token {
        headers.push(bearer(token));
    }
    send_json(
        app,
        "POST",
        "/api/v1/query",
        &headers,
        body.as_bytes().to_vec(),
    )
    .await
}

// ── App builders ──

pub fn default_config() -> PlatformConfig {
    PlatformConfig::from_source(|_| None).expect("config")
}

/// Config with the merchant-of-record webhook secret set.
pub fn config_with_mor_secret(secret: &str) -> PlatformConfig {
    PlatformConfig::from_source(|k| match k {
        "MOR_WEBHOOK_SECRET" => Some(secret.to_owned()),
        _ => None,
    })
    .expect("config")
}

/// Default config, an HS256 verifier for `secret`, and no query or
/// provisioning service. Override fields with struct update syntax.
pub fn app_state(secret: &str, vault: Arc<dyn VaultStore>) -> AppState {
    AppState {
        config: Arc::new(default_config()),
        vault,
        jwt: Some(Arc::new(JwtVerifier::hs256(secret, ISS, AUD))),
        query: None,
        provisioning: None,
    }
}

/// `syncs` full QuickBooks fixture syncs into a fresh vault, sealed to
/// `keypair` by the connector pipeline.
pub async fn synced_vault(
    tenant: TenantId,
    keypair: &TenantKeypair,
    syncs: usize,
) -> Arc<dyn VaultStore> {
    let vault: Arc<dyn VaultStore> = Arc::new(ObjectStoreVault::new_in_memory());
    let pipeline = EnclavePipeline::new(
        Arc::new(DevAttestation::allow_insecure_dev()),
        vault.clone(),
        false,
    );
    let job = SyncJob {
        tenant,
        tenant_public_key: keypair.public_key(),
        source: Arc::new(FixtureSource::quickbooks_demo().expect("fixture")),
    };
    for _ in 0..syncs {
        pipeline.run_sync(&job).await.expect("seal sync");
    }
    vault
}

/// A cohort dataset: 6 "flu" rows, 1 "rare_disease" row.
pub fn cohorts_parquet() -> Vec<u8> {
    let schema = Arc::new(Schema::new(vec![
        Field::new("condition", DataType::Utf8, false),
        Field::new("age", DataType::Int64, false),
    ]));
    let condition =
        StringArray::from_iter_values(["flu", "flu", "flu", "flu", "flu", "flu", "rare_disease"]);
    let age = Int64Array::from(vec![30, 40, 50, 33, 44, 55, 61]);
    let batch = RecordBatch::try_new(schema.clone(), vec![Arc::new(condition), Arc::new(age)])
        .expect("batch");
    let mut buf = Vec::new();
    let mut writer = ArrowWriter::try_new(&mut buf, schema, None).expect("writer");
    writer.write(&batch).expect("write");
    writer.close().expect("close");
    buf
}

/// An app where `steward` has a sealed `health` dataset ([`cohorts_parquet`])
/// and the research layer (catalog, grants, budgets; k=5, default budget
/// 100) is enabled, with the query gate's attestation.
pub async fn research_app(
    secret: &str,
    steward: TenantId,
    steward_keypair: TenantKeypair,
    attestation: Arc<dyn AttestationProvider>,
    require_attestation: bool,
) -> Router {
    let vault: Arc<dyn VaultStore> = Arc::new(ObjectStoreVault::new_in_memory());
    let connector = ConnectorSlug::new("health").expect("slug");
    // Commit the cohort dataset as a snapshot sealed to the steward's key
    // (as the pipeline would).
    let steward_public_key = steward_keypair.public_key();
    let mut snapshot =
        SnapshotWriter::begin(&*vault, steward, &steward_public_key, connector.clone());
    snapshot
        .put("cohorts", &cohorts_parquet())
        .await
        .expect("put");
    snapshot.commit().await.expect("commit");

    let mut keys = MultiTenantDevKeyProvider::new();
    keys.insert(steward, steward_keypair);

    let stores = ResearchStores {
        grants: Arc::new(InMemoryGrantRegistry::default()),
        budgets: Arc::new(InMemoryBudgetLedger::default()),
        catalog: Arc::new(InMemoryCatalogRegistry::default()),
    };
    let service = ConnectorQueryService::new(
        vault.clone(),
        Arc::new(keys),
        attestation,
        EngineSettings {
            zk: ZkMode::Disabled, // research mode forces ZK on regardless
            max_concurrent_queries: 4,
        },
        require_attestation,
    )
    .with_research(stores, 5, 100);

    build_app(AppState {
        query: Some(Arc::new(service)),
        ..app_state(secret, vault)
    })
}

/// The insecure development attestation, for builders that take one.
pub fn dev_attestation() -> Arc<dyn AttestationProvider> {
    Arc::new(DevAttestation::allow_insecure_dev())
}
