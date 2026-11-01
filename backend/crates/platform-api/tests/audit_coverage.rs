//! Audit-coverage contract: every security-relevant flow (key enrollment,
//! TEE attestation, provisioning, data access including misses and denials,
//! the research catalog) emits its SECURITY_AUDIT_EVENT record.

mod common;

use std::sync::Arc;

use axum::Router;
use axum::http::StatusCode;
use platform_api::admin::{ProvisioningService, default_connector_slugs};
use platform_api::query::{ConnectorQueryService, DevKeyProvider};
use platform_api::{AppState, build_app};
use platform_connectors::pipeline::{EnclavePipeline, SyncJob};
use platform_connectors::source::FixtureSource;
use platform_core::{TenantId, ZkMode};
use platform_crypto::TenantKeypair;
use platform_enclave::simulated_token::{
    SIMULATED_IMAGE_DIGEST, SimulatedClaims, SimulatedTokenProvider, TokenSigner,
};
use platform_enclave::token::ReleasePolicy;
use platform_enclave::{AttestationProvider, DevAttestation};
use platform_storage::{ObjectStoreVault, VaultStore};
use platform_telemetry::capture::AuditCapture;
use platform_tenancy::InMemoryTenantRegistry;
use quackxide_engine::EngineSettings;

use common::{app_state, bearer, call, dev_attestation, json_header, post, send, synced_vault};

const SECRET: &str = "audit-itest-secret";
const PADDLE_SECRET: &str = "pdl_ntfset_audit_secret";

fn sim_signer() -> &'static TokenSigner {
    static SIGNER: std::sync::OnceLock<TokenSigner> = std::sync::OnceLock::new();
    SIGNER.get_or_init(|| TokenSigner::generate("urn:audit:sim", SimulatedClaims::default()))
}

fn sim_policy() -> ReleasePolicy {
    ReleasePolicy {
        allowed_image_digests: vec![SIMULATED_IMAGE_DIGEST.into()],
    }
}

/// A simulated token provider whose tokens carry `claims`.
fn sim(claims: SimulatedClaims) -> Arc<SimulatedTokenProvider> {
    Arc::new(SimulatedTokenProvider::in_process(
        Arc::new(sim_signer().with_claims(claims)),
        sim_policy(),
    ))
}

fn token_for(tenant: TenantId) -> String {
    common::token_for(SECRET, tenant)
}

/// Full app: vault + jwt + provisioning + a query service with sealed
/// QuickBooks fixture data for `tenant`.
async fn full_app(tenant: TenantId, zk: ZkMode) -> Router {
    full_app_with_attestation(tenant, zk, dev_attestation(), false).await
}

/// As [`full_app`], with the query gate's attestation.
async fn full_app_with_attestation(
    tenant: TenantId,
    zk: ZkMode,
    attestation: Arc<dyn AttestationProvider>,
    require_attestation: bool,
) -> Router {
    let keypair = TenantKeypair::generate();
    let vault = synced_vault(tenant, &keypair, 1).await;

    let query = ConnectorQueryService::new(
        vault.clone(),
        Arc::new(DevKeyProvider::new(tenant, keypair)),
        attestation,
        EngineSettings {
            zk,
            max_concurrent_queries: 4,
        },
        require_attestation,
    );
    let provisioning = ProvisioningService::new(
        Arc::new(InMemoryTenantRegistry::new(default_connector_slugs())),
        vault.clone(),
    );

    build_app(AppState {
        config: Arc::new(common::config_with_mor_secret(PADDLE_SECRET)),
        query: Some(Arc::new(query)),
        provisioning: Some(Arc::new(provisioning)),
        ..app_state(SECRET, vault)
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
        &[bearer(&token)],
        Vec::new(),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Successful list → DataAccess ok.
    let (status, _) = send(
        &app,
        "GET",
        "/api/v1/drive/objects",
        &[bearer(&token)],
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
        &[bearer(&token), json_header()],
        body.into_bytes(),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, stored) = send(
        &app,
        "GET",
        "/api/v1/drive/enrollment",
        &[bearer(&token)],
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
        &[bearer(&token), json_header()],
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
        &[bearer(&other)],
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
        &[bearer(&token), json_header()],
        br#"{"connector":"quickbooks","sql":"SELECT COUNT(*) AS n FROM quickbooks"}"#.to_vec(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Broken SQL → failed execution, still audited.
    let (status, _) = send(
        &app,
        "POST",
        "/api/v1/query",
        &[bearer(&token), json_header()],
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
async fn attestation_refusal_is_audited() {
    let capture = AuditCapture::install();
    let tenant = TenantId::generate();
    let app = full_app_with_attestation(
        tenant,
        ZkMode::Disabled,
        Arc::new(DevAttestation::strict()),
        true,
    )
    .await;

    let (status, _) = send(
        &app,
        "POST",
        "/api/v1/query",
        &[bearer(&token_for(tenant)), json_header()],
        br#"{"connector":"quickbooks","sql":"SELECT COUNT(*) AS n FROM quickbooks"}"#.to_vec(),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);

    let events = capture.events();
    assert!(
        events.iter().any(|e| e.audit_kind == "tee.attestation"
            && e.outcome == "denied"
            && e.tenant_id == tenant.to_string()),
        "{events:?}"
    );
    assert_eq!(capture.count("engine.query"), 0, "{events:?}");
}

#[tokio::test]
async fn simulated_tokens_audit_simulated_outcome_and_refuse_invalid_or_required_hardware() {
    let capture = AuditCapture::install();
    let tenant = TenantId::generate();

    // 1. A valid simulated token on the query path (require_attestation = false)
    // verifies and emits outcome = "simulated".
    let app = full_app_with_attestation(
        tenant,
        ZkMode::Disabled,
        sim(SimulatedClaims::default()),
        false,
    )
    .await;

    let (status, _) = send(
        &app,
        "POST",
        "/api/v1/query",
        &[bearer(&token_for(tenant)), json_header()],
        br#"{"connector":"quickbooks","sql":"SELECT COUNT(*) AS n FROM quickbooks"}"#.to_vec(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        capture.contains("tee.attestation", "simulated"),
        "{:?}",
        capture.events()
    );

    // 2. A token reporting a debug image is rejected by the verifier even in dev mode.
    let debug_sim = sim(SimulatedClaims {
        dbgstat: "enabled".into(),
        ..SimulatedClaims::default()
    });
    let bad_app = full_app_with_attestation(tenant, ZkMode::Disabled, debug_sim, false).await;
    let (status, _) = send(
        &bad_app,
        "POST",
        "/api/v1/query",
        &[bearer(&token_for(tenant)), json_header()],
        br#"{"connector":"quickbooks","sql":"SELECT COUNT(*) AS n FROM quickbooks"}"#.to_vec(),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);

    // 3. A valid simulated token is rejected when hardware attestation is required (production mode).
    let prod_app = full_app_with_attestation(
        tenant,
        ZkMode::Disabled,
        sim(SimulatedClaims::default()),
        true,
    )
    .await;
    let (status, _) = send(
        &prod_app,
        "POST",
        "/api/v1/query",
        &[bearer(&token_for(tenant)), json_header()],
        br#"{"connector":"quickbooks","sql":"SELECT COUNT(*) AS n FROM quickbooks"}"#.to_vec(),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn provisioning_webhook_is_audited() {
    let capture = AuditCapture::install();
    let app = full_app(TenantId::generate(), ZkMode::Disabled).await;

    let body =
        br#"{"event_type":"subscription.created","data":{"id":"sub_a","customer_id":"cus_a","items":[{"price":{"id":"pri_x"}}]}}"#
            .to_vec();
    let (status, _) = send(
        &app,
        "POST",
        "/admin/webhooks/mor",
        &[
            (
                "Paddle-Signature",
                common::paddle_signature(PADDLE_SECRET, &body),
            ),
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

#[tokio::test]
async fn key_release_handshake_audits_ok_and_denied_outcomes() {
    use platform_api::key_release::{
        AttestedKeyProvider, EnclaveIdentity, InProcessKeyReleaseClient, KeyReleaseRelyingParty,
        StaticKeySource,
    };

    let capture = AuditCapture::install();
    let tenant = TenantId::generate();
    let vault: Arc<dyn VaultStore> = Arc::new(ObjectStoreVault::new_in_memory());
    let keypair = TenantKeypair::generate();
    let snp = sim(SimulatedClaims::default());

    let pipeline = EnclavePipeline::new(snp.clone(), vault.clone(), false);
    pipeline
        .run_sync(&SyncJob {
            tenant,
            tenant_public_key: keypair.public_key(),
            source: Arc::new(FixtureSource::quickbooks_demo().expect("fixture")),
        })
        .await
        .expect("seal");

    let rp = Arc::new(KeyReleaseRelyingParty::new(
        Arc::new(StaticKeySource(sim_signer().jwks())),
        sim_signer().issuer(),
        sim_policy(),
    ));
    rp.insert_tenant_key(tenant, &keypair);
    let ok_provider = Arc::new(AttestedKeyProvider::new(
        Arc::new(EnclaveIdentity::generate()),
        snp.clone(),
        Arc::new(InProcessKeyReleaseClient(rp.clone())),
    ));
    let ok_query = ConnectorQueryService::new(
        vault.clone(),
        ok_provider,
        snp.clone(),
        EngineSettings {
            zk: ZkMode::Disabled,
            max_concurrent_queries: 4,
        },
        false,
    );
    let ok_app = build_app(AppState {
        query: Some(Arc::new(ok_query)),
        ..app_state(SECRET, vault.clone())
    });

    let (status, _) = send(
        &ok_app,
        "POST",
        "/api/v1/query",
        &[bearer(&token_for(tenant)), json_header()],
        br#"{"connector":"quickbooks","sql":"SELECT COUNT(*) AS n FROM quickbooks"}"#.to_vec(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        capture.contains("crypto.key_release", "ok"),
        "{:?}",
        capture.events()
    );

    // An unapproved image digest triggers a key-release denial that is audited.
    let bad_snp = sim(SimulatedClaims {
        image_digest: format!("sha256:{}", "f".repeat(64)),
        ..SimulatedClaims::default()
    });
    let denied_provider = Arc::new(AttestedKeyProvider::new(
        Arc::new(EnclaveIdentity::generate()),
        bad_snp,
        Arc::new(InProcessKeyReleaseClient(rp)),
    ));
    let denied_query = ConnectorQueryService::new(
        vault.clone(),
        denied_provider,
        snp,
        EngineSettings {
            zk: ZkMode::Disabled,
            max_concurrent_queries: 4,
        },
        false,
    );
    let denied_app = build_app(AppState {
        query: Some(Arc::new(denied_query)),
        ..app_state(SECRET, vault)
    });

    let (status, _) = send(
        &denied_app,
        "POST",
        "/api/v1/query",
        &[bearer(&token_for(tenant)), json_header()],
        br#"{"connector":"quickbooks","sql":"SELECT COUNT(*) AS n FROM quickbooks"}"#.to_vec(),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        capture.contains("crypto.key_release", "denied"),
        "{:?}",
        capture.events()
    );
}

#[tokio::test]
async fn drive_listing_past_the_cap_is_audited() {
    let capture = AuditCapture::install();
    let tenant = TenantId::generate();
    let vault = Arc::new(ObjectStoreVault::new_in_memory());
    let manifest = serde_json::json!({
        "wrapped_key": { "iv_b64": "AAAAAAAAAAAAAAAA", "data_b64": "d3JhcHBlZA==" },
        "manifest": { "iv_b64": "AAAAAAAAAAAAAAAA", "data_b64": "bWFuaWZlc3Q=" },
        "chunk_count": 1,
        "encrypted_size_bytes": 1,
        "created_at_iso": "2026-01-01T00:00:00Z",
    })
    .to_string();
    for _ in 0..=platform_api::MAX_LISTED_OBJECTS {
        vault
            .put(
                &platform_storage::TenantPaths::drive_manifest(
                    tenant,
                    platform_core::ObjectId::generate(),
                ),
                manifest.clone().into(),
            )
            .await
            .expect("put");
    }
    let app = build_app(app_state(SECRET, vault));
    let (status, _) = send(
        &app,
        "GET",
        "/api/v1/drive/objects",
        &[bearer(&token_for(tenant))],
        Vec::new(),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        capture.contains("data.access", "denied"),
        "{:?}",
        capture.events()
    );
}

/// Asserts a `research.catalog` event with this outcome and exactly this
/// detail was captured. `contains()` compares only kind and outcome.
fn assert_catalog_event(capture: &AuditCapture, outcome: &str, detail: &str) {
    let events = capture.events();
    assert!(
        events.iter().any(|e| {
            e.audit_kind == "research.catalog" && e.outcome == outcome && e.detail == detail
        }),
        "no research.catalog {outcome} event {detail:?} in {events:?}"
    );
}

#[tokio::test]
async fn research_catalog_is_audited() {
    let capture = AuditCapture::install();
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let app = common::research_app(
        SECRET,
        steward,
        TenantKeypair::generate(),
        dev_attestation(),
        false,
    )
    .await;
    let stoken = token_for(steward);
    let rtoken = token_for(researcher);

    // Publish a listing, then request access to it.
    let (status, listing) = post(
        &app,
        "/api/v1/catalog",
        &stoken,
        r#"{"connector":"health","title":"Cohorts","license_fee_cents":0,"compute_rate_cents":0}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "publish: {listing}");
    let listing_id = listing["listing_id"].as_str().expect("listing id");
    let request_uri = format!("/api/v1/catalog/{listing_id}/request");
    let (status, request) = post(&app, &request_uri, &rtoken, "{}").await;
    assert_eq!(status, StatusCode::OK, "request: {request}");
    let request_id = request["request_id"].as_str().expect("request id");
    let approve = format!("/api/v1/research/requests/{request_id}/approve");
    let deny = format!("/api/v1/research/requests/{request_id}/deny");

    // A first approval, then a retry of it.
    let (status, resolved) = post(&app, &approve, &stoken, "{}").await;
    assert_eq!(status, StatusCode::OK, "approve: {resolved}");
    let grant_id = resolved["grant"]["grant_id"].as_str().expect("grant id");
    let (status, _) = post(&app, &approve, &stoken, "{}").await;
    assert_eq!(status, StatusCode::OK);

    // Denying the Approved request is refused.
    let (status, _) = post(&app, &deny, &stoken, "{}").await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // After a revoke, a retried approval is refused.
    let revoke = format!("/api/v1/grants/{grant_id}");
    let (status, _) = call(&app, "DELETE", &revoke, &stoken, None).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = post(&app, &approve, &stoken, "{}").await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // A fresh request, denied normally.
    let (status, fresh) = post(&app, &request_uri, &rtoken, "{}").await;
    assert_eq!(status, StatusCode::OK, "request: {fresh}");
    let fresh_id = fresh["request_id"].as_str().expect("request id");
    let fresh_deny = format!("/api/v1/research/requests/{fresh_id}/deny");
    let (status, _) = post(&app, &fresh_deny, &stoken, "{}").await;
    assert_eq!(status, StatusCode::OK);

    assert_catalog_event(
        &capture,
        "ok",
        &format!("published listing={listing_id} connector=health"),
    );
    assert_catalog_event(
        &capture,
        "ok",
        &format!("requested request={request_id} listing={listing_id} steward={steward}"),
    );
    assert_catalog_event(
        &capture,
        "ok",
        &format!("approved request={request_id} researcher={researcher}"),
    );
    assert_catalog_event(
        &capture,
        "ok",
        &format!("approved request={request_id} researcher={researcher} retry=true"),
    );
    assert_catalog_event(
        &capture,
        "denied",
        &format!("deny refused request={request_id} researcher={researcher} status=approved"),
    );
    assert_catalog_event(
        &capture,
        "denied",
        &format!("approve refused request={request_id} grant={grant_id} retry=true reason=revoked"),
    );
    assert_catalog_event(
        &capture,
        "ok",
        &format!("denied request={fresh_id} researcher={researcher}"),
    );
}
