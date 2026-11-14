//! Audit-coverage contract: every security-relevant flow (key enrollment,
//! TEE attestation, provisioning, data access including misses and denials,
//! the research catalog, research grants and budgets) emits its
//! SECURITY_AUDIT_EVENT record.

mod common;

use std::sync::Arc;

use axum::Router;
use axum::http::StatusCode;
use bytes::Bytes;
use platform_api::admin::{ProvisioningService, default_connector_slugs};
use platform_api::query::{ConnectorQueryService, DevKeyProvider};
use platform_api::research::{ResearchService, ResearchStores};
use platform_api::{AppState, build_app};
use platform_connectors::pipeline::{EnclavePipeline, SyncJob};
use platform_connectors::source::FixtureSource;
use platform_core::{ConnectorSlug, ObjectId, TenantId, ZkMode};
use platform_crypto::TenantKeypair;
use platform_enclave::simulated_token::{
    SIMULATED_IMAGE_DIGEST, SimulatedClaims, SimulatedTokenProvider, TokenSigner,
};
use platform_enclave::token::ReleasePolicy;
use platform_enclave::{AttestationProvider, DevAttestation};
use platform_storage::{ObjectStoreVault, TenantPaths, VaultStore};
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

/// Full app: vault + jwt + provisioning + research access + a query
/// service with sealed QuickBooks fixture data for `tenant`, who can also
/// grant research access to it.
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
    let config = Arc::new(common::config_with_mor_secret(PADDLE_SECRET));
    // The configured `k` and default budget, as the binary wires them.
    let research = Arc::new(ResearchService::from_config(
        ResearchStores::in_memory(),
        vault.clone(),
        &config.research,
    ));

    let query = ConnectorQueryService::new(
        vault.clone(),
        Arc::new(DevKeyProvider::new(tenant, keypair)),
        attestation,
        EngineSettings {
            zk,
            max_concurrent_queries: 4,
        },
        require_attestation,
    )
    .with_research(research.clone());
    let provisioning = ProvisioningService::new(
        Arc::new(InMemoryTenantRegistry::new(default_connector_slugs())),
        vault.clone(),
    );

    build_app(AppState {
        config,
        research: Some(research),
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
        br#"{"event_type":"subscription.created","occurred_at":"2026-07-30T12:00:00Z","data":{"id":"sub_a","customer_id":"cus_a","items":[{"price":{"id":"pri_x"}}]}}"#
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

    // Every status event is audited with what it did, even when nothing
    // changed: a skipped event is denied (stale or canceled), an unknown
    // subscription is a miss.
    for (subscription, event_type, occurred_at) in [
        ("sub_a", "subscription.paused", "2026-08-02T00:00:00Z"),
        ("sub_a", "subscription.paused", "2026-08-01T00:00:00Z"),
        ("sub_a", "subscription.resumed", "2026-08-01T00:00:00Z"),
        ("sub_a", "subscription.resumed", "2026-08-03T00:00:00Z"),
        ("sub_a", "subscription.canceled", "2026-07-31T00:00:00Z"),
        ("sub_a", "subscription.resumed", "2026-08-04T00:00:00Z"),
        ("sub_zzz", "subscription.resumed", "2026-08-04T00:00:00Z"),
    ] {
        let body = format!(
            r#"{{"event_type":"{event_type}","occurred_at":"{occurred_at}","data":{{"id":"{subscription}"}}}}"#
        )
        .into_bytes();
        let signature = common::paddle_signature(PADDLE_SECRET, &body);
        let (status, _) = send(
            &app,
            "POST",
            "/admin/webhooks/mor",
            &[("Paddle-Signature", signature), json_header()],
            body,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }
    let status_changes: Vec<_> = capture
        .events()
        .into_iter()
        .filter(|e| {
            e.audit_kind == "tenant.provisioned"
                && e.detail != "provisioned subscription=sub_a plan=pri_x"
        })
        .map(|e| (e.outcome, e.detail))
        .collect();
    let expected = [
        (
            "ok",
            "suspend subscription=sub_a occurred_at=2026-08-02 00:00:00 UTC",
        ),
        (
            "denied",
            "suspend subscription=sub_a occurred_at=2026-08-01 00:00:00 UTC reason=stale",
        ),
        (
            "denied",
            "resume subscription=sub_a occurred_at=2026-08-01 00:00:00 UTC reason=stale",
        ),
        (
            "ok",
            "resume subscription=sub_a occurred_at=2026-08-03 00:00:00 UTC",
        ),
        (
            "ok",
            "cancel subscription=sub_a occurred_at=2026-07-31 00:00:00 UTC",
        ),
        (
            "denied",
            "resume subscription=sub_a occurred_at=2026-08-04 00:00:00 UTC reason=canceled",
        ),
        (
            "miss",
            "resume subscription=sub_zzz occurred_at=2026-08-04 00:00:00 UTC",
        ),
    ]
    .map(|(o, d)| (o.to_owned(), d.to_owned()));
    assert_eq!(status_changes, expected);

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

#[tokio::test]
async fn orphan_sweep_deletions_are_audited() {
    let capture = AuditCapture::install();
    let vault = ObjectStoreVault::new_in_memory();
    let tenant = TenantId::generate();
    vault
        .put(
            &platform_storage::TenantPaths::drive_chunk(
                tenant,
                platform_core::ObjectId::generate(),
                0,
            ),
            bytes::Bytes::from_static(b"ciphertext"),
        )
        .await
        .expect("put");

    // As if the chunk were older than any upload may take.
    let later =
        chrono::Utc::now() + platform_api::sweep::ORPHAN_MIN_AGE + chrono::TimeDelta::minutes(1);
    let report = platform_api::sweep::sweep_orphaned_chunks(&vault, later)
        .await
        .expect("sweep");
    assert_eq!(report.chunks, 1);
    assert!(
        capture
            .events()
            .iter()
            .any(|e| e.audit_kind == "data.access"
                && e.outcome == "ok"
                && e.detail.starts_with("orphan_sweep")),
        "{:?}",
        capture.events()
    );
}

fn sweep_events(capture: &AuditCapture) -> Vec<(String, String)> {
    capture
        .events()
        .iter()
        .filter(|e| e.audit_kind == "data.access" && e.detail.starts_with("orphan_sweep"))
        .map(|e| (e.outcome.clone(), e.detail.clone()))
        .collect()
}

fn after_the_orphan_age() -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::now() + platform_api::sweep::ORPHAN_MIN_AGE + chrono::TimeDelta::minutes(1)
}

#[tokio::test]
async fn a_sweep_that_deletes_nothing_audits_nothing() {
    let capture = AuditCapture::install();
    let vault = ObjectStoreVault::new_in_memory();
    let (tenant, object) = (TenantId::generate(), platform_core::ObjectId::generate());
    // A complete object, and an upload still in progress.
    for path in [
        platform_storage::TenantPaths::drive_chunk(tenant, object, 0),
        platform_storage::TenantPaths::drive_manifest(tenant, object),
    ] {
        vault
            .put(&path, bytes::Bytes::from_static(b"ciphertext"))
            .await
            .expect("put");
    }
    platform_api::sweep::sweep_orphaned_chunks(&vault, after_the_orphan_age())
        .await
        .expect("sweep");
    vault
        .put(
            &platform_storage::TenantPaths::drive_chunk(
                tenant,
                platform_core::ObjectId::generate(),
                0,
            ),
            bytes::Bytes::from_static(b"ciphertext"),
        )
        .await
        .expect("put");
    let report = platform_api::sweep::sweep_orphaned_chunks(&vault, chrono::Utc::now())
        .await
        .expect("sweep");
    assert_eq!(report.recent, 1);

    assert_eq!(sweep_events(&capture), Vec::new());
}

#[tokio::test]
async fn a_failed_orphan_sweep_delete_is_audited() {
    let capture = AuditCapture::install();
    let vault = common::FlakyVault::new(
        common::Faults {
            delete: true,
            ..Default::default()
        },
        common::outage,
    );
    let (tenant, object) = (TenantId::generate(), platform_core::ObjectId::generate());
    vault
        .seed(
            &platform_storage::TenantPaths::drive_chunk(tenant, object, 0),
            bytes::Bytes::from_static(b"ciphertext"),
        )
        .await;

    platform_api::sweep::sweep_orphaned_chunks(&vault, after_the_orphan_age())
        .await
        .expect_err("the delete fails");
    assert_eq!(
        sweep_events(&capture),
        vec![(
            "failed".to_owned(),
            format!("orphan_sweep object={object} chunks=0")
        )]
    );
}

#[tokio::test]
async fn a_manifest_refused_during_a_sweep_is_audited_as_denied() {
    let capture = AuditCapture::install();
    let tenant = TenantId::generate();
    let object = platform_core::ObjectId::generate();
    let vault = Arc::new(ObjectStoreVault::new_in_memory());
    for path in [
        platform_storage::TenantPaths::drive_chunk(tenant, object, 0),
        platform_storage::TenantPaths::drive_sweep_marker(tenant, object),
    ] {
        vault
            .put(&path, bytes::Bytes::from_static(b"ciphertext"))
            .await
            .expect("put");
    }
    let app = build_app(app_state(SECRET, vault));
    let manifest = serde_json::json!({
        "wrapped_key": { "iv_b64": "AAAAAAAAAAAAAAAA", "data_b64": "d3JhcHBlZC1rZXk=" },
        "manifest": { "iv_b64": "AAAAAAAAAAAAAAAA", "data_b64": "bWFuaWZlc3Q=" },
        "chunk_count": 1,
        "encrypted_size_bytes": 28,
        "created_at_iso": "2026-07-30T12:00:00.000Z"
    });
    let (status, _) = send(
        &app,
        "PUT",
        &format!("/api/v1/drive/objects/{object}/manifest"),
        &[bearer(&token_for(tenant)), json_header()],
        manifest.to_string().into_bytes(),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let detail = format!("put_manifest object={object} chunk_count=1 reason=sweeping");
    assert!(
        capture
            .events()
            .iter()
            .any(|e| e.audit_kind == "data.access" && e.outcome == "denied" && e.detail == detail),
        "{:?}",
        capture.events()
    );
}

#[tokio::test]
async fn a_manifest_missing_chunks_is_audited_as_denied() {
    let capture = AuditCapture::install();
    let tenant = TenantId::generate();
    let app = full_app(tenant, ZkMode::Disabled).await;
    let manifest = serde_json::json!({
        "wrapped_key": { "iv_b64": "AAAAAAAAAAAAAAAA", "data_b64": "d3JhcHBlZC1rZXk=" },
        "manifest": { "iv_b64": "AAAAAAAAAAAAAAAA", "data_b64": "bWFuaWZlc3Q=" },
        "chunk_count": 1,
        "encrypted_size_bytes": 28,
        "created_at_iso": "2026-07-30T12:00:00.000Z"
    });
    let (status, _) = send(
        &app,
        "PUT",
        "/api/v1/drive/objects/00000000-aaaa-4bbb-8ccc-000000000001/manifest",
        &[bearer(&token_for(tenant)), json_header()],
        manifest.to_string().into_bytes(),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(
        capture
            .events()
            .iter()
            .any(|e| e.audit_kind == "data.access"
                && e.outcome == "denied"
                && e.detail.contains("missing_chunk=0")),
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

    // A retry that names a different budget is refused.
    let (status, _) = post(&app, &approve, &stoken, r#"{"query_budget":7}"#).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
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
        &format!("approve refused request={request_id} retry=true reason=budget"),
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

/// Asserts an event of `kind` with this outcome and exactly this detail.
fn assert_event(capture: &AuditCapture, kind: &str, outcome: &str, detail: &str) {
    let events = capture.events();
    assert!(
        events
            .iter()
            .any(|e| e.audit_kind == kind && e.outcome == outcome && e.detail == detail),
        "no {kind} {outcome} event {detail:?} in {events:?}"
    );
}

/// As [`assert_event`], for an event about `tenant`.
fn assert_tenant_event(
    capture: &AuditCapture,
    kind: &str,
    outcome: &str,
    tenant: TenantId,
    detail: &str,
) {
    let events = capture.events();
    let tenant = tenant.to_string();
    assert!(
        events.iter().any(|e| e.audit_kind == kind
            && e.outcome == outcome
            && e.tenant_id == tenant
            && e.detail == detail),
        "no {kind} {outcome} event for {tenant} {detail:?} in {events:?}"
    );
}

/// The number of `kind` events with this outcome.
fn count_outcome(capture: &AuditCapture, kind: &str, outcome: &str) -> usize {
    capture
        .events()
        .iter()
        .filter(|e| e.audit_kind == kind && e.outcome == outcome)
        .count()
}

#[tokio::test]
async fn research_grants_and_budgets_are_audited() {
    let capture = AuditCapture::install();
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let app = full_app(steward, ZkMode::Disabled).await;
    let stoken = token_for(steward);
    let rtoken = token_for(researcher);
    let query = format!(
        r#"{{"steward_tenant":"{steward}","connector":"quickbooks","sql":"SELECT COUNT(*) AS n FROM quickbooks"}}"#
    );

    // No grant yet: refused before the attestation gate runs. (Building the
    // app ran a connector sync, which passed a gate of its own.)
    let gates = capture.count("tee.attestation");
    let (status, _) = post(&app, "/api/v1/research/query", &rtoken, &query).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        capture.count("tee.attestation"),
        gates,
        "{:?}",
        capture.events()
    );

    // A one-query grant: the query spends it, and the next is refused.
    let (status, grant) = post(
        &app,
        "/api/v1/grants",
        &stoken,
        &format!(
            r#"{{"researcher_tenant":"{researcher}","connector":"quickbooks","query_budget":1}}"#
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "grant: {grant}");
    let grant_id = grant["grant_id"].as_str().expect("grant id");
    let (status, body) = post(&app, "/api/v1/research/query", &rtoken, &query).await;
    assert_eq!(status, StatusCode::OK, "query: {body}");
    let (status, _) = post(&app, "/api/v1/research/query", &rtoken, &query).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);

    // The steward tops the grant up, then revokes it.
    let budget = format!("/api/v1/grants/{grant_id}/budget");
    let (status, _) = post(&app, &budget, &stoken, r#"{"additional":2}"#).await;
    assert_eq!(status, StatusCode::OK);
    let revoke = format!("/api/v1/grants/{grant_id}");
    let (status, _) = call(&app, "DELETE", &revoke, &stoken, None).await;
    assert_eq!(status, StatusCode::OK);

    // Grant and revoke share kind and outcome; the detail tells them apart.
    assert_tenant_event(
        &capture,
        "auth.decision",
        "denied",
        researcher,
        &format!("no active grant for steward={steward} connector=quickbooks"),
    );
    assert_tenant_event(
        &capture,
        "tenant.provisioned",
        "ok",
        steward,
        &format!("granted researcher={researcher} connector=quickbooks budget_limit=1"),
    );
    assert_tenant_event(
        &capture,
        "research.budget",
        "denied",
        researcher,
        &format!("exhausted steward={steward} connector=quickbooks limit=1 spent=1"),
    );
    assert_tenant_event(
        &capture,
        "research.budget",
        "ok",
        steward,
        &format!("top_up grant={grant_id} added=2 limit=3"),
    );
    assert_tenant_event(
        &capture,
        "tenant.provisioned",
        "ok",
        steward,
        &format!("revoked grant={grant_id}"),
    );
}

#[tokio::test]
async fn refused_grant_id_requests_are_audited() {
    let capture = AuditCapture::install();
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let outsider = TenantId::generate();
    let app = full_app(steward, ZkMode::Disabled).await;
    let (status, grant) = post(
        &app,
        "/api/v1/grants",
        &token_for(steward),
        &format!(r#"{{"researcher_tenant":"{researcher}","connector":"quickbooks"}}"#),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "grant: {grant}");
    let grant_id = grant["grant_id"].as_str().expect("grant id").to_owned();
    let unknown_id = TenantId::generate().to_string();
    // A path segment that is not an id; it must not reach the stream.
    let not_an_id = "flu-cohort.csv";

    // Each probe: the caller, the grant id it sends, the id the record
    // shows, and whether a budget read is refused too (the grant's
    // researcher may read its budget). Revoke and top-up always are.
    let probes = [
        (outsider, unknown_id.as_str(), unknown_id.as_str(), true),
        (outsider, grant_id.as_str(), grant_id.as_str(), true),
        (outsider, not_an_id, "malformed", true),
        (researcher, grant_id.as_str(), grant_id.as_str(), false),
    ];
    for (who, sent, shown, reads) in probes {
        let token = token_for(who);
        let refused =
            |action: &str| format!("{action} refused grant={shown} reason=unknown_or_foreign");
        let (status, _) = call(
            &app,
            "DELETE",
            &format!("/api/v1/grants/{sent}"),
            &token,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let budget = format!("/api/v1/grants/{sent}/budget");
        let (status, _) = post(&app, &budget, &token, r#"{"additional":5}"#).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_tenant_event(
            &capture,
            "tenant.provisioned",
            "denied",
            who,
            &refused("revoke"),
        );
        assert_tenant_event(
            &capture,
            "research.budget",
            "denied",
            who,
            &refused("top_up"),
        );
        if reads {
            let (status, _) = call(&app, "GET", &budget, &token, None).await;
            assert_eq!(status, StatusCode::NOT_FOUND);
            assert_tenant_event(&capture, "research.budget", "denied", who, &refused("read"));
        }
    }

    // One event per refusal, and none of them revoked or topped up anything.
    assert_eq!(count_outcome(&capture, "tenant.provisioned", "denied"), 4);
    assert_eq!(count_outcome(&capture, "research.budget", "denied"), 7);
    assert_eq!(count_outcome(&capture, "research.budget", "ok"), 0);
    let events = capture.events();
    assert!(
        events.iter().all(|e| !e.detail.starts_with("revoked ")),
        "{events:?}"
    );
    assert!(
        events.iter().all(|e| !e.detail.contains("flu-cohort")),
        "{events:?}"
    );

    // Input refused with 400 before any lookup reads only the request and
    // is not audited: a malformed steward id or slug, a grant to oneself,
    // and a zero top-up.
    let stoken = token_for(steward);
    let malformed = [
        (
            "/api/v1/research/query".to_owned(),
            token_for(researcher),
            r#"{"steward_tenant":"not-a-tenant","connector":"quickbooks","sql":"SELECT COUNT(*) AS n FROM quickbooks"}"#.to_owned(),
        ),
        (
            "/api/v1/grants".to_owned(),
            stoken.clone(),
            format!(r#"{{"researcher_tenant":"{researcher}","connector":"Quick Books"}}"#),
        ),
        (
            "/api/v1/grants".to_owned(),
            stoken.clone(),
            format!(r#"{{"researcher_tenant":"{steward}","connector":"quickbooks"}}"#),
        ),
        (
            format!("/api/v1/grants/{grant_id}/budget"),
            stoken,
            r#"{"additional":0}"#.to_owned(),
        ),
    ];
    for (uri, token, body) in malformed {
        let (status, _) = post(&app, &uri, &token, &body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{uri} {body}");
    }
    assert_eq!(capture.events(), events);
}

#[tokio::test]
async fn dataset_upload_is_audited() {
    let capture = AuditCapture::install();
    let steward = TenantId::generate();
    let keypair = TenantKeypair::generate();
    let key = keypair.public_key();
    let vault: Arc<dyn VaultStore> = Arc::new(ObjectStoreVault::new_in_memory());
    let app = common::upload_research_app(SECRET, vec![(steward, keypair)], vault.clone());
    let token = token_for(steward);

    // Two uploads: the second commits and prunes the first, and an object
    // that an earlier attempt at its version left.
    let first = common::cohorts_upload(steward, &key, "upload_cohorts", None);
    let (status, _) =
        common::put_upload(&app, Some(&token), "upload_cohorts", first.body.clone()).await;
    assert_eq!(status, StatusCode::OK);
    let second = common::cohorts_upload(steward, &key, "upload_cohorts", Some(&first.version));
    let dataset = ConnectorSlug::new("upload_cohorts").expect("slug");
    vault
        .put(
            &TenantPaths::connector_snapshot_object(
                steward,
                &dataset,
                &second.version,
                ObjectId::generate(),
            ),
            Bytes::from_static(b"sealed"),
        )
        .await
        .expect("put");
    let (status, _) =
        common::put_upload(&app, Some(&token), "upload_cohorts", second.body.clone()).await;
    assert_eq!(status, StatusCode::OK);

    // Refusals: a body that is not an upload, a dataset outside the upload
    // namespace, and a stale version.
    let (status, _) = common::put_upload(
        &app,
        Some(&token),
        "upload_cohorts",
        b"not an upload".to_vec(),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let (status, _) =
        common::put_upload(&app, Some(&token), "research_extract", first.body.clone()).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) =
        common::put_upload(&app, Some(&token), "upload_cohorts", first.body.clone()).await;
    assert_eq!(status, StatusCode::CONFLICT);

    // Publishing a dataset the steward does not hold.
    let (status, _) = post(
        &app,
        "/api/v1/catalog",
        &token,
        r#"{"connector":"upload_other","title":"Cohorts","license_fee_cents":0,"compute_rate_cents":0}"#,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    for upload in [&first, &second] {
        assert_event(
            &capture,
            "data.access",
            "ok",
            &format!(
                "upload object dataset=upload_cohorts snapshot={} object={} ciphertext_bytes={}",
                upload.version,
                upload.object,
                object_bytes(&upload.body)
            ),
        );
        assert_event(
            &capture,
            "data.access",
            "committed",
            &format!(
                "dataset=upload_cohorts snapshot={} objects=1",
                upload.version
            ),
        );
    }
    assert_event(
        &capture,
        "data.access",
        "pruned",
        &format!(
            "dataset=upload_cohorts superseded_snapshot={} objects=1",
            first.version
        ),
    );
    assert_event(
        &capture,
        "data.access",
        "pruned",
        &format!(
            "dataset=upload_cohorts snapshot={} uncommitted_objects=1",
            second.version
        ),
    );
    for reason in ["bad_magic", "stale_version"] {
        assert_event(
            &capture,
            "data.access",
            "denied",
            &format!("upload refused dataset=upload_cohorts reason={reason}"),
        );
    }
    assert_event(
        &capture,
        "data.access",
        "denied",
        "upload refused dataset=research_extract reason=not_upload_dataset",
    );
    assert_event(
        &capture,
        "research.catalog",
        "denied",
        "publish refused connector=upload_other reason=not_held",
    );
    // Nothing from the body, such as a declared column name, reaches the
    // stream.
    assert!(
        capture
            .events()
            .iter()
            .all(|e| !e.detail.contains("condition")),
        "{:?}",
        capture.events()
    );
}

/// The object envelope's length in an upload body.
fn object_bytes(body: &[u8]) -> usize {
    let header = u32::from_be_bytes(body[4..8].try_into().expect("4 bytes")) as usize;
    let at = 8 + header;
    let manifest = u32::from_be_bytes(body[at..at + 4].try_into().expect("4 bytes")) as usize;
    body.len() - (at + 4 + manifest)
}

#[tokio::test]
async fn connector_snapshot_commit_and_prune_are_audited() {
    let capture = AuditCapture::install();
    let tenant = TenantId::generate();
    let keypair = TenantKeypair::generate();
    // Two syncs: the second commits and prunes the first.
    let _vault = synced_vault(tenant, &keypair, 2).await;
    let events = capture.events();
    for outcome in ["committed", "pruned"] {
        assert!(
            events.iter().any(|e| e.audit_kind == "connector.sync"
                && e.outcome == outcome
                && e.detail.starts_with("connector=quickbooks ")),
            "no connector.sync {outcome} in {events:?}"
        );
    }
}

#[tokio::test]
async fn production_mode_refusal_is_audited_without_values() {
    let capture = AuditCapture::install();
    let config = platform_config::PlatformConfig::from_source(|key| {
        (key == "JWT_HS256_SECRET").then(|| "audit-refusal-secret".to_owned())
    })
    .expect("config loads");
    assert!(platform_api::wiring::build_state(config).await.is_err());
    let events = capture.events();
    assert!(capture.contains("service.start", "denied"), "{events:?}");
    assert!(!capture.contains("service.start", "ok"), "{events:?}");
    assert!(
        !format!("{events:?}").contains("audit-refusal-secret"),
        "{events:?}"
    );
}
