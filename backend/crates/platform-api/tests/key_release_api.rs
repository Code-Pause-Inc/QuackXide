//! Integration tests for Step 2:
//! - Public enclave attestation endpoint (`GET /api/v1/attestation`) (`P85` / `P50`)
//! - Attestation-gated key release (`KeyReleaseRelyingParty`, `InProcessKeyReleaseClient`,
//!   `HttpKeyReleaseClient`, `AttestedKeyProvider`) (`P50` / `P51`)
//! - Once-per-query key release session scoping (`QueryKeySession`)

use std::sync::Arc;
use std::time::Duration;

use arrow::array::{Int64Array, StringArray};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatch;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use http_body_util::BodyExt;
use parquet::arrow::ArrowWriter;
use platform_api::admin::{ProvisioningService, default_connector_slugs};
use platform_api::key_release::{
    AttestationBundle, AttestedKeyProvider, EnclaveIdentity, EnrollTenantKeyRequest,
    HttpKeyReleaseClient, InProcessKeyReleaseClient, KeyReleaseClient, KeyReleaseRelyingParty,
    KeyReleaseRequest,
};
use platform_api::query::ConnectorQueryService;
use platform_api::research::ResearchStores;
use platform_api::{AppState, build_app};
use platform_auth::JwtVerifier;
use platform_config::PlatformConfig;
use platform_connectors::pipeline::{EnclavePipeline, SyncJob};
use platform_connectors::snapshot::SnapshotWriter;
use platform_connectors::source::FixtureSource;
use platform_core::{ConnectorSlug, TenantId, ZkMode};
use platform_crypto::TenantKeypair;
use platform_enclave::{
    AttestationProvider, AttestationVerifier, GuestPolicy, ReportDataBinding, SNP_REPORT_BYTES,
    SimulatedSnp, SimulatedSnpConfig, SnpCertChain, TeePlatform, TrustRoot,
};
use platform_storage::{ObjectStoreVault, VaultStore};
use platform_tenancy::InMemoryTenantRegistry;
use quackxide_engine::EngineSettings;
use tokio::net::TcpListener;
use tower::ServiceExt;

const SECRET: &str = "key-release-itest-secret";
const ISS: &str = "urn:platform:auth";
const AUD: &str = "urn:platform:drive";
const SIM_NOW: u64 = 1_700_000_000;

fn token_for(tenant: TenantId) -> String {
    platform_auth::mint_token(SECRET, ISS, AUD, tenant, "itest", 3600).expect("mint")
}

fn auth(token: &str) -> (&'static str, String) {
    ("Authorization", format!("Bearer {token}"))
}

fn json_header() -> (&'static str, String) {
    ("Content-Type", "application/json".to_owned())
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

fn sample_parquet_batch(start_id: i64, rows: i64) -> Vec<u8> {
    let schema = Arc::new(Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new("status", DataType::Utf8, false),
        Field::new("amount_cents", DataType::Int64, false),
    ]));
    let ids: Vec<i64> = (0..rows).map(|offset| start_id + offset).collect();
    let statuses: Vec<&str> = (0..rows).map(|_| "PAID").collect();
    let amounts: Vec<i64> = (0..rows).map(|_| 1_000).collect();

    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(Int64Array::from(ids)),
            Arc::new(StringArray::from(statuses)),
            Arc::new(Int64Array::from(amounts)),
        ],
    )
    .expect("batch");
    let mut buf = Vec::new();
    let mut writer = ArrowWriter::try_new(&mut buf, schema, None).expect("writer");
    writer.write(&batch).expect("write");
    writer.close().expect("close");
    buf
}

#[tokio::test]
async fn attestation_endpoint_returns_verifiable_snp_bundle_bound_to_caller_nonce_and_identity() {
    let vault: Arc<dyn VaultStore> = Arc::new(ObjectStoreVault::new_in_memory());
    let snp = Arc::new(SimulatedSnp::new());
    let identity = Arc::new(EnclaveIdentity::with_metadata([0x11; 32], [0x42; 32]));
    let relying_party = Arc::new(
        KeyReleaseRelyingParty::new(snp.verifier(SIM_NOW), false)
            .with_expected_config_digest([0x42; 32]),
    );
    let key_provider = Arc::new(AttestedKeyProvider::new(
        identity.clone(),
        snp.clone(),
        Arc::new(InProcessKeyReleaseClient(relying_party)),
    ));
    let query = ConnectorQueryService::new(
        vault.clone(),
        key_provider,
        snp.clone(),
        EngineSettings {
            zk: ZkMode::Disabled,
            max_concurrent_queries: 4,
        },
        false,
    )
    .with_enclave_identity(identity.clone());

    let app = build_app(AppState {
        config: Arc::new(PlatformConfig::from_source(|_| None).expect("config")),
        vault,
        jwt: Some(Arc::new(JwtVerifier::hs256(SECRET, ISS, AUD))),
        query: Some(Arc::new(query)),
        provisioning: None,
    });

    let nonce = [0u8; 32];
    let nonce_b64 = B64.encode(nonce);
    let (status, body) = send(
        &app,
        "GET",
        &format!("/api/v1/attestation?nonce_b64={nonce_b64}"),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));

    let bundle: AttestationBundle = serde_json::from_slice(&body).expect("json");
    assert_eq!(bundle.platform, "simulated");
    assert_eq!(
        bundle.enclave_hpke_public_key_b64,
        B64.encode(identity.enclave_hpke_public_key())
    );
    assert_eq!(
        bundle.result_signing_public_key_b64,
        B64.encode(identity.result_signing_public_key())
    );
    assert_eq!(bundle.tls_cert_sha256_b64, B64.encode([0x11; 32]));
    assert_eq!(bundle.config_digest_b64, B64.encode([0x42; 32]));

    let report_bytes = B64.decode(&bundle.report_b64).expect("report_b64");
    assert_eq!(report_bytes.len(), SNP_REPORT_BYTES);
    let cert_chain_bytes = B64.decode(&bundle.cert_chain_b64).expect("cert_chain_b64");
    let chain = SnpCertChain::from_bytes(&cert_chain_bytes).expect("cert chain");

    let expected_binding = identity.binding_for_nonce(nonce);
    let verified = snp
        .verifier(SIM_NOW)
        .verify(&report_bytes, &chain, &expected_binding.to_report_data())
        .expect("bundle must pass full cryptographic verification");
    assert_eq!(verified.platform(), TeePlatform::Simulated);

    // Invalid base64 or wrong-length nonces fail with 400.
    let (status, _) = send(
        &app,
        "GET",
        "/api/v1/attestation?nonce_b64=not-valid-base64!!!",
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let short_nonce = B64.encode([1u8; 16]);
    let (status, _) = send(
        &app,
        "GET",
        &format!("/api/v1/attestation?nonce_b64={short_nonce}"),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn end_to_end_query_and_research_query_over_http_key_release_and_once_per_query_session() {
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let vault: Arc<dyn VaultStore> = Arc::new(ObjectStoreVault::new_in_memory());
    let steward_key = TenantKeypair::generate();

    // Seal a 3-object snapshot so we can prove key release happens ONCE per query,
    // not 1 (manifest) + 3 (objects) = 4 times.
    let snp = Arc::new(SimulatedSnp::new());
    let slug = ConnectorSlug::new("quickbooks").unwrap();
    let steward_pk = steward_key.public_key();
    let mut snapshot = SnapshotWriter::begin(&*vault, steward, &steward_pk, slug.clone());
    snapshot
        .put("invoices_part1", &sample_parquet_batch(1, 5))
        .await
        .expect("put 1");
    snapshot
        .put("invoices_part2", &sample_parquet_batch(6, 5))
        .await
        .expect("put 2");
    snapshot
        .put("invoices_part3", &sample_parquet_batch(11, 5))
        .await
        .expect("put 3");
    snapshot.commit().await.expect("commit 3-object snapshot");

    // Start the standalone KeyReleaseRelyingParty on an ephemeral local TCP port.
    let relying_party = Arc::new(KeyReleaseRelyingParty::new(snp.verifier(SIM_NOW), false));
    relying_party.insert_tenant_key(steward, &steward_key);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let rp_router = relying_party.clone().router();
    let server_handle = tokio::spawn(async move {
        let _ = axum::serve(listener, rp_router).await;
    });

    let identity = Arc::new(EnclaveIdentity::generate());
    let http_client = Arc::new(HttpKeyReleaseClient::new(format!("http://{addr}")));
    let key_provider = Arc::new(AttestedKeyProvider::new(
        identity.clone(),
        snp.clone(),
        http_client,
    ));

    let query = ConnectorQueryService::new(
        vault.clone(),
        key_provider.clone(),
        snp.clone(),
        EngineSettings {
            zk: ZkMode::Enabled,
            max_concurrent_queries: 4,
        },
        false,
    )
    .with_enclave_identity(identity)
    .with_research(ResearchStores::in_memory(), 11, 100);

    let app = build_app(AppState {
        config: Arc::new(PlatformConfig::from_source(|_| None).expect("config")),
        vault,
        jwt: Some(Arc::new(JwtVerifier::hs256(SECRET, ISS, AUD))),
        query: Some(Arc::new(query)),
        provisioning: Some(Arc::new(ProvisioningService::new(
            Arc::new(InMemoryTenantRegistry::new(default_connector_slugs())),
            Arc::new(ObjectStoreVault::new_in_memory()),
        ))),
    });

    // 1. Steward runs an aggregate query across all 3 sealed Parquet objects.
    let (status, body) = send(
        &app,
        "POST",
        "/api/v1/query",
        &[auth(&token_for(steward)), json_header()],
        br#"{"connector":"quickbooks","sql":"SELECT status, COUNT(*) AS n, SUM(amount_cents) AS total FROM quickbooks GROUP BY status"}"#.to_vec(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let parsed: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(parsed["row_count"], 1);
    assert_eq!(parsed["rows"][0]["n"], 15);
    assert_eq!(parsed["rows"][0]["total"], 15_000);

    // Despite opening 1 manifest + 3 Parquet envelopes, key release happened exactly ONCE.
    assert_eq!(key_provider.release_count(), 1);
    assert_eq!(relying_party.release_count(), 1);

    // 2. Steward grants researcher access and researcher queries the steward's dataset.
    let grant_req = serde_json::json!({
        "researcher_tenant": researcher.to_string(),
        "connector": "quickbooks"
    });
    let (status, _) = send(
        &app,
        "POST",
        "/api/v1/grants",
        &[auth(&token_for(steward)), json_header()],
        serde_json::to_vec(&grant_req).unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let req_body = serde_json::json!({
        "steward_tenant": steward.to_string(),
        "connector": "quickbooks",
        "sql": "SELECT status, COUNT(*) AS n FROM quickbooks GROUP BY status"
    });
    let (status, body) = send(
        &app,
        "POST",
        "/api/v1/research/query",
        &[auth(&token_for(researcher)), json_header()],
        serde_json::to_vec(&req_body).unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    assert_eq!(key_provider.release_count(), 2);
    assert_eq!(relying_party.release_count(), 2);

    server_handle.abort();
}

#[tokio::test]
async fn key_release_relying_party_rejects_nonce_replay_mitm_key_swap_and_policy_violations() {
    let tenant = TenantId::generate();
    let tenant_key = TenantKeypair::generate();
    let snp = SimulatedSnp::new();
    let expected_cfg = [0xAA; 32];
    let rp = KeyReleaseRelyingParty::new(snp.verifier(SIM_NOW), false)
        .with_expected_config_digest(expected_cfg);

    // Enroll via the HTTP `/v1/keys` endpoint to verify enrollment round-trip as well.
    let router = Arc::new(rp).router();
    let enroll_req = EnrollTenantKeyRequest {
        tenant_id: tenant.to_string(),
        private_key_b64: B64.encode(tenant_key.to_private_key_bytes().expose()),
    };
    let (status, _) = send(
        &router,
        "PUT",
        "/v1/keys",
        &[json_header()],
        serde_json::to_vec(&enroll_req).unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Rebuild direct handle for fine-grained protocol negative tests.
    let rp = KeyReleaseRelyingParty::new(snp.verifier(SIM_NOW), false)
        .with_expected_config_digest(expected_cfg);
    rp.insert_tenant_key(tenant, &tenant_key);
    let identity = EnclaveIdentity::with_metadata([0u8; 32], expected_cfg);

    // 1. Unknown/unissued challenge nonce is rejected.
    let fake_nonce = [0x11u8; 32];
    let binding = identity.binding_for_nonce(fake_nonce);
    let evidence = snp
        .produce_evidence(&binding.to_report_data())
        .await
        .unwrap();
    assert!(
        rp.release_key(&KeyReleaseRequest {
            tenant_id: tenant.to_string(),
            nonce_b64: B64.encode(fake_nonce),
            report_b64: B64.encode(&evidence.report),
            cert_chain_b64: B64.encode(&evidence.cert_chain),
            enclave_hpke_public_key_b64: B64.encode(identity.enclave_hpke_public_key()),
            result_signing_public_key_b64: B64.encode(identity.result_signing_public_key()),
            tls_cert_sha256_b64: B64.encode([0u8; 32]),
            config_digest_b64: B64.encode(expected_cfg),
        })
        .is_err()
    );

    // 2. Valid challenge succeeds once, and replay of the same nonce is rejected.
    let challenge = rp.issue_challenge();
    let nonce_vec = B64.decode(&challenge.nonce_b64).unwrap();
    let nonce: [u8; 32] = nonce_vec.try_into().unwrap();
    let binding = identity.binding_for_nonce(nonce);
    let evidence = snp
        .produce_evidence(&binding.to_report_data())
        .await
        .unwrap();
    let valid_req = KeyReleaseRequest {
        tenant_id: tenant.to_string(),
        nonce_b64: challenge.nonce_b64.clone(),
        report_b64: B64.encode(&evidence.report),
        cert_chain_b64: B64.encode(&evidence.cert_chain),
        enclave_hpke_public_key_b64: B64.encode(identity.enclave_hpke_public_key()),
        result_signing_public_key_b64: B64.encode(identity.result_signing_public_key()),
        tls_cert_sha256_b64: B64.encode([0u8; 32]),
        config_digest_b64: B64.encode(expected_cfg),
    };
    let released = rp
        .release_key(&valid_req)
        .ok()
        .expect("first release must succeed");
    assert!(!released.wrapped_key_b64.is_empty());

    assert!(
        rp.release_key(&valid_req).is_err(),
        "replayed challenge nonce must fail"
    );

    // 3. MITM key-swap attack: attacker takes a genuine enclave report but substitutes
    // their own HPKE public key in the request so the relying party wraps the tenant key to them.
    let challenge = rp.issue_challenge();
    let nonce: [u8; 32] = B64
        .decode(&challenge.nonce_b64)
        .unwrap()
        .try_into()
        .unwrap();
    let binding = identity.binding_for_nonce(nonce);
    let evidence = snp
        .produce_evidence(&binding.to_report_data())
        .await
        .unwrap();
    let attacker_key = TenantKeypair::generate();
    assert!(
        rp.release_key(&KeyReleaseRequest {
            tenant_id: tenant.to_string(),
            nonce_b64: challenge.nonce_b64,
            report_b64: B64.encode(&evidence.report),
            cert_chain_b64: B64.encode(&evidence.cert_chain),
            enclave_hpke_public_key_b64: B64.encode(attacker_key.public_key().to_raw()),
            result_signing_public_key_b64: B64.encode(identity.result_signing_public_key()),
            tls_cert_sha256_b64: B64.encode([0u8; 32]),
            config_digest_b64: B64.encode(expected_cfg),
        })
        .is_err(),
        "MITM HPKE key substitution must fail REPORT_DATA binding"
    );

    // 4. Config digest mismatch is rejected.
    let challenge = rp.issue_challenge();
    let nonce: [u8; 32] = B64
        .decode(&challenge.nonce_b64)
        .unwrap()
        .try_into()
        .unwrap();
    let wrong_cfg_identity = EnclaveIdentity::with_metadata([0u8; 32], [0xBB; 32]);
    let binding = wrong_cfg_identity.binding_for_nonce(nonce);
    let evidence = snp
        .produce_evidence(&binding.to_report_data())
        .await
        .unwrap();
    assert!(
        rp.release_key(&KeyReleaseRequest {
            tenant_id: tenant.to_string(),
            nonce_b64: challenge.nonce_b64,
            report_b64: B64.encode(&evidence.report),
            cert_chain_b64: B64.encode(&evidence.cert_chain),
            enclave_hpke_public_key_b64: B64.encode(wrong_cfg_identity.enclave_hpke_public_key()),
            result_signing_public_key_b64: B64
                .encode(wrong_cfg_identity.result_signing_public_key()),
            tls_cert_sha256_b64: B64.encode([0u8; 32]),
            config_digest_b64: B64.encode([0xBB; 32]),
        })
        .is_err(),
        "wrong config digest must be rejected"
    );

    // 5. Expired challenge nonce is rejected.
    let short_ttl_rp = KeyReleaseRelyingParty::new(snp.verifier(SIM_NOW), false)
        .with_challenge_ttl(Duration::from_millis(1));
    short_ttl_rp.insert_tenant_key(tenant, &tenant_key);
    let challenge = short_ttl_rp.issue_challenge();
    tokio::time::sleep(Duration::from_millis(15)).await;
    let nonce: [u8; 32] = B64
        .decode(&challenge.nonce_b64)
        .unwrap()
        .try_into()
        .unwrap();
    let binding = ReportDataBinding {
        nonce,
        enclave_hpke_public_key: *identity.enclave_hpke_public_key(),
        result_signing_public_key: *identity.result_signing_public_key(),
        tls_cert_sha256: [0u8; 32],
        config_digest: [0u8; 32],
    };
    let evidence = snp
        .produce_evidence(&binding.to_report_data())
        .await
        .unwrap();
    assert!(
        short_ttl_rp
            .release_key(&KeyReleaseRequest {
                tenant_id: tenant.to_string(),
                nonce_b64: challenge.nonce_b64,
                report_b64: B64.encode(&evidence.report),
                cert_chain_b64: B64.encode(&evidence.cert_chain),
                enclave_hpke_public_key_b64: B64.encode(identity.enclave_hpke_public_key()),
                result_signing_public_key_b64: B64.encode(identity.result_signing_public_key()),
                tls_cert_sha256_b64: B64.encode([0u8; 32]),
                config_digest_b64: B64.encode([0u8; 32]),
            })
            .is_err(),
        "expired challenge must fail"
    );
}

#[tokio::test]
async fn query_endpoint_fails_closed_when_key_release_rejects_measurement_debug_or_unenrolled_tenant()
 {
    let tenant = TenantId::generate();
    let vault: Arc<dyn VaultStore> = Arc::new(ObjectStoreVault::new_in_memory());
    let keypair = TenantKeypair::generate();

    let good_snp = Arc::new(SimulatedSnp::new());
    let pipeline = EnclavePipeline::new(good_snp.clone(), vault.clone(), false);
    pipeline
        .run_sync(&SyncJob {
            tenant,
            tenant_public_key: keypair.public_key(),
            source: Arc::new(FixtureSource::quickbooks_demo().expect("fixture")),
        })
        .await
        .expect("seal");

    // Case 1: Enclave runs with a measurement not approved by the relying party.
    let bad_measurement_snp = Arc::new(SimulatedSnp::with_config(SimulatedSnpConfig {
        measurement: [0xEE; 48],
        ..SimulatedSnpConfig::default()
    }));
    let rp = Arc::new(KeyReleaseRelyingParty::new(
        good_snp.verifier(SIM_NOW),
        false,
    ));
    rp.insert_tenant_key(tenant, &keypair);
    let identity = Arc::new(EnclaveIdentity::generate());
    let bad_provider = Arc::new(AttestedKeyProvider::new(
        identity,
        bad_measurement_snp,
        Arc::new(InProcessKeyReleaseClient(rp)),
    ));
    let query = ConnectorQueryService::new(
        vault.clone(),
        bad_provider,
        good_snp.clone(),
        EngineSettings {
            zk: ZkMode::Disabled,
            max_concurrent_queries: 4,
        },
        false,
    );
    let app = build_app(AppState {
        config: Arc::new(PlatformConfig::from_source(|_| None).expect("config")),
        vault: vault.clone(),
        jwt: Some(Arc::new(JwtVerifier::hs256(SECRET, ISS, AUD))),
        query: Some(Arc::new(query)),
        provisioning: None,
    });
    let (status, _) = send(
        &app,
        "POST",
        "/api/v1/query",
        &[auth(&token_for(tenant)), json_header()],
        br#"{"connector":"quickbooks","sql":"SELECT COUNT(*) AS n FROM quickbooks"}"#.to_vec(),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);

    // Case 2: Relying party requires production AMD hardware (`require_hardware_sev_snp = true`),
    // rejecting `SimulatedSnp` evidence even if everything else matches.
    let prod_rp = Arc::new(KeyReleaseRelyingParty::new(
        good_snp.verifier(SIM_NOW),
        true,
    ));
    prod_rp.insert_tenant_key(tenant, &keypair);
    let prod_provider = Arc::new(AttestedKeyProvider::new(
        Arc::new(EnclaveIdentity::generate()),
        good_snp.clone(),
        Arc::new(InProcessKeyReleaseClient(prod_rp)),
    ));
    let prod_query = ConnectorQueryService::new(
        vault.clone(),
        prod_provider,
        good_snp.clone(),
        EngineSettings {
            zk: ZkMode::Disabled,
            max_concurrent_queries: 4,
        },
        false,
    );
    let prod_app = build_app(AppState {
        config: Arc::new(PlatformConfig::from_source(|_| None).expect("config")),
        vault: vault.clone(),
        jwt: Some(Arc::new(JwtVerifier::hs256(SECRET, ISS, AUD))),
        query: Some(Arc::new(prod_query)),
        provisioning: None,
    });
    let (status, _) = send(
        &prod_app,
        "POST",
        "/api/v1/query",
        &[auth(&token_for(tenant)), json_header()],
        br#"{"connector":"quickbooks","sql":"SELECT COUNT(*) AS n FROM quickbooks"}"#.to_vec(),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);

    // Case 3: Relying party configured with a mismatched ProductionAmd ARK root rejects the chain.
    let amd_root_rp = Arc::new(KeyReleaseRelyingParty::new(
        AttestationVerifier::new(
            TrustRoot::ProductionAmd {
                ark_public_keys_sec1: vec![vec![0x04; 97]],
            },
            SimulatedSnp::default_policy(SIM_NOW),
        ),
        false,
    ));
    amd_root_rp.insert_tenant_key(tenant, &keypair);
    let amd_root_provider = Arc::new(AttestedKeyProvider::new(
        Arc::new(EnclaveIdentity::generate()),
        good_snp.clone(),
        Arc::new(InProcessKeyReleaseClient(amd_root_rp)),
    ));
    let amd_root_query = ConnectorQueryService::new(
        vault.clone(),
        amd_root_provider,
        good_snp.clone(),
        EngineSettings {
            zk: ZkMode::Disabled,
            max_concurrent_queries: 4,
        },
        false,
    );
    let amd_root_app = build_app(AppState {
        config: Arc::new(PlatformConfig::from_source(|_| None).expect("config")),
        vault: vault.clone(),
        jwt: Some(Arc::new(JwtVerifier::hs256(SECRET, ISS, AUD))),
        query: Some(Arc::new(amd_root_query)),
        provisioning: None,
    });
    let (status, _) = send(
        &amd_root_app,
        "POST",
        "/api/v1/query",
        &[auth(&token_for(tenant)), json_header()],
        br#"{"connector":"quickbooks","sql":"SELECT COUNT(*) AS n FROM quickbooks"}"#.to_vec(),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);

    // Case 4: Tenant key not enrolled in the relying party -> fails closed with 503.
    let empty_rp = Arc::new(KeyReleaseRelyingParty::new(
        good_snp.verifier(SIM_NOW),
        false,
    ));
    let unenrolled_provider = Arc::new(AttestedKeyProvider::new(
        Arc::new(EnclaveIdentity::generate()),
        good_snp.clone(),
        Arc::new(InProcessKeyReleaseClient(empty_rp)),
    ));
    let unenrolled_query = ConnectorQueryService::new(
        vault.clone(),
        unenrolled_provider,
        good_snp,
        EngineSettings {
            zk: ZkMode::Disabled,
            max_concurrent_queries: 4,
        },
        false,
    );
    let unenrolled_app = build_app(AppState {
        config: Arc::new(PlatformConfig::from_source(|_| None).expect("config")),
        vault,
        jwt: Some(Arc::new(JwtVerifier::hs256(SECRET, ISS, AUD))),
        query: Some(Arc::new(unenrolled_query)),
        provisioning: None,
    });
    let (status, _) = send(
        &unenrolled_app,
        "POST",
        "/api/v1/query",
        &[auth(&token_for(tenant)), json_header()],
        br#"{"connector":"quickbooks","sql":"SELECT COUNT(*) AS n FROM quickbooks"}"#.to_vec(),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);

    // Case 5: GuestPolicy with DEBUG=1 is rejected by the relying party.
    let debug_snp = SimulatedSnp::with_config(SimulatedSnpConfig {
        policy: GuestPolicy::production_default().with_debug(true),
        ..SimulatedSnpConfig::default()
    });
    let debug_rp = Arc::new(KeyReleaseRelyingParty::new(
        debug_snp.verifier(SIM_NOW),
        false,
    ));
    debug_rp.insert_tenant_key(tenant, &keypair);
    let debug_client = InProcessKeyReleaseClient(debug_rp);
    let challenge = debug_client
        .issue_challenge()
        .await
        .ok()
        .expect("challenge");
    let nonce: [u8; 32] = B64
        .decode(&challenge.nonce_b64)
        .unwrap()
        .try_into()
        .unwrap();
    let debug_id = EnclaveIdentity::generate();
    let evidence = debug_snp
        .produce_evidence(&debug_id.binding_for_nonce(nonce).to_report_data())
        .await
        .unwrap();
    let res = debug_client
        .release_key(&KeyReleaseRequest {
            tenant_id: tenant.to_string(),
            nonce_b64: challenge.nonce_b64,
            report_b64: B64.encode(&evidence.report),
            cert_chain_b64: B64.encode(&evidence.cert_chain),
            enclave_hpke_public_key_b64: B64.encode(debug_id.enclave_hpke_public_key()),
            result_signing_public_key_b64: B64.encode(debug_id.result_signing_public_key()),
            tls_cert_sha256_b64: B64.encode([0u8; 32]),
            config_digest_b64: B64.encode([0u8; 32]),
        })
        .await;
    assert!(res.is_err());
}

#[tokio::test]
async fn cross_container_seed_derivation_and_env_tamper_refusal_over_http() {
    use platform_api::query::EnclaveKeyProvider as _;
    use platform_enclave::MEASUREMENT_BYTES;

    let tenant = TenantId::generate();
    let vault: Arc<dyn VaultStore> = Arc::new(ObjectStoreVault::new_in_memory());
    let keypair = TenantKeypair::generate();

    // Separate instances initialized purely via SIMULATED_SNP_SEED (as in separate Docker containers).
    let enclave_snp = Arc::new(SimulatedSnp::from_source(|k| match k {
        "SIMULATED_SNP_SEED" => Some("quackxide-docker-sim-seed-v1".into()),
        _ => None,
    }));
    let rp_snp = SimulatedSnp::from_source(|k| match k {
        "SIMULATED_SNP_SEED" => Some("quackxide-docker-sim-seed-v1".into()),
        _ => None,
    });

    // Seal synthetic QuickBooks data using enclave_snp.
    let pipeline = EnclavePipeline::new(enclave_snp.clone(), vault.clone(), false);
    pipeline
        .run_sync(&SyncJob {
            tenant,
            tenant_public_key: keypair.public_key(),
            source: Arc::new(FixtureSource::quickbooks_demo().expect("fixture")),
        })
        .await
        .expect("seal");

    // Start relying party HTTP server using rp_snp's derived ARK trust root.
    let rp = Arc::new(KeyReleaseRelyingParty::new(rp_snp.verifier(SIM_NOW), false));
    rp.insert_tenant_key(tenant, &keypair);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let rp_router = rp.router();
    tokio::spawn(async move {
        let _ = axum::serve(listener, rp_router).await;
    });
    let base_url = format!("http://{addr}");

    // 1. Happy path across containers: enclave_snp report verifies against rp_snp over HTTP.
    let identity = Arc::new(EnclaveIdentity::generate());
    let keys = Arc::new(AttestedKeyProvider::new(
        identity.clone(),
        enclave_snp.clone(),
        Arc::new(HttpKeyReleaseClient::new(&base_url)),
    ));
    let service = Arc::new(
        ConnectorQueryService::new(
            vault.clone(),
            keys,
            enclave_snp,
            EngineSettings {
                zk: ZkMode::Disabled,
                max_concurrent_queries: 4,
            },
            false,
        )
        .with_enclave_identity(identity),
    );
    let app = build_app(AppState {
        config: Arc::new(PlatformConfig::from_source(|_| None).expect("config")),
        vault: vault.clone(),
        jwt: Some(Arc::new(JwtVerifier::hs256(SECRET, ISS, AUD))),
        query: Some(service),
        provisioning: None,
    });
    let (status, _) = send(
        &app,
        "POST",
        "/api/v1/query",
        &[auth(&token_for(tenant)), json_header()],
        br#"{"connector":"quickbooks","sql":"SELECT COUNT(*) AS n FROM quickbooks"}"#.to_vec(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // 2. Container tampered measurement via SIMULATED_SNP_MEASUREMENT_HEX is refused over HTTP.
    let tampered_meas_snp = Arc::new(SimulatedSnp::from_source(|k| match k {
        "SIMULATED_SNP_SEED" => Some("quackxide-docker-sim-seed-v1".into()),
        "SIMULATED_SNP_MEASUREMENT_HEX" => Some("aa".repeat(MEASUREMENT_BYTES)),
        _ => None,
    }));
    let bad_meas_id = Arc::new(EnclaveIdentity::generate());
    let bad_meas_keys = AttestedKeyProvider::new(
        bad_meas_id,
        tampered_meas_snp,
        Arc::new(HttpKeyReleaseClient::new(&base_url)),
    );
    assert!(
        bad_meas_keys.begin_query_session(tenant).await.is_err(),
        "tampered SIMULATED_SNP_MEASUREMENT_HEX must be refused by relying party"
    );

    // 3. Container debug policy via SIMULATED_SNP_DEBUG=true is refused over HTTP.
    let debug_env_snp = Arc::new(SimulatedSnp::from_source(|k| match k {
        "SIMULATED_SNP_SEED" => Some("quackxide-docker-sim-seed-v1".into()),
        "SIMULATED_SNP_DEBUG" => Some("true".into()),
        _ => None,
    }));
    let debug_env_id = Arc::new(EnclaveIdentity::generate());
    let debug_env_keys = AttestedKeyProvider::new(
        debug_env_id,
        debug_env_snp,
        Arc::new(HttpKeyReleaseClient::new(&base_url)),
    );
    assert!(
        debug_env_keys.begin_query_session(tenant).await.is_err(),
        "SIMULATED_SNP_DEBUG=true must be refused by relying party"
    );
}
