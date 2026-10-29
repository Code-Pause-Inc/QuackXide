//! Integration tests for the simulated TEE's token-gated key release:
//! - Public enclave attestation endpoint (`GET /api/v1/attestation`) (`P85`)
//! - The key-release stand-in (`KeyReleaseRelyingParty`, its clients and
//!   `AttestedKeyProvider`), verifying simulated Confidential Space tokens
//!   (ADR 0004, P47)
//! - Once-per-query key release session scoping (`QueryKeySession`)

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;

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
    AttestationBundle, AttestedKeyProvider, EnclaveIdentity, HttpKeyReleaseClient, HttpKeySource,
    InProcessKeyReleaseClient, KeyReleaseRelyingParty, KeyReleaseRequest, KeySource,
    StaticKeySource, sim_attestation_router,
};
use platform_api::query::ConnectorQueryService;
use platform_api::research::ResearchStores;
use platform_api::{AppState, build_app};
use platform_auth::JwtVerifier;
use platform_config::PlatformConfig;
use platform_connectors::snapshot::SnapshotWriter;
use platform_core::{ConnectorSlug, TenantId, ZkMode};
use platform_crypto::{TenantKeypair, TenantPublicKey};
use platform_enclave::AttestationProvider;
use platform_enclave::simulated_token::{
    SIMULATED_IMAGE_DIGEST, SimulatedClaims, SimulatedTokenProvider, TokenSigner,
};
use platform_enclave::token::{
    JwkSet, ReleasePolicy, SIMULATED_AUDIENCE, TokenError, TokenVerifier, nonces_from_bytes,
};
use platform_storage::{ObjectStoreVault, VaultStore};
use platform_tenancy::InMemoryTenantRegistry;
use quackxide_engine::EngineSettings;
use tokio::net::TcpListener;
use tower::ServiceExt;

const SECRET: &str = "key-release-itest-secret";
const ISS: &str = "urn:platform:auth";
const AUD: &str = "urn:platform:drive";
const SIM_ISSUER: &str = "http://sim-attestation.test";
const MARKER: &str = "MARKERxMARKERxMARKER";

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

fn signer() -> &'static TokenSigner {
    static SIGNER: OnceLock<TokenSigner> = OnceLock::new();
    SIGNER.get_or_init(|| TokenSigner::generate(SIM_ISSUER, SimulatedClaims::default()))
}

fn rotated_signer() -> &'static TokenSigner {
    static SIGNER: OnceLock<TokenSigner> = OnceLock::new();
    SIGNER.get_or_init(|| TokenSigner::generate(SIM_ISSUER, SimulatedClaims::default()))
}

fn policy() -> ReleasePolicy {
    ReleasePolicy {
        allowed_image_digests: vec![SIMULATED_IMAGE_DIGEST.into()],
    }
}

fn provider(claims: SimulatedClaims) -> Arc<SimulatedTokenProvider> {
    Arc::new(SimulatedTokenProvider::in_process(
        Arc::new(signer().with_claims(claims)),
        policy(),
    ))
}

fn relying_party(source: Arc<dyn KeySource>) -> Arc<KeyReleaseRelyingParty> {
    Arc::new(KeyReleaseRelyingParty::new(source, SIM_ISSUER, policy()))
}

fn static_rp() -> Arc<KeyReleaseRelyingParty> {
    relying_party(Arc::new(StaticKeySource(signer().jwks())))
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A release request for `tenant` bound to `identity` and the challenge
/// `nonce_b64`, carrying `token`.
fn request(
    tenant: TenantId,
    identity: &EnclaveIdentity,
    nonce_b64: &str,
    token: String,
) -> KeyReleaseRequest {
    KeyReleaseRequest {
        tenant_id: tenant.to_string(),
        nonce_b64: nonce_b64.to_owned(),
        token,
        enclave_hpke_public_key_b64: B64.encode(identity.enclave_hpke_public_key()),
        result_signing_public_key_b64: B64.encode(identity.result_signing_public_key()),
        tls_cert_sha256_b64: B64.encode(identity.tls_cert_sha256()),
        config_digest_b64: B64.encode(identity.config_digest()),
    }
}

fn binding_nonces(identity: &EnclaveIdentity, nonce_b64: &str) -> Vec<String> {
    let nonce: [u8; 32] = B64.decode(nonce_b64).unwrap().try_into().unwrap();
    nonces_from_bytes(&identity.binding_for_nonce(nonce).to_report_data()).unwrap()
}

/// Ask `rp` to release `tenant`'s key with a token from `token_signer`.
async fn release_with(
    rp: &KeyReleaseRelyingParty,
    token_signer: &TokenSigner,
    tenant: TenantId,
) -> Result<(), &'static str> {
    let identity = EnclaveIdentity::generate();
    let challenge = rp.issue_challenge();
    let nonces = binding_nonces(&identity, &challenge.nonce_b64);
    let token = token_signer.sign(SIMULATED_AUDIENCE, &nonces, Duration::from_secs(600));
    rp.release_key(&request(tenant, &identity, &challenge.nonce_b64, token))
        .await
        .map(|_| ())
        .map_err(|_| "refused")
}

fn enrolled(rp: &KeyReleaseRelyingParty) -> TenantId {
    let tenant = TenantId::generate();
    rp.insert_tenant_key(tenant, &TenantKeypair::generate());
    tenant
}

/// A key source that serves `first`, then `then` on every later fetch.
struct RotatingSource {
    first: JwkSet,
    then: JwkSet,
    fetches: AtomicUsize,
}

#[async_trait]
impl KeySource for RotatingSource {
    async fn fetch(&self) -> Result<JwkSet, TokenError> {
        let n = self.fetches.fetch_add(1, Ordering::SeqCst);
        Ok(if n == 0 {
            self.first.clone()
        } else {
            self.then.clone()
        })
    }
}

struct UnreachableSource;

#[async_trait]
impl KeySource for UnreachableSource {
    async fn fetch(&self) -> Result<JwkSet, TokenError> {
        Err(TokenError::KeySetUnavailable)
    }
}

#[tokio::test]
async fn attestation_endpoint_returns_a_token_bound_to_caller_nonce_and_identity() {
    let vault: Arc<dyn VaultStore> = Arc::new(ObjectStoreVault::new_in_memory());
    let attestation = provider(SimulatedClaims::default());
    let identity = Arc::new(EnclaveIdentity::with_metadata([0x11; 32], [0x42; 32]));
    let key_provider = Arc::new(AttestedKeyProvider::new(
        identity.clone(),
        attestation.clone(),
        Arc::new(InProcessKeyReleaseClient(static_rp())),
    ));
    let query = ConnectorQueryService::new(
        vault.clone(),
        key_provider,
        attestation,
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
    let (status, body) = send(
        &app,
        "GET",
        &format!("/api/v1/attestation?nonce_b64={}", B64.encode(nonce)),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let bundle: AttestationBundle = serde_json::from_slice(&body).expect("json");
    assert_eq!(bundle.platform, "simulated");
    assert_eq!(bundle.tls_cert_sha256_b64, B64.encode([0x11; 32]));
    assert_eq!(bundle.config_digest_b64, B64.encode([0x42; 32]));
    assert_eq!(
        bundle.enclave_hpke_public_key_b64,
        B64.encode(identity.enclave_hpke_public_key())
    );

    // The token verifies against the signer's keys, bound to the caller's
    // nonce and the enclave's keys.
    let verifier =
        TokenVerifier::new(&signer().jwks(), SIM_ISSUER, SIMULATED_AUDIENCE, policy()).unwrap();
    let expected = nonces_from_bytes(&identity.binding_for_nonce(nonce).to_report_data()).unwrap();
    verifier
        .verify(&bundle.token, &expected)
        .expect("bundle token must verify");

    for bad in ["not-valid-base64!!!".to_owned(), B64.encode([1u8; 16])] {
        let (status, _) = send(
            &app,
            "GET",
            &format!("/api/v1/attestation?nonce_b64={bad}"),
            &[],
            Vec::new(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
async fn end_to_end_query_and_research_query_over_http_key_release_and_once_per_query_session() {
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let vault: Arc<dyn VaultStore> = Arc::new(ObjectStoreVault::new_in_memory());
    let steward_key = TenantKeypair::generate();

    // Seal a 3-object snapshot so we can prove key release happens ONCE per query,
    // not 1 (manifest) + 3 (objects) = 4 times.
    let attestation = provider(SimulatedClaims::default());
    let slug = ConnectorSlug::new("quickbooks").unwrap();
    let steward_pk = steward_key.public_key();
    let mut snapshot = SnapshotWriter::begin(&*vault, steward, &steward_pk, slug.clone());
    for (name, start) in [
        ("invoices_part1", 1),
        ("invoices_part2", 6),
        ("invoices_part3", 11),
    ] {
        snapshot
            .put(name, &sample_parquet_batch(start, 5))
            .await
            .expect("put");
    }
    snapshot.commit().await.expect("commit 3-object snapshot");

    // The stand-in on an ephemeral local TCP port.
    let rp = static_rp();
    rp.insert_tenant_key(steward, &steward_key);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let rp_router = rp.clone().router();
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, rp_router).await;
    });

    let identity = Arc::new(EnclaveIdentity::generate());
    let key_provider = Arc::new(AttestedKeyProvider::new(
        identity.clone(),
        attestation.clone(),
        Arc::new(HttpKeyReleaseClient::new(format!("http://{addr}"))),
    ));
    let query = ConnectorQueryService::new(
        vault.clone(),
        key_provider.clone(),
        attestation,
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
    assert_eq!(parsed["rows"][0]["n"], 15);
    assert_eq!(parsed["rows"][0]["total"], 15_000);
    // One manifest + three objects opened, one key release.
    assert_eq!(key_provider.release_count(), 1);
    assert_eq!(rp.release_count(), 1);

    let grant = serde_json::json!({
        "researcher_tenant": researcher.to_string(),
        "connector": "quickbooks"
    });
    let (status, _) = send(
        &app,
        "POST",
        "/api/v1/grants",
        &[auth(&token_for(steward)), json_header()],
        serde_json::to_vec(&grant).unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let research = serde_json::json!({
        "steward_tenant": steward.to_string(),
        "connector": "quickbooks",
        "sql": "SELECT status, COUNT(*) AS n FROM quickbooks GROUP BY status"
    });
    let (status, body) = send(
        &app,
        "POST",
        "/api/v1/research/query",
        &[auth(&token_for(researcher)), json_header()],
        serde_json::to_vec(&research).unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    assert_eq!(key_provider.release_count(), 2);
    assert_eq!(rp.release_count(), 2);

    server.abort();
}

#[tokio::test]
async fn release_succeeds_with_a_valid_token() {
    let rp = static_rp();
    let tenant = enrolled(&rp);
    release_with(&rp, signer(), tenant).await.expect("release");
    assert_eq!(rp.release_count(), 1);
}

#[tokio::test]
async fn replayed_challenge_is_refused() {
    let rp = static_rp();
    let tenant = enrolled(&rp);
    let identity = EnclaveIdentity::generate();
    let challenge = rp.issue_challenge();
    let nonces = binding_nonces(&identity, &challenge.nonce_b64);
    let token = signer().sign(SIMULATED_AUDIENCE, &nonces, Duration::from_secs(600));
    let req = request(tenant, &identity, &challenge.nonce_b64, token);
    assert!(rp.release_key(&req).await.is_ok(), "first use");
    assert!(
        rp.release_key(&req).await.is_err(),
        "replay must be refused"
    );
}

#[tokio::test]
async fn token_bound_to_other_keys_is_refused() {
    let rp = static_rp();
    let tenant = enrolled(&rp);
    let attested = EnclaveIdentity::generate();
    let attacker = EnclaveIdentity::generate();
    let challenge = rp.issue_challenge();
    let nonces = binding_nonces(&attested, &challenge.nonce_b64);
    let token = signer().sign(SIMULATED_AUDIENCE, &nonces, Duration::from_secs(600));
    // Same token, but the release asks for the key to be sealed to the attacker's key.
    let req = request(tenant, &attacker, &challenge.nonce_b64, token);
    assert!(rp.release_key(&req).await.is_err());
    assert_eq!(rp.release_count(), 0);
}

async fn refused_for(claims: SimulatedClaims) {
    let rp = static_rp();
    let tenant = enrolled(&rp);
    assert!(
        release_with(&rp, &signer().with_claims(claims), tenant)
            .await
            .is_err()
    );
    assert_eq!(rp.release_count(), 0);
}

#[tokio::test]
async fn debug_token_is_refused() {
    refused_for(SimulatedClaims {
        dbgstat: "enabled".into(),
        ..SimulatedClaims::default()
    })
    .await;
}

#[tokio::test]
async fn wrong_image_digest_is_refused() {
    refused_for(SimulatedClaims {
        image_digest: format!("sha256:{}", "0".repeat(64)),
        ..SimulatedClaims::default()
    })
    .await;
}

#[tokio::test]
async fn non_tdx_token_is_refused() {
    refused_for(SimulatedClaims {
        hwmodel: "GCP_AMD_SEV".into(),
        ..SimulatedClaims::default()
    })
    .await;
}

#[tokio::test]
async fn expired_token_is_refused() {
    let rp = static_rp();
    let tenant = enrolled(&rp);
    let identity = EnclaveIdentity::generate();
    let challenge = rp.issue_challenge();
    let nonces = binding_nonces(&identity, &challenge.nonce_b64);
    let token = signer().sign_at(
        SIMULATED_AUDIENCE,
        &nonces,
        now() - 7200,
        Duration::from_secs(60),
    );
    let req = request(tenant, &identity, &challenge.nonce_b64, token);
    assert!(rp.release_key(&req).await.is_err());
}

#[tokio::test]
async fn unknown_kid_refetches_once_then_succeeds() {
    let source = Arc::new(RotatingSource {
        first: signer().jwks(),
        then: rotated_signer().jwks(),
        fetches: AtomicUsize::new(0),
    });
    let rp = Arc::new(
        KeyReleaseRelyingParty::new(source.clone(), SIM_ISSUER, policy())
            .with_refetch_interval(Duration::ZERO),
    );
    let tenant = enrolled(&rp);
    release_with(&rp, signer(), tenant).await.expect("old key");
    // The simulator restarted with a new key.
    release_with(&rp, rotated_signer(), tenant)
        .await
        .expect("refetched key");
    assert_eq!(source.fetches.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn unknown_kid_after_refetch_is_refused() {
    let source = Arc::new(RotatingSource {
        first: signer().jwks(),
        then: signer().jwks(),
        fetches: AtomicUsize::new(0),
    });
    let rp = Arc::new(KeyReleaseRelyingParty::new(
        source.clone(),
        SIM_ISSUER,
        policy(),
    ));
    let tenant = enrolled(&rp);
    assert!(release_with(&rp, rotated_signer(), tenant).await.is_err());
    // A second unknown key inside the refetch interval does not fetch again.
    assert!(release_with(&rp, rotated_signer(), tenant).await.is_err());
    assert_eq!(source.fetches.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn unreachable_key_set_is_refused_and_audited_as_failed() {
    let capture = platform_telemetry::capture::AuditCapture::install();
    let rp = relying_party(Arc::new(UnreachableSource));
    let tenant = enrolled(&rp);
    assert!(release_with(&rp, signer(), tenant).await.is_err());
    assert!(
        capture.contains("crypto.key_release", "failed"),
        "{:?}",
        capture.events()
    );
}

async fn post_release(rp: Arc<KeyReleaseRelyingParty>, body: Vec<u8>) -> (StatusCode, Vec<u8>) {
    send(&rp.router(), "POST", "/v1/release", &[json_header()], body).await
}

#[tokio::test]
async fn oversized_release_body_is_refused() {
    let rp = static_rp();
    let tenant = enrolled(&rp);
    let identity = EnclaveIdentity::generate();
    let challenge = rp.issue_challenge();
    let req = request(
        tenant,
        &identity,
        &challenge.nonce_b64,
        "a".repeat(16 * 1024 + 1),
    );
    let (status, _) = post_release(rp.clone(), serde_json::to_vec(&req).unwrap()).await;
    assert!(!status.is_success(), "{status}");
    assert_eq!(rp.release_count(), 0);
}

#[tokio::test]
async fn refusal_bodies_carry_no_token_text() {
    let rp = static_rp();
    let tenant = enrolled(&rp);
    let identity = EnclaveIdentity::generate();
    let challenge = rp.issue_challenge();
    for token in [
        format!("{MARKER}.{MARKER}.{MARKER}"),
        signer().sign(
            SIMULATED_AUDIENCE,
            &[MARKER.to_owned()],
            Duration::from_secs(600),
        ),
    ] {
        let req = request(tenant, &identity, &challenge.nonce_b64, token);
        let (status, body) = post_release(rp.clone(), serde_json::to_vec(&req).unwrap()).await;
        assert!(!status.is_success());
        assert!(!String::from_utf8_lossy(&body).contains("MARKER"));
    }
}

#[tokio::test]
async fn enroll_returns_the_public_key() {
    let rp = static_rp();
    let keypair = TenantKeypair::generate();
    let body = serde_json::json!({
        "tenant_id": TenantId::generate().to_string(),
        "private_key_b64": B64.encode(keypair.to_private_key_bytes().expose()),
    });
    let (status, body) = send(
        &rp.router(),
        "PUT",
        "/v1/keys",
        &[json_header()],
        serde_json::to_vec(&body).unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let public = B64
        .decode(parsed["public_key_b64"].as_str().unwrap())
        .unwrap();
    assert_eq!(
        TenantPublicKey::from_raw(&public).unwrap().to_raw(),
        keypair.public_key().to_raw()
    );
}

#[tokio::test]
async fn http_sim_attestation_service_serves_tokens_and_keys_end_to_end() {
    // The sim-attestation service over HTTP, as in the compose stack.
    let sim = Arc::new(TokenSigner::generate(
        SIM_ISSUER,
        SimulatedClaims::default(),
    ));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let base = format!("http://{}", listener.local_addr().unwrap());
    let router = sim_attestation_router(sim);
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });

    let attestation = SimulatedTokenProvider::from_url(&base, SIM_ISSUER, policy());
    let rp = relying_party(Arc::new(HttpKeySource::new(&base)));
    let tenant = enrolled(&rp);
    let identity = Arc::new(EnclaveIdentity::generate());
    let key_provider = AttestedKeyProvider::new(
        identity,
        Arc::new(attestation),
        Arc::new(InProcessKeyReleaseClient(rp.clone())),
    );
    use platform_api::query::EnclaveKeyProvider as _;
    assert!(
        key_provider.begin_query_session(tenant).await.is_ok(),
        "release over HTTP"
    );
    assert_eq!(rp.release_count(), 1);

    // The provider's own check passes against the fetched keys too.
    let gate_provider = SimulatedTokenProvider::from_url(&base, SIM_ISSUER, policy());
    let evidence = gate_provider.produce_evidence(&[3u8; 32]).await.unwrap();
    gate_provider
        .verify_evidence(&evidence, &[3u8; 32])
        .unwrap();

    server.abort();
}

#[tokio::test]
async fn unenrolled_tenant_is_refused() {
    let rp = static_rp();
    assert!(
        release_with(&rp, signer(), TenantId::generate())
            .await
            .is_err()
    );
    assert_eq!(rp.release_count(), 0);
}
