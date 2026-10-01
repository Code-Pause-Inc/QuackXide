//! Confidential query endpoint over the full pipeline-to-engine stack: a
//! connector sync seals fixture data to a tenant key and the endpoint
//! queries it. Covers tenant isolation, the 503 fail-closed path, and the
//! ZK-mode policy gate.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use axum::response::IntoResponse;
use http_body_util::BodyExt;
use platform_api::query::{ConnectorQueryService, DevKeyProvider, EnclaveKeyProvider};
use platform_api::{ApiError, AppState, build_app};
use platform_auth::JwtVerifier;
use platform_config::PlatformConfig;
use platform_connectors::pipeline::{EnclavePipeline, SyncJob};
use platform_connectors::snapshot::{SnapshotManifest, SnapshotWriter, manifest_info};
use platform_connectors::source::FixtureSource;
use platform_core::{ConnectorSlug, TenantId, ZkMode};
use platform_crypto::{SecretBytes, TenantKeypair, hpke_seal_to_tenant};
use platform_enclave::DevAttestation;
use platform_storage::{ObjectStoreVault, TenantPaths, VaultStore};
use quackxide_engine::EngineSettings;
use tower::ServiceExt;

const SECRET: &str = "query-itest-secret";
const ISS: &str = "urn:platform:auth";
const AUD: &str = "urn:platform:drive";

fn token_for(tenant: TenantId) -> String {
    platform_auth::mint_token(SECRET, ISS, AUD, tenant, "itest", 3600).expect("mint")
}

/// Build an app whose vault already holds a QuickBooks sync sealed to
/// `tenant`, queryable via a dev key provider holding the matching keypair.
async fn app_with_sealed_quickbooks(tenant: TenantId, zk: ZkMode) -> Router {
    let vault: Arc<dyn VaultStore> = Arc::new(ObjectStoreVault::new_in_memory());
    let keypair = TenantKeypair::generate();

    // The connector pipeline seals the fixture into the vault.
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
    pipeline.run_sync(&job).await.expect("seal sync");

    let service = ConnectorQueryService::new(
        vault.clone(),
        Arc::new(DevKeyProvider::new(tenant, keypair)),
        Arc::new(DevAttestation::allow_insecure_dev()),
        EngineSettings {
            zk,
            max_concurrent_queries: 4,
        },
        false,
    )
    .with_min_cohort(2);

    let config = PlatformConfig::from_source(|_| None).expect("config");
    build_app(AppState {
        config: Arc::new(config),
        vault,
        jwt: Some(Arc::new(JwtVerifier::hs256(SECRET, ISS, AUD))),
        query: Some(Arc::new(service)),
        provisioning: None,
    })
}

async fn post_query(
    app: &Router,
    token: Option<&str>,
    body: &str,
) -> (StatusCode, serde_json::Value) {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/api/v1/query")
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let request = builder.body(Body::from(body.to_owned())).expect("request");
    let response = app.clone().oneshot(request).await.expect("response");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let json = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    };
    (status, json)
}

#[tokio::test]
async fn confidential_query_returns_aggregate_over_sealed_connector_data() {
    let tenant = TenantId::generate();
    let app = app_with_sealed_quickbooks(tenant, ZkMode::Disabled).await;
    let token = token_for(tenant);

    let (status, body) = post_query(
        &app,
        Some(&token),
        r#"{"connector":"quickbooks","sql":"SELECT currency, SUM(total) AS revenue FROM quickbooks GROUP BY currency ORDER BY currency"}"#,
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["object_count"], 1);
    assert_eq!(body["zk_mode"], false);
    let rows = body["rows"].as_array().expect("rows");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["currency"], "EUR");
    assert_eq!(rows[0]["revenue"], 99.99);
    assert_eq!(rows[1]["currency"], "USD");
    assert_eq!(rows[1]["revenue"], 1730.25);
}

#[tokio::test]
async fn query_requires_authentication() {
    let tenant = TenantId::generate();
    let app = app_with_sealed_quickbooks(tenant, ZkMode::Disabled).await;
    let (status, _) =
        post_query(&app, None, r#"{"connector":"quickbooks","sql":"SELECT 1"}"#).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn query_is_tenant_isolated() {
    let owner = TenantId::generate();
    let app = app_with_sealed_quickbooks(owner, ZkMode::Disabled).await;

    // A different tenant with a valid token sees no data (their connector
    // prefix is empty), and the key provider is never even asked to decrypt.
    let intruder = token_for(TenantId::generate());
    let (status, body) = post_query(
        &app,
        Some(&intruder),
        r#"{"connector":"quickbooks","sql":"SELECT SUM(total) AS revenue FROM quickbooks"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["object_count"], 0);
    assert_eq!(body["row_count"], 0);
    assert!(body["rows"].as_array().expect("rows").is_empty());
}

#[tokio::test]
async fn zk_mode_blocks_row_egress_at_the_endpoint() {
    let tenant = TenantId::generate();
    let app = app_with_sealed_quickbooks(tenant, ZkMode::Enabled).await;
    let token = token_for(tenant);

    // Aggregate is allowed under ZK mode.
    let (status, body) = post_query(
        &app,
        Some(&token),
        r#"{"connector":"quickbooks","sql":"SELECT COUNT(*) AS n FROM quickbooks"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["rows"][0]["n"], 3);
    assert_eq!(body["zk_mode"], true);

    // Cohorts below k = 2 (the single EUR invoice) are withheld.
    let (status, body) = post_query(
        &app,
        Some(&token),
        r#"{"connector":"quickbooks","sql":"SELECT currency, COUNT(*) AS n, SUM(total) AS revenue FROM quickbooks GROUP BY currency"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(
        body["rows"],
        serde_json::json!([{ "currency": "USD", "n": 2, "revenue": 1730.25 }])
    );
    assert_eq!(body["suppressed_rows"], 1);

    // Grouping by a unique key yields only sub-k cohorts: nothing egresses.
    let (status, body) = post_query(
        &app,
        Some(&token),
        r#"{"connector":"quickbooks","sql":"SELECT id, COUNT(*) AS n, MAX(total) AS t FROM quickbooks GROUP BY id"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["row_count"], 0);
    assert_eq!(body["suppressed_rows"], 3);

    // Aggregates without a genuine cohort size are rejected with 422.
    for sql in [
        "SELECT id, MAX(total) AS t FROM quickbooks GROUP BY id",
        "SELECT id, 9999 AS n FROM quickbooks GROUP BY id",
    ] {
        let body = serde_json::json!({ "connector": "quickbooks", "sql": sql }).to_string();
        let (status, _) = post_query(&app, Some(&token), &body).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{sql}");
    }

    // Row-level egress is rejected with 422.
    let (status, _) = post_query(
        &app,
        Some(&token),
        r#"{"connector":"quickbooks","sql":"SELECT id, total FROM quickbooks"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}

/// With ZK mode off nothing gates the plan, so the statement check alone
/// keeps decrypted rows off the host's disk.
#[tokio::test]
async fn copy_to_disk_is_refused_without_the_zk_gate() {
    let tenant = TenantId::generate();
    let app = app_with_sealed_quickbooks(tenant, ZkMode::Disabled).await;
    let token = token_for(tenant);
    let dir = std::env::temp_dir().join(format!("qx-copy-api-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let target = dir.join("out.csv");

    for sql in [
        format!(
            "COPY (SELECT * FROM quickbooks) TO '{}' STORED AS CSV",
            target.display()
        ),
        "CREATE TABLE copied AS SELECT * FROM quickbooks".to_owned(),
        "INSERT INTO quickbooks SELECT * FROM quickbooks".to_owned(),
    ] {
        let body = serde_json::json!({ "connector": "quickbooks", "sql": sql }).to_string();
        let (status, _) = post_query(&app, Some(&token), &body).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{sql}");
    }
    let written = target.exists();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(!written, "COPY wrote decrypted rows to disk");
}

#[tokio::test]
async fn query_unavailable_when_not_configured_returns_503() {
    let config = PlatformConfig::from_source(|_| None).expect("config");
    let app = build_app(AppState {
        config: Arc::new(config),
        vault: Arc::new(ObjectStoreVault::new_in_memory()),
        jwt: Some(Arc::new(JwtVerifier::hs256(SECRET, ISS, AUD))),
        query: None,
        provisioning: None,
    });
    let token = token_for(TenantId::generate());
    let (status, _) = post_query(
        &app,
        Some(&token),
        r#"{"connector":"quickbooks","sql":"SELECT 1"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn invalid_connector_slug_is_rejected() {
    let tenant = TenantId::generate();
    let app = app_with_sealed_quickbooks(tenant, ZkMode::Disabled).await;
    let token = token_for(tenant);
    let (status, _) = post_query(
        &app,
        Some(&token),
        r#"{"connector":"../etc","sql":"SELECT 1"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// Wraps the dev provider: tracks how many envelopes are being opened at
/// once (each open is held briefly so overlapping queries would show), and
/// can fail one chosen call.
struct ObservedKeys {
    inner: DevKeyProvider,
    calls: AtomicUsize,
    in_flight: AtomicUsize,
    max_in_flight: AtomicUsize,
    fail_on_call: Option<usize>,
}

#[async_trait]
impl EnclaveKeyProvider for ObservedKeys {
    async fn open_envelope(
        &self,
        tenant: TenantId,
        info: &[u8],
        envelope: &[u8],
    ) -> Result<SecretBytes, ApiError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if self.fail_on_call == Some(call) {
            return Err(ApiError::Backend);
        }
        let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_in_flight.fetch_max(now, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(50)).await;
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
        self.inner.open_envelope(tenant, info, envelope).await
    }
}

/// A query service over `syncs` sealed QuickBooks syncs for `tenant`.
async fn observed_service(
    tenant: TenantId,
    syncs: usize,
    max_concurrent_queries: usize,
    fail_on_call: Option<usize>,
) -> (ConnectorQueryService, Arc<ObservedKeys>) {
    let vault: Arc<dyn VaultStore> = Arc::new(ObjectStoreVault::new_in_memory());
    let keypair = TenantKeypair::generate();
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
    let keys = Arc::new(ObservedKeys {
        inner: DevKeyProvider::new(tenant, keypair),
        calls: AtomicUsize::new(0),
        in_flight: AtomicUsize::new(0),
        max_in_flight: AtomicUsize::new(0),
        fail_on_call,
    });
    let service = ConnectorQueryService::new(
        vault,
        keys.clone(),
        Arc::new(DevAttestation::allow_insecure_dev()),
        EngineSettings {
            zk: ZkMode::Disabled,
            max_concurrent_queries,
        },
        false,
    );
    (service, keys)
}

/// Status of an expected service error.
fn error_status(result: Result<serde_json::Value, ApiError>) -> StatusCode {
    match result {
        Ok(body) => panic!("expected an error, got {body}"),
        Err(err) => err.into_response().status(),
    }
}

const COUNT_SQL: &str = "SELECT COUNT(*) AS n FROM quickbooks";

async fn max_overlap_with_limit(limit: usize) -> usize {
    let tenant = TenantId::generate();
    let (service, keys) = observed_service(tenant, 1, limit, None).await;
    let connector = ConnectorSlug::new("quickbooks").expect("slug");
    let (a, b) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(
            service.query(tenant, &connector, COUNT_SQL),
            service.query(tenant, &connector, COUNT_SQL),
        )
    })
    .await
    .expect("queries must not deadlock");
    assert!(a.is_ok() && b.is_ok());
    keys.max_in_flight.load(Ordering::SeqCst)
}

#[tokio::test]
async fn max_concurrent_queries_bounds_plaintext_in_memory() {
    // The probe does observe overlap when the limit allows it...
    assert_eq!(max_overlap_with_limit(2).await, 2);
    // ...and a limit of 1 serializes decryption across queries.
    assert_eq!(max_overlap_with_limit(1).await, 1);
}

#[tokio::test]
async fn zero_query_limit_refuses_instead_of_hanging() {
    let tenant = TenantId::generate();
    let (service, keys) = observed_service(tenant, 1, 0, None).await;
    let connector = ConnectorSlug::new("quickbooks").expect("slug");
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        service.query(tenant, &connector, COUNT_SQL),
    )
    .await
    .expect("must not wait forever");
    assert_eq!(error_status(result), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(keys.calls.load(Ordering::SeqCst), 0, "nothing decrypted");
}

#[tokio::test]
async fn decryption_failure_midway_fails_closed_and_releases_the_slot() {
    let tenant = TenantId::generate();
    // A query opens the manifest, then the snapshot's object; the second
    // open fails after the manifest is already plaintext.
    let (service, keys) = observed_service(tenant, 2, 1, Some(2)).await;
    let connector = ConnectorSlug::new("quickbooks").expect("slug");

    let result = service.query(tenant, &connector, COUNT_SQL).await;
    assert_eq!(error_status(result), StatusCode::BAD_GATEWAY);

    // The only slot was released on the error path.
    let rows = tokio::time::timeout(
        Duration::from_secs(5),
        service.query(tenant, &connector, COUNT_SQL),
    )
    .await
    .expect("slot must be released")
    .map_err(|_| "query failed")
    .expect("second query");
    // Two syncs leave one snapshot: one manifest and one object per query.
    assert_eq!(rows["object_count"], 1);
    assert_eq!(keys.calls.load(Ordering::SeqCst), 4);
}

// ── Snapshots: repeated or interrupted syncs never change what a query reads ──

/// `syncs` full QuickBooks syncs into a fresh vault, sealed to `keypair`.
async fn synced_vault(
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

fn service_over(
    tenant: TenantId,
    keypair: TenantKeypair,
    vault: Arc<dyn VaultStore>,
    zk: ZkMode,
) -> ConnectorQueryService {
    ConnectorQueryService::new(
        vault,
        Arc::new(DevKeyProvider::new(tenant, keypair)),
        Arc::new(DevAttestation::allow_insecure_dev()),
        EngineSettings {
            zk,
            max_concurrent_queries: 4,
        },
        false,
    )
    .with_min_cohort(2)
}

const COHORT_SQL: &str =
    "SELECT currency, COUNT(*) AS n, SUM(total) AS revenue FROM quickbooks GROUP BY currency";

#[tokio::test]
async fn repeated_syncs_never_inflate_counts() {
    let connector = ConnectorSlug::new("quickbooks").expect("slug");
    for syncs in [1, 4] {
        let tenant = TenantId::generate();
        let keypair = TenantKeypair::generate();
        let vault = synced_vault(tenant, &keypair, syncs).await;
        let service = service_over(tenant, keypair, vault, ZkMode::Enabled);

        let rows = service
            .query(tenant, &connector, COUNT_SQL)
            .await
            .map_err(|_| "query failed")
            .expect("count");
        assert_eq!(rows["rows"][0]["n"], 3, "after {syncs} syncs");
        assert_eq!(rows["object_count"], 1, "after {syncs} syncs");

        // The single EUR invoice stays below k = 2 however many syncs ran.
        let rows = service
            .query(tenant, &connector, COHORT_SQL)
            .await
            .map_err(|_| "query failed")
            .expect("cohorts");
        assert_eq!(
            rows["rows"],
            serde_json::json!([{ "currency": "USD", "n": 2, "revenue": 1730.25 }]),
            "after {syncs} syncs"
        );
        assert_eq!(rows["suppressed_rows"], 1, "after {syncs} syncs");
    }
}

#[tokio::test]
async fn superseded_snapshots_are_pruned() {
    let tenant = TenantId::generate();
    let keypair = TenantKeypair::generate();
    let vault = synced_vault(tenant, &keypair, 3).await;
    let connector = ConnectorSlug::new("quickbooks").expect("slug");
    let manifests = vault
        .list(&TenantPaths::connector_manifests_prefix(tenant, &connector))
        .await
        .expect("list");
    let objects = vault
        .list(&TenantPaths::connector_snapshots_prefix(tenant, &connector))
        .await
        .expect("list");
    assert_eq!((manifests.len(), objects.len()), (1, 1));
}

#[tokio::test]
async fn an_uncommitted_sync_changes_nothing_queries_see() {
    let tenant = TenantId::generate();
    let keypair = TenantKeypair::generate();
    let vault = synced_vault(tenant, &keypair, 1).await;
    let connector = ConnectorSlug::new("quickbooks").expect("slug");

    // A second sync that dies after writing its object, before its manifest.
    let public_key = keypair.public_key();
    let mut interrupted = SnapshotWriter::begin(&*vault, tenant, &public_key, connector.clone());
    let fixture = vault
        .list(&TenantPaths::connector_snapshots_prefix(tenant, &connector))
        .await
        .expect("list");
    assert_eq!(fixture.len(), 1);
    interrupted
        .put("invoices", b"not reached by any query")
        .await
        .expect("put");
    drop(interrupted);

    let service = service_over(tenant, keypair, vault, ZkMode::Disabled);
    let rows = service
        .query(tenant, &connector, COUNT_SQL)
        .await
        .map_err(|_| "query failed")
        .expect("count");
    assert_eq!(rows["rows"][0]["n"], 3);
    assert_eq!(rows["object_count"], 1);
}

#[tokio::test]
async fn a_manifest_listing_an_object_twice_fails_closed() {
    let tenant = TenantId::generate();
    let keypair = TenantKeypair::generate();
    let vault = synced_vault(tenant, &keypair, 1).await;
    let connector = ConnectorSlug::new("quickbooks").expect("slug");
    let manifest_path = vault
        .list(&TenantPaths::connector_manifests_prefix(tenant, &connector))
        .await
        .expect("list")
        .remove(0);
    let version = TenantPaths::connector_manifest_version(tenant, &connector, &manifest_path)
        .expect("version");
    let object = vault
        .list(&TenantPaths::connector_snapshots_prefix(tenant, &connector))
        .await
        .expect("list")
        .into_iter()
        .find_map(|path| TenantPaths::connector_snapshot_object_parts(tenant, &connector, &path))
        .expect("object")
        .1;

    // Re-seal the manifest so it lists the one object twice.
    let doubled = SnapshotManifest {
        version: version.clone(),
        objects: vec![object, object],
    };
    let envelope = hpke_seal_to_tenant(
        &keypair.public_key(),
        &manifest_info(&tenant, &connector, &version),
        &serde_json::to_vec(&doubled).expect("json"),
    )
    .expect("seal");
    vault
        .put(&manifest_path, envelope.into())
        .await
        .expect("put");

    let service = service_over(tenant, keypair, vault, ZkMode::Disabled);
    let result = service.query(tenant, &connector, COUNT_SQL).await;
    assert_eq!(error_status(result), StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn grant_routes_without_research_config_report_research_unavailable() {
    let tenant = TenantId::generate();
    let app = app_with_sealed_quickbooks(tenant, ZkMode::Disabled).await;
    let request = Request::builder()
        .method("GET")
        .uri("/api/v1/grants")
        .header(
            header::AUTHORIZATION,
            format!("Bearer {}", token_for(tenant)),
        )
        .body(Body::empty())
        .expect("request");
    let response = app.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    assert_eq!(body["error"], "research access not configured");
}
