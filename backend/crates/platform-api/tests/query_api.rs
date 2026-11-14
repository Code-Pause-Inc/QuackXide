//! Confidential query endpoint over the full pipeline-to-engine stack: a
//! connector sync seals fixture data to a tenant key and the endpoint
//! queries it. Covers tenant isolation, the 503 fail-closed path, the
//! ZK-mode policy gate, and the per-query resource limits: each refusal's
//! status, that the plaintext slot comes back after every way a query ends,
//! and what a refused research query costs.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use axum::Router;
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use bytes::Bytes;
use platform_api::query::{ConnectorQueryService, DevKeyProvider, EnclaveKeyProvider};
use platform_api::research::{ResearchService, ResearchStores};
use platform_api::{ApiError, AppState, build_app};
use platform_connectors::snapshot::{SnapshotManifest, SnapshotWriter, manifest_info};
use platform_connectors::upload::MAX_MANIFEST_BYTES;
use platform_core::{ConnectorSlug, TenantId, ZkMode};
use platform_crypto::{SecretBytes, TenantKeypair, hpke_seal_to_tenant};
use platform_enclave::{AttestationProvider, DevAttestation};
use platform_storage::{
    ObjectStoreVault, SnapshotRecord, StorageError, StorageUsage, TenantPaths, VaultEntry,
    VaultPath, VaultStore,
};
use quackxide_engine::{EngineSettings, QueryLimits};

use common::{app_state, bearer, dev_attestation, post_query, send, synced_vault};

const SECRET: &str = "query-itest-secret";

fn token_for(tenant: TenantId) -> String {
    common::token_for(SECRET, tenant)
}

/// Build an app whose vault already holds a QuickBooks sync sealed to
/// `tenant`, queryable via a dev key provider holding the matching keypair.
async fn app_with_sealed_quickbooks(tenant: TenantId, zk: ZkMode) -> Router {
    app_with_attestation(tenant, zk, dev_attestation(), false).await
}

/// As [`app_with_sealed_quickbooks`], with the query gate's attestation.
async fn app_with_attestation(
    tenant: TenantId,
    zk: ZkMode,
    attestation: Arc<dyn AttestationProvider>,
    require_attestation: bool,
) -> Router {
    let keypair = TenantKeypair::generate();
    let vault = synced_vault(tenant, &keypair, 1).await;
    let service = ConnectorQueryService::new(
        vault.clone(),
        Arc::new(DevKeyProvider::new(tenant, keypair)),
        attestation,
        EngineSettings {
            zk,
            max_concurrent_queries: 4,
            limits: QueryLimits::default(),
        },
        require_attestation,
    )
    .with_min_cohort(2);

    build_app(AppState {
        query: Some(Arc::new(service)),
        ..app_state(SECRET, vault)
    })
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

fn simulated_token_provider() -> Arc<platform_enclave::simulated_token::SimulatedTokenProvider> {
    use platform_enclave::simulated_token::{
        SIMULATED_IMAGE_DIGEST, SimulatedClaims, SimulatedTokenProvider, TokenSigner,
    };
    let signer = TokenSigner::generate("urn:query:sim", SimulatedClaims::default());
    Arc::new(SimulatedTokenProvider::in_process(
        Arc::new(signer),
        platform_enclave::token::ReleasePolicy {
            allowed_image_digests: vec![SIMULATED_IMAGE_DIGEST.into()],
        },
    ))
}

#[tokio::test]
async fn query_response_names_the_tee_platform() {
    let tenant = TenantId::generate();
    let token = token_for(tenant);
    let sql = r#"{"connector":"quickbooks","sql":"SELECT COUNT(*) AS n FROM quickbooks"}"#;

    let simulated =
        app_with_attestation(tenant, ZkMode::Disabled, simulated_token_provider(), false).await;
    let (status, body) = post_query(&simulated, Some(&token), sql).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["tee_platform"], "simulated");

    let dev = app_with_sealed_quickbooks(tenant, ZkMode::Disabled).await;
    let (status, body) = post_query(&dev, Some(&token), sql).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["tee_platform"], "development");
}

#[tokio::test]
async fn query_is_refused_when_attestation_is_required_and_fails() {
    // No evidence at all, then development evidence where SEV-SNP is required.
    let providers: [Arc<dyn AttestationProvider>; 2] = [
        Arc::new(DevAttestation::strict()),
        Arc::new(DevAttestation::allow_insecure_dev()),
    ];
    for provider in providers {
        let tenant = TenantId::generate();
        let app = app_with_attestation(tenant, ZkMode::Disabled, provider, true).await;
        let (status, body) = post_query(
            &app,
            Some(&token_for(tenant)),
            r#"{"connector":"quickbooks","sql":"SELECT COUNT(*) AS n FROM quickbooks"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "body: {body}");
        assert_eq!(body["error"], "enclave attestation unavailable");
    }
}

#[tokio::test]
async fn query_refuses_every_tampered_simulated_token() {
    use platform_enclave::simulated_token::{
        SIMULATED_IMAGE_DIGEST, SimulatedClaims, Tamper, TamperedTokenProvider, TokenSigner,
    };
    use platform_enclave::token::ReleasePolicy;

    let signer = Arc::new(TokenSigner::generate(
        "urn:query:sim",
        SimulatedClaims::default(),
    ));
    for tamper in Tamper::ALL {
        let provider = TamperedTokenProvider::new(
            signer.clone(),
            ReleasePolicy {
                allowed_image_digests: vec![SIMULATED_IMAGE_DIGEST.into()],
            },
            tamper,
        );
        let tenant = TenantId::generate();
        let app = app_with_attestation(tenant, ZkMode::Disabled, Arc::new(provider), false).await;
        let (status, body) = post_query(
            &app,
            Some(&token_for(tenant)),
            r#"{"connector":"quickbooks","sql":"SELECT COUNT(*) AS n FROM quickbooks"}"#,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "{tamper:?}: {body}"
        );
        assert_eq!(
            body["error"], "enclave attestation unavailable",
            "{tamper:?}"
        );
    }
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
    let app = build_app(app_state(
        SECRET,
        Arc::new(ObjectStoreVault::new_in_memory()),
    ));
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
/// can fail one chosen call or hold it open for longer.
struct ObservedKeys {
    inner: DevKeyProvider,
    calls: AtomicUsize,
    in_flight: AtomicUsize,
    max_in_flight: AtomicUsize,
    fail_on_call: Option<usize>,
    slow_call: Option<(usize, Duration)>,
}

/// Counts one open in flight until it finishes or is dropped.
struct InFlight<'a>(&'a AtomicUsize);

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
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
        let _in_flight = InFlight(&self.in_flight);
        self.max_in_flight.fetch_max(now, Ordering::SeqCst);
        let hold = match self.slow_call {
            Some((slow, hold)) if slow == call => hold,
            _ => Duration::from_millis(50),
        };
        tokio::time::sleep(hold).await;
        self.inner.open_envelope(tenant, info, envelope).await
    }
}

/// How [`observed`] builds its query service.
struct Observe {
    max_concurrent_queries: usize,
    limits: QueryLimits,
    fail_on_call: Option<usize>,
    slow_call: Option<(usize, Duration)>,
}

impl Default for Observe {
    fn default() -> Self {
        Self {
            max_concurrent_queries: 4,
            limits: QueryLimits::default(),
            fail_on_call: None,
            slow_call: None,
        }
    }
}

/// A query service (ZK off) over `vault`, which holds data sealed to
/// `keypair` for `tenant`, opening keys through [`ObservedKeys`].
fn observed(
    tenant: TenantId,
    keypair: TenantKeypair,
    vault: Arc<dyn VaultStore>,
    observe: Observe,
    attestation: Arc<dyn AttestationProvider>,
    require_attestation: bool,
) -> (ConnectorQueryService, Arc<ObservedKeys>) {
    let keys = Arc::new(ObservedKeys {
        inner: DevKeyProvider::new(tenant, keypair),
        calls: AtomicUsize::new(0),
        in_flight: AtomicUsize::new(0),
        max_in_flight: AtomicUsize::new(0),
        fail_on_call: observe.fail_on_call,
        slow_call: observe.slow_call,
    });
    let service = ConnectorQueryService::new(
        vault,
        keys.clone(),
        attestation,
        EngineSettings {
            zk: ZkMode::Disabled,
            max_concurrent_queries: observe.max_concurrent_queries,
            limits: observe.limits,
        },
        require_attestation,
    );
    (service, keys)
}

/// A query service over `syncs` sealed QuickBooks syncs for `tenant`.
async fn observed_service(
    tenant: TenantId,
    syncs: usize,
    max_concurrent_queries: usize,
    fail_on_call: Option<usize>,
) -> (ConnectorQueryService, Arc<ObservedKeys>) {
    observed_service_with_attestation(
        tenant,
        syncs,
        max_concurrent_queries,
        fail_on_call,
        dev_attestation(),
        false,
    )
    .await
}

/// As [`observed_service`], with the query gate's attestation.
async fn observed_service_with_attestation(
    tenant: TenantId,
    syncs: usize,
    max_concurrent_queries: usize,
    fail_on_call: Option<usize>,
    attestation: Arc<dyn AttestationProvider>,
    require_attestation: bool,
) -> (ConnectorQueryService, Arc<ObservedKeys>) {
    let keypair = TenantKeypair::generate();
    let vault = synced_vault(tenant, &keypair, syncs).await;
    let observe = Observe {
        max_concurrent_queries,
        fail_on_call,
        ..Observe::default()
    };
    observed(
        tenant,
        keypair,
        vault,
        observe,
        attestation,
        require_attestation,
    )
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
async fn refused_attestation_opens_no_key() {
    let tenant = TenantId::generate();
    let (service, keys) = observed_service_with_attestation(
        tenant,
        1,
        4,
        None,
        Arc::new(DevAttestation::strict()),
        true,
    )
    .await;
    let connector = ConnectorSlug::new("quickbooks").expect("slug");
    let result = service.query(tenant, &connector, COUNT_SQL).await;
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

// ── Per-query resource limits ──

fn quickbooks() -> ConnectorSlug {
    ConnectorSlug::new("quickbooks").expect("slug")
}

/// Two groups (EUR and USD) over the QuickBooks fixture.
const BY_CURRENCY: &str =
    "SELECT currency, SUM(total) AS revenue FROM quickbooks GROUP BY currency";

/// Status, `Retry-After` and message of an expected refusal.
async fn refusal(
    result: Result<serde_json::Value, ApiError>,
) -> (StatusCode, Option<String>, String) {
    let response = match result {
        Ok(body) => panic!("expected a refusal, got {body}"),
        Err(err) => err.into_response(),
    };
    let status = response.status();
    let retry_after = response
        .headers()
        .get(header::RETRY_AFTER)
        .map(|value| value.to_str().expect("ascii").to_owned());
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let body: serde_json::Value = serde_json::from_slice(&body).expect("json");
    let message = body["error"].as_str().expect("message").to_owned();
    (status, retry_after, message)
}

/// A one-slot service over one QuickBooks sync, whose key opens can be
/// slowed as [`Observe::slow_call`] says.
async fn one_slot_service(
    tenant: TenantId,
    limits: QueryLimits,
    slow_call: Option<(usize, Duration)>,
) -> (ConnectorQueryService, Arc<ObservedKeys>) {
    let keypair = TenantKeypair::generate();
    let vault = synced_vault(tenant, &keypair, 1).await;
    let observe = Observe {
        max_concurrent_queries: 1,
        limits,
        slow_call,
        ..Observe::default()
    };
    observed(tenant, keypair, vault, observe, dev_attestation(), false)
}

/// Long enough to outlast a one-second wait, and within the default time
/// limit.
const HOLD: Duration = Duration::from_secs(30);

/// The paused clock runs each wait to its end only once nothing else can
/// run, so these tests are deterministic and take no real time.
#[tokio::test(start_paused = true)]
async fn a_query_that_waits_too_long_for_a_slot_is_refused_as_busy() {
    let tenant = TenantId::generate();
    let limits = QueryLimits {
        slot_wait: Duration::from_secs(1),
        ..QueryLimits::default()
    };
    // The first query holds the only slot while it opens its manifest.
    let (service, keys) = one_slot_service(tenant, limits, Some((1, HOLD))).await;
    let connector = quickbooks();
    let (first, second) = tokio::join!(service.query(tenant, &connector, COUNT_SQL), async {
        tokio::time::sleep(Duration::from_millis(10)).await;
        service.query(tenant, &connector, COUNT_SQL).await
    });

    let (status, retry_after, message) = refusal(second).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        retry_after,
        Some(platform_api::QUERY_BUSY_RETRY_AFTER_SECS.to_string())
    );
    assert_eq!(message, "confidential query capacity is busy; retry later");
    // Unlike the refusal for a query service that is not wired.
    let (_, unwired_retry, unwired) = refusal(Err(ApiError::QueryUnavailable)).await;
    assert_ne!(message, unwired);
    assert_eq!(unwired_retry, None);

    // The refused query opened nothing; the first ran to completion.
    first.map_err(|_| "first query failed").expect("first");
    assert_eq!(keys.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test(start_paused = true)]
async fn a_query_over_its_time_limit_is_dropped_and_releases_the_slot() {
    let tenant = TenantId::generate();
    let limits = QueryLimits {
        timeout: Duration::from_secs(1),
        ..QueryLimits::default()
    };
    // Its object opens for longer than the limit, with the manifest
    // already plaintext.
    let (service, keys) = one_slot_service(tenant, limits, Some((2, HOLD))).await;
    let connector = quickbooks();

    let (status, retry_after, message) =
        refusal(service.query(tenant, &connector, COUNT_SQL).await).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(retry_after, None);
    assert_eq!(message, "query exceeded its time limit");

    // The dropped work released the only slot: the next query runs.
    let rows = service
        .query(tenant, &connector, COUNT_SQL)
        .await
        .map_err(|_| "query failed")
        .expect("next query");
    assert_eq!(rows["rows"][0]["n"], 3);
    assert_eq!(keys.calls.load(Ordering::SeqCst), 4);
}

#[tokio::test(start_paused = true)]
async fn a_cancelled_query_releases_the_slot() {
    let tenant = TenantId::generate();
    let (service, keys) = one_slot_service(tenant, QueryLimits::default(), Some((2, HOLD))).await;
    let connector = quickbooks();

    // The caller goes away, as a disconnecting client does, while the
    // object opens.
    let gone = tokio::time::timeout(
        Duration::from_secs(1),
        service.query(tenant, &connector, COUNT_SQL),
    )
    .await;
    assert!(gone.is_err(), "still decrypting when dropped");
    assert_eq!(keys.in_flight.load(Ordering::SeqCst), 0);

    let rows = service
        .query(tenant, &connector, COUNT_SQL)
        .await
        .map_err(|_| "query failed")
        .expect("the slot was released");
    assert_eq!(rows["rows"][0]["n"], 3);
    assert_eq!(keys.calls.load(Ordering::SeqCst), 4);
}

/// Each size limit, set just below what `BY_CURRENCY` over the fixture
/// needs, is a 422 with its own message: never the 400 a broken query gets.
/// A second attempt finds the only slot free, and the input limits refuse
/// before any key is released.
#[tokio::test(start_paused = true)]
async fn each_size_limit_is_refused_with_422_and_releases_the_slot() {
    let defaults = QueryLimits::default();
    let cases = [
        (
            QueryLimits {
                max_input_bytes: 1,
                ..defaults
            },
            "dataset exceeds the query input size limit",
            true,
        ),
        (
            QueryLimits {
                max_input_objects: 0,
                ..defaults
            },
            "dataset exceeds the query input object limit",
            true,
        ),
        (
            QueryLimits {
                max_decoded_rows: 2,
                ..defaults
            },
            "dataset exceeds the query decoded row limit",
            false,
        ),
        (
            QueryLimits {
                max_decoded_bytes: 1,
                ..defaults
            },
            "dataset exceeds the query decoded size limit",
            false,
        ),
        (
            QueryLimits {
                memory_bytes: 1,
                ..defaults
            },
            "query exceeds its memory limit",
            false,
        ),
        (
            QueryLimits {
                max_result_rows: 1,
                ..defaults
            },
            "result exceeds the row limit",
            false,
        ),
        (
            QueryLimits {
                max_result_bytes: 1,
                ..defaults
            },
            "result exceeds the size limit",
            false,
        ),
    ];
    for (limits, expected, before_key_release) in cases {
        let tenant = TenantId::generate();
        let (service, keys) = one_slot_service(tenant, limits, None).await;
        for attempt in 1..=2 {
            let (status, retry_after, message) =
                refusal(service.query(tenant, &quickbooks(), BY_CURRENCY).await).await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{expected}");
            assert_eq!(message, expected, "attempt {attempt}");
            assert_eq!(retry_after, None, "{expected}");
        }
        let opened = keys.calls.load(Ordering::SeqCst);
        assert_eq!(opened, if before_key_release { 0 } else { 4 }, "{expected}");
    }

    // Under the default limits the same query answers.
    let tenant = TenantId::generate();
    let (service, _) = one_slot_service(tenant, defaults, None).await;
    let rows = service
        .query(tenant, &quickbooks(), BY_CURRENCY)
        .await
        .map_err(|_| "query failed")
        .expect("default limits");
    assert_eq!(rows["row_count"], 2);
}

/// A vault that reports nothing stored, as if a snapshot's objects grew
/// after the query sized its input.
struct UnderReportedUsage(Arc<dyn VaultStore>);

#[async_trait]
impl VaultStore for UnderReportedUsage {
    async fn put(&self, path: &VaultPath, ciphertext: Bytes) -> Result<(), StorageError> {
        self.0.put(path, ciphertext).await
    }
    async fn put_if_absent(&self, path: &VaultPath, ciphertext: Bytes) -> Result<(), StorageError> {
        self.0.put_if_absent(path, ciphertext).await
    }
    async fn get(&self, path: &VaultPath) -> Result<Bytes, StorageError> {
        self.0.get(path).await
    }
    async fn delete(&self, path: &VaultPath) -> Result<(), StorageError> {
        self.0.delete(path).await
    }
    async fn list(&self, prefix: &VaultPath) -> Result<Vec<VaultPath>, StorageError> {
        self.0.list(prefix).await
    }
    async fn list_entries(&self, prefix: &VaultPath) -> Result<Vec<VaultEntry>, StorageError> {
        self.0.list_entries(prefix).await
    }
    async fn usage(&self, _prefix: &VaultPath) -> Result<StorageUsage, StorageError> {
        Ok(StorageUsage::default())
    }
}

/// The input limits hold on what the manifest lists, even when the sizing
/// before key release saw less: the object is never opened.
#[tokio::test(start_paused = true)]
async fn the_input_limits_are_checked_again_while_decrypting() {
    for (limits, expected) in [
        (
            QueryLimits {
                max_input_bytes: 1,
                ..QueryLimits::default()
            },
            "dataset exceeds the query input size limit",
        ),
        (
            QueryLimits {
                max_input_objects: 0,
                ..QueryLimits::default()
            },
            "dataset exceeds the query input object limit",
        ),
    ] {
        let tenant = TenantId::generate();
        let keypair = TenantKeypair::generate();
        let vault = Arc::new(UnderReportedUsage(synced_vault(tenant, &keypair, 1).await));
        let observe = Observe {
            limits,
            ..Observe::default()
        };
        let (service, keys) = observed(tenant, keypair, vault, observe, dev_attestation(), false);
        let (status, _, message) =
            refusal(service.query(tenant, &quickbooks(), COUNT_SQL).await).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(message, expected);
        // The manifest only.
        assert_eq!(keys.calls.load(Ordering::SeqCst), 1, "{expected}");
    }
}

#[tokio::test]
async fn a_manifest_larger_than_any_writer_seals_fails_closed_before_key_release() {
    let tenant = TenantId::generate();
    let keypair = TenantKeypair::generate();
    let vault = synced_vault(tenant, &keypair, 1).await;
    let manifest = vault
        .list(&TenantPaths::connector_manifests_prefix(
            tenant,
            &quickbooks(),
        ))
        .await
        .expect("list")
        .remove(0);
    vault
        .put(&manifest, Bytes::from(vec![0u8; MAX_MANIFEST_BYTES + 1]))
        .await
        .expect("put");

    let (service, keys) = observed(
        tenant,
        keypair,
        vault,
        Observe::default(),
        dev_attestation(),
        false,
    );
    let result = service.query(tenant, &quickbooks(), COUNT_SQL).await;
    assert_eq!(error_status(result), StatusCode::BAD_GATEWAY);
    assert_eq!(keys.calls.load(Ordering::SeqCst), 0);
}

/// Grants `researcher` ten units on `steward`'s QuickBooks data and returns
/// the research service and the grant id.
async fn research_grant(
    vault: &Arc<dyn VaultStore>,
    steward: TenantId,
    researcher: TenantId,
) -> (Arc<ResearchService>, String) {
    let research = Arc::new(ResearchService::new(
        ResearchStores::in_memory(),
        vault.clone(),
        2,
        100,
    ));
    let grant = research
        .grant(steward, researcher, &quickbooks(), Some(10))
        .await
        .map_err(|_| "grant failed")
        .expect("grant");
    let grant_id = grant["grant_id"].as_str().expect("grant id").to_owned();
    (research, grant_id)
}

async fn spent(research: &ResearchService, researcher: TenantId, grant_id: &str) -> u64 {
    research
        .budget_state(researcher, grant_id)
        .await
        .map_err(|_| "budget read failed")
        .expect("budget")["spent"]
        .as_u64()
        .expect("spent")
}

const RESEARCH_SQL: &str = "SELECT currency, COUNT(*) AS n FROM quickbooks GROUP BY currency";

/// Today a research query is charged before it waits for a slot (P54
/// decides that order), so a query refused for want of a slot costs a unit.
#[tokio::test(start_paused = true)]
async fn a_research_query_refused_for_a_slot_is_charged() {
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let keypair = TenantKeypair::generate();
    let vault = synced_vault(steward, &keypair, 1).await;
    let (research, grant_id) = research_grant(&vault, steward, researcher).await;
    let observe = Observe {
        max_concurrent_queries: 1,
        limits: QueryLimits {
            slot_wait: Duration::from_secs(1),
            ..QueryLimits::default()
        },
        slow_call: Some((1, HOLD)),
        ..Observe::default()
    };
    let (service, _) = observed(steward, keypair, vault, observe, dev_attestation(), false);
    let service = service.with_research(research.clone());

    let connector = quickbooks();
    let (first, second) = tokio::join!(
        service.research_query(researcher, steward, &connector, RESEARCH_SQL),
        async {
            tokio::time::sleep(Duration::from_millis(10)).await;
            service
                .research_query(researcher, steward, &connector, RESEARCH_SQL)
                .await
        }
    );
    let (status, _, message) = refusal(second).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(message, "confidential query capacity is busy; retry later");
    let first = first.map_err(|_| "first query failed").expect("first");
    assert_eq!(
        first["rows"],
        serde_json::json!([{ "currency": "USD", "n": 2 }])
    );
    assert_eq!(spent(&research, researcher, &grant_id).await, 2);
}

/// Size-limit refusals of research queries cost a unit too, whether the
/// limit refuses before key release or after the engine ran.
#[tokio::test(start_paused = true)]
async fn research_queries_refused_by_a_size_limit_are_charged() {
    for (limits, expected) in [
        (
            QueryLimits {
                max_input_bytes: 1,
                ..QueryLimits::default()
            },
            "dataset exceeds the query input size limit",
        ),
        (
            QueryLimits {
                max_result_rows: 0,
                ..QueryLimits::default()
            },
            "result exceeds the row limit",
        ),
    ] {
        let steward = TenantId::generate();
        let researcher = TenantId::generate();
        let keypair = TenantKeypair::generate();
        let vault = synced_vault(steward, &keypair, 1).await;
        let (research, grant_id) = research_grant(&vault, steward, researcher).await;
        let observe = Observe {
            limits,
            ..Observe::default()
        };
        let (service, _) = observed(steward, keypair, vault, observe, dev_attestation(), false);
        let service = service.with_research(research.clone());

        let result = service
            .research_query(researcher, steward, &quickbooks(), RESEARCH_SQL)
            .await;
        let (status, _, message) = refusal(result).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{expected}");
        assert_eq!(message, expected);
        assert_eq!(
            spent(&research, researcher, &grant_id).await,
            1,
            "{expected}"
        );
    }
}

// ── Snapshots: repeated or interrupted syncs never change what a query reads ──

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
            limits: QueryLimits::default(),
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
    let records = vault
        .list(&TenantPaths::connector_records_prefix(tenant, &connector))
        .await
        .expect("list");
    assert_eq!((manifests.len(), objects.len(), records.len()), (1, 1, 1));
}

#[tokio::test]
async fn a_snapshot_without_its_record_fails_closed() {
    let tenant = TenantId::generate();
    let keypair = TenantKeypair::generate();
    let vault = synced_vault(tenant, &keypair, 1).await;
    let connector = ConnectorSlug::new("quickbooks").expect("slug");
    let record = vault
        .list(&TenantPaths::connector_records_prefix(tenant, &connector))
        .await
        .expect("list")
        .remove(0);
    vault.delete(&record).await.expect("delete");

    let service = service_over(tenant, keypair, vault, ZkMode::Disabled);
    let result = service.query(tenant, &connector, COUNT_SQL).await;
    assert_eq!(error_status(result), StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn a_record_naming_a_suite_this_build_cannot_read_fails_closed() {
    let tenant = TenantId::generate();
    let keypair = TenantKeypair::generate();
    let vault = synced_vault(tenant, &keypair, 1).await;
    let connector = ConnectorSlug::new("quickbooks").expect("slug");
    let service = service_over(tenant, keypair, vault.clone(), ZkMode::Disabled);
    service
        .query(tenant, &connector, COUNT_SQL)
        .await
        .map_err(|_| "query failed")
        .expect("the synced snapshot opens");

    // The same record, naming a suite no build has.
    let path = vault
        .list(&TenantPaths::connector_records_prefix(tenant, &connector))
        .await
        .expect("list")
        .remove(0);
    let version =
        TenantPaths::connector_record_version(tenant, &connector, &path).expect("record path");
    let stored = vault.get(&path).await.expect("record");
    let mut record = SnapshotRecord::parse(&stored, &version).expect("record parses");
    record.suite = "HPK9".to_owned();
    vault.put(&path, record.to_bytes()).await.expect("put");

    let result = service.query(tenant, &connector, COUNT_SQL).await;
    assert_eq!(error_status(result), StatusCode::BAD_GATEWAY);
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
    let (status, bytes) = send(
        &app,
        "GET",
        "/api/v1/grants",
        &[bearer(&token_for(tenant))],
        Vec::new(),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    assert_eq!(body["error"], "research access not configured");
}
