//! The HTTP edge: the page policy and security headers on every response,
//! including refusals, and oversized bodies refused with 413.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use bytes::Bytes;
use futures::StreamExt;
use http_body_util::BodyExt;
use platform_api::edge::{EdgeTimeouts, PAGE_CSP};
use platform_api::query::{ConnectorQueryService, DevKeyProvider, EnclaveKeyProvider};
use platform_api::{ApiError, AppState, MAX_CHUNK_BODY_BYTES, build_app, build_apps_with};
use platform_config::PlatformConfig;
use platform_core::{ConnectorSlug, TenantId};
use platform_crypto::{EnvelopeSuite, SecretBytes, TenantKeypair};
use platform_enclave::{AttestationEvidence, AttestationProvider, EnclaveError};
use platform_storage::{
    ObjectStoreVault, StorageError, StorageUsage, TenantPaths, VaultEntry, VaultPath, VaultStore,
};
use quackxide_engine::{EngineSettings, QueryLimits};
use tower::ServiceExt;

use common::{app_state, bearer, cohorts_upload, content_type, send_with_headers, synced_vault};

const SECRET: &str = "edge-itest-secret";

fn state() -> AppState {
    let vault: Arc<dyn VaultStore> = Arc::new(ObjectStoreVault::new_in_memory());
    app_state(SECRET, vault)
}

fn assert_edge_headers(headers: &HeaderMap, context: &str) {
    let expected = [
        ("content-security-policy", PAGE_CSP),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
        ("x-frame-options", "DENY"),
        ("cache-control", "no-store"),
    ];
    for (name, value) in expected {
        let all: Vec<_> = headers.get_all(name).iter().collect();
        assert_eq!(all.len(), 1, "{context}: {name} must appear once");
        assert_eq!(all[0], value, "{context}: {name}");
    }
}

#[tokio::test]
async fn headers_on_every_kind_of_response() {
    let app = build_app(state());
    let cases = [
        ("GET", "/healthz", StatusCode::OK),
        ("GET", "/api/v1/grants", StatusCode::UNAUTHORIZED),
        ("GET", "/api/v1/nope", StatusCode::NOT_FOUND),
        ("DELETE", "/healthz", StatusCode::METHOD_NOT_ALLOWED),
    ];
    for (method, uri, status) in cases {
        let (got, headers, _) = send_with_headers(&app, method, uri, &[], Vec::new()).await;
        assert_eq!(got, status, "{method} {uri}");
        assert_edge_headers(&headers, &format!("{method} {uri}"));
    }
}

#[tokio::test]
async fn oversized_bodies_are_refused_with_headers() {
    const MIB: usize = 1024 * 1024;
    let config = PlatformConfig::from_source(|k| (k == "DATASET_MAX_MIB").then(|| "1".to_owned()))
        .expect("config");
    let dataset_limit = usize::try_from(config.datasets.max_bytes).expect("limit")
        + platform_connectors::upload::MAX_BODY_OVERHEAD;
    let app = build_app(AppState {
        config: Arc::new(config),
        ..state()
    });
    let token = common::token_for(SECRET, TenantId::generate());
    let auth = bearer(&token);
    let object = "00000000-0000-0000-0000-000000000001";
    let cases = [
        (
            "PUT",
            format!("/api/v1/drive/objects/{object}/chunks/0"),
            "application/octet-stream",
            MAX_CHUNK_BODY_BYTES + 1,
        ),
        (
            "PUT",
            "/api/v1/datasets/upload_cohorts".to_owned(),
            "application/octet-stream",
            dataset_limit + 1,
        ),
        (
            "POST",
            "/api/v1/catalog".to_owned(),
            "application/json",
            2 * MIB + 1,
        ),
    ];
    for (method, uri, mime, size) in cases {
        let headers = [auth.clone(), content_type(mime)];
        let (status, response, _) =
            send_with_headers(&app, method, &uri, &headers, vec![b'a'; size]).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{method} {uri}");
        assert_edge_headers(&response, &format!("{method} {uri}"));
    }
}

// ── Timeouts ──

const SHORT: EdgeTimeouts = EdgeTimeouts {
    default: Duration::from_millis(200),
    query: Duration::from_millis(300),
    body_gap: Duration::from_millis(200),
};

/// Evidence that is never produced: a handler that waits on it never answers.
struct HangingAttestation;

#[async_trait]
impl AttestationProvider for HangingAttestation {
    async fn produce_evidence(&self, _: &[u8]) -> Result<AttestationEvidence, EnclaveError> {
        std::future::pending().await
    }
    async fn produce_browser_evidence(
        &self,
        _: &[u8],
    ) -> Result<AttestationEvidence, EnclaveError> {
        std::future::pending().await
    }
}

#[tokio::test]
async fn slow_handler_times_out_with_503() {
    let vault: Arc<dyn VaultStore> = Arc::new(ObjectStoreVault::new_in_memory());
    let tenant = TenantId::generate();
    let service = ConnectorQueryService::new(
        vault.clone(),
        Arc::new(DevKeyProvider::new(
            tenant,
            TenantKeypair::generate(EnvelopeSuite::CURRENT),
        )),
        Arc::new(HangingAttestation),
        EngineSettings {
            zk: platform_core::ZkMode::Disabled,
            max_concurrent_queries: 1,
            limits: QueryLimits::default(),
        },
        false,
    );
    let (app, _) = build_apps_with(
        AppState {
            query: Some(Arc::new(service)),
            ..app_state(SECRET, vault)
        },
        SHORT,
    );
    let nonce = "A".repeat(43);
    let started = Instant::now();
    let (status, headers, body) = send_with_headers(
        &app,
        "GET",
        &format!("/api/v1/attestation?nonce={nonce}"),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(body.is_empty(), "no detail in the body: {body:?}");
    assert_edge_headers(&headers, "timed out attestation");
}

/// A request body that sends `chunks` of `chunk` bytes, `gap` apart, then
/// stalls for good if `stall`.
fn paced_body(chunks: usize, chunk: usize, gap: Duration, stall: bool) -> Body {
    let sent = futures::stream::unfold(0, move |n| async move {
        if n == chunks {
            return None;
        }
        if n > 0 {
            tokio::time::sleep(gap).await;
        }
        Some((
            Ok::<_, std::io::Error>(Bytes::from(vec![b'a'; chunk])),
            n + 1,
        ))
    });
    if stall {
        Body::from_stream(sent.chain(futures::stream::pending()))
    } else {
        Body::from_stream(sent)
    }
}

async fn put_chunk_streaming(
    app: &Router,
    token: &str,
    body: Body,
) -> (StatusCode, HeaderMap, Bytes) {
    let object = "00000000-0000-0000-0000-000000000001";
    let request = Request::put(format!("/api/v1/drive/objects/{object}/chunks/0"))
        .header("Authorization", bearer(token).1)
        .header("Content-Type", "application/octet-stream")
        .body(body)
        .expect("request");
    let response = app.clone().oneshot(request).await.expect("response");
    let (parts, body) = response.into_parts();
    (
        parts.status,
        parts.headers,
        body.collect().await.expect("body").to_bytes(),
    )
}

#[tokio::test]
async fn stalled_upload_body_gets_408() {
    let (app, _) = build_apps_with(state(), SHORT);
    let token = common::token_for(SECRET, TenantId::generate());

    let started = Instant::now();
    let (status, headers, _) =
        put_chunk_streaming(&app, &token, paced_body(1, 64, Duration::ZERO, true)).await;
    assert_eq!(status, StatusCode::REQUEST_TIMEOUT);
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_edge_headers(&headers, "stalled upload");

    // Sent steadily, the same upload takes longer than the default total
    // timeout and still lands.
    let started = Instant::now();
    let (status, headers, _) = put_chunk_streaming(
        &app,
        &token,
        paced_body(8, 64, Duration::from_millis(50), false),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(started.elapsed() > SHORT.default, "the upload outlasted it");
    assert_edge_headers(&headers, "steady upload");
}

/// Hangs the first key open of a query for good; later opens pass through.
struct HangFirstOpen {
    inner: DevKeyProvider,
    opens: AtomicUsize,
}

#[async_trait]
impl EnclaveKeyProvider for HangFirstOpen {
    fn key_suite(&self, tenant: TenantId) -> Option<EnvelopeSuite> {
        self.inner.key_suite(tenant)
    }

    async fn open_envelope(
        &self,
        tenant: TenantId,
        info: &[u8],
        envelope: &[u8],
    ) -> Result<SecretBytes, ApiError> {
        if self.opens.fetch_add(1, Ordering::SeqCst) == 0 {
            std::future::pending::<()>().await;
        }
        self.inner.open_envelope(tenant, info, envelope).await
    }
}

#[tokio::test]
async fn timed_out_own_data_query_frees_its_slot() {
    let tenant = TenantId::generate();
    let keypair = TenantKeypair::generate(EnvelopeSuite::CURRENT);
    let vault = synced_vault(tenant, &keypair, 1).await;
    let service = ConnectorQueryService::new(
        vault.clone(),
        Arc::new(HangFirstOpen {
            inner: DevKeyProvider::new(tenant, keypair),
            opens: AtomicUsize::new(0),
        }),
        common::dev_attestation(),
        EngineSettings {
            zk: platform_core::ZkMode::Disabled,
            max_concurrent_queries: 1,
            // A second query that finds the slot held gives up quickly.
            limits: QueryLimits {
                slot_wait: Duration::from_millis(100),
                ..QueryLimits::default()
            },
        },
        false,
    );
    let (app, _) = build_apps_with(
        AppState {
            query: Some(Arc::new(service)),
            ..app_state(SECRET, vault)
        },
        SHORT,
    );
    let token = common::token_for(SECRET, tenant);
    let sql = r#"{"connector":"quickbooks","sql":"SELECT COUNT(*) AS n FROM quickbooks"}"#;

    let (status, body) = common::post_query(&app, Some(&token), sql).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    let (status, body) = common::post_query(&app, Some(&token), sql).await;
    assert_eq!(status, StatusCode::OK, "the slot was freed: {body}");
}

/// Stalls manifest writes for good: an upload cut after its objects.
struct StallManifests(ObjectStoreVault);

#[async_trait]
impl VaultStore for StallManifests {
    async fn put(&self, path: &VaultPath, ciphertext: Bytes) -> Result<(), StorageError> {
        if path.as_str().ends_with(".manifest") {
            std::future::pending::<()>().await;
        }
        self.0.put(path, ciphertext).await
    }
    async fn put_if_absent(&self, path: &VaultPath, ciphertext: Bytes) -> Result<(), StorageError> {
        if path.as_str().ends_with(".manifest") {
            std::future::pending::<()>().await;
        }
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
    async fn usage(&self, prefix: &VaultPath) -> Result<StorageUsage, StorageError> {
        self.0.usage(prefix).await
    }
}

#[tokio::test]
async fn cut_upload_commit_leaves_nothing_visible() {
    let steward = TenantId::generate();
    let keypair = TenantKeypair::generate(EnvelopeSuite::CURRENT);
    let vault: Arc<dyn VaultStore> = Arc::new(StallManifests(ObjectStoreVault::new_in_memory()));
    let key = keypair.public_key();
    let app = common::upload_research_app(SECRET, vec![(steward, keypair)], vault.clone());
    let token = common::token_for(SECRET, steward);
    let upload = cohorts_upload(steward, &key, "upload_cohorts", None);

    // The client goes away mid-commit, dropping the request's future.
    let cut = tokio::time::timeout(
        Duration::from_millis(500),
        common::put_upload(&app, Some(&token), "upload_cohorts", upload.body),
    )
    .await;
    assert!(cut.is_err(), "the commit should still be waiting");

    let slug = ConnectorSlug::new("upload_cohorts").expect("slug");
    let manifests = vault
        .list(&TenantPaths::connector_manifests_prefix(steward, &slug))
        .await
        .expect("list");
    assert!(manifests.is_empty(), "no manifest was committed");
    let (status, _, listing) = send_with_headers(
        &app,
        "GET",
        "/api/v1/datasets",
        &[bearer(&token)],
        Vec::new(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(listing, br#"{"datasets":[]}"#);
}
