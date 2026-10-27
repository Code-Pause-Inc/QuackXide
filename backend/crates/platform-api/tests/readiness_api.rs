//! `GET /readyz`: ready only when every dependency is up, and the public
//! response never says which one is down.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use bytes::Bytes;
use http_body_util::BodyExt;
use platform_api::query::{ConnectorQueryService, DevKeyProvider};
use platform_api::{AppState, build_app};
use platform_auth::JwtVerifier;
use platform_config::PlatformConfig;
use platform_core::{TenantId, ZkMode};
use platform_crypto::TenantKeypair;
use platform_enclave::{AttestationProvider, DevAttestation};
use platform_storage::{ObjectStoreVault, StorageError, StorageUsage, VaultPath, VaultStore};
use platform_telemetry::capture::AuditCapture;
use quackxide_engine::EngineSettings;
use serde_json::json;
use tower::ServiceExt;

/// How a test vault answers the readiness listing.
#[derive(Clone, Copy)]
enum Listing {
    Works,
    Fails,
    Hangs,
}

/// Counts listings; every other operation is unused here.
struct TestVault {
    listing: Listing,
    lists: AtomicUsize,
}

#[async_trait]
impl VaultStore for TestVault {
    async fn put(&self, _: &VaultPath, _: Bytes) -> Result<(), StorageError> {
        unreachable!("readiness never writes")
    }
    async fn put_if_absent(&self, _: &VaultPath, _: Bytes) -> Result<(), StorageError> {
        unreachable!("readiness never writes")
    }
    async fn get(&self, _: &VaultPath) -> Result<Bytes, StorageError> {
        unreachable!("readiness never reads")
    }
    async fn delete(&self, _: &VaultPath) -> Result<(), StorageError> {
        unreachable!("readiness never deletes")
    }
    async fn list(&self, _: &VaultPath) -> Result<Vec<VaultPath>, StorageError> {
        self.lists.fetch_add(1, Ordering::SeqCst);
        match self.listing {
            Listing::Works => Ok(Vec::new()),
            Listing::Fails => Err(StorageError::Backend("down".into())),
            Listing::Hangs => std::future::pending().await,
        }
    }
    async fn usage(&self, _: &VaultPath) -> Result<StorageUsage, StorageError> {
        unreachable!("readiness never measures usage")
    }
}

struct Setup {
    listing: Listing,
    /// None leaves the query service unconfigured.
    attestation: Option<(Arc<dyn AttestationProvider>, bool)>,
    jwt: bool,
}

/// Everything up: storage lists, attestation is not required, a verifier
/// is configured.
fn all_up() -> Setup {
    Setup {
        listing: Listing::Works,
        attestation: Some((Arc::new(DevAttestation::allow_insecure_dev()), false)),
        jwt: true,
    }
}

fn app(setup: Setup) -> (Router, Arc<TestVault>) {
    let vault = Arc::new(TestVault {
        listing: setup.listing,
        lists: AtomicUsize::new(0),
    });
    let query = setup.attestation.map(|(provider, required)| {
        let tenant = TenantId::generate();
        Arc::new(ConnectorQueryService::new(
            Arc::new(ObjectStoreVault::new_in_memory()),
            Arc::new(DevKeyProvider::new(tenant, TenantKeypair::generate())),
            provider,
            EngineSettings {
                zk: ZkMode::Enabled,
                max_concurrent_queries: 4,
            },
            required,
        ))
    });
    let jwt = setup.jwt.then(|| {
        Arc::new(JwtVerifier::hs256(
            "readiness-itest-secret",
            "urn:platform:auth",
            "urn:platform:drive",
        ))
    });
    let config = PlatformConfig::from_source(|_| None).expect("config");
    let app = build_app(AppState {
        config: Arc::new(config),
        vault: vault.clone(),
        jwt,
        query,
        provisioning: None,
    });
    (app, vault)
}

async fn readyz(app: &Router) -> (StatusCode, serde_json::Value) {
    let request = Request::builder()
        .uri("/readyz")
        .body(Body::empty())
        .expect("request");
    let response = app.clone().oneshot(request).await.expect("response");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    (status, serde_json::from_slice(&bytes).expect("json body"))
}

/// The body is exactly this, so it can never name a dependency.
fn not_ready() -> serde_json::Value {
    json!({ "status": "not_ready" })
}

#[tokio::test]
async fn ready_when_every_dependency_is_up() {
    let (app, _) = app(all_up());
    assert_eq!(
        readyz(&app).await,
        (StatusCode::OK, json!({ "status": "ready" }))
    );
}

#[tokio::test]
async fn storage_failure_is_not_ready() {
    let (app, _) = app(Setup {
        listing: Listing::Fails,
        ..all_up()
    });
    assert_eq!(
        readyz(&app).await,
        (StatusCode::SERVICE_UNAVAILABLE, not_ready())
    );
}

#[tokio::test(start_paused = true)]
async fn storage_that_hangs_is_not_ready_after_the_timeout() {
    let (app, _) = app(Setup {
        listing: Listing::Hangs,
        ..all_up()
    });
    let answer = tokio::time::timeout(Duration::from_secs(10), readyz(&app))
        .await
        .expect("the check times out instead of hanging");
    assert_eq!(answer, (StatusCode::SERVICE_UNAVAILABLE, not_ready()));
}

#[tokio::test]
async fn refused_attestation_is_not_ready() {
    // No evidence at all, then development evidence where SEV-SNP is required.
    let providers: [Arc<dyn AttestationProvider>; 2] = [
        Arc::new(DevAttestation::strict()),
        Arc::new(DevAttestation::allow_insecure_dev()),
    ];
    for provider in providers {
        let (app, _) = app(Setup {
            attestation: Some((provider, true)),
            ..all_up()
        });
        assert_eq!(
            readyz(&app).await,
            (StatusCode::SERVICE_UNAVAILABLE, not_ready())
        );
    }
}

#[tokio::test]
async fn unconfigured_query_service_is_not_ready() {
    let (app, _) = app(Setup {
        attestation: None,
        ..all_up()
    });
    assert_eq!(
        readyz(&app).await,
        (StatusCode::SERVICE_UNAVAILABLE, not_ready())
    );
}

#[tokio::test]
async fn missing_token_verifier_is_not_ready() {
    let (app, _) = app(Setup {
        jwt: false,
        ..all_up()
    });
    assert_eq!(
        readyz(&app).await,
        (StatusCode::SERVICE_UNAVAILABLE, not_ready())
    );
}

#[tokio::test(start_paused = true)]
async fn probes_share_one_result_for_a_few_seconds() {
    let (app, vault) = app(all_up());
    for _ in 0..3 {
        readyz(&app).await;
    }
    assert_eq!(vault.lists.load(Ordering::SeqCst), 1, "cached");

    tokio::time::advance(Duration::from_secs(6)).await;
    readyz(&app).await;
    assert_eq!(vault.lists.load(Ordering::SeqCst), 2, "checked again");
}

#[tokio::test]
async fn probes_emit_no_audit_events() {
    let capture = AuditCapture::install();
    let (app, _) = app(all_up());
    readyz(&app).await;
    assert!(capture.events().is_empty(), "{:?}", capture.events());
}
