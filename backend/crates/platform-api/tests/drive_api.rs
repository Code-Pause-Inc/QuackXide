//! Drive API: JWT enforcement and tenant isolation. Tenant identity comes
//! only from the token, so a valid tenant-B token must never observe tenant
//! A's objects.

mod common;

use std::sync::Arc;

use async_trait::async_trait;
use axum::Router;
use axum::http::StatusCode;
use bytes::Bytes;
use platform_api::{AppState, ManifestBody, build_app};
use platform_core::TenantId;
use std::sync::atomic::{AtomicUsize, Ordering};

use platform_storage::{ObjectStoreVault, StorageError, StorageUsage, VaultPath, VaultStore};

use common::{AUD, ISS, bearer, content_type, send};

const SECRET: &str = "integration-test-secret";

fn test_app() -> Router {
    build_app(common::app_state(
        SECRET,
        Arc::new(ObjectStoreVault::new_in_memory()),
    ))
}

fn token_for(tenant: TenantId) -> String {
    common::token_for(SECRET, tenant)
}

fn manifest_json() -> String {
    manifest_json_with_chunks(1)
}

fn manifest_json_with_chunks(chunk_count: u32) -> String {
    serde_json::json!({
        "wrapped_key": { "iv_b64": base64_iv(), "data_b64": "d3JhcHBlZC1rZXk=" },
        "manifest":    { "iv_b64": base64_iv(), "data_b64": "bWFuaWZlc3QtY3Q=" },
        "chunk_count": chunk_count,
        "encrypted_size_bytes": 44,
        "created_at_iso": "2026-07-30T12:00:00.000Z"
    })
    .to_string()
}

fn base64_iv() -> String {
    // 12 zero bytes
    "AAAAAAAAAAAAAAAA".to_string()
}

fn sealed_chunk_body() -> Vec<u8> {
    // 12-byte IV prefix + 16 bytes standing in for ciphertext+tag
    vec![0u8; 28]
}

const OBJ: &str = "00000000-aaaa-4bbb-8ccc-000000000001";

#[tokio::test]
async fn requests_without_a_token_are_401() {
    let app = test_app();
    let (status, _) = send(&app, "GET", "/api/v1/drive/objects", &[], Vec::new()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn garbage_and_expired_and_wrong_audience_tokens_are_401() {
    let app = test_app();
    let tenant = TenantId::generate();

    for bad in [
        "garbage.token.here".to_string(),
        platform_auth::mint_token(SECRET, ISS, AUD, tenant, "u", -3600).expect("mint"),
        platform_auth::mint_token(SECRET, ISS, "urn:other", tenant, "u", 3600).expect("mint"),
        platform_auth::mint_token("wrong-secret", ISS, AUD, tenant, "u", 3600).expect("mint"),
    ] {
        let (status, _) = send(
            &app,
            "GET",
            "/api/v1/drive/objects",
            &[bearer(&bad)],
            Vec::new(),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "token should be rejected: {bad}"
        );
    }
}

#[tokio::test]
async fn unauthenticated_public_routes_still_work() {
    let app = test_app();
    let (status, body) = send(&app, "GET", "/healthz", &[], Vec::new()).await;
    assert_eq!(status, StatusCode::OK);
    assert!(String::from_utf8_lossy(&body).contains("ok"));
}

#[tokio::test]
async fn manifest_and_chunk_round_trip() {
    let app = test_app();
    let token = token_for(TenantId::generate());

    let (status, _) = send(
        &app,
        "PUT",
        &format!("/api/v1/drive/objects/{OBJ}/manifest"),
        &[bearer(&token), content_type("application/json")],
        manifest_json().into_bytes(),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, _) = send(
        &app,
        "PUT",
        &format!("/api/v1/drive/objects/{OBJ}/chunks/0"),
        &[bearer(&token), content_type("application/octet-stream")],
        sealed_chunk_body(),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, body) = send(
        &app,
        "GET",
        &format!("/api/v1/drive/objects/{OBJ}/manifest"),
        &[bearer(&token)],
        Vec::new(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let parsed: ManifestBody = serde_json::from_slice(&body).expect("manifest json");
    assert_eq!(parsed.chunk_count, 1);

    let (status, body) = send(
        &app,
        "GET",
        &format!("/api/v1/drive/objects/{OBJ}/chunks/0"),
        &[bearer(&token)],
        Vec::new(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, sealed_chunk_body());

    let (status, body) = send(
        &app,
        "GET",
        "/api/v1/drive/objects",
        &[bearer(&token)],
        Vec::new(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let listed: Vec<serde_json::Value> = serde_json::from_slice(&body).expect("list json");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0]["object_id"], OBJ);
}

#[tokio::test]
async fn tenant_isolation_is_absolute() {
    let app = test_app();
    let token_a = token_for(TenantId::generate());
    let token_b = token_for(TenantId::generate());

    // Tenant A stores an object.
    send(
        &app,
        "PUT",
        &format!("/api/v1/drive/objects/{OBJ}/manifest"),
        &[bearer(&token_a), content_type("application/json")],
        manifest_json().into_bytes(),
    )
    .await;
    send(
        &app,
        "PUT",
        &format!("/api/v1/drive/objects/{OBJ}/chunks/0"),
        &[bearer(&token_a), content_type("application/octet-stream")],
        sealed_chunk_body(),
    )
    .await;

    // Tenant B, with a fully valid token and the exact object id, sees nothing.
    let (status, _) = send(
        &app,
        "GET",
        &format!("/api/v1/drive/objects/{OBJ}/manifest"),
        &[bearer(&token_b)],
        Vec::new(),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "cross-tenant manifest read must 404"
    );

    let (status, _) = send(
        &app,
        "GET",
        &format!("/api/v1/drive/objects/{OBJ}/chunks/0"),
        &[bearer(&token_b)],
        Vec::new(),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "cross-tenant chunk read must 404"
    );

    let (status, body) = send(
        &app,
        "GET",
        "/api/v1/drive/objects",
        &[bearer(&token_b)],
        Vec::new(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let listed: Vec<serde_json::Value> = serde_json::from_slice(&body).expect("list json");
    assert!(listed.is_empty(), "cross-tenant list must be empty");

    // B's delete of the same object id hits B's namespace — A is unaffected.
    let (status, _) = send(
        &app,
        "DELETE",
        &format!("/api/v1/drive/objects/{OBJ}"),
        &[bearer(&token_b)],
        Vec::new(),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, _) = send(
        &app,
        "GET",
        &format!("/api/v1/drive/objects/{OBJ}/manifest"),
        &[bearer(&token_a)],
        Vec::new(),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "tenant A's object must survive B's delete attempt"
    );
}

#[tokio::test]
async fn delete_removes_manifest_and_chunks() {
    let app = test_app();
    let token = token_for(TenantId::generate());

    send(
        &app,
        "PUT",
        &format!("/api/v1/drive/objects/{OBJ}/manifest"),
        &[bearer(&token), content_type("application/json")],
        manifest_json().into_bytes(),
    )
    .await;
    for index in 0..3 {
        send(
            &app,
            "PUT",
            &format!("/api/v1/drive/objects/{OBJ}/chunks/{index}"),
            &[bearer(&token), content_type("application/octet-stream")],
            sealed_chunk_body(),
        )
        .await;
    }

    let (status, _) = send(
        &app,
        "DELETE",
        &format!("/api/v1/drive/objects/{OBJ}"),
        &[bearer(&token)],
        Vec::new(),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    for index in 0..3 {
        let (status, _) = send(
            &app,
            "GET",
            &format!("/api/v1/drive/objects/{OBJ}/chunks/{index}"),
            &[bearer(&token)],
            Vec::new(),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
}

#[tokio::test]
async fn malformed_inputs_are_rejected() {
    let app = test_app();
    let token = token_for(TenantId::generate());

    // Non-UUID object id.
    let (status, _) = send(
        &app,
        "GET",
        "/api/v1/drive/objects/not-a-uuid/manifest",
        &[bearer(&token)],
        Vec::new(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Chunk body below the minimum sealed size.
    let (status, _) = send(
        &app,
        "PUT",
        &format!("/api/v1/drive/objects/{OBJ}/chunks/0"),
        &[bearer(&token), content_type("application/octet-stream")],
        vec![0u8; 10],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Oversized chunk body.
    let (status, _) = send(
        &app,
        "PUT",
        &format!("/api/v1/drive/objects/{OBJ}/chunks/0"),
        &[bearer(&token), content_type("application/octet-stream")],
        vec![0u8; 6 * 1024 * 1024],
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);

    // Manifest with a bad IV length.
    let bad_manifest = manifest_json().replace("AAAAAAAAAAAAAAAA", "AAAA");
    let (status, _) = send(
        &app,
        "PUT",
        &format!("/api/v1/drive/objects/{OBJ}/manifest"),
        &[bearer(&token), content_type("application/json")],
        bad_manifest.into_bytes(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn auth_not_configured_fails_closed_with_503() {
    let app = build_app(AppState {
        jwt: None,
        ..common::app_state(SECRET, Arc::new(ObjectStoreVault::new_in_memory()))
    });
    let token = token_for(TenantId::generate());
    let (status, _) = send(
        &app,
        "GET",
        "/api/v1/drive/objects",
        &[bearer(&token)],
        Vec::new(),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn delete_after_shrinking_manifest_removes_trailing_chunks() {
    let vault = Arc::new(ObjectStoreVault::new_in_memory());
    let app = build_app(common::app_state(SECRET, vault.clone()));
    let tenant = TenantId::generate();
    let token = token_for(tenant);

    send(
        &app,
        "PUT",
        &format!("/api/v1/drive/objects/{OBJ}/manifest"),
        &[bearer(&token), content_type("application/json")],
        manifest_json_with_chunks(3).into_bytes(),
    )
    .await;
    for index in 0..3 {
        send(
            &app,
            "PUT",
            &format!("/api/v1/drive/objects/{OBJ}/chunks/{index}"),
            &[bearer(&token), content_type("application/octet-stream")],
            sealed_chunk_body(),
        )
        .await;
    }
    // Overwrite with a smaller count: chunks 1 and 2 are now past its end.
    let (status, _) = send(
        &app,
        "PUT",
        &format!("/api/v1/drive/objects/{OBJ}/manifest"),
        &[bearer(&token), content_type("application/json")],
        manifest_json_with_chunks(1).into_bytes(),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, _) = send(
        &app,
        "DELETE",
        &format!("/api/v1/drive/objects/{OBJ}"),
        &[bearer(&token)],
        Vec::new(),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let object = OBJ.parse().expect("object id");
    let left = vault
        .list(&platform_storage::TenantPaths::drive_object_prefix(
            tenant, object,
        ))
        .await
        .expect("list");
    assert!(left.is_empty(), "stranded chunks: {left:?}");
}

/// Deletes every manifest right after listing it, as a `delete_object`
/// racing between `list_objects`'s `list` and `get` would.
struct RacingDeleteVault(ObjectStoreVault);

#[async_trait]
impl VaultStore for RacingDeleteVault {
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
        let paths = self.0.list(prefix).await?;
        if prefix.as_str().ends_with("/drive/manifests") {
            for path in &paths {
                self.0.delete(path).await?;
            }
        }
        Ok(paths)
    }
    async fn usage(&self, prefix: &VaultPath) -> Result<StorageUsage, StorageError> {
        self.0.usage(prefix).await
    }
}

#[tokio::test]
async fn listing_skips_manifests_deleted_concurrently() {
    let app = build_app(common::app_state(
        SECRET,
        Arc::new(RacingDeleteVault(ObjectStoreVault::new_in_memory())),
    ));
    let token = token_for(TenantId::generate());
    let (status, _) = send(
        &app,
        "PUT",
        &format!("/api/v1/drive/objects/{OBJ}/manifest"),
        &[bearer(&token), content_type("application/json")],
        manifest_json().into_bytes(),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, body) = send(
        &app,
        "GET",
        "/api/v1/drive/objects",
        &[bearer(&token)],
        Vec::new(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let listed: Vec<serde_json::Value> = serde_json::from_slice(&body).expect("list json");
    assert!(listed.is_empty(), "deleted manifest must not be listed");
}

// ── Storage outages ──

/// A drive app over a vault failing `faults` with `error`, and a token.
fn faulty_drive(faults: common::Faults, error: fn() -> StorageError) -> (Router, String) {
    let vault = Arc::new(common::FlakyVault::new(faults, error));
    let app = build_app(common::app_state(SECRET, vault));
    (app, token_for(TenantId::generate()))
}

async fn put_manifest(app: &Router, token: &str) -> StatusCode {
    send(
        app,
        "PUT",
        &format!("/api/v1/drive/objects/{OBJ}/manifest"),
        &[bearer(token), content_type("application/json")],
        manifest_json().into_bytes(),
    )
    .await
    .0
}

/// A transient outage is a 503 with `Retry-After`, never a 404 or an empty
/// success.
async fn assert_retryable_outage(app: &Router, token: &str, method: &str, uri: &str) {
    let body = if method == "PUT" {
        manifest_json().into_bytes()
    } else {
        Vec::new()
    };
    let (status, headers, body) = common::send_with_headers(
        app,
        method,
        uri,
        &[bearer(token), content_type("application/json")],
        body,
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{method} {uri}");
    assert_eq!(
        headers[axum::http::header::RETRY_AFTER],
        platform_api::STORAGE_RETRY_AFTER_SECS.to_string()
    );
    let json: serde_json::Value = serde_json::from_slice(&body).expect("error json");
    assert_eq!(json["error"], "storage temporarily unavailable");
}

#[tokio::test]
async fn put_outage_is_retryable() {
    let (app, token) = faulty_drive(
        common::Faults {
            put: true,
            ..Default::default()
        },
        common::outage,
    );
    let uri = format!("/api/v1/drive/objects/{OBJ}/manifest");
    assert_retryable_outage(&app, &token, "PUT", &uri).await;
}

#[tokio::test]
async fn get_outage_is_retryable_not_not_found() {
    let (app, token) = faulty_drive(
        common::Faults {
            get: true,
            ..Default::default()
        },
        common::outage,
    );
    assert_eq!(put_manifest(&app, &token).await, StatusCode::NO_CONTENT);
    let uri = format!("/api/v1/drive/objects/{OBJ}/manifest");
    assert_retryable_outage(&app, &token, "GET", &uri).await;
}

#[tokio::test]
async fn delete_outage_is_retryable() {
    let (app, token) = faulty_drive(
        common::Faults {
            delete: true,
            ..Default::default()
        },
        common::outage,
    );
    assert_eq!(put_manifest(&app, &token).await, StatusCode::NO_CONTENT);
    let uri = format!("/api/v1/drive/objects/{OBJ}");
    assert_retryable_outage(&app, &token, "DELETE", &uri).await;
}

#[tokio::test]
async fn list_outage_is_retryable_not_an_empty_list() {
    let (app, token) = faulty_drive(
        common::Faults {
            list: true,
            ..Default::default()
        },
        common::outage,
    );
    assert_retryable_outage(&app, &token, "GET", "/api/v1/drive/objects").await;
}

#[tokio::test]
async fn fatal_storage_failure_is_502_without_retry_after() {
    let (app, token) = faulty_drive(
        common::Faults {
            put: true,
            ..Default::default()
        },
        common::misconfigured,
    );
    let (status, headers, _) = common::send_with_headers(
        &app,
        "PUT",
        &format!("/api/v1/drive/objects/{OBJ}/manifest"),
        &[bearer(&token), content_type("application/json")],
        manifest_json().into_bytes(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert!(headers.get(axum::http::header::RETRY_AFTER).is_none());
}

/// A drive call against a GCS that accepts connections and never answers
/// fails as a retryable outage within the configured bound.
#[tokio::test]
async fn stalled_storage_fails_within_the_documented_bound() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let url = format!("http://{}", listener.local_addr().expect("addr"));
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });
    let settings = platform_config::StorageClientConfig {
        request_timeout: std::time::Duration::from_secs(1),
        connect_timeout: std::time::Duration::from_secs(1),
        max_retries: 1,
        retry_timeout: std::time::Duration::from_secs(1),
    };
    let vault =
        ObjectStoreVault::new_gcs_with_emulator("bucket", Some(&url), &settings).expect("vault");
    let app = build_app(common::app_state(SECRET, Arc::new(vault)));
    let token = token_for(TenantId::generate());

    let started = std::time::Instant::now();
    assert_retryable_outage(&app, &token, "GET", "/api/v1/drive/objects").await;
    let elapsed = started.elapsed();
    assert!(
        elapsed <= settings.worst_case() + std::time::Duration::from_secs(1),
        "{elapsed:?} exceeds {:?}",
        settings.worst_case()
    );
}

// ── Retryable delete ──

/// In-memory vault whose `fail_at`-th `delete` call (counting from 1) fails
/// once with an outage; every other call succeeds.
struct FailOnceDeleteVault {
    inner: ObjectStoreVault,
    deletes: AtomicUsize,
    fail_at: usize,
}

#[async_trait]
impl VaultStore for FailOnceDeleteVault {
    async fn put(&self, path: &VaultPath, ciphertext: Bytes) -> Result<(), StorageError> {
        self.inner.put(path, ciphertext).await
    }
    async fn put_if_absent(&self, path: &VaultPath, ciphertext: Bytes) -> Result<(), StorageError> {
        self.inner.put_if_absent(path, ciphertext).await
    }
    async fn get(&self, path: &VaultPath) -> Result<Bytes, StorageError> {
        self.inner.get(path).await
    }
    async fn delete(&self, path: &VaultPath) -> Result<(), StorageError> {
        if self.deletes.fetch_add(1, Ordering::SeqCst) + 1 == self.fail_at {
            return Err(common::outage());
        }
        self.inner.delete(path).await
    }
    async fn list(&self, prefix: &VaultPath) -> Result<Vec<VaultPath>, StorageError> {
        self.inner.list(prefix).await
    }
    async fn usage(&self, prefix: &VaultPath) -> Result<StorageUsage, StorageError> {
        self.inner.usage(prefix).await
    }
}

const CHUNKS: u32 = 3;

/// Upload a manifest and [`CHUNKS`] chunks, then delete with the
/// `fail_at`-th vault delete failing. Returns the app, token and vault.
async fn delete_failing_at(fail_at: usize) -> (Router, String, Arc<FailOnceDeleteVault>, TenantId) {
    let vault = Arc::new(FailOnceDeleteVault {
        inner: ObjectStoreVault::new_in_memory(),
        deletes: AtomicUsize::new(0),
        fail_at,
    });
    let app = build_app(common::app_state(SECRET, vault.clone()));
    let tenant = TenantId::generate();
    let token = token_for(tenant);
    let (status, _) = send(
        &app,
        "PUT",
        &format!("/api/v1/drive/objects/{OBJ}/manifest"),
        &[bearer(&token), content_type("application/json")],
        manifest_json_with_chunks(CHUNKS).into_bytes(),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    for index in 0..CHUNKS {
        let (status, _) = send(
            &app,
            "PUT",
            &format!("/api/v1/drive/objects/{OBJ}/chunks/{index}"),
            &[bearer(&token), content_type("application/octet-stream")],
            sealed_chunk_body(),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
    }
    (app, token, vault, tenant)
}

async fn delete_status(app: &Router, token: &str) -> StatusCode {
    send(
        app,
        "DELETE",
        &format!("/api/v1/drive/objects/{OBJ}"),
        &[bearer(token)],
        Vec::new(),
    )
    .await
    .0
}

async fn manifest_status(app: &Router, token: &str) -> StatusCode {
    send(
        app,
        "GET",
        &format!("/api/v1/drive/objects/{OBJ}/manifest"),
        &[bearer(token)],
        Vec::new(),
    )
    .await
    .0
}

#[tokio::test]
async fn delete_that_fails_partway_converges_on_retry() {
    // Fail between chunk deletes (2nd), and on the last delete, which is the
    // manifest (one per chunk, then the manifest).
    for fail_at in [2, CHUNKS as usize + 1] {
        let (app, token, vault, tenant) = delete_failing_at(fail_at).await;

        assert_eq!(
            delete_status(&app, &token).await,
            StatusCode::SERVICE_UNAVAILABLE,
            "fail_at={fail_at}"
        );
        // The object is still visible, so the retry can find it.
        assert_eq!(manifest_status(&app, &token).await, StatusCode::OK);

        assert_eq!(delete_status(&app, &token).await, StatusCode::NO_CONTENT);
        assert_eq!(manifest_status(&app, &token).await, StatusCode::NOT_FOUND);
        let object = OBJ.parse().expect("object id");
        let left = vault
            .list(&platform_storage::TenantPaths::drive_object_prefix(
                tenant, object,
            ))
            .await
            .expect("list");
        assert!(
            left.is_empty(),
            "fail_at={fail_at}: stranded chunks {left:?}"
        );

        // Deleting again is an honest 404.
        assert_eq!(delete_status(&app, &token).await, StatusCode::NOT_FOUND);
    }
}

// ── Listing cap ──

/// Store `count` manifests for `tenant` straight into `vault`, with
/// distinct creation times.
async fn store_manifests(vault: &dyn VaultStore, tenant: TenantId, count: usize) {
    let mut body: serde_json::Value = serde_json::from_str(&manifest_json()).expect("json");
    for i in 0..count {
        body["created_at_iso"] = format!("2026-01-01T00:00:{:02}.{i:06}Z", i % 60).into();
        vault
            .put(
                &platform_storage::TenantPaths::drive_manifest(
                    tenant,
                    platform_core::ObjectId::generate(),
                ),
                body.to_string().into(),
            )
            .await
            .expect("put manifest");
    }
}

async fn list(app: &Router, token: &str) -> (StatusCode, serde_json::Value) {
    common::send_json(
        app,
        "GET",
        "/api/v1/drive/objects",
        &[bearer(token)],
        Vec::new(),
    )
    .await
}

#[tokio::test]
async fn listing_at_the_cap_returns_every_object_newest_first() {
    let vault = Arc::new(ObjectStoreVault::new_in_memory());
    let tenant = TenantId::generate();
    store_manifests(vault.as_ref(), tenant, platform_api::MAX_LISTED_OBJECTS).await;
    let app = build_app(common::app_state(SECRET, vault));

    let (status, json) = list(&app, &token_for(tenant)).await;
    assert_eq!(status, StatusCode::OK);
    let entries = json.as_array().expect("array");
    assert_eq!(entries.len(), platform_api::MAX_LISTED_OBJECTS);
    let times: Vec<&str> = entries
        .iter()
        .map(|e| e["created_at_iso"].as_str().expect("time"))
        .collect();
    assert!(times.windows(2).all(|w| w[0] >= w[1]), "newest first");
}

#[tokio::test]
async fn listing_past_the_cap_is_refused_not_truncated() {
    let vault = Arc::new(ObjectStoreVault::new_in_memory());
    let tenant = TenantId::generate();
    store_manifests(vault.as_ref(), tenant, platform_api::MAX_LISTED_OBJECTS + 1).await;
    let app = build_app(common::app_state(SECRET, vault));

    let (status, json) = list(&app, &token_for(tenant)).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(json["error"], "too many objects to list");
}

/// Counts how many manifest reads are in flight at once.
struct ConcurrencyVault {
    inner: ObjectStoreVault,
    in_flight: AtomicUsize,
    peak: AtomicUsize,
}

#[async_trait]
impl VaultStore for ConcurrencyVault {
    async fn put(&self, path: &VaultPath, ciphertext: Bytes) -> Result<(), StorageError> {
        self.inner.put(path, ciphertext).await
    }
    async fn put_if_absent(&self, path: &VaultPath, ciphertext: Bytes) -> Result<(), StorageError> {
        self.inner.put_if_absent(path, ciphertext).await
    }
    async fn get(&self, path: &VaultPath) -> Result<Bytes, StorageError> {
        let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(now, Ordering::SeqCst);
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        let result = self.inner.get(path).await;
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
        result
    }
    async fn delete(&self, path: &VaultPath) -> Result<(), StorageError> {
        self.inner.delete(path).await
    }
    async fn list(&self, prefix: &VaultPath) -> Result<Vec<VaultPath>, StorageError> {
        self.inner.list(prefix).await
    }
    async fn usage(&self, prefix: &VaultPath) -> Result<StorageUsage, StorageError> {
        self.inner.usage(prefix).await
    }
}

#[tokio::test]
async fn manifest_reads_run_concurrently_but_bounded() {
    let vault = Arc::new(ConcurrencyVault {
        inner: ObjectStoreVault::new_in_memory(),
        in_flight: AtomicUsize::new(0),
        peak: AtomicUsize::new(0),
    });
    let tenant = TenantId::generate();
    store_manifests(vault.as_ref(), tenant, 64).await;
    let app = build_app(common::app_state(SECRET, vault.clone()));

    let (status, json) = list(&app, &token_for(tenant)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json.as_array().expect("array").len(), 64);
    let peak = vault.peak.load(Ordering::SeqCst);
    assert!(peak > 1, "reads ran one at a time");
    assert!(peak <= 16, "{peak} reads at once");
}

#[tokio::test]
async fn a_failed_manifest_read_fails_the_whole_listing() {
    let (app, token) = faulty_drive(
        common::Faults {
            get: true,
            ..Default::default()
        },
        common::outage,
    );
    assert_eq!(put_manifest(&app, &token).await, StatusCode::NO_CONTENT);
    assert_retryable_outage(&app, &token, "GET", "/api/v1/drive/objects").await;
}
