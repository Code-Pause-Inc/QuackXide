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
