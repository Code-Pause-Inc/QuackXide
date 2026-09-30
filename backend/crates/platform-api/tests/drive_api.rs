//! Drive API: JWT enforcement and tenant isolation. Tenant identity comes
//! only from the token, so a valid tenant-B token must never observe tenant
//! A's objects.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use platform_api::{AppState, ManifestBody, build_app};
use platform_auth::JwtVerifier;
use platform_config::PlatformConfig;
use platform_core::TenantId;
use platform_storage::ObjectStoreVault;
use tower::ServiceExt;

const SECRET: &str = "integration-test-secret";
const ISS: &str = "urn:platform:auth";
const AUD: &str = "urn:platform:drive";

fn test_app() -> Router {
    let config = PlatformConfig::from_source(|_| None).expect("default config");
    build_app(AppState {
        config: Arc::new(config),
        vault: Arc::new(ObjectStoreVault::new_in_memory()),
        jwt: Some(Arc::new(JwtVerifier::hs256(SECRET, ISS, AUD))),
        query: None,
        provisioning: None,
    })
}

fn token_for(tenant: TenantId) -> String {
    platform_auth::mint_token(SECRET, ISS, AUD, tenant, "itest", 3600).expect("mint")
}

fn manifest_json() -> String {
    serde_json::json!({
        "wrapped_key": { "iv_b64": base64_iv(), "data_b64": "d3JhcHBlZC1rZXk=" },
        "manifest":    { "iv_b64": base64_iv(), "data_b64": "bWFuaWZlc3QtY3Q=" },
        "chunk_count": 1,
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

async fn send(
    app: &Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Option<(&str, Vec<u8>)>,
) -> (StatusCode, Vec<u8>) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let request = match body {
        Some((content_type, bytes)) => builder
            .header(header::CONTENT_TYPE, content_type)
            .body(Body::from(bytes))
            .expect("request"),
        None => builder.body(Body::empty()).expect("request"),
    };
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

const OBJ: &str = "00000000-aaaa-4bbb-8ccc-000000000001";

#[tokio::test]
async fn requests_without_a_token_are_401() {
    let app = test_app();
    let (status, _) = send(&app, "GET", "/api/v1/drive/objects", None, None).await;
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
        let (status, _) = send(&app, "GET", "/api/v1/drive/objects", Some(&bad), None).await;
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
    let (status, body) = send(&app, "GET", "/healthz", None, None).await;
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
        Some(&token),
        Some(("application/json", manifest_json().into_bytes())),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, _) = send(
        &app,
        "PUT",
        &format!("/api/v1/drive/objects/{OBJ}/chunks/0"),
        Some(&token),
        Some(("application/octet-stream", sealed_chunk_body())),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, body) = send(
        &app,
        "GET",
        &format!("/api/v1/drive/objects/{OBJ}/manifest"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let parsed: ManifestBody = serde_json::from_slice(&body).expect("manifest json");
    assert_eq!(parsed.chunk_count, 1);

    let (status, body) = send(
        &app,
        "GET",
        &format!("/api/v1/drive/objects/{OBJ}/chunks/0"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, sealed_chunk_body());

    let (status, body) = send(&app, "GET", "/api/v1/drive/objects", Some(&token), None).await;
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
        Some(&token_a),
        Some(("application/json", manifest_json().into_bytes())),
    )
    .await;
    send(
        &app,
        "PUT",
        &format!("/api/v1/drive/objects/{OBJ}/chunks/0"),
        Some(&token_a),
        Some(("application/octet-stream", sealed_chunk_body())),
    )
    .await;

    // Tenant B, with a fully valid token and the exact object id, sees nothing.
    let (status, _) = send(
        &app,
        "GET",
        &format!("/api/v1/drive/objects/{OBJ}/manifest"),
        Some(&token_b),
        None,
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
        Some(&token_b),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "cross-tenant chunk read must 404"
    );

    let (status, body) = send(&app, "GET", "/api/v1/drive/objects", Some(&token_b), None).await;
    assert_eq!(status, StatusCode::OK);
    let listed: Vec<serde_json::Value> = serde_json::from_slice(&body).expect("list json");
    assert!(listed.is_empty(), "cross-tenant list must be empty");

    // B's delete of the same object id hits B's namespace — A is unaffected.
    let (status, _) = send(
        &app,
        "DELETE",
        &format!("/api/v1/drive/objects/{OBJ}"),
        Some(&token_b),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, _) = send(
        &app,
        "GET",
        &format!("/api/v1/drive/objects/{OBJ}/manifest"),
        Some(&token_a),
        None,
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
        Some(&token),
        Some(("application/json", manifest_json().into_bytes())),
    )
    .await;
    for index in 0..3 {
        send(
            &app,
            "PUT",
            &format!("/api/v1/drive/objects/{OBJ}/chunks/{index}"),
            Some(&token),
            Some(("application/octet-stream", sealed_chunk_body())),
        )
        .await;
    }

    let (status, _) = send(
        &app,
        "DELETE",
        &format!("/api/v1/drive/objects/{OBJ}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    for index in 0..3 {
        let (status, _) = send(
            &app,
            "GET",
            &format!("/api/v1/drive/objects/{OBJ}/chunks/{index}"),
            Some(&token),
            None,
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
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Chunk body below the minimum sealed size.
    let (status, _) = send(
        &app,
        "PUT",
        &format!("/api/v1/drive/objects/{OBJ}/chunks/0"),
        Some(&token),
        Some(("application/octet-stream", vec![0u8; 10])),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Oversized chunk body.
    let (status, _) = send(
        &app,
        "PUT",
        &format!("/api/v1/drive/objects/{OBJ}/chunks/0"),
        Some(&token),
        Some(("application/octet-stream", vec![0u8; 6 * 1024 * 1024])),
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);

    // Manifest with a bad IV length.
    let bad_manifest = manifest_json().replace("AAAAAAAAAAAAAAAA", "AAAA");
    let (status, _) = send(
        &app,
        "PUT",
        &format!("/api/v1/drive/objects/{OBJ}/manifest"),
        Some(&token),
        Some(("application/json", bad_manifest.into_bytes())),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn auth_not_configured_fails_closed_with_503() {
    let config = PlatformConfig::from_source(|_| None).expect("default config");
    let app = build_app(AppState {
        config: Arc::new(config),
        vault: Arc::new(ObjectStoreVault::new_in_memory()),
        jwt: None,
        query: None,
        provisioning: None,
    });
    let token = token_for(TenantId::generate());
    let (status, _) = send(&app, "GET", "/api/v1/drive/objects", Some(&token), None).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}
