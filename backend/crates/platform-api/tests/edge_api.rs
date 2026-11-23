//! The HTTP edge: the page policy and security headers on every response,
//! including refusals, and oversized bodies refused with 413.

mod common;

use std::sync::Arc;

use axum::http::{HeaderMap, StatusCode};
use platform_api::edge::PAGE_CSP;
use platform_api::{AppState, MAX_CHUNK_BODY_BYTES, build_app};
use platform_config::PlatformConfig;
use platform_core::TenantId;
use platform_storage::{ObjectStoreVault, VaultStore};

use common::{app_state, bearer, content_type, send_with_headers};

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
