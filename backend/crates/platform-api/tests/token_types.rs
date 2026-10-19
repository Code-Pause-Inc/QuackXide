//! Only access tokens reach data and admin routes. A pre-MFA (`preauth`) or
//! `refresh` token that verifies is still refused with 401 everywhere, so
//! the second factor cannot be skipped and a refresh token cannot be used
//! as an access token.

mod common;

use std::sync::Arc;

use axum::Router;
use axum::http::StatusCode;
use platform_api::{AppState, build_app};
use platform_auth::TokenType;
use platform_storage::ObjectStoreVault;
use platform_telemetry::capture::AuditCapture;

use common::{bearer, default_config, json_header, rs256_token, rs256_verifier};

/// One route behind `require_tenant` in each area, and the admin route.
const ROUTES: &[(&str, &str)] = &[
    ("GET", "/api/v1/drive/objects"),
    ("POST", "/api/v1/query"),
    ("GET", "/api/v1/grants"),
    ("POST", "/api/v1/research/query"),
    ("GET", "/api/v1/catalog"),
    ("GET", "/admin/tenants"),
];

fn app() -> Router {
    build_app(AppState {
        config: Arc::new(default_config()),
        vault: Arc::new(ObjectStoreVault::new_in_memory()),
        jwt: Some(Arc::new(rs256_verifier())),
        query: None,
        provisioning: None,
    })
}

async fn status(app: &Router, method: &str, uri: &str, token: &str) -> StatusCode {
    common::send(
        app,
        method,
        uri,
        &[bearer(token), json_header()],
        b"{}".to_vec(),
    )
    .await
    .0
}

#[tokio::test]
async fn preauth_and_refresh_tokens_are_refused_on_every_route() {
    let capture = AuditCapture::install();
    let app = app();
    let mut failures = Vec::new();
    for (token_type, admin) in [
        (TokenType::Preauth, false),
        (TokenType::Preauth, true),
        (TokenType::Refresh, false),
        (TokenType::Refresh, true),
    ] {
        let bearer = rs256_token(token_type, admin);
        for &(method, uri) in ROUTES {
            let got = status(&app, method, uri, &bearer).await;
            if got != StatusCode::UNAUTHORIZED {
                failures.push(format!("{token_type:?} adm={admin} {method} {uri}: {got}"));
            }
        }
    }
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
    assert!(
        capture
            .events()
            .iter()
            .any(|e| e.audit_kind == "auth.decision"
                && e.outcome == "denied"
                && e.detail == "token type not accepted on this route"),
        "{:?}",
        capture.events()
    );
}

#[tokio::test]
async fn access_tokens_still_pass_authentication() {
    let app = app();
    let user = rs256_token(TokenType::Access, false);
    let admin = rs256_token(TokenType::Access, true);
    for &(method, uri) in ROUTES {
        let bearer = if uri.starts_with("/admin") {
            &admin
        } else {
            &user
        };
        let got = status(&app, method, uri, bearer).await;
        assert_ne!(got, StatusCode::UNAUTHORIZED, "{method} {uri}");
    }
}
