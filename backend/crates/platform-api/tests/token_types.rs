//! Only access tokens reach data and admin routes. A pre-MFA (`preauth`) or
//! `refresh` token that verifies is still refused with 401 everywhere, so
//! the second factor cannot be skipped and a refresh token cannot be used
//! as an access token.

use std::sync::{Arc, OnceLock};

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use platform_api::{AppState, build_app};
use platform_auth::{GeneratedKeypair, JwtVerifier, TokenSigner, TokenType};
use platform_config::PlatformConfig;
use platform_core::TenantId;
use platform_storage::ObjectStoreVault;
use platform_telemetry::capture::AuditCapture;
use tower::ServiceExt;

const ISS: &str = "urn:platform:issuer";
const AUD: &str = "urn:platform:drive";

/// One route behind `require_tenant` in each area, and the admin route.
const ROUTES: &[(&str, &str)] = &[
    ("GET", "/api/v1/drive/objects"),
    ("POST", "/api/v1/query"),
    ("GET", "/api/v1/grants"),
    ("POST", "/api/v1/research/query"),
    ("GET", "/api/v1/catalog"),
    ("GET", "/admin/tenants"),
];

fn keypair() -> &'static GeneratedKeypair {
    static KEYPAIR: OnceLock<GeneratedKeypair> = OnceLock::new();
    KEYPAIR.get_or_init(|| platform_auth::generate_rs256_keypair(2048).expect("keypair"))
}

fn token(token_type: TokenType, admin: bool) -> String {
    let keys = keypair();
    TokenSigner::rs256_from_pem(&keys.private_pem, &keys.kid, ISS, AUD)
        .expect("signer")
        .mint(TenantId::generate(), "user-1", token_type, 900, admin)
        .expect("mint")
}

fn app() -> Router {
    let verifier = JwtVerifier::rs256_from_jwks(&keypair().jwks_json, ISS, AUD).expect("verifier");
    build_app(AppState {
        config: Arc::new(PlatformConfig::from_source(|_| None).expect("config")),
        vault: Arc::new(ObjectStoreVault::new_in_memory()),
        jwt: Some(Arc::new(verifier)),
        query: None,
        provisioning: None,
    })
}

async fn status(app: &Router, method: &str, uri: &str, token: &str) -> StatusCode {
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("{}"))
        .expect("request");
    app.clone()
        .oneshot(request)
        .await
        .expect("response")
        .status()
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
        let bearer = token(token_type, admin);
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
    let user = token(TokenType::Access, false);
    let admin = token(TokenType::Access, true);
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
