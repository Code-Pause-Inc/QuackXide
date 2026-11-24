//! `enclave-check` against a running simulated enclave: `verify` runs ADR
//! 0010's checks on the live evidence bundle, fetching the key set itself,
//! and `seal-query` prints a sealed request the enclave runs. A failed check
//! names itself, and nothing is sealed after one.
mod common;

use std::sync::Arc;

use axum::Router;
use axum::http::StatusCode;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use platform_api::checker;
use platform_api::key_release::sim_attestation_router;
use platform_core::TenantId;
use platform_crypto::{EnvelopeSuite, TenantKeypair};
use platform_enclave::simulated_token::TokenSigner;
use tokio::net::TcpListener;

use common::post;

const SECRET: &str = "enclave-check-itest-secret";
const ISSUER: &str = "urn:devstack:sim";

async fn serve(router: Router) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    base
}

/// The enclave's API and the simulator's key set, each on its own port.
struct Deployment {
    app: Router,
    api: String,
    jwks_url: String,
    steward: TenantId,
}

async fn deployment() -> Deployment {
    let steward = TenantId::generate();
    let (app, signer): (Router, Arc<TokenSigner>) =
        common::sealed_research_stack(SECRET, steward).await;
    let api = serve(app.clone()).await;
    let jwks_url = format!("{}/jwks", serve(sim_attestation_router(signer)).await);
    Deployment {
        app,
        api,
        jwks_url,
        steward,
    }
}

fn args(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| (*s).to_owned()).collect()
}

async fn run(list: &[&str]) -> Result<String, String> {
    checker::run(&args(list), &reqwest::Client::new()).await
}

#[tokio::test]
async fn verify_passes_on_the_simulated_stack() {
    let d = deployment().await;
    let out = run(&[
        "verify",
        "--api",
        &d.api,
        "--issuer",
        ISSUER,
        "--jwks-url",
        &d.jwks_url,
    ])
    .await
    .expect("verifies");
    assert!(out.starts_with("ok key_id="), "{out}");
    assert!(
        out.contains("not checked: TLS key binding (needs P67)"),
        "{out}"
    );
}

#[tokio::test]
async fn an_unreachable_key_set_fails() {
    let d = deployment().await;
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead = format!("http://{}/jwks", closed.local_addr().unwrap());
    drop(closed);
    let err = run(&[
        "verify",
        "--api",
        &d.api,
        "--issuer",
        ISSUER,
        "--jwks-url",
        &dead,
    ])
    .await
    .expect_err("no key set");
    assert!(err.contains("key set"), "{err}");
}

#[tokio::test]
async fn an_image_not_allowed_fails_check_3() {
    let d = deployment().await;
    let other = format!("sha256:{}", "0".repeat(64));
    let err = run(&[
        "verify",
        "--api",
        &d.api,
        "--issuer",
        ISSUER,
        "--jwks-url",
        &d.jwks_url,
        "--image-digest",
        &other,
    ])
    .await
    .expect_err("refused");
    assert!(err.starts_with("check 3"), "{err}");
}

/// `seal-query`'s output is a body the enclave runs, as the browser's would be.
#[tokio::test]
async fn seal_query_output_runs() {
    let d = deployment().await;
    let researcher = TenantId::generate();
    let (status, grant) = post(
        &d.app,
        "/api/v1/grants",
        &common::token_for(SECRET, d.steward),
        &format!(r#"{{"researcher_tenant":"{researcher}","connector":"health"}}"#),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "grant: {grant}");
    let grant_id = grant["grant_id"].as_str().expect("grant id");
    let recipient = B64URL.encode(
        TenantKeypair::generate(EnvelopeSuite::Hpk2)
            .public_key()
            .to_raw(),
    );
    let nonce = B64URL.encode([5u8; 32]);
    let body = run(&[
        "seal-query",
        "--api",
        &d.api,
        "--issuer",
        ISSUER,
        "--jwks-url",
        &d.jwks_url,
        "--researcher",
        &researcher.to_string(),
        "--grant",
        grant_id,
        "--steward",
        &d.steward.to_string(),
        "--connector",
        "health",
        "--recipient-key",
        &recipient,
        "--nonce",
        &nonce,
        "--sql",
        "SELECT condition, COUNT(*) AS n FROM health GROUP BY condition",
    ])
    .await
    .expect("sealed");
    let (status, result) = post(
        &d.app,
        "/api/v1/research/query",
        &common::token_for(SECRET, researcher),
        &body,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert_eq!(result["rows"][0]["condition"], "flu");
}

#[tokio::test]
async fn seal_query_seals_nothing_after_a_failed_check() {
    let d = deployment().await;
    let other = format!("sha256:{}", "0".repeat(64));
    let recipient = B64URL.encode(
        TenantKeypair::generate(EnvelopeSuite::Hpk2)
            .public_key()
            .to_raw(),
    );
    let nonce = B64URL.encode([5u8; 32]);
    let err = run(&[
        "seal-query",
        "--api",
        &d.api,
        "--issuer",
        ISSUER,
        "--jwks-url",
        &d.jwks_url,
        "--image-digest",
        &other,
        "--researcher",
        &TenantId::generate().to_string(),
        "--grant",
        "g",
        "--steward",
        &d.steward.to_string(),
        "--connector",
        "health",
        "--recipient-key",
        &recipient,
        "--nonce",
        &nonce,
        "--sql",
        "SELECT 1",
    ])
    .await
    .expect_err("refused");
    assert!(err.starts_with("check 3"), "{err}");
}
