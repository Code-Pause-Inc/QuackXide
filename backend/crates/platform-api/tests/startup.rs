//! Production mode at `platform-api` startup (ADR 0009): every
//! development-only path is refused before anything is built, and
//! development mode still boots.

use std::collections::HashMap;

use platform_api::wiring;
use platform_config::PlatformConfig;
use platform_telemetry::capture::AuditCapture;

fn config(pairs: &[(&str, &str)]) -> PlatformConfig {
    let map: HashMap<String, String> = pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    PlatformConfig::from_source(move |key| map.get(key).cloned()).expect("config loads")
}

async fn refused(pairs: &[(&str, &str)]) -> String {
    match wiring::build_state(config(pairs)).await {
        Ok(_) => panic!("{pairs:?} must be refused in production"),
        Err(err) => err.to_string(),
    }
}

#[tokio::test]
async fn production_refuses_each_dev_only_path() {
    for (pairs, needle) in [
        (vec![], "STORAGE_BUCKET"),
        (
            vec![("STORAGE_BUCKET", "b"), ("JWT_HS256_SECRET", "x")],
            "JWT_HS256_SECRET",
        ),
        (
            vec![
                ("STORAGE_BUCKET", "b"),
                ("TEE_ATTESTATION_REQUIRED", "false"),
            ],
            "TEE_ATTESTATION_REQUIRED",
        ),
        (
            vec![
                ("STORAGE_BUCKET", "b"),
                ("SIM_ATTESTATION_URL", "http://127.0.0.1:8070"),
            ],
            "SIM_ATTESTATION_URL",
        ),
        (
            vec![
                ("STORAGE_BUCKET", "b"),
                ("KEY_RELEASE_URL", "http://127.0.0.1:8090"),
            ],
            "KEY_RELEASE_URL",
        ),
    ] {
        let err = refused(&pairs).await;
        assert!(err.contains(needle), "{pairs:?}: {err}");
    }
}

#[tokio::test]
async fn an_unknown_app_env_is_production() {
    let err = refused(&[("APP_ENV", "staging"), ("JWT_HS256_SECRET", "x")]).await;
    assert!(err.contains("JWT_HS256_SECRET"), "{err}");
}

#[tokio::test]
async fn development_mode_boots_with_dev_paths() {
    let capture = AuditCapture::install();
    let state = wiring::build_state(config(&[
        ("APP_ENV", "development"),
        ("JWT_HS256_SECRET", "startup-itest-secret"),
        ("TEE_ATTESTATION_REQUIRED", "false"),
    ]))
    .await
    .expect("development boots");
    assert!(state.jwt.is_some());
    assert!(
        !capture.contains("service.start", "denied"),
        "{:?}",
        capture.events()
    );
}
