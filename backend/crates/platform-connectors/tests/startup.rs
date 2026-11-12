//! Production mode at `connector-worker` startup (ADR 0009).

use std::collections::HashMap;

use platform_config::PlatformConfig;
use platform_connectors::startup;
use platform_telemetry::capture::AuditCapture;

fn config(pairs: &[(&str, &str)]) -> PlatformConfig {
    let map: HashMap<String, String> = pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    PlatformConfig::from_source(move |key| map.get(key).cloned()).expect("config loads")
}

fn refused(pairs: &[(&str, &str)]) -> String {
    match startup::build(&config(pairs)) {
        Ok(_) => panic!("{pairs:?} must be refused in production"),
        Err(err) => err.to_string(),
    }
}

#[test]
fn production_refuses_fixture_sources_and_the_demo_tenant() {
    let capture = AuditCapture::install();
    let err = refused(&[("STORAGE_BUCKET", "b")]);
    assert!(err.contains("fixture"), "{err}");
    assert!(
        capture.contains("service.start", "denied"),
        "{:?}",
        capture.events()
    );
    let err = refused(&[
        ("STORAGE_BUCKET", "b"),
        ("DEMO_TENANT_ID", "t"),
        ("DEMO_TENANT_PUBLIC_KEY_B64", "k"),
    ]);
    assert!(err.contains("DEMO_TENANT_"), "{err}");
}

#[test]
fn production_refuses_dev_settings() {
    for (key, value) in [
        ("JWT_HS256_SECRET", "x"),
        ("TEE_ATTESTATION_REQUIRED", "false"),
        ("SIM_ATTESTATION_URL", "http://127.0.0.1:8070"),
    ] {
        let err = refused(&[("STORAGE_BUCKET", "b"), (key, value)]);
        assert!(err.contains(key), "{err}");
    }
    assert!(refused(&[]).contains("STORAGE_BUCKET"));
}

#[test]
fn development_mode_builds_the_fixture_jobs() {
    let started = startup::build(&config(&[
        ("APP_ENV", "development"),
        ("TEE_ATTESTATION_REQUIRED", "false"),
    ]))
    .expect("development boots");
    assert_eq!(started.jobs.len(), 3);
}
