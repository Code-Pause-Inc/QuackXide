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

fn development_with_demo_key(raw: &[u8]) -> anyhow::Result<startup::WorkerStartup> {
    use base64::Engine as _;
    let key = base64::engine::general_purpose::STANDARD.encode(raw);
    startup::build(&config(&[
        ("APP_ENV", "development"),
        ("TEE_ATTESTATION_REQUIRED", "false"),
        ("DEMO_TENANT_ID", "6f2c8a2e-1111-4222-8333-444455556666"),
        ("DEMO_TENANT_PUBLIC_KEY_B64", &key),
    ]))
}

#[test]
fn development_accepts_demo_keys_of_both_suites() {
    use platform_crypto::{EnvelopeSuite, TenantKeypair};
    for suite in [EnvelopeSuite::Hpk1, EnvelopeSuite::Hpk2] {
        let raw = TenantKeypair::generate(suite).public_key().to_raw();
        let started = development_with_demo_key(&raw).expect("development boots");
        assert_eq!(started.jobs[0].tenant_public_key.suite(), suite);
    }
}

#[test]
fn demo_key_of_unknown_length_is_refused() {
    for len in [31usize, 33, 1215, 1217] {
        let err = development_with_demo_key(&vec![7u8; len])
            .err()
            .expect("refused")
            .to_string();
        assert!(err.contains("DEMO_TENANT_PUBLIC_KEY_B64"), "{err}");
    }
}
