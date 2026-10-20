//! platform-api binary: config → telemetry → vault selection → serve.

use std::sync::Arc;

use platform_api::{AppState, build_apps};
use platform_auth::JwtVerifier;
use platform_config::PlatformConfig;
use platform_storage::{ObjectStoreVault, VaultStore};
use platform_telemetry::{AuditKind, security_audit_event};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = PlatformConfig::from_env()?;
    platform_telemetry::init_from_env();

    let vault: Arc<dyn VaultStore> = match config.storage.bucket.as_deref() {
        Some(bucket) => {
            tracing::info!(vault = "gcs", "storage vault: Google Cloud Storage");
            Arc::new(ObjectStoreVault::new_gcs(bucket)?)
        }
        None => {
            tracing::warn!(
                vault = "memory",
                "STORAGE_BUCKET unset — in-memory vault (dev only; data is lost on restart)"
            );
            Arc::new(ObjectStoreVault::new_in_memory())
        }
    };

    let jwt = config.auth.hs256_secret.as_deref().map(|secret| {
        Arc::new(JwtVerifier::hs256(
            secret,
            &config.auth.issuer,
            &config.auth.audience,
        ))
    });
    if jwt.is_none() {
        tracing::warn!("JWT_HS256_SECRET unset — drive routes will refuse with 503 (fail closed)");
    }

    let attestation = platform_enclave::provider_for(config.features.tee_attestation_required);
    if !config.features.tee_attestation_required {
        maybe_seed_demo_fixture(&vault, &attestation).await?;
    }

    let query = match config.enclave.key_release_url.as_deref() {
        Some(url) => {
            tracing::info!(
                key_release_url = %url,
                require_attestation = config.features.tee_attestation_required,
                "enclave key-release path configured"
            );
            let config_digest = match std::env::var("ENCLAVE_CONFIG_DIGEST_HEX") {
                Ok(raw) if !raw.trim().is_empty() => {
                    platform_enclave::decode_hex_array::<32>(raw.trim()).ok_or_else(|| {
                        anyhow::anyhow!(
                            "ENCLAVE_CONFIG_DIGEST_HEX must be exactly 64 hex chars (32 bytes)"
                        )
                    })?
                }
                _ => [0u8; 32],
            };
            let identity = Arc::new(platform_api::key_release::EnclaveIdentity::with_metadata(
                [0u8; 32],
                config_digest,
            ));
            let client = Arc::new(platform_api::key_release::HttpKeyReleaseClient::new(url));
            let keys = Arc::new(platform_api::key_release::AttestedKeyProvider::new(
                identity.clone(),
                attestation.clone(),
                client,
            ));
            let service = platform_api::query::ConnectorQueryService::new(
                vault.clone(),
                keys,
                attestation,
                quackxide_engine::EngineSettings {
                    zk: config.features.zk,
                    max_concurrent_queries: config.enclave.query_max_concurrent,
                },
                config.features.tee_attestation_required,
            )
            .with_enclave_identity(identity)
            .with_research(
                platform_api::research::ResearchStores::in_memory(),
                config.research.min_cohort_size,
                config.research.default_query_budget,
            );
            Some(Arc::new(service))
        }
        None => {
            tracing::info!(
                "confidential query + research endpoints disabled: KEY_RELEASE_URL unset (503)"
            );
            None
        }
    };

    // The in-memory registry is not durable; provisioning also writes a
    // control-plane marker to the vault.
    let registry: Arc<dyn platform_tenancy::TenantRegistry> =
        Arc::new(platform_tenancy::InMemoryTenantRegistry::new(
            platform_api::admin::default_connector_slugs(),
        ));
    let provisioning = Some(Arc::new(platform_api::admin::ProvisioningService::new(
        registry,
        vault.clone(),
    )));
    if config.billing.paddle_webhook_secret.is_none() {
        tracing::warn!("MOR_WEBHOOK_SECRET unset — MoR webhook refuses with 503 (fail closed)");
    }

    security_audit_event(AuditKind::ServiceStart, None, "ok", "platform-api booting");

    let bind_addr = config.server.bind_addr;
    let metrics_addr = config.server.metrics_bind_addr;
    let (app, metrics_app) = build_apps(AppState {
        config: Arc::new(config),
        vault,
        jwt,
        query,
        provisioning,
    });

    let shutdown = platform_telemetry::shutdown_signal()?;

    // Loopback only (enforced by platform-config), for a scraper on this host.
    let metrics_listener = tokio::net::TcpListener::bind(metrics_addr).await?;
    tracing::info!(%metrics_addr, "metrics listening");
    tokio::spawn(async move {
        if let Err(err) = axum::serve(metrics_listener, metrics_app).await {
            tracing::error!(error = %err, "metrics listener stopped");
        }
    });

    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    tracing::info!(%bind_addr, "platform-api listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await?;
    Ok(())
}

/// In simulated-TEE / dev mode (`TEE_ATTESTATION_REQUIRED=false`), optionally
/// seal the synthetic QuickBooks fixture into the vault for `DEMO_TENANT_ID`
/// using `DEMO_TENANT_PUBLIC_KEY_B64`.
async fn maybe_seed_demo_fixture(
    vault: &Arc<dyn VaultStore>,
    attestation: &Arc<dyn platform_enclave::AttestationProvider>,
) -> anyhow::Result<()> {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as B64;

    let (Ok(raw_tenant), Ok(raw_pk_b64)) = (
        std::env::var("DEMO_TENANT_ID"),
        std::env::var("DEMO_TENANT_PUBLIC_KEY_B64"),
    ) else {
        return Ok(());
    };
    let raw_tenant = raw_tenant.trim();
    let raw_pk_b64 = raw_pk_b64.trim();
    if raw_tenant.is_empty() || raw_pk_b64.is_empty() {
        return Ok(());
    }

    let tenant: platform_core::TenantId = raw_tenant.parse()?;
    let pk_bytes = B64.decode(raw_pk_b64)?;
    let tenant_public_key = platform_crypto::TenantPublicKey::from_raw(&pk_bytes)?;

    let pipeline = platform_connectors::pipeline::EnclavePipeline::new(
        attestation.clone(),
        vault.clone(),
        false,
    );
    let job = platform_connectors::pipeline::SyncJob {
        tenant,
        tenant_public_key,
        source: Arc::new(platform_connectors::source::FixtureSource::quickbooks_demo()?),
    };
    let report = pipeline.run_sync(&job).await?;
    tracing::info!(
        %tenant,
        objects_sealed = report.written.len(),
        connector = %report.connector,
        "sealed simulated-TEE demo fixture into vault"
    );
    Ok(())
}
