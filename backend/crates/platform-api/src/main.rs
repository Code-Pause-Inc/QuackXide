//! platform-api binary: config → telemetry → vault selection → serve.

use std::sync::Arc;

use platform_api::{AppState, build_app};
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

    // Query and research routes need the enclave key-release path, which this
    // binary does not configure; they fail closed with 503.
    tracing::info!(
        "confidential query + research endpoints disabled: enclave key-release path not configured (503)"
    );

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
    let app = build_app(AppState {
        config: Arc::new(config),
        vault,
        jwt,
        query: None,
        provisioning,
    });

    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    tracing::info!(%bind_addr, "platform-api listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
