//! Confidential connector sync worker.
//!
//! In production it runs in a Confidential VM with
//! `TEE_ATTESTATION_REQUIRED=true` and GCS as the vault. This binary runs the
//! pipeline against the embedded fixture sources for one demo tenant, set
//! via `DEMO_TENANT_ID` and `DEMO_TENANT_PUBLIC_KEY_B64` (base64 raw X25519).
//! Without them it uses an ephemeral keypair whose ciphertext nobody can
//! open.

use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use platform_config::PlatformConfig;
use platform_connectors::pipeline::{EnclavePipeline, SyncJob};
use platform_connectors::source::FixtureSource;
use platform_connectors::worker::SyncScheduler;
use platform_core::TenantId;
use platform_crypto::{TenantKeypair, TenantPublicKey};
use platform_storage::{ObjectStoreVault, VaultStore};
use platform_telemetry::{AuditKind, security_audit_event};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = PlatformConfig::from_env()?;
    platform_telemetry::init_from_env();
    security_audit_event(
        AuditKind::ServiceStart,
        None,
        "ok",
        "connector-worker booting",
    );

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

    let require_attestation = config.features.tee_attestation_required;
    let attestation = platform_enclave::provider_for(require_attestation);
    if !require_attestation {
        tracing::warn!("TEE_ATTESTATION_REQUIRED=false — syncs run UNATTESTED (dev only)");
    }

    let (tenant, tenant_public_key) = demo_tenant()?;
    tracing::info!(%tenant, "demo jobs configured for tenant");

    let pipeline = Arc::new(EnclavePipeline::new(
        attestation,
        vault,
        require_attestation,
    ));
    let jobs = vec![
        demo_job(
            tenant,
            &tenant_public_key,
            FixtureSource::quickbooks_demo()?,
        ),
        demo_job(tenant, &tenant_public_key, FixtureSource::odoo_demo()?),
        demo_job(tenant, &tenant_public_key, FixtureSource::crm_demo()?),
    ];

    let interval = std::time::Duration::from_secs(config.connectors.sync_interval_secs);
    tracing::info!(
        interval_secs = config.connectors.sync_interval_secs,
        "scheduler starting"
    );
    SyncScheduler::new(pipeline, jobs).run(interval).await;
    Ok(())
}

fn demo_job(tenant: TenantId, key: &TenantPublicKey, source: FixtureSource) -> SyncJob {
    SyncJob {
        tenant,
        tenant_public_key: key.clone(),
        source: Arc::new(source),
    }
}

fn demo_tenant() -> anyhow::Result<(TenantId, TenantPublicKey)> {
    match (
        std::env::var("DEMO_TENANT_ID")
            .ok()
            .filter(|v| !v.is_empty()),
        std::env::var("DEMO_TENANT_PUBLIC_KEY_B64")
            .ok()
            .filter(|v| !v.is_empty()),
    ) {
        (Some(tenant_raw), Some(key_b64)) => {
            let tenant: TenantId = tenant_raw
                .parse()
                .map_err(|e| anyhow::anyhow!("invalid DEMO_TENANT_ID: {e}"))?;
            let raw = B64
                .decode(key_b64.trim())
                .map_err(|e| anyhow::anyhow!("invalid DEMO_TENANT_PUBLIC_KEY_B64: {e}"))?;
            let key = TenantPublicKey::from_raw(&raw)
                .map_err(|e| anyhow::anyhow!("invalid tenant public key: {e}"))?;
            Ok((tenant, key))
        }
        _ => {
            let keypair = TenantKeypair::generate();
            let tenant = TenantId::generate();
            tracing::warn!(
                "no DEMO_TENANT_* env set — using an EPHEMERAL keypair; the private key is \
                 discarded, so this run's ciphertext is intentionally unopenable (dev only)"
            );
            Ok((tenant, keypair.public_key()))
        }
    }
}
