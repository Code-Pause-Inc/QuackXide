//! `connector-worker` startup, factored out of the binary so tests can drive
//! it: the production-mode gate, then the vault, attestation and the jobs.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use platform_config::{PlatformConfig, Service};
use platform_core::TenantId;
use platform_crypto::{TenantKeypair, TenantPublicKey};
use platform_storage::{ObjectStoreVault, VaultStore};
use platform_telemetry::{AuditKind, security_audit_event};

use crate::pipeline::{EnclavePipeline, SyncJob};
use crate::source::FixtureSource;

/// Everything the binary needs to run the scheduler.
pub struct WorkerStartup {
    pub pipeline: Arc<EnclavePipeline>,
    pub jobs: Vec<SyncJob>,
    pub interval: Duration,
}

/// Validate `config` with [`PlatformConfig::enforce_production`], then build
/// the pipeline and jobs. A refusal emits a `service.start` "denied" audit
/// event (reasons name keys, never values) and nothing is built.
pub fn build(config: &PlatformConfig) -> anyhow::Result<WorkerStartup> {
    config
        .enforce_production(Service::ConnectorWorker)
        .map_err(|refusal| anyhow::anyhow!("refusing to start: {refusal}"))?;
    security_audit_event(
        AuditKind::ServiceStart,
        None,
        "ok",
        &format!("connector-worker booting ({})", config.env.as_str()),
    );

    let vault: Arc<dyn VaultStore> = match config.storage.bucket.as_deref() {
        Some(bucket) => {
            tracing::info!(vault = "gcs", "storage vault: Google Cloud Storage");
            Arc::new(ObjectStoreVault::new_gcs(bucket, &config.storage.client)?)
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
        tracing::warn!(
            "TEE_ATTESTATION_REQUIRED=false — syncs attest through the simulated TEE (dev builds with SIM_ATTESTATION_URL) or are refused"
        );
    }

    let (tenant, tenant_public_key) = demo_tenant(config)?;
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

    Ok(WorkerStartup {
        pipeline,
        jobs,
        interval: Duration::from_secs(config.connectors.sync_interval_secs),
    })
}

fn demo_job(tenant: TenantId, key: &TenantPublicKey, source: FixtureSource) -> SyncJob {
    SyncJob {
        tenant,
        tenant_public_key: key.clone(),
        source: Arc::new(source),
    }
}

fn demo_tenant(config: &PlatformConfig) -> anyhow::Result<(TenantId, TenantPublicKey)> {
    let demo = &config.connectors.demo_tenant;
    match (demo.tenant_id.as_deref(), demo.public_key_b64.as_deref()) {
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
