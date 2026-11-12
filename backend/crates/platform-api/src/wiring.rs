//! Builds the API's [`AppState`] from configuration. `main` serves the
//! result, and integration tests call [`build_state`] to run exactly the
//! binary's wiring.
//!
//! Research access (catalog, access requests, grants, budgets) needs no key
//! material, so it is always built. The confidential query service needs
//! released tenant keys, so a build without the `dev` feature never builds
//! it: `POST /api/v1/query`, `POST /api/v1/research/query` and
//! `GET /api/v1/attestation` answer 503. A `dev` build builds it when
//! `KEY_RELEASE_URL` names the simulated TEE's key-release stand-in, on the
//! same research service the research routes use.
//!
//! Before any of that, [`PlatformConfig::enforce_production`] runs the
//! production-mode gate
//! (ADR 0009).

use std::sync::Arc;

use platform_auth::JwtVerifier;
use platform_config::{PlatformConfig, Service};
use platform_storage::{ObjectStoreVault, VaultStore};
use platform_telemetry::{AuditKind, security_audit_event};

use crate::AppState;
use crate::admin::{self, ProvisioningService};
use crate::research::{ResearchService, ResearchStores};

/// Builds the API state from `config`: vault, token verifier, attestation,
/// research access, the confidential query service and provisioning.
/// Refuses, with an audit event, a configuration this build or production
/// mode must not run; nothing is built before the production-mode gate.
pub async fn build_state(config: PlatformConfig) -> anyhow::Result<AppState> {
    config
        .enforce_production(Service::PlatformApi)
        .map_err(|refusal| anyhow::anyhow!("refusing to start: {refusal}"))?;

    let local_dir = std::env::var("STORAGE_LOCAL_DIR")
        .ok()
        .filter(|dir| !dir.trim().is_empty());
    let vault: Arc<dyn VaultStore> = match (config.storage.bucket.as_deref(), local_dir) {
        (Some(_), Some(_)) => {
            let reason = "set STORAGE_BUCKET or STORAGE_LOCAL_DIR, not both";
            security_audit_event(AuditKind::ServiceStart, None, "denied", reason);
            anyhow::bail!("refusing to start: {reason}");
        }
        #[cfg(feature = "dev")]
        (None, Some(dir)) => {
            tracing::warn!(vault = "local", %dir, "STORAGE_LOCAL_DIR set — local-directory vault (dev only)");
            Arc::new(ObjectStoreVault::new_local_dir(std::path::Path::new(
                dir.trim(),
            ))?)
        }
        // A release build never stores tenant data outside the bucket.
        #[cfg(not(feature = "dev"))]
        (None, Some(_)) => {
            let reason = "STORAGE_LOCAL_DIR is dev-only: the local-directory vault exists only with the dev feature";
            security_audit_event(AuditKind::ServiceStart, None, "denied", reason);
            anyhow::bail!("refusing to start: {reason}");
        }
        (Some(bucket), None) => {
            tracing::info!(vault = "gcs", "storage vault: Google Cloud Storage");
            Arc::new(ObjectStoreVault::new_gcs(bucket, &config.storage.client)?)
        }
        (None, None) => {
            tracing::warn!(
                vault = "memory",
                "STORAGE_BUCKET unset — in-memory vault (dev only; data is lost on restart)"
            );
            Arc::new(ObjectStoreVault::new_in_memory())
        }
    };

    let jwt = config.auth.hs256_secret.as_ref().map(|secret| {
        Arc::new(JwtVerifier::hs256(
            secret.expose(),
            &config.auth.issuer,
            &config.auth.audience,
        ))
    });
    if jwt.is_none() {
        tracing::warn!("JWT_HS256_SECRET unset — drive routes will refuse with 503 (fail closed)");
    }

    let attestation = platform_enclave::provider_for(config.features.tee_attestation_required);
    if !config.features.tee_attestation_required {
        maybe_seed_demo_fixture(&config, &vault, &attestation).await?;
    }

    // One `Arc` for the research routes and the query service, so the grant
    // a route creates is the one `research_query` checks and charges. The
    // stores are in memory until P62 makes them durable.
    let research = Arc::new(ResearchService::from_config(
        ResearchStores::in_memory(),
        &config.research,
    ));
    tracing::warn!(
        research_stores = "memory",
        "in-memory research stores (not durable; catalog listings, access requests, \
         grants and budgets are lost on restart)"
    );

    let query = match config.enclave.key_release_url.as_deref() {
        #[cfg(feature = "dev")]
        Some(url) => Some(Arc::new(key_release_query_service(
            &config,
            url,
            &vault,
            attestation,
            &research,
        )?)),
        // The key-release service is the simulated TEE's stand-in for Cloud
        // KMS (ADR 0004); a production build must not release keys through it.
        #[cfg(not(feature = "dev"))]
        Some(_) => {
            let reason = "KEY_RELEASE_URL is dev-only: the key-release stand-in exists only with the dev feature (ADR 0004)";
            security_audit_event(AuditKind::ServiceStart, None, "denied", reason);
            anyhow::bail!("refusing to start: {reason}");
        }
        None => {
            tracing::info!(
                "confidential query disabled: KEY_RELEASE_URL unset; /api/v1/query, \
                 /api/v1/research/query and /api/v1/attestation answer 503 \
                 (research access does not need key release)"
            );
            None
        }
    };

    // The in-memory registry is not durable; provisioning also writes a
    // control-plane marker to the vault.
    let registry: Arc<dyn platform_tenancy::TenantRegistry> = Arc::new(
        platform_tenancy::InMemoryTenantRegistry::new(admin::default_connector_slugs()),
    );
    let provisioning = Some(Arc::new(ProvisioningService::new(registry, vault.clone())));
    if config.billing.paddle_webhook_secret.is_none() {
        tracing::warn!("MOR_WEBHOOK_SECRET unset — MoR webhook refuses with 503 (fail closed)");
    }

    Ok(AppState {
        config: Arc::new(config),
        vault,
        jwt,
        research: Some(research),
        query,
        provisioning,
    })
}

/// DEV ONLY: the query service on the simulated TEE's key-release stand-in
/// at `url`, running research queries through `research`.
#[cfg(feature = "dev")]
fn key_release_query_service(
    config: &PlatformConfig,
    url: &str,
    vault: &Arc<dyn VaultStore>,
    attestation: Arc<dyn platform_enclave::AttestationProvider>,
    research: &Arc<ResearchService>,
) -> anyhow::Result<crate::query::ConnectorQueryService> {
    use anyhow::Context as _;

    use crate::key_release::{AttestedKeyProvider, EnclaveIdentity, HttpKeyReleaseClient};
    use crate::query::ConnectorQueryService;

    tracing::info!(
        key_release_url = %url,
        require_attestation = config.features.tee_attestation_required,
        "enclave key-release path configured"
    );
    let config_digest = match std::env::var("ENCLAVE_CONFIG_DIGEST_HEX") {
        Ok(raw) if !raw.trim().is_empty() => {
            platform_enclave::decode_hex_array::<32>(raw.trim())
                .context("ENCLAVE_CONFIG_DIGEST_HEX must be exactly 64 hex chars (32 bytes)")?
        }
        _ => [0u8; 32],
    };
    let identity = Arc::new(EnclaveIdentity::with_metadata([0u8; 32], config_digest));
    let keys = Arc::new(AttestedKeyProvider::new(
        identity.clone(),
        attestation.clone(),
        Arc::new(HttpKeyReleaseClient::new(url)),
    ));
    let service = ConnectorQueryService::new(
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
    .with_research(research.clone());
    Ok(service)
}

/// In simulated-TEE / dev mode (`TEE_ATTESTATION_REQUIRED=false`), optionally
/// seal the synthetic QuickBooks fixture into the vault for `DEMO_TENANT_ID`
/// using `DEMO_TENANT_PUBLIC_KEY_B64`.
async fn maybe_seed_demo_fixture(
    config: &PlatformConfig,
    vault: &Arc<dyn VaultStore>,
    attestation: &Arc<dyn platform_enclave::AttestationProvider>,
) -> anyhow::Result<()> {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as B64;

    let demo = &config.connectors.demo_tenant;
    let (Some(raw_tenant), Some(raw_pk_b64)) =
        (demo.tenant_id.as_deref(), demo.public_key_b64.as_deref())
    else {
        return Ok(());
    };

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
