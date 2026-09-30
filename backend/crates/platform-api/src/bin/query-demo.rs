//! DEV demo: seals a QuickBooks fixture with the connector pipeline, then
//! decrypts it in a query scope and prints an aggregate result. No
//! credentials or network required.
//!
//!   cargo run -p platform-api --bin query-demo

use std::sync::Arc;

use platform_api::query::{ConnectorQueryService, DevKeyProvider};
use platform_connectors::pipeline::{EnclavePipeline, SyncJob};
use platform_connectors::source::FixtureSource;
use platform_core::{ConnectorSlug, TenantId, ZkMode};
use platform_crypto::TenantKeypair;
use platform_enclave::DevAttestation;
use platform_storage::{ObjectStoreVault, VaultStore};
use quackxide_engine::EngineSettings;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    platform_telemetry::init_from_env();

    let vault: Arc<dyn VaultStore> = Arc::new(ObjectStoreVault::new_in_memory());
    let keypair = TenantKeypair::generate();
    let tenant = TenantId::generate();

    // Seal fixture connector data into the vault.
    let pipeline = EnclavePipeline::new(
        Arc::new(DevAttestation::allow_insecure_dev()),
        vault.clone(),
        false,
    );
    let job = SyncJob {
        tenant,
        tenant_public_key: keypair.public_key(),
        source: Arc::new(FixtureSource::quickbooks_demo()?),
    };
    let report = pipeline.run_sync(&job).await?;
    eprintln!(
        "sealed {} object(s) for tenant {tenant} under connector '{}'",
        report.written.len(),
        report.connector
    );

    // Decrypt in a QueryScope and run analytics.
    let service = ConnectorQueryService::new(
        vault,
        Arc::new(DevKeyProvider::new(tenant, keypair)),
        Arc::new(DevAttestation::allow_insecure_dev()),
        EngineSettings {
            zk: ZkMode::Disabled,
            max_concurrent_queries: 4,
        },
        false,
    );

    let sql = "SELECT currency, COUNT(*) AS invoices, SUM(total) AS revenue \
               FROM quickbooks GROUP BY currency ORDER BY revenue DESC";
    eprintln!("\nquery: {sql}\n");

    let result = service
        .query(
            tenant,
            &ConnectorSlug::new("quickbooks").expect("slug"),
            sql,
        )
        .await
        .map_err(|_| anyhow::anyhow!("query failed"))?;

    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}
