//! DEV demo: seals a QuickBooks fixture with the connector pipeline on the
//! simulated SEV-SNP TEE (`SimulatedSnp`), releases the tenant key via the
//! attestation-verifying relying party (`KeyReleaseRelyingParty` +
//! `AttestedKeyProvider`), and prints an aggregate result.
//!
//!   cargo run -p platform-api --features dev --bin query-demo

use std::sync::Arc;

use platform_api::key_release::{
    AttestedKeyProvider, EnclaveIdentity, InProcessKeyReleaseClient, KeyReleaseRelyingParty,
};
use platform_api::query::ConnectorQueryService;
use platform_connectors::pipeline::{EnclavePipeline, SyncJob};
use platform_connectors::source::FixtureSource;
use platform_core::{ConnectorSlug, TenantId, ZkMode};
use platform_crypto::TenantKeypair;
use platform_enclave::SimulatedSnp;
use platform_storage::{ObjectStoreVault, VaultStore};
use quackxide_engine::EngineSettings;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    platform_telemetry::init_from_env();

    let vault: Arc<dyn VaultStore> = Arc::new(ObjectStoreVault::new_in_memory());
    let keypair = TenantKeypair::generate();
    let tenant = TenantId::generate();
    let simulated_snp = Arc::new(SimulatedSnp::new());

    // Seal fixture connector data into the vault on the simulated TEE.
    let pipeline = EnclavePipeline::new(simulated_snp.clone(), vault.clone(), false);
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

    // Enroll the tenant key with the key-release relying party (separate from enclave RAM).
    let relying_party = Arc::new(KeyReleaseRelyingParty::new(
        simulated_snp.verifier(1_000),
        false,
    ));
    relying_party.insert_tenant_key(tenant, &keypair);

    let identity = Arc::new(EnclaveIdentity::generate());
    let keys = Arc::new(AttestedKeyProvider::new(
        identity.clone(),
        simulated_snp.clone(),
        Arc::new(InProcessKeyReleaseClient(relying_party)),
    ));

    // Decrypt in a QueryScope via attested key release and run analytics.
    let service = ConnectorQueryService::new(
        vault,
        keys,
        simulated_snp,
        EngineSettings {
            zk: ZkMode::Disabled,
            max_concurrent_queries: 4,
        },
        false,
    )
    .with_enclave_identity(identity);

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
