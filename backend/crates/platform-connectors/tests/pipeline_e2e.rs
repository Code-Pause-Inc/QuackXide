//! End-to-end pipeline tests: fixture → Parquet → HPKE envelope → vault,
//! then open and decode as the tenant; plus the fail-closed attestation
//! contract.

use std::sync::Arc;

use arrow::array::{Float64Array, StringArray};
use platform_connectors::parquet_out::read_parquet_batches;
use platform_connectors::pipeline::{EnclavePipeline, PipelineError, SyncJob, envelope_info};
use platform_connectors::snapshot::{SnapshotManifest, manifest_info};
use platform_connectors::source::FixtureSource;
use platform_connectors::worker::SyncScheduler;
use platform_core::TenantId;
use platform_crypto::TenantKeypair;
use platform_enclave::{DevAttestation, SnpAttestation};
use platform_storage::{ObjectStoreVault, TenantPaths, VaultStore};

fn dev_pipeline(vault: Arc<dyn VaultStore>) -> EnclavePipeline {
    EnclavePipeline::new(Arc::new(DevAttestation::allow_insecure_dev()), vault, false)
}

#[tokio::test]
async fn full_confidential_sync_round_trip() {
    let vault: Arc<dyn VaultStore> = Arc::new(ObjectStoreVault::new_in_memory());
    let keypair = TenantKeypair::generate();
    let tenant = TenantId::generate();

    let job = SyncJob {
        tenant,
        tenant_public_key: keypair.public_key(),
        source: Arc::new(FixtureSource::quickbooks_demo().expect("fixture")),
    };

    let report = dev_pipeline(vault.clone())
        .run_sync(&job)
        .await
        .expect("sync");
    assert_eq!(report.connector, "quickbooks");
    assert_eq!(report.written.len(), 1);

    let written = &report.written[0];
    assert!(
        written
            .path
            .starts_with(&format!("tenants/{tenant}/connectors/quickbooks/")),
        "object must live under the tenant's connector prefix, got {}",
        written.path
    );
    assert!(written.path.ends_with(".parquet"));

    let slug = platform_core::ConnectorSlug::new("quickbooks").expect("slug");
    let paths = vault
        .list(&TenantPaths::tenant_root(tenant))
        .await
        .expect("list");
    assert_eq!(
        paths.len(),
        2,
        "one sealed object and its snapshot manifest"
    );

    // The manifest commits exactly the object this sync wrote.
    let manifest = vault
        .get(&TenantPaths::connector_manifest(
            tenant,
            &slug,
            &report.snapshot,
        ))
        .await
        .expect("get manifest");
    let manifest = keypair
        .open_envelope(&manifest_info(&tenant, &slug, &report.snapshot), &manifest)
        .expect("tenant can open the manifest");
    let manifest: SnapshotManifest =
        serde_json::from_slice(manifest.expose()).expect("manifest json");
    assert_eq!(manifest.version, report.snapshot);
    assert_eq!(manifest.objects, vec![written.object]);

    let envelope = vault
        .get(&TenantPaths::connector_snapshot_object(
            tenant,
            &slug,
            &report.snapshot,
            written.object,
        ))
        .await
        .expect("get ciphertext");

    let info = envelope_info(&tenant, &slug, &written.object);
    let parquet = keypair
        .open_envelope(&info, &envelope)
        .expect("tenant can open the envelope");

    let batches =
        read_parquet_batches(bytes::Bytes::copy_from_slice(parquet.expose())).expect("parquet");
    let batch = &batches[0];
    assert_eq!(batch.num_rows(), 3);

    let ids = batch
        .column(0)
        .as_any()
        .downcast_ref::<StringArray>()
        .expect("id column");
    assert_eq!(ids.value(0), "1042");

    let totals = batch
        .column(4)
        .as_any()
        .downcast_ref::<Float64Array>()
        .expect("total column");
    assert_eq!(totals.value(0), 1250.0);
    assert_eq!(totals.value(1), 480.25);
}

#[tokio::test]
async fn scheduler_tick_runs_all_jobs_and_isolates_results() {
    let vault: Arc<dyn VaultStore> = Arc::new(ObjectStoreVault::new_in_memory());
    let keypair = TenantKeypair::generate();
    let tenant = TenantId::generate();

    let jobs = vec![
        SyncJob {
            tenant,
            tenant_public_key: keypair.public_key(),
            source: Arc::new(FixtureSource::quickbooks_demo().expect("fixture")),
        },
        SyncJob {
            tenant,
            tenant_public_key: keypair.public_key(),
            source: Arc::new(FixtureSource::odoo_demo().expect("fixture")),
        },
        SyncJob {
            tenant,
            tenant_public_key: keypair.public_key(),
            source: Arc::new(FixtureSource::crm_demo().expect("fixture")),
        },
    ];

    let scheduler = SyncScheduler::new(Arc::new(dev_pipeline(vault.clone())), jobs);
    // A second tick replaces each connector's snapshot instead of adding to it.
    for _ in 0..2 {
        let results = scheduler.tick().await;
        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|(_, r)| r.is_ok()));

        let stored = vault
            .list(&TenantPaths::tenant_root(tenant))
            .await
            .expect("list");
        assert_eq!(
            stored.len(),
            6,
            "one sealed object and one manifest per connector"
        );
    }
}

#[tokio::test]
async fn required_attestation_fails_closed_without_hardware() {
    let vault: Arc<dyn VaultStore> = Arc::new(ObjectStoreVault::new_in_memory());
    let pipeline = EnclavePipeline::new(Arc::new(SnpAttestation::new()), vault.clone(), true);
    let keypair = TenantKeypair::generate();

    let job = SyncJob {
        tenant: TenantId::generate(),
        tenant_public_key: keypair.public_key(),
        source: Arc::new(FixtureSource::quickbooks_demo().expect("fixture")),
    };

    let err = pipeline.run_sync(&job).await.expect_err("must refuse");
    assert!(matches!(err, PipelineError::AttestationRefused(_)));

    let stored = vault
        .list(&TenantPaths::tenant_root(job.tenant))
        .await
        .expect("list");
    assert!(stored.is_empty(), "nothing may be written on refusal");
}

#[tokio::test]
async fn dev_evidence_cannot_satisfy_required_attestation() {
    let vault: Arc<dyn VaultStore> = Arc::new(ObjectStoreVault::new_in_memory());
    let pipeline =
        EnclavePipeline::new(Arc::new(DevAttestation::allow_insecure_dev()), vault, true);
    let keypair = TenantKeypair::generate();

    let job = SyncJob {
        tenant: TenantId::generate(),
        tenant_public_key: keypair.public_key(),
        source: Arc::new(FixtureSource::quickbooks_demo().expect("fixture")),
    };

    let err = pipeline.run_sync(&job).await.expect_err("must refuse");
    assert!(matches!(err, PipelineError::AttestationRefused(_)));
}

#[tokio::test]
async fn envelopes_are_bound_to_their_object() {
    let vault: Arc<dyn VaultStore> = Arc::new(ObjectStoreVault::new_in_memory());
    let keypair = TenantKeypair::generate();
    let tenant = TenantId::generate();

    let job = SyncJob {
        tenant,
        tenant_public_key: keypair.public_key(),
        source: Arc::new(FixtureSource::crm_demo().expect("fixture")),
    };
    let report = dev_pipeline(vault.clone())
        .run_sync(&job)
        .await
        .expect("sync");
    let written = &report.written[0];

    let slug = platform_core::ConnectorSlug::new("generic_crm").expect("slug");
    let envelope = vault
        .get(&TenantPaths::connector_snapshot_object(
            tenant,
            &slug,
            &report.snapshot,
            written.object,
        ))
        .await
        .expect("get");
    let wrong_info = envelope_info(&tenant, &slug, &platform_core::ObjectId::generate());
    assert!(
        keypair.open_envelope(&wrong_info, &envelope).is_err(),
        "envelope replayed under another object id must not open"
    );

    let right_info = envelope_info(&tenant, &slug, &written.object);
    assert!(keypair.open_envelope(&right_info, &envelope).is_ok());
}
