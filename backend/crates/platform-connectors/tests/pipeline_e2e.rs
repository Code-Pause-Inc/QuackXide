//! End-to-end pipeline tests: fixture → Parquet → HPKE envelope → vault,
//! then open and decode as the tenant; plus the fail-closed attestation
//! contract.

use std::sync::Arc;
use std::time::Duration;

use arrow::array::{Float64Array, StringArray};
use async_trait::async_trait;
use platform_connectors::dataset::Dataset;
use platform_connectors::parquet_out::read_parquet_batches;
use platform_connectors::pipeline::{EnclavePipeline, PipelineError, SyncJob, envelope_info};
use platform_connectors::snapshot::{SnapshotManifest, manifest_info};
use platform_connectors::source::{ConnectorSource, FixtureSource, SyncContext};
use platform_connectors::worker::SyncScheduler;
use platform_connectors::{ConnectorDescriptor, ConnectorError};
use platform_core::{ConnectorSlug, TenantId};
use platform_crypto::TenantKeypair;
use platform_enclave::{DevAttestation, SnpAttestation};
use platform_storage::{ObjectStoreVault, TenantPaths, VaultStore};
use tokio::sync::{Notify, watch};

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

    let slug = ConnectorSlug::new("quickbooks").expect("slug");
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

/// A source whose fetch waits for the test, to hold a sync in flight.
struct GatedSource {
    inner: FixtureSource,
    started: Arc<Notify>,
    release: Arc<Notify>,
}

#[async_trait]
impl ConnectorSource for GatedSource {
    fn descriptor(&self) -> &ConnectorDescriptor {
        self.inner.descriptor()
    }

    async fn fetch(&self, ctx: &SyncContext) -> Result<Vec<Dataset>, ConnectorError> {
        self.started.notify_one();
        self.release.notified().await;
        self.inner.fetch(ctx).await
    }
}

#[tokio::test]
async fn stopping_the_scheduler_finishes_the_sync_in_flight_and_starts_no_more() {
    let vault: Arc<dyn VaultStore> = Arc::new(ObjectStoreVault::new_in_memory());
    let keypair = TenantKeypair::generate();
    let tenant = TenantId::generate();
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());

    let jobs = vec![
        SyncJob {
            tenant,
            tenant_public_key: keypair.public_key(),
            source: Arc::new(GatedSource {
                inner: FixtureSource::quickbooks_demo().expect("fixture"),
                started: started.clone(),
                release: release.clone(),
            }),
        },
        SyncJob {
            tenant,
            tenant_public_key: keypair.public_key(),
            source: Arc::new(FixtureSource::odoo_demo().expect("fixture")),
        },
    ];

    let (stop, stop_rx) = watch::channel(false);
    let scheduler = SyncScheduler::new(Arc::new(dev_pipeline(vault.clone())), jobs);
    let running = tokio::spawn(scheduler.run(Duration::from_secs(3600), stop_rx));

    // Stop while the first sync is fetching, then let it continue.
    started.notified().await;
    stop.send(true).expect("scheduler is running");
    release.notify_one();
    tokio::time::timeout(Duration::from_secs(5), running)
        .await
        .expect("scheduler stops")
        .expect("scheduler task");

    let quickbooks = ConnectorSlug::new("quickbooks").expect("slug");
    let manifests = vault
        .list(&TenantPaths::connector_manifests_prefix(
            tenant,
            &quickbooks,
        ))
        .await
        .expect("list");
    assert_eq!(manifests.len(), 1, "the sync in flight committed");
    let stored = vault
        .list(&TenantPaths::tenant_root(tenant))
        .await
        .expect("list");
    assert_eq!(
        stored.len(),
        2,
        "only that sync's object and manifest; the next job never started"
    );
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

/// A provider that refuses outright, as a build without the simulator does.
struct RejectingAttestation;

#[async_trait]
impl platform_enclave::AttestationProvider for RejectingAttestation {
    async fn produce_evidence(
        &self,
        _nonce: &[u8],
    ) -> Result<platform_enclave::AttestationEvidence, platform_enclave::EnclaveError> {
        Err(platform_enclave::EnclaveError::Rejected("refused".into()))
    }
}

#[tokio::test]
async fn rejected_provider_refuses_sync_even_when_not_required() {
    let vault: Arc<dyn VaultStore> = Arc::new(ObjectStoreVault::new_in_memory());
    let pipeline = EnclavePipeline::new(Arc::new(RejectingAttestation), vault.clone(), false);
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
async fn simulated_snp_sync_verifies_in_dev_and_refuses_bad_policy_or_required_hardware() {
    use platform_enclave::{GuestPolicy, SimulatedSnp, SimulatedSnpConfig};

    let vault: Arc<dyn VaultStore> = Arc::new(ObjectStoreVault::new_in_memory());
    let keypair = TenantKeypair::generate();
    let job = SyncJob {
        tenant: TenantId::generate(),
        tenant_public_key: keypair.public_key(),
        source: Arc::new(FixtureSource::quickbooks_demo().expect("fixture")),
    };

    // 1. Valid SimulatedSnp in dev mode (require_attestation = false) verifies and syncs.
    let valid_pipeline = EnclavePipeline::new(Arc::new(SimulatedSnp::new()), vault.clone(), false);
    valid_pipeline
        .run_sync(&job)
        .await
        .expect("simulated SNP sync succeeds in dev mode");

    // 2. SimulatedSnp with wrong measurement fails verification on the sync path.
    let wrong_meas = SimulatedSnp::with_config(SimulatedSnpConfig {
        measurement: [0xEE; 48],
        ..SimulatedSnpConfig::default()
    });
    let bad_meas_pipeline = EnclavePipeline::new(Arc::new(wrong_meas), vault.clone(), false);
    let err = bad_meas_pipeline
        .run_sync(&job)
        .await
        .expect_err("wrong measurement must refuse sync");
    assert!(matches!(err, PipelineError::AttestationRefused(_)));

    // 3. SimulatedSnp with debug policy fails verification on the sync path.
    let debug_sim = SimulatedSnp::with_config(SimulatedSnpConfig {
        policy: GuestPolicy::production_default().with_debug(true),
        ..SimulatedSnpConfig::default()
    });
    let debug_pipeline = EnclavePipeline::new(Arc::new(debug_sim), vault.clone(), false);
    let err = debug_pipeline
        .run_sync(&job)
        .await
        .expect_err("debug policy must refuse sync");
    assert!(matches!(err, PipelineError::AttestationRefused(_)));

    // 4. Valid SimulatedSnp is refused when hardware attestation is required (production).
    let prod_pipeline = EnclavePipeline::new(Arc::new(SimulatedSnp::new()), vault, true);
    let err = prod_pipeline
        .run_sync(&job)
        .await
        .expect_err("simulated SNP cannot satisfy required hardware attestation");
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
