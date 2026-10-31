//! The confidential sync pipeline: attestation gate → fetch → Parquet →
//! HPKE seal to the tenant public key → flush ciphertext to the vault as one
//! complete snapshot (see [`crate::snapshot`]).
//!
//! Plaintext exists only in process memory between `fetch` and
//! `hpke_seal_to_tenant`; the Parquet buffer is zeroized as soon as its
//! ciphertext exists. Nothing plaintext is ever written.

use std::sync::Arc;

use platform_core::{ConnectorSlug, ObjectId, SnapshotVersion, TenantId};
use platform_crypto::TenantPublicKey;
use platform_enclave::{AttestationProvider, EnclaveError, TeePlatform, fresh_nonce};
use platform_storage::VaultStore;
use platform_telemetry::{AuditKind, security_audit_event};

use crate::ConnectorError;
use crate::parquet_out::dataset_to_parquet;
use crate::snapshot::SnapshotWriter;
use crate::source::{ConnectorSource, SyncContext};

#[derive(Debug, thiserror::Error)]
pub enum PipelineError {
    #[error("attestation refused: {0}")]
    AttestationRefused(String),
    #[error(transparent)]
    Connector(#[from] ConnectorError),
    #[error("storage error: {0}")]
    Storage(String),
    #[error("envelope seal failed")]
    Seal,
}

/// One tenant-connector sync assignment.
pub struct SyncJob {
    pub tenant: TenantId,
    pub tenant_public_key: TenantPublicKey,
    pub source: Arc<dyn ConnectorSource>,
}

#[derive(Debug)]
pub struct WrittenObject {
    pub dataset: String,
    pub object: ObjectId,
    pub path: String,
    pub ciphertext_bytes: usize,
}

#[derive(Debug)]
pub struct SyncReport {
    pub connector: String,
    /// The snapshot this sync committed; queries now read only it.
    pub snapshot: SnapshotVersion,
    pub written: Vec<WrittenObject>,
}

/// HPKE `info` binding for a connector object
/// ([`platform_crypto::info::connector_object`]).
pub fn envelope_info(tenant: &TenantId, slug: &ConnectorSlug, object: &ObjectId) -> Vec<u8> {
    platform_crypto::info::connector_object(tenant, slug, object)
}

pub struct EnclavePipeline {
    attestation: Arc<dyn AttestationProvider>,
    vault: Arc<dyn VaultStore>,
    /// `TEE_ATTESTATION_REQUIRED` (true in production): only SEV-SNP
    /// evidence lets a sync proceed.
    require_attestation: bool,
}

impl EnclavePipeline {
    pub fn new(
        attestation: Arc<dyn AttestationProvider>,
        vault: Arc<dyn VaultStore>,
        require_attestation: bool,
    ) -> Self {
        Self {
            attestation,
            vault,
            require_attestation,
        }
    }

    async fn attestation_gate(&self, tenant: TenantId) -> Result<(), PipelineError> {
        let nonce = fresh_nonce();

        match self.attestation.produce_evidence(&nonce).await {
            Ok(evidence) if evidence.platform == TeePlatform::SevSnp => {
                if let Err(err) = self.attestation.verify_evidence(&evidence, &nonce) {
                    security_audit_event(
                        AuditKind::TeeAttestation,
                        Some(tenant),
                        "denied",
                        "SEV-SNP evidence failed verification",
                    );
                    return Err(PipelineError::AttestationRefused(err.to_string()));
                }
                security_audit_event(
                    AuditKind::TeeAttestation,
                    Some(tenant),
                    "ok",
                    "SEV-SNP evidence produced for sync",
                );
                Ok(())
            }
            Ok(evidence) if evidence.platform == TeePlatform::Simulated => {
                if self.require_attestation {
                    security_audit_event(
                        AuditKind::TeeAttestation,
                        Some(tenant),
                        "denied",
                        "simulated evidence cannot satisfy required hardware attestation",
                    );
                    return Err(PipelineError::AttestationRefused(
                        "evidence platform is simulated, not hardware".into(),
                    ));
                }
                if let Err(err) = self.attestation.verify_evidence(&evidence, &nonce) {
                    security_audit_event(
                        AuditKind::TeeAttestation,
                        Some(tenant),
                        "denied",
                        "simulated evidence failed verification",
                    );
                    return Err(PipelineError::AttestationRefused(err.to_string()));
                }
                security_audit_event(
                    AuditKind::TeeAttestation,
                    Some(tenant),
                    "simulated",
                    "simulated evidence verified for sync (dev only)",
                );
                Ok(())
            }
            Ok(_) if !self.require_attestation => {
                security_audit_event(
                    AuditKind::TeeAttestation,
                    Some(tenant),
                    "dev_insecure",
                    "development evidence accepted because attestation is not required",
                );
                Ok(())
            }
            Ok(_) => {
                security_audit_event(
                    AuditKind::TeeAttestation,
                    Some(tenant),
                    "denied",
                    "non-SEV-SNP evidence cannot satisfy required attestation",
                );
                Err(PipelineError::AttestationRefused(
                    "evidence platform is not SEV-SNP".into(),
                ))
            }
            // Only a missing TEE may run unattested in dev, as in `gate_execution`;
            // a provider that rejects (including a build without the simulator) refuses.
            Err(err @ EnclaveError::Unavailable(_)) if !self.require_attestation => {
                security_audit_event(
                    AuditKind::TeeAttestation,
                    Some(tenant),
                    "dev_unattested",
                    "proceeding without evidence because attestation is not required (dev only)",
                );
                tracing::warn!(error = %err, "sync running UNATTESTED (dev mode)");
                Ok(())
            }
            Err(err) => {
                security_audit_event(
                    AuditKind::TeeAttestation,
                    Some(tenant),
                    "denied",
                    "attestation unavailable; refusing sync (fail closed)",
                );
                Err(PipelineError::AttestationRefused(err.to_string()))
            }
        }
    }

    /// Run one confidential sync for one tenant-connector pair.
    pub async fn run_sync(&self, job: &SyncJob) -> Result<SyncReport, PipelineError> {
        self.attestation_gate(job.tenant).await?;

        let context = SyncContext {
            tenant: job.tenant,
            since: None,
        };
        let datasets = job.source.fetch(&context).await?;
        let slug = job.source.descriptor().slug.clone();

        let mut snapshot = SnapshotWriter::begin(
            &*self.vault,
            job.tenant,
            &job.tenant_public_key,
            slug.clone(),
        );
        let mut written = Vec::with_capacity(datasets.len());
        for dataset in &datasets {
            let parquet = dataset_to_parquet(dataset)?;
            let object = snapshot.put(&dataset.name, parquet.expose()).await?;
            drop(parquet); // zeroize the plaintext immediately

            security_audit_event(
                AuditKind::ConnectorSync,
                Some(job.tenant),
                "ok",
                &format!(
                    "dataset={} object={} rows={} sealed_bytes={}",
                    dataset.name,
                    object.object,
                    dataset.rows.len(),
                    object.ciphertext_bytes
                ),
            );
            written.push(object);
        }
        let snapshot = snapshot.commit().await?;

        Ok(SyncReport {
            connector: slug.as_str().to_owned(),
            snapshot,
            written,
        })
    }
}
