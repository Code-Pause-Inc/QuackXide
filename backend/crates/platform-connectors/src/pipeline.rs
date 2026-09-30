//! The confidential sync pipeline: attestation gate → fetch → Parquet →
//! HPKE seal to the tenant public key → flush ciphertext to the vault.
//!
//! Plaintext exists only in process memory between `fetch` and
//! `hpke_seal_to_tenant`; the Parquet buffer is zeroized as soon as its
//! ciphertext exists. Nothing plaintext is ever written.

use std::sync::Arc;

use platform_core::{ConnectorSlug, ObjectId, TenantId};
use platform_crypto::{TenantPublicKey, hpke_seal_to_tenant};
use platform_enclave::{AttestationProvider, TeePlatform};
use platform_storage::{TenantPaths, VaultStore};
use platform_telemetry::{AuditKind, security_audit_event};
use rand::RngCore;

use crate::ConnectorError;
use crate::parquet_out::dataset_to_parquet;
use crate::source::{ConnectorSource, SyncContext};

const ATTESTATION_NONCE_BYTES: usize = 32;

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
    pub written: Vec<WrittenObject>,
}

/// Canonical HPKE `info` binding for a connector object. The browser-side
/// reader must derive the identical string to open the envelope.
pub fn envelope_info(tenant: &TenantId, slug: &ConnectorSlug, object: &ObjectId) -> Vec<u8> {
    format!("tenant-envelope-v1|{tenant}|{slug}|{object}").into_bytes()
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
        let mut nonce = [0u8; ATTESTATION_NONCE_BYTES];
        rand::rngs::OsRng.fill_bytes(&mut nonce);

        match self.attestation.produce_evidence(&nonce).await {
            Ok(evidence) if evidence.platform == TeePlatform::SevSnp => {
                security_audit_event(
                    AuditKind::TeeAttestation,
                    Some(tenant),
                    "ok",
                    "SEV-SNP evidence produced for sync",
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
            Err(err) if !self.require_attestation => {
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

        let mut written = Vec::with_capacity(datasets.len());
        for dataset in &datasets {
            let object = ObjectId::generate();

            let parquet = dataset_to_parquet(dataset)?;
            let info = envelope_info(&job.tenant, &slug, &object);
            let envelope = hpke_seal_to_tenant(&job.tenant_public_key, &info, parquet.expose())
                .map_err(|_| PipelineError::Seal)?;
            drop(parquet); // zeroize the plaintext immediately
            let ciphertext_bytes = envelope.len();

            let path = TenantPaths::connector_object(job.tenant, &slug, object);
            self.vault
                .put(&path, envelope.into())
                .await
                .map_err(|e| PipelineError::Storage(e.to_string()))?;

            security_audit_event(
                AuditKind::ConnectorSync,
                Some(job.tenant),
                "ok",
                &format!(
                    "dataset={} object={object} rows={} sealed_bytes={}",
                    dataset.name,
                    dataset.rows.len(),
                    ciphertext_bytes
                ),
            );

            written.push(WrittenObject {
                dataset: dataset.name.clone(),
                object,
                path: path.as_str().to_owned(),
                ciphertext_bytes,
            });
        }

        Ok(SyncReport {
            connector: slug.as_str().to_owned(),
            written,
        })
    }
}
