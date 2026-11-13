//! Confidential query service behind `POST /api/v1/query`,
//! `POST /api/v1/research/query` and `GET /api/v1/attestation`.
//!
//! Inside the attested enclave, a query passes the attestation gate, decrypts
//! each sealed object of the dataset's current snapshot with the tenant key
//! released into the enclave (`EnclaveKeyProvider`), runs the SQL in a
//! [`QueryScope`], and zeroizes the decrypted blobs. A dataset is a
//! connector's or a steward upload's (ADR 0012); requests name it by its
//! slug in their `connector` field. Tenant identity comes only from the
//! verified JWT; requests name a dataset, never a tenant.
//!
//! Trust boundary: production releases tenant keys only into a
//! hardware-attested enclave whose RAM the operator cannot read. The dev
//! providers here hold keys in ordinary process memory and are for local use
//! only.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use platform_connectors::snapshot::{
    SnapshotManifest, manifest_info, newest_manifest, object_info,
};
use platform_core::{ConnectorSlug, DatasetKind, DeclaredSchema, TenantId};
use platform_crypto::{SecretBytes, TenantKeypair};
use platform_enclave::{AttestationProvider, fresh_nonce, gate_execution};
use platform_storage::{SnapshotRecord, StorageError, TenantPaths, VaultPath, VaultStore};
use platform_telemetry::{AuditKind, security_audit_event};
use platform_tenancy::BudgetError;
use prometheus_client::metrics::histogram::Histogram;
use quackxide_engine::{
    DisclosurePolicy, EngineSettings, MinCountThreshold, QueryError, QueryScope,
};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::{Semaphore, SemaphorePermit};

use crate::ApiError;
use crate::key_release::{AttestationBundle, EnclaveIdentity};
use crate::research::ResearchService;

/// Per-query handle holding a tenant's released key in enclave RAM for the
/// duration of a single query.
#[async_trait]
pub trait QueryKeySession: Send + Sync {
    async fn open_envelope(&self, info: &[u8], envelope: &[u8]) -> Result<SecretBytes, ApiError>;
}

struct DelegatingKeySession<'a, P: EnclaveKeyProvider + ?Sized> {
    provider: &'a P,
    tenant: TenantId,
}

#[async_trait]
impl<P: EnclaveKeyProvider + ?Sized> QueryKeySession for DelegatingKeySession<'_, P> {
    async fn open_envelope(&self, info: &[u8], envelope: &[u8]) -> Result<SecretBytes, ApiError> {
        self.provider
            .open_envelope(self.tenant, info, envelope)
            .await
    }
}

/// Opens a tenant's sealed envelopes inside the enclave. In production this is
/// Cloud KMS behind attestation (ADR 0004, P50); the simulated TEE uses the
/// dev-only `key_release::AttestedKeyProvider`.
#[async_trait]
pub trait EnclaveKeyProvider: Send + Sync {
    async fn open_envelope(
        &self,
        tenant: TenantId,
        info: &[u8],
        envelope: &[u8],
    ) -> Result<SecretBytes, ApiError>;

    /// Acquire a per-query key session for `tenant`. `key_release::AttestedKeyProvider`
    /// overrides this so key release happens once per query rather than once
    /// per envelope.
    async fn begin_query_session<'a>(
        &'a self,
        tenant: TenantId,
    ) -> Result<Box<dyn QueryKeySession + 'a>, ApiError> {
        Ok(Box::new(DelegatingKeySession {
            provider: self,
            tenant,
        }))
    }
}

/// DEV ONLY: holds one tenant keypair in process memory, which defeats the
/// zero-trust boundary. For local development and tests.
pub struct DevKeyProvider {
    tenant: TenantId,
    keypair: TenantKeypair,
}

impl DevKeyProvider {
    pub fn new(tenant: TenantId, keypair: TenantKeypair) -> Self {
        tracing::warn!(
            "DevKeyProvider active — tenant key lives in process memory (dev only, not zero-trust)"
        );
        Self { tenant, keypair }
    }
}

#[async_trait]
impl EnclaveKeyProvider for DevKeyProvider {
    async fn open_envelope(
        &self,
        tenant: TenantId,
        info: &[u8],
        envelope: &[u8],
    ) -> Result<SecretBytes, ApiError> {
        if tenant != self.tenant {
            return Err(ApiError::Backend);
        }
        self.keypair
            .open_envelope(info, envelope)
            .map_err(|_| ApiError::Backend)
    }
}

/// DEV ONLY: holds several tenants' keypairs so research queries, which
/// decrypt a steward's data on a researcher's behalf, can be exercised.
#[derive(Default)]
pub struct MultiTenantDevKeyProvider {
    keys: HashMap<TenantId, TenantKeypair>,
}

impl MultiTenantDevKeyProvider {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, tenant: TenantId, keypair: TenantKeypair) {
        self.keys.insert(tenant, keypair);
    }
}

#[async_trait]
impl EnclaveKeyProvider for MultiTenantDevKeyProvider {
    async fn open_envelope(
        &self,
        tenant: TenantId,
        info: &[u8],
        envelope: &[u8],
    ) -> Result<SecretBytes, ApiError> {
        self.keys
            .get(&tenant)
            .ok_or(ApiError::Backend)?
            .open_envelope(info, envelope)
            .map_err(|_| ApiError::Backend)
    }
}

/// Vault, key release, attestation, and engine settings for the query
/// endpoints, plus the research service through which research queries
/// check grants and charge budgets.
pub struct ConnectorQueryService {
    vault: Arc<dyn VaultStore>,
    keys: Arc<dyn EnclaveKeyProvider>,
    attestation: Arc<dyn AttestationProvider>,
    identity: Arc<EnclaveIdentity>,
    settings: EngineSettings,
    require_attestation: bool,
    /// The `Arc` `AppState::research` also holds. None ⇒ research queries
    /// refuse with 503.
    research: Option<Arc<ResearchService>>,
    /// Minimum cohort size `k` for disclosure control, shared by
    /// zero-knowledge and research queries. Zero refuses every such query.
    min_cohort: u64,
    /// Bounds how many queries hold decrypted plaintext at once
    /// (`EngineSettings::max_concurrent_queries`).
    plaintext_slots: Semaphore,
    /// Time spent waiting for a plaintext slot, exported as a metric.
    plaintext_wait: Histogram,
}

/// Budget units one research query consumes.
const RESEARCH_QUERY_COST: u64 = 1;

impl ConnectorQueryService {
    pub fn new(
        vault: Arc<dyn VaultStore>,
        keys: Arc<dyn EnclaveKeyProvider>,
        attestation: Arc<dyn AttestationProvider>,
        settings: EngineSettings,
        require_attestation: bool,
    ) -> Self {
        if settings.max_concurrent_queries == 0 {
            tracing::warn!("max_concurrent_queries is 0 — confidential queries will be refused");
        }
        let plaintext_slots =
            Semaphore::new(settings.max_concurrent_queries.min(Semaphore::MAX_PERMITS));
        Self {
            plaintext_slots,
            plaintext_wait: crate::metrics::latency_histogram(),
            vault,
            keys,
            attestation,
            identity: Arc::new(EnclaveIdentity::generate()),
            settings,
            require_attestation,
            research: None,
            min_cohort: platform_config::DEFAULT_MIN_COHORT_SIZE,
        }
    }

    /// Attach a shared [`EnclaveIdentity`] (used when pairing with
    /// the dev-only `key_release::AttestedKeyProvider` so `GET /api/v1/attestation`
    /// and key release report the identical ephemeral public keys).
    pub fn with_enclave_identity(mut self, identity: Arc<EnclaveIdentity>) -> Self {
        self.identity = identity;
        self
    }

    /// Produce an [`AttestationBundle`] binding `nonce` and this enclave's
    /// ephemeral public keys (`GET /api/v1/attestation`).
    pub async fn attestation_bundle(&self, nonce: [u8; 32]) -> Result<AttestationBundle, ApiError> {
        use base64::Engine as _;
        use base64::engine::general_purpose::STANDARD as B64;

        let binding = self.identity.binding_for_nonce(nonce);
        let report_data = binding.to_report_data();
        let evidence = self
            .attestation
            .produce_evidence(&report_data)
            .await
            .map_err(|_| ApiError::AttestationUnavailable)?;

        if self.require_attestation && evidence.platform != platform_enclave::TeePlatform::SevSnp {
            return Err(ApiError::AttestationUnavailable);
        }
        self.attestation
            .verify_evidence(&evidence, &report_data)
            .map_err(|_| ApiError::AttestationUnavailable)?;

        Ok(AttestationBundle {
            platform: platform_label(evidence.platform).to_owned(),
            nonce_b64: B64.encode(nonce),
            token: evidence.token,
            enclave_hpke_public_key_b64: B64.encode(self.identity.enclave_hpke_public_key()),
            result_signing_public_key_b64: B64.encode(self.identity.result_signing_public_key()),
            tls_cert_sha256_b64: B64.encode(self.identity.tls_cert_sha256()),
            config_digest_b64: B64.encode(self.identity.config_digest()),
        })
    }

    /// Enable research queries, which check grants and charge budgets
    /// through `research`. Also sets this service's `k` to `research`'s
    /// ([`with_min_cohort`](Self::with_min_cohort)). Pass the `Arc` that
    /// `AppState::research` holds, so the grant a research route creates is
    /// the one a research query checks and charges.
    pub fn with_research(mut self, research: Arc<ResearchService>) -> Self {
        self.min_cohort = research.min_cohort();
        self.research = Some(research);
        self
    }

    /// Set the minimum cohort size `k` (`RESEARCH_MIN_COHORT_SIZE`).
    pub fn with_min_cohort(mut self, min_cohort: u64) -> Self {
        self.min_cohort = min_cohort;
        self
    }

    fn threshold(&self) -> Arc<dyn DisclosurePolicy> {
        Arc::new(MinCountThreshold {
            k: i64::try_from(self.min_cohort).unwrap_or(i64::MAX),
        })
    }

    /// Attestation gate + audit, shared by own-data and research queries.
    /// Returns the platform that passed, for the response's `tee_platform`.
    async fn gate(
        &self,
        tenant: TenantId,
        label: &str,
    ) -> Result<platform_enclave::TeePlatform, ApiError> {
        let nonce = fresh_nonce();
        match gate_execution(self.attestation.as_ref(), self.require_attestation, &nonce).await {
            Ok(platform_enclave::TeePlatform::SevSnp) => {
                security_audit_event(
                    AuditKind::TeeAttestation,
                    Some(tenant),
                    "ok",
                    &format!("SEV-SNP evidence produced for {label}"),
                );
                Ok(platform_enclave::TeePlatform::SevSnp)
            }
            Ok(platform_enclave::TeePlatform::Simulated) => {
                security_audit_event(
                    AuditKind::TeeAttestation,
                    Some(tenant),
                    "simulated",
                    &format!("simulated evidence verified for {label} (dev only)"),
                );
                Ok(platform_enclave::TeePlatform::Simulated)
            }
            Ok(platform) => {
                security_audit_event(
                    AuditKind::TeeAttestation,
                    Some(tenant),
                    "dev_insecure",
                    &format!("{label} proceeding unattested (attestation not required; dev only)"),
                );
                Ok(platform)
            }
            Err(err) => {
                security_audit_event(
                    AuditKind::TeeAttestation,
                    Some(tenant),
                    "denied",
                    &format!("{label} refused: attestation unavailable"),
                );
                tracing::warn!(error = %err, "{label} refused by attestation gate");
                Err(ApiError::AttestationUnavailable)
            }
        }
    }

    /// Whether the attestation gate would let a query through now. Unlike
    /// `gate`, it emits no audit event, since readiness probes run every few
    /// seconds.
    pub async fn attestation_ready(&self) -> bool {
        gate_execution(
            self.attestation.as_ref(),
            self.require_attestation,
            &fresh_nonce(),
        )
        .await
        .is_ok()
    }

    /// Wait for a plaintext slot. Hold the permit until the decrypted blobs
    /// are dropped. A limit of zero refuses rather than waiting forever.
    async fn plaintext_slot(&self) -> Result<SemaphorePermit<'_>, ApiError> {
        if self.settings.max_concurrent_queries == 0 {
            return Err(ApiError::QueryUnavailable);
        }
        // Records the wait however it ends, including a cancelled query.
        let _wait = crate::metrics::Timer::start(self.plaintext_wait.clone());
        self.plaintext_slots
            .acquire()
            .await
            .map_err(|_| ApiError::QueryUnavailable)
    }

    /// The plaintext-slot wait histogram, for registering with the metrics.
    pub(crate) fn plaintext_wait_metric(&self) -> Histogram {
        self.plaintext_wait.clone()
    }

    /// A stored part of the current snapshot. Its manifest or record listed
    /// it, so a missing one is a broken or pruned snapshot (502), never a
    /// 404 about the caller's request.
    async fn snapshot_part(&self, owner: TenantId, path: &VaultPath) -> Result<Bytes, ApiError> {
        match self.vault.get(path).await {
            Ok(bytes) => Ok(bytes),
            Err(StorageError::NotFound) => {
                security_audit_event(
                    AuditKind::DataAccess,
                    Some(owner),
                    "failed",
                    "snapshot object listed by its manifest is missing",
                );
                Err(ApiError::Backend)
            }
            Err(other) => Err(other.into()),
        }
    }

    /// Decrypt `owner`'s current snapshot of `dataset` to plaintext Parquet:
    /// the objects listed by the newest manifest, and nothing else, so
    /// repeated or interrupted writes never add rows. Objects open under the
    /// `info` of the dataset's kind (ADR 0012). The snapshot's plaintext
    /// record is read before any key is released, and an upload's declared
    /// schema and row cap come back for the engine to check. The blobs
    /// zeroize on drop, so an error partway through wipes the objects
    /// already opened.
    async fn decrypt_dataset(
        &self,
        owner: TenantId,
        dataset: &ConnectorSlug,
    ) -> Result<DecryptedDataset, ApiError> {
        let Some((version, path)) = newest_manifest(&*self.vault, owner, dataset).await? else {
            return Ok(DecryptedDataset::default());
        };

        let record = match self
            .vault
            .get(&TenantPaths::connector_record(owner, dataset, &version))
            .await
        {
            Ok(bytes) => SnapshotRecord::parse(&bytes, &version).ok(),
            Err(StorageError::NotFound) => None,
            Err(other) => return Err(other.into()),
        };
        // Every committed snapshot has a record; an upload's must carry
        // what its steward declared.
        let declared = match (dataset.kind(), record) {
            (DatasetKind::Connector, Some(_)) => Some(None),
            (
                DatasetKind::Upload,
                Some(SnapshotRecord {
                    schema: Some(schema),
                    row_cap: Some(row_cap),
                    ..
                }),
            ) => Some(Some((schema, row_cap))),
            _ => None,
        };
        let Some(declared) = declared else {
            security_audit_event(
                AuditKind::DataAccess,
                Some(owner),
                "failed",
                "snapshot record is missing, malformed or incomplete",
            );
            return Err(ApiError::Backend);
        };

        let key_session = self.keys.begin_query_session(owner).await?;
        let envelope = self.snapshot_part(owner, &path).await?;
        let info = manifest_info(&owner, dataset, &version);
        let plaintext = key_session.open_envelope(&info, &envelope).await?;
        let manifest = serde_json::from_slice::<SnapshotManifest>(plaintext.expose())
            .ok()
            .filter(|m| m.version == version)
            .filter(|m| m.objects.iter().collect::<HashSet<_>>().len() == m.objects.len());
        let Some(manifest) = manifest else {
            security_audit_event(
                AuditKind::DataAccess,
                Some(owner),
                "failed",
                "snapshot manifest is malformed, mismatched or lists an object twice",
            );
            return Err(ApiError::Backend);
        };

        let mut blobs = Vec::with_capacity(manifest.objects.len());
        for object in &manifest.objects {
            let path = TenantPaths::connector_snapshot_object(owner, dataset, &version, *object);
            let envelope = self.snapshot_part(owner, &path).await?;
            let info = object_info(&owner, dataset, object);
            let plaintext = key_session.open_envelope(&info, &envelope).await?;
            blobs.push(plaintext);
        }
        Ok(DecryptedDataset { blobs, declared })
    }

    pub async fn query(
        &self,
        tenant: TenantId,
        connector: &ConnectorSlug,
        sql: &str,
    ) -> Result<Value, ApiError> {
        let tee_platform = platform_label(self.gate(tenant, "query").await?);
        let _slot = self.plaintext_slot().await?;
        let dataset = self.decrypt_dataset(tenant, connector).await?;
        let object_count = dataset.blobs.len();
        let zk_mode = self.settings.zk.is_enabled();

        if dataset.blobs.is_empty() {
            security_audit_event(
                AuditKind::QueryExecuted,
                Some(tenant),
                "ok",
                &format!("connector={connector} objects=0 (no data)"),
            );
            return Ok(json!({
                "rows": [], "row_count": 0, "suppressed_rows": 0, "object_count": 0,
                "zk_mode": zk_mode, "tee_platform": tee_platform,
            }));
        }

        let disclosure = zk_mode.then(|| self.threshold());
        let result = run_scoped(self.settings.clone(), disclosure, connector, dataset, sql).await;
        let (rows, suppressed) = match result {
            Ok(outcome) => outcome,
            Err(err) => {
                security_audit_event(
                    AuditKind::QueryExecuted,
                    Some(tenant),
                    "failed",
                    &format!("connector={connector} objects={object_count} zk={zk_mode}"),
                );
                return Err(err);
            }
        };
        let row_count = rows.as_array().map(Vec::len).unwrap_or(0);
        security_audit_event(
            AuditKind::QueryExecuted,
            Some(tenant),
            "ok",
            &format!(
                "connector={connector} objects={object_count} rows={row_count} \
                 suppressed={suppressed} zk={zk_mode}"
            ),
        );
        Ok(json!({
            "rows": rows, "row_count": row_count, "suppressed_rows": suppressed,
            "object_count": object_count, "zk_mode": zk_mode, "tee_platform": tee_platform,
        }))
    }

    fn research(&self) -> Result<&ResearchService, ApiError> {
        self.research
            .as_deref()
            .ok_or(ApiError::ResearchUnavailable)
    }

    /// Run a disclosure-controlled aggregate query by `researcher` over
    /// `steward`'s connector data. Requires an active grant; aggregate-only
    /// and min-cohort suppression are applied unconditionally.
    pub async fn research_query(
        &self,
        researcher: TenantId,
        steward: TenantId,
        connector: &ConnectorSlug,
        sql: &str,
    ) -> Result<Value, ApiError> {
        let research = self.research()?;
        // Grant check first — no data is touched without authorization.
        let grant = research
            .find_active_grant(researcher, steward, connector)
            .await?;
        let Some(grant) = grant else {
            security_audit_event(
                AuditKind::AuthDecision,
                Some(researcher),
                "denied",
                &format!("no active grant for steward={steward} connector={connector}"),
            );
            return Err(ApiError::Forbidden);
        };

        let tee_platform = platform_label(self.gate(researcher, "research query").await?);

        // Budget charge — after the attestation gate so operator
        // infrastructure failures never burn researcher budget, but before
        // any data is touched: an accepted query consumes budget even if the
        // plan gate later rejects it, so probing the aggregate-only boundary
        // costs budget. Charges are not refunded.
        let budget = match research.charge(&grant.grant_id, RESEARCH_QUERY_COST).await {
            Ok(state) => state,
            Err(err) => {
                let detail = match &err {
                    BudgetError::Exhausted(state) => format!(
                        "exhausted steward={steward} connector={connector} limit={} spent={}",
                        state.limit, state.spent
                    ),
                    BudgetError::UnknownGrant => {
                        format!("no ledger entry steward={steward} connector={connector}")
                    }
                };
                security_audit_event(
                    AuditKind::ResearchBudget,
                    Some(researcher),
                    "denied",
                    &detail,
                );
                return Err(ApiError::BudgetExhausted);
            }
        };

        // The steward's key is released into the enclave to decrypt their
        // data. A dataset that does not match its declaration is refused
        // after this charge (ADR 0012; P54 decides whether that stays).
        let _slot = self.plaintext_slot().await?;
        let dataset = self.decrypt_dataset(steward, connector).await?;
        let object_count = dataset.blobs.len();

        if dataset.blobs.is_empty() {
            security_audit_event(
                AuditKind::QueryExecuted,
                Some(researcher),
                "ok",
                &format!(
                    "research steward={steward} connector={connector} objects=0 \
                     budget_remaining={}",
                    budget.remaining()
                ),
            );
            return Ok(json!({
                "rows": [], "row_count": 0, "suppressed_rows": 0,
                "object_count": 0, "min_cohort": self.min_cohort, "mode": "research",
                "budget_remaining": budget.remaining(), "tee_platform": tee_platform,
            }));
        }

        // Research mode always enforces aggregate-only and disclosure control.
        let mut research_settings = self.settings.clone();
        research_settings.zk = platform_core::ZkMode::Enabled;
        let outcome = run_scoped(
            research_settings,
            Some(self.threshold()),
            connector,
            dataset,
            sql,
        )
        .await;

        let (rows, suppressed) = match outcome {
            Ok(v) => v,
            Err(err) => {
                // Still charged, so the failed attempt appears in the meter.
                security_audit_event(
                    AuditKind::QueryExecuted,
                    Some(researcher),
                    "failed",
                    &format!(
                        "research steward={steward} connector={connector} \
                         objects={object_count} budget_remaining={}",
                        budget.remaining()
                    ),
                );
                return Err(err);
            }
        };
        let row_count = rows.as_array().map(Vec::len).unwrap_or(0);

        // Billing meters research access from this audit record.
        security_audit_event(
            AuditKind::QueryExecuted,
            Some(researcher),
            "ok",
            &format!(
                "research steward={steward} connector={connector} objects={object_count} \
                 rows={row_count} suppressed={suppressed} k={} budget_spent={} \
                 budget_remaining={}",
                self.min_cohort,
                RESEARCH_QUERY_COST,
                budget.remaining()
            ),
        );

        Ok(json!({
            "rows": rows,
            "row_count": row_count,
            "suppressed_rows": suppressed,
            "object_count": object_count,
            "min_cohort": self.min_cohort,
            "mode": "research",
            "budget_remaining": budget.remaining(),
            "tee_platform": tee_platform,
        }))
    }
}

/// The platform name in attestation bundles and query responses; the portal
/// shows a simulated-TEE notice on "simulated".
fn platform_label(platform: platform_enclave::TeePlatform) -> &'static str {
    match platform {
        platform_enclave::TeePlatform::SevSnp => "amd-sev-snp",
        platform_enclave::TeePlatform::Simulated => "simulated",
        platform_enclave::TeePlatform::Development => "development",
    }
}

/// Decrypted dataset objects. Each element zeroizes on drop, so no exit
/// path (error, early return, or cancellation) leaves plaintext behind.
type DecryptedObjects = Vec<SecretBytes>;

/// A dataset's decrypted current snapshot and, for an upload, the schema
/// and row cap its steward declared for it.
#[derive(Default)]
struct DecryptedDataset {
    blobs: DecryptedObjects,
    declared: Option<(DeclaredSchema, u64)>,
}

/// Run `sql` over a decrypted dataset in a fresh scope, registered as the
/// table `dataset` and checked against its declaration, if any. Consumes
/// the blobs, so they are zeroized when this returns on any path.
/// Returns the rows and the number suppressed by disclosure control.
async fn run_scoped(
    settings: EngineSettings,
    disclosure: Option<Arc<dyn DisclosurePolicy>>,
    dataset: &ConnectorSlug,
    decrypted: DecryptedDataset,
    sql: &str,
) -> Result<(Value, usize), ApiError> {
    let mut scope = QueryScope::new(settings);
    if let Some(policy) = disclosure {
        scope.set_disclosure(policy);
    }
    let blob_refs: Vec<&[u8]> = decrypted.blobs.iter().map(SecretBytes::expose).collect();
    match &decrypted.declared {
        Some((schema, row_cap)) => {
            scope.register_parquet_declared(dataset.as_str(), &blob_refs, schema, *row_cap)
        }
        None => scope.register_parquet_many(dataset.as_str(), &blob_refs),
    }
    .map_err(map_query_error)?;
    let rows = scope.sql_json(sql).await.map_err(map_query_error)?;
    Ok((rows, scope.last_suppressed_rows()))
}

fn map_query_error(err: QueryError) -> ApiError {
    match err {
        QueryError::ZkPolicy => {
            ApiError::QueryRejected("row-level egress is not permitted in zero-knowledge mode")
        }
        QueryError::Disclosure(_) => {
            ApiError::QueryRejected("query rejected by disclosure control (see cohort-size rules)")
        }
        QueryError::StatementNotAllowed => {
            ApiError::QueryRejected("only read-only queries are permitted")
        }
        // A planning/execution failure is almost always the caller's SQL.
        QueryError::Execution(_) => ApiError::BadRequest("query could not be executed"),
        QueryError::Parquet(_) | QueryError::Serialize(_) => ApiError::Backend,
        // The stored data, not the caller's query, is at fault.
        QueryError::DeclarationMismatch(_) => ApiError::DatasetMismatch,
    }
}

#[derive(Debug, Deserialize)]
pub struct QueryRequest {
    /// The dataset's slug: a connector's, or an upload's (`upload_…`).
    pub connector: String,
    pub sql: String,
}

#[derive(Debug, Deserialize)]
pub struct GrantRequest {
    /// Tenant id (UUID) to grant research access to.
    pub researcher_tenant: String,
    /// The dataset's slug: a connector's, or an upload's (`upload_…`).
    pub connector: String,
    /// Query-budget allocation for this grant. Omitted ⇒ the platform
    /// default (`RESEARCH_DEFAULT_QUERY_BUDGET`).
    #[serde(default)]
    pub query_budget: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct TopUpRequest {
    /// Budget units to add to the grant's lifetime allocation.
    pub additional: u64,
}

#[derive(Debug, Deserialize)]
pub struct ResearchQueryRequest {
    /// Steward tenant id (UUID) whose data is being queried.
    pub steward_tenant: String,
    /// The dataset's slug: a connector's, or an upload's (`upload_…`).
    pub connector: String,
    pub sql: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decrypted_objects_zeroize_on_drop() {
        // Plaintext copies must never be plain `Vec<u8>`: dropping them on
        // an error path would leave the data in freed memory.
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<DecryptedObjects>();
    }
}
