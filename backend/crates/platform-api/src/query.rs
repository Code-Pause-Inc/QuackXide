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
//!
//! Every query runs within its [`QueryLimits`](platform_core::QueryLimits):
//! a bounded wait for a plaintext slot, input sized before any key is
//! released, and one time limit over everything that holds plaintext. Each
//! refusal is an [`ApiError::QueryLimit`] with an `engine.query` "denied"
//! event naming the limit. A research query is charged before any of them,
//! so each costs a unit, as a plan-gate refusal does (P54 decides the order).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use platform_connectors::snapshot::{
    SnapshotManifest, manifest_info, newest_manifest, object_info,
};
use platform_connectors::upload::MAX_MANIFEST_BYTES;
use platform_core::{ConnectorSlug, DatasetKind, DeclaredSchema, QueryLimit, TenantId};
use platform_crypto::{EnvelopeSuite, SecretBytes, TenantKeypair};
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
    /// Replaces the disclosure threshold in this crate's unit tests, which
    /// make the engine panic mid-query. Not compiled into any other build.
    #[cfg(test)]
    disclosure_for_tests: Option<Arc<dyn DisclosurePolicy>>,
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
            #[cfg(test)]
            disclosure_for_tests: None,
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
        #[cfg(test)]
        if let Some(policy) = &self.disclosure_for_tests {
            return policy.clone();
        }
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

    /// Wait for a plaintext slot, at most `QueryLimits::slot_wait`. Hold the
    /// permit until the decrypted blobs are dropped. A limit of zero
    /// refuses rather than waiting forever, and no slot within the wait is
    /// [`QueryLimit::SlotWait`] (503), not the missing wiring that
    /// `QueryUnavailable` reports.
    async fn plaintext_slot(&self) -> Result<SemaphorePermit<'_>, ApiError> {
        if self.settings.max_concurrent_queries == 0 {
            return Err(ApiError::QueryUnavailable);
        }
        // Records the wait however it ends, including a cancelled query.
        let _wait = crate::metrics::Timer::start(self.plaintext_wait.clone());
        let acquire = self.plaintext_slots.acquire();
        match tokio::time::timeout(self.settings.limits.slot_wait, acquire).await {
            Ok(permit) => permit.map_err(|_| ApiError::QueryUnavailable),
            Err(_) => Err(ApiError::QueryLimit(QueryLimit::SlotWait)),
        }
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
    /// record is read before any key is released and must name a suite this
    /// build reads, and an upload's declared schema and row cap come back
    /// for the engine to check. The blobs
    /// zeroize on drop, so an error partway through wipes the objects
    /// already opened.
    ///
    /// Before any key is released, the objects stored at the snapshot's
    /// version must fit `QueryLimits::max_input_objects` and
    /// `max_input_bytes` (ciphertext bytes) and the sealed manifest must
    /// fit the upload route's manifest bound. Both input limits are checked
    /// again on what the manifest lists, cumulatively, before each object
    /// is opened.
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
            Ok(bytes) => SnapshotRecord::parse(&bytes, &version)
                .ok()
                .filter(|record| EnvelopeSuite::from_id(&record.suite).is_ok()),
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
                "snapshot record is missing, malformed, incomplete or of an unknown suite",
            );
            return Err(ApiError::Backend);
        };

        // Sized from storage alone. Objects at this version that the
        // manifest does not list (left by an attempt that stopped) count
        // too, so this can only overstate the input.
        let limits = &self.settings.limits;
        let stored = self
            .vault
            .usage(&TenantPaths::connector_snapshot_prefix(
                owner, dataset, &version,
            ))
            .await?;
        if stored.object_count > limits.max_input_objects {
            return Err(ApiError::QueryLimit(QueryLimit::InputObjects));
        }
        if stored.total_bytes > limits.max_input_bytes {
            return Err(ApiError::QueryLimit(QueryLimit::InputBytes));
        }
        let envelope = self.snapshot_part(owner, &path).await?;
        if envelope.len() > MAX_MANIFEST_BYTES {
            security_audit_event(
                AuditKind::DataAccess,
                Some(owner),
                "failed",
                "snapshot manifest is larger than any writer seals one",
            );
            return Err(ApiError::Backend);
        }

        let key_session = self.keys.begin_query_session(owner).await?;
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
        if u64::try_from(manifest.objects.len()).unwrap_or(u64::MAX) > limits.max_input_objects {
            return Err(ApiError::QueryLimit(QueryLimit::InputObjects));
        }

        let mut blobs = Vec::with_capacity(manifest.objects.len());
        let mut input_bytes = 0u64;
        for object in &manifest.objects {
            let path = TenantPaths::connector_snapshot_object(owner, dataset, &version, *object);
            let envelope = self.snapshot_part(owner, &path).await?;
            input_bytes =
                input_bytes.saturating_add(u64::try_from(envelope.len()).unwrap_or(u64::MAX));
            if input_bytes > limits.max_input_bytes {
                return Err(ApiError::QueryLimit(QueryLimit::InputBytes));
            }
            let info = object_info(&owner, dataset, object);
            let plaintext = key_session.open_envelope(&info, &envelope).await?;
            blobs.push(plaintext);
        }
        Ok(DecryptedDataset { blobs, declared })
    }

    /// Take a plaintext slot, then decrypt `owner`'s current snapshot of
    /// `dataset` and run `sql` over it within `QueryLimits::timeout`. On
    /// expiry the work is dropped: the blobs are zeroized and the slot is
    /// released, as they are on every other way out, including the caller
    /// dropping this future or a panic unwinding through it. Decoding is
    /// synchronous, so the decode limits bound the one stretch the timer
    /// cannot interrupt.
    async fn decrypt_and_run(
        &self,
        owner: TenantId,
        dataset: &ConnectorSlug,
        settings: EngineSettings,
        disclosure: Option<Arc<dyn DisclosurePolicy>>,
        sql: &str,
    ) -> Result<Ran, Stopped> {
        let _slot = self
            .plaintext_slot()
            .await
            .map_err(Stopped::before_engine)?;
        let timeout = settings.limits.timeout;
        let work = async {
            let decrypted = self
                .decrypt_dataset(owner, dataset)
                .await
                .map_err(Stopped::before_engine)?;
            let objects = decrypted.blobs.len();
            if objects == 0 {
                return Ok(Ran {
                    objects,
                    rows: Value::Array(Vec::new()),
                    suppressed: 0,
                });
            }
            let (rows, suppressed) = run_scoped(settings, disclosure, dataset, decrypted, sql)
                .await
                .map_err(|err| Stopped {
                    err,
                    objects: Some(objects),
                })?;
            Ok(Ran {
                objects,
                rows,
                suppressed,
            })
        };
        match tokio::time::timeout(timeout, work).await {
            Ok(ran) => ran,
            Err(_elapsed) => Err(Stopped::before_engine(ApiError::QueryLimit(
                QueryLimit::Time,
            ))),
        }
    }

    pub async fn query(
        &self,
        tenant: TenantId,
        connector: &ConnectorSlug,
        sql: &str,
    ) -> Result<Value, ApiError> {
        let tee_platform = platform_label(self.gate(tenant, "query").await?);
        let zk_mode = self.settings.zk.is_enabled();
        let disclosure = zk_mode.then(|| self.threshold());
        let ran = self
            .decrypt_and_run(tenant, connector, self.settings.clone(), disclosure, sql)
            .await
            .map_err(|stopped| {
                stopped.audit(
                    tenant,
                    &format!("connector={connector}"),
                    &format!("zk={zk_mode}"),
                )
            })?;
        let Ran {
            objects: object_count,
            rows,
            suppressed,
        } = ran;

        if object_count == 0 {
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
        // data. A dataset that does not match its declaration, and every
        // resource-limit refusal from the slot wait on, are refused after
        // this charge (ADR 0012; P54 decides whether that stays). Research
        // mode always enforces aggregate-only and disclosure control.
        let research_settings = EngineSettings {
            zk: platform_core::ZkMode::Enabled,
            ..self.settings.clone()
        };
        let ran = self
            .decrypt_and_run(
                steward,
                connector,
                research_settings,
                Some(self.threshold()),
                sql,
            )
            .await
            // Still charged, so the failed or refused attempt appears in the
            // meter.
            .map_err(|stopped| {
                stopped.audit(
                    researcher,
                    &format!("research steward={steward} connector={connector}"),
                    &format!("budget_remaining={}", budget.remaining()),
                )
            })?;
        let Ran {
            objects: object_count,
            rows,
            suppressed,
        } = ran;

        if object_count == 0 {
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

/// A query that ran: the objects it decrypted (none for a dataset with no
/// snapshot), its rows, and how many rows disclosure control withheld.
struct Ran {
    objects: usize,
    rows: Value,
    suppressed: usize,
}

/// Why a query stopped once it passed the attestation gate.
struct Stopped {
    err: ApiError,
    /// The objects decrypted when the engine failed or refused the query;
    /// `None` when it stopped before the engine ran.
    objects: Option<usize>,
}

impl Stopped {
    fn before_engine(err: ApiError) -> Self {
        Self { err, objects: None }
    }

    /// Records the stop as `engine.query` and returns the error: "denied"
    /// naming the limit for a resource-limit refusal, wherever it came
    /// from; "failed" with the object count when the engine failed; and
    /// nothing for another failure before the engine ran, which the check
    /// that failed records if it is a security decision. `subject` names
    /// the dataset and `context` ends the record.
    fn audit(self, actor: TenantId, subject: &str, context: &str) -> ApiError {
        match (&self.err, self.objects) {
            (ApiError::QueryLimit(limit), _) => security_audit_event(
                AuditKind::QueryExecuted,
                Some(actor),
                "denied",
                &format!("{subject} limit={limit} {context}"),
            ),
            (_, Some(objects)) => security_audit_event(
                AuditKind::QueryExecuted,
                Some(actor),
                "failed",
                &format!("{subject} objects={objects} {context}"),
            ),
            (_, None) => {}
        }
        self.err
    }
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
        // A resource limit, never the caller's SQL error.
        QueryError::LimitExceeded(limit) => ApiError::QueryLimit(limit),
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
    use std::time::Duration;

    use arrow::array::{Int64Array, RecordBatch, StringArray};
    use arrow::datatypes::{DataType, Field, Schema};
    use futures::FutureExt;
    use parquet::arrow::ArrowWriter;
    use platform_connectors::snapshot::SnapshotWriter;
    use platform_core::{ObjectId, QueryLimits, SnapshotVersion, ZkMode};
    use platform_crypto::hpke_seal_to_tenant;
    use platform_enclave::DevAttestation;
    use platform_storage::ObjectStoreVault;
    use quackxide_engine::disclosure::DisclosureOutcome;

    use super::*;

    #[test]
    fn decrypted_objects_zeroize_on_drop() {
        // Plaintext copies must never be plain `Vec<u8>`: dropping them on
        // an error path would leave the data in freed memory.
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<DecryptedObjects>();
        // Each opened envelope, the manifest's included, until it is kept.
        assert_zeroize_on_drop::<SecretBytes>();
    }

    /// The input-object limit is reached before the manifest bound: a
    /// manifest listing the most objects configuration allows still fits,
    /// so a manifest over the bound never comes from a writer.
    #[test]
    fn a_manifest_at_the_object_limit_fits_the_manifest_bound() {
        let tenant = TenantId::generate();
        let dataset = ConnectorSlug::new("upload_widest").expect("slug");
        let version = SnapshotVersion::generate();
        let objects = (0..platform_config::MAX_QUERY_MAX_INPUT_OBJECTS)
            .map(|_| ObjectId::generate())
            .collect();
        let manifest = SnapshotManifest {
            version: version.clone(),
            objects,
        };
        let sealed = hpke_seal_to_tenant(
            &TenantKeypair::generate().public_key(),
            &manifest_info(&tenant, &dataset, &version),
            &serde_json::to_vec(&manifest).expect("json"),
        )
        .expect("seal");
        assert!(sealed.len() <= MAX_MANIFEST_BYTES, "{} bytes", sealed.len());
    }

    /// A disclosure policy that panics, standing in for a panic anywhere in
    /// the engine once the dataset is decrypted and registered.
    struct Panics;

    impl DisclosurePolicy for Panics {
        fn apply(&self, _: Vec<RecordBatch>) -> Result<DisclosureOutcome, QueryError> {
            panic!("disclosure policy panicked");
        }
    }

    /// A one-slot ZK query service over a committed `cohorts` snapshot.
    async fn one_slot_service() -> (ConnectorQueryService, TenantId, ConnectorSlug) {
        let tenant = TenantId::generate();
        let keypair = TenantKeypair::generate();
        let dataset = ConnectorSlug::new("cohorts").expect("slug");
        let schema = Arc::new(Schema::new(vec![
            Field::new("condition", DataType::Utf8, false),
            Field::new("age", DataType::Int64, false),
        ]));
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(StringArray::from_iter_values(["flu", "flu", "flu"])),
                Arc::new(Int64Array::from(vec![30, 40, 50])),
            ],
        )
        .expect("batch");
        let mut parquet = Vec::new();
        let mut writer = ArrowWriter::try_new(&mut parquet, schema, None).expect("writer");
        writer.write(&batch).expect("write");
        writer.close().expect("close");

        let vault: Arc<dyn VaultStore> = Arc::new(ObjectStoreVault::new_in_memory());
        let public_key = keypair.public_key();
        let mut snapshot = SnapshotWriter::begin(&*vault, tenant, &public_key, dataset.clone());
        snapshot.put("cohorts", &parquet).await.expect("put");
        snapshot.commit().await.expect("commit");

        let service = ConnectorQueryService::new(
            vault,
            Arc::new(DevKeyProvider::new(tenant, keypair)),
            Arc::new(DevAttestation::allow_insecure_dev()),
            EngineSettings {
                zk: ZkMode::Enabled,
                max_concurrent_queries: 1,
                limits: QueryLimits::default(),
            },
            false,
        )
        .with_min_cohort(2);
        (service, tenant, dataset)
    }

    const COHORT_SQL: &str = "SELECT condition, COUNT(*) AS n FROM cohorts GROUP BY condition";

    /// A panic in the engine unwinds through the query: the plaintext slot
    /// is released and the decrypted blobs are dropped (and zeroized, by
    /// type) on the way out, so the next query runs.
    #[tokio::test]
    async fn a_panic_in_the_engine_releases_the_slot() {
        let (mut service, tenant, dataset) = one_slot_service().await;
        service.disclosure_for_tests = Some(Arc::new(Panics));
        let unwound = std::panic::AssertUnwindSafe(service.query(tenant, &dataset, COHORT_SQL))
            .catch_unwind()
            .await;
        assert!(unwound.is_err(), "the policy must have panicked");

        service.disclosure_for_tests = None;
        let rows = tokio::time::timeout(
            Duration::from_secs(5),
            service.query(tenant, &dataset, COHORT_SQL),
        )
        .await
        .expect("the only slot was released")
        .map_err(|_| "query failed")
        .expect("next query");
        assert_eq!(
            rows["rows"],
            serde_json::json!([{ "condition": "flu", "n": 3 }])
        );
    }
}
