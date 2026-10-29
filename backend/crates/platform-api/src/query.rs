//! Confidential query service behind `POST /api/v1/query` and the research
//! endpoints.
//!
//! Inside the attested enclave, a query passes the attestation gate, decrypts
//! each of the connector's sealed objects with the tenant key released into
//! the enclave (`EnclaveKeyProvider`), runs the SQL in a [`QueryScope`], and
//! zeroizes the decrypted blobs. Tenant identity comes only from the verified
//! JWT; requests name a connector, never a tenant.
//!
//! Trust boundary: production releases tenant keys only into a
//! hardware-attested enclave whose RAM the operator cannot read. The dev
//! providers here hold keys in ordinary process memory and are for local use
//! only.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use async_trait::async_trait;
use platform_connectors::pipeline::envelope_info;
use platform_connectors::snapshot::{SnapshotManifest, manifest_info};
use platform_core::{ConnectorSlug, TenantId};
use platform_crypto::{SecretBytes, TenantKeypair};
use platform_enclave::{AttestationProvider, fresh_nonce, gate_execution};
use platform_storage::{TenantPaths, VaultStore};
use platform_telemetry::{AuditKind, security_audit_event};
use platform_tenancy::{BudgetError, BudgetLedger, BudgetState, CatalogRegistry, GrantRegistry};
use prometheus_client::metrics::histogram::Histogram;
use quackxide_engine::{
    DisclosurePolicy, EngineSettings, MinCountThreshold, QueryError, QueryScope,
};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::{Semaphore, SemaphorePermit};

use crate::ApiError;
use crate::key_release::{AttestationBundle, EnclaveIdentity};

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
/// endpoint, plus the optional research-access layer.
pub struct ConnectorQueryService {
    vault: Arc<dyn VaultStore>,
    keys: Arc<dyn EnclaveKeyProvider>,
    attestation: Arc<dyn AttestationProvider>,
    identity: Arc<EnclaveIdentity>,
    settings: EngineSettings,
    require_attestation: bool,
    /// None ⇒ research access not configured ⇒ research/grant routes 503.
    grants: Option<Arc<dyn GrantRegistry>>,
    /// Per-grant query budgets — bounds adaptive (differencing) querying and
    /// meters billable access. None whenever `grants` is None.
    budgets: Option<Arc<dyn BudgetLedger>>,
    /// Dataset catalog and access requests.
    catalog: Option<Arc<dyn CatalogRegistry>>,
    /// Minimum cohort size `k` for disclosure control, shared by
    /// zero-knowledge and research queries. Zero refuses every such query.
    min_cohort: u64,
    /// Budget units allocated to a grant when the steward doesn't specify.
    default_budget: u64,
    /// Bounds how many queries hold decrypted plaintext at once
    /// (`EngineSettings::max_concurrent_queries`).
    plaintext_slots: Semaphore,
    /// Time spent waiting for a plaintext slot, exported as a metric.
    plaintext_wait: Histogram,
}

/// Budget units one research query consumes.
const RESEARCH_QUERY_COST: u64 = 1;
/// Grant budget until `with_research` configures one.
const DEFAULT_QUERY_BUDGET: u64 = 100;

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
            grants: None,
            budgets: None,
            catalog: None,
            min_cohort: platform_config::DEFAULT_MIN_COHORT_SIZE,
            default_budget: DEFAULT_QUERY_BUDGET,
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

    /// Enable the research-access layer: catalog, access requests, grants,
    /// and per-grant budget metering.
    pub fn with_research(
        mut self,
        stores: crate::research::ResearchStores,
        min_cohort: u64,
        default_query_budget: u64,
    ) -> Self {
        self.grants = Some(stores.grants);
        self.budgets = Some(stores.budgets);
        self.catalog = Some(stores.catalog);
        self.default_budget = default_query_budget;
        self.with_min_cohort(min_cohort)
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
                    &format!("simulated SEV-SNP evidence verified for {label} (dev only)"),
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

    /// Decrypt `owner`'s current connector snapshot to plaintext Parquet:
    /// the objects listed by the newest manifest, and nothing else, so
    /// repeated or interrupted syncs never add rows. The blobs zeroize on
    /// drop, so an error partway through wipes the objects already opened.
    async fn decrypt_connector(
        &self,
        owner: TenantId,
        connector: &ConnectorSlug,
    ) -> Result<DecryptedObjects, ApiError> {
        let manifests = self
            .vault
            .list(&TenantPaths::connector_manifests_prefix(owner, connector))
            .await?;
        let Some((version, path)) = manifests
            .iter()
            .filter_map(|path| {
                TenantPaths::connector_manifest_version(owner, connector, path)
                    .map(|version| (version, path))
            })
            .max_by(|a, b| a.0.cmp(&b.0))
        else {
            return Ok(Vec::new());
        };

        let key_session = self.keys.begin_query_session(owner).await?;
        let envelope = self.vault.get(path).await?;
        let info = manifest_info(&owner, connector, &version);
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
                "connector snapshot manifest is malformed, mismatched or lists an object twice",
            );
            return Err(ApiError::Backend);
        };

        let mut blobs = Vec::with_capacity(manifest.objects.len());
        for object in &manifest.objects {
            let path = TenantPaths::connector_snapshot_object(owner, connector, &version, *object);
            let envelope = self.vault.get(&path).await?;
            let info = envelope_info(&owner, connector, object);
            let plaintext = key_session.open_envelope(&info, &envelope).await?;
            blobs.push(plaintext);
        }
        Ok(blobs)
    }

    pub async fn query(
        &self,
        tenant: TenantId,
        connector: &ConnectorSlug,
        sql: &str,
    ) -> Result<Value, ApiError> {
        let tee_platform = platform_label(self.gate(tenant, "query").await?);
        let _slot = self.plaintext_slot().await?;
        let blobs = self.decrypt_connector(tenant, connector).await?;
        let object_count = blobs.len();
        let zk_mode = self.settings.zk.is_enabled();

        if blobs.is_empty() {
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
        let result = run_scoped(self.settings.clone(), disclosure, connector, blobs, sql).await;
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

    fn grants(&self) -> Result<&Arc<dyn GrantRegistry>, ApiError> {
        self.grants.as_ref().ok_or(ApiError::ResearchUnavailable)
    }

    fn budgets(&self) -> Result<&Arc<dyn BudgetLedger>, ApiError> {
        self.budgets.as_ref().ok_or(ApiError::ResearchUnavailable)
    }

    pub(crate) fn catalog(&self) -> Result<&Arc<dyn CatalogRegistry>, ApiError> {
        self.catalog.as_ref().ok_or(ApiError::ResearchUnavailable)
    }

    pub(crate) fn default_budget(&self) -> u64 {
        self.default_budget
    }

    /// Steward grants a researcher aggregate access to one of its connectors,
    /// allocating a query budget (default from config when unspecified).
    pub async fn grant(
        &self,
        steward: TenantId,
        researcher: TenantId,
        connector: &ConnectorSlug,
        query_budget: Option<u64>,
    ) -> Result<Value, ApiError> {
        let grant = self
            .grants()?
            .create(steward, researcher, connector.as_str())
            .await
            .map_err(|_| ApiError::Backend)?;
        // Insert-if-absent: re-granting reuses the grant id, so it can never
        // reset spend — allocation only rises, via explicit top-ups.
        let budget = self
            .budgets()?
            .open(&grant.grant_id, query_budget.unwrap_or(self.default_budget))
            .await
            .map_err(|_| ApiError::Backend)?;
        security_audit_event(
            AuditKind::TenantProvisioned,
            Some(steward),
            "ok",
            &format!(
                "granted researcher={researcher} connector={connector} budget_limit={}",
                budget.limit
            ),
        );
        let mut value = serde_json::to_value(&grant).map_err(|_| ApiError::Backend)?;
        value["budget"] = budget_json(&budget)?;
        Ok(value)
    }

    /// Steward-only budget top-up. Non-stewards — including the grant's own
    /// researcher — get the same "not found" as an unknown id: allocation
    /// control mirrors the revoke discipline (no existence oracle).
    pub async fn top_up_budget(
        &self,
        steward: TenantId,
        grant_id: &str,
        additional: u64,
    ) -> Result<Value, ApiError> {
        let owns = self
            .grants()?
            .list_for(steward)
            .await
            .map_err(|_| ApiError::Backend)?
            .into_iter()
            .any(|g| g.grant_id == grant_id && g.steward_tenant == steward);
        if !owns {
            return Err(ApiError::NotFound);
        }
        let budget = self
            .budgets()?
            .top_up(grant_id, additional)
            .await
            .map_err(|_| ApiError::Backend)?;
        security_audit_event(
            AuditKind::ResearchBudget,
            Some(steward),
            "ok",
            &format!(
                "top_up grant={grant_id} added={additional} limit={}",
                budget.limit
            ),
        );
        budget_json(&budget)
    }

    /// Budget standing — visible only to the grant's parties (steward or
    /// researcher); anyone else gets the same "not found" as an unknown id.
    pub async fn budget_state(&self, caller: TenantId, grant_id: &str) -> Result<Value, ApiError> {
        let is_party = self
            .grants()?
            .list_for(caller)
            .await
            .map_err(|_| ApiError::Backend)?
            .into_iter()
            .any(|g| g.grant_id == grant_id);
        if !is_party {
            return Err(ApiError::NotFound);
        }
        let budget = self
            .budgets()?
            .state(grant_id)
            .await
            .map_err(|_| ApiError::Backend)?
            .ok_or(ApiError::NotFound)?;
        budget_json(&budget)
    }

    pub async fn revoke_grant(&self, steward: TenantId, grant_id: &str) -> Result<Value, ApiError> {
        let revoked = self
            .grants()?
            .revoke(steward, grant_id)
            .await
            .map_err(|_| ApiError::Backend)?
            .ok_or(ApiError::NotFound)?;
        security_audit_event(
            AuditKind::TenantProvisioned,
            Some(steward),
            "ok",
            &format!("revoked grant={grant_id}"),
        );
        serde_json::to_value(&revoked).map_err(|_| ApiError::Backend)
    }

    pub async fn list_grants(&self, tenant: TenantId) -> Result<Value, ApiError> {
        let grants = self
            .grants()?
            .list_for(tenant)
            .await
            .map_err(|_| ApiError::Backend)?;
        Ok(json!({ "grants": grants }))
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
        // Grant check first — no data is touched without authorization.
        let grant = self
            .grants()?
            .find_active(researcher, steward, connector.as_str())
            .await
            .map_err(|_| ApiError::Backend)?;
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
        let budget = match self
            .budgets()?
            .charge(&grant.grant_id, RESEARCH_QUERY_COST)
            .await
        {
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

        // The steward's key is released into the enclave to decrypt their data.
        let _slot = self.plaintext_slot().await?;
        let blobs = self.decrypt_connector(steward, connector).await?;
        let object_count = blobs.len();

        if blobs.is_empty() {
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
            blobs,
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

/// Serialize a budget with its derived `remaining`.
fn budget_json(budget: &BudgetState) -> Result<Value, ApiError> {
    let mut value = serde_json::to_value(budget).map_err(|_| ApiError::Backend)?;
    value["remaining"] = json!(budget.remaining());
    Ok(value)
}

/// Decrypted connector objects. Each element zeroizes on drop, so no exit
/// path (error, early return, or cancellation) leaves plaintext behind.
type DecryptedObjects = Vec<SecretBytes>;

/// Run `sql` over decrypted `blobs` in a fresh scope. Consumes the blobs, so
/// they are zeroized when this returns on any path.
/// Returns the rows and the number suppressed by disclosure control.
async fn run_scoped(
    settings: EngineSettings,
    disclosure: Option<Arc<dyn DisclosurePolicy>>,
    connector: &ConnectorSlug,
    blobs: DecryptedObjects,
    sql: &str,
) -> Result<(Value, usize), ApiError> {
    let mut scope = QueryScope::new(settings);
    if let Some(policy) = disclosure {
        scope.set_disclosure(policy);
    }
    let blob_refs: Vec<&[u8]> = blobs.iter().map(SecretBytes::expose).collect();
    scope
        .register_parquet_many(connector.as_str(), &blob_refs)
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
    }
}

#[derive(Debug, Deserialize)]
pub struct QueryRequest {
    pub connector: String,
    pub sql: String,
}

#[derive(Debug, Deserialize)]
pub struct GrantRequest {
    /// Tenant id (UUID) to grant research access to.
    pub researcher_tenant: String,
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
