//! Research access: the dataset catalog, access requests, grants and
//! per-grant query budgets ([`ResearchService`]), and their HTTP handlers.
//!
//! None of it needs key material, so these routes are served without key
//! release: the binary always builds the service (`crate::wiring`), and only
//! `POST /api/v1/research/query` also needs the confidential query service.
//! That query checks and charges grants through the same
//! `Arc<ResearchService>`, so the grant a route here creates is the one the
//! query checks and charges.
//!
//! A steward publishes a listing for one of its sealed connector datasets,
//! opting it into discoverability. Researchers browse the catalog and file
//! access requests; approval mints the grant and budget through the same path
//! as a direct grant, except that a retried approval never re-activates a
//! revoked grant. Prices are integer cents in the configured currency.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::{Extension, Json};
use platform_config::ResearchConfig;
use platform_core::{ConnectorSlug, TenantId};
use platform_telemetry::{AuditKind, security_audit_event};
use platform_tenancy::{
    AccessRequest, BudgetError, BudgetLedger, BudgetState, CatalogError, CatalogRegistry,
    DatasetGrant, GrantOutcome, GrantRegistry, ListingDetails, RequestStatus,
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{ApiError, AppState, AuthedTenant, research_service};

/// Stores backing the research-access layer.
pub struct ResearchStores {
    pub grants: Arc<dyn GrantRegistry>,
    pub budgets: Arc<dyn BudgetLedger>,
    pub catalog: Arc<dyn CatalogRegistry>,
}

impl ResearchStores {
    pub fn in_memory() -> Self {
        Self {
            grants: Arc::new(platform_tenancy::InMemoryGrantRegistry::default()),
            budgets: Arc::new(platform_tenancy::InMemoryBudgetLedger::default()),
            catalog: Arc::new(platform_tenancy::InMemoryCatalogRegistry::default()),
        }
    }
}

/// Research access: catalog, access requests, grants and per-grant budgets,
/// with the minimum cohort size research queries use. Built once and shared
/// as one `Arc` by `AppState::research` and the query service.
pub struct ResearchService {
    grants: Arc<dyn GrantRegistry>,
    /// Per-grant query budgets — bounds adaptive (differencing) querying and
    /// meters billable access.
    budgets: Arc<dyn BudgetLedger>,
    /// Dataset catalog and access requests.
    catalog: Arc<dyn CatalogRegistry>,
    /// Minimum cohort size `k` for disclosure control
    /// (`RESEARCH_MIN_COHORT_SIZE`). Zero refuses every research query.
    min_cohort: u64,
    /// Budget units allocated to a grant when the steward doesn't specify
    /// (`RESEARCH_DEFAULT_QUERY_BUDGET`).
    default_budget: u64,
}

/// Bounds on user-authored free text; oversize input is refused, not
/// truncated.
pub const MAX_TITLE_CHARS: usize = 120;
pub const MAX_DESCRIPTION_CHARS: usize = 2000;
pub const MAX_NOTE_CHARS: usize = 1000;

// ── Wire types ───────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct PublishListingRequest {
    pub connector: String,
    pub title: String,
    #[serde(default)]
    pub description: String,
    /// One-time access (license) fee for an approved grant, in cents.
    pub license_fee_cents: u64,
    /// Compute rate per query-budget unit, in cents.
    pub compute_rate_cents: u64,
    /// Query units included on approval. Omitted ⇒ the platform default
    /// (`RESEARCH_DEFAULT_QUERY_BUDGET`).
    #[serde(default)]
    pub grant_budget: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
pub struct RequestAccessBody {
    /// Researcher-stated purpose (e.g. an IRB/protocol reference).
    #[serde(default)]
    pub note: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct ApproveRequestBody {
    /// Steward override of the listing's included query budget. Recorded
    /// with the approval; a retry may repeat it but not change it.
    #[serde(default)]
    pub query_budget: Option<u64>,
}

// ── Service methods ──────────────────────────────────────────────────────────

impl ResearchService {
    pub fn new(stores: ResearchStores, min_cohort: u64, default_budget: u64) -> Self {
        Self {
            grants: stores.grants,
            budgets: stores.budgets,
            catalog: stores.catalog,
            min_cohort,
            default_budget,
        }
    }

    /// From `RESEARCH_MIN_COHORT_SIZE` and `RESEARCH_DEFAULT_QUERY_BUDGET`.
    /// `RESEARCH_PRICING_CURRENCY` stays on `PlatformConfig`, where
    /// `catalog_index` reads it.
    pub fn from_config(stores: ResearchStores, config: &ResearchConfig) -> Self {
        Self::new(stores, config.min_cohort_size, config.default_query_budget)
    }

    /// The configured `k`. The query service applies it to research queries
    /// and to own-data queries in zero-knowledge mode.
    pub fn min_cohort(&self) -> u64 {
        self.min_cohort
    }

    // ── Grants and budgets ──

    /// Steward grants a researcher aggregate access to one of its connectors,
    /// allocating a query budget (default from config when unspecified).
    /// `create` re-activates a revoked grant, so this is only for a new
    /// decision by the steward. Approvals mint their grant in
    /// [`resolve_access_request`](Self::resolve_access_request).
    pub async fn grant(
        &self,
        steward: TenantId,
        researcher: TenantId,
        connector: &ConnectorSlug,
        query_budget: Option<u64>,
    ) -> Result<Value, ApiError> {
        let grant = self
            .grants
            .create(steward, researcher, connector.as_str())
            .await
            .map_err(|_| ApiError::Backend)?;
        self.fund_grant(&grant, query_budget, None).await
    }

    /// Fund the query budget of a grant that was just created or found
    /// active, audit the grant, and return it with its budget as JSON. A
    /// direct grant opens its budget; re-granting reuses the grant id, so it
    /// never resets spend. An access-request approval (`approval` is its
    /// request id) adds its budget once, on top of what the grant already
    /// has: a follow-up request tops the grant up, and a retry of the same
    /// approval adds nothing. All grant paths use it, so they cannot drift.
    async fn fund_grant(
        &self,
        grant: &DatasetGrant,
        query_budget: Option<u64>,
        approval: Option<&str>,
    ) -> Result<Value, ApiError> {
        let units = query_budget.unwrap_or(self.default_budget);
        let id = &grant.grant_id;
        let budget = match approval {
            None => self
                .budgets
                .open(id, units)
                .await
                .map_err(|_| ApiError::Backend)?,
            Some(request_id) => {
                self.budgets
                    .open(id, 0)
                    .await
                    .map_err(|_| ApiError::Backend)?;
                self.budgets
                    .top_up_once(id, request_id, units)
                    .await
                    .map_err(|_| ApiError::Backend)?
            }
        };
        let researcher = grant.researcher_tenant;
        let connector = &grant.connector;
        security_audit_event(
            AuditKind::TenantProvisioned,
            Some(grant.steward_tenant),
            "ok",
            &format!(
                "granted researcher={researcher} connector={connector} budget_limit={}",
                budget.limit
            ),
        );
        let mut value = serde_json::to_value(grant).map_err(|_| ApiError::Backend)?;
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
            .grants
            .list_for(steward)
            .await
            .map_err(|_| ApiError::Backend)?
            .into_iter()
            .any(|g| g.grant_id == grant_id && g.steward_tenant == steward);
        if !owns {
            return Err(ApiError::NotFound);
        }
        let budget = self
            .budgets
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
            .grants
            .list_for(caller)
            .await
            .map_err(|_| ApiError::Backend)?
            .into_iter()
            .any(|g| g.grant_id == grant_id);
        if !is_party {
            return Err(ApiError::NotFound);
        }
        let budget = self
            .budgets
            .state(grant_id)
            .await
            .map_err(|_| ApiError::Backend)?
            .ok_or(ApiError::NotFound)?;
        budget_json(&budget)
    }

    pub async fn revoke_grant(&self, steward: TenantId, grant_id: &str) -> Result<Value, ApiError> {
        let revoked = self
            .grants
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
            .grants
            .list_for(tenant)
            .await
            .map_err(|_| ApiError::Backend)?;
        Ok(json!({ "grants": grants }))
    }

    // ── For `ConnectorQueryService::research_query` ──

    /// The researcher's active grant on `steward`'s `connector`, if any.
    /// The research query checks this before touching any data and audits
    /// the refusal itself.
    pub(crate) async fn find_active_grant(
        &self,
        researcher: TenantId,
        steward: TenantId,
        connector: &ConnectorSlug,
    ) -> Result<Option<DatasetGrant>, ApiError> {
        self.grants
            .find_active(researcher, steward, connector.as_str())
            .await
            .map_err(|_| ApiError::Backend)
    }

    /// Charge `cost` units to `grant_id`'s budget. The research query
    /// charges after the attestation gate and audits a refusal itself.
    pub(crate) async fn charge(
        &self,
        grant_id: &str,
        cost: u64,
    ) -> Result<BudgetState, BudgetError> {
        self.budgets.charge(grant_id, cost).await
    }

    // ── Catalog and access requests ──

    /// Publish or re-publish a catalog listing for one of the steward's
    /// connectors (upsert; the listing id is stable).
    pub async fn publish_listing(
        &self,
        steward: TenantId,
        connector: &ConnectorSlug,
        req: &PublishListingRequest,
    ) -> Result<Value, ApiError> {
        let details = ListingDetails {
            title: req.title.trim().to_owned(),
            description: req.description.trim().to_owned(),
            license_fee_cents: req.license_fee_cents,
            compute_rate_cents: req.compute_rate_cents,
            grant_budget: req.grant_budget.unwrap_or(self.default_budget),
        };
        let listing = self
            .catalog
            .publish(steward, connector.as_str(), details)
            .await
            .map_err(|_| ApiError::Backend)?;
        security_audit_event(
            AuditKind::ResearchCatalog,
            Some(steward),
            "ok",
            &format!(
                "published listing={} connector={connector}",
                listing.listing_id
            ),
        );
        serde_json::to_value(&listing).map_err(|_| ApiError::Backend)
    }

    /// Withdraw a listing. Steward-only; everyone else sees "not found".
    pub async fn unpublish_listing(
        &self,
        steward: TenantId,
        listing_id: &str,
    ) -> Result<Value, ApiError> {
        let listing = self
            .catalog
            .unpublish(steward, listing_id)
            .await
            .map_err(|_| ApiError::Backend)?
            .ok_or(ApiError::NotFound)?;
        security_audit_event(
            AuditKind::ResearchCatalog,
            Some(steward),
            "ok",
            &format!("unpublished listing={listing_id}"),
        );
        serde_json::to_value(&listing).map_err(|_| ApiError::Backend)
    }

    /// Every published listing — the researcher-browsable catalog.
    pub async fn list_catalog(&self) -> Result<Value, ApiError> {
        let listings = self
            .catalog
            .list_published()
            .await
            .map_err(|_| ApiError::Backend)?;
        serde_json::to_value(&listings).map_err(|_| ApiError::Backend)
    }

    /// File an access request against a published listing.
    pub async fn request_access(
        &self,
        researcher: TenantId,
        listing_id: &str,
        note: &str,
    ) -> Result<Value, ApiError> {
        let request = self
            .catalog
            .request_access(listing_id, researcher, note)
            .await
            .map_err(|err| match err {
                CatalogError::NotFound => ApiError::NotFound,
                CatalogError::SelfRequest => {
                    ApiError::BadRequest("cannot request access to your own dataset")
                }
            })?;
        security_audit_event(
            AuditKind::ResearchCatalog,
            Some(researcher),
            "ok",
            &format!(
                "requested request={} listing={listing_id} steward={}",
                request.request_id, request.steward_tenant
            ),
        );
        serde_json::to_value(&request).map_err(|_| ApiError::Backend)
    }

    /// Requests where the caller is researcher or steward.
    pub async fn list_access_requests(&self, tenant: TenantId) -> Result<Value, ApiError> {
        let requests = self
            .catalog
            .list_requests_for(tenant)
            .await
            .map_err(|_| ApiError::Backend)?;
        Ok(json!({ "requests": requests }))
    }

    /// Resolve an access request. Only its steward may; other tenants and
    /// unknown ids get the same "not found" (no existence oracle).
    ///
    /// Approval marks the request Approved first, recording its query budget
    /// (the steward's override, else the listing's included budget) in the
    /// same step, then mints the grant and adds that budget to it once,
    /// keyed by the request (see `fund_grant`). If a later step fails, the request stays Approved
    /// without a usable grant (fail closed) and the steward retries:
    /// approving an already-Approved request re-runs every step after
    /// `resolve` (slug, grant and budget), all idempotent, so the retry
    /// converges. A retry finishes the recorded decision: it adds the
    /// approved budget if the failed attempt did not, and a retry that names
    /// a different `query_budget` is refused (400) and audited as `denied`. A retry never undoes a
    /// revoke: in place of `create`, it mints with
    /// [`GrantRegistry::create_unless_revoked`], which checks for a revoked
    /// grant and creates in one atomic step, so a revoke that lands while
    /// the retry runs holds too. A retry that finds this researcher's grant
    /// for the connector revoked is refused with the same "not found", even
    /// when the revoke came before the approval (fail closed). A retry is
    /// also refused once the grant was revoked after the approval and then
    /// re-granted: that re-grant is a newer decision with its own budget.
    /// Only an explicit re-grant or a new request restores access. A retry is
    /// audited with `retry=true`, and a refused retry as `denied`.
    ///
    /// Denial acts only on a Pending request and only records the outcome.
    /// Denied is terminal and an Approved request cannot be denied (the
    /// refusal is audited), so no grant is ever minted for a Pending or
    /// Denied request.
    pub async fn resolve_access_request(
        &self,
        steward: TenantId,
        request_id: &str,
        approve: bool,
        budget_override: Option<u64>,
    ) -> Result<Value, ApiError> {
        let (request, retry) = match self
            .catalog
            .resolve(steward, request_id, approve, budget_override)
            .await
            .map_err(|_| ApiError::Backend)?
        {
            // A Pending request, now resolved: a first decision.
            Some(request) => (request, false),
            // An earlier approval recorded Approved, then failed: a retry.
            // Re-run the steps below for the request's own steward only.
            // Denied stays terminal.
            None if approve => {
                let Some(request) = self.approved_request(steward, request_id).await? else {
                    // Still Pending after an approval: its listing was
                    // unpublished. The caller gets the same "not found".
                    if let Some(pending) = self
                        .own_request(steward, request_id, RequestStatus::Pending)
                        .await?
                    {
                        security_audit_event(
                            AuditKind::ResearchCatalog,
                            Some(steward),
                            "denied",
                            &format!(
                                "approve refused request={request_id} researcher={} reason=unpublished",
                                pending.researcher_tenant
                            ),
                        );
                    }
                    return Err(ApiError::NotFound);
                };
                (request, true)
            }
            // Denying an Approved request is refused. Audit the refusal;
            // the caller still gets the same "not found" as an unknown id.
            None => {
                if let Some(approved) = self.approved_request(steward, request_id).await? {
                    security_audit_event(
                        AuditKind::ResearchCatalog,
                        Some(steward),
                        "denied",
                        &format!(
                            "deny refused request={request_id} researcher={} status=approved",
                            approved.researcher_tenant
                        ),
                    );
                }
                return Err(ApiError::NotFound);
            }
        };
        if !approve {
            security_audit_event(
                AuditKind::ResearchCatalog,
                Some(steward),
                "ok",
                &format!(
                    "denied request={request_id} researcher={}",
                    request.researcher_tenant
                ),
            );
            return Ok(json!({ "request": request }));
        }

        // A retry finishes the recorded decision, budget included: it may
        // repeat the approved budget or leave it out, but not change it.
        if retry && budget_override.is_some() && budget_override != request.approved_budget {
            security_audit_event(
                AuditKind::ResearchCatalog,
                Some(steward),
                "denied",
                &format!("approve refused request={request_id} retry=true reason=budget"),
            );
            return Err(ApiError::BadRequest(
                "a retry cannot change the approved budget",
            ));
        }
        let connector = ConnectorSlug::new(&request.connector).map_err(|_| ApiError::Backend)?;
        // The approval recorded its budget: the steward's override, else the
        // listing's included budget.
        let query_budget = request.approved_budget;
        // A first approval is a new decision, so it may re-activate a revoked
        // grant. A retry may not.
        let grant = if retry {
            self.grant_on_retry(steward, &request, &connector, query_budget)
                .await?
        } else {
            let grant = self
                .grants
                .create(steward, request.researcher_tenant, connector.as_str())
                .await
                .map_err(|_| ApiError::Backend)?;
            self.fund_grant(&grant, query_budget, Some(&request.request_id))
                .await?
        };
        let retry_note = if retry { " retry=true" } else { "" };
        security_audit_event(
            AuditKind::ResearchCatalog,
            Some(steward),
            "ok",
            &format!(
                "approved request={request_id} researcher={}{retry_note}",
                request.researcher_tenant
            ),
        );
        Ok(json!({ "request": request, "grant": grant }))
    }

    /// The caller's own request `request_id`, if it is Approved.
    /// `list_requests_for` also returns requests where the caller is the
    /// researcher, so the steward is checked as well.
    async fn approved_request(
        &self,
        steward: TenantId,
        request_id: &str,
    ) -> Result<Option<AccessRequest>, ApiError> {
        self.own_request(steward, request_id, RequestStatus::Approved)
            .await
    }

    /// The caller's own request `request_id` as steward, if it has `status`.
    async fn own_request(
        &self,
        steward: TenantId,
        request_id: &str,
        status: RequestStatus,
    ) -> Result<Option<AccessRequest>, ApiError> {
        Ok(self
            .catalog
            .list_requests_for(steward)
            .await
            .map_err(|_| ApiError::Backend)?
            .into_iter()
            .find(|r| {
                r.request_id == request_id && r.steward_tenant == steward && r.status == status
            }))
    }

    /// Mint the grant for an approval retry. The revoked check and the grant
    /// are one registry step ([`GrantRegistry::create_unless_revoked`]), so a
    /// retry never undoes a revoke, even one that lands while it runs. A
    /// revoked grant stays revoked, and a grant revoked since the approval
    /// was re-granted by a newer decision, which this retry must not add to.
    /// Either refusal is audited and the caller gets the same "not found" as
    /// an unknown request.
    async fn grant_on_retry(
        &self,
        steward: TenantId,
        request: &AccessRequest,
        connector: &ConnectorSlug,
        query_budget: Option<u64>,
    ) -> Result<Value, ApiError> {
        let outcome = self
            .grants
            .create_unless_revoked(steward, request.researcher_tenant, connector.as_str())
            .await
            .map_err(|_| ApiError::Backend)?;
        let (grant, reason) = match outcome {
            GrantOutcome::Revoked(revoked) => (revoked, "revoked"),
            GrantOutcome::Active(grant) if revoked_since(&grant, request) => {
                (grant, "revoked_since")
            }
            GrantOutcome::Active(grant) => {
                return self
                    .fund_grant(&grant, query_budget, Some(&request.request_id))
                    .await;
            }
        };
        let request_id = &request.request_id;
        security_audit_event(
            AuditKind::ResearchCatalog,
            Some(steward),
            "denied",
            &format!(
                "approve refused request={request_id} grant={} retry=true reason={reason}",
                grant.grant_id
            ),
        );
        Err(ApiError::NotFound)
    }
}

/// Whether `grant` was revoked at or after `request` was approved. A
/// re-grant since then is a new decision, so the stale approval's retry
/// must not add to it. Unparseable timestamps count as revoked (fail closed).
fn revoked_since(grant: &DatasetGrant, request: &AccessRequest) -> bool {
    let Some(revoked_at) = &grant.revoked_at_iso else {
        return false;
    };
    let parse = |iso: &str| chrono::DateTime::parse_from_rfc3339(iso).ok();
    match (parse(revoked_at), parse(&request.updated_at_iso)) {
        (Some(revoked), Some(approved)) => revoked >= approved,
        _ => true,
    }
}

/// Serialize a budget with its derived `remaining`.
fn budget_json(budget: &BudgetState) -> Result<Value, ApiError> {
    let mut value = serde_json::to_value(budget).map_err(|_| ApiError::Backend)?;
    value["remaining"] = json!(budget.remaining());
    Ok(value)
}

// ── Handlers ─────────────────────────────────────────────────────────────────

fn require_text(value: &str, max: usize, what: &'static str) -> Result<(), ApiError> {
    if value.trim().is_empty() || value.chars().count() > max {
        return Err(ApiError::BadRequest(what));
    }
    Ok(())
}

/// `GET /api/v1/catalog` — published listings + the platform pricing currency.
pub(crate) async fn catalog_index(
    State(state): State<AppState>,
    Extension(AuthedTenant(_tenant)): Extension<AuthedTenant>,
) -> Result<Json<Value>, ApiError> {
    let research = research_service(&state)?;
    let listings = research.list_catalog().await?;
    Ok(Json(json!({
        "listings": listings,
        "currency": state.config.research.pricing_currency,
    })))
}

/// `POST /api/v1/catalog` — steward publishes a listing.
pub(crate) async fn publish_listing(
    State(state): State<AppState>,
    Extension(AuthedTenant(steward)): Extension<AuthedTenant>,
    Json(req): Json<PublishListingRequest>,
) -> Result<Json<Value>, ApiError> {
    let research = research_service(&state)?;
    let connector = ConnectorSlug::new(&req.connector)
        .map_err(|_| ApiError::BadRequest("invalid connector slug"))?;
    require_text(
        &req.title,
        MAX_TITLE_CHARS,
        "title is required (max 120 chars)",
    )?;
    if req.description.chars().count() > MAX_DESCRIPTION_CHARS {
        return Err(ApiError::BadRequest(
            "description too long (max 2000 chars)",
        ));
    }
    Ok(Json(
        research.publish_listing(steward, &connector, &req).await?,
    ))
}

/// `DELETE /api/v1/catalog/{listing_id}` — steward withdraws a listing.
pub(crate) async fn unpublish_listing(
    State(state): State<AppState>,
    Extension(AuthedTenant(steward)): Extension<AuthedTenant>,
    Path(listing_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let research = research_service(&state)?;
    Ok(Json(
        research.unpublish_listing(steward, &listing_id).await?,
    ))
}

/// `POST /api/v1/catalog/{listing_id}/request` — researcher requests access.
pub(crate) async fn request_dataset_access(
    State(state): State<AppState>,
    Extension(AuthedTenant(researcher)): Extension<AuthedTenant>,
    Path(listing_id): Path<String>,
    Json(body): Json<RequestAccessBody>,
) -> Result<Json<Value>, ApiError> {
    let research = research_service(&state)?;
    if body.note.chars().count() > MAX_NOTE_CHARS {
        return Err(ApiError::BadRequest("note too long (max 1000 chars)"));
    }
    Ok(Json(
        research
            .request_access(researcher, &listing_id, body.note.trim())
            .await?,
    ))
}

/// `GET /api/v1/research/requests` — requests the caller is party to.
pub(crate) async fn list_access_requests(
    State(state): State<AppState>,
    Extension(AuthedTenant(tenant)): Extension<AuthedTenant>,
) -> Result<Json<Value>, ApiError> {
    let research = research_service(&state)?;
    Ok(Json(research.list_access_requests(tenant).await?))
}

/// `POST /api/v1/research/requests/{id}/approve` — steward approves.
pub(crate) async fn approve_access_request(
    State(state): State<AppState>,
    Extension(AuthedTenant(steward)): Extension<AuthedTenant>,
    Path(request_id): Path<String>,
    body: Option<Json<ApproveRequestBody>>,
) -> Result<Json<Value>, ApiError> {
    let research = research_service(&state)?;
    let override_budget = body.and_then(|Json(b)| b.query_budget);
    Ok(Json(
        research
            .resolve_access_request(steward, &request_id, true, override_budget)
            .await?,
    ))
}

/// `POST /api/v1/research/requests/{id}/deny` — steward denies.
pub(crate) async fn deny_access_request(
    State(state): State<AppState>,
    Extension(AuthedTenant(steward)): Extension<AuthedTenant>,
    Path(request_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let research = research_service(&state)?;
    Ok(Json(
        research
            .resolve_access_request(steward, &request_id, false, None)
            .await?,
    ))
}
