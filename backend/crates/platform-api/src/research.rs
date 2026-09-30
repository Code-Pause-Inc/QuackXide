//! Dataset catalog and access-request API.
//!
//! A steward publishes a listing for one of its sealed connector datasets,
//! opting it into discoverability. Researchers browse the catalog and file
//! access requests; approval mints the grant and budget through the same path
//! as a direct grant. Prices are integer cents in the configured currency.

use axum::extract::{Path, State};
use axum::{Extension, Json};
use platform_core::{ConnectorSlug, TenantId};
use platform_telemetry::{AuditKind, security_audit_event};
use platform_tenancy::{
    BudgetLedger, CatalogError, CatalogRegistry, GrantRegistry, ListingDetails,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;

use crate::query::ConnectorQueryService;
use crate::{ApiError, AppState, AuthedTenant, query_service};

/// Stores backing the research-access layer.
pub struct ResearchStores {
    pub grants: Arc<dyn GrantRegistry>,
    pub budgets: Arc<dyn BudgetLedger>,
    pub catalog: Arc<dyn CatalogRegistry>,
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
    /// Steward override of the listing's included query budget.
    #[serde(default)]
    pub query_budget: Option<u64>,
}

// ── Service methods ──────────────────────────────────────────────────────────

impl ConnectorQueryService {
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
            grant_budget: req.grant_budget.unwrap_or(self.default_budget()),
        };
        let listing = self
            .catalog()?
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
            .catalog()?
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
            .catalog()?
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
            .catalog()?
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
            .catalog()?
            .list_requests_for(tenant)
            .await
            .map_err(|_| ApiError::Backend)?;
        Ok(json!({ "requests": requests }))
    }

    /// Resolve a pending request. Approval mints the grant + budget through
    /// the same path as a direct grant (idempotent, so a retried approval
    /// after a partial failure converges); denial only records the outcome.
    pub async fn resolve_access_request(
        &self,
        steward: TenantId,
        request_id: &str,
        approve: bool,
        budget_override: Option<u64>,
    ) -> Result<Value, ApiError> {
        let request = self
            .catalog()?
            .resolve(steward, request_id, approve)
            .await
            .map_err(|_| ApiError::Backend)?
            .ok_or(ApiError::NotFound)?;

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

        let connector = ConnectorSlug::new(&request.connector).map_err(|_| ApiError::Backend)?;
        // Budget priority: steward override, then the listing's included
        // budget, then the platform default applied by `grant`.
        let listed_budget = self
            .catalog()?
            .get_listing(&request.listing_id)
            .await
            .map_err(|_| ApiError::Backend)?
            .map(|l| l.grant_budget);
        let grant = self
            .grant(
                steward,
                request.researcher_tenant,
                &connector,
                budget_override.or(listed_budget),
            )
            .await?;
        security_audit_event(
            AuditKind::ResearchCatalog,
            Some(steward),
            "ok",
            &format!(
                "approved request={request_id} researcher={}",
                request.researcher_tenant
            ),
        );
        Ok(json!({ "request": request, "grant": grant }))
    }
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
    let service = query_service(&state)?;
    let listings = service.list_catalog().await?;
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
    let service = query_service(&state)?;
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
        service.publish_listing(steward, &connector, &req).await?,
    ))
}

/// `DELETE /api/v1/catalog/{listing_id}` — steward withdraws a listing.
pub(crate) async fn unpublish_listing(
    State(state): State<AppState>,
    Extension(AuthedTenant(steward)): Extension<AuthedTenant>,
    Path(listing_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let service = query_service(&state)?;
    Ok(Json(service.unpublish_listing(steward, &listing_id).await?))
}

/// `POST /api/v1/catalog/{listing_id}/request` — researcher requests access.
pub(crate) async fn request_dataset_access(
    State(state): State<AppState>,
    Extension(AuthedTenant(researcher)): Extension<AuthedTenant>,
    Path(listing_id): Path<String>,
    Json(body): Json<RequestAccessBody>,
) -> Result<Json<Value>, ApiError> {
    let service = query_service(&state)?;
    if body.note.chars().count() > MAX_NOTE_CHARS {
        return Err(ApiError::BadRequest("note too long (max 1000 chars)"));
    }
    Ok(Json(
        service
            .request_access(researcher, &listing_id, body.note.trim())
            .await?,
    ))
}

/// `GET /api/v1/research/requests` — requests the caller is party to.
pub(crate) async fn list_access_requests(
    State(state): State<AppState>,
    Extension(AuthedTenant(tenant)): Extension<AuthedTenant>,
) -> Result<Json<Value>, ApiError> {
    let service = query_service(&state)?;
    Ok(Json(service.list_access_requests(tenant).await?))
}

/// `POST /api/v1/research/requests/{id}/approve` — steward approves.
pub(crate) async fn approve_access_request(
    State(state): State<AppState>,
    Extension(AuthedTenant(steward)): Extension<AuthedTenant>,
    Path(request_id): Path<String>,
    body: Option<Json<ApproveRequestBody>>,
) -> Result<Json<Value>, ApiError> {
    let service = query_service(&state)?;
    let override_budget = body.and_then(|Json(b)| b.query_budget);
    Ok(Json(
        service
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
    let service = query_service(&state)?;
    Ok(Json(
        service
            .resolve_access_request(steward, &request_id, false, None)
            .await?,
    ))
}
