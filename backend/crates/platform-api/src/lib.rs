//! platform-api: the HTTP edge of the platform.
//!
//! Tenant identity comes only from the verified JWT `tid` claim, never from a
//! path, query, or body, and every storage path is derived from it through
//! `platform_storage::TenantPaths`, so cross-tenant access cannot be
//! expressed. Drive payloads are opaque ciphertext to this process.

use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, Path, Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Extension, Json, Router};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use bytes::Bytes;
use platform_auth::JwtVerifier;
use platform_config::PlatformConfig;
use platform_core::{ConnectorSlug, ObjectId, TenantId};
use platform_storage::{StorageError, TenantPaths, VaultStore};
use platform_telemetry::{AuditKind, security_audit_event};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tower_http::trace::TraceLayer;

pub mod admin;
pub mod query;
pub mod research;
use admin::ProvisioningService;
use query::{
    ConnectorQueryService, GrantRequest, QueryRequest, ResearchQueryRequest, TopUpRequest,
};

/// 4 MiB plaintext chunk + GCM tag + IV prefix, with headroom.
pub const MAX_CHUNK_BODY_BYTES: usize = 5 * 1024 * 1024;
/// IV prefix (12) + GCM tag (16): the smallest valid sealed chunk.
const MIN_CHUNK_BODY_BYTES: usize = 28;
const MAX_CHUNK_INDEX: u32 = 1 << 20;
const GCM_IV_BYTES: usize = 12;
/// HPKE suite recorded alongside an enrolled tenant key.
const HPKE_SUITE: &str = "DHKEM(X25519,HKDF-SHA256)+AES-256-GCM";

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<PlatformConfig>,
    pub vault: Arc<dyn VaultStore>,
    /// None ⇒ auth not configured ⇒ drive routes refuse (fail closed).
    pub jwt: Option<Arc<JwtVerifier>>,
    /// None ⇒ query, grant, catalog, and research routes refuse with 503.
    pub query: Option<Arc<ConnectorQueryService>>,
    /// None ⇒ admin and webhook routes refuse with 503.
    pub provisioning: Option<Arc<ProvisioningService>>,
}

/// Tenant proven by JWT verification; inserted by the auth middleware and
/// the only tenant source handlers can reach.
#[derive(Debug, Clone, Copy)]
pub struct AuthedTenant(pub TenantId);

// ── Wire types (all fields are ciphertext or opaque metadata) ────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncPayloadB64 {
    pub iv_b64: String,
    pub data_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestBody {
    pub wrapped_key: EncPayloadB64,
    pub manifest: EncPayloadB64,
    pub chunk_count: u32,
    pub encrypted_size_bytes: u64,
    pub created_at_iso: String,
}

#[derive(Debug, Serialize)]
struct ListEntry {
    object_id: String,
    #[serde(flatten)]
    body: ManifestBody,
}

// ── Errors ───────────────────────────────────────────────────────────────────

pub enum ApiError {
    Unauthorized,
    Forbidden,
    AuthNotConfigured,
    NotFound,
    BadRequest(&'static str),
    Backend,
    /// The confidential query service is not configured (503).
    QueryUnavailable,
    /// Research access (grants, budgets, catalog) is not configured (503).
    ResearchUnavailable,
    /// Admin provisioning is not configured (503).
    ProvisioningUnavailable,
    /// No MoR webhook secret is configured, so no event can be verified (503).
    WebhookNotConfigured,
    /// Query refused by the enclave attestation gate.
    AttestationUnavailable,
    /// Query rejected by the zero-knowledge policy gate.
    QueryRejected(&'static str),
    /// Research query refused: the grant's query budget is spent. The
    /// steward can restore access with a top-up.
    BudgetExhausted,
}

impl From<StorageError> for ApiError {
    fn from(err: StorageError) -> Self {
        match err {
            StorageError::NotFound => ApiError::NotFound,
            StorageError::Backend(_) => ApiError::Backend,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            ApiError::Forbidden => (StatusCode::FORBIDDEN, "forbidden"),
            ApiError::AuthNotConfigured => (
                StatusCode::SERVICE_UNAVAILABLE,
                "authentication not configured",
            ),
            ApiError::NotFound => (StatusCode::NOT_FOUND, "not found"),
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            ApiError::Backend => (StatusCode::BAD_GATEWAY, "storage backend error"),
            ApiError::QueryUnavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "confidential query not available",
            ),
            ApiError::ResearchUnavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "research access not configured",
            ),
            ApiError::ProvisioningUnavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "provisioning not configured",
            ),
            ApiError::WebhookNotConfigured => (
                StatusCode::SERVICE_UNAVAILABLE,
                "webhook secret not configured",
            ),
            ApiError::AttestationUnavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "enclave attestation unavailable",
            ),
            ApiError::QueryRejected(msg) => (StatusCode::UNPROCESSABLE_ENTITY, msg),
            ApiError::BudgetExhausted => (
                StatusCode::TOO_MANY_REQUESTS,
                "research query budget exhausted",
            ),
        };
        let mut response = (status, Json(json!({ "error": message }))).into_response();
        if matches!(status, StatusCode::UNAUTHORIZED) {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, "Bearer".parse().expect("static"));
        }
        response
    }
}

// ── Auth middleware ──────────────────────────────────────────────────────────

/// Verify the request's bearer token. `Err` carries the response to return.
fn authenticate(
    state: &AppState,
    req: &Request,
) -> Result<platform_auth::VerifiedClaims, ApiError> {
    let verifier = state.jwt.as_ref().ok_or_else(|| {
        security_audit_event(
            AuditKind::AuthDecision,
            None,
            "refused",
            "auth not configured; failing closed",
        );
        ApiError::AuthNotConfigured
    })?;

    let token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));

    match token.map(|t| verifier.verify(t)) {
        Some(Ok(claims)) if claims.token_type == platform_auth::TokenType::Access => Ok(claims),
        Some(Ok(_)) => {
            // A pre-MFA or refresh token verified but does not grant access.
            security_audit_event(
                AuditKind::AuthDecision,
                None,
                "denied",
                "token type not accepted on this route",
            );
            Err(ApiError::Unauthorized)
        }
        _ => {
            security_audit_event(
                AuditKind::AuthDecision,
                None,
                "denied",
                "missing or invalid bearer token",
            );
            Err(ApiError::Unauthorized)
        }
    }
}

async fn require_tenant(State(state): State<AppState>, mut req: Request, next: Next) -> Response {
    match authenticate(&state, &req) {
        Ok(claims) => {
            req.extensions_mut().insert(AuthedTenant(claims.tenant));
            next.run(req).await
        }
        Err(err) => err.into_response(),
    }
}

/// Like [`require_tenant`], but additionally requires the admin claim.
async fn require_admin(State(state): State<AppState>, mut req: Request, next: Next) -> Response {
    match authenticate(&state, &req) {
        Ok(claims) if claims.admin => {
            req.extensions_mut().insert(AuthedTenant(claims.tenant));
            next.run(req).await
        }
        Ok(_) => {
            security_audit_event(
                AuditKind::AuthDecision,
                None,
                "denied",
                "admin route requires admin claim",
            );
            ApiError::Forbidden.into_response()
        }
        Err(err) => err.into_response(),
    }
}

// ── Router ───────────────────────────────────────────────────────────────────

pub fn build_app(state: AppState) -> Router {
    let tenant_auth = || middleware::from_fn_with_state(state.clone(), require_tenant);

    let drive = Router::new()
        .route("/objects", get(list_objects))
        .route(
            "/objects/{object_id}/manifest",
            put(put_manifest).get(get_manifest),
        )
        .route(
            "/objects/{object_id}/chunks/{chunk_index}",
            put(put_chunk).get(get_chunk),
        )
        .route("/objects/{object_id}", delete(delete_object))
        .route("/enrollment", put(put_enrollment).get(get_enrollment))
        .layer(DefaultBodyLimit::max(MAX_CHUNK_BODY_BYTES))
        .layer(tenant_auth());

    let query = Router::new()
        .route("/", post(run_query))
        .layer(tenant_auth());

    let grants = Router::new()
        .route("/", get(list_grants).post(create_grant))
        .route("/{grant_id}", delete(revoke_grant))
        .route("/{grant_id}/budget", get(get_budget).post(top_up_budget))
        .layer(tenant_auth());

    let research = Router::new()
        .route("/query", post(run_research_query))
        .route("/requests", get(research::list_access_requests))
        .route(
            "/requests/{request_id}/approve",
            post(research::approve_access_request),
        )
        .route(
            "/requests/{request_id}/deny",
            post(research::deny_access_request),
        )
        .layer(tenant_auth());

    let catalog = Router::new()
        .route(
            "/",
            get(research::catalog_index).post(research::publish_listing),
        )
        .route("/{listing_id}", delete(research::unpublish_listing))
        .route(
            "/{listing_id}/request",
            post(research::request_dataset_access),
        )
        .layer(tenant_auth());

    let admin_tenants = Router::new()
        .route("/", get(admin_list_tenants))
        .route(
            "/{tenant_id}/connectors/{slug}",
            post(admin_toggle_connector),
        )
        .layer(middleware::from_fn_with_state(state.clone(), require_admin));

    // Authorized by Paddle signature, not by JWT.
    let webhooks = Router::new().route("/mor", post(mor_webhook));

    Router::new()
        .route("/healthz", get(healthz))
        .route("/api/v1/meta", get(meta))
        .nest("/api/v1/drive", drive)
        .nest("/api/v1/query", query)
        .nest("/api/v1/grants", grants)
        .nest("/api/v1/research", research)
        .nest("/api/v1/catalog", catalog)
        .nest("/admin/tenants", admin_tenants)
        .nest("/admin/webhooks", webhooks)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

// ── Public handlers ──────────────────────────────────────────────────────────

async fn healthz() -> Json<serde_json::Value> {
    Json(json!({ "status": "ok" }))
}

/// Public branding/feature metadata, all from env config; the engine name
/// must never appear here.
async fn meta(State(state): State<AppState>) -> Json<serde_json::Value> {
    let cfg = &state.config;
    Json(json!({
        "name": cfg.brand.public_name,
        "domain": cfg.brand.domain_name,
        "support_email": cfg.brand.support_email,
        "features": { "zk_enabled": cfg.features.zk.is_enabled() },
    }))
}

// ── Admin console + MoR webhook handlers ─────────────────────────────────────

/// `POST /admin/webhooks/mor` — Paddle webhook. Reads the raw body (required
/// for HMAC) and the `Paddle-Signature` header.
async fn mor_webhook(State(state): State<AppState>, req: Request) -> Response {
    let provisioning = match provisioning_service(&state) {
        Ok(provisioning) => provisioning,
        Err(err) => return err.into_response(),
    };
    let signature = req
        .headers()
        .get("Paddle-Signature")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    let raw_body = match axum::body::to_bytes(req.into_body(), admin::MAX_WEBHOOK_BYTES).await {
        Ok(bytes) => bytes,
        Err(_) => return ApiError::BadRequest("body too large").into_response(),
    };

    let result = admin::handle_mor_webhook(
        provisioning,
        state.config.billing.paddle_webhook_secret.as_deref(),
        state.config.billing.signature_tolerance_secs,
        signature.as_deref(),
        &raw_body,
    )
    .await;

    match result {
        Ok(body) => Json(body).into_response(),
        Err(err) => err.into_response(),
    }
}

fn provisioning_service(state: &AppState) -> Result<&ProvisioningService, ApiError> {
    state
        .provisioning
        .as_deref()
        .ok_or(ApiError::ProvisioningUnavailable)
}

async fn admin_list_tenants(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let provisioning = provisioning_service(&state)?;
    Ok(Json(admin::list_tenants(provisioning).await?))
}

async fn admin_toggle_connector(
    State(state): State<AppState>,
    Path((tenant_id, slug)): Path<(String, String)>,
    Json(body): Json<admin::ToggleConnectorRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let provisioning = provisioning_service(&state)?;
    let tenant: TenantId = tenant_id
        .parse()
        .map_err(|_| ApiError::BadRequest("invalid tenant id"))?;
    Ok(Json(
        admin::toggle_connector(provisioning, tenant, &slug, body.enabled).await?,
    ))
}

// ── Confidential query ───────────────────────────────────────────────────────

async fn run_query(
    State(state): State<AppState>,
    Extension(AuthedTenant(tenant)): Extension<AuthedTenant>,
    Json(req): Json<QueryRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let service = query_service(&state)?;
    let connector = ConnectorSlug::new(&req.connector)
        .map_err(|_| ApiError::BadRequest("invalid connector slug"))?;
    let result = service.query(tenant, &connector, &req.sql).await?;
    Ok(Json(result))
}

// ── Research access: grants + disclosure-controlled queries ──────────────────

pub(crate) fn query_service(state: &AppState) -> Result<&Arc<ConnectorQueryService>, ApiError> {
    state.query.as_ref().ok_or(ApiError::QueryUnavailable)
}

/// Steward grants a researcher aggregate access to one of its connectors.
async fn create_grant(
    State(state): State<AppState>,
    Extension(AuthedTenant(steward)): Extension<AuthedTenant>,
    Json(req): Json<GrantRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let service = query_service(&state)?;
    let researcher: TenantId = req
        .researcher_tenant
        .parse()
        .map_err(|_| ApiError::BadRequest("invalid researcher tenant id"))?;
    if researcher == steward {
        return Err(ApiError::BadRequest("cannot grant to yourself"));
    }
    let connector = ConnectorSlug::new(&req.connector)
        .map_err(|_| ApiError::BadRequest("invalid connector slug"))?;
    Ok(Json(
        service
            .grant(steward, researcher, &connector, req.query_budget)
            .await?,
    ))
}

/// Steward raises a grant's query-budget allocation.
async fn top_up_budget(
    State(state): State<AppState>,
    Extension(AuthedTenant(steward)): Extension<AuthedTenant>,
    Path(grant_id): Path<String>,
    Json(req): Json<TopUpRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let service = query_service(&state)?;
    if req.additional == 0 {
        return Err(ApiError::BadRequest("top-up amount must be positive"));
    }
    Ok(Json(
        service
            .top_up_budget(steward, &grant_id, req.additional)
            .await?,
    ))
}

/// Budget standing for a grant the caller is party to.
async fn get_budget(
    State(state): State<AppState>,
    Extension(AuthedTenant(caller)): Extension<AuthedTenant>,
    Path(grant_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let service = query_service(&state)?;
    Ok(Json(service.budget_state(caller, &grant_id).await?))
}

async fn revoke_grant(
    State(state): State<AppState>,
    Extension(AuthedTenant(steward)): Extension<AuthedTenant>,
    Path(grant_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let service = query_service(&state)?;
    Ok(Json(service.revoke_grant(steward, &grant_id).await?))
}

async fn list_grants(
    State(state): State<AppState>,
    Extension(AuthedTenant(tenant)): Extension<AuthedTenant>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let service = query_service(&state)?;
    Ok(Json(service.list_grants(tenant).await?))
}

async fn run_research_query(
    State(state): State<AppState>,
    Extension(AuthedTenant(researcher)): Extension<AuthedTenant>,
    Json(req): Json<ResearchQueryRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let service = query_service(&state)?;
    let steward: TenantId = req
        .steward_tenant
        .parse()
        .map_err(|_| ApiError::BadRequest("invalid steward tenant id"))?;
    let connector = ConnectorSlug::new(&req.connector)
        .map_err(|_| ApiError::BadRequest("invalid connector slug"))?;
    let result = service
        .research_query(researcher, steward, &connector, &req.sql)
        .await?;
    Ok(Json(result))
}

// ── Drive ────────────────────────────────────────────────────────────────────

fn parse_object_id(raw: &str) -> Result<ObjectId, ApiError> {
    raw.parse()
        .map_err(|_| ApiError::BadRequest("invalid object id"))
}

fn validate_payload(payload: &EncPayloadB64) -> Result<(), ApiError> {
    let iv = B64
        .decode(&payload.iv_b64)
        .map_err(|_| ApiError::BadRequest("invalid base64 in payload"))?;
    if iv.len() != GCM_IV_BYTES {
        return Err(ApiError::BadRequest("invalid IV length"));
    }
    B64.decode(&payload.data_b64)
        .map_err(|_| ApiError::BadRequest("invalid base64 in payload"))?;
    Ok(())
}

async fn put_manifest(
    State(state): State<AppState>,
    Extension(AuthedTenant(tenant)): Extension<AuthedTenant>,
    Path(object_id): Path<String>,
    Json(body): Json<ManifestBody>,
) -> Result<StatusCode, ApiError> {
    let object_id = parse_object_id(&object_id)?;
    if body.chunk_count > MAX_CHUNK_INDEX {
        return Err(ApiError::BadRequest("chunk count too large"));
    }
    validate_payload(&body.wrapped_key)?;
    validate_payload(&body.manifest)?;

    let stored = serde_json::to_vec(&body).map_err(|_| ApiError::Backend)?;
    state
        .vault
        .put(
            &TenantPaths::drive_manifest(tenant, object_id),
            stored.into(),
        )
        .await?;
    security_audit_event(
        AuditKind::DataAccess,
        Some(tenant),
        "ok",
        &format!("put_manifest object={object_id}"),
    );
    Ok(StatusCode::NO_CONTENT)
}

/// Fetch a vault object, auditing misses: a 404 on a tenant-scoped read is a
/// security signal (e.g. a cross-tenant object-id probe), so it must appear
/// in the audit stream, not vanish into an HTTP status.
async fn audited_get(
    state: &AppState,
    tenant: TenantId,
    path: &platform_storage::VaultPath,
    what: &str,
) -> Result<Bytes, ApiError> {
    match state.vault.get(path).await {
        Ok(bytes) => Ok(bytes),
        Err(StorageError::NotFound) => {
            security_audit_event(AuditKind::DataAccess, Some(tenant), "miss", what);
            Err(ApiError::NotFound)
        }
        Err(other) => Err(other.into()),
    }
}

async fn get_manifest(
    State(state): State<AppState>,
    Extension(AuthedTenant(tenant)): Extension<AuthedTenant>,
    Path(object_id): Path<String>,
) -> Result<Response, ApiError> {
    let object_id = parse_object_id(&object_id)?;
    let detail = format!("get_manifest object={object_id}");
    let stored = audited_get(
        &state,
        tenant,
        &TenantPaths::drive_manifest(tenant, object_id),
        &detail,
    )
    .await?;
    security_audit_event(AuditKind::DataAccess, Some(tenant), "ok", &detail);
    Ok(([(header::CONTENT_TYPE, "application/json")], stored).into_response())
}

async fn list_objects(
    State(state): State<AppState>,
    Extension(AuthedTenant(tenant)): Extension<AuthedTenant>,
) -> Result<Json<Vec<ListEntry>>, ApiError> {
    let paths = state
        .vault
        .list(&TenantPaths::drive_manifest_prefix(tenant))
        .await?;

    let mut entries = Vec::with_capacity(paths.len());
    for path in paths {
        let Some(object_id) = path
            .as_str()
            .rsplit('/')
            .next()
            .and_then(|name| name.strip_suffix(".json"))
            .map(str::to_owned)
        else {
            continue;
        };
        let stored = state.vault.get(&path).await?;
        match serde_json::from_slice::<ManifestBody>(&stored) {
            Ok(body) => entries.push(ListEntry { object_id, body }),
            Err(_) => {
                tracing::warn!(%path, "skipping unparsable manifest record");
            }
        }
    }
    entries.sort_by(|a, b| b.body.created_at_iso.cmp(&a.body.created_at_iso));
    security_audit_event(
        AuditKind::DataAccess,
        Some(tenant),
        "ok",
        &format!("list_objects count={}", entries.len()),
    );
    Ok(Json(entries))
}

async fn put_chunk(
    State(state): State<AppState>,
    Extension(AuthedTenant(tenant)): Extension<AuthedTenant>,
    Path((object_id, chunk_index)): Path<(String, u32)>,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    let object_id = parse_object_id(&object_id)?;
    if chunk_index >= MAX_CHUNK_INDEX {
        return Err(ApiError::BadRequest("chunk index too large"));
    }
    if body.len() < MIN_CHUNK_BODY_BYTES {
        return Err(ApiError::BadRequest(
            "chunk body too small to be sealed data",
        ));
    }

    state
        .vault
        .put(
            &TenantPaths::drive_chunk(tenant, object_id, chunk_index),
            body,
        )
        .await?;
    security_audit_event(
        AuditKind::DataAccess,
        Some(tenant),
        "ok",
        &format!("put_chunk object={object_id} index={chunk_index}"),
    );
    Ok(StatusCode::NO_CONTENT)
}

async fn get_chunk(
    State(state): State<AppState>,
    Extension(AuthedTenant(tenant)): Extension<AuthedTenant>,
    Path((object_id, chunk_index)): Path<(String, u32)>,
) -> Result<Response, ApiError> {
    let object_id = parse_object_id(&object_id)?;
    let detail = format!("get_chunk object={object_id} index={chunk_index}");
    let bytes = audited_get(
        &state,
        tenant,
        &TenantPaths::drive_chunk(tenant, object_id, chunk_index),
        &detail,
    )
    .await?;
    security_audit_event(AuditKind::DataAccess, Some(tenant), "ok", &detail);
    Ok(([(header::CONTENT_TYPE, "application/octet-stream")], bytes).into_response())
}

async fn delete_object(
    State(state): State<AppState>,
    Extension(AuthedTenant(tenant)): Extension<AuthedTenant>,
    Path(object_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let object_id = parse_object_id(&object_id)?;
    let manifest_path = TenantPaths::drive_manifest(tenant, object_id);
    let detail = format!("delete_object object={object_id}");

    // Existence check first: not every backend errors when deleting a
    // missing key, and an absent object must be an honest 404 everywhere.
    audited_get(&state, tenant, &manifest_path, &detail).await?;
    state.vault.delete(&manifest_path).await?;

    let chunks = state
        .vault
        .list(&TenantPaths::drive_object_prefix(tenant, object_id))
        .await?;
    for chunk_path in chunks {
        match state.vault.delete(&chunk_path).await {
            Ok(()) | Err(StorageError::NotFound) => {}
            Err(err) => return Err(err.into()),
        }
    }
    security_audit_event(AuditKind::DataAccess, Some(tenant), "ok", &detail);
    Ok(StatusCode::NO_CONTENT)
}

// ── Key enrollment ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentBody {
    /// Base64 raw X25519 public key: the browser-generated tenant HPKE key.
    pub hpke_public_key_b64: String,
}

/// Enroll the tenant's HPKE public key, which enclave pipelines use to seal
/// connector data to the tenant. The key is validated as an X25519 point
/// before storage, and every attempt is audited.
async fn put_enrollment(
    State(state): State<AppState>,
    Extension(AuthedTenant(tenant)): Extension<AuthedTenant>,
    Json(body): Json<EnrollmentBody>,
) -> Result<StatusCode, ApiError> {
    let public_key_b64 = body.hpke_public_key_b64.trim();
    let raw = B64
        .decode(public_key_b64)
        .map_err(|_| ApiError::BadRequest("invalid base64 public key"))?;
    if platform_crypto::TenantPublicKey::from_raw(&raw).is_err() {
        security_audit_event(
            AuditKind::KeyEnrollment,
            Some(tenant),
            "denied",
            "rejected malformed public key",
        );
        return Err(ApiError::BadRequest("invalid public key"));
    }

    let record = json!({
        "hpke_public_key_b64": public_key_b64,
        "suite": HPKE_SUITE,
    });
    let stored = serde_json::to_vec(&record).map_err(|_| ApiError::Backend)?;
    state
        .vault
        .put(&TenantPaths::tenant_enrollment(tenant), stored.into())
        .await?;

    security_audit_event(
        AuditKind::KeyEnrollment,
        Some(tenant),
        "ok",
        "tenant HPKE public key enrolled",
    );
    Ok(StatusCode::NO_CONTENT)
}

async fn get_enrollment(
    State(state): State<AppState>,
    Extension(AuthedTenant(tenant)): Extension<AuthedTenant>,
) -> Result<Response, ApiError> {
    let stored = audited_get(
        &state,
        tenant,
        &TenantPaths::tenant_enrollment(tenant),
        "get_enrollment",
    )
    .await?;
    security_audit_event(AuditKind::DataAccess, Some(tenant), "ok", "get_enrollment");
    Ok(([(header::CONTENT_TYPE, "application/json")], stored).into_response())
}
