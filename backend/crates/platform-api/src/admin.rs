//! Admin console API and the Merchant-of-Record (Paddle) webhook.
//!
//! * `POST /admin/webhooks/mor`: HMAC-verified Paddle subscription events
//!   that provision or suspend a tenant. Authorized by signature, not JWT.
//! * `GET /admin/tenants`: tenants with storage usage and connector toggles.
//! * `POST /admin/tenants/{tenant_id}/connectors/{slug}`: enable or disable a
//!   connector.
//!
//! Admin routes require the JWT `adm` claim.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use platform_billing::{ProvisioningAction, action_for, parse_event, verify_paddle_signature};
use platform_connectors::catalog;
use platform_core::{ConnectorSlug, TenantId};
use platform_storage::{TenantPaths, VaultStore};
use platform_telemetry::{AuditKind, security_audit_event};
use platform_tenancy::{TenancyError, TenantRecord, TenantRegistry, TenantStatus};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::ApiError;

/// Upper bound on a MoR webhook body (Paddle events are small JSON).
pub const MAX_WEBHOOK_BYTES: usize = 256 * 1024;

/// Built-in catalog slugs, seeded disabled at provisioning time.
pub fn default_connector_slugs() -> Vec<String> {
    catalog()
        .iter()
        .map(|c| c.slug.as_str().to_owned())
        .collect()
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Provisioning driven by MoR events. Each provisioned tenant also gets a
/// control-plane marker in the vault, outside any tenant data prefix, so it
/// survives an in-memory registry restart.
pub struct ProvisioningService {
    registry: Arc<dyn TenantRegistry>,
    vault: Arc<dyn VaultStore>,
}

impl ProvisioningService {
    pub fn new(registry: Arc<dyn TenantRegistry>, vault: Arc<dyn VaultStore>) -> Self {
        Self { registry, vault }
    }

    pub fn registry(&self) -> &Arc<dyn TenantRegistry> {
        &self.registry
    }

    pub fn vault(&self) -> &Arc<dyn VaultStore> {
        &self.vault
    }

    async fn apply(&self, action: ProvisioningAction) -> Result<Value, ApiError> {
        match action {
            ProvisioningAction::Provision {
                subscription_id,
                customer_id,
                plan,
            } => {
                let record = self
                    .registry
                    .provision(&subscription_id, &customer_id, &plan)
                    .await
                    .map_err(|_| ApiError::Backend)?;
                // Durable marker (best effort; provisioning already succeeded).
                // A missing marker loses the tenant on a registry restart, so
                // failures are surfaced to operators.
                match serde_json::to_vec(&record) {
                    Ok(bytes) => {
                        if let Err(err) = self
                            .vault
                            .put(&TenantPaths::control_marker(record.tenant_id), bytes.into())
                            .await
                        {
                            tracing::warn!(
                                tenant = %record.tenant_id,
                                error = %err,
                                "durable tenant marker write failed"
                            );
                        }
                    }
                    Err(_) => tracing::warn!(
                        tenant = %record.tenant_id,
                        "durable tenant marker could not be serialized"
                    ),
                }
                security_audit_event(
                    AuditKind::TenantProvisioned,
                    Some(record.tenant_id),
                    "ok",
                    &format!("provisioned subscription={subscription_id} plan={plan}"),
                );
                Ok(json!({
                    "received": true,
                    "action": "provisioned",
                    "tenant_id": record.tenant_id,
                }))
            }
            ProvisioningAction::Suspend { subscription_id } => {
                let updated = self
                    .registry
                    .set_status(&subscription_id, TenantStatus::Suspended)
                    .await
                    .map_err(|_| ApiError::Backend)?;
                let tenant = updated.as_ref().map(|r| r.tenant_id);
                security_audit_event(
                    AuditKind::TenantProvisioned,
                    tenant,
                    if updated.is_some() { "ok" } else { "noop" },
                    &format!("suspend subscription={subscription_id}"),
                );
                Ok(json!({
                    "received": true,
                    "action": "suspended",
                    "matched": updated.is_some(),
                }))
            }
            ProvisioningAction::Ignore { reason } => Ok(json!({
                "received": true,
                "action": "ignored",
                "reason": reason,
            })),
        }
    }
}

/// Verify a Paddle webhook and apply its provisioning action. Without a
/// configured `secret` the webhook is refused with 503.
pub async fn handle_mor_webhook(
    provisioning: &ProvisioningService,
    secret: Option<&str>,
    tolerance_secs: u64,
    signature_header: Option<&str>,
    raw_body: &[u8],
) -> Result<Value, ApiError> {
    let secret = secret.ok_or(ApiError::WebhookNotConfigured)?;
    let signature = signature_header.ok_or(ApiError::Unauthorized)?;

    verify_paddle_signature(secret, signature, raw_body, now_unix(), tolerance_secs).map_err(
        |err| {
            security_audit_event(
                AuditKind::AuthDecision,
                None,
                "denied",
                "MoR webhook signature rejected",
            );
            tracing::warn!(error = %err, "MoR webhook signature verification failed");
            ApiError::Unauthorized
        },
    )?;

    let event = parse_event(raw_body).map_err(|_| ApiError::BadRequest("malformed event"))?;
    tracing::info!(event_type = %event.event_type, "MoR webhook verified");
    provisioning.apply(action_for(&event)).await
}

/// A tenant plus its live storage usage, for the admin list.
#[derive(serde::Serialize)]
pub struct TenantView {
    #[serde(flatten)]
    record: TenantRecord,
    storage_object_count: u64,
    storage_bytes: u64,
}

pub async fn list_tenants(provisioning: &ProvisioningService) -> Result<Value, ApiError> {
    let records = provisioning
        .registry
        .list()
        .await
        .map_err(|_| ApiError::Backend)?;

    let mut views = Vec::with_capacity(records.len());
    for record in records {
        // Reporting zero on a failed lookup would misstate stored data.
        let usage = provisioning
            .vault
            .usage(&TenantPaths::tenant_root(record.tenant_id))
            .await
            .map_err(|_| ApiError::Backend)?;
        views.push(TenantView {
            record,
            storage_object_count: usage.object_count,
            storage_bytes: usage.total_bytes,
        });
    }
    Ok(json!({ "tenants": views }))
}

#[derive(Debug, Deserialize)]
pub struct ToggleConnectorRequest {
    pub enabled: bool,
}

pub async fn toggle_connector(
    provisioning: &ProvisioningService,
    tenant: TenantId,
    connector_raw: &str,
    enabled: bool,
) -> Result<Value, ApiError> {
    let connector = ConnectorSlug::new(connector_raw)
        .map_err(|_| ApiError::BadRequest("invalid connector slug"))?;
    if !catalog().iter().any(|c| c.slug == connector) {
        return Err(ApiError::BadRequest("unknown connector"));
    }

    let record = provisioning
        .registry
        .set_connector(tenant, connector.as_str(), enabled)
        .await
        .map_err(registry_error)?;

    security_audit_event(
        AuditKind::TenantProvisioned,
        Some(tenant),
        "ok",
        &format!("connector {connector} set enabled={enabled}"),
    );
    serde_json::to_value(&record).map_err(|_| ApiError::Backend)
}

/// Only a missing tenant is a 404; any other registry failure is a backend
/// error, never reported as absence.
fn registry_error(err: TenancyError) -> ApiError {
    if matches!(err, TenancyError::NotFound) {
        ApiError::NotFound
    } else {
        ApiError::Backend
    }
}
