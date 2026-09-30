//! Structured JSON logging and the `SECURITY_AUDIT_EVENT` stream.
//!
//! Every security-relevant action emits one audit record via
//! [`security_audit_event`]. Records carry identifiers and outcomes only,
//! never key material, plaintext, filenames, or query text.

use platform_core::TenantId;

pub mod capture;

/// `tracing` target for audit records, so log routing can split them from
/// operational logs.
pub const SECURITY_AUDIT_TARGET: &str = "SECURITY_AUDIT_EVENT";

/// Initialize process-wide JSON tracing, filtered by `RUST_LOG` (default
/// `info`). Later calls are no-ops.
pub fn init_from_env() {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().json().flatten_event(true))
        .try_init();
}

/// Fixed audit vocabulary; every variant is part of the compliance surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditKind {
    ServiceStart,
    KeyEnrollment,
    TeeAttestation,
    TenantProvisioned,
    DataAccess,
    ConnectorSync,
    QueryExecuted,
    AuthDecision,
    /// Query-budget top-ups, exhaustion refusals, and ledger anomalies.
    ResearchBudget,
    /// Listings published/withdrawn and access requests filed/resolved.
    /// Identifiers only, never titles or notes.
    ResearchCatalog,
}

impl AuditKind {
    pub fn as_str(self) -> &'static str {
        match self {
            AuditKind::ServiceStart => "service.start",
            AuditKind::KeyEnrollment => "crypto.key_enrollment",
            AuditKind::TeeAttestation => "tee.attestation",
            AuditKind::TenantProvisioned => "tenant.provisioned",
            AuditKind::DataAccess => "data.access",
            AuditKind::ConnectorSync => "connector.sync",
            AuditKind::QueryExecuted => "engine.query",
            AuditKind::AuthDecision => "auth.decision",
            AuditKind::ResearchBudget => "research.budget",
            AuditKind::ResearchCatalog => "research.catalog",
        }
    }
}

/// Emit one audit record. `outcome` is machine-readable ("ok", "denied",
/// "failed"); `detail` must not contain secrets or customer content.
pub fn security_audit_event(
    kind: AuditKind,
    tenant: Option<TenantId>,
    outcome: &str,
    detail: &str,
) {
    let tenant = tenant.map(|t| t.to_string());
    tracing::info!(
        target: SECURITY_AUDIT_TARGET,
        audit_kind = kind.as_str(),
        tenant_id = tenant.as_deref().unwrap_or("-"),
        outcome,
        detail,
        "security audit event"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_kinds_have_stable_names() {
        assert_eq!(AuditKind::TeeAttestation.as_str(), "tee.attestation");
        assert_eq!(AuditKind::DataAccess.as_str(), "data.access");
    }

    #[test]
    fn emitting_without_init_does_not_panic() {
        security_audit_event(AuditKind::ServiceStart, None, "ok", "test boot");
        security_audit_event(
            AuditKind::DataAccess,
            Some(TenantId::generate()),
            "denied",
            "test denial",
        );
    }
}
