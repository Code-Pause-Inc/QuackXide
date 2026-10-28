//! Structured JSON logging and the `SECURITY_AUDIT_EVENT` stream.
//!
//! Every security-relevant action emits one audit record via
//! [`security_audit_event`]. Records carry identifiers and outcomes only,
//! never key material, plaintext, filenames, or query text.

use platform_core::TenantId;
use tracing::Subscriber;
use tracing_subscriber::filter::{EnvFilter, FilterExt, filter_fn};
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::{Layer, SubscriberExt};

pub mod capture;
mod shutdown;

pub use shutdown::shutdown_signal;

/// `tracing` target for audit records, so log routing can split them from
/// operational logs.
pub const SECURITY_AUDIT_TARGET: &str = "SECURITY_AUDIT_EVENT";
/// Operational filter used when `RUST_LOG` is unset or does not parse.
const DEFAULT_FILTER: &str = "info";

/// Build the process subscriber. Both of its layers write JSON lines to
/// `writer`. The operational layer is filtered by `filter` (`RUST_LOG`
/// syntax; `info` if it does not parse) and never writes audit records. The
/// audit layer writes every `SECURITY_AUDIT_EVENT` record whatever `filter`
/// says, so no configuration can turn the audit stream off.
/// [`init_from_env`] installs it; tests call it directly.
pub fn build_subscriber<W>(filter: &str, writer: W) -> impl Subscriber + Send + Sync + 'static
where
    W: for<'w> MakeWriter<'w> + Clone + Send + Sync + 'static,
{
    let operational_filter = EnvFilter::try_new(filter)
        .unwrap_or_else(|_| EnvFilter::new(DEFAULT_FILTER))
        .and(filter_fn(|meta| meta.target() != SECURITY_AUDIT_TARGET));
    let operational_layer = tracing_subscriber::fmt::layer()
        .json()
        .flatten_event(true)
        .with_writer(writer.clone())
        .with_filter(operational_filter);
    let audit_layer = tracing_subscriber::fmt::layer()
        .json()
        .flatten_event(true)
        .with_writer(writer)
        .with_filter(filter_fn(|meta| meta.target() == SECURITY_AUDIT_TARGET));
    tracing_subscriber::registry()
        .with(operational_layer)
        .with(audit_layer)
}

/// Install [`build_subscriber`] process-wide, writing to stdout, with the
/// operational filter from `RUST_LOG` (default `info`). Audit records are
/// written whatever `RUST_LOG` says. Later calls are no-ops.
pub fn init_from_env() {
    use tracing_subscriber::util::SubscriberInitExt;

    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| DEFAULT_FILTER.to_owned());
    let _ = build_subscriber(&filter, std::io::stdout).try_init();
}

/// Fixed audit vocabulary; every variant is part of the compliance surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditKind {
    ServiceStart,
    KeyEnrollment,
    KeyRelease,
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
            AuditKind::KeyRelease => "crypto.key_release",
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
        // Emitting outside a capture can race a capture's install (see
        // `capture`), so hold the same exclusive lock.
        let _exclusive = capture::capture_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        security_audit_event(AuditKind::ServiceStart, None, "ok", "test boot");
        security_audit_event(
            AuditKind::DataAccess,
            Some(TenantId::generate()),
            "denied",
            "test denial",
        );
    }
    /// `RUST_LOG` filters operational logs only: under every filter, even
    /// one naming the audit target, each audit record is written once.
    #[test]
    fn audit_records_ignore_the_operational_filter() {
        // A scoped subscriber shares the callsite-interest cache with
        // captures (see `capture`), so hold the same exclusive lock.
        let _exclusive = capture::capture_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for filter in ["error", "off", "SECURITY_AUDIT_EVENT=off", "trace"] {
            let output = SharedBuffer::default();
            let sink = output.clone();
            let subscriber = build_subscriber(filter, move || sink.clone());
            tracing::subscriber::with_default(subscriber, || {
                security_audit_event(AuditKind::ServiceStart, None, "ok", "filter probe");
                tracing::info!("info probe");
            });

            let lines = output.lines();
            let audit: Vec<&String> = lines
                .iter()
                .filter(|line| line.contains("filter probe"))
                .collect();
            assert_eq!(audit.len(), 1, "{filter}: {lines:?}");
            assert!(
                audit[0].contains(r#""target":"SECURITY_AUDIT_EVENT""#),
                "{filter}: {}",
                audit[0]
            );
            let operational = lines.iter().any(|line| line.contains("info probe"));
            assert_eq!(operational, filter == "trace", "{filter}: {lines:?}");
        }
    }

    /// An in-memory writer the test reads back.
    #[derive(Clone, Default)]
    struct SharedBuffer(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl SharedBuffer {
        fn lines(&self) -> Vec<String> {
            let bytes = self.0.lock().expect("buffer lock").clone();
            String::from_utf8(bytes)
                .expect("log output is UTF-8")
                .lines()
                .map(str::to_owned)
                .collect()
        }
    }

    impl std::io::Write for SharedBuffer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let mut buffer = self.0.lock().expect("buffer lock");
            buffer.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
}
