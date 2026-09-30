//! Test support: capture audit records emitted by code under test so audit
//! coverage can be asserted.
//!
//! Captures are thread-local (`tracing::subscriber::set_default`); install
//! one at the top of a single-threaded test, run the code, then assert.

use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};

use tracing::field::{Field, Visit};
use tracing_subscriber::Registry;
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};

/// Captures are exclusive process-wide. Scoped subscribers share the global
/// callsite-interest cache, and a guard dropping on another thread can make
/// the audit callsite briefly read as disabled, losing an event.
pub(crate) fn capture_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(Mutex::default)
}

/// One captured audit record (string fields as emitted).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CapturedAudit {
    pub audit_kind: String,
    pub tenant_id: String,
    pub outcome: String,
    pub detail: String,
}

#[derive(Default)]
struct Collector(Mutex<Vec<CapturedAudit>>);

struct CaptureLayer(Arc<Collector>);

struct FieldVisitor<'a>(&'a mut CapturedAudit);

impl Visit for FieldVisitor<'_> {
    fn record_str(&mut self, field: &Field, value: &str) {
        match field.name() {
            "audit_kind" => self.0.audit_kind = value.to_owned(),
            "tenant_id" => self.0.tenant_id = value.to_owned(),
            "outcome" => self.0.outcome = value.to_owned(),
            "detail" => self.0.detail = value.to_owned(),
            _ => {}
        }
    }

    fn record_debug(&mut self, _field: &Field, _value: &dyn std::fmt::Debug) {}
}

impl<S: tracing::Subscriber> Layer<S> for CaptureLayer {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        if event.metadata().target() != crate::SECURITY_AUDIT_TARGET {
            return;
        }
        let mut captured = CapturedAudit::default();
        event.record(&mut FieldVisitor(&mut captured));
        self.0.0.lock().expect("capture lock").push(captured);
    }
}

/// Scoped audit-event capture for the current thread. Field order matters:
/// the subscriber guard drops before the exclusivity lock, so no other
/// capture installs mid-teardown.
pub struct AuditCapture {
    collector: Arc<Collector>,
    _guard: tracing::subscriber::DefaultGuard,
    _exclusive: MutexGuard<'static, ()>,
}

impl AuditCapture {
    pub fn install() -> Self {
        const PRIME_ATTEMPTS: usize = 1_000;
        // Poisoning only means another capturing test panicked.
        let exclusive = capture_lock()
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let collector = Arc::new(Collector::default());
        let subscriber = Registry::default().with(CaptureLayer(collector.clone()));
        let guard = tracing::subscriber::set_default(subscriber);
        let capture = Self {
            collector,
            _guard: guard,
            _exclusive: exclusive,
        };
        // The audit callsite registers lazily. A first emission on another
        // thread can still be registering it when this capture installs,
        // then cache it as disabled, so events reach neither subscriber.
        // A probe arriving mid-registration proves nothing, so after each
        // arrival recompute every callsite's interest against the live
        // dispatchers and require a probe to arrive again.
        capture.prime(PRIME_ATTEMPTS);
        for _ in 0..PRIME_ATTEMPTS {
            tracing::callsite::rebuild_interest_cache();
            if capture.probe() {
                // Give a registration still in flight time to finish, then
                // confirm the callsite survives one more rebuild.
                std::thread::sleep(std::time::Duration::from_millis(1));
                tracing::callsite::rebuild_interest_cache();
                if capture.probe() {
                    break;
                }
            }
            capture.prime(PRIME_ATTEMPTS);
        }
        assert!(
            capture.probe(),
            "audit callsite never became live under capture"
        );
        capture.collector.0.lock().expect("capture lock").clear();
        capture
    }

    /// Emit probes until one arrives.
    fn prime(&self, attempts: usize) {
        for _ in 0..attempts {
            if self.probe() {
                return;
            }
            std::thread::yield_now();
        }
    }

    /// Emit one probe; true if it was captured.
    fn probe(&self) -> bool {
        let before = self.events().len();
        crate::security_audit_event(
            crate::AuditKind::ServiceStart,
            None,
            "prime",
            "capture warmup probe",
        );
        self.events().len() > before
    }

    pub fn events(&self) -> Vec<CapturedAudit> {
        self.collector.0.lock().expect("capture lock").clone()
    }

    /// True if any captured event matches `audit_kind` + `outcome`.
    pub fn contains(&self, audit_kind: &str, outcome: &str) -> bool {
        self.events()
            .iter()
            .any(|e| e.audit_kind == audit_kind && e.outcome == outcome)
    }

    pub fn count(&self, audit_kind: &str) -> usize {
        self.events()
            .iter()
            .filter(|e| e.audit_kind == audit_kind)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuditKind, security_audit_event};
    use platform_core::TenantId;

    #[test]
    fn captures_emitted_audit_events_with_fields() {
        let capture = AuditCapture::install();
        let tenant = TenantId::generate();
        security_audit_event(AuditKind::DataAccess, Some(tenant), "ok", "unit probe");
        security_audit_event(AuditKind::AuthDecision, None, "denied", "no token");

        let events = capture.events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].audit_kind, "data.access");
        assert_eq!(events[0].tenant_id, tenant.to_string());
        assert_eq!(events[0].outcome, "ok");
        assert_eq!(events[0].detail, "unit probe");
        assert!(capture.contains("auth.decision", "denied"));
        assert_eq!(capture.count("data.access"), 1);
    }

    #[test]
    fn ignores_non_audit_events() {
        let capture = AuditCapture::install();
        tracing::info!(target: "operational", "not an audit event");
        assert!(capture.events().is_empty());
    }
}
