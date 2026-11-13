//! Control-plane registries: tenants, dataset grants, query budgets, and the
//! research catalog.
//!
//! This is operational metadata, distinct from the ciphertext vault. Each
//! registry is a trait with an in-memory implementation; a durable backend
//! implements the same trait.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use platform_core::TenantId;
use serde::Serialize;

pub mod budget;
pub mod catalog;
pub mod grants;
pub use budget::{BudgetError, BudgetLedger, BudgetState, InMemoryBudgetLedger};
pub use catalog::{
    AccessRequest, CatalogError, CatalogRegistry, DatasetListing, InMemoryCatalogRegistry,
    ListingDetails, RequestStatus,
};
pub use grants::{DatasetGrant, GrantOutcome, GrantRegistry, InMemoryGrantRegistry};

#[derive(Debug, thiserror::Error)]
pub enum TenancyError {
    #[error("tenant not found")]
    NotFound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TenantStatus {
    Active,
    /// Paused; a newer resume reactivates it.
    Suspended,
    /// Final: no billing event changes it.
    Canceled,
}

/// Result of [`TenantRegistry::set_status`]. Every variant carries the
/// record as it stands, so callers can audit without a second read.
#[derive(Debug, Clone)]
pub enum StatusOutcome {
    /// The change was applied.
    Applied(TenantRecord),
    /// Not applied: the event is not newer than the last applied change.
    Stale(TenantRecord),
    /// Not applied: the tenant is canceled.
    Canceled(TenantRecord),
}

/// One tenant's control-plane record.
#[derive(Debug, Clone, Serialize)]
pub struct TenantRecord {
    pub tenant_id: TenantId,
    pub status: TenantStatus,
    /// `occurred_at` of the billing event that last set `status`; older
    /// events arriving later are not applied, except a cancel.
    pub status_changed_at: Option<DateTime<Utc>>,
    /// Merchant-of-Record subscription id (Paddle) — the idempotency key.
    pub subscription_id: String,
    pub customer_id: String,
    pub plan: String,
    /// Connector slug → enabled. Toggled from the admin console.
    pub connectors: HashMap<String, bool>,
    pub created_at_iso: String,
    pub updated_at_iso: String,
}

pub(crate) fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// Random opaque id for registry records.
pub(crate) fn new_id() -> String {
    TenantId::generate().to_string()
}

#[async_trait]
pub trait TenantRegistry: Send + Sync {
    /// Provision a tenant for a subscription. Idempotent on
    /// `subscription_id`: a repeated call (webhook retry) returns the
    /// existing record unchanged, never reactivating it, and does not mint
    /// a new tenant.
    async fn provision(
        &self,
        subscription_id: &str,
        customer_id: &str,
        plan: &str,
    ) -> Result<TenantRecord, TenancyError>;

    async fn get(&self, tenant: TenantId) -> Result<Option<TenantRecord>, TenancyError>;
    async fn get_by_subscription(
        &self,
        subscription_id: &str,
    ) -> Result<Option<TenantRecord>, TenancyError>;
    async fn list(&self) -> Result<Vec<TenantRecord>, TenancyError>;

    /// Set status by subscription id (cancel, pause and resume events).
    /// Nothing changes a `Canceled` tenant. `Canceled` applies whatever its
    /// `occurred_at`; otherwise only an event that occurred after the last
    /// applied change applies, and on a tie only `Suspended`. `None` for an
    /// unknown subscription.
    async fn set_status(
        &self,
        subscription_id: &str,
        status: TenantStatus,
        occurred_at: DateTime<Utc>,
    ) -> Result<Option<StatusOutcome>, TenancyError>;

    /// Toggle a connector for a tenant (admin console).
    async fn set_connector(
        &self,
        tenant: TenantId,
        connector: &str,
        enabled: bool,
    ) -> Result<TenantRecord, TenancyError>;
}

#[derive(Default)]
struct Inner {
    by_tenant: HashMap<TenantId, TenantRecord>,
    by_subscription: HashMap<String, TenantId>,
}

/// In-memory registry; not durable across restarts.
#[derive(Default)]
pub struct InMemoryTenantRegistry {
    inner: Mutex<Inner>,
    /// Connector slugs seeded (disabled) at provisioning time.
    default_connectors: Vec<String>,
}

impl InMemoryTenantRegistry {
    pub fn new(default_connectors: Vec<String>) -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            default_connectors,
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().expect("tenant registry lock")
    }
}

#[async_trait]
impl TenantRegistry for InMemoryTenantRegistry {
    async fn provision(
        &self,
        subscription_id: &str,
        customer_id: &str,
        plan: &str,
    ) -> Result<TenantRecord, TenancyError> {
        let mut inner = self.lock();
        if let Some(tenant) = inner.by_subscription.get(subscription_id).copied() {
            return Ok(inner.by_tenant[&tenant].clone());
        }

        let tenant_id = TenantId::generate();
        let now = now_iso();
        let connectors = self
            .default_connectors
            .iter()
            .map(|slug| (slug.clone(), false))
            .collect();
        let record = TenantRecord {
            tenant_id,
            status: TenantStatus::Active,
            status_changed_at: None,
            subscription_id: subscription_id.to_owned(),
            customer_id: customer_id.to_owned(),
            plan: plan.to_owned(),
            connectors,
            created_at_iso: now.clone(),
            updated_at_iso: now,
        };
        inner
            .by_subscription
            .insert(subscription_id.to_owned(), tenant_id);
        inner.by_tenant.insert(tenant_id, record.clone());
        Ok(record)
    }

    async fn get(&self, tenant: TenantId) -> Result<Option<TenantRecord>, TenancyError> {
        Ok(self.lock().by_tenant.get(&tenant).cloned())
    }

    async fn get_by_subscription(
        &self,
        subscription_id: &str,
    ) -> Result<Option<TenantRecord>, TenancyError> {
        let inner = self.lock();
        Ok(inner
            .by_subscription
            .get(subscription_id)
            .and_then(|t| inner.by_tenant.get(t))
            .cloned())
    }

    async fn list(&self) -> Result<Vec<TenantRecord>, TenancyError> {
        let mut records: Vec<_> = self.lock().by_tenant.values().cloned().collect();
        records.sort_by(|a, b| a.created_at_iso.cmp(&b.created_at_iso));
        Ok(records)
    }

    async fn set_status(
        &self,
        subscription_id: &str,
        status: TenantStatus,
        occurred_at: DateTime<Utc>,
    ) -> Result<Option<StatusOutcome>, TenancyError> {
        let mut inner = self.lock();
        let Some(tenant) = inner.by_subscription.get(subscription_id).copied() else {
            return Ok(None);
        };
        let record = inner.by_tenant.get_mut(&tenant).expect("indexed record");
        if record.status == TenantStatus::Canceled {
            return Ok(Some(StatusOutcome::Canceled(record.clone())));
        }
        let stale = status != TenantStatus::Canceled
            && record.status_changed_at.is_some_and(|last| {
                occurred_at < last || (occurred_at == last && status == TenantStatus::Active)
            });
        if stale {
            return Ok(Some(StatusOutcome::Stale(record.clone())));
        }
        record.status = status;
        record.status_changed_at = Some(occurred_at);
        record.updated_at_iso = now_iso();
        Ok(Some(StatusOutcome::Applied(record.clone())))
    }

    async fn set_connector(
        &self,
        tenant: TenantId,
        connector: &str,
        enabled: bool,
    ) -> Result<TenantRecord, TenancyError> {
        let mut inner = self.lock();
        let record = inner
            .by_tenant
            .get_mut(&tenant)
            .ok_or(TenancyError::NotFound)?;
        record.connectors.insert(connector.to_owned(), enabled);
        record.updated_at_iso = now_iso();
        Ok(record.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn registry() -> InMemoryTenantRegistry {
        InMemoryTenantRegistry::new(vec!["quickbooks".into(), "odoo".into()])
    }

    #[tokio::test]
    async fn provision_seeds_disabled_connectors_and_is_idempotent() {
        let reg = registry();
        let first = reg
            .provision("sub_1", "cus_1", "pro")
            .await
            .expect("provision");
        assert_eq!(first.status, TenantStatus::Active);
        assert_eq!(first.connectors.get("quickbooks"), Some(&false));
        assert_eq!(first.connectors.len(), 2);

        let again = reg
            .provision("sub_1", "cus_1", "pro")
            .await
            .expect("provision");
        assert_eq!(again.tenant_id, first.tenant_id);
        assert_eq!(reg.list().await.expect("list").len(), 1);
    }

    fn at(day: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, day, 0, 0, 0).unwrap()
    }

    /// What `set_status` did, and the status it left.
    fn outcome(result: Option<StatusOutcome>) -> (&'static str, TenantStatus) {
        match result.expect("record") {
            StatusOutcome::Applied(r) => ("applied", r.status),
            StatusOutcome::Stale(r) => ("stale", r.status),
            StatusOutcome::Canceled(r) => ("canceled", r.status),
        }
    }

    #[tokio::test]
    async fn set_status_applies_only_events_newer_than_the_last_change() {
        use TenantStatus::{Active, Suspended};
        let reg = registry();
        reg.provision("sub_3", "cus_3", "pro")
            .await
            .expect("provision");
        let set = |s, day| reg.set_status("sub_3", s, at(day));

        assert_eq!(
            outcome(set(Suspended, 2).await.unwrap()),
            ("applied", Suspended)
        );
        // Older, and a tie, cannot resume; a tie may still suspend. A skip
        // asking for the current status is still stale.
        assert_eq!(outcome(set(Active, 1).await.unwrap()), ("stale", Suspended));
        assert_eq!(outcome(set(Active, 2).await.unwrap()), ("stale", Suspended));
        assert_eq!(
            outcome(set(Suspended, 1).await.unwrap()),
            ("stale", Suspended)
        );
        assert_eq!(outcome(set(Active, 3).await.unwrap()), ("applied", Active));
        assert_eq!(outcome(set(Suspended, 2).await.unwrap()), ("stale", Active));
        assert_eq!(
            outcome(set(Suspended, 3).await.unwrap()),
            ("applied", Suspended)
        );

        let again = reg
            .provision("sub_3", "cus_3", "pro")
            .await
            .expect("provision");
        assert_eq!(again.status, Suspended, "provision never reactivates");
        assert_eq!(again.status_changed_at, Some(at(3)));
    }

    #[tokio::test]
    async fn cancel_applies_late_and_nothing_changes_it_after() {
        use TenantStatus::{Active, Canceled, Suspended};
        let reg = registry();
        reg.provision("sub_4", "cus_4", "pro")
            .await
            .expect("provision");
        let set = |s, day| reg.set_status("sub_4", s, at(day));

        assert_eq!(outcome(set(Active, 3).await.unwrap()), ("applied", Active));
        assert_eq!(
            outcome(set(Canceled, 2).await.unwrap()),
            ("applied", Canceled)
        );
        for status in [Active, Suspended, Canceled] {
            assert_eq!(
                outcome(set(status, 4).await.unwrap()),
                ("canceled", Canceled)
            );
        }
    }

    #[tokio::test]
    async fn suspend_by_subscription_and_toggle_connector() {
        let reg = registry();
        let rec = reg
            .provision("sub_2", "cus_2", "pro")
            .await
            .expect("provision");

        let suspended = reg
            .set_status("sub_2", TenantStatus::Suspended, at(1))
            .await
            .expect("set");
        assert_eq!(outcome(suspended), ("applied", TenantStatus::Suspended));

        let toggled = reg
            .set_connector(rec.tenant_id, "quickbooks", true)
            .await
            .expect("toggle");
        assert_eq!(toggled.connectors.get("quickbooks"), Some(&true));
    }

    #[tokio::test]
    async fn set_status_on_unknown_subscription_is_none() {
        let reg = registry();
        assert!(
            reg.set_status("nope", TenantStatus::Suspended, at(1))
                .await
                .expect("ok")
                .is_none()
        );
    }

    #[tokio::test]
    async fn toggle_connector_on_unknown_tenant_errors() {
        let reg = registry();
        let err = reg
            .set_connector(TenantId::generate(), "quickbooks", true)
            .await
            .expect_err("must error");
        assert!(matches!(err, TenancyError::NotFound));
    }
}
