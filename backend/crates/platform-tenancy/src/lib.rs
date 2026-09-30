//! Control-plane registries: tenants, dataset grants, query budgets, and the
//! research catalog.
//!
//! This is operational metadata, distinct from the ciphertext vault. Each
//! registry is a trait with an in-memory implementation; a durable backend
//! implements the same trait.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

use async_trait::async_trait;
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
pub use grants::{DatasetGrant, GrantRegistry, InMemoryGrantRegistry};

#[derive(Debug, thiserror::Error)]
pub enum TenancyError {
    #[error("tenant not found")]
    NotFound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TenantStatus {
    Active,
    Suspended,
}

/// One tenant's control-plane record.
#[derive(Debug, Clone, Serialize)]
pub struct TenantRecord {
    pub tenant_id: TenantId,
    pub status: TenantStatus,
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
    /// existing record and does not mint a new tenant.
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

    /// Set status by subscription id (cancellation/pause events).
    async fn set_status(
        &self,
        subscription_id: &str,
        status: TenantStatus,
    ) -> Result<Option<TenantRecord>, TenancyError>;

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
    ) -> Result<Option<TenantRecord>, TenancyError> {
        let mut inner = self.lock();
        let Some(tenant) = inner.by_subscription.get(subscription_id).copied() else {
            return Ok(None);
        };
        let record = inner.by_tenant.get_mut(&tenant).expect("indexed record");
        record.status = status;
        record.updated_at_iso = now_iso();
        Ok(Some(record.clone()))
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

    #[tokio::test]
    async fn suspend_by_subscription_and_toggle_connector() {
        let reg = registry();
        let rec = reg
            .provision("sub_2", "cus_2", "pro")
            .await
            .expect("provision");

        let suspended = reg
            .set_status("sub_2", TenantStatus::Suspended)
            .await
            .expect("set")
            .expect("record");
        assert_eq!(suspended.status, TenantStatus::Suspended);

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
            reg.set_status("nope", TenantStatus::Suspended)
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
