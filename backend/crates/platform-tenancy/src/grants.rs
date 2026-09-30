//! Dataset grants: research-access authorization.
//!
//! The **steward** owns (and seals) a dataset; a **researcher** is another
//! tenant allowed to run aggregate queries over it, never to read rows. A
//! [`DatasetGrant`] is the steward's revocable authorization of one
//! researcher for one dataset (steward × connector). Research queries
//! without an active grant are refused.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

use async_trait::async_trait;
use platform_core::TenantId;
use serde::Serialize;

use crate::{TenancyError, new_id, now_iso};

#[derive(Debug, Clone, Serialize)]
pub struct DatasetGrant {
    pub grant_id: String,
    /// Data owner: the tenant whose key seals the dataset.
    pub steward_tenant: TenantId,
    /// The tenant allowed to run disclosure-controlled aggregate queries.
    pub researcher_tenant: TenantId,
    /// Dataset selector: the connector slug under the steward's prefix.
    pub connector: String,
    pub revoked: bool,
    pub created_at_iso: String,
    pub updated_at_iso: String,
}

#[async_trait]
pub trait GrantRegistry: Send + Sync {
    /// Create (or re-activate) a grant. Idempotent per
    /// (steward, researcher, connector): repeating returns the existing
    /// grant, un-revoking it if needed.
    async fn create(
        &self,
        steward: TenantId,
        researcher: TenantId,
        connector: &str,
    ) -> Result<DatasetGrant, TenancyError>;

    /// Active grant lookup used on every research query.
    async fn find_active(
        &self,
        researcher: TenantId,
        steward: TenantId,
        connector: &str,
    ) -> Result<Option<DatasetGrant>, TenancyError>;

    /// Revoke by id; only the grant's steward may revoke.
    async fn revoke(
        &self,
        steward: TenantId,
        grant_id: &str,
    ) -> Result<Option<DatasetGrant>, TenancyError>;

    /// Every grant where the tenant is steward or researcher (console view).
    async fn list_for(&self, tenant: TenantId) -> Result<Vec<DatasetGrant>, TenancyError>;
}

/// In-memory registry; not durable across restarts.
#[derive(Default)]
pub struct InMemoryGrantRegistry {
    by_id: Mutex<HashMap<String, DatasetGrant>>,
}

impl InMemoryGrantRegistry {
    fn lock(&self) -> MutexGuard<'_, HashMap<String, DatasetGrant>> {
        self.by_id.lock().expect("grant lock")
    }
}

impl DatasetGrant {
    fn covers(&self, steward: TenantId, researcher: TenantId, connector: &str) -> bool {
        self.steward_tenant == steward
            && self.researcher_tenant == researcher
            && self.connector == connector
    }
}

#[async_trait]
impl GrantRegistry for InMemoryGrantRegistry {
    async fn create(
        &self,
        steward: TenantId,
        researcher: TenantId,
        connector: &str,
    ) -> Result<DatasetGrant, TenancyError> {
        let mut grants = self.lock();
        if let Some(existing) = grants
            .values_mut()
            .find(|g| g.covers(steward, researcher, connector))
        {
            if existing.revoked {
                existing.revoked = false;
                existing.updated_at_iso = now_iso();
            }
            return Ok(existing.clone());
        }
        let now = now_iso();
        let grant = DatasetGrant {
            grant_id: new_id(),
            steward_tenant: steward,
            researcher_tenant: researcher,
            connector: connector.to_owned(),
            revoked: false,
            created_at_iso: now.clone(),
            updated_at_iso: now,
        };
        grants.insert(grant.grant_id.clone(), grant.clone());
        Ok(grant)
    }

    async fn find_active(
        &self,
        researcher: TenantId,
        steward: TenantId,
        connector: &str,
    ) -> Result<Option<DatasetGrant>, TenancyError> {
        Ok(self
            .lock()
            .values()
            .find(|g| !g.revoked && g.covers(steward, researcher, connector))
            .cloned())
    }

    async fn revoke(
        &self,
        steward: TenantId,
        grant_id: &str,
    ) -> Result<Option<DatasetGrant>, TenancyError> {
        match self.lock().get_mut(grant_id) {
            Some(grant) if grant.steward_tenant == steward => {
                grant.revoked = true;
                grant.updated_at_iso = now_iso();
                Ok(Some(grant.clone()))
            }
            // Unknown and someone else's grant are indistinguishable: no
            // cross-tenant existence oracle.
            _ => Ok(None),
        }
    }

    async fn list_for(&self, tenant: TenantId) -> Result<Vec<DatasetGrant>, TenancyError> {
        let mut out: Vec<_> = self
            .lock()
            .values()
            .filter(|g| g.steward_tenant == tenant || g.researcher_tenant == tenant)
            .cloned()
            .collect();
        out.sort_by(|a, b| a.created_at_iso.cmp(&b.created_at_iso));
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn create_find_revoke_lifecycle() {
        let registry = InMemoryGrantRegistry::default();
        let steward = TenantId::generate();
        let researcher = TenantId::generate();

        let grant = registry
            .create(steward, researcher, "quickbooks")
            .await
            .expect("create");
        assert!(!grant.revoked);

        let found = registry
            .find_active(researcher, steward, "quickbooks")
            .await
            .expect("find")
            .expect("active grant");
        assert_eq!(found.grant_id, grant.grant_id);

        // Direction matters: the steward is not thereby a researcher.
        assert!(
            registry
                .find_active(steward, researcher, "quickbooks")
                .await
                .expect("find")
                .is_none()
        );
        // Other connectors are not covered.
        assert!(
            registry
                .find_active(researcher, steward, "odoo")
                .await
                .expect("find")
                .is_none()
        );

        let revoked = registry
            .revoke(steward, &grant.grant_id)
            .await
            .expect("revoke")
            .expect("was mine");
        assert!(revoked.revoked);
        assert!(
            registry
                .find_active(researcher, steward, "quickbooks")
                .await
                .expect("find")
                .is_none()
        );
    }

    #[tokio::test]
    async fn create_is_idempotent_and_reactivates() {
        let registry = InMemoryGrantRegistry::default();
        let steward = TenantId::generate();
        let researcher = TenantId::generate();

        let first = registry
            .create(steward, researcher, "quickbooks")
            .await
            .expect("create");
        registry
            .revoke(steward, &first.grant_id)
            .await
            .expect("revoke");
        let again = registry
            .create(steward, researcher, "quickbooks")
            .await
            .expect("create again");
        assert_eq!(
            again.grant_id, first.grant_id,
            "same identity, re-activated"
        );
        assert!(!again.revoked);
    }

    #[tokio::test]
    async fn only_the_steward_can_revoke() {
        let registry = InMemoryGrantRegistry::default();
        let steward = TenantId::generate();
        let researcher = TenantId::generate();
        let grant = registry
            .create(steward, researcher, "quickbooks")
            .await
            .expect("create");

        // The researcher (or anyone else) cannot revoke — and learns nothing.
        assert!(
            registry
                .revoke(researcher, &grant.grant_id)
                .await
                .expect("ok")
                .is_none()
        );
        assert!(
            registry
                .find_active(researcher, steward, "quickbooks")
                .await
                .expect("find")
                .is_some(),
            "grant must still be active"
        );
    }

    #[tokio::test]
    async fn list_shows_both_directions() {
        let registry = InMemoryGrantRegistry::default();
        let steward = TenantId::generate();
        let researcher = TenantId::generate();
        registry
            .create(steward, researcher, "quickbooks")
            .await
            .expect("create");

        assert_eq!(registry.list_for(steward).await.expect("list").len(), 1);
        assert_eq!(registry.list_for(researcher).await.expect("list").len(), 1);
        assert!(
            registry
                .list_for(TenantId::generate())
                .await
                .expect("list")
                .is_empty()
        );
    }
}
