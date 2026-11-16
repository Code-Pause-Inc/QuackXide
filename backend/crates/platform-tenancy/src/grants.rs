//! Dataset grants: research-access authorization.
//!
//! The **steward** owns (and seals) a dataset; a **researcher** is another
//! tenant allowed to run aggregate queries over it, never to read rows. A
//! [`DatasetGrant`] is the steward's revocable authorization of one
//! researcher for one dataset (steward × dataset slug, a connector's or an
//! upload's). Research queries without an active grant are refused.

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
    /// Dataset selector: the dataset's slug under the steward's prefix, a
    /// connector's or an upload's (`upload_…`, ADR 0012).
    pub connector: String,
    pub revoked: bool,
    /// When the grant was last revoked. Kept on re-activation, so an
    /// approval retry can tell a revoke that came after its approval.
    pub revoked_at_iso: Option<String>,
    pub created_at_iso: String,
    pub updated_at_iso: String,
}

/// Result of [`GrantRegistry::create_unless_revoked`]. Both variants carry
/// the grant, so callers can audit its id without a second read.
#[derive(Debug, Clone)]
pub enum GrantOutcome {
    /// A new grant, or the existing active one.
    Active(DatasetGrant),
    /// The existing grant, which the steward revoked. It stays revoked.
    Revoked(DatasetGrant),
}

#[async_trait]
pub trait GrantRegistry: Send + Sync {
    /// Create (or re-activate) a grant. Idempotent per
    /// (steward, researcher, connector): repeating returns the existing
    /// grant, un-revoking it if needed. Call it only for a new decision by
    /// the steward (a direct grant or a first approval); an approval retry
    /// uses [`create_unless_revoked`].
    ///
    /// [`create_unless_revoked`]: GrantRegistry::create_unless_revoked
    async fn create(
        &self,
        steward: TenantId,
        researcher: TenantId,
        connector: &str,
    ) -> Result<DatasetGrant, TenancyError>;

    /// Create a grant unless this (steward, researcher, connector) already
    /// has a revoked one. Returns [`GrantOutcome::Active`] with a new grant
    /// or the existing active one, and [`GrantOutcome::Revoked`] with the
    /// existing revoked one. Never clears `revoked`, and never adds a second
    /// grant beside a revoked one.
    ///
    /// The check and the insert are one atomic step, so a concurrent revoke
    /// is never undone: it lands either before the check (the result is
    /// `Revoked`) or after the insert (the grant ends up revoked). A durable
    /// backend needs a conditional insert or a transaction.
    async fn create_unless_revoked(
        &self,
        steward: TenantId,
        researcher: TenantId,
        connector: &str,
    ) -> Result<GrantOutcome, TenancyError>;

    /// Active grant lookup used on every research query.
    async fn find_active(
        &self,
        researcher: TenantId,
        steward: TenantId,
        connector: &str,
    ) -> Result<Option<DatasetGrant>, TenancyError>;

    /// Revoke by id; only the grant's steward may revoke. Sets
    /// `revoked_at_iso`, which `create` keeps on re-activation. A durable
    /// backend must persist it: approval retries refuse based on it, and a
    /// lost value lets a stale retry add budget to a newer grant.
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
    /// A new, active grant with a fresh id.
    fn new(steward: TenantId, researcher: TenantId, connector: &str) -> Self {
        let now = now_iso();
        Self {
            grant_id: new_id(),
            steward_tenant: steward,
            researcher_tenant: researcher,
            connector: connector.to_owned(),
            revoked: false,
            revoked_at_iso: None,
            created_at_iso: now.clone(),
            updated_at_iso: now,
        }
    }

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
        let grant = DatasetGrant::new(steward, researcher, connector);
        grants.insert(grant.grant_id.clone(), grant.clone());
        Ok(grant)
    }

    async fn create_unless_revoked(
        &self,
        steward: TenantId,
        researcher: TenantId,
        connector: &str,
    ) -> Result<GrantOutcome, TenancyError> {
        // One lock covers the check and the insert, so no revoke can land
        // between them. Revoked grants match too: a fresh grant beside a
        // revoked one would undo the revoke just as clearing it would.
        let mut grants = self.lock();
        if let Some(existing) = grants
            .values()
            .find(|g| g.covers(steward, researcher, connector))
        {
            let existing = existing.clone();
            return Ok(if existing.revoked {
                GrantOutcome::Revoked(existing)
            } else {
                GrantOutcome::Active(existing)
            });
        }
        let grant = DatasetGrant::new(steward, researcher, connector);
        grants.insert(grant.grant_id.clone(), grant.clone());
        Ok(GrantOutcome::Active(grant))
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
                let now = now_iso();
                grant.revoked = true;
                grant.revoked_at_iso = Some(now.clone());
                grant.updated_at_iso = now;
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
    async fn revoke_time_survives_reactivation() {
        let registry = InMemoryGrantRegistry::default();
        let steward = TenantId::generate();
        let researcher = TenantId::generate();
        let grant = registry
            .create(steward, researcher, "health")
            .await
            .unwrap();
        assert_eq!(grant.revoked_at_iso, None);

        let revoked = registry
            .revoke(steward, &grant.grant_id)
            .await
            .unwrap()
            .unwrap();
        let revoked_at = revoked.revoked_at_iso.expect("revoke records its time");
        let again = registry
            .create(steward, researcher, "health")
            .await
            .unwrap();
        assert!(!again.revoked);
        assert_eq!(again.revoked_at_iso.as_deref(), Some(revoked_at.as_str()));
    }

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

    #[tokio::test]
    async fn create_unless_revoked_creates_then_is_idempotent() {
        let registry = InMemoryGrantRegistry::default();
        let steward = TenantId::generate();
        let researcher = TenantId::generate();

        // No grant yet: one is created, and it is active.
        let GrantOutcome::Active(first) = registry
            .create_unless_revoked(steward, researcher, "quickbooks")
            .await
            .expect("create")
        else {
            panic!("no grant existed, so none can be revoked");
        };
        assert!(!first.revoked);
        let found = registry
            .find_active(researcher, steward, "quickbooks")
            .await
            .expect("find")
            .expect("active grant");
        assert_eq!(found.grant_id, first.grant_id);

        // An active grant: the same one comes back, and nothing is added.
        let GrantOutcome::Active(again) = registry
            .create_unless_revoked(steward, researcher, "quickbooks")
            .await
            .expect("create again")
        else {
            panic!("an active grant was reported revoked");
        };
        assert_eq!(again.grant_id, first.grant_id);
        assert_eq!(registry.list_for(steward).await.expect("list").len(), 1);
    }

    #[tokio::test]
    async fn reactivation_by_create_unless_revoked_is_refused() {
        let registry = InMemoryGrantRegistry::default();
        let steward = TenantId::generate();
        let researcher = TenantId::generate();
        let grant = registry
            .create(steward, researcher, "quickbooks")
            .await
            .expect("create");
        registry
            .revoke(steward, &grant.grant_id)
            .await
            .expect("revoke")
            .expect("was mine");

        // Refused: the revoked grant comes back and stays revoked.
        let GrantOutcome::Revoked(revoked) = registry
            .create_unless_revoked(steward, researcher, "quickbooks")
            .await
            .expect("create unless revoked")
        else {
            panic!("a revoked grant was re-activated");
        };
        assert_eq!(revoked.grant_id, grant.grant_id);
        assert!(revoked.revoked);
        assert!(
            registry
                .find_active(researcher, steward, "quickbooks")
                .await
                .expect("find")
                .is_none()
        );
        // No fresh grant beside it either.
        assert_eq!(registry.list_for(steward).await.expect("list").len(), 1);

        // An explicit re-grant still re-activates the same grant.
        let regranted = registry
            .create(steward, researcher, "quickbooks")
            .await
            .expect("re-grant");
        assert_eq!(regranted.grant_id, grant.grant_id);
        assert!(!regranted.revoked);
    }
}
