//! Dataset catalog and access requests.
//!
//! A steward publishes a listing for one of its sealed connector datasets;
//! researchers browse published listings and request access; the steward
//! approves (minting a grant and budget) or denies. Publishing is an explicit
//! opt-in to discoverability: unpublished datasets are indistinguishable
//! from nonexistent ones.
//!
//! Prices are integer cents; the display currency is configuration.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

use async_trait::async_trait;
use platform_core::TenantId;
use serde::Serialize;

use crate::{TenancyError, new_id, now_iso};

/// Steward-authored, deliberately public listing metadata.
#[derive(Debug, Clone, Serialize)]
pub struct DatasetListing {
    pub listing_id: String,
    pub steward_tenant: TenantId,
    /// Dataset selector: the connector slug under the steward's prefix.
    pub connector: String,
    pub title: String,
    pub description: String,
    /// One-time access (license) fee for an approved grant, in cents.
    pub license_fee_cents: u64,
    /// Compute rate per query-budget unit, in cents.
    pub compute_rate_cents: u64,
    /// Query-budget units included when a request is approved.
    pub grant_budget: u64,
    pub published: bool,
    pub created_at_iso: String,
    pub updated_at_iso: String,
}

/// The steward-settable fields of a listing (everything but identity).
#[derive(Debug, Clone)]
pub struct ListingDetails {
    pub title: String,
    pub description: String,
    pub license_fee_cents: u64,
    pub compute_rate_cents: u64,
    pub grant_budget: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestStatus {
    Pending,
    Approved,
    Denied,
}

/// A researcher's request for access to a published listing.
#[derive(Debug, Clone, Serialize)]
pub struct AccessRequest {
    pub request_id: String,
    pub listing_id: String,
    pub steward_tenant: TenantId,
    pub researcher_tenant: TenantId,
    pub connector: String,
    /// Researcher-stated purpose (bounded at the API edge; may be empty).
    pub note: String,
    pub status: RequestStatus,
    pub created_at_iso: String,
    pub updated_at_iso: String,
}

#[derive(Debug, thiserror::Error)]
pub enum CatalogError {
    /// Unknown or unpublished listing — indistinguishable by design.
    #[error("listing not found")]
    NotFound,
    /// A steward cannot request access to its own dataset.
    #[error("cannot request access to your own dataset")]
    SelfRequest,
}

#[async_trait]
pub trait CatalogRegistry: Send + Sync {
    /// Publish (or re-publish) a listing. Upsert per (steward, connector):
    /// the listing id is stable, details are replaced, `published` is set.
    async fn publish(
        &self,
        steward: TenantId,
        connector: &str,
        details: ListingDetails,
    ) -> Result<DatasetListing, TenancyError>;

    /// Withdraw a listing. Steward-only; unknown ids and other stewards'
    /// listings are indistinguishable (`None`). Existing grants are untouched.
    async fn unpublish(
        &self,
        steward: TenantId,
        listing_id: &str,
    ) -> Result<Option<DatasetListing>, TenancyError>;

    /// Every published listing (the researcher-browsable catalog).
    async fn list_published(&self) -> Result<Vec<DatasetListing>, TenancyError>;

    /// Lookup regardless of published state (steward/approval flows).
    async fn get_listing(&self, listing_id: &str) -> Result<Option<DatasetListing>, TenancyError>;

    /// File an access request against a published listing. An existing
    /// Pending request from the same researcher is returned unchanged;
    /// resolved history never blocks a fresh request.
    async fn request_access(
        &self,
        listing_id: &str,
        researcher: TenantId,
        note: &str,
    ) -> Result<AccessRequest, CatalogError>;

    /// Every request where the tenant is researcher or steward.
    async fn list_requests_for(&self, tenant: TenantId)
    -> Result<Vec<AccessRequest>, TenancyError>;

    /// Resolve a Pending request (approve or deny). Only the listing's
    /// steward may; unknown ids, other stewards' requests, and
    /// already-resolved requests are indistinguishable (`None`).
    async fn resolve(
        &self,
        steward: TenantId,
        request_id: &str,
        approve: bool,
    ) -> Result<Option<AccessRequest>, TenancyError>;
}

/// In-memory registry; not durable across restarts.
#[derive(Default)]
pub struct InMemoryCatalogRegistry {
    inner: Mutex<Inner>,
}

impl InMemoryCatalogRegistry {
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().expect("catalog lock")
    }
}

#[derive(Default)]
struct Inner {
    listings: HashMap<String, DatasetListing>,
    requests: HashMap<String, AccessRequest>,
}

#[async_trait]
impl CatalogRegistry for InMemoryCatalogRegistry {
    async fn publish(
        &self,
        steward: TenantId,
        connector: &str,
        details: ListingDetails,
    ) -> Result<DatasetListing, TenancyError> {
        let mut inner = self.lock();
        let now = now_iso();
        if let Some(existing) = inner
            .listings
            .values_mut()
            .find(|l| l.steward_tenant == steward && l.connector == connector)
        {
            existing.title = details.title;
            existing.description = details.description;
            existing.license_fee_cents = details.license_fee_cents;
            existing.compute_rate_cents = details.compute_rate_cents;
            existing.grant_budget = details.grant_budget;
            existing.published = true;
            existing.updated_at_iso = now;
            return Ok(existing.clone());
        }
        let listing = DatasetListing {
            listing_id: new_id(),
            steward_tenant: steward,
            connector: connector.to_owned(),
            title: details.title,
            description: details.description,
            license_fee_cents: details.license_fee_cents,
            compute_rate_cents: details.compute_rate_cents,
            grant_budget: details.grant_budget,
            published: true,
            created_at_iso: now.clone(),
            updated_at_iso: now,
        };
        inner
            .listings
            .insert(listing.listing_id.clone(), listing.clone());
        Ok(listing)
    }

    async fn unpublish(
        &self,
        steward: TenantId,
        listing_id: &str,
    ) -> Result<Option<DatasetListing>, TenancyError> {
        match self.lock().listings.get_mut(listing_id) {
            Some(listing) if listing.steward_tenant == steward => {
                listing.published = false;
                listing.updated_at_iso = now_iso();
                Ok(Some(listing.clone()))
            }
            _ => Ok(None),
        }
    }

    async fn list_published(&self) -> Result<Vec<DatasetListing>, TenancyError> {
        let mut out: Vec<_> = self
            .lock()
            .listings
            .values()
            .filter(|l| l.published)
            .cloned()
            .collect();
        out.sort_by(|a, b| a.created_at_iso.cmp(&b.created_at_iso));
        Ok(out)
    }

    async fn get_listing(&self, listing_id: &str) -> Result<Option<DatasetListing>, TenancyError> {
        Ok(self.lock().listings.get(listing_id).cloned())
    }

    async fn request_access(
        &self,
        listing_id: &str,
        researcher: TenantId,
        note: &str,
    ) -> Result<AccessRequest, CatalogError> {
        let mut inner = self.lock();
        let (steward, connector) = match inner.listings.get(listing_id) {
            Some(l) if l.published => (l.steward_tenant, l.connector.clone()),
            // Unknown and unpublished are the same from outside.
            _ => return Err(CatalogError::NotFound),
        };
        if steward == researcher {
            return Err(CatalogError::SelfRequest);
        }
        if let Some(pending) = inner.requests.values().find(|r| {
            r.listing_id == listing_id
                && r.researcher_tenant == researcher
                && r.status == RequestStatus::Pending
        }) {
            return Ok(pending.clone());
        }
        let now = now_iso();
        let request = AccessRequest {
            request_id: new_id(),
            listing_id: listing_id.to_owned(),
            steward_tenant: steward,
            researcher_tenant: researcher,
            connector,
            note: note.to_owned(),
            status: RequestStatus::Pending,
            created_at_iso: now.clone(),
            updated_at_iso: now,
        };
        inner
            .requests
            .insert(request.request_id.clone(), request.clone());
        Ok(request)
    }

    async fn list_requests_for(
        &self,
        tenant: TenantId,
    ) -> Result<Vec<AccessRequest>, TenancyError> {
        let mut out: Vec<_> = self
            .lock()
            .requests
            .values()
            .filter(|r| r.steward_tenant == tenant || r.researcher_tenant == tenant)
            .cloned()
            .collect();
        out.sort_by(|a, b| a.created_at_iso.cmp(&b.created_at_iso));
        Ok(out)
    }

    async fn resolve(
        &self,
        steward: TenantId,
        request_id: &str,
        approve: bool,
    ) -> Result<Option<AccessRequest>, TenancyError> {
        match self.lock().requests.get_mut(request_id) {
            Some(request)
                if request.steward_tenant == steward
                    && request.status == RequestStatus::Pending =>
            {
                request.status = if approve {
                    RequestStatus::Approved
                } else {
                    RequestStatus::Denied
                };
                request.updated_at_iso = now_iso();
                Ok(Some(request.clone()))
            }
            _ => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn details(title: &str) -> ListingDetails {
        ListingDetails {
            title: title.to_owned(),
            description: "de-identified cohort extracts".to_owned(),
            license_fee_cents: 120_000,
            compute_rate_cents: 40,
            grant_budget: 25,
        }
    }

    #[tokio::test]
    async fn publish_is_upsert_per_steward_connector() {
        let registry = InMemoryCatalogRegistry::default();
        let steward = TenantId::generate();

        let first = registry
            .publish(steward, "health", details("Cohorts v1"))
            .await
            .expect("publish");
        let second = registry
            .publish(steward, "health", details("Cohorts v2"))
            .await
            .expect("republish");
        assert_eq!(second.listing_id, first.listing_id, "stable identity");
        assert_eq!(second.title, "Cohorts v2");
        assert_eq!(registry.list_published().await.expect("list").len(), 1);

        // A different steward's listing for the same connector is distinct.
        let other = TenantId::generate();
        registry
            .publish(other, "health", details("Other cohorts"))
            .await
            .expect("publish other");
        assert_eq!(registry.list_published().await.expect("list").len(), 2);
    }

    #[tokio::test]
    async fn unpublish_hides_from_catalog_and_blocks_requests() {
        let registry = InMemoryCatalogRegistry::default();
        let steward = TenantId::generate();
        let researcher = TenantId::generate();
        let listing = registry
            .publish(steward, "health", details("Cohorts"))
            .await
            .expect("publish");

        // Only the steward can unpublish; others learn nothing.
        assert!(
            registry
                .unpublish(researcher, &listing.listing_id)
                .await
                .expect("ok")
                .is_none()
        );
        registry
            .unpublish(steward, &listing.listing_id)
            .await
            .expect("ok")
            .expect("mine");
        assert!(registry.list_published().await.expect("list").is_empty());
        assert!(matches!(
            registry
                .request_access(&listing.listing_id, researcher, "")
                .await,
            Err(CatalogError::NotFound)
        ));
    }

    #[tokio::test]
    async fn request_lifecycle_pending_idempotent_and_resolution() {
        let registry = InMemoryCatalogRegistry::default();
        let steward = TenantId::generate();
        let researcher = TenantId::generate();
        let listing = registry
            .publish(steward, "health", details("Cohorts"))
            .await
            .expect("publish");

        let request = registry
            .request_access(&listing.listing_id, researcher, "IRB study 44-A")
            .await
            .expect("request");
        assert_eq!(request.status, RequestStatus::Pending);

        // Repeat while pending → same request, no duplicates.
        let again = registry
            .request_access(&listing.listing_id, researcher, "different note")
            .await
            .expect("request again");
        assert_eq!(again.request_id, request.request_id);
        assert_eq!(again.note, "IRB study 44-A", "original note kept");

        // Only the steward can resolve; researcher learns nothing.
        assert!(
            registry
                .resolve(researcher, &request.request_id, true)
                .await
                .expect("ok")
                .is_none()
        );
        let approved = registry
            .resolve(steward, &request.request_id, true)
            .await
            .expect("ok")
            .expect("mine");
        assert_eq!(approved.status, RequestStatus::Approved);

        // Already resolved → not actionable again.
        assert!(
            registry
                .resolve(steward, &request.request_id, false)
                .await
                .expect("ok")
                .is_none()
        );

        // Resolved history doesn't block a fresh request.
        let fresh = registry
            .request_access(&listing.listing_id, researcher, "follow-up")
            .await
            .expect("re-request");
        assert_ne!(fresh.request_id, request.request_id);
        assert_eq!(fresh.status, RequestStatus::Pending);
    }

    #[tokio::test]
    async fn self_request_is_refused() {
        let registry = InMemoryCatalogRegistry::default();
        let steward = TenantId::generate();
        let listing = registry
            .publish(steward, "health", details("Cohorts"))
            .await
            .expect("publish");
        assert!(matches!(
            registry
                .request_access(&listing.listing_id, steward, "")
                .await,
            Err(CatalogError::SelfRequest)
        ));
    }

    #[tokio::test]
    async fn requests_visible_to_both_parties_only() {
        let registry = InMemoryCatalogRegistry::default();
        let steward = TenantId::generate();
        let researcher = TenantId::generate();
        let listing = registry
            .publish(steward, "health", details("Cohorts"))
            .await
            .expect("publish");
        registry
            .request_access(&listing.listing_id, researcher, "")
            .await
            .expect("request");

        assert_eq!(
            registry
                .list_requests_for(steward)
                .await
                .expect("list")
                .len(),
            1
        );
        assert_eq!(
            registry
                .list_requests_for(researcher)
                .await
                .expect("list")
                .len(),
            1
        );
        assert!(
            registry
                .list_requests_for(TenantId::generate())
                .await
                .expect("list")
                .is_empty()
        );
    }
}
