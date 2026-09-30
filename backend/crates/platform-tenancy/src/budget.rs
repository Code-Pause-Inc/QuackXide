//! Per-grant query budgets: the rate-of-disclosure control.
//!
//! Threshold suppression bounds what a single query reveals but not
//! overlapping-query differencing (two aggregates whose cohorts differ by
//! one row isolate that row). Every research query therefore consumes budget
//! from its grant, and an exhausted grant refuses until the steward tops it
//! up. The same ledger is the billing meter.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

use async_trait::async_trait;
use serde::Serialize;

use crate::TenancyError;

/// One grant's budget standing. `spent` is monotonic and `limit` only rises,
/// so budget is never silently reset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BudgetState {
    pub grant_id: String,
    /// Total units allocated over the grant's lifetime.
    pub limit: u64,
    /// Units consumed so far.
    pub spent: u64,
}

impl BudgetState {
    pub fn remaining(&self) -> u64 {
        self.limit.saturating_sub(self.spent)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BudgetError {
    /// No ledger entry for the grant; callers treat this like exhaustion.
    #[error("no budget ledger entry for grant")]
    UnknownGrant,
    /// Remaining budget is below the requested cost. Carries the standing so
    /// callers can audit without a second read.
    #[error("query budget exhausted")]
    Exhausted(BudgetState),
}

#[async_trait]
pub trait BudgetLedger: Send + Sync {
    /// Open a grant's entry with an initial allocation. Insert-if-absent, so
    /// re-granting (which reuses the grant id) never resets spend; only
    /// [`top_up`] raises the allocation.
    ///
    /// [`top_up`]: BudgetLedger::top_up
    async fn open(&self, grant_id: &str, limit: u64) -> Result<BudgetState, TenancyError>;

    /// Atomically consume `cost` units. Refuses without partial spend when
    /// the entry is missing or remaining < cost.
    async fn charge(&self, grant_id: &str, cost: u64) -> Result<BudgetState, BudgetError>;

    /// Raise the lifetime allocation (steward top-up). Saturating: cannot
    /// overflow, cannot lower.
    async fn top_up(&self, grant_id: &str, additional: u64) -> Result<BudgetState, BudgetError>;

    /// Current standing, if an entry exists.
    async fn state(&self, grant_id: &str) -> Result<Option<BudgetState>, TenancyError>;
}

/// In-memory ledger. A durable backend must make `charge` an atomic
/// conditional update.
#[derive(Default)]
pub struct InMemoryBudgetLedger {
    by_grant: Mutex<HashMap<String, BudgetState>>,
}

impl InMemoryBudgetLedger {
    fn lock(&self) -> MutexGuard<'_, HashMap<String, BudgetState>> {
        self.by_grant.lock().expect("budget lock")
    }
}

#[async_trait]
impl BudgetLedger for InMemoryBudgetLedger {
    async fn open(&self, grant_id: &str, limit: u64) -> Result<BudgetState, TenancyError> {
        let mut ledger = self.lock();
        let entry = ledger
            .entry(grant_id.to_owned())
            .or_insert_with(|| BudgetState {
                grant_id: grant_id.to_owned(),
                limit,
                spent: 0,
            });
        Ok(entry.clone())
    }

    async fn charge(&self, grant_id: &str, cost: u64) -> Result<BudgetState, BudgetError> {
        let mut ledger = self.lock();
        let entry = ledger.get_mut(grant_id).ok_or(BudgetError::UnknownGrant)?;
        if entry.remaining() < cost {
            return Err(BudgetError::Exhausted(entry.clone()));
        }
        entry.spent += cost;
        Ok(entry.clone())
    }

    async fn top_up(&self, grant_id: &str, additional: u64) -> Result<BudgetState, BudgetError> {
        let mut ledger = self.lock();
        let entry = ledger.get_mut(grant_id).ok_or(BudgetError::UnknownGrant)?;
        entry.limit = entry.limit.saturating_add(additional);
        Ok(entry.clone())
    }

    async fn state(&self, grant_id: &str) -> Result<Option<BudgetState>, TenancyError> {
        Ok(self.lock().get(grant_id).cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn charge_decrements_until_exhausted() {
        let ledger = InMemoryBudgetLedger::default();
        ledger.open("g1", 2).await.expect("open");

        let after = ledger.charge("g1", 1).await.expect("first charge");
        assert_eq!(after.remaining(), 1);
        let after = ledger.charge("g1", 1).await.expect("second charge");
        assert_eq!(after.remaining(), 0);

        let err = ledger.charge("g1", 1).await.expect_err("exhausted");
        let BudgetError::Exhausted(state) = err else {
            panic!("expected Exhausted");
        };
        assert_eq!(state.spent, 2, "refusal must not spend");
    }

    #[tokio::test]
    async fn charge_never_partially_spends_past_the_limit() {
        let ledger = InMemoryBudgetLedger::default();
        ledger.open("g1", 3).await.expect("open");
        assert!(ledger.charge("g1", 5).await.is_err());
        assert_eq!(
            ledger
                .state("g1")
                .await
                .expect("state")
                .expect("entry")
                .spent,
            0
        );
    }

    #[tokio::test]
    async fn unknown_grant_fails_closed() {
        let ledger = InMemoryBudgetLedger::default();
        assert!(matches!(
            ledger.charge("nope", 1).await,
            Err(BudgetError::UnknownGrant)
        ));
        assert!(matches!(
            ledger.top_up("nope", 1).await,
            Err(BudgetError::UnknownGrant)
        ));
        assert!(ledger.state("nope").await.expect("ok").is_none());
    }

    #[tokio::test]
    async fn open_is_insert_if_absent_so_regrant_cannot_reset_spend() {
        let ledger = InMemoryBudgetLedger::default();
        ledger.open("g1", 5).await.expect("open");
        ledger.charge("g1", 4).await.expect("charge");

        let reopened = ledger.open("g1", 100).await.expect("reopen");
        assert_eq!(reopened.limit, 5);
        assert_eq!(reopened.spent, 4);
    }

    #[tokio::test]
    async fn top_up_raises_limit_and_restores_access() {
        let ledger = InMemoryBudgetLedger::default();
        ledger.open("g1", 1).await.expect("open");
        ledger.charge("g1", 1).await.expect("charge");
        assert!(ledger.charge("g1", 1).await.is_err());

        let topped = ledger.top_up("g1", 2).await.expect("top up");
        assert_eq!(topped.limit, 3);
        assert_eq!(topped.remaining(), 2);
        assert!(ledger.charge("g1", 1).await.is_ok());
    }

    #[tokio::test]
    async fn top_up_saturates_instead_of_overflowing() {
        let ledger = InMemoryBudgetLedger::default();
        ledger.open("g1", u64::MAX - 1).await.expect("open");
        let topped = ledger.top_up("g1", 10).await.expect("top up");
        assert_eq!(topped.limit, u64::MAX);
    }

    #[tokio::test]
    async fn zero_limit_grant_is_born_exhausted() {
        let ledger = InMemoryBudgetLedger::default();
        ledger.open("g1", 0).await.expect("open");
        assert!(matches!(
            ledger.charge("g1", 1).await,
            Err(BudgetError::Exhausted(_))
        ));
    }
}
