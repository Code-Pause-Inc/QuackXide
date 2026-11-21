//! The replay and retry store for sealed research queries (ADR 0010
//! "Sealed request"). One store per enclave key set: a request nonce is
//! recorded with its envelope's digest just before the budget charge, and
//! the query's response is kept for one token lifetime, so a client that
//! lost it can send the same envelope again and get it with no new charge.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use platform_crypto::SecretBytes;

use crate::ApiError;

/// How long a stored response is kept: one attestation token lifetime, the
/// longest a client session lasts (ADR 0010).
pub(crate) const STORED_RESPONSE_TTL: Duration =
    Duration::from_secs(platform_enclave::token::MAX_TOKEN_LIFETIME_SECS);

/// A finished query's response, as first sent.
pub(crate) enum StoredOutcome {
    /// The JSON body of a 200.
    Ok(SecretBytes),
    Err(ApiError),
}

impl Clone for StoredOutcome {
    fn clone(&self) -> Self {
        match self {
            Self::Ok(body) => Self::Ok(SecretBytes::new(body.expose().to_vec())),
            Self::Err(err) => Self::Err(err.clone()),
        }
    }
}

/// What [`ReplayStore::begin`] found for a nonce.
pub(crate) enum Begin {
    /// First use: run the query, then [`ReplayGuard::finish`].
    New(ReplayGuard),
    /// The same envelope again: send this, with no new charge.
    Stored(StoredOutcome),
    /// Another envelope under the nonce, a retry while the query runs, or a
    /// stored response that has expired (409; re-send under a new nonce).
    Refused,
}

enum State {
    Running,
    Done(StoredOutcome),
    /// The response was dropped; the nonce stays recorded.
    Expired,
}

struct Entry {
    digest: [u8; 32],
    state: State,
}

#[derive(Default)]
struct Entries {
    by_nonce: HashMap<[u8; 32], Entry>,
    /// Finished nonces, oldest first, so expiry pops from the front.
    finished: VecDeque<(Instant, [u8; 32])>,
}

impl Entries {
    fn expire(&mut self, now: Instant) {
        while let Some(&(stored_at, nonce)) = self.finished.front() {
            if now.saturating_duration_since(stored_at) <= STORED_RESPONSE_TTL {
                break;
            }
            self.finished.pop_front();
            if let Some(entry) = self.by_nonce.get_mut(&nonce) {
                entry.state = State::Expired;
            }
        }
    }

    fn finish(&mut self, nonce: [u8; 32], outcome: StoredOutcome, now: Instant) {
        if let Some(entry) = self.by_nonce.get_mut(&nonce) {
            entry.state = State::Done(outcome);
            self.finished.push_back((now, nonce));
        }
    }
}

/// Recorded nonces for one key set. Ceiling: entries live as long as the
/// key set and each one cost a budget unit, so they are bounded by the
/// budget charged since the process started; rotating the key set (a new
/// store) is the upgrade path if that grows too large.
#[derive(Default)]
pub(crate) struct ReplayStore {
    entries: Arc<Mutex<Entries>>,
}

fn lock(entries: &Mutex<Entries>) -> MutexGuard<'_, Entries> {
    // Every update leaves the map consistent, so a panic elsewhere while
    // holding the lock leaves nothing half-written.
    entries.lock().unwrap_or_else(PoisonError::into_inner)
}

impl ReplayStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Record `nonce` with `envelope_digest` if it is new; otherwise say
    /// what the earlier request left.
    pub(crate) fn begin(&self, nonce: [u8; 32], envelope_digest: [u8; 32], now: Instant) -> Begin {
        let mut entries = lock(&self.entries);
        entries.expire(now);
        match entries.by_nonce.get(&nonce) {
            None => {
                entries.by_nonce.insert(
                    nonce,
                    Entry {
                        digest: envelope_digest,
                        state: State::Running,
                    },
                );
                Begin::New(ReplayGuard {
                    entries: Arc::clone(&self.entries),
                    nonce,
                    finished: false,
                })
            }
            Some(entry) if entry.digest != envelope_digest => Begin::Refused,
            Some(Entry {
                state: State::Done(outcome),
                ..
            }) => Begin::Stored(outcome.clone()),
            Some(_) => Begin::Refused,
        }
    }
}

/// A nonce whose query is running. Dropped without [`finish`](Self::finish)
/// (the query's task panicked), it stores a 503, so the nonce is never left
/// running.
pub(crate) struct ReplayGuard {
    entries: Arc<Mutex<Entries>>,
    nonce: [u8; 32],
    finished: bool,
}

impl ReplayGuard {
    pub(crate) fn finish(mut self, outcome: StoredOutcome, now: Instant) {
        self.finished = true;
        lock(&self.entries).finish(self.nonce, outcome, now);
    }
}

impl Drop for ReplayGuard {
    fn drop(&mut self) {
        if !self.finished {
            lock(&self.entries).finish(
                self.nonce,
                StoredOutcome::Err(ApiError::QueryUnavailable),
                Instant::now(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use platform_crypto::SecretBytes;

    use super::*;
    use crate::ApiError;

    const NONCE: [u8; 32] = [1; 32];
    const DIGEST: [u8; 32] = [2; 32];

    fn ok(body: &[u8]) -> StoredOutcome {
        StoredOutcome::Ok(SecretBytes::new(body.to_vec()))
    }

    fn finished(store: &ReplayStore, outcome: StoredOutcome, at: Instant) {
        match store.begin(NONCE, DIGEST, at) {
            Begin::New(guard) => guard.finish(outcome, at),
            _ => panic!("expected a new entry"),
        }
    }

    #[test]
    fn a_new_nonce_begins() {
        let store = ReplayStore::new();
        assert!(matches!(
            store.begin(NONCE, DIGEST, Instant::now()),
            Begin::New(_)
        ));
    }

    #[test]
    fn the_same_envelope_gets_the_stored_outcome() {
        let store = ReplayStore::new();
        let t = Instant::now();
        finished(&store, ok(b"r"), t);
        match store.begin(NONCE, DIGEST, t) {
            Begin::Stored(StoredOutcome::Ok(body)) => assert_eq!(body.expose(), b"r"),
            _ => panic!("expected the stored response"),
        }
    }

    #[test]
    fn another_envelope_under_a_used_nonce_is_refused() {
        let store = ReplayStore::new();
        let t = Instant::now();
        finished(&store, ok(b"r"), t);
        assert!(matches!(store.begin(NONCE, [3; 32], t), Begin::Refused));
    }

    #[test]
    fn a_retry_while_running_is_refused() {
        let store = ReplayStore::new();
        let t = Instant::now();
        let _running = store.begin(NONCE, DIGEST, t);
        assert!(matches!(store.begin(NONCE, DIGEST, t), Begin::Refused));
    }

    #[test]
    fn an_expired_response_is_refused() {
        let store = ReplayStore::new();
        let t = Instant::now();
        finished(&store, ok(b"r"), t);
        let later = t + STORED_RESPONSE_TTL + Duration::from_secs(1);
        assert!(matches!(store.begin(NONCE, DIGEST, later), Begin::Refused));
        let much_later = later + STORED_RESPONSE_TTL;
        assert!(matches!(
            store.begin(NONCE, DIGEST, much_later),
            Begin::Refused
        ));
    }

    #[test]
    fn a_dropped_guard_stores_an_error() {
        let store = ReplayStore::new();
        let t = Instant::now();
        drop(store.begin(NONCE, DIGEST, t));
        assert!(matches!(
            store.begin(NONCE, DIGEST, t),
            Begin::Stored(StoredOutcome::Err(ApiError::QueryUnavailable))
        ));
    }

    #[test]
    fn stored_errors_replay() {
        let store = ReplayStore::new();
        let t = Instant::now();
        finished(&store, StoredOutcome::Err(ApiError::BudgetExhausted), t);
        assert!(matches!(
            store.begin(NONCE, DIGEST, t),
            Begin::Stored(StoredOutcome::Err(ApiError::BudgetExhausted))
        ));
    }
}
