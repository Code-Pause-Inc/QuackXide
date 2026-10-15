//! `GET /readyz`: whether this process can serve right now. It is public
//! (load-balancer health checks are unauthenticated), so the response says
//! only ready or not ready; which check failed goes to the operational log.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use platform_storage::TenantPaths;
use serde_json::json;
use tokio::sync::Mutex;
use tokio::time::Instant;

use crate::AppState;

/// How long a result is reused. The endpoint is public and each check costs
/// a storage request and an attestation report, so callers share one run.
const CACHE_FOR: Duration = Duration::from_secs(5);
/// A check that takes longer than this counts as failed.
const CHECK_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Default)]
pub(crate) struct Readiness {
    /// The last run: when it finished and which checks failed.
    last: Mutex<Option<(Instant, Vec<&'static str>)>>,
}

impl Readiness {
    async fn is_ready(&self, state: &AppState) -> bool {
        // Held across the run, so concurrent probes wait for one result.
        let mut last = self.last.lock().await;
        if let Some((at, failed)) = last.as_ref()
            && at.elapsed() < CACHE_FOR
        {
            return failed.is_empty();
        }
        let failed = failed_checks(state).await;
        if last.as_ref().map(|(_, previous)| previous) != Some(&failed) {
            if failed.is_empty() {
                tracing::info!("ready");
            } else {
                tracing::warn!(failed = ?failed, "not ready");
            }
        }
        let ready = failed.is_empty();
        *last = Some((Instant::now(), failed));
        ready
    }
}

/// Names of the checks that fail. Registry and verification-key checks are
/// added as durable registries (P62) and key sources (P28) land.
async fn failed_checks(state: &AppState) -> Vec<&'static str> {
    let (storage, attestation) = tokio::join!(
        within_timeout(async {
            state
                .vault
                .list(&TenantPaths::readiness_probe())
                .await
                .is_ok()
        }),
        within_timeout(async {
            match &state.query {
                Some(query) => query.attestation_ready().await,
                None => false,
            }
        }),
    );
    let mut failed = Vec::new();
    if !storage {
        failed.push("storage");
    }
    if state.query.is_none() {
        failed.push("query_service");
    } else if !attestation {
        failed.push("attestation");
    }
    if state.jwt.is_none() {
        failed.push("token_verifier");
    }
    failed
}

async fn within_timeout(check: impl Future<Output = bool>) -> bool {
    tokio::time::timeout(CHECK_TIMEOUT, check)
        .await
        .unwrap_or(false)
}

pub(crate) async fn readyz(
    State(state): State<AppState>,
    Extension(readiness): Extension<Arc<Readiness>>,
) -> Response {
    if readiness.is_ready(&state).await {
        (StatusCode::OK, Json(json!({ "status": "ready" }))).into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "status": "not_ready" })),
        )
            .into_response()
    }
}
