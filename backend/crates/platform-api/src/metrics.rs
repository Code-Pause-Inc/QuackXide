//! Operational metrics. They are served on their own loopback listener
//! (`METRICS_BIND_ADDR`), never on the public API. Labels carry route
//! patterns, methods, status codes and refusal kinds only: no tenant ids,
//! paths, messages or SQL.

use std::sync::Arc;
use std::time::Instant;

use axum::extract::{MatchedPath, Request, State};
use axum::http::{Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::histogram::{Histogram, exponential_buckets};
use prometheus_client::registry::Registry;

/// Set on every `ApiError` response; names the kind of refusal.
#[derive(Clone, Copy)]
pub(crate) struct Refusal(pub(crate) &'static str);

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct RequestLabels {
    method: &'static str,
    route: String,
    status: u16,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct RouteLabels {
    method: &'static str,
    route: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct RefusalLabels {
    reason: &'static str,
}

/// Buckets from 1 ms to about 33 s.
pub(crate) fn latency_histogram() -> Histogram {
    Histogram::new(exponential_buckets(0.001, 2.0, 16))
}

/// Records the time since `start` into a histogram when dropped, so work
/// that is cancelled (a client that goes away, a query that stops waiting)
/// is timed too.
pub(crate) struct Timer {
    histogram: Histogram,
    started: Instant,
}

impl Timer {
    pub(crate) fn start(histogram: Histogram) -> Self {
        Self {
            histogram,
            started: Instant::now(),
        }
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        self.histogram.observe(self.started.elapsed().as_secs_f64());
    }
}

pub(crate) struct Metrics {
    registry: Registry,
    requests: Family<RequestLabels, Counter>,
    durations: Family<RouteLabels, Histogram, fn() -> Histogram>,
    refusals: Family<RefusalLabels, Counter>,
}

impl Metrics {
    /// `plaintext_wait` is the query service's histogram, when one is
    /// configured.
    pub(crate) fn new(plaintext_wait: Option<Histogram>) -> Self {
        let mut registry = Registry::default();
        let requests = Family::<RequestLabels, Counter>::default();
        registry.register(
            "http_requests",
            "HTTP requests by method, route pattern and status",
            requests.clone(),
        );
        let durations = Family::new_with_constructor(latency_histogram as fn() -> Histogram);
        registry.register(
            "http_request_duration_seconds",
            "HTTP request latency by method and route pattern",
            durations.clone(),
        );
        let refusals = Family::<RefusalLabels, Counter>::default();
        registry.register(
            "api_refusals",
            "Error responses by kind of refusal",
            refusals.clone(),
        );
        if let Some(histogram) = plaintext_wait {
            registry.register(
                "query_plaintext_slot_wait_seconds",
                "Time queries wait for a plaintext slot",
                histogram,
            );
        }
        Self {
            registry,
            requests,
            durations,
            refusals,
        }
    }
}

/// Middleware: counts and times every request, and counts refusals.
pub(crate) async fn track(
    State(metrics): State<Arc<Metrics>>,
    request: Request,
    next: Next,
) -> Response {
    let method = method_label(request.method());
    // The route pattern, never the path: paths carry object ids.
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map_or_else(|| "unmatched".to_owned(), |path| path.as_str().to_owned());
    let _timer = Timer::start(metrics.durations.get_or_create_owned(&RouteLabels {
        method,
        route: route.clone(),
    }));
    let response = next.run(request).await;

    // Only completed requests are counted: a dropped one has no status.
    metrics
        .requests
        .get_or_create(&RequestLabels {
            method,
            route,
            status: response.status().as_u16(),
        })
        .inc();
    // Error responses that did not come from `ApiError` (axum's own
    // rejections: bad JSON, wrong content type, body too large) count too.
    let status = response.status();
    let reason = match response.extensions().get::<Refusal>() {
        Some(Refusal(reason)) => Some(*reason),
        None if status.is_client_error() || status.is_server_error() => Some("other"),
        None => None,
    };
    if let Some(reason) = reason {
        metrics
            .refusals
            .get_or_create(&RefusalLabels { reason })
            .inc();
    }
    response
}

/// Unusual methods share one label, so a caller cannot add label values.
fn method_label(method: &Method) -> &'static str {
    match *method {
        Method::GET => "GET",
        Method::POST => "POST",
        Method::PUT => "PUT",
        Method::DELETE => "DELETE",
        Method::PATCH => "PATCH",
        Method::HEAD => "HEAD",
        Method::OPTIONS => "OPTIONS",
        _ => "other",
    }
}

/// `GET /metrics` on the metrics listener.
pub(crate) async fn render(State(metrics): State<Arc<Metrics>>) -> Response {
    let mut body = String::new();
    if encode(&mut body, &metrics.registry).is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    (
        [(
            header::CONTENT_TYPE,
            "application/openmetrics-text; version=1.0.0; charset=utf-8",
        )],
        body,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use axum::Router;
    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::get;
    use tower::ServiceExt;

    use super::*;

    fn encoded(registry: &Registry) -> String {
        let mut body = String::new();
        encode(&mut body, registry).expect("encode");
        body
    }

    #[tokio::test]
    async fn timer_records_cancelled_work() {
        let histogram = latency_histogram();
        let mut registry = Registry::default();
        registry.register("wait_seconds", "test", histogram.clone());

        let work = async {
            let _timer = Timer::start(histogram.clone());
            std::future::pending::<()>().await
        };
        assert!(
            tokio::time::timeout(Duration::from_millis(20), work)
                .await
                .is_err()
        );

        assert!(encoded(&registry).contains("wait_seconds_count 1"));
    }

    #[tokio::test]
    async fn dropped_requests_are_timed_but_not_counted() {
        let metrics = Arc::new(Metrics::new(None));
        let app = Router::new()
            .route("/slow", get(std::future::pending::<&'static str>))
            .layer(axum::middleware::from_fn_with_state(metrics.clone(), track));
        let request = Request::builder()
            .uri("/slow")
            .body(Body::empty())
            .expect("request");
        assert!(
            tokio::time::timeout(Duration::from_millis(20), app.oneshot(request))
                .await
                .is_err()
        );

        let body = encoded(&metrics.registry);
        assert!(
            body.contains(r#"http_request_duration_seconds_count{method="GET",route="/slow"} 1"#),
            "{body}"
        );
        assert!(!body.contains("http_requests_total{"), "{body}");
    }
}
