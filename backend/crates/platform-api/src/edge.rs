//! The HTTP edge shared by every response: the page policy and the baseline
//! security headers.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderName, HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use futures::TryStreamExt;
use platform_core::QueryLimits;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::timeout::TimeoutBody;

/// The page Content-Security-Policy, one line, defined once in
/// `page-csp.txt` (also read by the frontend's `vite preview`).
pub const PAGE_CSP: &str = include_str!("../page-csp.txt");

/// Total time for every route that is neither a query nor an upload.
pub const DEFAULT_ROUTE_TIMEOUT: Duration = Duration::from_secs(60);
/// Added to a query's slot wait and run limit for the work around the run:
/// key release, storage reads and writing the response.
pub const QUERY_ROUTE_MARGIN: Duration = Duration::from_secs(60);
/// Longest an upload body may go without delivering data.
pub const BODY_GAP_TIMEOUT: Duration = Duration::from_secs(30);

/// How long each route group may take. Query routes get a total timeout and
/// uploads get none, only a gap between body reads.
#[derive(Debug, Clone, Copy)]
pub struct EdgeTimeouts {
    pub default: Duration,
    pub query: Duration,
    pub body_gap: Duration,
}

impl EdgeTimeouts {
    /// The query total is the slot wait, the run limit and the margin, so
    /// the query's own limits end it first.
    pub fn from_limits(limits: &QueryLimits) -> Self {
        Self {
            default: DEFAULT_ROUTE_TIMEOUT,
            query: limits.slot_wait + limits.timeout + QUERY_ROUTE_MARGIN,
            body_gap: BODY_GAP_TIMEOUT,
        }
    }
}

/// Answer 408 when the request body goes `gap` without delivering data.
/// tower-http's `RequestBodyTimeoutLayer` alone ends the body with an error
/// that handlers' extractors report as 400, so this notes the timeout and
/// replaces the response.
pub(crate) async fn body_gap(
    State(gap): State<Duration>,
    request: Request,
    next: Next,
) -> Response {
    let timed_out = Arc::new(AtomicBool::new(false));
    let seen = timed_out.clone();
    let (parts, body) = request.into_parts();
    let body = Body::new(TimeoutBody::new(gap, body))
        .into_data_stream()
        .inspect_err(move |err| {
            if std::error::Error::source(err)
                .is_some_and(|source| source.is::<tower_http::timeout::TimeoutError>())
            {
                seen.store(true, Ordering::SeqCst);
            }
        });
    let response = next
        .run(Request::from_parts(parts, Body::from_stream(body)))
        .await;
    if timed_out.load(Ordering::SeqCst) {
        return StatusCode::REQUEST_TIMEOUT.into_response();
    }
    response
}

/// Answer a panicking handler with a generic 500. The panic payload may hold
/// request data, so it is dropped unread and the log line is fixed.
pub(crate) fn catch_panics(router: Router) -> Router {
    router.layer(CatchPanicLayer::custom(
        |_payload: Box<dyn std::any::Any + Send>| {
            tracing::error!("request handler panicked");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(serde_json::json!({ "error": "internal" })),
            )
                .into_response()
        },
    ))
}

/// Set the baseline security headers on every response of `router`,
/// replacing any value a handler set, so each appears exactly once.
pub(crate) fn security_headers(router: Router) -> Router {
    let set =
        |name: HeaderName, value: HeaderValue| SetResponseHeaderLayer::overriding(name, value);
    router
        .layer(set(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(PAGE_CSP),
        ))
        .layer(set(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(set(
            header::REFERRER_POLICY,
            HeaderValue::from_static("no-referrer"),
        ))
        .layer(set(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
        .layer(set(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOGLE_KEY_SET: &str = "https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com";

    #[test]
    fn query_timeout_follows_the_limits() {
        let secs = Duration::from_secs;
        let limits = QueryLimits {
            slot_wait: secs(10),
            timeout: secs(60),
            ..QueryLimits::default()
        };
        let timeouts = EdgeTimeouts::from_limits(&limits);
        assert_eq!(timeouts.query, secs(130));
        assert_eq!(timeouts.default, secs(60));
        assert_eq!(timeouts.body_gap, secs(30));
        let long = QueryLimits {
            slot_wait: secs(120),
            timeout: secs(600),
            ..QueryLimits::default()
        };
        assert_eq!(EdgeTimeouts::from_limits(&long).query, secs(780));
    }

    #[test]
    fn page_csp_file_is_one_clean_line() {
        assert!(!PAGE_CSP.contains(['\n', '\r']));
        assert_eq!(PAGE_CSP, PAGE_CSP.trim());
        assert!(HeaderValue::from_str(PAGE_CSP).is_ok());
        assert!(PAGE_CSP.contains("frame-ancestors 'none'"));
        assert!(PAGE_CSP.contains("'wasm-unsafe-eval'"));
        assert!(!PAGE_CSP.contains("unsafe-inline"));
        assert!(
            !PAGE_CSP
                .replace("wasm-unsafe-eval", "")
                .contains("unsafe-eval")
        );
        let connect = PAGE_CSP
            .split("; ")
            .find_map(|d| d.strip_prefix("connect-src "))
            .expect("connect-src");
        assert_eq!(
            connect.split(' ').collect::<Vec<_>>(),
            ["'self'", GOOGLE_KEY_SET]
        );
    }

    #[tokio::test]
    async fn edge_replaces_headers_a_handler_sets() {
        use axum::body::Body;
        use axum::http::Request;
        use axum::routing::get;
        use tower::ServiceExt;

        let app = security_headers(Router::new().route(
            "/",
            get(|| async {
                (
                    [
                        (header::CACHE_CONTROL, "public, max-age=60"),
                        (header::CONTENT_SECURITY_POLICY, "default-src *"),
                    ],
                    "ok",
                )
            }),
        ));
        let response = app
            .oneshot(Request::get("/").body(Body::empty()).expect("request"))
            .await
            .expect("response");
        for (name, expected) in [
            (header::CACHE_CONTROL, "no-store"),
            (header::CONTENT_SECURITY_POLICY, PAGE_CSP),
        ] {
            let all: Vec<_> = response.headers().get_all(&name).iter().collect();
            assert_eq!(all, [expected], "{name}");
        }
    }

    async fn boom() -> &'static str {
        panic!("MARKER-secret")
    }

    /// A router that panics with a recognisable message, wrapped as the real
    /// routes are, with the metrics router that reports on it.
    ///
    /// The tests share one callsite for the log event, and a scoped
    /// subscriber only sees it when no other test is registering it, so the
    /// guard serialises them.
    async fn panicking_app() -> (Router, Router, tokio::sync::MutexGuard<'static, ()>) {
        use axum::routing::get;

        static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
        let serial = SERIAL.lock().await;

        let metrics = Arc::new(crate::metrics::Metrics::new(None));
        let app = crate::wrap_edge(Router::new().route("/boom", get(boom)), metrics.clone());
        let report = Router::new()
            .route("/metrics", get(crate::metrics::render))
            .with_state(metrics);
        (app, report, serial)
    }

    async fn get_body(app: &Router, uri: &str) -> (Response, String) {
        use axum::http::Request;
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        let response = app
            .clone()
            .oneshot(Request::get(uri).body(Body::empty()).expect("request"))
            .await
            .expect("response");
        let (parts, body) = response.into_parts();
        let bytes = body.collect().await.expect("body").to_bytes();
        let text = String::from_utf8_lossy(&bytes).into_owned();
        (Response::from_parts(parts, Body::empty()), text)
    }

    #[tokio::test]
    async fn panic_returns_a_generic_500() {
        let (app, _, _serial) = panicking_app().await;
        let (response, body) = get_body(&app, "/boom").await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body, r#"{"error":"internal"}"#);
        assert!(!body.contains("MARKER"));
        for (name, expected) in [
            (header::CONTENT_SECURITY_POLICY, PAGE_CSP),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (header::REFERRER_POLICY, "no-referrer"),
            (header::X_FRAME_OPTIONS, "DENY"),
            (header::CACHE_CONTROL, "no-store"),
        ] {
            let all: Vec<_> = response.headers().get_all(&name).iter().collect();
            assert_eq!(all, [expected], "{name}");
        }
    }

    #[derive(Clone, Default)]
    struct Captured(Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("lock").extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn panic_is_logged_without_its_payload() {
        let (app, _, _serial) = panicking_app().await;
        let output = Captured::default();
        let sink = output.clone();
        // The test runtime is current-thread, so the thread-local default
        // sees the event the layer emits.
        let _guard = tracing::subscriber::set_default(platform_telemetry::build_subscriber(
            "trace",
            move || sink.clone(),
        ));
        // Another test's panic may have registered the callsite while no
        // subscriber was set, caching it as disabled.
        tracing::callsite::rebuild_interest_cache();
        get_body(&app, "/boom").await;

        let text = String::from_utf8(output.0.lock().expect("lock").clone()).expect("UTF-8");
        let lines: Vec<serde_json::Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).expect("JSON line"))
            .collect();
        let errors: Vec<_> = lines
            .iter()
            .filter(|line| line["level"] == "ERROR")
            .collect();
        assert_eq!(errors.len(), 1, "{text}");
        assert_eq!(errors[0]["message"], "request handler panicked");
        assert!(
            lines
                .iter()
                .all(|line| line["target"] != platform_telemetry::SECURITY_AUDIT_TARGET),
            "{text}"
        );
        assert!(!text.contains("MARKER"), "{text}");
    }

    #[tokio::test]
    async fn panic_is_counted_by_request_metrics() {
        let (app, report, _serial) = panicking_app().await;
        get_body(&app, "/boom").await;
        let (_, metrics) = get_body(&report, "/metrics").await;
        assert!(
            metrics.contains(r#"http_requests_total{method="GET",route="/boom",status="500"} 1"#),
            "{metrics}"
        );
    }
}
