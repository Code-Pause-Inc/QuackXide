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
}
