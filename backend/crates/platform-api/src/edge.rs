//! The HTTP edge shared by every response: the page policy and the baseline
//! security headers.

use axum::Router;
use axum::http::{HeaderName, HeaderValue, header};
use tower_http::set_header::SetResponseHeaderLayer;

/// The page Content-Security-Policy, one line, defined once in
/// `page-csp.txt` (also read by the frontend's `vite preview`).
pub const PAGE_CSP: &str = include_str!("../page-csp.txt");

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
