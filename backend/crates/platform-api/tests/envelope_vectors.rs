//! The enrollment cases of the shared envelope vectors
//! (`fixtures/envelope/hpk1.json`) against the enrollment route: the keys
//! the browser accepts and refuses are the ones the API accepts and refuses.

mod common;

use std::sync::Arc;

use axum::http::StatusCode;
use platform_api::build_app;
use platform_core::TenantId;
use platform_storage::ObjectStoreVault;

use common::{bearer, json_header, send};

const SECRET: &str = "integration-test-secret";

#[tokio::test]
async fn enrollment_vectors_are_accepted_or_refused_as_recorded() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../fixtures/envelope/hpk1.json"
    );
    let vectors: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).expect("vector file")).expect("json");
    let app = build_app(common::app_state(
        SECRET,
        Arc::new(ObjectStoreVault::new_in_memory()),
    ));
    let token = common::token_for(SECRET, TenantId::generate());

    for case in vectors["enrollment"].as_array().expect("enrollment cases") {
        let body = serde_json::json!({ "hpke_public_key_b64": case["public_b64"] });
        let (status, _) = send(
            &app,
            "PUT",
            "/api/v1/drive/enrollment",
            &[bearer(&token), json_header()],
            body.to_string().into_bytes(),
        )
        .await;
        let expected = if case["valid"] == true {
            StatusCode::NO_CONTENT
        } else {
            StatusCode::BAD_REQUEST
        };
        assert_eq!(status, expected, "{}", case["name"]);
    }
}
