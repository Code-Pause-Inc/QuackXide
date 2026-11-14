//! The shared envelope vectors (`fixtures/envelope/hpk1.json`) against the
//! API: the enrollment keys the browser accepts and refuses are the ones the
//! enrollment route accepts and refuses, and the upload route refuses the
//! envelopes whose framing is broken.

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

#[tokio::test]
async fn badly_framed_envelope_vectors_are_refused_by_the_upload_route() {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as B64;

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
    let steward = TenantId::generate();
    let token = common::token_for(SECRET, steward);
    let keypair = platform_crypto::TenantKeypair::generate();

    let framing = vectors["envelopes"]
        .as_array()
        .expect("envelope cases")
        .iter()
        .filter(|case| case["error"] == "invalid envelope framing")
        .collect::<Vec<_>>();
    assert_eq!(framing.len(), 2, "wrong frame magic and truncated frame");
    for case in framing {
        let envelope = B64
            .decode(case["envelope_b64"].as_str().expect("base64"))
            .expect("decode");
        // A well-formed upload whose object is the vector's envelope.
        let sealed = common::cohorts_upload(steward, &keypair.public_key(), "upload_cohorts", None);
        let header = u32::from_be_bytes(sealed.body[4..8].try_into().expect("4 bytes")) as usize;
        let at = 8 + header;
        let manifest =
            u32::from_be_bytes(sealed.body[at..at + 4].try_into().expect("4 bytes")) as usize;
        let mut body = sealed.body[..at + 4 + manifest].to_vec();
        body.extend_from_slice(&envelope);

        let (status, response) =
            common::put_upload(&app, Some(&token), "upload_cohorts", body).await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{}: {response}",
            case["name"]
        );
        assert_eq!(
            response["error"], "upload object is not a supported envelope frame",
            "{}",
            case["name"]
        );
    }
}
