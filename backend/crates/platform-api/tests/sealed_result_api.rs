//! Research results sealed to the researcher and signed by the enclave (ADR
//! 0010 "Recipient key" and "Sealed and signed result"), through the
//! sealed-result functions: a real research result is sealed to the
//! researcher's enrolled key and opens only after the browser's checks, and
//! a recipient key that is not the enrolled one is refused.

mod common;

use axum::http::StatusCode;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use platform_api::ApiError;
use platform_api::query::ResearchRequest;
use platform_api::sealed::{ResultBinding, SealedQueryResponse, result_info};
use platform_core::{ConnectorSlug, TenantId};
use platform_crypto::{EnvelopeSuite, ResultVerifyingKeys, TenantKeypair};
use platform_storage::TenantPaths;
use serde_json::Value;

use common::{enroll_key, post, sealed_result_app};

const SECRET: &str = "sealed-result-itest-secret";
const AGG_SQL: &str =
    "SELECT condition, COUNT(*) AS n FROM health GROUP BY condition ORDER BY condition";

fn token_for(tenant: TenantId) -> String {
    common::token_for(SECRET, tenant)
}

fn status_of(err: ApiError) -> StatusCode {
    use axum::response::IntoResponse as _;
    err.into_response().status()
}

/// The browser's side: verify the signatures under the key set from the
/// evidence bundle, recompute `info` from its own request, then open.
fn accept(
    response: &SealedQueryResponse,
    verified: &ResultVerifyingKeys,
    recipient: &TenantKeypair,
    researcher: TenantId,
    binding: &ResultBinding<'_>,
) -> Option<Value> {
    let frame = URL_SAFE_NO_PAD.decode(&response.sealed_result).ok()?;
    let info = result_info(recipient.suite(), researcher, binding).ok()?;
    let signature = response.signature.to_signature().ok()?;
    verified.verify(&info, &frame, &signature).ok()?;
    let opened = recipient.open_envelope(&info, &frame).ok()?;
    serde_json::from_slice(opened.expose()).ok()
}

#[tokio::test]
async fn a_research_result_is_sealed_to_the_enrolled_key_and_signed() {
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let (app, service, _vault) = sealed_result_app(
        SECRET,
        steward,
        TenantKeypair::generate(EnvelopeSuite::Hpk2),
    )
    .await;
    let (status, grant) = post(
        &app,
        "/api/v1/grants",
        &token_for(steward),
        &format!(r#"{{"researcher_tenant":"{researcher}","connector":"health"}}"#),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{grant}");
    let grant_id = grant["grant_id"].as_str().expect("grant id").to_owned();

    // The researcher's browser key, enrolled through the API.
    let recipient = TenantKeypair::generate(EnvelopeSuite::Hpk2);
    assert_eq!(
        enroll_key(&app, &token_for(researcher), &recipient.public_key()).await,
        StatusCode::NO_CONTENT
    );
    // The browser verified this key set from the evidence bundle.
    let bundle = service
        .attestation_bundle([1u8; 32])
        .await
        .unwrap_or_else(|e| panic!("no bundle: {}", status_of(e)));
    let verified = bundle.signing_keys.to_verifying_keys().expect("keys");

    let presented = recipient.public_key();
    let checked = service
        .verify_recipient(researcher, &presented)
        .await
        .unwrap_or_else(|e| panic!("recipient refused: {}", status_of(e)));
    let payload = service
        .research_query(
            researcher,
            ResearchRequest::plain(
                steward,
                ConnectorSlug::new("health").expect("slug"),
                AGG_SQL,
            ),
        )
        .await
        .unwrap_or_else(|e| panic!("query refused: {}", status_of(e)));
    let nonce = [5u8; 32];
    let binding = ResultBinding {
        grant_id: &grant_id,
        request_nonce: &nonce,
        sql: AGG_SQL,
        schema_version: None,
    };
    let response = service
        .seal_research_result(&checked, &binding, &payload)
        .unwrap_or_else(|e| panic!("seal failed: {}", status_of(e)));
    assert_eq!(response.key_id, bundle.key_id);

    // None of the aggregate rows or counts is on the wire. Quoted, so a
    // match cannot come from inside a base64url value.
    let wire = serde_json::to_string(&response).expect("json");
    for value in [
        r#""flu""#,
        r#""rows""#,
        r#""suppressed_rows""#,
        r#""budget_remaining""#,
    ] {
        assert!(!wire.contains(value), "{value} in {wire}");
    }
    // The researcher opens exactly the result the enclave computed.
    let opened = accept(&response, &verified, &recipient, researcher, &binding).expect("opens");
    let computed: serde_json::Value = serde_json::from_slice(payload.expose()).expect("json");
    assert_eq!(opened, computed);
    assert_eq!(
        opened["rows"],
        serde_json::json!([{ "condition": "flu", "n": 6 }])
    );
    assert_eq!(opened["suppressed_rows"], 1);

    // The same response presented for another request nonce is refused.
    let replayed = ResultBinding {
        request_nonce: &[6u8; 32],
        ..binding
    };
    assert!(accept(&response, &verified, &recipient, researcher, &replayed).is_none());
}

#[tokio::test]
async fn a_recipient_key_substituted_in_the_enrollment_record_is_refused() {
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let (app, service, vault) = sealed_result_app(
        SECRET,
        steward,
        TenantKeypair::generate(EnvelopeSuite::Hpk2),
    )
    .await;
    let browser = TenantKeypair::generate(EnvelopeSuite::Hpk2);
    let substitute = TenantKeypair::generate(EnvelopeSuite::Hpk2);

    // No enrolled key: nothing to match, so 403.
    let presented = browser.public_key();
    let refused = service.verify_recipient(researcher, &presented).await;
    assert_eq!(
        refused.map_err(status_of).err(),
        Some(StatusCode::FORBIDDEN)
    );

    // The researcher enrolls; then an operator overwrites the record with
    // its own key. The browser still presents its own key in the sealed
    // request, which no longer matches, so the query is refused before any
    // result exists.
    let token = token_for(researcher);
    assert_eq!(
        enroll_key(&app, &token, &browser.public_key()).await,
        StatusCode::NO_CONTENT
    );
    assert!(
        service
            .verify_recipient(researcher, &presented)
            .await
            .is_ok()
    );
    common::write_enrollment(&*vault, researcher, &substitute.public_key()).await;
    let refused = service.verify_recipient(researcher, &presented).await;
    assert_eq!(
        refused.map_err(status_of).err(),
        Some(StatusCode::FORBIDDEN)
    );

    // The check is per researcher: the same key enrolled by another
    // researcher is theirs, and still not this researcher's.
    let other = TenantId::generate();
    assert_eq!(
        enroll_key(&app, &token_for(other), &browser.public_key()).await,
        StatusCode::NO_CONTENT
    );
    assert!(service.verify_recipient(other, &presented).await.is_ok());
    let refused = service.verify_recipient(researcher, &presented).await;
    assert_eq!(
        refused.map_err(status_of).err(),
        Some(StatusCode::FORBIDDEN)
    );
}

#[tokio::test]
async fn an_unreadable_enrollment_record_refuses_the_recipient_with_500() {
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let (_app, service, vault) = sealed_result_app(
        SECRET,
        steward,
        TenantKeypair::generate(EnvelopeSuite::Hpk2),
    )
    .await;
    vault
        .put(
            &TenantPaths::tenant_enrollment(researcher),
            Bytes::from_static(b"not an enrollment record"),
        )
        .await
        .expect("put");
    let key = TenantKeypair::generate(EnvelopeSuite::Hpk2).public_key();
    let refused = service.verify_recipient(researcher, &key).await;
    assert_eq!(
        refused.map_err(status_of).err(),
        Some(StatusCode::INTERNAL_SERVER_ERROR)
    );
}
