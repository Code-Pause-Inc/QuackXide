//! The tenant envelope seal and open, built for wasm32 and loaded only by
//! the browser's crypto worker (`frontend/src/lib/crypto/envelope.ts`).
//!
//! It is `platform-crypto`'s own envelope code, so the browser and the
//! enclave share one implementation. Sealing needs only the recipient's
//! public key. Opening takes the device's raw private key, which the worker
//! decrypts just before the call (ADR 0007, "Browser private-key storage");
//! this module zeroizes its copy before returning. The drive KEK and
//! per-file keys never enter this module's memory.
//!
//! The functions without `wasm_bindgen` hold the logic and are tested
//! natively; the exported wrappers only convert errors.

use platform_crypto::{
    CryptoError, TenantPublicKey, hpke_open_with_private_key, hpke_seal_to_tenant, info,
    tenant_public_key_from_private,
};
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

/// Seal `plaintext` to a raw tenant public key under `info`, returning the
/// framed envelope. The suite is the current one ([`EnvelopeSuite::CURRENT`]);
/// the frame's magic names it.
///
/// [`EnvelopeSuite::CURRENT`]: platform_crypto::EnvelopeSuite::CURRENT
pub fn seal_envelope(
    recipient_public_key: &[u8],
    info: &[u8],
    mut plaintext: Vec<u8>,
) -> Result<Vec<u8>, CryptoError> {
    let sealed = TenantPublicKey::from_raw(recipient_public_key)
        .and_then(|recipient| hpke_seal_to_tenant(&recipient, info, &plaintext));
    // The JavaScript caller keeps its own copy; this one is wasm memory that
    // is reused, never returned to the browser.
    plaintext.zeroize();
    sealed
}

/// Open a framed envelope with the device's raw private key. The suite comes
/// from the frame magic. The key is zeroized here whether or not the open
/// succeeds; the JavaScript caller zeroizes its own copy.
pub fn open_envelope(
    mut private_key: Vec<u8>,
    info: &[u8],
    envelope: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let opened = hpke_open_with_private_key(&private_key, info, envelope);
    private_key.zeroize();
    // The plaintext leaves wasm memory as a copy; this one is zeroized when
    // `SecretBytes` drops.
    opened.map(|plaintext| plaintext.expose().to_vec())
}

/// The raw public key of a raw private key, for enrollment. The key is
/// zeroized here; the caller zeroizes its own copy.
pub fn public_key_from_private_key(mut private_key: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
    let public = tenant_public_key_from_private(&private_key);
    private_key.zeroize();
    public.map(|key| key.to_raw())
}

/// The `info` string for one object of a steward upload. Each field is
/// refused if empty or if it contains the separator.
pub fn steward_upload_info(
    tenant: &str,
    dataset: &str,
    object: &str,
) -> Result<Vec<u8>, CryptoError> {
    Ok(info::steward_upload(
        info::check_field(tenant)?,
        info::check_field(dataset)?,
        info::check_field(object)?,
    ))
}

/// The `info` string for a connector object, checked as
/// [`steward_upload_info`].
pub fn connector_object_info(
    tenant: &str,
    connector: &str,
    object: &str,
) -> Result<Vec<u8>, CryptoError> {
    Ok(info::connector_object(
        info::check_field(tenant)?,
        info::check_field(connector)?,
        info::check_field(object)?,
    ))
}

/// The `info` string for a connector snapshot manifest, checked as
/// [`steward_upload_info`].
pub fn snapshot_manifest_info(
    tenant: &str,
    connector: &str,
    version: &str,
) -> Result<Vec<u8>, CryptoError> {
    Ok(info::snapshot_manifest(
        info::check_field(tenant)?,
        info::check_field(connector)?,
        info::check_field(version)?,
    ))
}

/// The `info` string for a result sealed to a researcher, checked as
/// [`steward_upload_info`].
pub fn research_result_info(researcher_tenant: &str, query: &str) -> Result<Vec<u8>, CryptoError> {
    Ok(info::research_result(
        info::check_field(researcher_tenant)?,
        info::check_field(query)?,
    ))
}

// ── wasm exports ─────────────────────────────────────────────────────────────
//
// Error messages are `CryptoError`'s, which carry no key material or data.

fn js_error(err: CryptoError) -> JsError {
    JsError::new(&err.to_string())
}

#[wasm_bindgen(js_name = sealEnvelope)]
pub fn seal_envelope_js(
    recipient_public_key: &[u8],
    info: &[u8],
    plaintext: Vec<u8>,
) -> Result<Vec<u8>, JsError> {
    seal_envelope(recipient_public_key, info, plaintext).map_err(js_error)
}

#[wasm_bindgen(js_name = openEnvelope)]
pub fn open_envelope_js(
    private_key: Vec<u8>,
    info: &[u8],
    envelope: &[u8],
) -> Result<Vec<u8>, JsError> {
    open_envelope(private_key, info, envelope).map_err(js_error)
}

#[wasm_bindgen(js_name = publicKeyFromPrivateKey)]
pub fn public_key_from_private_key_js(private_key: Vec<u8>) -> Result<Vec<u8>, JsError> {
    public_key_from_private_key(private_key).map_err(js_error)
}

#[wasm_bindgen(js_name = stewardUploadInfo)]
pub fn steward_upload_info_js(
    tenant: &str,
    dataset: &str,
    object: &str,
) -> Result<Vec<u8>, JsError> {
    steward_upload_info(tenant, dataset, object).map_err(js_error)
}

#[wasm_bindgen(js_name = connectorObjectInfo)]
pub fn connector_object_info_js(
    tenant: &str,
    connector: &str,
    object: &str,
) -> Result<Vec<u8>, JsError> {
    connector_object_info(tenant, connector, object).map_err(js_error)
}

#[wasm_bindgen(js_name = snapshotManifestInfo)]
pub fn snapshot_manifest_info_js(
    tenant: &str,
    connector: &str,
    version: &str,
) -> Result<Vec<u8>, JsError> {
    snapshot_manifest_info(tenant, connector, version).map_err(js_error)
}

#[wasm_bindgen(js_name = researchResultInfo)]
pub fn research_result_info_js(researcher_tenant: &str, query: &str) -> Result<Vec<u8>, JsError> {
    research_result_info(researcher_tenant, query).map_err(js_error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use platform_crypto::{HPKE_ENVELOPE_MAGIC, TenantKeypair};

    #[test]
    fn sealed_envelope_opens_with_the_recipient_key() {
        let keypair = TenantKeypair::generate();
        let info = steward_upload_info("t", "d", "o").expect("info");
        let envelope =
            seal_envelope(&keypair.public_key().to_raw(), &info, b"rows".to_vec()).expect("seal");
        assert_eq!(envelope[..4], HPKE_ENVELOPE_MAGIC);
        let opened = keypair.open_envelope(&info, &envelope).expect("open");
        assert_eq!(opened.expose(), b"rows");
    }

    #[test]
    fn open_round_trips_with_the_raw_private_key() {
        let keypair = TenantKeypair::generate();
        let raw = keypair.to_private_key_bytes().expose().to_vec();
        let public = public_key_from_private_key(raw.clone()).expect("public key");
        assert_eq!(public, keypair.public_key().to_raw());
        let info = research_result_info("t", "q").expect("info");
        let envelope = seal_envelope(&public, &info, b"result".to_vec()).expect("seal");
        assert_eq!(
            open_envelope(raw.clone(), &info, &envelope).expect("open"),
            b"result"
        );
        assert!(matches!(
            open_envelope(raw, b"other", &envelope),
            Err(CryptoError::OpenFailed)
        ));
    }

    #[test]
    fn open_refuses_a_malformed_private_key() {
        for raw in [vec![], vec![1u8; 31], vec![1u8; 33]] {
            assert!(matches!(
                open_envelope(raw.clone(), b"i", b"HPK1"),
                Err(CryptoError::InvalidKeyLength)
            ));
            assert!(matches!(
                public_key_from_private_key(raw),
                Err(CryptoError::InvalidKeyLength)
            ));
        }
    }

    #[test]
    fn seal_refuses_a_malformed_public_key() {
        for raw in [&[][..], &[1u8; 31], &[1u8; 33]] {
            assert!(matches!(
                seal_envelope(raw, b"i", b"x".to_vec()),
                Err(CryptoError::InvalidPublicKey)
            ));
        }
    }

    #[test]
    fn info_builders_refuse_empty_and_separator_fields() {
        assert!(steward_upload_info("", "d", "o").is_err());
        assert!(steward_upload_info("t", "d|x", "o").is_err());
        assert!(connector_object_info("t", "c", "").is_err());
        assert!(snapshot_manifest_info("t|", "c", "v").is_err());
        assert!(research_result_info("t", "q|").is_err());
    }
}
