//! DEV ONLY: the simulated TEE's key-release stand-in for Cloud KMS (ADR 0004).
//!
//! Verifies simulated Confidential Space tokens with the production
//! `TokenVerifier` before wrapping tenant keys under HPKE to the enclave's
//! ephemeral public key. Built only with the `dev` feature.
//!
//! Environment:
//! - `KEY_RELEASE_BIND_ADDR`: bind address (default `127.0.0.1:8090`).
//! - `SIM_ATTESTATION_URL`: base URL of the `sim-attestation` service, whose
//!   `GET /jwks` supplies the token-signing keys (required).
//! - `SIM_ATTESTATION_ISSUER`: expected token issuer (default
//!   `http://sim-attestation:8070`).
//! - `KEY_RELEASE_ALLOWED_IMAGE_DIGEST`: image digest the release policy
//!   allows (default: the simulator's built-in digest).
//! - `KEY_RELEASE_EXPECTED_CONFIG_DIGEST_HEX`: optional 64-char hex (32-byte)
//!   expected deployment configuration digest.
//! - `TEE_ATTESTATION_REQUIRED`: must be `false`; the stand-in verifies
//!   simulated tokens only.

use std::net::SocketAddr;
use std::sync::Arc;

use platform_api::key_release::{HttpKeySource, KeyReleaseRelyingParty};
use platform_enclave::decode_hex_array;
use platform_enclave::simulated_token::{DEFAULT_SIM_ISSUER, SIMULATED_IMAGE_DIGEST};
use platform_enclave::token::ReleasePolicy;

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key)
        .ok()
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| default.to_owned())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    platform_telemetry::init_from_env();

    let required = env_or("TEE_ATTESTATION_REQUIRED", "true");
    if !matches!(
        required.to_ascii_lowercase().as_str(),
        "0" | "false" | "off" | "no"
    ) {
        anyhow::bail!(
            "the key-release stand-in verifies simulated tokens only (ADR 0004); \
             set TEE_ATTESTATION_REQUIRED=false"
        );
    }

    let bind_addr: SocketAddr = env_or("KEY_RELEASE_BIND_ADDR", "127.0.0.1:8090").parse()?;
    let sim_url = env_or("SIM_ATTESTATION_URL", "");
    if sim_url.is_empty() {
        anyhow::bail!("SIM_ATTESTATION_URL must be set (fail closed)");
    }
    let policy = ReleasePolicy {
        allowed_image_digests: vec![env_or(
            "KEY_RELEASE_ALLOWED_IMAGE_DIGEST",
            SIMULATED_IMAGE_DIGEST,
        )],
    };
    let mut relying_party = KeyReleaseRelyingParty::new(
        Arc::new(HttpKeySource::new(&sim_url)),
        env_or("SIM_ATTESTATION_ISSUER", DEFAULT_SIM_ISSUER),
        policy,
    );
    let cfg = env_or("KEY_RELEASE_EXPECTED_CONFIG_DIGEST_HEX", "");
    if !cfg.is_empty() {
        let digest = decode_hex_array::<32>(&cfg).ok_or_else(|| {
            anyhow::anyhow!(
                "KEY_RELEASE_EXPECTED_CONFIG_DIGEST_HEX must be exactly 64 hex chars (32 bytes)"
            )
        })?;
        relying_party = relying_party.with_expected_config_digest(digest);
    }

    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    tracing::info!(%bind_addr, "key-release stand-in listening");
    axum::serve(listener, Arc::new(relying_party).router()).await?;
    Ok(())
}
