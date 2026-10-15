//! Standalone attestation-verifying key-release relying-party service (`P50`).
//!
//! Verifies 1184-byte binary SEV-SNP attestation reports (`ARK -> ASK -> VCEK`
//! chain, `MEASUREMENT`, `GuestPolicy`, `TcbVersion`, and 64-byte
//! `REPORT_DATA`) before wrapping tenant keys under HPKE to the enclave's
//! ephemeral public key.
//!
//! Environment:
//! - `KEY_RELEASE_BIND_ADDR`: bind address (default `127.0.0.1:8090`).
//! - `KEY_RELEASE_ARK_PUBKEY_B64`: base64 SEC1 P-384 public key of the trusted
//!   ARK root.
//! - `SIMULATED_SNP_SEED`: when `TEE_ATTESTATION_REQUIRED=false` and
//!   `KEY_RELEASE_ARK_PUBKEY_B64` is unset, deterministically derives the
//!   simulated ARK public key so `enclave-api` and `key-release-service` share
//!   the same synthetic root of trust in local Docker.
//! - `KEY_RELEASE_EXPECTED_MEASUREMENT_HEX`: optional 96-char hex (48-byte)
//!   expected `MEASUREMENT` allowlist override.
//! - `KEY_RELEASE_EXPECTED_CONFIG_DIGEST_HEX`: optional 64-char hex (32-byte)
//!   expected `config_digest` in `REPORT_DATA`.
//! - `TEE_ATTESTATION_REQUIRED`: when `true` (default), pins the root as
//!   `TrustRoot::ProductionAmd` and requires hardware `TeePlatform::SevSnp`.
//!   When `false`, pins `TrustRoot::Simulated` for the local simulated TEE.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use platform_api::key_release::KeyReleaseRelyingParty;
use platform_enclave::{
    AttestationVerifier, MEASUREMENT_BYTES, SimulatedSnp, SimulatedSnpConfig, TrustRoot,
    decode_hex_array,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    platform_telemetry::init_from_env();

    let bind_addr: SocketAddr = std::env::var("KEY_RELEASE_BIND_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8090".to_owned())
        .parse()?;

    let require_hardware = match std::env::var("TEE_ATTESTATION_REQUIRED") {
        Ok(raw) => !matches!(
            raw.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "off" | "no"
        ),
        Err(_) => true,
    };

    let ark_sec1 = match std::env::var("KEY_RELEASE_ARK_PUBKEY_B64") {
        Ok(ark_b64) if !ark_b64.trim().is_empty() => B64.decode(ark_b64.trim())?,
        _ if !require_hardware => {
            let seed = std::env::var("SIMULATED_SNP_SEED").map_err(|_| {
                anyhow::anyhow!(
                    "either KEY_RELEASE_ARK_PUBKEY_B64 or SIMULATED_SNP_SEED must be set (fail closed)"
                )
            })?;
            let trimmed = seed.trim();
            if trimmed.is_empty() {
                anyhow::bail!("SIMULATED_SNP_SEED must not be empty (fail closed)");
            }
            let sim = SimulatedSnp::with_seed_and_config(
                trimmed.as_bytes(),
                SimulatedSnpConfig::default(),
            );
            sim.cert_chain().ark.public_key_sec1.clone()
        }
        _ => {
            anyhow::bail!(
                "KEY_RELEASE_ARK_PUBKEY_B64 must be set when TEE_ATTESTATION_REQUIRED=true (fail closed)"
            );
        }
    };

    let trust_root = if require_hardware {
        TrustRoot::ProductionAmd {
            ark_public_keys_sec1: vec![ark_sec1],
        }
    } else {
        TrustRoot::Simulated {
            ark_public_key_sec1: ark_sec1,
        }
    };

    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mut policy = SimulatedSnp::default_policy(now_unix);
    if let Ok(raw_meas) = std::env::var("KEY_RELEASE_EXPECTED_MEASUREMENT_HEX") {
        let trimmed = raw_meas.trim();
        if !trimmed.is_empty() {
            let m = decode_hex_array::<MEASUREMENT_BYTES>(trimmed).ok_or_else(|| {
                anyhow::anyhow!(
                    "KEY_RELEASE_EXPECTED_MEASUREMENT_HEX must be exactly 96 hex chars (48 bytes)"
                )
            })?;
            policy.expected_measurements = vec![m];
        }
    }

    let verifier = AttestationVerifier::new(trust_root, policy);
    let mut relying_party = KeyReleaseRelyingParty::new(verifier, require_hardware);
    if let Ok(raw_cfg) = std::env::var("KEY_RELEASE_EXPECTED_CONFIG_DIGEST_HEX") {
        let trimmed = raw_cfg.trim();
        if !trimmed.is_empty() {
            let cfg_digest = decode_hex_array::<32>(trimmed).ok_or_else(|| {
                anyhow::anyhow!(
                    "KEY_RELEASE_EXPECTED_CONFIG_DIGEST_HEX must be exactly 64 hex chars (32 bytes)"
                )
            })?;
            relying_party = relying_party.with_expected_config_digest(cfg_digest);
        }
    }
    let relying_party = Arc::new(relying_party);

    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    tracing::info!(
        %bind_addr,
        require_hardware,
        "key-release relying party listening"
    );
    axum::serve(listener, relying_party.router()).await?;
    Ok(())
}
