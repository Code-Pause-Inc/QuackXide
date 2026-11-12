//! DEV ONLY: the simulated attestation service. It plays Google's part for
//! the simulated TEE: signs Confidential Space-shaped tokens with a throwaway
//! key and publishes the key set (ADR 0004). Built only with the `dev`
//! feature.
//!
//! Environment:
//! - `SIM_ATTESTATION_BIND_ADDR`: bind address (default `127.0.0.1:8070`).
//! - `SIM_ATTESTATION_ISSUER`: token issuer (default
//!   `http://sim-attestation:8070`).
//! - `SIM_TOKEN_HWMODEL`, `SIM_TOKEN_DBGSTAT`, `SIM_TOKEN_IMAGE_DIGEST`:
//!   override the claims, to test refusals.

use std::net::SocketAddr;
use std::sync::Arc;

use platform_api::key_release::sim_attestation_router;
use platform_enclave::simulated_token::{DEFAULT_SIM_ISSUER, SimulatedClaims, TokenSigner};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    platform_telemetry::init_from_env();

    let bind_addr: SocketAddr = std::env::var("SIM_ATTESTATION_BIND_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8070".to_owned())
        .parse()?;
    let issuer = std::env::var("SIM_ATTESTATION_ISSUER")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_SIM_ISSUER.to_owned());
    let signer = Arc::new(TokenSigner::generate(issuer, SimulatedClaims::from_env()));

    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    tracing::info!(%bind_addr, "sim-attestation listening (dev only)");
    axum::serve(listener, sim_attestation_router(signer)).await?;
    Ok(())
}
