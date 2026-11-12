//! Confidential connector sync worker.
//!
//! In production it runs in a Confidential VM with GCS as the vault, and
//! production mode (ADR 0009) refuses to start while the only sources are
//! the embedded fixtures. In development (`APP_ENV=development`) it runs the
//! pipeline against those fixtures for one demo tenant, set via
//! `DEMO_TENANT_ID` and `DEMO_TENANT_PUBLIC_KEY_B64` (base64 raw X25519).
//! Without them it uses an ephemeral keypair whose ciphertext nobody can
//! open.

use platform_config::PlatformConfig;
use platform_connectors::startup;
use platform_connectors::worker::SyncScheduler;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = PlatformConfig::from_env()?;
    platform_telemetry::init_from_env();
    let startup::WorkerStartup {
        pipeline,
        jobs,
        interval,
    } = startup::build(&config)?;

    tracing::info!(interval_secs = interval.as_secs(), "scheduler starting");
    let shutdown = platform_telemetry::shutdown_signal()?;
    let (stop, stop_rx) = tokio::sync::watch::channel(false);
    tokio::join!(
        SyncScheduler::new(pipeline, jobs).run(interval, stop_rx),
        async {
            shutdown.await;
            // Lets the sync in flight commit before the scheduler returns.
            let _ = stop.send(true);
        },
    );
    Ok(())
}
