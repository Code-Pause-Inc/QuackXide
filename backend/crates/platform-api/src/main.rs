//! platform-api binary: config → telemetry → state (`platform_api::wiring`) → serve.

use platform_api::build_apps;
use platform_config::PlatformConfig;
use platform_telemetry::{AuditKind, security_audit_event};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = PlatformConfig::from_env()?;
    // Before `build_state`, so its warnings and any refusal's audit event
    // are emitted.
    platform_telemetry::init_from_env();

    let state = platform_api::wiring::build_state(config).await?;

    security_audit_event(AuditKind::ServiceStart, None, "ok", "platform-api booting");

    let bind_addr = state.config.server.bind_addr;
    let metrics_addr = state.config.server.metrics_bind_addr;
    let (app, metrics_app) = build_apps(state);

    let shutdown = platform_telemetry::shutdown_signal()?;

    // Loopback only (enforced by platform-config), for a scraper on this host.
    let metrics_listener = tokio::net::TcpListener::bind(metrics_addr).await?;
    tracing::info!(%metrics_addr, "metrics listening");
    tokio::spawn(async move {
        if let Err(err) = axum::serve(metrics_listener, metrics_app).await {
            tracing::error!(error = %err, "metrics listener stopped");
        }
    });

    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    tracing::info!(%bind_addr, "platform-api listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await?;
    Ok(())
}
