//! Process shutdown on Ctrl-C or SIGTERM, shared by every service binary.

#[cfg(unix)]
use tokio::signal::unix::{SignalKind, signal};

/// Completes on Ctrl-C or SIGTERM, which is how a VM or container runtime
/// stops the service. Call it before serving or scheduling work: the SIGTERM
/// handler is installed then, so a stop request that arrives during startup
/// is not lost.
#[cfg(unix)]
pub fn shutdown_signal() -> std::io::Result<impl std::future::Future<Output = ()>> {
    let mut terminate = signal(SignalKind::terminate())?;
    Ok(async move {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => tracing::info!("Ctrl-C received, shutting down"),
            _ = terminate.recv() => tracing::info!("SIGTERM received, shutting down"),
        }
    })
}

#[cfg(not(unix))]
pub fn shutdown_signal() -> std::io::Result<impl std::future::Future<Output = ()>> {
    Ok(async {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("Ctrl-C received, shutting down");
    })
}

#[cfg(all(test, unix))]
mod tests {
    use std::time::Duration;

    #[tokio::test]
    async fn sigterm_completes_the_shutdown_signal() {
        let mut shutdown = Box::pin(super::shutdown_signal().expect("install SIGTERM handler"));
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut shutdown)
                .await
                .is_err(),
            "completed before any signal"
        );

        // The handler is installed, so SIGTERM reaches it instead of ending
        // the test process.
        let status = std::process::Command::new("kill")
            .args(["-TERM", &std::process::id().to_string()])
            .status()
            .expect("run kill");
        assert!(status.success());

        tokio::time::timeout(Duration::from_secs(5), shutdown)
            .await
            .expect("SIGTERM completes the shutdown signal");
    }
}
