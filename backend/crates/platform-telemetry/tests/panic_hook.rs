//! The panic hook keeps a panic's message out of stderr and the logs. A
//! panic hook and the stdout subscriber are process-wide, so this test runs
//! its own binary again as a child that panics, and reads what it wrote.

use std::process::Command;

/// Appears only in the panic's message.
const MARKER: &str = "panicmarker9c41e2";
const CHILD: &str = "PANIC_HOOK_TEST_CHILD";
const TEST: &str = "a_panic_logs_its_location_and_never_its_message";

#[test]
fn a_panic_logs_its_location_and_never_its_message() {
    if std::env::var_os(CHILD).is_some() {
        platform_telemetry::init_from_env();
        // In a thread of its own, so the test harness does not report it.
        let panicked = std::thread::spawn(|| panic!("{MARKER}")).join().is_err();
        assert!(panicked);
        return;
    }
    let output = Command::new(std::env::current_exe().expect("test binary"))
        .args(["--exact", TEST, "--nocapture", "--test-threads=1"])
        .env(CHILD, "1")
        .env("RUST_LOG", "trace")
        .output()
        .expect("child runs");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "child failed:\n{stdout}\n{stderr}");
    for (name, stream) in [("stdout", &stdout), ("stderr", &stderr)] {
        assert!(
            !stream.contains(MARKER),
            "{name} holds the panic message:\n{stream}"
        );
    }
    let event = stdout
        .lines()
        .find(|line| line.contains("a thread panicked"))
        .unwrap_or_else(|| panic!("no panic event in stdout:\n{stdout}"));
    assert!(event.contains("\"level\":\"ERROR\""), "{event}");
    assert!(event.contains("tests/panic_hook.rs:"), "{event}");
}
