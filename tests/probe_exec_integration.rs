//! Integration test for the exec-first probe building blocks against a real
//! container. Requires a running Docker daemon, so it is `#[ignore]` by default.
//!
//! Run manually with:
//!   cargo test --test probe_exec_integration -- --ignored --nocapture
#![cfg(feature = "docker")]

use std::process::Command;

fn docker(args: &[&str]) -> std::process::Output {
    Command::new("docker")
        .args(args)
        .output()
        .expect("failed to run docker")
}

/// Removes the test container on drop, even if an assertion panics.
struct Cleanup(&'static str);
impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = docker(&["rm", "-f", self.0]);
    }
}

#[tokio::test]
#[ignore = "requires a running Docker daemon"]
async fn exec_first_probe_resolves_by_label_and_reaches_localhost() {
    const CONTAINER: &str = "stacker-probe-exec-it";
    let _ = docker(&["rm", "-f", CONTAINER]);

    // A container whose Docker Compose service name (== container name) does NOT
    // equal the app code, but carries the stacker label with the app code —
    // exactly the generated-`app`-service situation the fix targets.
    let start = docker(&[
        "run",
        "-d",
        "--name",
        CONTAINER,
        "-l",
        "my.stacker.service=probeapp",
        "nginx:alpine",
    ]);
    assert!(
        start.status.success(),
        "failed to start container: {}",
        String::from_utf8_lossy(&start.stderr)
    );
    let _cleanup = Cleanup(CONTAINER);

    // Let nginx come up.
    tokio::time::sleep(std::time::Duration::from_millis(800)).await;

    // 1) Resolution: app_code "probeapp" resolves to the container via the
    //    my.stacker.service label, even though the container name differs.
    let resolved = status_panel::agent::docker::resolve_container_name("probeapp")
        .await
        .expect("resolve_container_name");
    assert_eq!(
        resolved, CONTAINER,
        "app code should resolve to the container via my.stacker.service label"
    );

    // 2) Exec-first probe: the same command shape the probe builds, run inside
    //    the container's own namespace — reaches the app on localhost with no
    //    shared network.
    let cmd = "if command -v curl >/dev/null 2>&1; then curl -sf -m 5 'http://localhost:80/' 2>/dev/null || true; \
               elif command -v wget >/dev/null 2>&1; then wget -q -T 5 -O - 'http://localhost:80/' 2>/dev/null || true; fi";
    let (exit_code, stdout, stderr) =
        status_panel::agent::docker::exec_in_container_with_output_resolved(&resolved, cmd)
            .await
            .expect("exec_in_container_with_output_resolved");

    assert_eq!(exit_code, 0, "exec exit code (stderr: {stderr})");
    assert!(
        stdout.to_lowercase().contains("nginx"),
        "expected the nginx welcome page from localhost, got: {stdout}"
    );
}
