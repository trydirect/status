use sha2::{Digest, Sha256};
use status_panel::commands::{get_update_status, start_update_job, UpdatePhase};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::{Mutex, OnceLock};
use tokio::sync::RwLock;
use tokio::time::{sleep, Duration};

// ── Env-var serialization guard ─────────────────────────────────────────────

static TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
fn lock_tests() -> std::sync::MutexGuard<'static, ()> {
    match TEST_LOCK.get_or_init(|| Mutex::new(())).lock() {
        Ok(g) => g,
        Err(e) => e.into_inner(),
    }
}

/// RAII guard that restores env vars on drop (even on panic).
struct EnvGuard {
    vars: Vec<(String, Option<String>)>,
}

impl EnvGuard {
    fn new(keys: &[&str]) -> Self {
        let vars = keys
            .iter()
            .map(|k| (k.to_string(), std::env::var(k).ok()))
            .collect();
        Self { vars }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (key, original) in &self.vars {
            match original {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

/// Verify that HTTP update URLs are rejected with a clear error.
#[tokio::test]
async fn start_update_job_rejects_http_url() {
    let _g = lock_tests();
    let _env = EnvGuard::new(&["UPDATE_BINARY_URL", "UPDATE_EXPECTED_SHA256"]);

    let mut server = mockito::Server::new_async().await;
    let _mock = server
        .mock("GET", "/releases/1.2.3/status-linux-x86_64")
        .with_status(200)
        .with_body(b"hello-update".as_slice())
        .create_async()
        .await;

    // mockito uses http:// — our HTTPS enforcement should reject this
    std::env::set_var(
        "UPDATE_BINARY_URL",
        format!("{}/releases/1.2.3/status-linux-x86_64", server.url()),
    );
    std::env::set_var("UPDATE_EXPECTED_SHA256", "deadbeef");

    let jobs = Arc::new(RwLock::new(HashMap::new()));
    let job_id = start_update_job(jobs.clone(), Some("1.2.3".to_string()))
        .await
        .expect("job should start");

    let mut phase = UpdatePhase::Pending;
    for _ in 0..30 {
        if let Some(st) = get_update_status(jobs.clone(), &job_id).await {
            phase = st.phase;
            if matches!(phase, UpdatePhase::Completed | UpdatePhase::Failed(_)) {
                break;
            }
        }
        sleep(Duration::from_millis(100)).await;
    }

    match phase {
        UpdatePhase::Failed(msg) => {
            assert!(
                msg.contains("HTTPS"),
                "should mention HTTPS requirement, got: {}",
                msg
            );
        }
        other => panic!("expected Failed, got {:?}", other),
    }
}

/// Verify that an unreachable HTTPS URL fails at the download phase.
/// Mockito only serves HTTP, so we use a localhost URL that nothing listens on.
#[tokio::test]
async fn update_fails_when_download_unreachable() {
    let _g = lock_tests();
    let _env = EnvGuard::new(&["UPDATE_BINARY_URL", "UPDATE_EXPECTED_SHA256"]);

    let binary_bytes = b"hello-update";
    let mut hasher = Sha256::new();
    hasher.update(binary_bytes);
    let correct_sha = format!("{:x}", hasher.finalize());

    std::env::set_var(
        "UPDATE_BINARY_URL",
        "https://localhost:1/nonexistent-binary",
    );
    std::env::set_var("UPDATE_EXPECTED_SHA256", &correct_sha);

    let jobs = Arc::new(RwLock::new(HashMap::new()));
    let job_id = start_update_job(jobs.clone(), Some("1.0.0".to_string()))
        .await
        .expect("job should start");

    let mut phase = UpdatePhase::Pending;
    for _ in 0..50 {
        if let Some(st) = get_update_status(jobs.clone(), &job_id).await {
            phase = st.phase;
            if matches!(phase, UpdatePhase::Completed | UpdatePhase::Failed(_)) {
                break;
            }
        }
        sleep(Duration::from_millis(100)).await;
    }

    // Should fail because localhost:1 doesn't serve anything
    assert!(
        matches!(phase, UpdatePhase::Failed(_)),
        "expected failure for unreachable URL, got {:?}",
        phase
    );
}
