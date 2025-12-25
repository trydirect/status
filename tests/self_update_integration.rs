use status_panel::commands::{start_update_job, get_update_status, UpdatePhase};
use tokio::time::{sleep, Duration};
use std::sync::Arc;
use tokio::sync::RwLock;
use std::collections::HashMap;
use sha2::{Digest, Sha256};

// Integration test covering download + optional sha256 verification.
#[tokio::test]
async fn start_update_job_downloads_and_verifies() {
    let binary_bytes = b"hello-update";
    // Compute sha256 for verification
    let mut hasher = Sha256::new();
    hasher.update(binary_bytes);
    let expected = format!("{:x}", hasher.finalize());

    // Mock server hosting the binary
    let server = mockito::Server::new_async().await;
    let mock = server
        .mock("GET", "/releases/1.2.3/status-linux-x86_64")
        .with_status(200)
        .with_body(binary_bytes.as_slice())
        .create_async()
        .await;

    // Point updater to the mock server
    std::env::set_var("UPDATE_SERVER_URL", server.url());
    std::env::set_var("UPDATE_EXPECTED_SHA256", expected);

    let jobs = Arc::new(RwLock::new(HashMap::new()));
    let job_id = start_update_job(jobs.clone(), Some("1.2.3".to_string()))
        .await
        .expect("job should start");

    // Wait for completion
    let mut phase = UpdatePhase::Pending;
    for _ in 0..30 {
        if let Some(st) = get_update_status(jobs.clone(), &job_id).await {
            phase = st.phase;
            if matches!(phase, UpdatePhase::Completed | UpdatePhase::Failed(_)) { break; }
        }
        sleep(Duration::from_millis(100)).await;
    }

    mock.assert_async().await;
    match phase {
        UpdatePhase::Completed => {},
        UpdatePhase::Failed(msg) => panic!("update failed: {}", msg),
        other => panic!("unexpected phase: {:?}", other),
    }

    // Temp file should exist
    let tmp_path = format!("/tmp/status-panel.{}.bin", job_id);
    let data = tokio::fs::read(&tmp_path).await.expect("temp binary exists");
    assert_eq!(data, binary_bytes);

    // Cleanup temp file
    let _ = tokio::fs::remove_file(&tmp_path).await;
}
