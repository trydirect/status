//! End-to-end tests for the native `backup` command (WS-1): the agent runs the
//! plan's `argv` as a child process and streams the archive to a mocked
//! backup-storage backend (mockito — the mock library this repo uses).
//!
//! Contract: `config/shared-fixtures/api-contracts/backups-storage.json`.

use std::sync::OnceLock;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use status_panel::commands::backup::{self, BackupCommand};
use status_panel::commands::stacker::parse_stacker_command;
use status_panel::transport::Command as AgentCommand;

/// Env manipulation is process-global: serialize the tests that read/write it.
/// Tokio's Mutex keeps the guard legal to hold across `.await` points.
async fn env_lock() -> tokio::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await
}

fn set_env(name: &str, value: &str) {
    std::env::set_var(name, value);
}

fn agent_command(params: Value) -> AgentCommand {
    AgentCommand {
        id: "cmd-1".to_string(),
        command_id: "cmd-1".to_string(),
        name: "backup".to_string(),
        params,
        deployment_hash: Some("hash-1".to_string()),
        app_code: None,
    }
}

/// Parse + normalize + validate exactly like the daemon does.
fn parse_backup(params: Value) -> BackupCommand {
    let parsed = parse_stacker_command(&agent_command(params))
        .expect("backup command must parse")
        .expect("command must be recognized as a stacker command");
    match parsed {
        status_panel::commands::stacker::StackerCommand::Backup(cmd) => cmd,
        other => panic!("expected Backup command, got {:?}", other),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn dump_params(argv: Vec<&str>, upload: Value) -> Value {
    json!({
        "action": "dump",
        "run_id": 123,
        "timeout": 60,
        "plan": {
            "argv": argv,
            "upload": upload,
        }
    })
}

fn multipart_upload(url: &str) -> Value {
    json!({
        "url": url,
        "body": {
            "type": "multipart",
            "file_field": "file",
            "fields": [{"name": "device_id", "value": "$AGENT_ID"}]
        },
        "auth": {"type": "none"},
        "headers": [["X-Backup-Filename", "$BACKUP_FILENAME"]]
    })
}

// ---------------------------------------------------------------------------
// Dump
// ---------------------------------------------------------------------------

#[tokio::test]
async fn dump_streams_multipart_upload_and_reports_size_checksum_and_file_id() {
    let _guard = env_lock().await;
    set_env("AGENT_ID", "agent-9");

    let mut server = mockito::Server::new_async().await;
    let upload_mock = server
        .mock("POST", "/upload")
        .match_header(
            "x-backup-filename",
            mockito::Matcher::Regex(r"^run-123-\d{8}T\d{6}Z$".to_string()),
        )
        .match_body(mockito::Matcher::AllOf(vec![
            mockito::Matcher::Regex("name=\"device_id\"".to_string()),
            mockito::Matcher::Regex("agent-9".to_string()),
            mockito::Matcher::Regex("name=\"file\"".to_string()),
            mockito::Matcher::Regex("hello-archive".to_string()),
        ]))
        .with_status(200)
        .with_body(r#"{"file_id":"f-42"}"#)
        .expect(1)
        .create_async()
        .await;

    let params = dump_params(
        vec!["printf", "hello-archive"],
        multipart_upload(&format!("{}/upload", server.url())),
    );
    let cmd = parse_backup(params);
    let result = backup::handle_backup(&agent_command(json!({})), &cmd)
        .await
        .unwrap();

    upload_mock.assert_async().await;
    assert_eq!(result.status, "success");
    assert!(
        result.error.is_none(),
        "unexpected error: {:?}",
        result.error
    );
    let body = result.result.expect("result body");
    assert_eq!(body["type"], "backup");
    assert_eq!(body["action"], "dump");
    assert_eq!(body["run_id"], 123);
    assert_eq!(body["size_bytes"], 13);
    assert_eq!(
        body["checksum"],
        hex_encode(&Sha256::digest(b"hello-archive"))
    );
    assert_eq!(body["remote_file_id"], "f-42");
}

#[tokio::test]
async fn dump_with_raw_body_streams_the_archive_as_the_request_body() {
    let _guard = env_lock().await;

    let mut server = mockito::Server::new_async().await;
    let upload_mock = server
        .mock("POST", "/upload")
        .match_header("content-type", "application/octet-stream")
        .match_body(mockito::Matcher::Exact("raw-archive".to_string()))
        .with_status(200)
        .with_body(r#"{"file_id":"f-7"}"#)
        .expect(1)
        .create_async()
        .await;

    let upload = json!({
        "url": format!("{}/upload", server.url()),
        "body": {"type": "raw"},
        "auth": {"type": "none"},
        "headers": []
    });
    let params = dump_params(vec!["printf", "raw-archive"], upload);
    let cmd = parse_backup(params);
    let result = backup::handle_backup(&agent_command(json!({})), &cmd)
        .await
        .unwrap();

    upload_mock.assert_async().await;
    assert_eq!(result.status, "success");
    let body = result.result.expect("result body");
    assert_eq!(body["size_bytes"], 11);
    assert_eq!(body["remote_file_id"], "f-7");
}

#[tokio::test]
async fn dump_with_client_credentials_exchanges_a_token_and_authenticates() {
    let _guard = env_lock().await;
    set_env("BACKUP_E2E_CLIENT_ID", "cid-e2e");
    set_env("BACKUP_E2E_CLIENT_SECRET", "sec-e2e");

    let mut server = mockito::Server::new_async().await;
    let token_mock = server
        .mock("POST", "/oauth/v2/token")
        .match_body(mockito::Matcher::Regex("client_id=cid-e2e".to_string()))
        .with_status(200)
        .with_body(r#"{"access_token":"tok-e2e","token_type":"Bearer"}"#)
        .expect(1)
        .create_async()
        .await;
    let upload_mock = server
        .mock("POST", "/upload")
        .match_header("authorization", "Bearer tok-e2e")
        .with_status(200)
        .with_body(r#"{"file_id":"f-cc"}"#)
        .expect(1)
        .create_async()
        .await;

    let upload = json!({
        "url": format!("{}/upload", server.url()),
        "body": {"type": "raw"},
        "auth": {
            "type": "client_credentials",
            "token_url": format!("{}/oauth/v2/token", server.url()),
            "client_id_env": "BACKUP_E2E_CLIENT_ID",
            "client_secret_env": "BACKUP_E2E_CLIENT_SECRET",
            "scope": "openid"
        },
        "headers": []
    });
    let params = dump_params(vec!["printf", "cc"], upload);
    let cmd = parse_backup(params);
    let result = backup::handle_backup(&agent_command(json!({})), &cmd)
        .await
        .unwrap();

    token_mock.assert_async().await;
    upload_mock.assert_async().await;
    assert_eq!(result.status, "success");
    let body = result.result.expect("result body");
    assert_eq!(body["remote_file_id"], "f-cc");
}

#[tokio::test]
async fn failed_dump_reports_failure_with_partial_upload_stats() {
    let _guard = env_lock().await;
    set_env("AGENT_ID", "agent-9");

    let mut server = mockito::Server::new_async().await;
    let upload_mock = server
        .mock("POST", "/upload")
        .with_status(200)
        .with_body(r#"{"file_id":"f-partial"}"#)
        .expect(1)
        .create_async()
        .await;

    // `false` exits non-zero: the archive is invalid even though the upload
    // leg returned a file id — the run must be reported failed (with the
    // remote file id so the partial file can be cleaned up).
    let params = dump_params(
        vec!["false"],
        multipart_upload(&format!("{}/upload", server.url())),
    );
    let cmd = parse_backup(params);
    let result = backup::handle_backup(&agent_command(json!({})), &cmd)
        .await
        .unwrap();

    upload_mock.assert_async().await;
    assert_eq!(result.status, "failed");
    assert!(result.error.as_deref().unwrap_or("").contains("exited"));
    let errors = result.errors.expect("errors entry required");
    assert_eq!(errors[0].code, "backup_failed");
    let body = result.result.expect("result body");
    // Stacker's run lifecycle reads `result.error` when marking the run failed.
    assert!(body["error"].as_str().unwrap().contains("exited"));
    assert_eq!(body["remote_file_id"], "f-partial");
    assert_eq!(body["size_bytes"], 0);
}

#[tokio::test]
async fn dump_timeout_reports_timeout_status_and_kills_the_process() {
    let _guard = env_lock().await;

    let server = mockito::Server::new_async().await;

    let params = json!({
        "action": "dump",
        "run_id": 5,
        "timeout": 1,
        "plan": {
            "argv": ["sleep", "30"],
            "upload": {
                "url": format!("{}/upload", server.url()),
                "body": {"type": "raw"},
                "auth": {"type": "none"},
                "headers": []
            }
        }
    });
    let cmd = parse_backup(params);
    let started = std::time::Instant::now();
    let result = backup::handle_backup(&agent_command(json!({})), &cmd)
        .await
        .unwrap();

    assert_eq!(result.status, "timeout");
    assert!(started.elapsed() < std::time::Duration::from_secs(20));
    assert!(result.error.as_deref().unwrap_or("").contains("timed out"));
    let errors = result.errors.expect("errors entry required");
    assert_eq!(errors[0].code, "backup_timeout");
    let body = result.result.expect("result body");
    assert_eq!(body["run_id"], 5);
}

// ---------------------------------------------------------------------------
// Restore
// ---------------------------------------------------------------------------

#[tokio::test]
async fn restore_streams_the_download_into_the_process_and_reports_bytes() {
    let _guard = env_lock().await;

    let mut server = mockito::Server::new_async().await;
    let download_mock = server
        .mock("GET", "/upload/files/f-1")
        .match_header("authorization", "Bearer tok-restore")
        .with_status(200)
        .with_body("RESTORED-BYTES")
        .expect(1)
        .create_async()
        .await;

    let params = json!({
        "action": "restore",
        "run_id": 7,
        "timeout": 60,
        "plan": {
            "argv": ["cat"],
            "download": {
                "url": format!("{}/upload/files/f-1", server.url()),
                "auth": {"type": "bearer", "token_env": "BACKUP_E2E_TOKEN"},
                "headers": []
            }
        }
    });
    set_env("BACKUP_E2E_TOKEN", "tok-restore");
    let cmd = parse_backup(params);
    let result = backup::handle_backup(&agent_command(json!({})), &cmd)
        .await
        .unwrap();

    download_mock.assert_async().await;
    assert_eq!(result.status, "success");
    assert!(
        result.error.is_none(),
        "unexpected error: {:?}",
        result.error
    );
    let body = result.result.expect("result body");
    assert_eq!(body["action"], "restore");
    assert_eq!(body["run_id"], 7);
    assert_eq!(body["size_bytes"], 14);
    // The download carries no checksum: the agent must not claim verification.
    assert_eq!(body["integrity_verified"], false);
}

#[tokio::test]
async fn restore_with_a_failing_download_reports_failure() {
    let _guard = env_lock().await;

    let mut server = mockito::Server::new_async().await;
    let download_mock = server
        .mock("GET", "/upload/files/f-missing")
        .with_status(404)
        .with_body("gone")
        .expect(1)
        .create_async()
        .await;

    let params = json!({
        "action": "restore",
        "run_id": 8,
        "timeout": 60,
        "plan": {
            "argv": ["cat"],
            "download": {
                "url": format!("{}/upload/files/f-missing", server.url()),
                "auth": {"type": "none"},
                "headers": []
            }
        }
    });
    let cmd = parse_backup(params);
    let result = backup::handle_backup(&agent_command(json!({})), &cmd)
        .await
        .unwrap();

    download_mock.assert_async().await;
    assert_eq!(result.status, "failed");
    assert!(result
        .error
        .as_deref()
        .unwrap_or("")
        .contains("download rejected"));
}
