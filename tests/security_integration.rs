use axum::extract::{Path, State};
use axum::http::{Request, StatusCode};
use axum::routing::{get, post};
use axum::{body::Body, Json, Router};
use base64::{engine::general_purpose, Engine};
use hmac::{Hmac, Mac};
use http_body_util::BodyExt;
use mockito::{Matcher, Server};
use serde_json::json;
use serde_json::Value;
use sha2::Sha256;
use status_panel::agent::config::{Config, ReqData};
use status_panel::comms::local_api::{create_router, AppState};
use std::sync::Arc;
use std::sync::{Mutex, OnceLock};
use tokio::net::TcpListener;
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout, Duration};
use tower::ServiceExt; // for Router::oneshot
use uuid::Uuid;

static TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
fn lock_tests() -> std::sync::MutexGuard<'static, ()> {
    match TEST_LOCK.get_or_init(|| Mutex::new(())).lock() {
        Ok(g) => g,
        Err(e) => e.into_inner(),
    }
}

fn test_config() -> Arc<Config> {
    Arc::new(Config {
        domain: Some("test.example.com".to_string()),
        subdomains: None,
        apps_info: None,
        reqdata: ReqData {
            email: "test@example.com".to_string(),
        },
        ssl: Some("letsencrypt".to_string()),
        compose_agent_enabled: false,
        control_plane: None,
        firewall: None,
    })
}

fn router_with_env(agent_id: &str, token: &str, scopes: &str) -> Router {
    std::env::set_var("AGENT_ID", agent_id);
    std::env::set_var("AGENT_TOKEN", token);
    std::env::set_var("AGENT_SCOPES", scopes);
    std::env::set_var("RATE_LIMIT_PER_MIN", "1000");
    let state = Arc::new(AppState::new(test_config(), false, None));
    create_router(state)
}

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
struct TargetCaptureState {
    requests: Arc<AsyncMutex<Vec<(String, Value)>>>,
    status: StatusCode,
    response_body: Value,
}

fn sign_b64(token: &str, body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(token.as_bytes()).unwrap();
    mac.update(body);
    let sig = mac.finalize().into_bytes();
    general_purpose::STANDARD.encode(sig)
}

async fn post_with_sig(
    app: &Router,
    path: &str,
    agent_id: &str,
    token: &str,
    body_json: serde_json::Value,
    request_id: Option<String>,
) -> (StatusCode, bytes::Bytes) {
    let body_str = body_json.to_string();
    let ts = format!("{}", chrono::Utc::now().timestamp());
    let rid = request_id.unwrap_or_else(|| Uuid::new_v4().to_string());
    let sig = sign_b64(token, body_str.as_bytes());
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/json")
                .header("X-Agent-Id", agent_id)
                .header("X-Timestamp", ts)
                .header("X-Request-Id", rid)
                .header("X-Agent-Signature", sig)
                .body(Body::from(body_str))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, body)
}

async fn post_raw_with_sig(
    app: &Router,
    path: &str,
    agent_id: &str,
    token: &str,
    body: &str,
    timestamp: Option<String>,
    request_id: Option<String>,
) -> (StatusCode, bytes::Bytes) {
    let ts = timestamp.unwrap_or_else(|| format!("{}", chrono::Utc::now().timestamp()));
    let rid = request_id.unwrap_or_else(|| Uuid::new_v4().to_string());
    let sig = sign_b64(token, body.as_bytes());
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/json")
                .header("X-Agent-Id", agent_id)
                .header("X-Timestamp", ts)
                .header("X-Request-Id", rid)
                .header("X-Agent-Signature", sig)
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, body)
}

async fn capture_target_request(
    Path(path): Path<String>,
    State(state): State<TargetCaptureState>,
    Json(payload): Json<Value>,
) -> (StatusCode, Json<Value>) {
    state
        .requests
        .lock()
        .await
        .push((format!("/{}", path), payload));
    (state.status, Json(state.response_body.clone()))
}

async fn source_payload_handler(State(payload): State<Value>) -> Json<Value> {
    Json(payload)
}

async fn spawn_target_capture_server(
    status: StatusCode,
    response_body: Value,
) -> (
    String,
    Arc<AsyncMutex<Vec<(String, Value)>>>,
    JoinHandle<()>,
) {
    let requests = Arc::new(AsyncMutex::new(Vec::new()));
    let state = TargetCaptureState {
        requests: requests.clone(),
        status,
        response_body,
    };
    let app = Router::new()
        .route("/{path}", post(capture_target_request))
        .with_state(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (base_url, requests, handle)
}

async fn spawn_source_server(payload: Value) -> (String, JoinHandle<()>) {
    let app = Router::new()
        .route("/source", get(source_payload_handler))
        .with_state(payload);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (base_url, handle)
}

async fn wait_for_request_count(
    requests: &Arc<AsyncMutex<Vec<(String, Value)>>>,
    expected: usize,
) -> Vec<(String, Value)> {
    timeout(Duration::from_secs(5), async {
        loop {
            let snapshot = requests.lock().await.clone();
            if snapshot.len() >= expected {
                return snapshot;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("timed out waiting for captured requests")
}

#[tokio::test]
async fn execute_requires_signature_and_scope() {
    let _g = lock_tests();
    let app = router_with_env("agent-1", "secret-token", "commands:execute");

    // Missing signature
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/commands/execute")
                .header("content-type", "application/json")
                .header("X-Agent-Id", "agent-1")
                .body(Body::from(
                    json!({
                        "id": "cmd-1",
                        "command_id": "cmd-exec-1",
                        "name": "echo hello",
                        "params": {"timeout_secs": 2}
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // With signature & scope
    let (status, _) = post_with_sig(
        &app,
        "/api/v1/commands/execute",
        "agent-1",
        "secret-token",
        json!({"id": "cmd-2", "command_id": "cmd-exec-2", "name": "echo hi", "params": {"timeout_secs": 2}}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn replay_detection_returns_409() {
    let _g = lock_tests();
    let app = router_with_env("agent-1", "secret-token", "commands:execute");
    let rid = Uuid::new_v4().to_string();
    let path = "/api/v1/commands/execute";
    let body = json!({"id": "cmd-3", "command_id": "cmd-exec-3", "name": "echo hi", "params": {}});

    let (s1, _) = post_with_sig(
        &app,
        path,
        "agent-1",
        "secret-token",
        body.clone(),
        Some(rid.clone()),
    )
    .await;
    assert_eq!(s1, StatusCode::OK);

    let (s2, b2) = post_with_sig(&app, path, "agent-1", "secret-token", body, Some(rid)).await;
    assert_eq!(s2, StatusCode::CONFLICT);
    let msg: serde_json::Value = serde_json::from_slice(&b2).unwrap();
    assert_eq!(msg["error"], "replay detected");
}

#[tokio::test]
async fn rate_limit_returns_429() {
    let _g = lock_tests();
    // Set very low rate limit BEFORE creating router
    std::env::set_var("RATE_LIMIT_PER_MIN", "1");
    std::env::set_var("AGENT_ID", "agent-1");
    std::env::set_var("AGENT_TOKEN", "secret-token");
    std::env::set_var("AGENT_SCOPES", "commands:execute");
    let state = Arc::new(AppState::new(test_config(), false, None));
    let app = create_router(state);
    let path = "/api/v1/commands/execute";

    let (s1, _) = post_with_sig(
        &app,
        path,
        "agent-1",
        "secret-token",
        json!({"id":"r1","command_id":"cmd-rate-1","name":"echo a","params":{}}),
        None,
    )
    .await;
    assert_eq!(s1, StatusCode::OK);

    let (s2, _) = post_with_sig(
        &app,
        path,
        "agent-1",
        "secret-token",
        json!({"id":"r2","command_id":"cmd-rate-2","name":"echo b","params":{}}),
        None,
    )
    .await;
    assert_eq!(s2, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn scope_denied_returns_403() {
    let _g = lock_tests();
    // Do not include commands:execute
    let app = router_with_env("agent-1", "secret-token", "commands:report");
    let (status, body) = post_with_sig(
        &app,
        "/api/v1/commands/execute",
        "agent-1",
        "secret-token",
        json!({"id": "cmd-4", "command_id": "cmd-exec-4", "name": "echo hi", "params": {}}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let msg: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(msg["error"], "insufficient scope");
}

#[tokio::test]
async fn wait_can_require_signature() {
    let _g = lock_tests();
    // Enable signing for GET /wait
    std::env::set_var("WAIT_REQUIRE_SIGNATURE", "true");
    let app = router_with_env("agent-1", "secret-token", "commands:wait");

    // Missing signature should fail
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/commands/wait/session?timeout=1")
                .header("X-Agent-Id", "agent-1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Provide signature over empty body
    let ts = format!("{}", chrono::Utc::now().timestamp());
    let rid = Uuid::new_v4().to_string();
    let sig = sign_b64("secret-token", b"");
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/commands/wait/session?timeout=1")
                .header("X-Agent-Id", "agent-1")
                .header("X-Timestamp", ts)
                .header("X-Request-Id", rid)
                .header("X-Agent-Signature", sig)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    // No commands queued -> 204 No Content
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn given_signed_local_wait_request_when_queue_is_empty_then_local_wait_returns_no_content() {
    let _g = lock_tests();
    std::env::set_var("WAIT_REQUIRE_SIGNATURE", "true");
    let app = router_with_env("agent-1", "secret-token", "commands:wait");

    let ts = format!("{}", chrono::Utc::now().timestamp());
    let rid = Uuid::new_v4().to_string();
    let sig = sign_b64("secret-token", b"");
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/commands/wait/session?timeout=1")
                .header("X-Agent-Id", "agent-1")
                .header("X-Timestamp", ts)
                .header("X-Request-Id", rid)
                .header("X-Agent-Signature", sig)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn given_pipe_command_enqueued_when_agent_waits_and_reports_result_then_transport_path_delivers_and_records_execution(
) {
    let _g = lock_tests();
    std::env::set_var("WAIT_REQUIRE_SIGNATURE", "true");
    let app = router_with_env(
        "agent-1",
        "secret-token",
        "commands:enqueue,commands:wait,commands:report",
    );

    let (enqueue_status, enqueue_body) = post_with_sig(
        &app,
        "/api/v1/commands/enqueue",
        "agent-1",
        "secret-token",
        json!({
            "id": "queued-activate-pipe",
            "command_id": "queued-activate-pipe",
            "name": "activate_pipe",
            "deployment_hash": "dep-daemon",
            "params": {
                "pipe_instance_id": "pipe-daemon-1",
                "target_url": "https://example.com",
                "trigger_type": "manual"
            }
        }),
        None,
    )
    .await;
    assert_eq!(enqueue_status, StatusCode::ACCEPTED);
    let enqueue_payload: Value = serde_json::from_slice(&enqueue_body).unwrap();
    assert_eq!(enqueue_payload["queued"], true);

    let ts = format!("{}", chrono::Utc::now().timestamp());
    let rid = Uuid::new_v4().to_string();
    let sig = sign_b64("secret-token", b"");
    let wait_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/commands/wait/dep-daemon?timeout=1")
                .header("X-Agent-Id", "agent-1")
                .header("X-Timestamp", ts)
                .header("X-Request-Id", rid)
                .header("X-Agent-Signature", sig)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(wait_response.status(), StatusCode::OK);
    let waited_body = wait_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let waited_payload: Value = serde_json::from_slice(&waited_body).unwrap();
    assert_eq!(waited_payload["name"], "activate_pipe");
    assert_eq!(waited_payload["deployment_hash"], "dep-daemon");
    assert_eq!(
        waited_payload["params"]["pipe_instance_id"],
        "pipe-daemon-1"
    );

    let (report_status, report_body) = post_with_sig(
        &app,
        "/api/v1/commands/report",
        "agent-1",
        "secret-token",
        json!({
            "command_id": "queued-activate-pipe",
            "status": "success",
            "result": {
                "type": "activate_pipe",
                "pipe_instance_id": "pipe-daemon-1"
            },
            "completed_at": chrono::Utc::now().to_rfc3339(),
            "deployment_hash": "dep-daemon",
            "command_type": "activate_pipe",
            "executed_by": "status_panel"
        }),
        None,
    )
    .await;
    assert_eq!(report_status, StatusCode::OK);
    let report_payload: Value = serde_json::from_slice(&report_body).unwrap();
    assert_eq!(report_payload["accepted"], true);

    let metrics_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/diagnostics/commands")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(metrics_response.status(), StatusCode::OK);
    let metrics_body = metrics_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let metrics_payload: Value = serde_json::from_slice(&metrics_body).unwrap();
    assert_eq!(metrics_payload["status_panel_count"], 1);
    assert_eq!(metrics_payload["total_count"], 1);
    assert_eq!(metrics_payload["last_control_plane"], "status_panel");
}

#[tokio::test]
async fn given_registered_webhook_pipe_when_signed_webhook_arrives_then_payload_is_forwarded_to_target(
) {
    let _g = lock_tests();
    let mut server = Server::new_async().await;
    let target = server
        .mock("POST", "/pipe-target")
        .match_body(Matcher::Exact(r#"{"email":"webhook@try.direct"}"#.into()))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"accepted":true}"#)
        .create_async()
        .await;

    let app = router_with_env("agent-1", "secret-token", "commands:execute");

    let (activate_status, _) = post_with_sig(
        &app,
        "/api/v1/commands/execute",
        "agent-1",
        "secret-token",
        json!({
            "id": "cmd-activate-webhook",
            "command_id": "cmd-activate-webhook",
            "name": "activate_pipe",
            "params": {
                "deployment_hash": "dep-webhook",
                "pipe_instance_id": "pipe-webhook-1",
                "target_url": server.url(),
                "target_endpoint": "/pipe-target",
                "target_method": "POST",
                "field_mapping": { "email": "$.user.email" },
                "trigger_type": "webhook"
            }
        }),
        None,
    )
    .await;
    assert_eq!(activate_status, StatusCode::OK);

    let (webhook_status, webhook_body) = post_with_sig(
        &app,
        "/api/v1/pipes/webhook/dep-webhook/pipe-webhook-1",
        "agent-1",
        "secret-token",
        json!({
            "user": {
                "email": "webhook@try.direct"
            }
        }),
        None,
    )
    .await;

    assert_eq!(webhook_status, StatusCode::OK);
    let payload: serde_json::Value = serde_json::from_slice(&webhook_body).unwrap();
    assert_eq!(payload["status"], "success");
    assert_eq!(payload["result"]["target_response"]["transport"], "http");
    assert_eq!(payload["result"]["target_response"]["delivered"], true);
    target.assert_async().await;
}

#[tokio::test]
async fn given_signed_webhook_request_without_execute_scope_when_pipe_ingest_is_called_then_it_is_rejected(
) {
    let _g = lock_tests();
    let app = router_with_env("agent-1", "secret-token", "commands:report");

    let (status, body) = post_with_sig(
        &app,
        "/api/v1/pipes/webhook/dep-webhook/pipe-webhook-1",
        "agent-1",
        "secret-token",
        json!({"user": {"email": "webhook@try.direct"}}),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    let payload: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["error"], "insufficient scope");
}

#[tokio::test]
async fn given_signed_webhook_request_with_invalid_json_when_pipe_ingest_is_called_then_it_returns_bad_request(
) {
    let _g = lock_tests();
    let app = router_with_env("agent-1", "secret-token", "commands:execute");

    let (status, body) = post_raw_with_sig(
        &app,
        "/api/v1/pipes/webhook/dep-webhook/pipe-webhook-1",
        "agent-1",
        "secret-token",
        "{invalid-json",
        None,
        None,
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let payload: Value = serde_json::from_slice(&body).unwrap();
    assert!(payload["error"]
        .as_str()
        .unwrap_or_default()
        .contains("invalid webhook payload"));
}

#[tokio::test]
async fn given_replayed_signed_webhook_request_when_pipe_ingest_is_called_then_replay_is_blocked() {
    let _g = lock_tests();
    let app = router_with_env("agent-1", "secret-token", "commands:execute");
    let request_id = Uuid::new_v4().to_string();

    let (first_status, first_body) = post_with_sig(
        &app,
        "/api/v1/pipes/webhook/dep-webhook/missing-pipe",
        "agent-1",
        "secret-token",
        json!({"user": {"email": "webhook@try.direct"}}),
        Some(request_id.clone()),
    )
    .await;
    assert_eq!(first_status, StatusCode::OK);
    let first_payload: Value = serde_json::from_slice(&first_body).unwrap();
    assert_eq!(first_payload["status"], "failed");
    assert_eq!(first_payload["result"]["success"], false);

    let (second_status, second_body) = post_with_sig(
        &app,
        "/api/v1/pipes/webhook/dep-webhook/missing-pipe",
        "agent-1",
        "secret-token",
        json!({"user": {"email": "webhook@try.direct"}}),
        Some(request_id),
    )
    .await;
    assert_eq!(second_status, StatusCode::CONFLICT);
    let second_payload: Value = serde_json::from_slice(&second_body).unwrap();
    assert_eq!(second_payload["error"], "replay detected");
}

#[tokio::test]
async fn given_reactivated_manual_pipe_when_it_is_triggered_then_only_the_latest_target_receives_payload(
) {
    let _g = lock_tests();
    let (target_url, requests, target_handle) =
        spawn_target_capture_server(StatusCode::OK, json!({"accepted": true})).await;
    let app = router_with_env("agent-1", "secret-token", "commands:execute");

    let (first_activate_status, first_activate_body) = post_with_sig(
        &app,
        "/api/v1/commands/execute",
        "agent-1",
        "secret-token",
        json!({
            "id": "cmd-activate-first",
            "command_id": "cmd-activate-first",
            "name": "activate_pipe",
            "params": {
                "deployment_hash": "dep-reactivate",
                "pipe_instance_id": "pipe-reactivate-1",
                "target_url": target_url,
                "target_endpoint": "/first",
                "target_method": "POST",
                "field_mapping": { "email": "$.user.email" },
                "trigger_type": "manual"
            }
        }),
        None,
    )
    .await;
    assert_eq!(first_activate_status, StatusCode::OK);
    let first_activate_payload: Value = serde_json::from_slice(&first_activate_body).unwrap();
    assert_eq!(first_activate_payload["result"]["replaced"], false);
    assert_eq!(first_activate_payload["result"]["reactivated"], false);

    let (second_activate_status, second_activate_body) = post_with_sig(
        &app,
        "/api/v1/commands/execute",
        "agent-1",
        "secret-token",
        json!({
            "id": "cmd-activate-second",
            "command_id": "cmd-activate-second",
            "name": "activate_pipe",
            "params": {
                "deployment_hash": "dep-reactivate",
                "pipe_instance_id": "pipe-reactivate-1",
                "target_url": target_url,
                "target_endpoint": "/second",
                "target_method": "POST",
                "field_mapping": { "email": "$.user.email" },
                "trigger_type": "manual"
            }
        }),
        None,
    )
    .await;
    assert_eq!(second_activate_status, StatusCode::OK);
    let second_activate_payload: Value = serde_json::from_slice(&second_activate_body).unwrap();
    assert_eq!(second_activate_payload["result"]["replaced"], true);
    assert_eq!(second_activate_payload["result"]["reactivated"], true);

    let (trigger_status, trigger_body) = post_with_sig(
        &app,
        "/api/v1/commands/execute",
        "agent-1",
        "secret-token",
        json!({
            "id": "cmd-trigger-reactivate",
            "command_id": "cmd-trigger-reactivate",
            "name": "trigger_pipe",
            "params": {
                "deployment_hash": "dep-reactivate",
                "pipe_instance_id": "pipe-reactivate-1",
                "input_data": {
                    "user": {
                        "email": "replace@try.direct"
                    }
                }
            }
        }),
        None,
    )
    .await;
    assert_eq!(trigger_status, StatusCode::OK);
    let trigger_payload: Value = serde_json::from_slice(&trigger_body).unwrap();
    assert_eq!(trigger_payload["status"], "success");

    let captured = wait_for_request_count(&requests, 1).await;
    assert_eq!(
        captured,
        vec![(
            "/second".to_string(),
            json!({"email": "replace@try.direct"})
        )]
    );

    target_handle.abort();
}

#[tokio::test]
async fn given_poll_pipe_when_source_worker_fetches_payload_then_target_receives_it_and_deactivation_stops_future_deliveries(
) {
    let _g = lock_tests();
    std::env::set_var("PIPE_POLL_INTERVAL_SECS", "1");
    let (source_url, source_handle) =
        spawn_source_server(json!({"user": {"email": "poll@try.direct"}})).await;
    let (target_url, requests, target_handle) =
        spawn_target_capture_server(StatusCode::OK, json!({"accepted": true})).await;
    let app = router_with_env("agent-1", "secret-token", "commands:execute");

    let (activate_status, activate_body) = post_with_sig(
        &app,
        "/api/v1/commands/execute",
        "agent-1",
        "secret-token",
        json!({
            "id": "cmd-activate-poll",
            "command_id": "cmd-activate-poll",
            "name": "activate_pipe",
            "params": {
                "deployment_hash": "dep-poll",
                "pipe_instance_id": "pipe-poll-1",
                "source_endpoint": format!("{}/source", source_url),
                "source_method": "GET",
                "target_url": target_url,
                "target_endpoint": "/pipe-target",
                "target_method": "POST",
                "field_mapping": { "email": "$.user.email" },
                "trigger_type": "poll"
            }
        }),
        None,
    )
    .await;
    assert_eq!(activate_status, StatusCode::OK);
    let activate_payload: Value = serde_json::from_slice(&activate_body).unwrap();
    assert_eq!(activate_payload["status"], "success");

    let first_delivery = wait_for_request_count(&requests, 1).await;
    assert_eq!(
        first_delivery,
        vec![(
            "/pipe-target".to_string(),
            json!({"email": "poll@try.direct"})
        )]
    );

    let (deactivate_status, deactivate_body) = post_with_sig(
        &app,
        "/api/v1/commands/execute",
        "agent-1",
        "secret-token",
        json!({
            "id": "cmd-deactivate-poll",
            "command_id": "cmd-deactivate-poll",
            "name": "deactivate_pipe",
            "params": {
                "deployment_hash": "dep-poll",
                "pipe_instance_id": "pipe-poll-1"
            }
        }),
        None,
    )
    .await;
    assert_eq!(deactivate_status, StatusCode::OK);
    let deactivate_payload: Value = serde_json::from_slice(&deactivate_body).unwrap();
    assert_eq!(
        deactivate_payload["result"]["lifecycle"]["state"],
        "inactive"
    );

    sleep(Duration::from_millis(1300)).await;
    let final_snapshot = requests.lock().await.clone();
    assert_eq!(final_snapshot.len(), 1);

    std::env::remove_var("PIPE_POLL_INTERVAL_SECS");
    target_handle.abort();
    source_handle.abort();
}

#[tokio::test]
async fn given_registered_manual_pipe_when_target_returns_server_error_then_failed_delivery_shape_and_lifecycle_are_reported(
) {
    let _g = lock_tests();
    let (target_url, requests, target_handle) = spawn_target_capture_server(
        StatusCode::INTERNAL_SERVER_ERROR,
        json!({"error": "downstream unavailable"}),
    )
    .await;
    let app = router_with_env("agent-1", "secret-token", "commands:execute");

    let (activate_status, _) = post_with_sig(
        &app,
        "/api/v1/commands/execute",
        "agent-1",
        "secret-token",
        json!({
            "id": "cmd-activate-fail",
            "command_id": "cmd-activate-fail",
            "name": "activate_pipe",
            "params": {
                "deployment_hash": "dep-fail",
                "pipe_instance_id": "pipe-fail-1",
                "target_url": target_url,
                "target_endpoint": "/pipe-target",
                "target_method": "POST",
                "field_mapping": { "email": "$.user.email" },
                "trigger_type": "manual"
            }
        }),
        None,
    )
    .await;
    assert_eq!(activate_status, StatusCode::OK);

    let (trigger_status, trigger_body) = post_with_sig(
        &app,
        "/api/v1/commands/execute",
        "agent-1",
        "secret-token",
        json!({
            "id": "cmd-trigger-fail",
            "command_id": "cmd-trigger-fail",
            "name": "trigger_pipe",
            "params": {
                "deployment_hash": "dep-fail",
                "pipe_instance_id": "pipe-fail-1",
                "input_data": {
                    "user": {
                        "email": "failure@try.direct"
                    }
                }
            }
        }),
        None,
    )
    .await;
    assert_eq!(trigger_status, StatusCode::OK);
    let trigger_payload: Value = serde_json::from_slice(&trigger_body).unwrap();
    assert_eq!(trigger_payload["status"], "failed");
    assert_eq!(trigger_payload["result"]["success"], false);
    assert_eq!(
        trigger_payload["result"]["target_response"]["transport"],
        "http"
    );
    assert_eq!(trigger_payload["result"]["target_response"]["status"], 500);
    assert_eq!(
        trigger_payload["result"]["target_response"]["delivered"],
        false
    );
    assert_eq!(
        trigger_payload["result"]["target_response"]["body"],
        json!({"error": "downstream unavailable"})
    );
    assert_eq!(trigger_payload["result"]["lifecycle"]["state"], "failed");

    let captured = wait_for_request_count(&requests, 1).await;
    assert_eq!(
        captured,
        vec![(
            "/pipe-target".to_string(),
            json!({"email": "failure@try.direct"})
        )]
    );

    target_handle.abort();
}

#[tokio::test]
async fn given_registered_manual_pipe_when_it_is_triggered_and_deactivated_then_follow_up_trigger_fails_cleanly(
) {
    let _g = lock_tests();
    let mut server = Server::new_async().await;
    let target = server
        .mock("POST", "/pipe-target")
        .match_body(Matcher::Exact(r#"{"email":"manual@try.direct"}"#.into()))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"accepted":true}"#)
        .expect(1)
        .create_async()
        .await;

    let app = router_with_env("agent-1", "secret-token", "commands:execute");

    let (activate_status, activate_body) = post_with_sig(
        &app,
        "/api/v1/commands/execute",
        "agent-1",
        "secret-token",
        json!({
            "id": "cmd-activate-manual",
            "command_id": "cmd-activate-manual",
            "name": "activate_pipe",
            "params": {
                "deployment_hash": "dep-manual",
                "pipe_instance_id": "pipe-manual-1",
                "target_url": server.url(),
                "target_endpoint": "/pipe-target",
                "target_method": "POST",
                "field_mapping": { "email": "$.user.email" },
                "trigger_type": "manual"
            }
        }),
        None,
    )
    .await;
    assert_eq!(activate_status, StatusCode::OK);
    let activate_payload: serde_json::Value = serde_json::from_slice(&activate_body).unwrap();
    assert_eq!(activate_payload["status"], "success");
    assert_eq!(activate_payload["result"]["active"], true);
    assert_eq!(activate_payload["result"]["lifecycle"]["state"], "active");

    let (trigger_status, trigger_body) = post_with_sig(
        &app,
        "/api/v1/commands/execute",
        "agent-1",
        "secret-token",
        json!({
            "id": "cmd-trigger-manual",
            "command_id": "cmd-trigger-manual",
            "name": "trigger_pipe",
            "params": {
                "deployment_hash": "dep-manual",
                "pipe_instance_id": "pipe-manual-1",
                "input_data": {
                    "user": {
                        "email": "manual@try.direct"
                    }
                }
            }
        }),
        None,
    )
    .await;
    assert_eq!(trigger_status, StatusCode::OK);
    let trigger_payload: serde_json::Value = serde_json::from_slice(&trigger_body).unwrap();
    assert_eq!(trigger_payload["status"], "success");
    assert_eq!(trigger_payload["result"]["success"], true);
    assert_eq!(
        trigger_payload["result"]["target_response"]["transport"],
        "http"
    );
    assert_eq!(
        trigger_payload["result"]["target_response"]["delivered"],
        true
    );
    assert_eq!(trigger_payload["result"]["lifecycle"]["state"], "active");
    assert_eq!(trigger_payload["result"]["lifecycle"]["trigger_count"], 1);

    let (deactivate_status, deactivate_body) = post_with_sig(
        &app,
        "/api/v1/commands/execute",
        "agent-1",
        "secret-token",
        json!({
            "id": "cmd-deactivate-manual",
            "command_id": "cmd-deactivate-manual",
            "name": "deactivate_pipe",
            "params": {
                "deployment_hash": "dep-manual",
                "pipe_instance_id": "pipe-manual-1"
            }
        }),
        None,
    )
    .await;
    assert_eq!(deactivate_status, StatusCode::OK);
    let deactivate_payload: serde_json::Value = serde_json::from_slice(&deactivate_body).unwrap();
    assert_eq!(deactivate_payload["status"], "success");
    assert_eq!(deactivate_payload["result"]["active"], false);
    assert_eq!(
        deactivate_payload["result"]["lifecycle"]["state"],
        "inactive"
    );

    let (follow_up_status, follow_up_body) = post_with_sig(
        &app,
        "/api/v1/commands/execute",
        "agent-1",
        "secret-token",
        json!({
            "id": "cmd-trigger-after-deactivate",
            "command_id": "cmd-trigger-after-deactivate",
            "name": "trigger_pipe",
            "params": {
                "deployment_hash": "dep-manual",
                "pipe_instance_id": "pipe-manual-1",
                "input_data": {
                    "user": {
                        "email": "manual@try.direct"
                    }
                }
            }
        }),
        None,
    )
    .await;
    assert_eq!(follow_up_status, StatusCode::OK);
    let follow_up_payload: serde_json::Value = serde_json::from_slice(&follow_up_body).unwrap();
    assert_eq!(follow_up_payload["status"], "failed");
    assert_eq!(follow_up_payload["result"]["success"], false);
    assert_eq!(
        follow_up_payload["result"]["error"],
        "trigger_pipe requires target_url or target_container"
    );
    assert_eq!(follow_up_payload["result"]["lifecycle"]["state"], "failed");

    target.assert_async().await;
}
