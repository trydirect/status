use axum::http::{Request, StatusCode};
use axum::{body::Body, Router};
use base64::{engine::general_purpose, Engine};
use hmac::{Hmac, Mac};
use http_body_util::BodyExt;
use mockito::{Matcher, Server};
use serde_json::json;
use sha2::Sha256;
use status_panel::agent::config::{Config, ReqData};
use status_panel::comms::local_api::{create_router, AppState};
use std::sync::Arc;
use std::sync::{Mutex, OnceLock};
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
async fn given_registered_webhook_pipe_when_signed_webhook_arrives_then_payload_is_forwarded_to_target()
{
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
    assert_eq!(trigger_payload["result"]["target_response"]["transport"], "http");
    assert_eq!(trigger_payload["result"]["target_response"]["delivered"], true);
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
    assert_eq!(deactivate_payload["result"]["lifecycle"]["state"], "inactive");

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
