use anyhow::{anyhow, Context, Result};
use chrono::Utc;
// use clap::command;
// use nix::libc::segment_command_64;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use reqwest::Client;
use serde::Serialize;
use serde_json::Value;
use std::time::Duration;
use tracing::{debug, trace};
use uuid::Uuid;

use crate::security::request_signer::compute_signature_base64;
use crate::transport::Command;

const TS_OVERRIDE_ENV: &str = "HTTP_POLLING_TS_OVERRIDE";
const REQUEST_ID_OVERRIDE_ENV: &str = "HTTP_POLLING_REQUEST_ID_OVERRIDE";

#[derive(Debug, Clone)]
pub struct PollResponse {
    pub command: Option<Command>,
    pub next_poll_secs: Option<u64>,
}

fn signing_meta() -> (i64, String) {
    let ts = std::env::var(TS_OVERRIDE_ENV)
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or_else(|| Utc::now().timestamp());

    let request_id =
        std::env::var(REQUEST_ID_OVERRIDE_ENV).unwrap_or_else(|_| Uuid::new_v4().to_string());

    (ts, request_id)
}

fn build_signed_headers(agent_id: &str, agent_token: &str, body: &[u8]) -> Result<HeaderMap> {
    let (ts, request_id) = signing_meta();
    let sig = compute_signature_base64(agent_token, body);

    debug!(
        agent_id = %agent_id,
        timestamp = %ts,
        request_id = %request_id,
        signature = %sig,
        "building signed HMAC headers"
    );

    let mut headers = HeaderMap::new();
    headers.insert("X-Agent-Id", HeaderValue::from_str(agent_id)?);
    headers.insert("X-Timestamp", HeaderValue::from_str(&ts.to_string())?);
    headers.insert("X-Request-Id", HeaderValue::from_str(&request_id)?);
    headers.insert("X-Agent-Signature", HeaderValue::from_str(&sig)?);

    let bearer = format!("Bearer {}", agent_token);
    headers.insert(AUTHORIZATION, HeaderValue::from_str(&bearer)?);

    Ok(headers)
}

async fn signed_get(
    client: &Client,
    url: &str,
    agent_id: &str,
    agent_token: &str,
    timeout: Duration,
) -> Result<reqwest::Response> {
    let headers = build_signed_headers(agent_id, agent_token, b"")?;

    trace!(
        url = %url,
        agent_id = %agent_id,
        timeout_secs = %timeout.as_secs(),
        "sending signed GET request"
    );

    client
        .get(url)
        .timeout(timeout)
        .headers(headers)
        .send()
        .await
        .context("long poll send")
}

async fn signed_post_json<T: Serialize>(
    client: &Client,
    url: &str,
    agent_id: &str,
    agent_token: &str,
    payload: &T,
) -> Result<reqwest::Response> {
    let body = serde_json::to_vec(payload).context("serialize json body")?;
    let headers = build_signed_headers(agent_id, agent_token, &body)?;

    client
        .post(url)
        .headers(headers)
        .header(CONTENT_TYPE, "application/json")
        .body(body)
        .send()
        .await
        .context("post send")
}

/// Long-poll the dashboard for a command.
/// Returns Some(Command) if available within timeout, else None.
pub async fn wait_for_command(
    base_url: &str,
    deployment_hash: &str,
    agent_id: &str,
    agent_token: &str,
    timeout_secs: u64,
    priority: Option<&str>,
) -> Result<PollResponse> {
    let url = build_wait_command_url(base_url, deployment_hash, timeout_secs, priority);

    debug!(
        url = %url,
        deployment_hash = %deployment_hash,
        timeout_secs = %timeout_secs,
        priority = ?priority,
        "initiating long-poll request to dashboard"
    );

    let client = create_http_client()?;
    let response =
        send_long_poll_request(&client, &url, agent_id, agent_token, timeout_secs).await?;

    handle_poll_response(response, &url).await
}

// --- Private helper functions ---

fn build_wait_command_url(
    base_url: &str,
    deployment_hash: &str,
    timeout_secs: u64,
    priority: Option<&str>,
) -> String {
    format!(
        "{}/api/v1/agent/commands/wait/{}?timeout={}&priority={}",
        base_url,
        deployment_hash,
        timeout_secs,
        priority.unwrap_or("normal")
    )
}

fn create_http_client() -> Result<Client> {
    Client::builder().build().context("building http client")
}

async fn send_long_poll_request(
    client: &Client,
    url: &str,
    agent_id: &str,
    agent_token: &str,
    timeout_secs: u64,
) -> Result<reqwest::Response> {
    signed_get(
        client,
        url,
        agent_id,
        agent_token,
        Duration::from_secs(timeout_secs + 5),
    )
    .await
}

async fn handle_poll_response(response: reqwest::Response, url: &str) -> Result<PollResponse> {
    let status_code = response.status().as_u16();
    debug!(
        status_code = %status_code,
        url = %url,
        "received response from /wait endpoint"
    );

    match status_code {
        200 => parse_command_from_response(response).await,
        204 => Ok(PollResponse {
            command: None,
            next_poll_secs: None,
        }),
        _ => handle_error_response(response, status_code, url)
            .await
            .map(|_| PollResponse {
                command: None,
                next_poll_secs: None,
            }),
    }
}

async fn parse_command_from_response(response: reqwest::Response) -> Result<PollResponse> {
    let body_text = response.text().await.context("read response body")?;
    debug!(
        status_code = 200,
        response_body = %body_text,
        "poll response: HTTP 200 with body"
    );

    let json_value: Value = serde_json::from_str(&body_text).context("parse command json")?;

    extract_command_from_json(json_value, &body_text)
}

fn extract_command_from_json(json_value: Value, body_text: &str) -> Result<PollResponse> {
    let next_poll_secs = extract_next_poll_secs(&json_value);

    // Stacker API returns commands wrapped in an "item" field
    let item = json_value.get("item");

    // Handle empty/null item
    let command_object = match item {
        Some(Value::Object(obj)) if !obj.is_empty() => obj,
        _ => {
            debug!(
                response_body = %body_text,
                "poll response: 200 but 'item' is null/missing - no command available"
            );
            return Ok(PollResponse {
                command: None,
                next_poll_secs,
            });
        }
    };

    // Validate required fields
    let command_id = validate_command_id(command_object, body_text)?;

    // Extract command fields
    let command_type = extract_field_or_default(command_object, "type", "unknown");
    let parameters = extract_parameters(command_object);
    let deployment_hash = extract_optional_string(command_object, "deployment_hash");
    let app_code = extract_app_code(&parameters);

    let command = Command {
        id: command_id.clone(),
        command_id,
        name: command_type,
        params: parameters,
        deployment_hash,
        app_code,
    };

    debug!(
        command_id = %command.command_id,
        command_name = %command.name,
        "poll response: command received from queue"
    );

    Ok(PollResponse {
        command: Some(command),
        next_poll_secs,
    })
}

fn extract_next_poll_secs(json_value: &Value) -> Option<u64> {
    json_value
        .get("meta")
        .and_then(|meta| meta.get("next_poll_secs"))
        .and_then(|value| {
            value
                .as_u64()
                .or_else(|| value.as_str().and_then(|s| s.parse::<u64>().ok()))
        })
}

fn validate_command_id(
    command_object: &serde_json::Map<String, Value>,
    body_text: &str,
) -> Result<String> {
    command_object
        .get("command_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| {
            debug!(
                response_body = %body_text,
                "poll response: 200 but item has no 'command_id' field - treating as no command"
            );
            anyhow!("missing command_id field")
        })
}

fn extract_field_or_default(
    object: &serde_json::Map<String, Value>,
    field: &str,
    default: &str,
) -> String {
    object
        .get(field)
        .and_then(|v| v.as_str())
        .unwrap_or(default)
        .to_string()
}

fn extract_parameters(object: &serde_json::Map<String, Value>) -> Value {
    object
        .get("parameters")
        .cloned()
        .unwrap_or(Value::Object(serde_json::Map::new()))
}

fn extract_optional_string(object: &serde_json::Map<String, Value>, field: &str) -> Option<String> {
    object.get(field).and_then(|v| v.as_str()).map(String::from)
}

fn extract_app_code(parameters: &Value) -> Option<String> {
    parameters
        .get("app_code")
        .and_then(|v| v.as_str())
        .map(String::from)
}

async fn handle_error_response(
    response: reqwest::Response,
    status_code: u16,
    url: &str,
) -> Result<Option<Command>> {
    let error_body = response
        .text()
        .await
        .unwrap_or_else(|_| "<failed to read body>".to_string());

    debug!(
        status_code = %status_code,
        error_body = %error_body,
        url = %url,
        "poll response: unexpected HTTP status"
    );

    Err(anyhow!(
        "unexpected status: {} | body: {}",
        status_code,
        error_body
    ))
}

/// Report command result back to dashboard.
#[allow(clippy::too_many_arguments)]
pub async fn report_result(
    base_url: &str,
    agent_id: &str,
    agent_token: &str,
    command_id: &str,
    deployment_hash: &str,
    status: &str,
    result: &Option<serde_json::Value>,
    error: &Option<String>,
    completed_at: &str,
) -> Result<()> {
    let url = format!("{}/api/v1/agent/commands/report", base_url);

    let mut body = serde_json::Map::new();
    body.insert(
        "command_id".to_string(),
        serde_json::Value::String(command_id.to_string()),
    );
    body.insert(
        "deployment_hash".to_string(),
        serde_json::Value::String(deployment_hash.to_string()),
    );
    body.insert(
        "status".to_string(),
        serde_json::Value::String(status.to_string()),
    );
    body.insert(
        "completed_at".to_string(),
        serde_json::Value::String(completed_at.to_string()),
    );

    if let Some(res) = result {
        body.insert("result".to_string(), res.clone());
    }

    if let Some(err) = error {
        body.insert("error".to_string(), serde_json::Value::String(err.clone()));
    } else {
        body.insert("error".to_string(), serde_json::Value::Null);
    }

    debug!(url = %url, body = ?body, "reporting command result to stacker");

    let client = Client::new();
    let resp = signed_post_json(&client, &url, agent_id, agent_token, &body).await?;
    let status_code = resp.status();

    if status_code.is_success() {
        debug!(status_code = %status_code.as_u16(), "command result reported successfully");
        Ok(())
    } else {
        let error_body = resp
            .text()
            .await
            .unwrap_or_else(|_| "<failed to read body>".to_string());
        debug!(status_code = %status_code.as_u16(), error_body = %error_body, "command result report failed");
        Err(anyhow!(
            "report failed: {} | body: {}",
            status_code,
            error_body
        ))
    }
}

/// Update app status after executing a command.
pub async fn update_app_status<T: Serialize>(
    base_url: &str,
    agent_id: &str,
    agent_token: &str,
    payload: &T,
) -> Result<()> {
    let url = format!("{}/api/v1/apps/status", base_url);
    let client = Client::new();
    let resp = signed_post_json(&client, &url, agent_id, agent_token, payload).await?;

    if resp.status().is_success() {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "app status update failed: {}",
            resp.status()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::{Matcher, Server};
    use serde_json::json;
    use std::env;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[tokio::test]
    async fn report_result_posts_payload() {
        let _guard = env_lock().lock().expect("env lock poisoned");
        env::set_var(TS_OVERRIDE_ENV, "1700000000");
        env::set_var(REQUEST_ID_OVERRIDE_ENV, "req-123");

        let mut server = Server::new_async().await;
        let base_url = server.url();
        let agent_id = "agent-123";
        let agent_token = "token-abc";
        let command_id = "cmd-1";
        let deployment_hash = "dep-hash-123";
        let status = "success";
        let result: Option<serde_json::Value> = None;
        let error = None;
        let completed_at = "2023-11-15T10:00:00Z";

        let mut payload = serde_json::Map::new();
        payload.insert(
            "command_id".to_string(),
            serde_json::Value::String(command_id.to_string()),
        );
        payload.insert(
            "deployment_hash".to_string(),
            serde_json::Value::String(deployment_hash.to_string()),
        );
        payload.insert(
            "status".to_string(),
            serde_json::Value::String(status.to_string()),
        );
        payload.insert(
            "completed_at".to_string(),
            serde_json::Value::String(completed_at.to_string()),
        );
        if let Some(value) = result.clone() {
            payload.insert("result".to_string(), value);
        }
        payload.insert("error".to_string(), serde_json::Value::Null);

        let body = serde_json::to_vec(&payload).unwrap();
        let signature = compute_signature_base64(agent_token, &body);
        let ts = env::var(TS_OVERRIDE_ENV).unwrap();
        let req_id = env::var(REQUEST_ID_OVERRIDE_ENV).unwrap();
        let mock = server
            .mock("POST", "/api/v1/agent/commands/report")
            .match_header("X-Agent-Id", Matcher::Exact(agent_id.into()))
            .match_header(
                "Authorization",
                Matcher::Exact(format!("Bearer {}", agent_token)),
            )
            .match_header("X-Timestamp", Matcher::Exact(ts))
            .match_header("X-Request-Id", Matcher::Exact(req_id))
            .match_header("X-Agent-Signature", Matcher::Exact(signature))
            .match_body(Matcher::Exact(String::from_utf8(body.clone()).unwrap()))
            .with_status(200)
            .create_async()
            .await;

        report_result(
            &base_url,
            agent_id,
            agent_token,
            command_id,
            deployment_hash,
            status,
            &result,
            &error,
            completed_at,
        )
        .await
        .expect("report_result should succeed");
        mock.assert();
    }

    #[tokio::test]
    async fn update_app_status_posts_payload() {
        let _guard = env_lock().lock().expect("env lock poisoned");
        env::set_var(TS_OVERRIDE_ENV, "1700000001");
        env::set_var(REQUEST_ID_OVERRIDE_ENV, "req-456");

        let mut server = Server::new_async().await;
        let base_url = server.url();
        let agent_id = "agent-123";
        let agent_token = "token-abc";
        let payload = json!({
            "deployment_hash": "dep-1",
            "app_code": "web",
            "status": "running"
        });

        let body = serde_json::to_vec(&payload).unwrap();
        let signature = compute_signature_base64(agent_token, &body);
        let ts = env::var(TS_OVERRIDE_ENV).unwrap();
        let req_id = env::var(REQUEST_ID_OVERRIDE_ENV).unwrap();
        let mock = server
            .mock("POST", "/api/v1/apps/status")
            .match_header("X-Agent-Id", Matcher::Exact(agent_id.into()))
            .match_header(
                "Authorization",
                Matcher::Exact(format!("Bearer {}", agent_token)),
            )
            .match_header("X-Timestamp", Matcher::Exact(ts))
            .match_header("X-Request-Id", Matcher::Exact(req_id))
            .match_header("X-Agent-Signature", Matcher::Exact(signature))
            .match_body(Matcher::Exact(String::from_utf8(body.clone()).unwrap()))
            .with_status(200)
            .create_async()
            .await;

        update_app_status(&base_url, agent_id, agent_token, &payload)
            .await
            .expect("update_app_status should succeed");
        mock.assert();
    }

    #[tokio::test]
    async fn wait_for_command_adds_hmac_headers() {
        let _guard = env_lock().lock().expect("env lock poisoned");
        env::set_var(TS_OVERRIDE_ENV, "1700000002");
        env::set_var(REQUEST_ID_OVERRIDE_ENV, "req-789");

        let mut server = Server::new_async().await;
        let base_url = server.url();
        let agent_id = "agent-123";
        let agent_token = "token-abc";
        let deployment = "dep-1";
        let priority = "normal";

        let signature = compute_signature_base64(agent_token, b"");
        let ts = env::var(TS_OVERRIDE_ENV).unwrap();
        let req_id = env::var(REQUEST_ID_OVERRIDE_ENV).unwrap();

        let path = format!(
            "/api/v1/agent/commands/wait/{}?timeout=30&priority={}",
            deployment, priority
        );

        let mock = server
            .mock("GET", path.as_str())
            .match_header("X-Agent-Id", Matcher::Exact(agent_id.into()))
            .match_header(
                "Authorization",
                Matcher::Exact(format!("Bearer {}", agent_token)),
            )
            .match_header("X-Timestamp", Matcher::Exact(ts))
            .match_header("X-Request-Id", Matcher::Exact(req_id))
            .match_header("X-Agent-Signature", Matcher::Exact(signature))
            .with_status(204)
            .create_async()
            .await;

        let result = wait_for_command(
            &base_url,
            deployment,
            agent_id,
            agent_token,
            30,
            Some(priority),
        )
        .await
        .expect("wait should succeed");

        assert!(result.command.is_none());
        mock.assert();
    }
}
