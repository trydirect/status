use anyhow::{anyhow, Context, Result};
use chrono::Utc;
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

fn signing_meta() -> (i64, String) {
    let ts = std::env::var(TS_OVERRIDE_ENV)
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or_else(|| Utc::now().timestamp());

    let request_id = std::env::var(REQUEST_ID_OVERRIDE_ENV).unwrap_or_else(|_| Uuid::new_v4().to_string());

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
) -> Result<Option<Command>> {
    let url = format!(
        "{}/api/v1/agent/commands/wait/{}?timeout={}&priority={}",
        base_url,
        deployment_hash,
        timeout_secs,
        priority.unwrap_or("normal")
    );

    debug!(
        url = %url,
        deployment_hash = %deployment_hash,
        timeout_secs = %timeout_secs,
        priority = ?priority,
        "initiating long-poll request to dashboard"
    );

    let client = Client::builder()
        .build()
        .context("building http client")?;

    let resp = signed_get(
        &client,
        &url,
        agent_id,
        agent_token,
        Duration::from_secs(timeout_secs + 5),
    )
    .await?;

    let status_code = resp.status().as_u16();
    debug!(
        status_code = %status_code,
        url = %url,
        "received response from /wait endpoint"
    );

    match status_code {
        200 => {
            let body_text = resp.text().await.context("read response body")?;
            debug!(
                status_code = %status_code,
                response_body = %body_text,
                "poll response: HTTP 200 with body"
            );

            let val: Value = serde_json::from_str(&body_text).context("parse command json")?;

            // Stacker API returns commands wrapped in an "item" field:
            // {"message":"Command available","item":{"id":"...","type":"logs","parameters":{...}}}
            // Or for empty queue: {"message":"No command available","item":null}
            let item = val.get("item");
            
            // Check if item is null or missing
            let command_obj = match item {
                Some(Value::Object(obj)) if !obj.is_empty() => item.unwrap(),
                _ => {
                    debug!(
                        response_body = %body_text,
                        "poll response: 200 but 'item' is null/missing - no command available"
                    );
                    return Ok(None);
                }
            };

            // Verify the command has an id
            let maybe_id = command_obj.get("id").and_then(|v| v.as_str());
            if maybe_id.is_none() {
                debug!(
                    response_body = %body_text,
                    "poll response: 200 but item has no 'id' field - treating as no command"
                );
                return Ok(None);
            }

            // Map Stacker field names to Command struct:
            // Stacker uses "type" -> Command uses "name"
            // Stacker uses "parameters" -> Command uses "params"
            let cmd_type = command_obj.get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let cmd_params = command_obj.get("parameters")
                .cloned()
                .unwrap_or(Value::Object(serde_json::Map::new()));
            let deployment_hash = command_obj.get("deployment_hash")
                .and_then(|v| v.as_str())
                .map(String::from);
            
            // Extract app_code from parameters if present
            let app_code = cmd_params.get("app_code")
                .and_then(|v| v.as_str())
                .map(String::from);

            let cmd = Command {
                id: maybe_id.unwrap().to_string(),
                name: cmd_type.to_string(),
                params: cmd_params,
                deployment_hash,
                app_code,
            };

            debug!(
                command_id = %cmd.id,
                command_name = %cmd.name,
                "poll response: command received from queue"
            );
            Ok(Some(cmd))
        }
        204 => {
            debug!(
                status_code = %status_code,
                "poll response: HTTP 204 No Content - queue empty, no commands pending"
            );
            Ok(None)
        }
        code => {
            // Try to read error body for better debugging
            let error_body = resp.text().await.unwrap_or_else(|_| "<failed to read body>".to_string());
            debug!(
                status_code = %code,
                error_body = %error_body,
                url = %url,
                "poll response: unexpected HTTP status"
            );
            Err(anyhow::anyhow!("unexpected status: {} | body: {}", code, error_body))
        }
    }
}

/// Report command result back to dashboard.
pub async fn report_result(
    base_url: &str,
    agent_id: &str,
    agent_token: &str,
    payload: &Value,
) -> Result<()> {
    let url = format!("{}/api/v1/agent/commands/report", base_url);
    let client = Client::new();
    let resp = signed_post_json(&client, &url, agent_id, agent_token, payload).await?;

    if resp.status().is_success() {
        Ok(())
    } else {
        Err(anyhow!("report failed: {}", resp.status()))
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

    #[tokio::test]
    async fn report_result_posts_payload() {
        env::set_var(TS_OVERRIDE_ENV, "1700000000");
        env::set_var(REQUEST_ID_OVERRIDE_ENV, "req-123");

        let mut server = Server::new_async().await;
        let base_url = server.url();
        let agent_id = "agent-123";
        let agent_token = "token-abc";
        let payload = json!({
            "command_id": "cmd-1",
            "status": "success"
        });

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

        report_result(&base_url, agent_id, agent_token, &payload)
            .await
            .expect("report_result should succeed");
        mock.assert();
    }

    #[tokio::test]
    async fn update_app_status_posts_payload() {
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

        assert!(result.is_none());
        mock.assert();
    }
}
