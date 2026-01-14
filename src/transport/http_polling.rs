use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use reqwest::Client;
use serde::Serialize;
use serde_json::Value;
use std::time::Duration;
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

    match resp.status().as_u16() {
        200 => {
            let val: Value = resp.json().await.context("parse command json")?;

            // Some dashboards return 200 with a "message" instead of 204. Gracefully treat that as no command.
            let maybe_id = val.get("id").and_then(|v| v.as_str());
            if maybe_id.is_none() {
                return Ok(None);
            }

            let cmd: Command = serde_json::from_value(val.clone()).map_err(|e| {
                // Surface the payload to simplify debugging malformed commands
                anyhow::anyhow!("map to Command: {} | payload={} ", e, val)
            })?;
            Ok(Some(cmd))
        }
        204 => Ok(None),
        code => Err(anyhow::anyhow!("unexpected status: {}", code)),
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
