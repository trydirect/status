use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::Value;
use std::time::Duration;

use crate::transport::Command;

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

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs + 5))
        .build()
        .context("building http client")?;

    let request = client
        .get(&url)
        .header("X-Agent-Id", agent_id)
        .bearer_auth(agent_token);

    let resp = request.send().await.context("long poll send")?;

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
    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .header("X-Agent-Id", agent_id)
        .bearer_auth(agent_token)
        .json(payload)
        .send()
        .await
        .context("report send")?;

    if resp.status().is_success() {
        Ok(())
    } else {
        Err(anyhow::anyhow!("report failed: {}", resp.status()))
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
    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .header("X-Agent-Id", agent_id)
        .bearer_auth(agent_token)
        .json(payload)
        .send()
        .await
        .context("apps status send")?;

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

    #[tokio::test]
    async fn report_result_posts_payload() {
        let mut server = Server::new_async().await;
        let base_url = server.url();
        let agent_id = "agent-123";
        let agent_token = "token-abc";
        let payload = json!({
            "command_id": "cmd-1",
            "status": "success"
        });

        let body = payload.to_string();
        let mock = server
            .mock("POST", "/api/v1/agent/commands/report")
            .match_header("X-Agent-Id", Matcher::Exact(agent_id.into()))
            .match_header(
                "Authorization",
                Matcher::Exact(format!("Bearer {}", agent_token)),
            )
            .match_body(Matcher::Exact(body.clone()))
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
        let mut server = Server::new_async().await;
        let base_url = server.url();
        let agent_id = "agent-123";
        let agent_token = "token-abc";
        let payload = json!({
            "deployment_hash": "dep-1",
            "app_code": "web",
            "status": "running"
        });

        let body = payload.to_string();
        let mock = server
            .mock("POST", "/api/v1/apps/status")
            .match_header("X-Agent-Id", Matcher::Exact(agent_id.into()))
            .match_header(
                "Authorization",
                Matcher::Exact(format!("Bearer {}", agent_token)),
            )
            .match_body(Matcher::Exact(body.clone()))
            .with_status(200)
            .create_async()
            .await;

        update_app_status(&base_url, agent_id, agent_token, &payload)
            .await
            .expect("update_app_status should succeed");
        mock.assert();
    }
}
