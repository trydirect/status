use anyhow::{Context, Result};
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
