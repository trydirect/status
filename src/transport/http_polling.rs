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

    let resp = client
        .get(&url)
        .header("X-Agent-Id", agent_id)
        .send()
        .await
        .context("long poll send")?;

    match resp.status().as_u16() {
        200 => {
            let val: Value = resp.json().await.context("parse command json")?;
            let cmd: Command = serde_json::from_value(val).context("map to Command")?;
            Ok(Some(cmd))
        }
        204 => Ok(None),
        code => Err(anyhow::anyhow!("unexpected status: {}", code)),
    }
}

/// Report command result back to dashboard.
pub async fn report_result(base_url: &str, agent_id: &str, payload: &Value) -> Result<()> {
    let url = format!("{}/api/v1/agent/commands/report", base_url);
    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .header("X-Agent-Id", agent_id)
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
