use std::sync::Arc;

use anyhow::Result;
use tokio::signal;
use tokio::sync::{broadcast, RwLock};
use tokio::time::Duration;
use tracing::{error, info, warn};

use crate::agent::config::Config;
use crate::commands::executor::CommandExecutor;
use crate::commands::TimeoutStrategy;
use crate::monitoring::{spawn_heartbeat, MetricsCollector, MetricsSnapshot, MetricsStore};
use crate::transport::http_polling;

pub async fn run(config_path: String) -> Result<()> {
    let cfg = Config::from_file(&config_path)?;
    info!(domain=?cfg.domain, "Agent daemon starting");

    // Check if compose agent is enabled
    let compose_agent_enabled = std::env::var("COMPOSE_AGENT_ENABLED")
        .ok()
        .and_then(|v| v.parse::<bool>().ok())
        .or(Some(cfg.compose_agent_enabled))
        .unwrap_or(false);

    let control_plane = std::env::var("CONTROL_PLANE")
        .ok()
        .or(cfg.control_plane.clone())
        .unwrap_or_else(|| "status_panel".to_string());

    if !compose_agent_enabled && control_plane == "status_panel" {
        warn!("compose_agent=false - running in legacy mode (Status Panel handles all operations)");
    } else if compose_agent_enabled {
        info!("compose_agent=true - compose-agent sidecar handling Docker operations");
    }

    info!(control_plane = %control_plane, "Control plane identified");

    let collector = Arc::new(MetricsCollector::new());
    let store: MetricsStore = Arc::new(RwLock::new(MetricsSnapshot::default()));
    let (tx, _) = broadcast::channel(32);
    let webhook = std::env::var("METRICS_WEBHOOK").ok();
    let metrics_interval = std::env::var("METRICS_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(10));

    let heartbeat_handle = spawn_heartbeat(collector, store, metrics_interval, tx, webhook.clone());
    info!(
        interval_secs = metrics_interval.as_secs(),
        webhook = webhook.as_deref().unwrap_or("none"),
        "metrics heartbeat started"
    );

    // Parse long-polling configuration
    let dashboard_url = std::env::var("DASHBOARD_URL")
        .unwrap_or_else(|_| "http://localhost:5000".to_string());
    let agent_id = std::env::var("AGENT_ID").unwrap_or_else(|_| "default-agent".to_string());
    let deployment_hash = std::env::var("DEPLOYMENT_HASH")
        .unwrap_or_else(|_| "unknown-deployment".to_string());
    let polling_timeout = std::env::var("POLLING_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(30);
    let polling_backoff = std::env::var("POLLING_BACKOFF_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(5);
    let command_timeout = std::env::var("COMMAND_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(300);
    let agent_token = std::env::var("AGENT_TOKEN").unwrap_or_default();
    if agent_token.is_empty() {
        warn!("AGENT_TOKEN is not set; authenticated dashboard requests will fail");
    }

    info!(
        dashboard_url = %dashboard_url,
        agent_id = %agent_id,
        deployment_hash = %deployment_hash,
        polling_timeout_secs = polling_timeout,
        polling_backoff_secs = polling_backoff,
        command_timeout_secs = command_timeout,
        "long-polling configuration initialized"
    );

    // Spawn the long-polling loop
    let polling_handle = tokio::spawn(async move {
        polling_loop(
            dashboard_url,
            deployment_hash,
            agent_id,
            agent_token,
            polling_timeout,
            polling_backoff,
            command_timeout,
        )
        .await;
    });

    // Wait for shutdown signal (Ctrl+C) then stop all loops
    signal::ctrl_c().await?;
    info!("shutdown signal received, stopping daemon");

    heartbeat_handle.abort();
    polling_handle.abort();
    let _ = heartbeat_handle.await; // Ignore cancellation errors
    let _ = polling_handle.await;

    Ok(())
}

/// Long-polling loop: continuously waits for commands and executes them
async fn polling_loop(
    dashboard_url: String,
    deployment_hash: String,
    agent_id: String,
    agent_token: String,
    polling_timeout: u64,
    polling_backoff: u64,
    command_timeout: u64,
) {
    let executor = CommandExecutor::new();

    loop {
        match http_polling::wait_for_command(
            &dashboard_url,
            &deployment_hash,
            &agent_id,
            &agent_token,
            polling_timeout,
            None,
        )
        .await
        {
            Ok(Some(cmd)) => {
                info!(
                    command_id = %cmd.id,
                    command_name = %cmd.name,
                    "command received from dashboard"
                );

                // Execute the command with configured timeout
                match execute_and_report(
                    &executor,
                    &dashboard_url,
                    &agent_id,
                    &agent_token,
                    cmd,
                    command_timeout,
                )
                .await
                {
                    Ok(_) => {
                        info!("command execution and reporting completed");
                    }
                    Err(e) => {
                        error!("command execution error: {}", e);
                    }
                }
            }
            Ok(None) => {
                // Polling timeout with no command — loop immediately for next poll
                trace_event("polling_timeout");
            }
            Err(e) => {
                // Network error — apply backoff before retrying
                error!("polling error: {}", e);
                info!(
                    backoff_secs = polling_backoff,
                    "applying backoff before retry"
                );
                tokio::time::sleep(Duration::from_secs(polling_backoff)).await;
            }
        }
    }
}

/// Execute a command and report results back to dashboard
async fn execute_and_report(
    executor: &CommandExecutor,
    dashboard_url: &str,
    agent_id: &str,
    agent_token: &str,
    cmd: crate::transport::Command,
    command_timeout: u64,
) -> Result<()> {
    use crate::commands::stacker::{execute_stacker_command, parse_stacker_command};
    use crate::transport::CommandResult;
    use serde_json::json;

    // First, try to parse as a stacker command (health, logs, restart)
    let cmd_result = match parse_stacker_command(&cmd) {
        Ok(Some(stacker_cmd)) => {
            info!(
                command_id = %cmd.id,
                command_type = %cmd.name,
                "executing stacker command"
            );
            match execute_stacker_command(&cmd, &stacker_cmd).await {
                Ok(result) => result,
                Err(e) => {
                    error!(command_id = %cmd.id, error = %e, "stacker command execution failed");
                    CommandResult {
                        command_id: cmd.id.clone(),
                        status: "failed".to_string(),
                        result: None,
                        error: Some(e.to_string()),
                        ..CommandResult::default()
                    }
                }
            }
        }
        Ok(None) => {
            // Not a stacker command, fall back to shell execution
            info!(
                command_id = %cmd.id,
                command_name = %cmd.name,
                "executing as shell command"
            );
            let strategy = TimeoutStrategy::backup_strategy(command_timeout);
            let exec_result = executor.execute(&cmd, strategy).await;

            match exec_result {
                Ok(output) => CommandResult {
                    command_id: cmd.id.clone(),
                    status: "success".to_string(),
                    result: Some(json!({
                        "stdout": output.stdout,
                        "stderr": output.stderr,
                        "exit_code": output.exit_code,
                    })),
                    error: None,
                    ..CommandResult::default()
                },
                Err(e) => CommandResult {
                    command_id: cmd.id.clone(),
                    status: "failed".to_string(),
                    result: None,
                    error: Some(e.to_string()),
                    ..CommandResult::default()
                },
            }
        }
        Err(e) => {
            // Failed to parse command parameters
            error!(command_id = %cmd.id, error = %e, "failed to parse command");
            CommandResult {
                command_id: cmd.id.clone(),
                status: "failed".to_string(),
                result: None,
                error: Some(format!("Invalid command parameters: {}", e)),
                ..CommandResult::default()
            }
        }
    };

    // Report the result back
    let payload = serde_json::to_value(&cmd_result)?;
    http_polling::report_result(dashboard_url, agent_id, agent_token, &payload).await?;

    Ok(())
}

fn trace_event(event: &str) {
    use tracing::trace;
    trace!(event = event, "daemon event");
}
