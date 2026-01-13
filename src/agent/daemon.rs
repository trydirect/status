use std::sync::Arc;

use anyhow::Result;
use chrono::{SecondsFormat, Utc};
use serde::Serialize;
use tokio::signal;
use tokio::sync::{broadcast, RwLock};
use tokio::time::Duration;
use tracing::{error, info, warn};

use crate::agent::config::Config;
use crate::commands::executor::CommandExecutor;
use crate::commands::TimeoutStrategy;
use crate::monitoring::{spawn_heartbeat, MetricsCollector, MetricsSnapshot, MetricsStore};
use crate::transport::{http_polling, CommandResult};
use serde_json::{json, Value};

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
    let dashboard_url =
        std::env::var("DASHBOARD_URL").unwrap_or_else(|_| "http://localhost:5000".to_string());
    let agent_id = std::env::var("AGENT_ID").unwrap_or_else(|_| "default-agent".to_string());
    let deployment_hash =
        std::env::var("DEPLOYMENT_HASH").unwrap_or_else(|_| "unknown-deployment".to_string());
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

    if let Some(app_status) = build_app_status_update(&cmd_result) {
        if let Err(e) =
            http_polling::update_app_status(dashboard_url, agent_id, agent_token, &app_status).await
        {
            warn!(
                command_id = %cmd_result.command_id,
                error = %e,
                "failed to update app status"
            );
        }
    }

    Ok(())
}

#[derive(Debug, Serialize)]
struct AppStatusUpdate {
    deployment_hash: String,
    app_code: String,
    status: String,
    logs: Vec<String>,
    timestamp: String,
}

fn build_app_status_update(result: &CommandResult) -> Option<AppStatusUpdate> {
    let deployment_hash = result.deployment_hash.clone()?;
    let app_code = result.app_code.clone()?;
    let command_type = result.command_type.as_deref()?;

    let (status, logs) = match command_type {
        "health" => parse_health_update(result),
        "logs" => parse_logs_update(result),
        "restart" => parse_restart_update(result),
        _ => return None,
    };

    Some(AppStatusUpdate {
        deployment_hash,
        app_code,
        status,
        logs,
        timestamp: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    })
}

fn parse_health_update(result: &CommandResult) -> (String, Vec<String>) {
    if let Some(body) = result.result.as_ref() {
        let container_state = body
            .get("container_state")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let mut logs = vec![format!(
            "status={} container_state={}",
            body.get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown"),
            container_state
        )];

        if let Some(errors) = body.get("errors").and_then(|v| v.as_array()) {
            for error in errors {
                logs.push(format_error_entry(error));
            }
        }

        let status = if result.status == "success" {
            container_state_to_app_status(container_state)
        } else {
            "error"
        };

        (status.to_string(), logs)
    } else {
        ("error".to_string(), default_error_logs(result))
    }
}

fn parse_logs_update(result: &CommandResult) -> (String, Vec<String>) {
    if let Some(body) = result.result.as_ref() {
        let logs = body
            .get("lines")
            .and_then(|v| v.as_array())
            .map(|lines| {
                lines
                    .iter()
                    .map(|line| {
                        let ts = line.get("ts").and_then(|v| v.as_str()).unwrap_or("");
                        let stream = line.get("stream").and_then(|v| v.as_str()).unwrap_or("");
                        let message = line.get("message").and_then(|v| v.as_str()).unwrap_or("");
                        format!("{ts} [{stream}] {message}")
                    })
                    .collect::<Vec<String>>()
            })
            .unwrap_or_else(Vec::new);

        let status = if result.status == "success" {
            "running".to_string()
        } else {
            "error".to_string()
        };

        (status, logs)
    } else {
        ("error".to_string(), default_error_logs(result))
    }
}

fn parse_restart_update(result: &CommandResult) -> (String, Vec<String>) {
    if let Some(body) = result.result.as_ref() {
        let container_state = body
            .get("container_state")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let mut logs = vec![format!(
            "restart status={} container_state={}",
            body.get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown"),
            container_state
        )];

        if let Some(errors) = body.get("errors").and_then(|v| v.as_array()) {
            for error in errors {
                logs.push(format_error_entry(error));
            }
        }

        let status = if result.status == "success" {
            container_state_to_app_status(container_state)
        } else {
            "error"
        };

        (status.to_string(), logs)
    } else {
        ("error".to_string(), default_error_logs(result))
    }
}

fn container_state_to_app_status(state: &str) -> &'static str {
    let normalized = state.to_lowercase();
    match normalized.as_str() {
        "running" | "starting" => "running",
        "paused" | "exited" | "stopped" => "stopped",
        _ => "error",
    }
}

fn format_error_entry(value: &Value) -> String {
    let code = value
        .get("code")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let message = value
        .get("message")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    if let Some(details) = value.get("details").and_then(|v| v.as_str()) {
        format!("error({code}): {message} ({details})")
    } else {
        format!("error({code}): {message}")
    }
}

fn default_error_logs(result: &CommandResult) -> Vec<String> {
    vec![result
        .error
        .as_deref()
        .unwrap_or("command failed without details")
        .to_string()]
}

fn trace_event(event: &str) {
    use tracing::trace;
    trace!(event = event, "daemon event");
}
