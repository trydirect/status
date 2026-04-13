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
use crate::commands::firewall::FirewallPolicy;
use crate::commands::validator::CommandValidator;
use crate::commands::TimeoutStrategy;
use crate::monitoring::{
    spawn_heartbeat, ControlPlane, MetricsCollector, MetricsSnapshot, MetricsStore,
};
use crate::security::token_provider::TokenProvider;
use crate::security::vault_client::VaultClient;
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

    let control_plane = ControlPlane::from_value(
        std::env::var("CONTROL_PLANE")
            .ok()
            .as_deref()
            .or(cfg.control_plane.as_deref()),
    );

    if !compose_agent_enabled && control_plane == ControlPlane::StatusPanel {
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

    let alert_manager = {
        let cfg = crate::monitoring::alerting::AlertConfig::from_env();
        let mgr = crate::monitoring::alerting::AlertManager::new(cfg);
        if mgr.is_enabled() {
            info!("outbound alerting enabled");
            Some(std::sync::Arc::new(mgr))
        } else {
            None
        }
    };

    let heartbeat_handle = spawn_heartbeat(
        collector,
        store,
        metrics_interval,
        tx,
        webhook.clone(),
        alert_manager,
    );
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

    // Build a shared token provider (Vault → env fallback on 401/403)
    let vault_client = VaultClient::from_env().ok().flatten();
    let token_provider = TokenProvider::new(agent_token, vault_client, deployment_hash.clone());

    info!(
        dashboard_url = %dashboard_url,
        agent_id = %agent_id,
        deployment_hash = %deployment_hash,
        polling_timeout_secs = polling_timeout,
        polling_backoff_secs = polling_backoff,
        command_timeout_secs = command_timeout,
        "long-polling configuration initialized"
    );

    // Build firewall policy from config (no API port in daemon mode)
    let firewall_policy = FirewallPolicy::from_config(&cfg, None);

    let ctx = PollingContext {
        dashboard_url,
        deployment_hash,
        agent_id,
        token_provider,
        polling_timeout,
        polling_backoff,
        command_timeout,
        firewall_policy,
        control_plane,
    };

    // Spawn the long-polling loop
    let polling_handle = tokio::spawn(async move {
        polling_loop(ctx).await;
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

struct PollingContext {
    dashboard_url: String,
    deployment_hash: String,
    agent_id: String,
    token_provider: TokenProvider,
    polling_timeout: u64,
    polling_backoff: u64,
    command_timeout: u64,
    firewall_policy: FirewallPolicy,
    control_plane: ControlPlane,
}

/// Long-polling loop: continuously waits for commands and executes them
async fn polling_loop(ctx: PollingContext) {
    let executor = CommandExecutor::new();

    loop {
        match http_polling::wait_for_command_with_retry(
            &ctx.dashboard_url,
            &ctx.deployment_hash,
            &ctx.agent_id,
            &ctx.token_provider,
            ctx.polling_timeout,
            None,
        )
        .await
        {
            Ok(response) => {
                if let Some(cmd) = response.command {
                    info!(
                        command_id = %cmd.command_id,
                        command_name = %cmd.name,
                        "command received from dashboard queue"
                    );
                    // Execute the command with configured timeout
                    match execute_and_report(&executor, &ctx, cmd).await {
                        Ok(_) => {
                            info!("command execution and reporting completed");
                        }
                        Err(e) => {
                            error!("command execution error: {}", e);
                        }
                    }
                } else {
                    // Polling timeout with no command — loop immediately for next poll
                    trace_event("polling_timeout");
                    if let Some(next_poll) = response.next_poll_secs {
                        tokio::time::sleep(Duration::from_secs(next_poll)).await;
                    }
                }
            }
            Err(e) => {
                // Network error — apply backoff before retrying
                error!("polling error: {}", e);
                info!(
                    backoff_secs = ctx.polling_backoff,
                    "applying backoff before retry"
                );
                tokio::time::sleep(Duration::from_secs(ctx.polling_backoff)).await;
            }
        }
    }
}

/// Execute a command and report results back to dashboard
async fn execute_and_report(
    executor: &CommandExecutor,
    ctx: &PollingContext,
    cmd: crate::transport::Command,
) -> Result<()> {
    use crate::commands::stacker::{execute_stacker_command, parse_stacker_command};

    // First, try to parse as a stacker command (health, logs, restart)
    let cmd_result = match parse_stacker_command(&cmd) {
        Ok(Some(stacker_cmd)) => {
            info!(
                command_id = %cmd.command_id,
                command_type = %cmd.name,
                "executing stacker command"
            );
            match execute_stacker_command(&cmd, &stacker_cmd, &ctx.firewall_policy).await {
                Ok(result) => result,
                Err(e) => {
                    error!(command_id = %cmd.command_id, error = %e, "stacker command execution failed");
                    CommandResult {
                        command_id: cmd.command_id.clone(),
                        status: "failed".to_string(),
                        result: None,
                        error: Some(e.to_string()),
                        completed_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
                        executed_by: Some(ctx.control_plane.to_string()),
                        ..CommandResult::default()
                    }
                }
            }
        }
        Ok(None) => {
            // Not a stacker command — validate before shell execution
            let validator = CommandValidator::default_secure();
            if let Err(e) = validator.validate(&cmd) {
                error!(
                    command_id = %cmd.command_id,
                    command_name = %cmd.name,
                    error = %e,
                    "shell command rejected by validator"
                );
                CommandResult {
                    command_id: cmd.command_id.clone(),
                    status: "failed".to_string(),
                    result: None,
                    error: Some(format!("Command validation failed: {}", e)),
                    completed_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
                    executed_by: Some(ctx.control_plane.to_string()),
                    ..CommandResult::default()
                }
            } else {
                info!(
                    command_id = %cmd.command_id,
                    command_name = %cmd.name,
                    "executing validated shell command"
                );
                let strategy = TimeoutStrategy::backup_strategy(ctx.command_timeout);
                let exec_result = executor.execute(&cmd, strategy).await;

                match exec_result {
                    Ok(output) => CommandResult {
                        command_id: cmd.command_id.clone(),
                        status: "success".to_string(),
                        result: Some(json!({
                            "stdout": output.stdout,
                            "stderr": output.stderr,
                            "exit_code": output.exit_code,
                        })),
                        error: None,
                        completed_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
                        executed_by: Some(ctx.control_plane.to_string()),
                        ..CommandResult::default()
                    },
                    Err(e) => CommandResult {
                        command_id: cmd.command_id.clone(),
                        status: "failed".to_string(),
                        result: None,
                        error: Some(e.to_string()),
                        completed_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
                        executed_by: Some(ctx.control_plane.to_string()),
                        ..CommandResult::default()
                    },
                }
            }
        }
        Err(e) => {
            // Failed to parse command parameters
            error!(command_id = %cmd.command_id, error = %e, "failed to parse command");
            CommandResult {
                command_id: cmd.command_id.clone(),
                status: "failed".to_string(),
                result: None,
                error: Some(format!("Invalid command parameters: {}", e)),
                completed_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
                executed_by: Some(ctx.control_plane.to_string()),
                ..CommandResult::default()
            }
        }
    };

    // Report the result back
    info!(
        command_id = %cmd_result.command_id,
        status = %cmd_result.status,
        "reporting command result to stacker"
    );
    http_polling::report_result_with_retry(
        &ctx.dashboard_url,
        &ctx.agent_id,
        &ctx.token_provider,
        &cmd_result.command_id,
        &ctx.deployment_hash,
        &cmd_result.status,
        &cmd_result.result,
        &cmd_result.error,
        &cmd_result.completed_at,
    )
    .await?;
    info!(
        command_id = %cmd_result.command_id,
        "stacker acknowledged command result"
    );

    if let Some(app_status) = build_app_status_update(&cmd_result) {
        if let Err(e) = http_polling::update_app_status_with_retry(
            &ctx.dashboard_url,
            &ctx.agent_id,
            &ctx.token_provider,
            &app_status,
        )
        .await
        {
            warn!(
                command_id = %cmd_result.command_id,
                error = %e,
                "failed to update app status"
            );
        } else {
            info!(
                command_id = %cmd_result.command_id,
                status = %app_status.status,
                "reported app status to stacker"
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
