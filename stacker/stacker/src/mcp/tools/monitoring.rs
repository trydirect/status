//! MCP Tools for Logs & Monitoring via Status Agent.
//!
//! These tools provide AI access to:
//! - Container logs (paginated, redacted)
//! - Container health metrics (CPU, RAM, network)
//! - Deployment-wide container status
//!
//! Commands are dispatched to Status Agent via Stacker's agent communication layer.
//!
//! Deployment resolution is handled via `DeploymentIdentifier` which supports:
//! - Stack Builder deployments (deployment_hash directly)
//! - User Service installations (deployment_id → lookup hash via connector)

use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::time::{sleep, Duration, Instant};

use crate::connectors::user_service::UserServiceDeploymentResolver;
use crate::db;
use crate::mcp::protocol::{Tool, ToolContent};
use crate::mcp::registry::{ToolContext, ToolHandler};
use crate::models::{Command, CommandPriority};
use crate::services::{DeploymentIdentifier, DeploymentResolver, VaultService};
use serde::Deserialize;

const DEFAULT_LOG_LIMIT: usize = 100;
const MAX_LOG_LIMIT: usize = 500;
const COMMAND_RESULT_TIMEOUT_SECS: u64 = 8;
const COMMAND_POLL_INTERVAL_MS: u64 = 400;

fn paused_deployment_cli_commands(server_ip: Option<&str>) -> Vec<String> {
    let mut commands = vec![
        "stacker status".to_string(),
        "stacker status --watch".to_string(),
        "stacker agent status".to_string(),
        "stacker logs --tail 100".to_string(),
    ];

    if let Some(ip) = server_ip.filter(|ip| !ip.trim().is_empty()) {
        commands.push(format!(
            "ssh -i ~/.config/stacker/ssh/<server-key> -p 22 root@{}",
            ip
        ));
    }

    commands
}

fn paused_deployment_mcp_sequence() -> Vec<&'static str> {
    vec![
        "get_deployment_status",
        "get_deployment_events",
        "get_deployment_state",
        "get_docker_compose_yaml",
        "list_containers",
        "get_container_logs",
        "get_error_summary",
        "get_container_health",
        "escalate_to_support",
    ]
}

/// Helper to create a resolver from context.
/// Uses UserServiceDeploymentResolver from connectors to support legacy installations.
fn create_resolver(context: &ToolContext) -> UserServiceDeploymentResolver {
    UserServiceDeploymentResolver::from_context(
        &context.settings.user_service_url,
        context.user.access_token.as_deref(),
    )
}

/// Poll for command result with timeout.
/// Waits up to COMMAND_RESULT_TIMEOUT_SECS for the command to complete.
/// Returns the command if result/error is available, or None if timeout.
async fn wait_for_command_result(
    pg_pool: &sqlx::PgPool,
    command_id: &str,
) -> Result<Option<Command>, String> {
    let wait_deadline = Instant::now() + Duration::from_secs(COMMAND_RESULT_TIMEOUT_SECS);

    while Instant::now() < wait_deadline {
        let fetched = db::command::fetch_by_command_id(pg_pool, command_id)
            .await
            .map_err(|e| format!("Failed to fetch command: {}", e))?;

        if let Some(cmd) = fetched {
            let status = cmd.status.to_lowercase();
            // Return if completed, failed, or has result/error
            if status == "completed"
                || status == "failed"
                || cmd.result.is_some()
                || cmd.error.is_some()
            {
                return Ok(Some(cmd));
            }
        }

        sleep(Duration::from_millis(COMMAND_POLL_INTERVAL_MS)).await;
    }

    Ok(None)
}

/// Get container logs from a deployment
pub struct GetContainerLogsTool;

#[async_trait]
impl ToolHandler for GetContainerLogsTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            #[serde(default)]
            deployment_id: Option<i64>,
            #[serde(default)]
            deployment_hash: Option<String>,
            #[serde(default)]
            app_code: Option<String>,
            #[serde(default)]
            limit: Option<usize>,
            #[serde(default)]
            cursor: Option<String>,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        // Create identifier from args (prefers hash if both provided)
        let identifier =
            DeploymentIdentifier::try_from_options(params.deployment_hash, params.deployment_id)?;

        // Resolve to deployment_hash
        let resolver = create_resolver(context);
        let deployment_hash = resolver.resolve(&identifier).await?;

        let limit = params.limit.unwrap_or(DEFAULT_LOG_LIMIT).min(MAX_LOG_LIMIT);

        // Create command for agent
        let command_id = uuid::Uuid::new_v4().to_string();
        let command = Command::new(
            command_id.clone(),
            deployment_hash.clone(),
            "logs".to_string(),
            context.user.id.clone(),
        )
        .with_parameters(json!({
            "name": "stacker.logs",
            "params": {
                "deployment_hash": deployment_hash,
                "app_code": params.app_code.clone().unwrap_or_default(),
                "limit": limit,
                "cursor": params.cursor,
                "redact": true  // Always redact for AI safety
            }
        }));

        // Insert command and add to queue
        let command = db::command::insert(&context.pg_pool, &command)
            .await
            .map_err(|e| format!("Failed to create command: {}", e))?;

        db::command::add_to_queue(
            &context.pg_pool,
            &command.command_id,
            &deployment_hash,
            &CommandPriority::Normal,
        )
        .await
        .map_err(|e| format!("Failed to queue command: {}", e))?;

        // Wait for result or timeout
        let result = if let Some(cmd) =
            wait_for_command_result(&context.pg_pool, &command.command_id).await?
        {
            let status = cmd.status.to_lowercase();
            json!({
                "status": status,
                "command_id": cmd.command_id,
                "deployment_hash": deployment_hash,
                "app_code": params.app_code,
                "limit": limit,
                "result": cmd.result,
                "error": cmd.error,
                "message": "Logs retrieved."
            })
        } else {
            json!({
                "status": "queued",
                "command_id": command.command_id,
                "deployment_hash": deployment_hash,
                "app_code": params.app_code,
                "limit": limit,
                "message": "Log request queued. Agent will process shortly."
            })
        };

        tracing::info!(
            user_id = %context.user.id,
            deployment_id = ?params.deployment_id,
            deployment_hash = %deployment_hash,
            "Queued logs command via MCP"
        );

        Ok(ToolContent::Text {
            text: result.to_string(),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "get_container_logs".to_string(),
            description: "Fetch container logs from a deployment. Logs are automatically redacted to remove sensitive information like passwords and API keys.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "deployment_id": {
                        "type": "number",
                        "description": "The deployment/installation ID (for legacy User Service deployments)"
                    },
                    "deployment_hash": {
                        "type": "string",
                        "description": "The deployment hash (for Stack Builder deployments). Use this if available in context."
                    },
                    "app_code": {
                        "type": "string",
                        "description": "Specific app/container to get logs from (e.g., 'nginx', 'postgres'). If omitted, returns logs from all containers."
                    },
                    "limit": {
                        "type": "number",
                        "description": "Maximum number of log lines to return (default: 100, max: 500)"
                    },
                    "cursor": {
                        "type": "string",
                        "description": "Pagination cursor for fetching more logs"
                    }
                },
                "required": []
            }),
        }
    }
}

/// Get container health metrics from a deployment
pub struct GetContainerHealthTool;

#[async_trait]
impl ToolHandler for GetContainerHealthTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            #[serde(default)]
            deployment_id: Option<i64>,
            #[serde(default)]
            deployment_hash: Option<String>,
            #[serde(default)]
            app_code: Option<String>,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        // Create identifier and resolve to hash
        let identifier =
            DeploymentIdentifier::try_from_options(params.deployment_hash, params.deployment_id)?;
        let resolver = create_resolver(context);
        let deployment_hash = resolver.resolve(&identifier).await?;

        // Create health command for agent
        let command_id = uuid::Uuid::new_v4().to_string();
        let command = Command::new(
            command_id.clone(),
            deployment_hash.clone(),
            "health".to_string(),
            context.user.id.clone(),
        )
        .with_parameters(json!({
            "name": "stacker.health",
            "params": {
                "deployment_hash": deployment_hash,
                "app_code": params.app_code.clone().unwrap_or_default(),
                "include_metrics": true
            }
        }));

        let command = db::command::insert(&context.pg_pool, &command)
            .await
            .map_err(|e| format!("Failed to create command: {}", e))?;

        db::command::add_to_queue(
            &context.pg_pool,
            &command.command_id,
            &deployment_hash,
            &CommandPriority::Normal,
        )
        .await
        .map_err(|e| format!("Failed to queue command: {}", e))?;

        // Wait for result or timeout
        let result = if let Some(cmd) =
            wait_for_command_result(&context.pg_pool, &command.command_id).await?
        {
            let status = cmd.status.to_lowercase();
            json!({
                "status": status,
                "command_id": cmd.command_id,
                "deployment_hash": deployment_hash,
                "app_code": params.app_code,
                "result": cmd.result,
                "error": cmd.error,
                "message": "Health metrics retrieved."
            })
        } else {
            json!({
                "status": "queued",
                "command_id": command.command_id,
                "deployment_hash": deployment_hash,
                "app_code": params.app_code,
                "message": "Health check queued. Agent will process shortly."
            })
        };

        tracing::info!(
            user_id = %context.user.id,
            deployment_id = ?params.deployment_id,
            deployment_hash = %deployment_hash,
            "Queued health command via MCP"
        );

        Ok(ToolContent::Text {
            text: result.to_string(),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "get_container_health".to_string(),
            description: "Get health metrics for containers in a deployment including CPU usage, memory usage, network I/O, and uptime.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "deployment_id": {
                        "type": "number",
                        "description": "The deployment/installation ID (for legacy User Service deployments)"
                    },
                    "deployment_hash": {
                        "type": "string",
                        "description": "The deployment hash (for Stack Builder deployments). Use this if available in context."
                    },
                    "app_code": {
                        "type": "string",
                        "description": "Specific app/container to check (e.g., 'nginx', 'postgres'). If omitted, returns health for all containers."
                    }
                },
                "required": []
            }),
        }
    }
}

/// Restart a container in a deployment
pub struct RestartContainerTool;

#[async_trait]
impl ToolHandler for RestartContainerTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            #[serde(default)]
            deployment_id: Option<i64>,
            #[serde(default)]
            deployment_hash: Option<String>,
            app_code: String,
            #[serde(default)]
            force: bool,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        if params.app_code.trim().is_empty() {
            return Err("app_code is required to restart a specific container".to_string());
        }

        // Create identifier and resolve to hash
        let identifier =
            DeploymentIdentifier::try_from_options(params.deployment_hash, params.deployment_id)?;
        let resolver = create_resolver(context);
        let deployment_hash = resolver.resolve(&identifier).await?;

        // Create restart command for agent
        let command_id = uuid::Uuid::new_v4().to_string();
        let command = Command::new(
            command_id.clone(),
            deployment_hash.clone(),
            "restart".to_string(),
            context.user.id.clone(),
        )
        .with_priority(CommandPriority::High) // Restart is high priority
        .with_parameters(json!({
            "name": "stacker.restart",
            "params": {
                "deployment_hash": deployment_hash,
                "app_code": params.app_code.clone(),
                "force": params.force
            }
        }));

        let command = db::command::insert(&context.pg_pool, &command)
            .await
            .map_err(|e| format!("Failed to create command: {}", e))?;

        db::command::add_to_queue(
            &context.pg_pool,
            &command.command_id,
            &deployment_hash,
            &CommandPriority::High,
        )
        .await
        .map_err(|e| format!("Failed to queue command: {}", e))?;

        let result = json!({
            "status": "queued",
            "command_id": command.command_id,
            "deployment_hash": deployment_hash,
            "app_code": params.app_code,
            "message": format!("Restart command for '{}' queued. Container will restart shortly.", params.app_code)
        });

        tracing::warn!(
            user_id = %context.user.id,
            deployment_id = ?params.deployment_id,
            deployment_hash = %deployment_hash,
            app_code = %params.app_code,
            "Queued RESTART command via MCP"
        );

        Ok(ToolContent::Text {
            text: result.to_string(),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "restart_container".to_string(),
            description: "Restart a specific container in a deployment. This is a potentially disruptive action - use when a container is unhealthy or needs to pick up configuration changes.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "deployment_id": {
                        "type": "number",
                        "description": "The deployment/installation ID (for legacy User Service deployments)"
                    },
                    "deployment_hash": {
                        "type": "string",
                        "description": "The deployment hash (for Stack Builder deployments). Use this if available in context."
                    },
                    "app_code": {
                        "type": "string",
                        "description": "The app/container code to restart (e.g., 'nginx', 'postgres')"
                    },
                    "force": {
                        "type": "boolean",
                        "description": "Force restart even if container appears healthy (default: false)"
                    }
                },
                "required": ["app_code"]
            }),
        }
    }
}

/// Diagnose deployment issues
pub struct DiagnoseDeploymentTool;

#[async_trait]
impl ToolHandler for DiagnoseDeploymentTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            #[serde(default)]
            deployment_id: Option<i64>,
            #[serde(default)]
            deployment_hash: Option<String>,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        // Create identifier and resolve with full info
        let identifier = DeploymentIdentifier::try_from_options(
            params.deployment_hash.clone(),
            params.deployment_id,
        )?;
        let resolver = create_resolver(context);
        let info = resolver.resolve_with_info(&identifier).await?;

        let deployment_hash = info.deployment_hash.clone();
        let mut status = info.status;
        let mut domain = info.domain;
        let server_ip = info.server_ip;
        let mut apps_info: Option<Value> = info.apps.as_ref().map(|apps| {
            json!(apps
                .iter()
                .map(|a| json!({
                    "app_code": a.app_code,
                    "display_name": a.name,
                    "version": a.version,
                    "port": a.port
                }))
                .collect::<Vec<_>>())
        });

        // For Stack Builder deployments (hash-based), fetch from Stacker's database
        if params.deployment_hash.is_some() || (apps_info.is_none() && !deployment_hash.is_empty())
        {
            // Fetch deployment from Stacker DB
            if let Ok(Some(deployment)) =
                db::deployment::fetch_by_deployment_hash(&context.pg_pool, &deployment_hash).await
            {
                status = if deployment.status.is_empty() {
                    "unknown".to_string()
                } else {
                    deployment.status.clone()
                };

                // Fetch apps from project
                if let Ok(project_apps) =
                    db::project_app::fetch_by_project(&context.pg_pool, deployment.project_id).await
                {
                    let apps_list: Vec<Value> = project_apps
                        .iter()
                        .map(|app| {
                            json!({
                                "app_code": app.code,
                                "display_name": app.name,
                                "image": app.image,
                                "domain": app.domain,
                                "status": "configured"
                            })
                        })
                        .collect();
                    apps_info = Some(json!(apps_list));

                    // Try to get domain from first app if not set
                    if domain.is_none() {
                        domain = project_apps.iter().find_map(|a| a.domain.clone());
                    }
                }
            }
        }

        // Build diagnostic summary
        let mut issues: Vec<String> = Vec::new();
        let mut recommendations: Vec<String> = Vec::new();

        // Check deployment status
        match status.as_str() {
            "failed" => {
                issues.push("Deployment is in FAILED state".to_string());
                recommendations.push("Check deployment logs for error details".to_string());
                recommendations.push("Verify cloud credentials are valid".to_string());
            }
            "paused" => {
                issues.push("Deployment is PAUSED and needs troubleshooting".to_string());
                recommendations.push(
                    "Continue with stacker status --watch to collect the final installer message"
                        .to_string(),
                );
                recommendations.push(
                    "Use the backup SSH command printed by deploy if the server IP is reachable"
                        .to_string(),
                );
                recommendations.push("Inspect Docker Compose config, container logs, and config-bundle file mappings before redeploying".to_string());
            }
            "pending" => {
                issues.push("Deployment is still PENDING".to_string());
                recommendations.push(
                    "Wait for deployment to complete or check for stuck processes".to_string(),
                );
            }
            "running" | "completed" => {
                // Deployment looks healthy from our perspective
            }
            s => {
                issues.push(format!("Deployment has unusual status: {}", s));
            }
        }

        // Check if agent is connected (check last heartbeat)
        if let Ok(Some(agent)) =
            db::agent::fetch_by_deployment_hash(&context.pg_pool, &deployment_hash).await
        {
            if let Some(last_seen) = agent.last_heartbeat {
                let now = chrono::Utc::now();
                let diff = now.signed_duration_since(last_seen);
                if diff.num_minutes() > 5 {
                    issues.push(format!(
                        "Agent last seen {} minutes ago - may be offline",
                        diff.num_minutes()
                    ));
                    recommendations.push(
                        "Check if server is running and has network connectivity".to_string(),
                    );
                }
            }
        } else {
            issues.push("No agent registered for this deployment".to_string());
            recommendations
                .push("Ensure the Status Agent is installed and running on the server".to_string());
        }

        let result = json!({
            "deployment_id": params.deployment_id,
            "deployment_hash": deployment_hash,
            "status": status,
            "domain": domain,
            "server_ip": server_ip,
            "apps": apps_info,
            "issues_found": issues.len(),
            "issues": issues,
            "recommendations": recommendations,
            "mcp_tool_sequence": paused_deployment_mcp_sequence(),
            "stacker_cli_commands": if status == "paused" || status == "failed" {
                paused_deployment_cli_commands(server_ip.as_deref())
            } else {
                vec![
                    "stacker status".to_string(),
                    "stacker agent status".to_string(),
                ]
            },
            "safe_ai_context": {
                "include": [
                    "deployment id/hash and status",
                    "last installer message",
                    "sanitized docker compose error",
                    "redacted compose env_file/image/ports snippets",
                    "config bundle source -> destination mappings"
                ],
                "exclude": [
                    "cloud tokens",
                    "registry tokens",
                    "private SSH keys",
                    "full .env contents"
                ]
            },
            "next_steps": if issues.is_empty() {
                vec!["Deployment appears healthy. Use get_container_health for detailed metrics.".to_string()]
            } else {
                vec!["Address the issues above, then re-run diagnosis.".to_string()]
            }
        });

        tracing::info!(
            user_id = %context.user.id,
            deployment_id = ?params.deployment_id,
            deployment_hash = %deployment_hash,
            issues = issues.len(),
            "Ran deployment diagnosis via MCP"
        );

        Ok(ToolContent::Text {
            text: serde_json::to_string_pretty(&result).unwrap_or_else(|_| result.to_string()),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "diagnose_deployment".to_string(),
            description: "Run diagnostic checks on a deployment to identify potential issues. Returns a list of detected problems and recommended actions.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "deployment_id": {
                        "type": "number",
                        "description": "The deployment/installation ID (for legacy User Service deployments)"
                    },
                    "deployment_hash": {
                        "type": "string",
                        "description": "The deployment hash (for Stack Builder deployments). Use this if available in context."
                    }
                },
                "required": []
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{paused_deployment_cli_commands, paused_deployment_mcp_sequence};

    #[test]
    fn paused_deployment_cli_commands_include_status_and_ssh_when_ip_exists() {
        let commands = paused_deployment_cli_commands(Some("178.105.162.176"));

        assert!(commands.contains(&"stacker status".to_string()));
        assert!(commands.contains(&"stacker status --watch".to_string()));
        assert!(commands
            .iter()
            .any(|command| command.contains("root@178.105.162.176")));
    }

    #[test]
    fn paused_deployment_mcp_sequence_prioritizes_diagnosis_before_escalation() {
        let sequence = paused_deployment_mcp_sequence();

        assert_eq!(sequence.first(), Some(&"get_deployment_status"));
        assert!(sequence.contains(&"get_container_logs"));
        assert_eq!(sequence.last(), Some(&"escalate_to_support"));
    }
}

/// Stop a container in a deployment
pub struct StopContainerTool;

#[async_trait]
impl ToolHandler for StopContainerTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            #[serde(default)]
            deployment_id: Option<i64>,
            #[serde(default)]
            deployment_hash: Option<String>,
            app_code: String,
            #[serde(default)]
            timeout: Option<u32>,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        if params.app_code.trim().is_empty() {
            return Err("app_code is required to stop a specific container".to_string());
        }

        // Create identifier and resolve to hash
        let identifier =
            DeploymentIdentifier::try_from_options(params.deployment_hash, params.deployment_id)?;
        let resolver = create_resolver(context);
        let deployment_hash = resolver.resolve(&identifier).await?;

        // Create stop command for agent
        let timeout = params.timeout.unwrap_or(30); // Default 30 second graceful shutdown
        let command_id = uuid::Uuid::new_v4().to_string();
        let command = Command::new(
            command_id.clone(),
            deployment_hash.clone(),
            "stop".to_string(),
            context.user.id.clone(),
        )
        .with_priority(CommandPriority::High)
        .with_parameters(json!({
            "name": "stacker.stop",
            "params": {
                "deployment_hash": deployment_hash,
                "app_code": params.app_code.clone(),
                "timeout": timeout
            }
        }));

        let command = db::command::insert(&context.pg_pool, &command)
            .await
            .map_err(|e| format!("Failed to create command: {}", e))?;

        db::command::add_to_queue(
            &context.pg_pool,
            &command.command_id,
            &deployment_hash,
            &CommandPriority::High,
        )
        .await
        .map_err(|e| format!("Failed to queue command: {}", e))?;

        let result = json!({
            "status": "queued",
            "command_id": command.command_id,
            "deployment_hash": deployment_hash,
            "app_code": params.app_code,
            "timeout": timeout,
            "message": format!("Stop command for '{}' queued. Container will stop within {} seconds.", params.app_code, timeout)
        });

        tracing::warn!(
            user_id = %context.user.id,
            deployment_id = ?params.deployment_id,
            deployment_hash = %deployment_hash,
            app_code = %params.app_code,
            "Queued STOP command via MCP"
        );

        Ok(ToolContent::Text {
            text: result.to_string(),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "stop_container".to_string(),
            description: "Stop a specific container in a deployment. This will gracefully stop the container, allowing it to complete in-progress work. Use restart_container if you want to stop and start again.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "deployment_id": {
                        "type": "number",
                        "description": "The deployment/installation ID (for legacy User Service deployments)"
                    },
                    "deployment_hash": {
                        "type": "string",
                        "description": "The deployment hash (for Stack Builder deployments). Use this if available in context."
                    },
                    "app_code": {
                        "type": "string",
                        "description": "The app/container code to stop (e.g., 'nginx', 'postgres')"
                    },
                    "timeout": {
                        "type": "number",
                        "description": "Graceful shutdown timeout in seconds (default: 30)"
                    }
                },
                "required": ["app_code"]
            }),
        }
    }
}

/// Start a stopped container in a deployment
pub struct StartContainerTool;

#[async_trait]
impl ToolHandler for StartContainerTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            #[serde(default)]
            deployment_id: Option<i64>,
            #[serde(default)]
            deployment_hash: Option<String>,
            app_code: String,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        if params.app_code.trim().is_empty() {
            return Err("app_code is required to start a specific container".to_string());
        }

        // Create identifier and resolve to hash
        let identifier =
            DeploymentIdentifier::try_from_options(params.deployment_hash, params.deployment_id)?;
        let resolver = create_resolver(context);
        let deployment_hash = resolver.resolve(&identifier).await?;

        // Create start command for agent
        let command_id = uuid::Uuid::new_v4().to_string();
        let command = Command::new(
            command_id.clone(),
            deployment_hash.clone(),
            "start".to_string(),
            context.user.id.clone(),
        )
        .with_priority(CommandPriority::High)
        .with_parameters(json!({
            "name": "stacker.start",
            "params": {
                "deployment_hash": deployment_hash,
                "app_code": params.app_code.clone()
            }
        }));

        let command = db::command::insert(&context.pg_pool, &command)
            .await
            .map_err(|e| format!("Failed to create command: {}", e))?;

        db::command::add_to_queue(
            &context.pg_pool,
            &command.command_id,
            &deployment_hash,
            &CommandPriority::High,
        )
        .await
        .map_err(|e| format!("Failed to queue command: {}", e))?;

        let result = json!({
            "status": "queued",
            "command_id": command.command_id,
            "deployment_hash": deployment_hash,
            "app_code": params.app_code,
            "message": format!("Start command for '{}' queued. Container will start shortly.", params.app_code)
        });

        tracing::info!(
            user_id = %context.user.id,
            deployment_id = ?params.deployment_id,
            deployment_hash = %deployment_hash,
            app_code = %params.app_code,
            "Queued START command via MCP"
        );

        Ok(ToolContent::Text {
            text: result.to_string(),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "start_container".to_string(),
            description: "Start a stopped container in a deployment. Use this after stop_container to bring a container back online.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "deployment_id": {
                        "type": "number",
                        "description": "The deployment/installation ID (for legacy User Service deployments)"
                    },
                    "deployment_hash": {
                        "type": "string",
                        "description": "The deployment hash (for Stack Builder deployments). Use this if available in context."
                    },
                    "app_code": {
                        "type": "string",
                        "description": "The app/container code to start (e.g., 'nginx', 'postgres')"
                    }
                },
                "required": ["app_code"]
            }),
        }
    }
}

/// Get a summary of errors from container logs
pub struct GetErrorSummaryTool;

#[async_trait]
impl ToolHandler for GetErrorSummaryTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            #[serde(default)]
            deployment_id: Option<i64>,
            #[serde(default)]
            deployment_hash: Option<String>,
            #[serde(default)]
            app_code: Option<String>,
            #[serde(default)]
            hours: Option<u32>,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        // Create identifier and resolve to hash
        let identifier =
            DeploymentIdentifier::try_from_options(params.deployment_hash, params.deployment_id)?;
        let resolver = create_resolver(context);
        let deployment_hash = resolver.resolve(&identifier).await?;

        let hours = params.hours.unwrap_or(24).min(168); // Max 7 days

        // Create error summary command for agent
        let command_id = uuid::Uuid::new_v4().to_string();
        let command = Command::new(
            command_id.clone(),
            deployment_hash.clone(),
            "error_summary".to_string(),
            context.user.id.clone(),
        )
        .with_parameters(json!({
            "name": "stacker.error_summary",
            "params": {
                "deployment_hash": deployment_hash,
                "app_code": params.app_code.clone().unwrap_or_default(),
                "hours": hours,
                "redact": true
            }
        }));

        let command = db::command::insert(&context.pg_pool, &command)
            .await
            .map_err(|e| format!("Failed to create command: {}", e))?;

        db::command::add_to_queue(
            &context.pg_pool,
            &command.command_id,
            &deployment_hash,
            &CommandPriority::Normal,
        )
        .await
        .map_err(|e| format!("Failed to queue command: {}", e))?;

        let result = json!({
            "status": "queued",
            "command_id": command.command_id,
            "deployment_hash": deployment_hash,
            "app_code": params.app_code,
            "hours": hours,
            "message": format!("Error summary request queued for the last {} hours. Agent will analyze logs shortly.", hours)
        });

        tracing::info!(
            user_id = %context.user.id,
            deployment_id = ?params.deployment_id,
            deployment_hash = %deployment_hash,
            hours = hours,
            "Queued error summary command via MCP"
        );

        Ok(ToolContent::Text {
            text: result.to_string(),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "get_error_summary".to_string(),
            description: "Get a summary of errors and warnings from container logs. Returns categorized error counts, most frequent errors, and suggested fixes.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "deployment_id": {
                        "type": "number",
                        "description": "The deployment/installation ID (for legacy User Service deployments)"
                    },
                    "deployment_hash": {
                        "type": "string",
                        "description": "The deployment hash (for Stack Builder deployments). Use this if available in context."
                    },
                    "app_code": {
                        "type": "string",
                        "description": "Specific app/container to analyze. If omitted, analyzes all containers."
                    },
                    "hours": {
                        "type": "number",
                        "description": "Number of hours to look back (default: 24, max: 168)"
                    }
                },
                "required": []
            }),
        }
    }
}

/// List all containers in a deployment
/// This tool discovers running containers and their status, which is essential
/// for subsequent operations like proxy configuration, log retrieval, etc.
pub struct ListContainersTool;

#[async_trait]
impl ToolHandler for ListContainersTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            #[serde(default)]
            deployment_id: Option<i64>,
            #[serde(default)]
            deployment_hash: Option<String>,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        // Create identifier and resolve to hash
        let identifier =
            DeploymentIdentifier::try_from_options(params.deployment_hash, params.deployment_id)?;
        let resolver = create_resolver(context);
        let deployment_hash = resolver.resolve(&identifier).await?;

        // Create list_containers command for agent
        let command_id = uuid::Uuid::new_v4().to_string();
        let command = Command::new(
            command_id.clone(),
            deployment_hash.clone(),
            "list_containers".to_string(),
            context.user.id.clone(),
        )
        .with_parameters(json!({
            "name": "stacker.list_containers",
            "params": {
                "deployment_hash": deployment_hash.clone(),
            }
        }));

        let command = db::command::insert(&context.pg_pool, &command)
            .await
            .map_err(|e| format!("Failed to create command: {}", e))?;

        db::command::add_to_queue(
            &context.pg_pool,
            &command.command_id,
            &deployment_hash,
            &CommandPriority::High, // High priority for quick discovery
        )
        .await
        .map_err(|e| format!("Failed to queue command: {}", e))?;

        // Also try to get containers from project_app table if we have a project
        let mut known_apps: Vec<serde_json::Value> = Vec::new();
        if let Ok(Some(deployment)) =
            db::deployment::fetch_by_deployment_hash(&context.pg_pool, &deployment_hash).await
        {
            if let Ok(apps) =
                db::project_app::fetch_by_project(&context.pg_pool, deployment.project_id).await
            {
                for app in apps {
                    known_apps.push(json!({
                        "code": app.code,
                        "name": app.name,
                        "image": app.image,
                        "parent_app_code": app.parent_app_code,
                        "enabled": app.enabled,
                        "ports": app.ports,
                        "domain": app.domain,
                    }));
                }
            }
        }

        let result = json!({
            "status": "queued",
            "command_id": command.command_id,
            "deployment_hash": deployment_hash,
            "message": "Container listing queued. Agent will respond with running containers shortly.",
            "known_apps": known_apps,
            "hint": if !known_apps.is_empty() {
                format!("Found {} registered apps in this deployment. Use these app codes for logs, health, restart, or proxy commands.", known_apps.len())
            } else {
                "No registered apps found yet. Agent will discover running containers.".to_string()
            }
        });

        tracing::info!(
            user_id = %context.user.id,
            deployment_hash = %deployment_hash,
            known_apps_count = known_apps.len(),
            "Queued list_containers command via MCP"
        );

        Ok(ToolContent::Text {
            text: serde_json::to_string_pretty(&result).unwrap_or_else(|_| result.to_string()),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "list_containers".to_string(),
            description: "List all containers running in a deployment. Returns container names, status, and registered app configurations. Use this to discover available containers before configuring proxies, viewing logs, or checking health.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "deployment_id": {
                        "type": "number",
                        "description": "The deployment/installation ID (for legacy User Service deployments)"
                    },
                    "deployment_hash": {
                        "type": "string",
                        "description": "The deployment hash (for Stack Builder deployments). Use this if available in context."
                    }
                },
                "required": []
            }),
        }
    }
}

/// Get the docker-compose.yml configuration for a deployment
/// Retrieves the compose file from Vault for analysis and troubleshooting
pub struct GetDockerComposeYamlTool;

#[async_trait]
impl ToolHandler for GetDockerComposeYamlTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            #[serde(default)]
            deployment_id: Option<i64>,
            #[serde(default)]
            deployment_hash: Option<String>,
            #[serde(default)]
            app_code: Option<String>,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        // Create identifier and resolve to hash
        let identifier =
            DeploymentIdentifier::try_from_options(params.deployment_hash, params.deployment_id)?;
        let resolver = create_resolver(context);
        let deployment_hash = resolver.resolve(&identifier).await?;

        // Initialize Vault service
        let vault = VaultService::from_settings(&context.settings.vault)
            .map_err(|e| format!("Vault service not configured: {}", e))?;

        // Determine what to fetch: specific app compose or global compose
        let app_name = params
            .app_code
            .clone()
            .unwrap_or_else(|| "_compose".to_string());

        match vault.fetch_app_config(&deployment_hash, &app_name).await {
            Ok(config) => {
                let result = json!({
                    "deployment_hash": deployment_hash,
                    "app_code": params.app_code,
                    "content_type": config.content_type,
                    "destination_path": config.destination_path,
                    "compose_yaml": config.content,
                    "message": if params.app_code.is_some() {
                        format!("Docker compose for app '{}' retrieved successfully", app_name)
                    } else {
                        "Docker compose configuration retrieved successfully".to_string()
                    }
                });

                tracing::info!(
                    user_id = %context.user.id,
                    deployment_hash = %deployment_hash,
                    app_code = ?params.app_code,
                    "Retrieved docker-compose.yml via MCP"
                );

                Ok(ToolContent::Text {
                    text: serde_json::to_string_pretty(&result)
                        .unwrap_or_else(|_| result.to_string()),
                })
            }
            Err(e) => {
                tracing::warn!(
                    user_id = %context.user.id,
                    deployment_hash = %deployment_hash,
                    error = %e,
                    "Failed to fetch docker-compose.yml from Vault"
                );
                Err(format!("Failed to retrieve docker-compose.yml: {}", e))
            }
        }
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "get_docker_compose_yaml".to_string(),
            description: "Retrieve the docker-compose.yml configuration for a deployment. This shows the actual service definitions, volumes, networks, and environment variables. Useful for troubleshooting configuration issues.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "deployment_id": {
                        "type": "number",
                        "description": "The deployment/installation ID (for legacy User Service deployments)"
                    },
                    "deployment_hash": {
                        "type": "string",
                        "description": "The deployment hash (for Stack Builder deployments). Use this if available in context."
                    },
                    "app_code": {
                        "type": "string",
                        "description": "Specific app code to get compose for. If omitted, returns the main docker-compose.yml for the entire stack."
                    }
                },
                "required": []
            }),
        }
    }
}

/// Get server resource metrics (CPU, RAM, disk) from a deployment
/// Dispatches a command to the status agent to collect system metrics
pub struct GetServerResourcesTool;

#[async_trait]
impl ToolHandler for GetServerResourcesTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            #[serde(default)]
            deployment_id: Option<i64>,
            #[serde(default)]
            deployment_hash: Option<String>,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        // Create identifier and resolve to hash
        let identifier =
            DeploymentIdentifier::try_from_options(params.deployment_hash, params.deployment_id)?;
        let resolver = create_resolver(context);
        let deployment_hash = resolver.resolve(&identifier).await?;

        // Create server_resources command for agent
        let command_id = uuid::Uuid::new_v4().to_string();
        let command = Command::new(
            command_id.clone(),
            deployment_hash.clone(),
            "server_resources".to_string(),
            context.user.id.clone(),
        )
        .with_parameters(json!({
            "name": "stacker.server_resources",
            "params": {
                "deployment_hash": deployment_hash.clone(),
                "include_disk": true,
                "include_network": true
            }
        }));

        let command = db::command::insert(&context.pg_pool, &command)
            .await
            .map_err(|e| format!("Failed to create command: {}", e))?;

        db::command::add_to_queue(
            &context.pg_pool,
            &command.command_id,
            &deployment_hash,
            &CommandPriority::Normal,
        )
        .await
        .map_err(|e| format!("Failed to queue command: {}", e))?;

        // Wait for result or timeout
        let result = if let Some(cmd) =
            wait_for_command_result(&context.pg_pool, &command.command_id).await?
        {
            let status = cmd.status.to_lowercase();
            json!({
                "status": status,
                "command_id": cmd.command_id,
                "deployment_hash": deployment_hash,
                "result": cmd.result,
                "error": cmd.error,
                "message": "Server resources collected.",
                "metrics_included": ["cpu_percent", "memory_used", "memory_total", "disk_used", "disk_total", "network_io"]
            })
        } else {
            json!({
                "status": "queued",
                "command_id": command.command_id,
                "deployment_hash": deployment_hash,
                "message": "Server resources request queued. Agent will collect CPU, RAM, disk, and network metrics shortly.",
                "metrics_included": ["cpu_percent", "memory_used", "memory_total", "disk_used", "disk_total", "network_io"]
            })
        };

        tracing::info!(
            user_id = %context.user.id,
            deployment_hash = %deployment_hash,
            "Queued server_resources command via MCP"
        );

        Ok(ToolContent::Text {
            text: serde_json::to_string_pretty(&result).unwrap_or_else(|_| result.to_string()),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "get_server_resources".to_string(),
            description: "Get server resource metrics including CPU usage, RAM usage, disk space, and network I/O. Useful for diagnosing resource exhaustion issues or capacity planning.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "deployment_id": {
                        "type": "number",
                        "description": "The deployment/installation ID (for legacy User Service deployments)"
                    },
                    "deployment_hash": {
                        "type": "string",
                        "description": "The deployment hash (for Stack Builder deployments). Use this if available in context."
                    }
                },
                "required": []
            }),
        }
    }
}

/// Execute a command inside a running container
/// Allows running diagnostic commands for troubleshooting
pub struct GetContainerExecTool;

#[async_trait]
impl ToolHandler for GetContainerExecTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            #[serde(default)]
            deployment_id: Option<i64>,
            #[serde(default)]
            deployment_hash: Option<String>,
            app_code: String,
            command: String,
            #[serde(default)]
            timeout: Option<u32>,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        if params.app_code.trim().is_empty() {
            return Err("app_code is required to execute a command in a container".to_string());
        }

        if params.command.trim().is_empty() {
            return Err("command is required".to_string());
        }

        // Security: Block dangerous commands
        let blocked_patterns = [
            "rm -rf /", "mkfs", "dd if=", ":(){", // Fork bomb
            "shutdown", "reboot", "halt", "poweroff", "init 0", "init 6",
        ];

        let cmd_lower = params.command.to_lowercase();
        for pattern in &blocked_patterns {
            if cmd_lower.contains(pattern) {
                return Err(format!(
                    "Command '{}' is not allowed for security reasons",
                    pattern
                ));
            }
        }

        // Create identifier and resolve to hash
        let identifier =
            DeploymentIdentifier::try_from_options(params.deployment_hash, params.deployment_id)?;
        let resolver = create_resolver(context);
        let deployment_hash = resolver.resolve(&identifier).await?;

        let timeout = params.timeout.unwrap_or(30).min(120); // Max 2 minutes

        // Create exec command for agent
        let command_id = uuid::Uuid::new_v4().to_string();
        let command = Command::new(
            command_id.clone(),
            deployment_hash.clone(),
            "exec".to_string(),
            context.user.id.clone(),
        )
        .with_priority(CommandPriority::High)
        .with_timeout(timeout as i32)
        .with_parameters(json!({
            "name": "stacker.exec",
            "params": {
                "deployment_hash": deployment_hash.clone(),
                "app_code": params.app_code.clone(),
                "command": params.command.clone(),
                "timeout": timeout,
                "redact_output": true  // Always redact sensitive data
            }
        }));

        let command = db::command::insert(&context.pg_pool, &command)
            .await
            .map_err(|e| format!("Failed to create command: {}", e))?;

        db::command::add_to_queue(
            &context.pg_pool,
            &command.command_id,
            &deployment_hash,
            &CommandPriority::High,
        )
        .await
        .map_err(|e| format!("Failed to queue command: {}", e))?;

        let result = json!({
            "status": "queued",
            "command_id": command.command_id,
            "deployment_hash": deployment_hash,
            "app_code": params.app_code,
            "command": params.command,
            "timeout": timeout,
            "message": format!("Exec command queued for container '{}'. Output will be redacted for security.", params.app_code)
        });

        tracing::warn!(
            user_id = %context.user.id,
            deployment_hash = %deployment_hash,
            app_code = %params.app_code,
            command = %params.command,
            "Queued EXEC command via MCP"
        );

        Ok(ToolContent::Text {
            text: serde_json::to_string_pretty(&result).unwrap_or_else(|_| result.to_string()),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "get_container_exec".to_string(),
            description: "Execute a command inside a running container for troubleshooting. Output is automatically redacted to remove sensitive information. Use for diagnostics like checking disk space, memory, running processes, or verifying config files.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "deployment_id": {
                        "type": "number",
                        "description": "The deployment/installation ID (for legacy User Service deployments)"
                    },
                    "deployment_hash": {
                        "type": "string",
                        "description": "The deployment hash (for Stack Builder deployments). Use this if available in context."
                    },
                    "app_code": {
                        "type": "string",
                        "description": "The app/container code to execute command in (e.g., 'nginx', 'postgres')"
                    },
                    "command": {
                        "type": "string",
                        "description": "The command to execute (e.g., 'df -h', 'free -m', 'ps aux', 'cat /etc/nginx/nginx.conf')"
                    },
                    "timeout": {
                        "type": "number",
                        "description": "Command timeout in seconds (default: 30, max: 120)"
                    }
                },
                "required": ["app_code", "command"]
            }),
        }
    }
}
