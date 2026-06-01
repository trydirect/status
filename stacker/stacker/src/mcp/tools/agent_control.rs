//! MCP Tools for Agent-based App Lifecycle Management.
//!
//! These tools give the AI the ability to deploy new apps, remove apps,
//! and configure reverse proxies on deployments managed by the Status Panel agent.
//!
//! All operations go through the same queue-based dispatch as the monitoring tools:
//! Command → DB queue → Agent polls → Agent executes → Agent reports result.

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::connectors::user_service::UserServiceDeploymentResolver;
use crate::db;
use crate::mcp::protocol::{Tool, ToolContent};
use crate::mcp::registry::{ToolContext, ToolHandler};
use crate::models::{Command, CommandPriority};
use crate::services::{DeploymentIdentifier, DeploymentResolver};

const COMMAND_RESULT_TIMEOUT_SECS: u64 = 15;
const COMMAND_POLL_INTERVAL_MS: u64 = 500;

/// Reuse the polling helper from monitoring (same logic, configurable timeout).
async fn wait_for_command_result(
    pg_pool: &sqlx::PgPool,
    command_id: &str,
    timeout_secs: u64,
) -> Result<Option<crate::models::Command>, String> {
    use tokio::time::{sleep, Duration, Instant};

    let deadline = Instant::now() + Duration::from_secs(timeout_secs);

    while Instant::now() < deadline {
        let fetched = db::command::fetch_by_command_id(pg_pool, command_id)
            .await
            .map_err(|e| format!("Failed to fetch command: {}", e))?;

        if let Some(cmd) = fetched {
            let status = cmd.status.to_lowercase();
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

fn create_resolver(context: &ToolContext) -> UserServiceDeploymentResolver {
    UserServiceDeploymentResolver::from_context(
        &context.settings.user_service_url,
        context.user.access_token.as_deref(),
    )
}

/// Enqueue a command, wait for result, return structured JSON.
async fn enqueue_and_wait(
    context: &ToolContext,
    deployment_hash: &str,
    command_type: &str,
    parameters: Value,
    timeout_secs: u64,
) -> Result<Value, String> {
    let command_id = uuid::Uuid::new_v4().to_string();
    let command = Command::new(
        command_id.clone(),
        deployment_hash.to_string(),
        command_type.to_string(),
        context.user.id.clone(),
    )
    .with_parameters(parameters.clone());

    let command = db::command::insert(&context.pg_pool, &command)
        .await
        .map_err(|e| format!("Failed to create command: {}", e))?;

    db::command::add_to_queue(
        &context.pg_pool,
        &command.command_id,
        deployment_hash,
        &CommandPriority::Normal,
    )
    .await
    .map_err(|e| format!("Failed to queue command: {}", e))?;

    if let Some(cmd) =
        wait_for_command_result(&context.pg_pool, &command.command_id, timeout_secs).await?
    {
        let status = cmd.status.to_lowercase();
        Ok(json!({
            "status": status,
            "command_id": cmd.command_id,
            "deployment_hash": deployment_hash,
            "command_type": command_type,
            "result": cmd.result,
            "error": cmd.error,
        }))
    } else {
        Ok(json!({
            "status": "queued",
            "command_id": command.command_id,
            "deployment_hash": deployment_hash,
            "command_type": command_type,
            "message": "Command queued. Agent will process shortly.",
        }))
    }
}

async fn enqueue_request_and_wait(
    context: &ToolContext,
    request: &crate::cli::stacker_client::AgentEnqueueRequest,
    timeout_secs: u64,
) -> Result<Value, String> {
    let command_id = uuid::Uuid::new_v4().to_string();
    let mut command = Command::new(
        command_id.clone(),
        request.deployment_hash.clone(),
        request.command_type.clone(),
        context.user.id.clone(),
    );
    if let Some(parameters) = request.parameters.clone() {
        command = command.with_parameters(parameters);
    }
    if let Some(timeout_seconds) = request.timeout_seconds {
        command = command.with_timeout(timeout_seconds);
    }

    let command = db::command::insert(&context.pg_pool, &command)
        .await
        .map_err(|e| format!("Failed to create command: {}", e))?;

    db::command::add_to_queue(
        &context.pg_pool,
        &command.command_id,
        &request.deployment_hash,
        &CommandPriority::Normal,
    )
    .await
    .map_err(|e| format!("Failed to queue command: {}", e))?;

    if let Some(cmd) =
        wait_for_command_result(&context.pg_pool, &command.command_id, timeout_secs).await?
    {
        let status = cmd.status.to_lowercase();
        Ok(json!({
            "status": status,
            "command_id": cmd.command_id,
            "deployment_hash": request.deployment_hash,
            "command_type": request.command_type,
            "result": cmd.result,
            "error": cmd.error,
        }))
    } else {
        Ok(json!({
            "status": "queued",
            "command_id": command.command_id,
            "deployment_hash": request.deployment_hash,
            "command_type": request.command_type,
            "message": "Command queued. Agent will process shortly.",
        }))
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Deploy App Tool
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

pub struct DeployAppTool;

#[async_trait]
impl ToolHandler for DeployAppTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            #[serde(default)]
            deployment_id: Option<i64>,
            #[serde(default)]
            deployment_hash: Option<String>,
            app_code: String,
            #[serde(default)]
            image: Option<String>,
            #[serde(default)]
            force_recreate: Option<bool>,
            #[serde(default)]
            force_config_overwrite: Option<bool>,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;
        let force_recreate = params.force_recreate.unwrap_or(false);
        let force_config_overwrite = params.force_config_overwrite.unwrap_or(force_recreate);

        let identifier =
            DeploymentIdentifier::try_from_options(params.deployment_hash, params.deployment_id)?;
        let resolver = create_resolver(context);
        let deployment_hash = resolver.resolve(&identifier).await?;

        let result = enqueue_and_wait(
            context,
            &deployment_hash,
            "deploy_app",
            json!({
                "app_code": params.app_code,
                "image": params.image,
                "pull": true,
                "force_recreate": force_recreate,
                "force_config_overwrite": force_config_overwrite,
            }),
            COMMAND_RESULT_TIMEOUT_SECS,
        )
        .await?;

        tracing::info!(
            user_id = %context.user.id,
            deployment_hash = %deployment_hash,
            app_code = %params.app_code,
            "Queued deploy_app command via MCP"
        );

        Ok(ToolContent::Text {
            text: result.to_string(),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "deploy_app".to_string(),
            description: "Deploy or update an app container on a deployment. The Status Panel agent will pull the image and start the container.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "deployment_id": {
                        "type": "number",
                        "description": "The deployment/installation ID (for User Service deployments)"
                    },
                    "deployment_hash": {
                        "type": "string",
                        "description": "The deployment hash (for Stack Builder deployments)"
                    },
                    "app_code": {
                        "type": "string",
                        "description": "The app code to deploy (e.g., 'nginx', 'postgres', 'myapp')"
                    },
                    "image": {
                        "type": "string",
                        "description": "Docker image to use (e.g., 'nginx:latest'). If omitted, uses the compose config."
                    },
                    "force_recreate": {
                        "type": "boolean",
                        "description": "Force recreate the container even if config hasn't changed"
                    },
                    "force_config_overwrite": {
                        "type": "boolean",
                        "description": "Force overwriting drifted runtime config files such as .env"
                    }
                },
                "required": ["app_code"]
            }),
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Remove App Tool
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

pub struct RemoveAppTool;

#[async_trait]
impl ToolHandler for RemoveAppTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            #[serde(default)]
            deployment_id: Option<i64>,
            #[serde(default)]
            deployment_hash: Option<String>,
            app_code: String,
            #[serde(default)]
            remove_volumes: Option<bool>,
            #[serde(default)]
            remove_image: Option<bool>,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        let identifier =
            DeploymentIdentifier::try_from_options(params.deployment_hash, params.deployment_id)?;
        let resolver = create_resolver(context);
        let deployment_hash = resolver.resolve(&identifier).await?;

        let result = enqueue_and_wait(
            context,
            &deployment_hash,
            "remove_app",
            json!({
                "app_code": params.app_code,
                "delete_config": true,
                "remove_volumes": params.remove_volumes.unwrap_or(false),
                "remove_image": params.remove_image.unwrap_or(false),
            }),
            COMMAND_RESULT_TIMEOUT_SECS,
        )
        .await?;

        tracing::info!(
            user_id = %context.user.id,
            deployment_hash = %deployment_hash,
            app_code = %params.app_code,
            "Queued remove_app command via MCP"
        );

        Ok(ToolContent::Text {
            text: result.to_string(),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "remove_app".to_string(),
            description: "Remove an app container from a deployment. Stops and removes the container, optionally removing volumes and images.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "deployment_id": {
                        "type": "number",
                        "description": "The deployment/installation ID"
                    },
                    "deployment_hash": {
                        "type": "string",
                        "description": "The deployment hash"
                    },
                    "app_code": {
                        "type": "string",
                        "description": "The app code to remove"
                    },
                    "remove_volumes": {
                        "type": "boolean",
                        "description": "Also remove associated volumes (default: false)"
                    },
                    "remove_image": {
                        "type": "boolean",
                        "description": "Also remove the Docker image (default: false)"
                    }
                },
                "required": ["app_code"]
            }),
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Configure Proxy Tool
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

pub struct ConfigureProxyAgentTool;

#[async_trait]
impl ToolHandler for ConfigureProxyAgentTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            #[serde(default)]
            deployment_id: Option<i64>,
            #[serde(default)]
            deployment_hash: Option<String>,
            app_code: String,
            domain_names: Vec<String>,
            forward_port: u16,
            #[serde(default)]
            forward_host: Option<String>,
            #[serde(default = "default_true")]
            ssl_enabled: bool,
            #[serde(default = "default_create")]
            action: String,
        }

        fn default_true() -> bool {
            true
        }
        fn default_create() -> String {
            "create".to_string()
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        let identifier =
            DeploymentIdentifier::try_from_options(params.deployment_hash, params.deployment_id)?;
        let resolver = create_resolver(context);
        let deployment_hash = resolver.resolve(&identifier).await?;

        let result = enqueue_and_wait(
            context,
            &deployment_hash,
            "configure_proxy",
            json!({
                "app_code": params.app_code,
                "domain_names": params.domain_names,
                "forward_host": params.forward_host,
                "forward_port": params.forward_port,
                "ssl_enabled": params.ssl_enabled,
                "ssl_forced": params.ssl_enabled,
                "http2_support": params.ssl_enabled,
                "action": params.action,
            }),
            COMMAND_RESULT_TIMEOUT_SECS,
        )
        .await?;

        tracing::info!(
            user_id = %context.user.id,
            deployment_hash = %deployment_hash,
            app_code = %params.app_code,
            "Queued configure_proxy command via MCP"
        );

        Ok(ToolContent::Text {
            text: result.to_string(),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "configure_proxy_agent".to_string(),
            description: "Configure a reverse proxy (Nginx Proxy Manager) for an app container via the Status Panel agent. Creates, updates, or deletes proxy host entries with optional SSL.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "deployment_id": {
                        "type": "number",
                        "description": "The deployment/installation ID"
                    },
                    "deployment_hash": {
                        "type": "string",
                        "description": "The deployment hash"
                    },
                    "app_code": {
                        "type": "string",
                        "description": "The app code to proxy"
                    },
                    "domain_names": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Domain names to proxy (e.g., ['myapp.example.com'])"
                    },
                    "forward_port": {
                        "type": "number",
                        "description": "Container port to forward to (e.g., 8080)"
                    },
                    "forward_host": {
                        "type": "string",
                        "description": "Container/service name to forward to (defaults to app_code)"
                    },
                    "ssl_enabled": {
                        "type": "boolean",
                        "description": "Enable SSL with Let's Encrypt; set false for plain HTTP hosts (default: true)"
                    },
                    "action": {
                        "type": "string",
                        "enum": ["create", "update", "delete"],
                        "description": "Proxy action: create, update, or delete (default: create)"
                    }
                },
                "required": ["app_code", "domain_names", "forward_port"]
            }),
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Get Agent Status Tool
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

pub struct GetAgentStatusTool;

#[async_trait]
impl ToolHandler for GetAgentStatusTool {
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

        let identifier =
            DeploymentIdentifier::try_from_options(params.deployment_hash, params.deployment_id)?;
        let resolver = create_resolver(context);
        let deployment_hash = resolver.resolve(&identifier).await?;

        // Fetch agent directly from DB
        let agent = db::agent::fetch_by_deployment_hash(&context.pg_pool, &deployment_hash)
            .await
            .ok()
            .flatten();

        let result = if let Some(agent) = agent {
            json!({
                "status": "found",
                "deployment_hash": deployment_hash,
                "agent": {
                    "id": agent.id,
                    "deployment_hash": agent.deployment_hash,
                    "status": agent.status,
                    "version": agent.version,
                    "capabilities": agent.capabilities,
                    "system_info": agent.system_info,
                    "last_heartbeat": agent.last_heartbeat.map(|h| h.to_rfc3339()),
                }
            })
        } else {
            json!({
                "status": "not_found",
                "deployment_hash": deployment_hash,
                "message": "No agent registered for this deployment. The Status Panel agent may not be installed or has not yet connected."
            })
        };

        Ok(ToolContent::Text {
            text: result.to_string(),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "get_agent_status".to_string(),
            description: "Check if a Status Panel agent is registered and online for a deployment. Returns agent version, capabilities, and last heartbeat.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "deployment_id": {
                        "type": "number",
                        "description": "The deployment/installation ID"
                    },
                    "deployment_hash": {
                        "type": "string",
                        "description": "The deployment hash"
                    }
                }
            }),
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Get Agent Command History Tool
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

pub struct GetAgentCommandHistoryTool;

#[async_trait]
impl ToolHandler for GetAgentCommandHistoryTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            #[serde(default)]
            deployment_id: Option<i64>,
            #[serde(default)]
            deployment_hash: Option<String>,
            #[serde(default)]
            limit: Option<usize>,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        let identifier =
            DeploymentIdentifier::try_from_options(params.deployment_hash, params.deployment_id)?;
        let resolver = create_resolver(context);
        let deployment_hash = resolver.resolve(&identifier).await?;

        let commands = db::command::fetch_by_deployment(&context.pg_pool, &deployment_hash).await?;
        let limit = params.limit.unwrap_or(20);
        let commands: Vec<Value> = commands
            .into_iter()
            .take(limit)
            .map(|command| {
                json!({
                    "command_id": command.command_id,
                    "type": command.r#type,
                    "status": command.status,
                    "priority": command.priority,
                    "created_at": command.created_at.to_rfc3339(),
                    "updated_at": command.updated_at.to_rfc3339(),
                    "parameters": command.parameters,
                    "result": command.result,
                    "error": command.error,
                    "timeout_seconds": command.timeout_seconds,
                })
            })
            .collect();

        Ok(ToolContent::Text {
            text: json!({
                "status": "ok",
                "deployment_hash": deployment_hash,
                "commands": commands,
            })
            .to_string(),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "get_agent_command_history".to_string(),
            description: "List recent commands queued for a deployment's Status Panel agent, including status, timestamps, and any reported result or error.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "deployment_id": {
                        "type": "number",
                        "description": "The deployment/installation ID"
                    },
                    "deployment_hash": {
                        "type": "string",
                        "description": "The deployment hash"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of commands to return (default: 20)"
                    }
                }
            }),
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Execute Agent Command Tool
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

pub struct ExecuteAgentCommandTool;

#[async_trait]
impl ToolHandler for ExecuteAgentCommandTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            #[serde(default)]
            deployment_id: Option<i64>,
            #[serde(default)]
            deployment_hash: Option<String>,
            command_type: String,
            #[serde(default)]
            parameters: Option<Value>,
            #[serde(default)]
            timeout_seconds: Option<i32>,
            #[serde(default)]
            wait_timeout_seconds: Option<u64>,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        let identifier =
            DeploymentIdentifier::try_from_options(params.deployment_hash, params.deployment_id)?;
        let resolver = create_resolver(context);
        let deployment_hash = resolver.resolve(&identifier).await?;

        let mut request = crate::cli::stacker_client::AgentEnqueueRequest::new(
            &deployment_hash,
            &params.command_type,
        );
        if let Some(parameters) = params.parameters {
            request = request.with_raw_parameters(parameters);
        }
        if let Some(timeout_seconds) = params.timeout_seconds {
            request = request.with_timeout(timeout_seconds);
        }

        let result = enqueue_request_and_wait(
            context,
            &request,
            params
                .wait_timeout_seconds
                .unwrap_or(COMMAND_RESULT_TIMEOUT_SECS),
        )
        .await?;

        Ok(ToolContent::Text {
            text: result.to_string(),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "execute_agent_command".to_string(),
            description: "Queue a raw command for the Status Panel agent and optionally wait for the result. Use for advanced operations not covered by a dedicated MCP tool.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "deployment_id": {
                        "type": "number",
                        "description": "The deployment/installation ID"
                    },
                    "deployment_hash": {
                        "type": "string",
                        "description": "The deployment hash"
                    },
                    "command_type": {
                        "type": "string",
                        "description": "Raw agent command type to enqueue"
                    },
                    "parameters": {
                        "description": "Optional raw JSON parameters for the command",
                        "oneOf": [
                            { "type": "object" },
                            { "type": "array" },
                            { "type": "string" },
                            { "type": "number" },
                            { "type": "boolean" },
                            { "type": "null" }
                        ],
                    },
                    "timeout_seconds": {
                        "type": "number",
                        "description": "Optional agent-side timeout to store with the command request"
                    },
                    "wait_timeout_seconds": {
                        "type": "number",
                        "description": "How long MCP should wait for a terminal command result before returning queued status (default: 15)"
                    }
                },
                "required": ["command_type"]
            }),
        }
    }
}
