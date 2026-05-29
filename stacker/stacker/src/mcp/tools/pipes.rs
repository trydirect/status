use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::cli::stacker_client::{
    AgentEnqueueRequest, CreatePipeInstanceApiRequest, CreatePipeTemplateApiRequest,
    PipeInstanceInfo, StackerClient,
};
use crate::connectors::user_service::UserServiceDeploymentResolver;
use crate::mcp::protocol::{Tool, ToolContent};
use crate::mcp::registry::{ToolContext, ToolHandler};
use crate::services::{DeploymentIdentifier, DeploymentResolver, TypedErrorEnvelope};

pub struct ListPipesTool;
pub struct GetPipeTool;
pub struct ListPipeTemplatesTool;
pub struct CreatePipeTemplateTool;
pub struct CreatePipeInstanceTool;
pub struct GetPipeHistoryTool;
pub struct ReplayPipeExecutionTool;
pub struct ActivatePipeTool;
pub struct DeactivatePipeTool;
pub struct TriggerPipeTool;

const PIPE_COMMAND_TIMEOUT_SECS: u64 = 90;
const PIPE_COMMAND_POLL_INTERVAL_SECS: u64 = 1;

fn create_resolver(context: &ToolContext) -> UserServiceDeploymentResolver {
    UserServiceDeploymentResolver::from_context(
        &context.settings.user_service_url,
        context.user.access_token.as_deref(),
    )
}

fn stacker_base_url(context: &ToolContext) -> String {
    let host = match context.settings.app_host.trim() {
        "" | "0.0.0.0" => "127.0.0.1",
        host => host,
    };

    format!("http://{}:{}", host, context.settings.app_port)
}

fn stacker_client(context: &ToolContext) -> Result<StackerClient, String> {
    let token = context.user.access_token.as_deref().ok_or_else(|| {
        TypedErrorEnvelope::permission_denied(
            "Authenticated MCP mutation requires a user access token",
        )
        .to_pretty_json()
    })?;

    Ok(StackerClient::new(&stacker_base_url(context), token))
}

async fn resolve_deployment_hash(
    context: &ToolContext,
    deployment_hash: Option<String>,
    deployment_id: Option<i64>,
) -> Result<String, String> {
    let identifier = DeploymentIdentifier::try_from_options(deployment_hash, deployment_id)?;
    create_resolver(context)
        .resolve(&identifier)
        .await
        .map_err(|e| e.to_string())
}

async fn require_pipe(client: &StackerClient, pipe_id: &str) -> Result<PipeInstanceInfo, String> {
    client
        .get_pipe_instance(pipe_id)
        .await
        .map_err(|e| format!("Failed to fetch pipe '{}': {}", pipe_id, e))?
        .ok_or_else(|| format!("Pipe instance '{}' not found", pipe_id))
}

async fn ensure_pipe_capability(
    client: &StackerClient,
    deployment_hash: &str,
) -> Result<(), String> {
    let capabilities = client
        .deployment_capabilities(deployment_hash)
        .await
        .map_err(|e| format!("Failed to fetch deployment capabilities: {}", e))?;

    if capabilities.features.pipes {
        return Ok(());
    }

    let capabilities_list = if capabilities.capabilities.is_empty() {
        "(none)".to_string()
    } else {
        capabilities.capabilities.join(", ")
    };

    Err(format!(
        "The active agent for deployment '{}' does not support pipe commands. Agent status: {}. Capabilities: {}. Update or relink the Status Panel agent so it advertises 'pipes', then retry.",
        capabilities.deployment_hash,
        if capabilities.status.is_empty() {
            "unknown"
        } else {
            &capabilities.status
        },
        capabilities_list
    ))
}

fn pipe_command_response(result: crate::cli::stacker_client::AgentCommandInfo) -> Value {
    json!({
        "command_id": result.command_id,
        "deployment_hash": result.deployment_hash,
        "command_type": result.command_type,
        "status": result.status,
        "priority": result.priority,
        "parameters": result.parameters,
        "result": result.result,
        "error": result.error,
        "created_at": result.created_at,
        "updated_at": result.updated_at,
    })
}

async fn run_pipe_command(
    client: &StackerClient,
    request: &AgentEnqueueRequest,
    wait_timeout_seconds: u64,
) -> Result<Value, String> {
    let result = client
        .agent_poll_result(
            request,
            wait_timeout_seconds,
            PIPE_COMMAND_POLL_INTERVAL_SECS,
        )
        .await
        .map_err(|e| format!("Agent command failed: {}", e))?;

    Ok(pipe_command_response(result))
}

async fn resolve_pipe_deployment(
    context: &ToolContext,
    client: &StackerClient,
    pipe_id: &str,
    deployment_hash: Option<String>,
    deployment_id: Option<i64>,
) -> Result<(PipeInstanceInfo, String), String> {
    let pipe = require_pipe(client, pipe_id).await?;
    let resolved = if deployment_hash.is_some() || deployment_id.is_some() {
        let explicit = resolve_deployment_hash(context, deployment_hash, deployment_id).await?;
        if explicit != pipe.deployment_hash {
            return Err(format!(
                "Pipe '{}' belongs to deployment '{}', not '{}'",
                pipe_id, pipe.deployment_hash, explicit
            ));
        }
        explicit
    } else {
        pipe.deployment_hash.clone()
    };

    Ok((pipe, resolved))
}

async fn activate_pipe_request(
    client: &StackerClient,
    pipe: &PipeInstanceInfo,
    trigger: &str,
    poll_interval: u32,
) -> Result<AgentEnqueueRequest, String> {
    let (source_endpoint, source_method, target_endpoint, target_method, field_mapping) =
        if let Some(template_id) = pipe.template_id.as_ref() {
            let templates = client
                .list_pipe_templates(None, None)
                .await
                .map_err(|e| format!("Failed to load pipe templates: {}", e))?;

            if let Some(template) = templates
                .iter()
                .find(|template| &template.id == template_id)
            {
                (
                    template.source_endpoint["path"]
                        .as_str()
                        .unwrap_or("/")
                        .to_string(),
                    template.source_endpoint["method"]
                        .as_str()
                        .unwrap_or("GET")
                        .to_string(),
                    template.target_endpoint["path"]
                        .as_str()
                        .unwrap_or("/")
                        .to_string(),
                    template.target_endpoint["method"]
                        .as_str()
                        .unwrap_or("POST")
                        .to_string(),
                    pipe.field_mapping_override
                        .clone()
                        .unwrap_or(template.field_mapping.clone()),
                )
            } else {
                (
                    "/".to_string(),
                    "GET".to_string(),
                    "/".to_string(),
                    "POST".to_string(),
                    serde_json::json!({}),
                )
            }
        } else {
            (
                "/".to_string(),
                "GET".to_string(),
                "/".to_string(),
                "POST".to_string(),
                pipe.field_mapping_override
                    .clone()
                    .unwrap_or(serde_json::json!({})),
            )
        };

    let params = json!({
        "pipe_instance_id": pipe.id,
        "source_adapter": pipe.source_adapter.clone(),
        "source_container": pipe.source_container.clone(),
        "source_endpoint": source_endpoint,
        "source_method": source_method,
        "target_adapter": pipe.target_adapter.clone(),
        "target_container": pipe.target_container.clone(),
        "target_url": pipe.target_url.clone(),
        "target_endpoint": target_endpoint,
        "target_method": target_method,
        "field_mapping": field_mapping,
        "trigger_type": trigger,
        "poll_interval_secs": poll_interval,
    });

    Ok(
        AgentEnqueueRequest::new(&pipe.deployment_hash, "activate_pipe")
            .with_raw_parameters(params),
    )
}

#[async_trait]
impl ToolHandler for ListPipesTool {
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
        let deployment_hash =
            resolve_deployment_hash(context, params.deployment_hash, params.deployment_id).await?;
        let client = stacker_client(context)?;
        let pipes = client
            .list_pipe_instances(&deployment_hash)
            .await
            .map_err(|e| format!("Failed to list pipes: {}", e))?;

        Ok(ToolContent::Text {
            text: json!({
                "status": "ok",
                "deployment_hash": deployment_hash,
                "pipes": pipes,
            })
            .to_string(),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "list_pipes".to_string(),
            description: "List remote pipe instances for a deployment.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "deployment_id": { "type": "number", "description": "The deployment/installation ID" },
                    "deployment_hash": { "type": "string", "description": "The deployment hash" }
                }
            }),
        }
    }
}

#[async_trait]
impl ToolHandler for GetPipeTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            pipe_id: String,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;
        let client = stacker_client(context)?;
        let pipe = require_pipe(&client, &params.pipe_id).await?;

        Ok(ToolContent::Text {
            text: json!({
                "status": "ok",
                "pipe": pipe,
            })
            .to_string(),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "get_pipe".to_string(),
            description: "Get details for a single remote pipe instance.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pipe_id": { "type": "string", "description": "Pipe instance ID" }
                },
                "required": ["pipe_id"]
            }),
        }
    }
}

#[async_trait]
impl ToolHandler for ListPipeTemplatesTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            #[serde(default)]
            source_app_type: Option<String>,
            #[serde(default)]
            target_app_type: Option<String>,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;
        let client = stacker_client(context)?;
        let templates = client
            .list_pipe_templates(
                params.source_app_type.as_deref(),
                params.target_app_type.as_deref(),
            )
            .await
            .map_err(|e| format!("Failed to list pipe templates: {}", e))?;

        Ok(ToolContent::Text {
            text: json!({
                "status": "ok",
                "templates": templates,
            })
            .to_string(),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "list_pipe_templates".to_string(),
            description:
                "List remote pipe templates, optionally filtered by source or target app type."
                    .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "source_app_type": { "type": "string", "description": "Optional source app type filter" },
                    "target_app_type": { "type": "string", "description": "Optional target app type filter" }
                }
            }),
        }
    }
}

#[async_trait]
impl ToolHandler for CreatePipeTemplateTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            request: CreatePipeTemplateApiRequest,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;
        let client = stacker_client(context)?;
        let template = client
            .create_pipe_template(&params.request)
            .await
            .map_err(|e| format!("Failed to create pipe template: {}", e))?;

        Ok(ToolContent::Text {
            text: json!({
                "status": "created",
                "template": template,
            })
            .to_string(),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "create_pipe_template".to_string(),
            description: "Create a reusable remote pipe template.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "request": {
                        "type": "object",
                        "description": "Pipe template request matching CreatePipeTemplateApiRequest"
                    }
                },
                "required": ["request"]
            }),
        }
    }
}

#[async_trait]
impl ToolHandler for CreatePipeInstanceTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            #[serde(default)]
            deployment_id: Option<i64>,
            #[serde(default)]
            deployment_hash: Option<String>,
            request: CreatePipeInstanceApiRequest,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;
        let deployment_hash =
            resolve_deployment_hash(context, params.deployment_hash, params.deployment_id).await?;
        let client = stacker_client(context)?;

        let mut request = params.request;
        request.deployment_hash = Some(deployment_hash.clone());

        let pipe = client
            .create_pipe_instance(&request)
            .await
            .map_err(|e| format!("Failed to create pipe instance: {}", e))?;

        Ok(ToolContent::Text {
            text: json!({
                "status": "created",
                "deployment_hash": deployment_hash,
                "pipe": pipe,
            })
            .to_string(),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "create_pipe_instance".to_string(),
            description: "Create a remote pipe instance for a deployment.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "deployment_id": { "type": "number", "description": "The deployment/installation ID" },
                    "deployment_hash": { "type": "string", "description": "The deployment hash" },
                    "request": {
                        "type": "object",
                        "description": "Pipe instance request matching CreatePipeInstanceApiRequest"
                    }
                },
                "required": ["request"]
            }),
        }
    }
}

#[async_trait]
impl ToolHandler for GetPipeHistoryTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            instance_id: String,
            #[serde(default)]
            limit: Option<i64>,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;
        let client = stacker_client(context)?;
        let executions = client
            .list_pipe_executions(&params.instance_id, params.limit.unwrap_or(20), 0)
            .await
            .map_err(|e| format!("Failed to fetch pipe execution history: {}", e))?;

        Ok(ToolContent::Text {
            text: json!({
                "status": "ok",
                "instance_id": params.instance_id,
                "executions": executions,
            })
            .to_string(),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "get_pipe_history".to_string(),
            description: "Get recent execution history for a pipe instance.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "instance_id": { "type": "string", "description": "Pipe instance ID" },
                    "limit": { "type": "integer", "description": "Maximum number of executions to return (default: 20)" }
                },
                "required": ["instance_id"]
            }),
        }
    }
}

#[async_trait]
impl ToolHandler for ReplayPipeExecutionTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            execution_id: String,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;
        let client = stacker_client(context)?;
        let replay = client
            .replay_pipe_execution(&params.execution_id)
            .await
            .map_err(|e| format!("Failed to replay pipe execution: {}", e))?;

        Ok(ToolContent::Text {
            text: json!({
                "status": "replayed",
                "replay": replay,
            })
            .to_string(),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "replay_pipe_execution".to_string(),
            description: "Replay a previous pipe execution.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "execution_id": { "type": "string", "description": "Pipe execution ID" }
                },
                "required": ["execution_id"]
            }),
        }
    }
}

#[async_trait]
impl ToolHandler for ActivatePipeTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            pipe_id: String,
            #[serde(default)]
            deployment_id: Option<i64>,
            #[serde(default)]
            deployment_hash: Option<String>,
            #[serde(default = "default_trigger")]
            trigger: String,
            #[serde(default = "default_poll_interval")]
            poll_interval: u32,
            #[serde(default = "default_wait_timeout")]
            wait_timeout_seconds: u64,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;
        let client = stacker_client(context)?;
        let (pipe, deployment_hash) = resolve_pipe_deployment(
            context,
            &client,
            &params.pipe_id,
            params.deployment_hash,
            params.deployment_id,
        )
        .await?;
        ensure_pipe_capability(&client, &deployment_hash).await?;

        client
            .update_pipe_status(&params.pipe_id, "active")
            .await
            .map_err(|e| format!("Failed to set pipe status to active: {}", e))?;

        let request =
            activate_pipe_request(&client, &pipe, &params.trigger, params.poll_interval).await?;
        let command = run_pipe_command(&client, &request, params.wait_timeout_seconds).await?;

        Ok(ToolContent::Text {
            text: json!({
                "status": "active",
                "pipe_id": params.pipe_id,
                "deployment_hash": deployment_hash,
                "trigger": params.trigger,
                "poll_interval": params.poll_interval,
                "command": command,
            })
            .to_string(),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "activate_pipe".to_string(),
            description: "Activate a remote pipe and start its agent listener.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pipe_id": { "type": "string", "description": "Pipe instance ID" },
                    "deployment_id": { "type": "number", "description": "Optional deployment/installation ID for validation" },
                    "deployment_hash": { "type": "string", "description": "Optional deployment hash for validation" },
                    "trigger": { "type": "string", "description": "Trigger type: webhook, poll, or manual", "default": "webhook" },
                    "poll_interval": { "type": "integer", "description": "Poll interval in seconds when trigger=poll", "default": 300 },
                    "wait_timeout_seconds": { "type": "integer", "description": "How long MCP should wait for the agent command result", "default": 90 }
                },
                "required": ["pipe_id"]
            }),
        }
    }
}

#[async_trait]
impl ToolHandler for DeactivatePipeTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            pipe_id: String,
            #[serde(default)]
            deployment_id: Option<i64>,
            #[serde(default)]
            deployment_hash: Option<String>,
            #[serde(default = "default_wait_timeout")]
            wait_timeout_seconds: u64,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;
        let client = stacker_client(context)?;
        let (_pipe, deployment_hash) = resolve_pipe_deployment(
            context,
            &client,
            &params.pipe_id,
            params.deployment_hash,
            params.deployment_id,
        )
        .await?;
        ensure_pipe_capability(&client, &deployment_hash).await?;

        client
            .update_pipe_status(&params.pipe_id, "paused")
            .await
            .map_err(|e| format!("Failed to set pipe status to paused: {}", e))?;

        let request = AgentEnqueueRequest::new(&deployment_hash, "deactivate_pipe")
            .with_raw_parameters(json!({ "pipe_instance_id": params.pipe_id }));
        let command = run_pipe_command(&client, &request, params.wait_timeout_seconds).await?;

        Ok(ToolContent::Text {
            text: json!({
                "status": "paused",
                "pipe_id": params.pipe_id,
                "deployment_hash": deployment_hash,
                "command": command,
            })
            .to_string(),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "deactivate_pipe".to_string(),
            description: "Pause a remote pipe and stop its agent listener.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pipe_id": { "type": "string", "description": "Pipe instance ID" },
                    "deployment_id": { "type": "number", "description": "Optional deployment/installation ID for validation" },
                    "deployment_hash": { "type": "string", "description": "Optional deployment hash for validation" },
                    "wait_timeout_seconds": { "type": "integer", "description": "How long MCP should wait for the agent command result", "default": 90 }
                },
                "required": ["pipe_id"]
            }),
        }
    }
}

#[async_trait]
impl ToolHandler for TriggerPipeTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            pipe_id: String,
            #[serde(default)]
            deployment_id: Option<i64>,
            #[serde(default)]
            deployment_hash: Option<String>,
            #[serde(default)]
            input_data: Value,
            #[serde(default = "default_wait_timeout")]
            wait_timeout_seconds: u64,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;
        let client = stacker_client(context)?;
        let (_pipe, deployment_hash) = resolve_pipe_deployment(
            context,
            &client,
            &params.pipe_id,
            params.deployment_hash,
            params.deployment_id,
        )
        .await?;
        ensure_pipe_capability(&client, &deployment_hash).await?;

        let request = AgentEnqueueRequest::new(&deployment_hash, "trigger_pipe")
            .with_raw_parameters(json!({
                "pipe_instance_id": params.pipe_id,
                "input_data": params.input_data,
            }));
        let command = run_pipe_command(&client, &request, params.wait_timeout_seconds).await?;

        Ok(ToolContent::Text {
            text: json!({
                "status": "triggered",
                "pipe_id": params.pipe_id,
                "deployment_hash": deployment_hash,
                "command": command,
            })
            .to_string(),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "trigger_pipe".to_string(),
            description: "Execute a one-shot remote pipe trigger with input data.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pipe_id": { "type": "string", "description": "Pipe instance ID" },
                    "deployment_id": { "type": "number", "description": "Optional deployment/installation ID for validation" },
                    "deployment_hash": { "type": "string", "description": "Optional deployment hash for validation" },
                    "input_data": {
                        "description": "Optional JSON payload to inject into the pipe trigger",
                        "oneOf": [
                            { "type": "object" },
                            { "type": "array" },
                            { "type": "string" },
                            { "type": "number" },
                            { "type": "boolean" },
                            { "type": "null" }
                        ]
                    },
                    "wait_timeout_seconds": { "type": "integer", "description": "How long MCP should wait for the agent command result", "default": 90 }
                },
                "required": ["pipe_id"]
            }),
        }
    }
}

fn default_trigger() -> String {
    "webhook".to_string()
}

fn default_poll_interval() -> u32 {
    300
}

fn default_wait_timeout() -> u64 {
    PIPE_COMMAND_TIMEOUT_SECS
}
