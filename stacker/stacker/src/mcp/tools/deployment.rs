use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::cli::stacker_client::StackerClient;
use crate::connectors::user_service::UserServiceDeploymentResolver;
use crate::db;
use crate::mcp::protocol::{Tool, ToolContent};
use crate::mcp::registry::{ToolContext, ToolHandler};
use crate::models::{Command, CommandPriority, Deployment};
use crate::services::{
    build_deploy_plan, build_rollback_plan, resolve_rollback_plan_context, DeployPlan,
    DeployPlanAction, DeployPlanOperation, DeployPlanRollback, DeployPlanScope,
    DeploymentAgentState, DeploymentDriftState, DeploymentEvent, DeploymentEventFeed,
    DeploymentIdentifier, DeploymentLastCommandState, DeploymentProjectState, DeploymentResolver,
    DeploymentRuntimeState, DeploymentState, DeploymentStateDeployment, TypedErrorCode,
    TypedErrorEnvelope, TypedRemediationClass, DEPLOY_PLAN_SCHEMA_VERSION,
};

/// Get deployment status
pub struct GetDeploymentStatusTool;
pub struct GetDeploymentStateTool;
pub struct GetDeploymentPlanTool;
pub struct GetDeploymentEventsTool;
pub struct ApplyDeploymentPlanTool;

const COMMAND_RESULT_TIMEOUT_SECS: u64 = 15;
const COMMAND_POLL_INTERVAL_MS: u64 = 500;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct McpDeploymentStatusResponse {
    id: i32,
    project_id: i32,
    deployment_hash: String,
    status: String,
    runtime: String,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct McpStartDeploymentResponse {
    id: i32,
    project_id: i32,
    status: String,
    deployment_hash: String,
    created_at: chrono::DateTime<chrono::Utc>,
    message: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct McpCancelDeploymentResponse {
    deployment_id: i32,
    status: String,
    message: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct McpDeploymentStateResponse {
    schema_version: String,
    project: DeploymentProjectState,
    deployment: DeploymentStateDeployment,
    agent: DeploymentAgentState,
    runtime: DeploymentRuntimeState,
    apps: Vec<crate::services::DeploymentAppState>,
    drift: DeploymentDriftState,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_command: Option<DeploymentLastCommandState>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct McpDeploymentPlanResponse {
    schema_version: String,
    deployment_hash: String,
    operation: DeployPlanOperation,
    target: String,
    fingerprint: String,
    scope: DeployPlanScope,
    has_changes: bool,
    actions: Vec<DeployPlanAction>,
    reasoning: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rollback: Option<DeployPlanRollback>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct McpDeploymentEventsResponse {
    schema_version: String,
    deployment_hash: String,
    events: Vec<DeploymentEvent>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct McpApplyDeploymentPlanResponse {
    schema_version: String,
    deployment_hash: String,
    operation: DeployPlanOperation,
    fingerprint: String,
    applied: bool,
    has_changes: bool,
    status: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    command_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rollback: Option<DeployPlanRollback>,
}

#[derive(Deserialize)]
struct DeploymentLookupArgs {
    #[serde(default)]
    deployment_id: Option<i64>,
    #[serde(default)]
    deployment_hash: Option<String>,
}

#[derive(Deserialize)]
struct DeploymentPlanArgs {
    #[serde(flatten)]
    lookup: DeploymentLookupArgs,
    #[serde(default)]
    operation: Option<DeployPlanOperation>,
    #[serde(default)]
    app_code: Option<String>,
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    expected_fingerprint: Option<String>,
    #[serde(default)]
    rollback_target: Option<String>,
}

#[derive(Deserialize)]
struct ApplyDeploymentPlanArgs {
    #[serde(flatten)]
    plan: DeploymentPlanArgs,
    #[serde(default)]
    confirm: bool,
}

impl From<Deployment> for McpDeploymentStatusResponse {
    fn from(value: Deployment) -> Self {
        Self {
            id: value.id,
            project_id: value.project_id,
            deployment_hash: value.deployment_hash,
            status: value.status,
            runtime: value.runtime,
            created_at: value.created_at,
            updated_at: value.updated_at,
        }
    }
}

impl From<DeploymentState> for McpDeploymentStateResponse {
    fn from(value: DeploymentState) -> Self {
        Self {
            schema_version: value.schema_version,
            project: value.project,
            deployment: value.deployment,
            agent: value.agent,
            runtime: value.runtime,
            apps: value.apps,
            drift: value.drift,
            last_command: value.last_command,
        }
    }
}

impl From<DeployPlan> for McpDeploymentPlanResponse {
    fn from(value: DeployPlan) -> Self {
        Self {
            schema_version: value.schema_version,
            deployment_hash: value.deployment_hash,
            operation: value.operation,
            target: value.target,
            fingerprint: value.fingerprint,
            scope: value.scope,
            has_changes: value.has_changes,
            actions: value.actions,
            reasoning: value.reasoning,
            rollback: value.rollback,
        }
    }
}

impl From<DeploymentEventFeed> for McpDeploymentEventsResponse {
    fn from(value: DeploymentEventFeed) -> Self {
        Self {
            schema_version: value.schema_version,
            deployment_hash: value.deployment_hash,
            events: value.events,
        }
    }
}

fn json_tool_content<T: Serialize>(value: &T) -> Result<ToolContent, String> {
    Ok(ToolContent::Text {
        text: serde_json::to_string(value).map_err(|e| format!("Serialization error: {}", e))?,
    })
}

async fn wait_for_command_result(
    pg_pool: &sqlx::PgPool,
    command_id: &str,
    timeout_secs: u64,
) -> Result<Option<Command>, String> {
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

fn apply_confirmation_required_error() -> String {
    TypedErrorEnvelope::invalid_request("apply_deployment_plan requires confirm=true")
        .with_context("tool", "apply_deployment_plan")
        .to_pretty_json()
}

fn unsupported_apply_operation_error(operation: &DeployPlanOperation) -> String {
    let operation_name = serde_json::to_string(operation)
        .unwrap_or_else(|_| "\"unknown\"".to_string())
        .trim_matches('"')
        .to_string();

    TypedErrorEnvelope::new(
        TypedErrorCode::InvalidRequest,
        "apply_deployment_plan currently supports deploy_app and rollback_deploy; full deploy apply still requires local CLI context",
        false,
        TypedRemediationClass::Configuration,
    )
    .with_context("operation", operation_name)
    .to_pretty_json()
}

async fn resolve_owned_deployment(
    context: &ToolContext,
    args: DeploymentLookupArgs,
) -> Result<(String, Deployment), String> {
    let identifier =
        DeploymentIdentifier::try_from_options(args.deployment_hash, args.deployment_id)?;
    let deployment_hash = create_resolver(context).resolve(&identifier).await?;
    let deployment = db::deployment::fetch_by_deployment_hash(&context.pg_pool, &deployment_hash)
        .await
        .map_err(|e| {
            tracing::error!("Failed to fetch deployment: {}", e);
            format!("Database error: {}", e)
        })?
        .ok_or_else(|| "Deployment not found".to_string())?;

    if deployment.user_id.as_deref() != Some(&context.user.id) {
        return Err("Deployment not found".to_string());
    }

    Ok((deployment_hash, deployment))
}

async fn build_validated_plan(
    context: &ToolContext,
    args: DeploymentPlanArgs,
) -> Result<(Deployment, DeployPlan), String> {
    let operation = args.operation.unwrap_or(DeployPlanOperation::Deploy);
    let target = args.target.as_deref().unwrap_or("cloud");
    let (deployment_hash, deployment) = resolve_owned_deployment(context, args.lookup).await?;
    let state = DeploymentState::for_deployment_hash(&context.pg_pool, &deployment_hash)
        .await
        .map_err(|e| format!("Database error: {}", e))?
        .ok_or_else(|| "Deployment not found".to_string())?;

    let plan = match operation {
        DeployPlanOperation::RollbackDeploy => {
            let requested_target = args
                .rollback_target
                .as_deref()
                .ok_or_else(|| "rollback_target is required for rollback plans".to_string())?;
            let rollback =
                resolve_rollback_plan_context(&context.pg_pool, &deployment, requested_target)
                    .await
                    .map_err(|error| error.to_pretty_json())?;
            build_rollback_plan(
                &state,
                target,
                rollback,
                args.expected_fingerprint.as_deref(),
            )
        }
        _ => build_deploy_plan(
            &state,
            operation,
            target,
            args.app_code.as_deref(),
            args.expected_fingerprint.as_deref(),
        ),
    }
    .map_err(|error| error.to_pretty_json())?;

    Ok((deployment, plan))
}

#[async_trait]
impl ToolHandler for GetDeploymentStatusTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        let args: DeploymentLookupArgs =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;
        let (deployment_hash, deployment) = resolve_owned_deployment(context, args).await?;

        let response = McpDeploymentStatusResponse::from(deployment);

        tracing::info!("Got deployment status for hash: {}", deployment_hash);

        json_tool_content(&response)
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "get_deployment_status".to_string(),
            description:
                "Get the current status of a deployment (pending, running, completed, failed). Provide either deployment_hash or deployment_id."
                    .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "deployment_hash": {
                        "type": "string",
                        "description": "Deployment hash (preferred, e.g., 'deployment_abc123')"
                    },
                    "deployment_id": {
                        "type": "number",
                        "description": "Deployment ID (legacy numeric ID from User Service)"
                    }
                },
                "required": []
            }),
        }
    }
}

#[async_trait]
impl ToolHandler for GetDeploymentStateTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        let args: DeploymentLookupArgs =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;
        let (deployment_hash, _) = resolve_owned_deployment(context, args).await?;
        let state = DeploymentState::for_deployment_hash(&context.pg_pool, &deployment_hash)
            .await
            .map_err(|e| format!("Database error: {}", e))?
            .ok_or_else(|| "Deployment not found".to_string())?;

        json_tool_content(&McpDeploymentStateResponse::from(state))
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "get_deployment_state".to_string(),
            description: "Get the canonical machine-readable deployment state. Provide either deployment_hash or deployment_id.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "deployment_hash": {
                        "type": "string",
                        "description": "Deployment hash (preferred, e.g., 'deployment_abc123')"
                    },
                    "deployment_id": {
                        "type": "number",
                        "description": "Deployment ID (legacy numeric ID from User Service)"
                    }
                },
                "required": []
            }),
        }
    }
}

#[async_trait]
impl ToolHandler for GetDeploymentPlanTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        let args: DeploymentPlanArgs =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;
        let (_, plan) = build_validated_plan(context, args).await?;

        json_tool_content(&McpDeploymentPlanResponse::from(plan))
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "get_deployment_plan".to_string(),
            description: "Preview a deployment or rollback plan with stable fingerprinting before any mutation.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "deployment_hash": {
                        "type": "string",
                        "description": "Deployment hash (preferred, e.g., 'deployment_abc123')"
                    },
                    "deployment_id": {
                        "type": "number",
                        "description": "Deployment ID (legacy numeric ID from User Service)"
                    },
                    "operation": {
                        "type": "string",
                        "enum": ["deploy", "deploy_app", "rollback_deploy"],
                        "description": "Plan mode. Defaults to 'deploy'."
                    },
                    "app_code": {
                        "type": "string",
                        "description": "Required for deploy_app plans; ignored for deployment-wide plans."
                    },
                    "target": {
                        "type": "string",
                        "description": "Deployment target. Defaults to 'cloud'."
                    },
                    "expected_fingerprint": {
                        "type": "string",
                        "description": "Optional stale-plan guard. The plan fails if this fingerprint no longer matches."
                    },
                    "rollback_target": {
                        "type": "string",
                        "description": "Required for rollback_deploy plans. Use 'previous' or a specific marketplace version."
                    }
                },
                "required": []
            }),
        }
    }
}

#[async_trait]
impl ToolHandler for ApplyDeploymentPlanTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        let args: ApplyDeploymentPlanArgs =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        if !args.confirm {
            return Err(apply_confirmation_required_error());
        }

        let (deployment, plan) = build_validated_plan(context, args.plan).await?;

        if !plan.has_changes {
            return json_tool_content(&McpApplyDeploymentPlanResponse {
                schema_version: DEPLOY_PLAN_SCHEMA_VERSION.to_string(),
                deployment_hash: plan.deployment_hash,
                operation: plan.operation,
                fingerprint: plan.fingerprint,
                applied: false,
                has_changes: false,
                status: "noop".to_string(),
                message: "Plan already satisfied. Nothing to apply.".to_string(),
                command_id: None,
                rollback: plan.rollback,
            });
        }

        match plan.operation {
            DeployPlanOperation::DeployApp => {
                let app_code = plan.scope.app_code.clone().ok_or_else(|| {
                    TypedErrorEnvelope::invalid_request(
                        "apply_deployment_plan requires an appCode/app_code for deploy_app operations",
                    )
                    .to_pretty_json()
                })?;
                let result = enqueue_and_wait(
                    context,
                    &plan.deployment_hash,
                    "deploy_app",
                    json!({
                        "app_code": app_code,
                        "image": serde_json::Value::Null,
                        "pull": true,
                        "force_recreate": false,
                        "force_config_overwrite": false,
                    }),
                    COMMAND_RESULT_TIMEOUT_SECS,
                )
                .await?;

                let status = result
                    .get("status")
                    .and_then(|value| value.as_str())
                    .unwrap_or("queued")
                    .to_string();
                let message = result
                    .get("message")
                    .and_then(|value| value.as_str())
                    .map(ToOwned::to_owned)
                    .unwrap_or_else(|| {
                        format!("deploy_app apply accepted for {}", plan.deployment_hash)
                    });
                let command_id = result
                    .get("command_id")
                    .and_then(|value| value.as_str())
                    .map(ToOwned::to_owned);

                json_tool_content(&McpApplyDeploymentPlanResponse {
                    schema_version: DEPLOY_PLAN_SCHEMA_VERSION.to_string(),
                    deployment_hash: plan.deployment_hash,
                    operation: plan.operation,
                    fingerprint: plan.fingerprint,
                    applied: true,
                    has_changes: true,
                    status,
                    message,
                    command_id,
                    rollback: None,
                })
            }
            DeployPlanOperation::RollbackDeploy => {
                let rollback = plan.rollback.clone().ok_or_else(|| {
                    TypedErrorEnvelope::internal_error(
                        "Rollback plan did not include a resolved target version",
                    )
                    .to_pretty_json()
                })?;
                let client = stacker_client(context)?;
                let response = client
                    .rollback_project(deployment.project_id, &rollback.resolved_version)
                    .await
                    .map_err(|error| match error {
                        crate::cli::error::CliError::Typed(envelope) => envelope.to_pretty_json(),
                        other => {
                            TypedErrorEnvelope::internal_error(other.to_string()).to_pretty_json()
                        }
                    })?;

                json_tool_content(&McpApplyDeploymentPlanResponse {
                    schema_version: DEPLOY_PLAN_SCHEMA_VERSION.to_string(),
                    deployment_hash: plan.deployment_hash,
                    operation: plan.operation,
                    fingerprint: plan.fingerprint,
                    applied: true,
                    has_changes: true,
                    status: response.status.unwrap_or_else(|| "accepted".to_string()),
                    message: response.msg.unwrap_or_else(|| {
                        format!("Rollback accepted for {}", rollback.resolved_version)
                    }),
                    command_id: None,
                    rollback: Some(rollback),
                })
            }
            DeployPlanOperation::Deploy => Err(unsupported_apply_operation_error(&plan.operation)),
        }
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "apply_deployment_plan".to_string(),
            description: "Apply a previously previewed deployment plan after revalidating its fingerprint. Supports deploy_app and rollback_deploy operations.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "deployment_hash": {
                        "type": "string",
                        "description": "Deployment hash (preferred, e.g., 'deployment_abc123')"
                    },
                    "deployment_id": {
                        "type": "number",
                        "description": "Deployment ID (legacy numeric ID from User Service)"
                    },
                    "operation": {
                        "type": "string",
                        "enum": ["deploy", "deploy_app", "rollback_deploy"],
                        "description": "Mutation mode. deploy currently returns an unsupported typed error because it still requires local CLI context."
                    },
                    "app_code": {
                        "type": "string",
                        "description": "Required for deploy_app applies."
                    },
                    "target": {
                        "type": "string",
                        "description": "Deployment target. Defaults to 'cloud'."
                    },
                    "expected_fingerprint": {
                        "type": "string",
                        "description": "Required fingerprint from get_deployment_plan to prevent stale applies."
                    },
                    "rollback_target": {
                        "type": "string",
                        "description": "Required for rollback_deploy applies. Use 'previous' or a specific marketplace version."
                    },
                    "confirm": {
                        "type": "boolean",
                        "description": "Must be true to acknowledge the mutation."
                    }
                },
                "required": ["expected_fingerprint", "confirm"]
            }),
        }
    }
}

#[async_trait]
impl ToolHandler for GetDeploymentEventsTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        let args: DeploymentLookupArgs =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;
        let (deployment_hash, _) = resolve_owned_deployment(context, args).await?;
        let feed = DeploymentEventFeed::for_deployment_hash(&context.pg_pool, &deployment_hash)
            .await
            .map_err(|e| format!("Database error: {}", e))?
            .ok_or_else(|| "Deployment not found".to_string())?;

        json_tool_content(&McpDeploymentEventsResponse::from(feed))
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "get_deployment_events".to_string(),
            description: "Get the structured deployment event feed for progress, failure, and remediation signals.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "deployment_hash": {
                        "type": "string",
                        "description": "Deployment hash (preferred, e.g., 'deployment_abc123')"
                    },
                    "deployment_id": {
                        "type": "number",
                        "description": "Deployment ID (legacy numeric ID from User Service)"
                    }
                },
                "required": []
            }),
        }
    }
}

/// Start a new deployment
pub struct StartDeploymentTool;

#[async_trait]
impl ToolHandler for StartDeploymentTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            project_id: i32,
            cloud_id: Option<i32>,
            environment: Option<String>,
        }

        let args: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        // Verify user owns the project
        let project = db::project::fetch(&context.pg_pool, args.project_id)
            .await
            .map_err(|e| format!("Project not found: {}", e))?
            .ok_or_else(|| "Project not found".to_string())?;

        if project.user_id != context.user.id {
            return Err("Unauthorized: You do not own this project".to_string());
        }

        // Create deployment record with hash
        let deployment_hash = uuid::Uuid::new_v4().to_string();
        let deployment = crate::models::Deployment::new(
            args.project_id,
            Some(context.user.id.clone()),
            deployment_hash.clone(),
            "pending".to_string(),
            "runc".to_string(),
            json!({ "environment": args.environment.unwrap_or_else(|| "production".to_string()), "cloud_id": args.cloud_id }),
        );

        let deployment = db::deployment::insert(&context.pg_pool, deployment)
            .await
            .map_err(|e| format!("Failed to create deployment: {}", e))?;

        let response = McpStartDeploymentResponse {
            id: deployment.id,
            project_id: deployment.project_id,
            status: deployment.status,
            deployment_hash: deployment.deployment_hash,
            created_at: deployment.created_at,
            message: "Deployment initiated - agent will connect shortly".to_string(),
        };

        tracing::info!(
            "Started deployment {} for project {}",
            deployment.id,
            args.project_id
        );

        json_tool_content(&response)
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "start_deployment".to_string(),
            description: "Initiate deployment of a project to cloud infrastructure".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "project_id": {
                        "type": "number",
                        "description": "Project ID to deploy"
                    },
                    "cloud_id": {
                        "type": "number",
                        "description": "Cloud provider ID (optional)"
                    },
                    "environment": {
                        "type": "string",
                        "description": "Deployment environment (optional, default: production)",
                        "enum": ["development", "staging", "production"]
                    }
                },
                "required": ["project_id"]
            }),
        }
    }
}

/// Cancel a deployment
pub struct CancelDeploymentTool;

#[async_trait]
impl ToolHandler for CancelDeploymentTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            deployment_id: i32,
        }

        let args: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        let _deployment = db::deployment::fetch(&context.pg_pool, args.deployment_id)
            .await
            .map_err(|e| format!("Deployment not found: {}", e))?
            .ok_or_else(|| "Deployment not found".to_string())?;

        // Verify user owns the project (via deployment)
        let project = db::project::fetch(&context.pg_pool, _deployment.project_id)
            .await
            .map_err(|e| format!("Project not found: {}", e))?
            .ok_or_else(|| "Project not found".to_string())?;

        if project.user_id != context.user.id {
            return Err("Unauthorized: You do not own this deployment".to_string());
        }

        // Mark deployment as cancelled (would update status in real implementation)
        let response = McpCancelDeploymentResponse {
            deployment_id: args.deployment_id,
            status: "cancelled".to_string(),
            message: "Deployment cancellation initiated".to_string(),
        };

        tracing::info!("Cancelled deployment {}", args.deployment_id);

        json_tool_content(&response)
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "cancel_deployment".to_string(),
            description: "Cancel an in-progress or pending deployment".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "deployment_id": {
                        "type": "number",
                        "description": "Deployment ID to cancel"
                    }
                },
                "required": ["deployment_id"]
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::registry::ToolRegistry;
    use crate::{configuration::Settings, mcp::registry::ToolContext, models::User};
    use actix_web::web;
    use chrono::Utc;
    use serde_json::json;
    use std::sync::Arc;

    #[test]
    fn deployment_status_response_omits_internal_fields() {
        let deployment = Deployment {
            id: 31,
            project_id: 17,
            deployment_hash: "deployment_state_online".to_string(),
            user_id: Some("user-1".to_string()),
            deleted: Some(false),
            status: "healthy".to_string(),
            runtime: "runc".to_string(),
            metadata: json!({"status_message": "hidden"}),
            last_seen_at: Some(Utc::now()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let response = McpDeploymentStatusResponse::from(deployment);
        let serialized = serde_json::to_value(&response).expect("serialize MCP status response");

        assert_eq!(serialized["deploymentHash"], "deployment_state_online");
        assert_eq!(serialized["status"], "healthy");
        assert!(serialized.get("metadata").is_none());
        assert!(serialized.get("userId").is_none());
        assert!(serialized.get("deleted").is_none());
        assert!(serialized.get("lastSeenAt").is_none());
    }

    #[test]
    fn start_deployment_response_uses_allow_list_shape() {
        let response = McpStartDeploymentResponse {
            id: 31,
            project_id: 17,
            status: "pending".to_string(),
            deployment_hash: "deployment_state_online".to_string(),
            created_at: Utc::now(),
            message: "Deployment initiated - agent will connect shortly".to_string(),
        };

        let serialized = serde_json::to_value(&response).expect("serialize start response");
        assert!(serialized.get("projectId").is_some());
        assert!(serialized.get("message").is_some());
        assert!(serialized.get("metadata").is_none());
    }

    #[test]
    fn deployment_state_response_uses_stable_contract_shape() {
        let state = DeploymentState {
            schema_version: "v1alpha1".to_string(),
            project: crate::services::DeploymentProjectState {
                id: 17,
                identity: "demo".to_string(),
                name: "Demo".to_string(),
            },
            deployment: crate::services::DeploymentStateDeployment {
                id: 31,
                deployment_hash: "deployment_state_online".to_string(),
                status: "healthy".to_string(),
                runtime: "runc".to_string(),
            },
            agent: DeploymentAgentState {
                id: Some("agent-1".to_string()),
                status: "online".to_string(),
                version: Some("1.0.0".to_string()),
                last_heartbeat: None,
                capabilities: vec!["compose".to_string()],
                features: crate::services::DeploymentAgentFeatures {
                    compose: true,
                    kata_runtime: false,
                    backup: false,
                    pipes: false,
                    proxy_credentials_vault: false,
                },
            },
            runtime: DeploymentRuntimeState {
                compose_path: "/opt/stacker/docker-compose.remote.yml".to_string(),
                env_path: "/home/trydirect/project/.env".to_string(),
            },
            apps: vec![],
            drift: DeploymentDriftState {
                has_drift: false,
                summary: "no drift detected".to_string(),
            },
            last_command: None,
        };

        let serialized = serde_json::to_value(McpDeploymentStateResponse::from(state))
            .expect("serialize deployment state");
        assert_eq!(serialized["schemaVersion"], "v1alpha1");
        assert!(serialized.get("project").is_some());
        assert!(serialized.get("deployment").is_some());
        assert!(serialized.get("metadata").is_none());
    }

    #[test]
    fn deployment_ai_tools_are_registered() {
        let registry = ToolRegistry::new();
        assert!(registry.has_tool("get_deployment_state"));
        assert!(registry.has_tool("get_deployment_plan"));
        assert!(registry.has_tool("get_deployment_events"));
        assert!(registry.has_tool("apply_deployment_plan"));
    }

    #[test]
    fn apply_deployment_plan_response_has_allow_list_shape() {
        let response = McpApplyDeploymentPlanResponse {
            schema_version: DEPLOY_PLAN_SCHEMA_VERSION.to_string(),
            deployment_hash: "deployment_state_online".to_string(),
            operation: DeployPlanOperation::DeployApp,
            fingerprint: "fingerprint-123".to_string(),
            applied: true,
            has_changes: true,
            status: "queued".to_string(),
            message: "Command queued. Agent will process shortly.".to_string(),
            command_id: Some("cmd-1".to_string()),
            rollback: None,
        };

        let serialized = serde_json::to_value(&response).expect("serialize apply response");
        assert_eq!(serialized["schemaVersion"], DEPLOY_PLAN_SCHEMA_VERSION);
        assert_eq!(serialized["operation"], "deploy_app");
        assert!(serialized.get("commandId").is_some());
        assert!(serialized.get("result").is_none());
        assert!(serialized.get("meta").is_none());
    }

    #[test]
    fn apply_deployment_plan_requires_confirmation_with_typed_error() {
        let envelope =
            serde_json::from_str::<TypedErrorEnvelope>(&apply_confirmation_required_error())
                .expect("deserialize typed confirmation error");

        assert_eq!(envelope.code, TypedErrorCode::InvalidRequest);
        assert_eq!(
            envelope.message,
            "apply_deployment_plan requires confirm=true"
        );
        assert_eq!(
            envelope.context.get("tool").map(|value| value.as_str()),
            Some("apply_deployment_plan")
        );
    }

    #[test]
    fn apply_deployment_plan_rejects_full_deploy_with_typed_error() {
        let envelope = serde_json::from_str::<TypedErrorEnvelope>(
            &unsupported_apply_operation_error(&DeployPlanOperation::Deploy),
        )
        .expect("deserialize typed unsupported operation error");

        assert_eq!(envelope.code, TypedErrorCode::InvalidRequest);
        assert!(envelope
            .message
            .contains("currently supports deploy_app and rollback_deploy"));
        assert_eq!(
            envelope
                .context
                .get("operation")
                .map(|value| value.as_str()),
            Some("deploy")
        );
    }

    #[tokio::test]
    async fn apply_deployment_plan_confirmation_error_does_not_reflect_secret_inputs() {
        let tool = ApplyDeploymentPlanTool;
        let pg_pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://postgres:postgres@localhost/stacker_test")
            .expect("lazy pool");
        let context = ToolContext {
            user: Arc::new(User {
                id: "user-1".to_string(),
                first_name: "Test".to_string(),
                last_name: "User".to_string(),
                email: "test@example.com".to_string(),
                role: "group_user".to_string(),
                email_confirmed: true,
                mfa_verified: true,
                access_token: None,
            }),
            pg_pool,
            settings: web::Data::new(Settings::default()),
        };
        let args = json!({
            "deployment_hash": "deployment_state_online",
            "operation": "deploy_app",
            "app_code": "SUPER_SECRET_SHOULD_NOT_LEAK",
            "expected_fingerprint": "fingerprint-SUPER_SECRET_SHOULD_NOT_LEAK",
            "confirm": false
        });

        let error = tool
            .execute(args, &context)
            .await
            .expect_err("confirm=false should reject apply");

        assert!(error.contains("confirm=true"));
        assert!(!error.contains("SUPER_SECRET_SHOULD_NOT_LEAK"));
    }
}
