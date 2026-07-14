use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::db;
use crate::helpers::{remote_runtime_compose_path, remote_runtime_env_path};
use crate::mcp::protocol::{Tool, ToolContent};
use crate::mcp::registry::{ToolContext, ToolHandler};
use crate::models::{Project, ProjectApp};
use crate::services::config_renderer::EnvRenderInput;
use crate::services::{
    build_explain_env, build_explain_topology, ExplainEnv, ExplainEnvLayer, ExplainRenderedEnv,
    ExplainTopology, ExplainTopologyService,
};

pub struct ExplainEnvTool;
pub struct ExplainTopologyTool;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct McpExplainEnvResponse {
    schema_version: String,
    deployment_hash: String,
    app_code: String,
    local_authoring_env_path: String,
    runtime_env_path: String,
    runtime_compose_path: String,
    layers: Vec<McpExplainEnvLayerResponse>,
    destination: McpExplainDestinationResponse,
    rendered_env: McpExplainRenderedEnvResponse,
    reasoning: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct McpExplainEnvLayerResponse {
    name: String,
    key_names: Vec<String>,
    key_count: usize,
    hash: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct McpExplainDestinationResponse {
    path: String,
    write_policy: String,
    drift_protection: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct McpExplainRenderedEnvResponse {
    hash: String,
    inputs: Vec<String>,
    server_secrets_inherited: bool,
    service_secrets_override_server_secrets: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct McpExplainTopologyResponse {
    schema_version: String,
    deployment_hash: String,
    target: String,
    local_compose_path: String,
    runtime_compose_path: String,
    local_authoring_env_path: String,
    runtime_env_path: String,
    services: Vec<McpExplainTopologyServiceResponse>,
    reasoning: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct McpExplainTopologyServiceResponse {
    code: String,
    name: String,
    enabled: bool,
}

#[derive(Deserialize)]
struct ExplainArgs {
    deployment_hash: String,
    #[serde(default)]
    app_code: Option<String>,
}

fn local_authoring_env_path(project: &Project) -> String {
    project
        .request_json
        .get("env_file")
        .and_then(|value| value.as_str())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| ".env".to_string())
}

fn runtime_compose_path(project: &Project) -> String {
    project
        .request_json
        .pointer("/custom/deployment_artifacts/config_bundle/remote_compose_path")
        .and_then(|value| value.as_str())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| remote_runtime_compose_path().to_string())
}

fn project_target(project: &Project) -> String {
    project
        .request_json
        .pointer("/deploy/target")
        .and_then(|value| value.as_str())
        .unwrap_or("cloud")
        .to_string()
}

fn app_env_input(app: &ProjectApp) -> EnvRenderInput {
    let mut input = EnvRenderInput::default();
    if let Some(env) = app.environment.as_ref().and_then(|value| value.as_object()) {
        input.service = env
            .iter()
            .filter_map(|(key, value)| value.as_str().map(|value| (key.clone(), value.to_string())))
            .collect();
    }
    input
}

fn topology_services(apps: &[ProjectApp]) -> Vec<ExplainTopologyService> {
    apps.iter()
        .map(|app| ExplainTopologyService {
            code: app.code.clone(),
            name: app.name.clone(),
            enabled: app.enabled.unwrap_or(true),
        })
        .collect()
}

fn json_tool_content<T: Serialize>(value: &T) -> Result<ToolContent, String> {
    Ok(ToolContent::Text {
        text: serde_json::to_string_pretty(value)
            .map_err(|err| format!("Serialization error: {err}"))?,
    })
}

impl From<ExplainEnvLayer> for McpExplainEnvLayerResponse {
    fn from(value: ExplainEnvLayer) -> Self {
        Self {
            name: value.name,
            key_names: value.key_names,
            key_count: value.key_count,
            hash: value.hash,
        }
    }
}

impl From<crate::services::ExplainDestination> for McpExplainDestinationResponse {
    fn from(value: crate::services::ExplainDestination) -> Self {
        Self {
            path: value.path,
            write_policy: value.write_policy,
            drift_protection: value.drift_protection,
        }
    }
}

impl From<ExplainRenderedEnv> for McpExplainRenderedEnvResponse {
    fn from(value: ExplainRenderedEnv) -> Self {
        Self {
            hash: value.hash,
            inputs: value.inputs,
            server_secrets_inherited: value.server_secrets_inherited,
            service_secrets_override_server_secrets: value.service_secrets_override_server_secrets,
        }
    }
}

impl From<ExplainEnv> for McpExplainEnvResponse {
    fn from(value: ExplainEnv) -> Self {
        Self {
            schema_version: value.schema_version,
            deployment_hash: value.deployment_hash,
            app_code: value.app_code,
            local_authoring_env_path: value.local_authoring_env_path,
            runtime_env_path: value.runtime_env_path,
            runtime_compose_path: value.runtime_compose_path,
            layers: value.layers.into_iter().map(Into::into).collect(),
            destination: value.destination.into(),
            rendered_env: value.rendered_env.into(),
            reasoning: value.reasoning,
        }
    }
}

impl From<ExplainTopologyService> for McpExplainTopologyServiceResponse {
    fn from(value: ExplainTopologyService) -> Self {
        Self {
            code: value.code,
            name: value.name,
            enabled: value.enabled,
        }
    }
}

impl From<ExplainTopology> for McpExplainTopologyResponse {
    fn from(value: ExplainTopology) -> Self {
        Self {
            schema_version: value.schema_version,
            deployment_hash: value.deployment_hash,
            target: value.target,
            local_compose_path: value.local_compose_path,
            runtime_compose_path: value.runtime_compose_path,
            local_authoring_env_path: value.local_authoring_env_path,
            runtime_env_path: value.runtime_env_path,
            services: value.services.into_iter().map(Into::into).collect(),
            reasoning: value.reasoning,
        }
    }
}

async fn load_owned_deployment(
    context: &ToolContext,
    deployment_hash: &str,
) -> Result<(crate::models::Deployment, Project), String> {
    let deployment = db::deployment::fetch_by_deployment_hash(&context.pg_pool, deployment_hash)
        .await
        .map_err(|err| format!("Failed to fetch deployment: {err}"))?
        .ok_or_else(|| "Deployment not found".to_string())?;
    let project = db::project::fetch(&context.pg_pool, deployment.project_id)
        .await
        .map_err(|err| format!("Failed to fetch project: {err}"))?
        .ok_or_else(|| "Project not found".to_string())?;
    if project.user_id != context.user.id {
        return Err("Deployment not found".to_string());
    }
    Ok((deployment, project))
}

#[async_trait]
impl ToolHandler for ExplainEnvTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        let args: ExplainArgs =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {e}"))?;
        let (deployment, project) = load_owned_deployment(context, &args.deployment_hash).await?;
        let app_code = args.app_code.unwrap_or_else(|| "app".to_string());

        let apps =
            db::project_app::fetch_by_deployment(&context.pg_pool, project.id, deployment.id)
                .await
                .map_err(|err| format!("Failed to fetch apps: {err}"))?;
        let app = apps
            .iter()
            .find(|app| app.code == app_code)
            .or_else(|| apps.first())
            .ok_or_else(|| "No deployment apps found".to_string())?;

        let explain = build_explain_env(
            &deployment.deployment_hash,
            &app.code,
            &local_authoring_env_path(&project),
            remote_runtime_env_path(),
            &runtime_compose_path(&project),
            app_env_input(app),
        )
        .map_err(|err| err.to_string())?;

        json_tool_content(&McpExplainEnvResponse::from(explain))
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "explain_env".to_string(),
            description: "Explain runtime env provenance for a deployment app without exposing secret values.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "deployment_hash": { "type": "string", "description": "Deployment hash to inspect" },
                    "app_code": { "type": "string", "description": "Optional app code; defaults to first deployment app" }
                },
                "required": ["deployment_hash"]
            }),
        }
    }
}

#[async_trait]
impl ToolHandler for ExplainTopologyTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        let args: ExplainArgs =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {e}"))?;
        let (deployment, project) = load_owned_deployment(context, &args.deployment_hash).await?;

        let apps =
            db::project_app::fetch_by_deployment(&context.pg_pool, project.id, deployment.id)
                .await
                .map_err(|err| format!("Failed to fetch apps: {err}"))?;

        let topology = build_explain_topology(
            &deployment.deployment_hash,
            &project_target(&project),
            "stacker.yml",
            &runtime_compose_path(&project),
            &local_authoring_env_path(&project),
            remote_runtime_env_path(),
            topology_services(&apps),
        );

        json_tool_content(&McpExplainTopologyResponse::from(topology))
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "explain_topology".to_string(),
            description: "Explain deployment topology paths and service targets without exposing secret values.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "deployment_hash": { "type": "string", "description": "Deployment hash to inspect" }
                },
                "required": ["deployment_hash"]
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::registry::ToolRegistry;
    use crate::models::{Deployment, Project, ProjectApp};
    use serde_json::json;

    #[test]
    fn explain_tools_have_expected_schema_names() {
        assert_eq!(ExplainEnvTool.schema().name, "explain_env");
        assert_eq!(ExplainTopologyTool.schema().name, "explain_topology");
    }

    #[test]
    fn explain_tools_are_registered() {
        let registry = ToolRegistry::new();
        assert!(registry.has_tool("explain_env"));
        assert!(registry.has_tool("explain_topology"));
    }

    #[test]
    fn explain_env_text_never_contains_secret_values() {
        let project = Project::new(
            "user-1".to_string(),
            "demo".to_string(),
            json!({}),
            json!({
                "env_file": "docker/prod/.env",
                "custom": {
                    "deployment_artifacts": {
                        "config_bundle": {
                            "remote_compose_path": "/opt/stacker/deployments/prod/docker-compose.remote.yml"
                        }
                    }
                }
            }),
        );
        let deployment = Deployment::new(
            1,
            Some("user-1".to_string()),
            "deployment_demo".to_string(),
            "running".to_string(),
            "runc".to_string(),
            json!({}),
        );
        let mut app = ProjectApp::new(
            1,
            "api".to_string(),
            "API".to_string(),
            "demo/api:latest".to_string(),
        );
        app.environment = Some(json!({
            "DATABASE_URL": "SUPER_SECRET_SHOULD_NOT_LEAK",
            "API_ACCESS_TOKEN": "TOKEN_SECRET_SHOULD_NOT_LEAK",
            "REGISTRY_USERNAME": "REGISTRY_USER_SHOULD_NOT_LEAK",
            "REGISTRY_PASSWORD": "REGISTRY_PASSWORD_SHOULD_NOT_LEAK",
            "RUST_LOG": "debug"
        }));

        let explain = build_explain_env(
            &deployment.deployment_hash,
            &app.code,
            &local_authoring_env_path(&project),
            remote_runtime_env_path(),
            &runtime_compose_path(&project),
            app_env_input(&app),
        )
        .expect("explain env should build");
        let text = serde_json::to_string_pretty(&explain).expect("serialize explain env");

        assert!(text.contains("DATABASE_URL"));
        assert!(text.contains("API_ACCESS_TOKEN"));
        assert!(text.contains("REGISTRY_USERNAME"));
        assert!(text.contains("REGISTRY_PASSWORD"));
        assert!(!text.contains("SUPER_SECRET_SHOULD_NOT_LEAK"));
        assert!(!text.contains("TOKEN_SECRET_SHOULD_NOT_LEAK"));
        assert!(!text.contains("REGISTRY_USER_SHOULD_NOT_LEAK"));
        assert!(!text.contains("REGISTRY_PASSWORD_SHOULD_NOT_LEAK"));
    }

    #[test]
    fn explain_env_mcp_response_has_allow_list_shape() {
        let explain = build_explain_env(
            "deployment_demo",
            "api",
            "docker/prod/.env",
            remote_runtime_env_path(),
            remote_runtime_compose_path(),
            app_env_input(&{
                let mut app = ProjectApp::new(
                    1,
                    "api".to_string(),
                    "API".to_string(),
                    "demo/api:latest".to_string(),
                );
                app.environment = Some(json!({
                    "DATABASE_URL": "SUPER_SECRET_SHOULD_NOT_LEAK",
                    "API_ACCESS_TOKEN": "TOKEN_SECRET_SHOULD_NOT_LEAK",
                    "REGISTRY_USERNAME": "REGISTRY_USER_SHOULD_NOT_LEAK",
                    "REGISTRY_PASSWORD": "REGISTRY_PASSWORD_SHOULD_NOT_LEAK",
                    "RUST_LOG": "debug"
                }));
                app
            }),
        )
        .expect("explain env should build");

        let response = McpExplainEnvResponse::from(explain);
        let serialized = serde_json::to_value(&response).expect("serialize MCP explain env");

        assert!(serialized.get("schemaVersion").is_some());
        assert!(serialized.get("layers").is_some());
        assert!(serialized.get("requestJson").is_none());
        assert!(serialized.get("environment").is_none());
        let text = serde_json::to_string(&serialized).expect("serialize MCP explain env response");
        assert!(!text.contains("SUPER_SECRET_SHOULD_NOT_LEAK"));
        assert!(!text.contains("TOKEN_SECRET_SHOULD_NOT_LEAK"));
        assert!(!text.contains("REGISTRY_USER_SHOULD_NOT_LEAK"));
        assert!(!text.contains("REGISTRY_PASSWORD_SHOULD_NOT_LEAK"));
    }

    #[test]
    fn explain_topology_mcp_response_has_allow_list_shape() {
        let topology = build_explain_topology(
            "deployment_state_online",
            "cloud",
            "docker/prod/compose.yml",
            remote_runtime_compose_path(),
            "docker/prod/.env",
            remote_runtime_env_path(),
            vec![ExplainTopologyService {
                code: "upload".to_string(),
                name: "Upload".to_string(),
                enabled: true,
            }],
        );

        let response = McpExplainTopologyResponse::from(topology);
        let serialized = serde_json::to_value(&response).expect("serialize MCP topology");

        assert!(serialized.get("services").is_some());
        assert!(serialized.get("target").is_some());
        assert!(serialized.get("requestJson").is_none());
        assert!(serialized.get("metadata").is_none());
    }
}
