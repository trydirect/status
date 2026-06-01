use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::mcp::protocol::{Tool, ToolContent};
use crate::mcp::registry::{ToolContext, ToolHandler};

fn install_service_base_url() -> String {
    std::env::var("INSTALL_SERVICE_URL").unwrap_or_else(|_| "http://install:4400".to_string())
}

async fn call_install_service(
    method: reqwest::Method,
    path: &str,
    body: Option<Value>,
) -> Result<Value, String> {
    let base_url = install_service_base_url().trim_end_matches('/').to_string();
    let url = format!("{}{}", base_url, path);

    let mut request = reqwest::Client::new().request(method, &url);

    if let Ok(internal_key) = std::env::var("INTERNAL_SERVICES_ACCESS_KEY") {
        request = request
            .header("Authorization", format!("Bearer {}", internal_key))
            .header("X-Internal-Key", internal_key);
    }

    if let Some(body) = body {
        request = request.json(&body);
    }

    let response = request
        .send()
        .await
        .map_err(|e| format!("Failed to call Install Service: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let error_body = response.text().await.unwrap_or_default();
        return Err(format!("Install Service error {}: {}", status, error_body));
    }

    response
        .json::<Value>()
        .await
        .map_err(|e| format!("Failed to parse Install Service response: {}", e))
}

pub struct PreviewInstallConfigTool;

#[async_trait]
impl ToolHandler for PreviewInstallConfigTool {
    async fn execute(&self, args: Value, _context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            payload: Value,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        let response = call_install_service(
            reqwest::Method::POST,
            "/api/preview-app-config",
            Some(params.payload),
        )
        .await?;

        Ok(ToolContent::Text {
            text: response.to_string(),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "preview_install_config".to_string(),
            description:
                "Preview generated install configuration by calling Install Service /api/preview-app-config"
                    .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "payload": {
                        "type": "object",
                        "description": "Request body accepted by Install Service /api/preview-app-config"
                    }
                },
                "required": ["payload"]
            }),
        }
    }
}

pub struct GetAnsibleRoleDefaultsTool;

#[async_trait]
impl ToolHandler for GetAnsibleRoleDefaultsTool {
    async fn execute(&self, args: Value, _context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            role_name: String,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        let response = call_install_service(
            reqwest::Method::GET,
            &format!("/api/role-defaults/{}", params.role_name),
            None,
        )
        .await?;

        Ok(ToolContent::Text {
            text: response.to_string(),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "get_ansible_role_defaults".to_string(),
            description: "Get default variables for an Ansible role from Install Service /api/role-defaults/{role_name}"
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "role_name": {
                        "type": "string",
                        "description": "Ansible role name"
                    }
                },
                "required": ["role_name"]
            }),
        }
    }
}

pub struct RenderAnsibleTemplateTool;

#[async_trait]
impl ToolHandler for RenderAnsibleTemplateTool {
    async fn execute(&self, args: Value, _context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            payload: Value,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        let response = call_install_service(
            reqwest::Method::POST,
            "/api/render-templates",
            Some(params.payload),
        )
        .await?;

        Ok(ToolContent::Text {
            text: response.to_string(),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "render_ansible_template".to_string(),
            description:
                "Render Ansible templates by calling Install Service /api/render-templates"
                    .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "payload": {
                        "type": "object",
                        "description": "Request body accepted by Install Service /api/render-templates"
                    }
                },
                "required": ["payload"]
            }),
        }
    }
}
