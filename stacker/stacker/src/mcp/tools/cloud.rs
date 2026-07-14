use async_trait::async_trait;
use serde_json::{json, Value};

use crate::connectors::{
    fetch_app_service_catalog, HetznerCloudClient, HetznerCloudConnector, HetznerSnapshotTarget,
};
use crate::db;
use crate::forms::CloudForm;
use crate::mcp::protocol::{Tool, ToolContent};
use crate::mcp::registry::{ToolContext, ToolHandler};
use crate::models;
use serde::Deserialize;

/// List user's cloud credentials
pub struct ListCloudsTool;

#[async_trait]
impl ToolHandler for ListCloudsTool {
    async fn execute(&self, _args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        let clouds = db::cloud::fetch_by_user(&context.pg_pool, &context.user.id)
            .await
            .map_err(|e| {
                tracing::error!("Failed to fetch clouds: {}", e);
                format!("Database error: {}", e)
            })?;

        let result =
            serde_json::to_string(&clouds).map_err(|e| format!("Serialization error: {}", e))?;

        tracing::info!(
            "Listed {} clouds for user {}",
            clouds.len(),
            context.user.id
        );

        Ok(ToolContent::Text { text: result })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "list_clouds".to_string(),
            description: "List all cloud provider credentials owned by the authenticated user"
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {},
                "required": []
            }),
        }
    }
}

/// Get a specific cloud by ID
pub struct GetCloudTool;

#[async_trait]
impl ToolHandler for GetCloudTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            id: i32,
        }

        let args: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        let cloud = db::cloud::fetch(&context.pg_pool, args.id)
            .await
            .map_err(|e| {
                tracing::error!("Failed to fetch cloud: {}", e);
                format!("Cloud error: {}", e)
            })?
            .ok_or_else(|| "Cloud not found".to_string())?;

        let result =
            serde_json::to_string(&cloud).map_err(|e| format!("Serialization error: {}", e))?;

        tracing::info!("Retrieved cloud {} for user {}", args.id, context.user.id);

        Ok(ToolContent::Text { text: result })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "get_cloud".to_string(),
            description: "Get details of a specific cloud provider credential by ID".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "id": {
                        "type": "number",
                        "description": "Cloud ID"
                    }
                },
                "required": ["id"]
            }),
        }
    }
}

/// Delete a cloud credential
pub struct DeleteCloudTool;

#[async_trait]
impl ToolHandler for DeleteCloudTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            id: i32,
        }

        let args: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        let _cloud = db::cloud::fetch(&context.pg_pool, args.id)
            .await
            .map_err(|e| format!("Cloud error: {}", e))?
            .ok_or_else(|| "Cloud not found".to_string())?;

        db::cloud::delete(&context.pg_pool, args.id, &context.user.id)
            .await
            .map_err(|e| format!("Failed to delete cloud: {}", e))?;

        let response = serde_json::json!({
            "id": args.id,
            "message": "Cloud credential deleted successfully"
        });

        tracing::info!("Deleted cloud {} for user {}", args.id, context.user.id);

        Ok(ToolContent::Text {
            text: response.to_string(),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "delete_cloud".to_string(),
            description: "Delete a cloud provider credential".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "id": {
                        "type": "number",
                        "description": "Cloud ID to delete"
                    }
                },
                "required": ["id"]
            }),
        }
    }
}

/// Add new cloud credentials
pub struct AddCloudTool;

#[async_trait]
impl ToolHandler for AddCloudTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            provider: String,
            cloud_token: Option<String>,
            cloud_key: Option<String>,
            cloud_secret: Option<String>,
            save_token: Option<bool>,
        }

        let args: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        // Validate provider
        let valid_providers = ["aws", "digitalocean", "hetzner", "azure", "gcp"];
        if !valid_providers.contains(&args.provider.to_lowercase().as_str()) {
            return Err(format!(
                "Invalid provider. Must be one of: {}",
                valid_providers.join(", ")
            ));
        }

        // Validate at least one credential is provided
        if args.cloud_token.is_none() && args.cloud_key.is_none() && args.cloud_secret.is_none() {
            return Err(
                "At least one of cloud_token, cloud_key, or cloud_secret must be provided"
                    .to_string(),
            );
        }

        // Create cloud record
        let cloud = models::Cloud {
            id: 0, // Will be set by DB
            user_id: context.user.id.clone(),
            name: String::new(), // auto-generated by db::cloud::insert as "{provider}-{id}"
            provider: args.provider.clone(),
            cloud_token: args.cloud_token,
            cloud_key: args.cloud_key,
            cloud_secret: args.cloud_secret,
            save_token: args.save_token,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        let created_cloud = db::cloud::insert(&context.pg_pool, cloud)
            .await
            .map_err(|e| format!("Failed to create cloud: {}", e))?;

        let response = serde_json::json!({
            "id": created_cloud.id,
            "provider": created_cloud.provider,
            "save_token": created_cloud.save_token,
            "created_at": created_cloud.created_at,
            "message": "Cloud credentials added successfully"
        });

        tracing::info!(
            "Added cloud {} for user {}",
            created_cloud.id,
            context.user.id
        );

        Ok(ToolContent::Text {
            text: response.to_string(),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "add_cloud".to_string(),
            description: "Add new cloud provider credentials for deployments".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "provider": {
                        "type": "string",
                        "description": "Cloud provider name (aws, digitalocean, hetzner, azure, gcp)",
                        "enum": ["aws", "digitalocean", "hetzner", "azure", "gcp"]
                    },
                    "cloud_token": {
                        "type": "string",
                        "description": "Cloud API token (optional)"
                    },
                    "cloud_key": {
                        "type": "string",
                        "description": "Cloud access key (optional)"
                    },
                    "cloud_secret": {
                        "type": "string",
                        "description": "Cloud secret key (optional)"
                    },
                    "save_token": {
                        "type": "boolean",
                        "description": "Whether to save the token for future use (default: true)"
                    }
                },
                "required": ["provider"]
            }),
        }
    }
}

/// List available cloud regions for a provider
pub struct ListCloudRegionsTool;

#[async_trait]
impl ToolHandler for ListCloudRegionsTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            provider: String,
            #[serde(default)]
            cloud_id: Option<i32>,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        let payload = fetch_app_service_catalog(
            &params.provider.to_lowercase(),
            "regions",
            params.cloud_id,
            context.user.access_token.as_deref(),
        )
        .await?;

        Ok(ToolContent::Text {
            text: payload.to_string(),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "list_cloud_regions".to_string(),
            description: "List available regions from App Service for a cloud provider".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "provider": {
                        "type": "string",
                        "enum": ["do", "htz", "lo", "scw", "aws", "gc", "vu", "ovh", "upc", "ali"],
                        "description": "Cloud provider code"
                    },
                    "cloud_id": {
                        "type": "number",
                        "description": "Optional cloud credential ID"
                    }
                },
                "required": ["provider"]
            }),
        }
    }
}

/// List available server sizes/plans for a provider
pub struct ListCloudServerSizesTool;

#[async_trait]
impl ToolHandler for ListCloudServerSizesTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            provider: String,
            #[serde(default)]
            cloud_id: Option<i32>,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        let payload = fetch_app_service_catalog(
            &params.provider.to_lowercase(),
            "servers",
            params.cloud_id,
            context.user.access_token.as_deref(),
        )
        .await?;

        Ok(ToolContent::Text {
            text: payload.to_string(),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "list_cloud_server_sizes".to_string(),
            description: "List available server sizes/plans from App Service for a cloud provider"
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "provider": {
                        "type": "string",
                        "enum": ["do", "htz", "lo", "scw", "aws", "gc", "vu", "ovh", "upc", "ali"],
                        "description": "Cloud provider code"
                    },
                    "cloud_id": {
                        "type": "number",
                        "description": "Optional cloud credential ID"
                    }
                },
                "required": ["provider"]
            }),
        }
    }
}

/// List available images for a provider
pub struct ListCloudImagesTool;

#[async_trait]
impl ToolHandler for ListCloudImagesTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            provider: String,
            #[serde(default)]
            cloud_id: Option<i32>,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        let payload = fetch_app_service_catalog(
            &params.provider.to_lowercase(),
            "images",
            params.cloud_id,
            context.user.access_token.as_deref(),
        )
        .await?;

        Ok(ToolContent::Text {
            text: payload.to_string(),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "list_cloud_images".to_string(),
            description: "List available OS/images from App Service for a cloud provider"
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "provider": {
                        "type": "string",
                        "enum": ["do", "htz", "lo", "scw", "aws", "gc", "vu", "ovh", "upc", "ali"],
                        "description": "Cloud provider code"
                    },
                    "cloud_id": {
                        "type": "number",
                        "description": "Optional cloud credential ID"
                    }
                },
                "required": ["provider"]
            }),
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Server Snapshot Tool
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Deserialize)]
struct RequestServerSnapshotArgs {
    #[serde(default)]
    server_id: Option<i32>,
    #[serde(default)]
    deployment_id: Option<i64>,
    #[serde(default)]
    deployment_hash: Option<String>,
    #[serde(default)]
    provider_server_id: Option<i64>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    confirm_snapshot: Option<bool>,
}

pub struct RequestServerSnapshotTool;

#[async_trait]
impl ToolHandler for RequestServerSnapshotTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        let params: RequestServerSnapshotArgs =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        if params.confirm_snapshot != Some(true) {
            let response = json!({
                "status": "confirmation_required",
                "snapshot_required": true,
                "message": "Creating a cloud snapshot is a provider write operation. Re-run with confirm_snapshot=true after user approval before risky remote troubleshooting.",
                "risky_operations": [
                    "remote_exec",
                    "direct_ssh_remediation",
                    "restart_container",
                    "stop_container",
                    "remove_app",
                    "deploy_app_with_force_overwrite",
                    "proxy_or_firewall_changes"
                ],
                "required_argument": "confirm_snapshot"
            });
            return Ok(ToolContent::Text {
                text: response.to_string(),
            });
        }

        let server = resolve_snapshot_server(context, &params).await?;
        let cloud_id = server.cloud_id.ok_or_else(|| {
            "Server has no linked cloud credential for snapshot creation".to_string()
        })?;
        let cloud = db::cloud::fetch(&context.pg_pool, cloud_id)
            .await
            .map_err(|e| format!("Cloud error: {}", e))?
            .ok_or_else(|| "Linked cloud credential not found".to_string())?;
        if cloud.user_id != context.user.id {
            return Err("Unauthorized: cloud credential does not belong to this user".to_string());
        }

        let provider = normalize_snapshot_provider(&cloud.provider);
        if provider != "hetzner" {
            return Err(format!(
                "Server snapshots are currently supported for Hetzner only; provider was {}",
                cloud.provider
            ));
        }

        let cloud = if cloud.save_token == Some(true) {
            CloudForm::decode_model(cloud, true)
        } else {
            cloud
        };
        let token = cloud
            .cloud_token
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| "Hetzner snapshot requires a valid saved cloud token".to_string())?;

        let description = params.description.clone().unwrap_or_else(|| {
            let reason = params
                .reason
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or("AI-assisted troubleshooting");
            format!(
                "Stacker pre-troubleshooting snapshot for server {}: {}",
                server.id, reason
            )
        });

        let target = HetznerSnapshotTarget {
            provider_server_id: params.provider_server_id,
            server_name: server
                .name
                .clone()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty()),
            public_ip: server
                .srv_ip
                .clone()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty()),
        };

        if target.provider_server_id.is_none()
            && target.server_name.is_none()
            && target.public_ip.is_none()
        {
            return Err(
                "Cannot match Hetzner server: provide provider_server_id or save server name/public IP"
                    .to_string(),
            );
        }

        let connector = HetznerCloudClient::from_env()
            .map_err(|e| format!("Failed to initialize Hetzner connector: {}", e))?;
        let snapshot = connector
            .create_server_snapshot(token, target, &description)
            .await
            .map_err(|e| format!("Hetzner snapshot request failed: {}", e))?;

        tracing::info!(
            user_id = %context.user.id,
            server_id = server.id,
            cloud_id = cloud_id,
            action_id = snapshot.action_id,
            image_id = ?snapshot.image_id,
            "Requested Hetzner server snapshot via MCP"
        );

        let response = json!({
            "status": "snapshot_requested",
            "provider": "hetzner",
            "server_id": server.id,
            "snapshot": snapshot,
            "message": "Hetzner snapshot request accepted. Wait for the action/image to complete before high-risk remediation."
        });
        Ok(ToolContent::Text {
            text: response.to_string(),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "request_server_snapshot".to_string(),
            description: "Request a cloud snapshot for a remote server before risky AI-assisted troubleshooting. Hetzner is supported first. This is a provider write operation and requires confirm_snapshot=true.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "server_id": {
                        "type": "number",
                        "description": "Stacker server ID. Preferred when available."
                    },
                    "deployment_id": {
                        "type": "number",
                        "description": "Stacker deployment/installation ID to locate the linked server."
                    },
                    "deployment_hash": {
                        "type": "string",
                        "description": "Deployment hash to locate the linked server."
                    },
                    "provider_server_id": {
                        "type": "number",
                        "description": "Optional Hetzner server ID. If omitted Stacker matches by saved public IP or server name."
                    },
                    "description": {
                        "type": "string",
                        "description": "Snapshot description stored at the provider. Do not include secrets."
                    },
                    "reason": {
                        "type": "string",
                        "description": "Human-readable reason for the snapshot request."
                    },
                    "confirm_snapshot": {
                        "type": "boolean",
                        "description": "Must be true after explicit user approval because this creates a provider snapshot."
                    }
                },
                "required": ["confirm_snapshot"]
            }),
        }
    }
}

async fn resolve_snapshot_server(
    context: &ToolContext,
    params: &RequestServerSnapshotArgs,
) -> Result<models::Server, String> {
    if let Some(server_id) = params.server_id {
        let server = db::server::fetch(&context.pg_pool, server_id)
            .await?
            .ok_or_else(|| "Server not found".to_string())?;
        if server.user_id != context.user.id {
            return Err("Unauthorized: server does not belong to this user".to_string());
        }
        return Ok(server);
    }

    let deployment = if let Some(hash) = params.deployment_hash.as_deref() {
        db::deployment::fetch_by_deployment_hash(&context.pg_pool, hash)
            .await?
            .ok_or_else(|| "Deployment not found for deployment_hash".to_string())?
    } else if let Some(deployment_id) = params.deployment_id {
        db::deployment::fetch(&context.pg_pool, deployment_id as i32)
            .await?
            .ok_or_else(|| "Deployment not found for deployment_id".to_string())?
    } else {
        return Err("Provide server_id, deployment_id, or deployment_hash".to_string());
    };

    if deployment.user_id.as_deref() != Some(context.user.id.as_str()) {
        let project = db::project::fetch(&context.pg_pool, deployment.project_id)
            .await
            .map_err(|e| format!("Project lookup failed: {}", e))?
            .ok_or_else(|| "Project not found for deployment".to_string())?;
        if project.user_id != context.user.id {
            return Err("Unauthorized: deployment does not belong to this user".to_string());
        }
    }

    let mut servers = db::server::fetch_by_project(&context.pg_pool, deployment.project_id).await?;
    servers.retain(|server| server.user_id == context.user.id);
    servers
        .into_iter()
        .find(|server| server.cloud_id.is_some())
        .ok_or_else(|| {
            "No cloud-backed server found for deployment project; pass server_id".to_string()
        })
}

fn normalize_snapshot_provider(provider: &str) -> String {
    match provider.trim().to_lowercase().as_str() {
        "htz" | "hcloud" | "hetzner_cloud" => "hetzner".to_string(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod snapshot_tool_tests {
    use super::normalize_snapshot_provider;

    #[test]
    fn snapshot_provider_normalizes_hetzner_aliases() {
        assert_eq!(normalize_snapshot_provider("hetzner"), "hetzner");
        assert_eq!(normalize_snapshot_provider("htz"), "hetzner");
        assert_eq!(normalize_snapshot_provider("hcloud"), "hetzner");
        assert_eq!(normalize_snapshot_provider("hetzner_cloud"), "hetzner");
    }
}
