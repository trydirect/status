//! MCP tools for Vault-backed remote service secrets.

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::db;
use crate::forms::RemoteSecretMetadataResponse;
use crate::mcp::protocol::{Tool, ToolContent};
use crate::mcp::registry::{ToolContext, ToolHandler};
use crate::services::VaultService;

async fn ensure_owned_project(context: &ToolContext, project_id: i32) -> Result<(), String> {
    let project = db::project::fetch(&context.pg_pool, project_id)
        .await
        .map_err(|e| format!("Failed to fetch project: {}", e))?
        .ok_or_else(|| "Project not found".to_string())?;

    if project.user_id != context.user.id {
        return Err("Project not found".to_string());
    }

    Ok(())
}

async fn ensure_owned_target(
    context: &ToolContext,
    project_id: i32,
    target_code: &str,
) -> Result<(), String> {
    ensure_owned_project(context, project_id).await?;

    db::project_app::fetch_by_project_and_code(&context.pg_pool, project_id, target_code)
        .await
        .map_err(|e| format!("Failed to fetch target: {}", e))?
        .ok_or_else(|| format!("Deployable service/app target '{}' not found", target_code))?;

    Ok(())
}

fn validate_secret_name(name: &str) -> Result<(), String> {
    let mut chars = name.chars();
    match chars.next() {
        Some(first) if first == '_' || first.is_ascii_alphabetic() => {}
        _ => {
            return Err(format!(
                "Invalid secret name '{}': must match [A-Za-z_][A-Za-z0-9_]*",
                name
            ));
        }
    }

    if chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric()) {
        Ok(())
    } else {
        Err(format!(
            "Invalid secret name '{}': must match [A-Za-z_][A-Za-z0-9_]*",
            name
        ))
    }
}

fn vault_from_context(context: &ToolContext) -> Result<VaultService, String> {
    VaultService::from_settings(&context.settings.vault)
        .map_err(|error| format!("Vault is not available for remote secrets: {}", error))
}

fn render_json(value: Value) -> ToolContent {
    ToolContent::Text {
        text: serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string()),
    }
}

/// List deployable service/app targets that can receive remote service secrets.
pub struct ListRemoteSecretTargetsTool;

#[async_trait]
impl ToolHandler for ListRemoteSecretTargetsTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            project_id: i32,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        ensure_owned_project(context, params.project_id).await?;

        let targets = db::project_app::fetch_by_project(&context.pg_pool, params.project_id)
            .await
            .map_err(|e| format!("Failed to list remote secret targets: {}", e))?;

        let items: Vec<Value> = targets
            .into_iter()
            .map(|target| {
                json!({
                    "code": target.code,
                    "name": target.name,
                    "enabled": target.enabled,
                    "image": target.image
                })
            })
            .collect();

        Ok(render_json(json!({
            "project_id": params.project_id,
            "targets": items,
            "count": items.len(),
            "note": "Use one of these target codes with service-scope remote secrets."
        })))
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "list_remote_secret_targets".to_string(),
            description: "List deployable service/app target codes that can receive Vault-backed service-scope remote secrets for a project.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "project_id": {
                        "type": "number",
                        "description": "Project ID to inspect"
                    }
                },
                "required": ["project_id"]
            }),
        }
    }
}

/// List metadata for remote service secrets on one target.
pub struct ListRemoteServiceSecretsTool;

#[async_trait]
impl ToolHandler for ListRemoteServiceSecretsTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            project_id: i32,
            target_code: String,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        ensure_owned_target(context, params.project_id, &params.target_code).await?;

        let items: Vec<RemoteSecretMetadataResponse> = db::remote_secret::list_service_secrets(
            &context.pg_pool,
            &context.user.id,
            params.project_id,
            &params.target_code,
        )
        .await
        .map_err(|e| format!("Failed to list remote service secrets: {}", e))?
        .into_iter()
        .map(Into::into)
        .collect();

        Ok(render_json(json!({
            "project_id": params.project_id,
            "target_code": params.target_code,
            "secrets": items,
            "count": items.len(),
            "note": "Secret values are not returned; only metadata is exposed."
        })))
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "list_remote_service_secrets".to_string(),
            description: "List metadata for Vault-backed service-scope remote secrets on one deployable service/app target. Plaintext values are never returned.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "project_id": {
                        "type": "number",
                        "description": "Project ID containing the target"
                    },
                    "target_code": {
                        "type": "string",
                        "description": "Deployable service/app target code from list_remote_secret_targets"
                    }
                },
                "required": ["project_id", "target_code"]
            }),
        }
    }
}

/// Get metadata for one remote service secret.
pub struct GetRemoteServiceSecretTool;

#[async_trait]
impl ToolHandler for GetRemoteServiceSecretTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            project_id: i32,
            target_code: String,
            name: String,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;
        validate_secret_name(&params.name)?;
        ensure_owned_target(context, params.project_id, &params.target_code).await?;

        let secret = db::remote_secret::fetch_service_secret(
            &context.pg_pool,
            &context.user.id,
            params.project_id,
            &params.target_code,
            &params.name,
        )
        .await
        .map_err(|e| format!("Failed to fetch remote service secret: {}", e))?
        .ok_or_else(|| "Secret not found".to_string())?;

        Ok(render_json(json!({
            "secret": RemoteSecretMetadataResponse::from(secret),
            "note": "Secret values are not returned; only metadata is exposed."
        })))
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "get_remote_service_secret".to_string(),
            description: "Get metadata for one Vault-backed service-scope remote secret. Plaintext values are never returned.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "project_id": {
                        "type": "number",
                        "description": "Project ID containing the target"
                    },
                    "target_code": {
                        "type": "string",
                        "description": "Deployable service/app target code from list_remote_secret_targets"
                    },
                    "name": {
                        "type": "string",
                        "description": "Secret name, matching [A-Za-z_][A-Za-z0-9_]*"
                    }
                },
                "required": ["project_id", "target_code", "name"]
            }),
        }
    }
}

/// Set or replace one remote service secret.
pub struct SetRemoteServiceSecretTool;

#[async_trait]
impl ToolHandler for SetRemoteServiceSecretTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            project_id: i32,
            target_code: String,
            name: String,
            value: String,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;
        validate_secret_name(&params.name)?;
        if params.value.is_empty() {
            return Err("Secret value must not be empty".to_string());
        }
        ensure_owned_target(context, params.project_id, &params.target_code).await?;

        let vault = vault_from_context(context)?;
        let vault_path = vault.service_secret_path(
            &context.user.id,
            params.project_id,
            &params.target_code,
            &params.name,
        );

        vault
            .store_secret_value(&vault_path, &params.value)
            .await
            .map_err(|e| format!("Failed to store secret value in Vault: {}", e))?;

        let secret = db::remote_secret::upsert_service_secret(
            &context.pg_pool,
            &context.user.id,
            params.project_id,
            &params.target_code,
            &params.name,
            &vault_path,
            &context.user.id,
            "synced",
        )
        .await
        .map_err(|e| format!("Failed to upsert remote service secret metadata: {}", e))?;

        tracing::info!(
            user_id = %context.user.id,
            project_id = params.project_id,
            target_code = %params.target_code,
            secret_name = %params.name,
            "Set remote service secret metadata via MCP"
        );

        Ok(render_json(json!({
            "secret": RemoteSecretMetadataResponse::from(secret),
            "note": "Secret stored in Vault. Plaintext value is not returned."
        })))
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "set_remote_service_secret".to_string(),
            description: "Set or replace a Vault-backed service-scope remote secret for one deployable service/app target. The value is written to Vault and is never returned.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "project_id": {
                        "type": "number",
                        "description": "Project ID containing the target"
                    },
                    "target_code": {
                        "type": "string",
                        "description": "Deployable service/app target code from list_remote_secret_targets"
                    },
                    "name": {
                        "type": "string",
                        "description": "Secret name, matching [A-Za-z_][A-Za-z0-9_]*"
                    },
                    "value": {
                        "type": "string",
                        "description": "Secret value to store in Vault"
                    }
                },
                "required": ["project_id", "target_code", "name", "value"]
            }),
        }
    }
}

/// Delete one remote service secret.
pub struct DeleteRemoteServiceSecretTool;

#[async_trait]
impl ToolHandler for DeleteRemoteServiceSecretTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            project_id: i32,
            target_code: String,
            name: String,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;
        validate_secret_name(&params.name)?;
        ensure_owned_target(context, params.project_id, &params.target_code).await?;

        let secret = db::remote_secret::fetch_service_secret(
            &context.pg_pool,
            &context.user.id,
            params.project_id,
            &params.target_code,
            &params.name,
        )
        .await
        .map_err(|e| format!("Failed to fetch remote service secret: {}", e))?
        .ok_or_else(|| "Secret not found".to_string())?;

        let vault = vault_from_context(context)?;
        vault
            .delete_secret_value(&secret.vault_path)
            .await
            .map_err(|e| format!("Failed to delete secret value from Vault: {}", e))?;

        db::remote_secret::delete_secret_by_id(&context.pg_pool, secret.id)
            .await
            .map_err(|e| format!("Failed to delete remote service secret metadata: {}", e))?;

        tracing::info!(
            user_id = %context.user.id,
            project_id = params.project_id,
            target_code = %params.target_code,
            secret_name = %params.name,
            "Deleted remote service secret metadata via MCP"
        );

        Ok(render_json(json!({
            "deleted": true,
            "project_id": params.project_id,
            "target_code": params.target_code,
            "name": params.name,
            "scope": "service"
        })))
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "delete_remote_service_secret".to_string(),
            description: "Delete a Vault-backed service-scope remote secret from one deployable service/app target.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "project_id": {
                        "type": "number",
                        "description": "Project ID containing the target"
                    },
                    "target_code": {
                        "type": "string",
                        "description": "Deployable service/app target code from list_remote_secret_targets"
                    },
                    "name": {
                        "type": "string",
                        "description": "Secret name, matching [A-Za-z_][A-Za-z0-9_]*"
                    }
                },
                "required": ["project_id", "target_code", "name"]
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{validate_secret_name, ListRemoteSecretTargetsTool, SetRemoteServiceSecretTool};
    use crate::mcp::registry::ToolHandler;

    #[test]
    fn validates_cli_compatible_secret_names() {
        assert!(validate_secret_name("S3_BUCKET").is_ok());
        assert!(validate_secret_name("_TOKEN").is_ok());
        assert!(validate_secret_name("1TOKEN").is_err());
        assert!(validate_secret_name("S3-BUCKET").is_err());
    }

    #[test]
    fn remote_secret_schemas_use_target_language() {
        let list_schema = ListRemoteSecretTargetsTool.schema();
        assert_eq!(list_schema.name, "list_remote_secret_targets");
        assert!(list_schema.description.contains("service/app target"));

        let set_schema = SetRemoteServiceSecretTool.schema();
        assert_eq!(set_schema.name, "set_remote_service_secret");
        assert!(set_schema.description.contains("Vault-backed"));
        assert!(set_schema.description.contains("never returned"));
    }
}
