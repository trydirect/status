//! MCP Tools for Nginx Proxy Manager integration
//!
//! These tools allow AI chat to configure reverse proxies for deployed applications.

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::connectors::user_service::UserServiceDeploymentResolver;
use crate::db;
use crate::mcp::protocol::{Tool, ToolContent};
use crate::mcp::registry::{ToolContext, ToolHandler};
use crate::models::{Command, CommandPriority};
use crate::services::{DeploymentIdentifier, DeploymentResolver};

/// Helper to create a resolver from context.
fn create_resolver(context: &ToolContext) -> UserServiceDeploymentResolver {
    UserServiceDeploymentResolver::from_context(
        &context.settings.user_service_url,
        context.user.access_token.as_deref(),
    )
}

/// Configure a reverse proxy for an application
///
/// Creates or updates a proxy host in Nginx Proxy Manager to route
/// a domain to a container's port.
pub struct ConfigureProxyTool;

#[async_trait]
impl ToolHandler for ConfigureProxyTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            /// The deployment ID (for legacy User Service deployments)
            #[serde(default)]
            deployment_id: Option<i64>,
            /// The deployment hash (for Stack Builder deployments)
            #[serde(default)]
            deployment_hash: Option<String>,
            /// App code (container name) to proxy
            app_code: String,
            /// Domain name(s) to proxy (e.g., ["komodo.example.com"])
            domain_names: Vec<String>,
            /// Port on the container to forward to
            forward_port: u16,
            /// Container/service name to forward to (defaults to app_code)
            #[serde(default)]
            forward_host: Option<String>,
            /// Enable SSL with Let's Encrypt (default: true)
            #[serde(default = "default_true")]
            ssl_enabled: bool,
            /// Force HTTPS redirect (default: true)
            #[serde(default = "default_true")]
            ssl_forced: bool,
            /// HTTP/2 support (default: true)
            #[serde(default = "default_true")]
            http2_support: bool,
        }

        fn default_true() -> bool {
            true
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        // Create identifier from args (prefers hash if both provided)
        let identifier = DeploymentIdentifier::try_from_options(
            params.deployment_hash.clone(),
            params.deployment_id,
        )?;

        // Resolve to deployment_hash
        let resolver = create_resolver(context);
        let deployment_hash = resolver.resolve(&identifier).await?;

        // Validate domain names
        if params.domain_names.is_empty() {
            return Err("At least one domain_name is required".to_string());
        }

        // Validate port
        if params.forward_port == 0 {
            return Err("forward_port must be greater than 0".to_string());
        }

        // Create command for agent
        let command_id = uuid::Uuid::new_v4().to_string();
        let command = Command::new(
            command_id.clone(),
            deployment_hash.clone(),
            "configure_proxy".to_string(),
            context.user.id.clone(),
        )
        .with_parameters(json!({
            "name": "stacker.configure_proxy",
            "params": {
                "deployment_hash": deployment_hash,
                "app_code": params.app_code,
                "domain_names": params.domain_names,
                "forward_port": params.forward_port,
                "forward_host": params.forward_host.clone().unwrap_or_else(|| params.app_code.clone()),
                "ssl_enabled": params.ssl_enabled,
                "ssl_forced": params.ssl_forced,
                "http2_support": params.http2_support,
                "action": "create"
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

        tracing::info!(
            user_id = %context.user.id,
            deployment_hash = %deployment_hash,
            app_code = %params.app_code,
            domains = ?params.domain_names,
            port = %params.forward_port,
            "Queued configure_proxy command via MCP"
        );

        let response = json!({
            "status": "queued",
            "command_id": command.command_id,
            "deployment_hash": deployment_hash,
            "app_code": params.app_code,
            "domain_names": params.domain_names,
            "forward_port": params.forward_port,
            "ssl_enabled": params.ssl_enabled,
            "message": format!(
                "Proxy configuration command queued. Domain(s) {} will be configured to forward to {}:{}",
                params.domain_names.join(", "),
                params.forward_host.as_ref().unwrap_or(&params.app_code),
                params.forward_port
            )
        });

        Ok(ToolContent::Text {
            text: response.to_string(),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "configure_proxy".to_string(),
            description: "Configure a reverse proxy (Nginx Proxy Manager) to route a domain to an application. Set ssl_enabled=false for plain HTTP hosts; when enabled, SSL certificates are requested with Let's Encrypt.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "deployment_id": {
                        "type": "number",
                        "description": "The deployment/installation ID (for legacy User Service deployments)"
                    },
                    "deployment_hash": {
                        "type": "string",
                        "description": "The deployment hash (for Stack Builder deployments)"
                    },
                    "app_code": {
                        "type": "string",
                        "description": "The app code (container name) to proxy to"
                    },
                    "domain_names": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Domain name(s) to proxy (e.g., ['komodo.example.com'])"
                    },
                    "forward_port": {
                        "type": "number",
                        "description": "Port on the container to forward traffic to"
                    },
                    "forward_host": {
                        "type": "string",
                        "description": "Container/service name to forward to (defaults to app_code)"
                    },
                    "ssl_enabled": {
                        "type": "boolean",
                        "description": "Enable SSL with Let's Encrypt; set false for plain HTTP hosts (default: true)"
                    },
                    "ssl_forced": {
                        "type": "boolean",
                        "description": "Force HTTPS redirect when SSL is enabled (default: true)"
                    },
                    "http2_support": {
                        "type": "boolean",
                        "description": "Enable HTTP/2 support (default: true)"
                    }
                },
                "required": ["app_code", "domain_names", "forward_port"]
            }),
        }
    }
}

/// Delete a reverse proxy configuration
pub struct DeleteProxyTool;

#[async_trait]
impl ToolHandler for DeleteProxyTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            /// The deployment ID (for legacy User Service deployments)
            #[serde(default)]
            deployment_id: Option<i64>,
            /// The deployment hash (for Stack Builder deployments)
            #[serde(default)]
            deployment_hash: Option<String>,
            /// App code associated with the proxy
            app_code: String,
            /// Domain name(s) to remove proxy for
            domain_names: Vec<String>,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        // Create identifier from args (prefers hash if both provided)
        let identifier = DeploymentIdentifier::try_from_options(
            params.deployment_hash.clone(),
            params.deployment_id,
        )?;

        // Resolve to deployment_hash
        let resolver = create_resolver(context);
        let deployment_hash = resolver.resolve(&identifier).await?;

        // Validate domain names
        if params.domain_names.is_empty() {
            return Err(
                "At least one domain_name is required to identify the proxy to delete".to_string(),
            );
        }

        // Create command for agent
        let command_id = uuid::Uuid::new_v4().to_string();
        let command = Command::new(
            command_id.clone(),
            deployment_hash.clone(),
            "configure_proxy".to_string(),
            context.user.id.clone(),
        )
        .with_parameters(json!({
            "name": "stacker.configure_proxy",
            "params": {
                "deployment_hash": deployment_hash,
                "app_code": params.app_code,
                "domain_names": params.domain_names,
                "forward_port": 0,  // Not needed for delete
                "action": "delete"
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

        tracing::info!(
            user_id = %context.user.id,
            deployment_hash = %deployment_hash,
            app_code = %params.app_code,
            domains = ?params.domain_names,
            "Queued delete_proxy command via MCP"
        );

        let response = json!({
            "status": "queued",
            "command_id": command.command_id,
            "deployment_hash": deployment_hash,
            "app_code": params.app_code,
            "domain_names": params.domain_names,
            "message": format!(
                "Delete proxy command queued. Proxy for domain(s) {} will be removed.",
                params.domain_names.join(", ")
            )
        });

        Ok(ToolContent::Text {
            text: response.to_string(),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "delete_proxy".to_string(),
            description: "Delete a reverse proxy configuration from Nginx Proxy Manager."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "deployment_id": {
                        "type": "number",
                        "description": "The deployment/installation ID (for legacy User Service deployments)"
                    },
                    "deployment_hash": {
                        "type": "string",
                        "description": "The deployment hash (for Stack Builder deployments)"
                    },
                    "app_code": {
                        "type": "string",
                        "description": "The app code associated with the proxy"
                    },
                    "domain_names": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Domain name(s) to remove proxy for (used to identify the proxy host)"
                    }
                },
                "required": ["app_code", "domain_names"]
            }),
        }
    }
}

/// List all proxy hosts configured for a deployment
pub struct ListProxiesTool;

#[async_trait]
impl ToolHandler for ListProxiesTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            /// The deployment ID (for legacy User Service deployments)
            #[serde(default)]
            deployment_id: Option<i64>,
            /// The deployment hash (for Stack Builder deployments)
            #[serde(default)]
            deployment_hash: Option<String>,
            /// Optional: filter by app_code
            #[serde(default)]
            app_code: Option<String>,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        // Create identifier from args (prefers hash if both provided)
        let identifier = DeploymentIdentifier::try_from_options(
            params.deployment_hash.clone(),
            params.deployment_id,
        )?;

        // Resolve to deployment_hash
        let resolver = create_resolver(context);
        let deployment_hash = resolver.resolve(&identifier).await?;

        // Create command for agent
        let command_id = uuid::Uuid::new_v4().to_string();
        let command = Command::new(
            command_id.clone(),
            deployment_hash.clone(),
            "configure_proxy".to_string(),
            context.user.id.clone(),
        )
        .with_parameters(json!({
            "name": "stacker.configure_proxy",
            "params": {
                "deployment_hash": deployment_hash,
                "app_code": params.app_code.clone().unwrap_or_default(),
                "action": "list"
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

        tracing::info!(
            user_id = %context.user.id,
            deployment_hash = %deployment_hash,
            "Queued list_proxies command via MCP"
        );

        let response = json!({
            "status": "queued",
            "command_id": command.command_id,
            "deployment_hash": deployment_hash,
            "message": "List proxies command queued. Results will be available when agent responds."
        });

        Ok(ToolContent::Text {
            text: response.to_string(),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "list_proxies".to_string(),
            description: "List all reverse proxy configurations for a deployment.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "deployment_id": {
                        "type": "number",
                        "description": "The deployment/installation ID (for legacy User Service deployments)"
                    },
                    "deployment_hash": {
                        "type": "string",
                        "description": "The deployment hash (for Stack Builder deployments)"
                    },
                    "app_code": {
                        "type": "string",
                        "description": "Optional: filter proxies by app code"
                    }
                },
                "required": []
            }),
        }
    }
}
