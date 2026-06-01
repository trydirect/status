//! MCP Tools for App Configuration Management.
//!
//! These tools provide AI access to:
//! - View and update app environment variables
//! - Manage app port configurations
//! - Configure app domains and SSL
//! - View and modify app settings
//!
//! Configuration changes are staged and applied on next deployment/restart.

use async_trait::async_trait;
use serde_json::{json, Map, Value};
use std::collections::{BTreeSet, HashSet};

use crate::db;
use crate::mcp::protocol::{Tool, ToolContent};
use crate::mcp::registry::{ToolContext, ToolHandler};
use crate::services::env_model::normalize_json_env;
use serde::{Deserialize, Serialize};

/// Get environment variables for an app in a project
pub struct GetAppEnvVarsTool;

#[async_trait]
impl ToolHandler for GetAppEnvVarsTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            project_id: i32,
            app_code: String,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        // Verify project ownership
        let project = db::project::fetch(&context.pg_pool, params.project_id)
            .await
            .map_err(|e| format!("Failed to fetch project: {}", e))?
            .ok_or_else(|| "Project not found".to_string())?;

        if project.user_id != context.user.id {
            return Err("Project not found".to_string()); // Don't reveal existence to non-owner
        }

        // Fetch app configuration from project
        let app = db::project_app::fetch_by_project_and_code(
            &context.pg_pool,
            params.project_id,
            &params.app_code,
        )
        .await
        .map_err(|e| format!("Failed to fetch app: {}", e))?
        .ok_or_else(|| format!("App '{}' not found in project", params.app_code))?;

        // Parse environment variables from app config
        let env_vars = app.environment.clone().unwrap_or_default();
        let secure_keys = load_remote_secret_names(
            &context.pg_pool,
            &context.user.id,
            params.project_id,
            &params.app_code,
        )
        .await?;
        let redacted_env = redact_sensitive_env_vars_with_secure_keys(&env_vars, &secure_keys);
        let env_entries = build_env_var_entries(&env_vars, &secure_keys);
        let secure_count = env_entries.iter().filter(|entry| entry.secure).count();

        let result = json!({
            "project_id": params.project_id,
            "app_code": params.app_code,
            "environment_variables": redacted_env,
            "environment_entries": env_entries,
            "count": redacted_env.as_object().map(|o| o.len()).unwrap_or(0),
            "secure_count": secure_count,
            "note": "Sensitive values are redacted for security. Vault-backed variables are marked with secure=true."
        });

        tracing::info!(
            user_id = %context.user.id,
            project_id = params.project_id,
            app_code = %params.app_code,
            "Fetched app environment variables via MCP"
        );

        Ok(ToolContent::Text {
            text: serde_json::to_string_pretty(&result).unwrap_or_else(|_| result.to_string()),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "get_app_env_vars".to_string(),
            description: "Get environment variables configured for a specific app in a project. Sensitive values (passwords, API keys) are automatically redacted for security.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "project_id": {
                        "type": "number",
                        "description": "The project ID containing the app"
                    },
                    "app_code": {
                        "type": "string",
                        "description": "The app code (e.g., 'nginx', 'postgres', 'redis')"
                    }
                },
                "required": ["project_id", "app_code"]
            }),
        }
    }
}

/// Set or update an environment variable for an app
pub struct SetAppEnvVarTool;

#[async_trait]
impl ToolHandler for SetAppEnvVarTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            project_id: i32,
            app_code: String,
            name: String,
            value: String,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        // Validate env var name
        if !is_valid_env_var_name(&params.name) {
            return Err("Invalid environment variable name. Must start with a letter and contain only alphanumeric characters and underscores.".to_string());
        }

        // Verify project ownership
        let project = db::project::fetch(&context.pg_pool, params.project_id)
            .await
            .map_err(|e| format!("Failed to fetch project: {}", e))?
            .ok_or_else(|| "Project not found".to_string())?;

        if project.user_id != context.user.id {
            return Err("Project not found".to_string());
        }

        // Fetch and update app configuration
        let mut app = db::project_app::fetch_by_project_and_code(
            &context.pg_pool,
            params.project_id,
            &params.app_code,
        )
        .await
        .map_err(|e| format!("Failed to fetch app: {}", e))?
        .ok_or_else(|| format!("App '{}' not found in project", params.app_code))?;

        // Update environment variable
        let mut env = app.environment.clone().unwrap_or_else(|| json!({}));
        if let Some(obj) = env.as_object_mut() {
            obj.insert(params.name.clone(), json!(params.value));
        }
        app.environment = Some(env);

        // Save updated app config
        db::project_app::update(&context.pg_pool, &app)
            .await
            .map_err(|e| format!("Failed to update app: {}", e))?;

        let result = json!({
            "success": true,
            "project_id": params.project_id,
            "app_code": params.app_code,
            "variable": params.name,
            "action": "set",
            "note": "Environment variable updated. Changes will take effect on next restart or redeploy."
        });

        tracing::info!(
            user_id = %context.user.id,
            project_id = params.project_id,
            app_code = %params.app_code,
            var_name = %params.name,
            "Set environment variable via MCP"
        );

        Ok(ToolContent::Text {
            text: serde_json::to_string_pretty(&result).unwrap_or_else(|_| result.to_string()),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "set_app_env_var".to_string(),
            description: "Set or update an environment variable for a specific app in a project. Changes are staged and will take effect on the next container restart or redeployment.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "project_id": {
                        "type": "number",
                        "description": "The project ID containing the app"
                    },
                    "app_code": {
                        "type": "string",
                        "description": "The app code (e.g., 'nginx', 'postgres', 'redis')"
                    },
                    "name": {
                        "type": "string",
                        "description": "Environment variable name (e.g., 'DATABASE_URL', 'LOG_LEVEL')"
                    },
                    "value": {
                        "type": "string",
                        "description": "Value to set for the environment variable"
                    }
                },
                "required": ["project_id", "app_code", "name", "value"]
            }),
        }
    }
}

/// Delete an environment variable from an app
pub struct DeleteAppEnvVarTool;

#[async_trait]
impl ToolHandler for DeleteAppEnvVarTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            project_id: i32,
            app_code: String,
            name: String,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        // Verify project ownership
        let project = db::project::fetch(&context.pg_pool, params.project_id)
            .await
            .map_err(|e| format!("Failed to fetch project: {}", e))?
            .ok_or_else(|| "Project not found".to_string())?;

        if project.user_id != context.user.id {
            return Err("Project not found".to_string());
        }

        // Fetch and update app configuration
        let mut app = db::project_app::fetch_by_project_and_code(
            &context.pg_pool,
            params.project_id,
            &params.app_code,
        )
        .await
        .map_err(|e| format!("Failed to fetch app: {}", e))?
        .ok_or_else(|| format!("App '{}' not found in project", params.app_code))?;

        // Remove environment variable
        let mut env = app.environment.clone().unwrap_or_else(|| json!({}));
        let existed = if let Some(obj) = env.as_object_mut() {
            obj.remove(&params.name).is_some()
        } else {
            false
        };
        app.environment = Some(env);

        if !existed {
            return Err(format!(
                "Environment variable '{}' not found in app '{}'",
                params.name, params.app_code
            ));
        }

        // Save updated app config
        db::project_app::update(&context.pg_pool, &app)
            .await
            .map_err(|e| format!("Failed to update app: {}", e))?;

        let result = json!({
            "success": true,
            "project_id": params.project_id,
            "app_code": params.app_code,
            "variable": params.name,
            "action": "deleted",
            "note": "Environment variable removed. Changes will take effect on next restart or redeploy."
        });

        tracing::info!(
            user_id = %context.user.id,
            project_id = params.project_id,
            app_code = %params.app_code,
            var_name = %params.name,
            "Deleted environment variable via MCP"
        );

        Ok(ToolContent::Text {
            text: serde_json::to_string_pretty(&result).unwrap_or_else(|_| result.to_string()),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "delete_app_env_var".to_string(),
            description: "Remove an environment variable from a specific app in a project. Changes will take effect on the next container restart or redeployment.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "project_id": {
                        "type": "number",
                        "description": "The project ID containing the app"
                    },
                    "app_code": {
                        "type": "string",
                        "description": "The app code (e.g., 'nginx', 'postgres', 'redis')"
                    },
                    "name": {
                        "type": "string",
                        "description": "Environment variable name to delete"
                    }
                },
                "required": ["project_id", "app_code", "name"]
            }),
        }
    }
}

/// Get the full app configuration including ports, volumes, and settings
pub struct GetAppConfigTool;

#[async_trait]
impl ToolHandler for GetAppConfigTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            project_id: i32,
            app_code: String,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        // Verify project ownership
        let project = db::project::fetch(&context.pg_pool, params.project_id)
            .await
            .map_err(|e| format!("Failed to fetch project: {}", e))?
            .ok_or_else(|| "Project not found".to_string())?;

        if project.user_id != context.user.id {
            return Err("Project not found".to_string());
        }

        // Fetch app configuration
        let app = db::project_app::fetch_by_project_and_code(
            &context.pg_pool,
            params.project_id,
            &params.app_code,
        )
        .await
        .map_err(|e| format!("Failed to fetch app: {}", e))?
        .ok_or_else(|| format!("App '{}' not found in project", params.app_code))?;

        // Build config response with redacted sensitive data
        let env_vars = app.environment.clone().unwrap_or_default();
        let redacted_env = redact_sensitive_env_vars(&env_vars);

        let result = json!({
            "project_id": params.project_id,
            "app_code": params.app_code,
            "app_name": app.name,
            "image": app.image,
            "ports": app.ports,
            "volumes": app.volumes,
            "environment_variables": redacted_env,
            "domain": app.domain,
            "ssl_enabled": app.ssl_enabled.unwrap_or(false),
            "restart_policy": app.restart_policy.clone().unwrap_or_else(|| "unless-stopped".to_string()),
            "resources": app.resources,
            "depends_on": app.depends_on,
            "note": "Sensitive environment variable values are redacted for security."
        });

        tracing::info!(
            user_id = %context.user.id,
            project_id = params.project_id,
            app_code = %params.app_code,
            "Fetched full app configuration via MCP"
        );

        Ok(ToolContent::Text {
            text: serde_json::to_string_pretty(&result).unwrap_or_else(|_| result.to_string()),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "get_app_config".to_string(),
            description: "Get the full configuration for a specific app in a project, including ports, volumes, environment variables, resource limits, and SSL settings.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "project_id": {
                        "type": "number",
                        "description": "The project ID containing the app"
                    },
                    "app_code": {
                        "type": "string",
                        "description": "The app code (e.g., 'nginx', 'postgres', 'redis')"
                    }
                },
                "required": ["project_id", "app_code"]
            }),
        }
    }
}

/// Update app port mappings
pub struct UpdateAppPortsTool;

#[async_trait]
impl ToolHandler for UpdateAppPortsTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct PortMapping {
            host: u16,
            container: u16,
            #[serde(default = "default_protocol")]
            protocol: String,
        }

        fn default_protocol() -> String {
            "tcp".to_string()
        }

        #[derive(Deserialize)]
        struct Args {
            project_id: i32,
            app_code: String,
            ports: Vec<PortMapping>,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        // Validate ports (u16 type already enforces max 65535, so we only check for 0)
        for port in &params.ports {
            if port.host == 0 {
                return Err(format!("Invalid host port: {}", port.host));
            }
            if port.container == 0 {
                return Err(format!("Invalid container port: {}", port.container));
            }
            if port.protocol != "tcp" && port.protocol != "udp" {
                return Err(format!(
                    "Invalid protocol '{}'. Must be 'tcp' or 'udp'.",
                    port.protocol
                ));
            }
        }

        // Verify project ownership
        let project = db::project::fetch(&context.pg_pool, params.project_id)
            .await
            .map_err(|e| format!("Failed to fetch project: {}", e))?
            .ok_or_else(|| "Project not found".to_string())?;

        if project.user_id != context.user.id {
            return Err("Project not found".to_string());
        }

        // Fetch and update app
        let mut app = db::project_app::fetch_by_project_and_code(
            &context.pg_pool,
            params.project_id,
            &params.app_code,
        )
        .await
        .map_err(|e| format!("Failed to fetch app: {}", e))?
        .ok_or_else(|| format!("App '{}' not found in project", params.app_code))?;

        // Update ports
        let ports_json: Vec<Value> = params
            .ports
            .iter()
            .map(|p| {
                json!({
                    "host": p.host,
                    "container": p.container,
                    "protocol": p.protocol
                })
            })
            .collect();

        app.ports = Some(json!(ports_json));

        // Save updated app config
        db::project_app::update(&context.pg_pool, &app)
            .await
            .map_err(|e| format!("Failed to update app: {}", e))?;

        let result = json!({
            "success": true,
            "project_id": params.project_id,
            "app_code": params.app_code,
            "ports": ports_json,
            "note": "Port mappings updated. Changes will take effect on next redeploy."
        });

        tracing::info!(
            user_id = %context.user.id,
            project_id = params.project_id,
            app_code = %params.app_code,
            ports_count = params.ports.len(),
            "Updated app port mappings via MCP"
        );

        Ok(ToolContent::Text {
            text: serde_json::to_string_pretty(&result).unwrap_or_else(|_| result.to_string()),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "update_app_ports".to_string(),
            description: "Update port mappings for a specific app. Allows configuring which ports are exposed from the container to the host.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "project_id": {
                        "type": "number",
                        "description": "The project ID containing the app"
                    },
                    "app_code": {
                        "type": "string",
                        "description": "The app code (e.g., 'nginx', 'postgres')"
                    },
                    "ports": {
                        "type": "array",
                        "description": "Array of port mappings",
                        "items": {
                            "type": "object",
                            "properties": {
                                "host": {
                                    "type": "number",
                                    "description": "Port on the host machine"
                                },
                                "container": {
                                    "type": "number",
                                    "description": "Port inside the container"
                                },
                                "protocol": {
                                    "type": "string",
                                    "enum": ["tcp", "udp"],
                                    "description": "Protocol (default: tcp)"
                                }
                            },
                            "required": ["host", "container"]
                        }
                    }
                },
                "required": ["project_id", "app_code", "ports"]
            }),
        }
    }
}

/// Update app domain configuration
pub struct UpdateAppDomainTool;

#[async_trait]
impl ToolHandler for UpdateAppDomainTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            project_id: i32,
            app_code: String,
            domain: String,
            #[serde(default)]
            enable_ssl: Option<bool>,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        // Basic domain validation
        if !is_valid_domain(&params.domain) {
            return Err("Invalid domain format. Please provide a valid domain name (e.g., 'example.com' or 'app.example.com')".to_string());
        }

        // Verify project ownership
        let project = db::project::fetch(&context.pg_pool, params.project_id)
            .await
            .map_err(|e| format!("Failed to fetch project: {}", e))?
            .ok_or_else(|| "Project not found".to_string())?;

        if project.user_id != context.user.id {
            return Err("Project not found".to_string());
        }

        // Fetch and update app
        let mut app = db::project_app::fetch_by_project_and_code(
            &context.pg_pool,
            params.project_id,
            &params.app_code,
        )
        .await
        .map_err(|e| format!("Failed to fetch app: {}", e))?
        .ok_or_else(|| format!("App '{}' not found in project", params.app_code))?;

        // Update domain and SSL
        app.domain = Some(params.domain.clone());
        if let Some(ssl) = params.enable_ssl {
            app.ssl_enabled = Some(ssl);
        }

        // Save updated app config
        db::project_app::update(&context.pg_pool, &app)
            .await
            .map_err(|e| format!("Failed to update app: {}", e))?;

        let result = json!({
            "success": true,
            "project_id": params.project_id,
            "app_code": params.app_code,
            "domain": params.domain,
            "ssl_enabled": app.ssl_enabled.unwrap_or(false),
            "note": "Domain configuration updated. Remember to point your DNS to the server IP. Changes take effect on next redeploy.",
            "dns_instructions": format!(
                "Add an A record pointing '{}' to your server's IP address.",
                params.domain
            )
        });

        tracing::info!(
            user_id = %context.user.id,
            project_id = params.project_id,
            app_code = %params.app_code,
            domain = %params.domain,
            "Updated app domain via MCP"
        );

        Ok(ToolContent::Text {
            text: serde_json::to_string_pretty(&result).unwrap_or_else(|_| result.to_string()),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "update_app_domain".to_string(),
            description: "Configure the domain for a specific app. Optionally enable SSL/HTTPS for secure connections.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "project_id": {
                        "type": "number",
                        "description": "The project ID containing the app"
                    },
                    "app_code": {
                        "type": "string",
                        "description": "The app code (e.g., 'nginx', 'wordpress')"
                    },
                    "domain": {
                        "type": "string",
                        "description": "The domain name (e.g., 'myapp.example.com')"
                    },
                    "enable_ssl": {
                        "type": "boolean",
                        "description": "Enable SSL/HTTPS with Let's Encrypt (default: false)"
                    }
                },
                "required": ["project_id", "app_code", "domain"]
            }),
        }
    }
}

// Helper functions

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct AppEnvVarEntry {
    name: String,
    value: String,
    secure: bool,
    redacted: bool,
    source: String,
}

async fn load_remote_secret_names(
    pool: &sqlx::PgPool,
    user_id: &str,
    project_id: i32,
    app_code: &str,
) -> Result<HashSet<String>, String> {
    db::remote_secret::list_service_secrets(pool, user_id, project_id, app_code)
        .await
        .map(|secrets| secrets.into_iter().map(|secret| secret.name).collect())
        .map_err(|error| format!("Failed to load remote service secrets: {}", error))
}

/// Redact sensitive environment variable values
fn redact_sensitive_env_vars(env: &Value) -> Value {
    redact_sensitive_env_vars_with_secure_keys(env, &HashSet::new())
}

fn redact_sensitive_env_vars_with_secure_keys(env: &Value, secure_keys: &HashSet<String>) -> Value {
    let mut normalized = normalize_environment_object(env);
    for key in secure_keys {
        normalized.insert(key.clone(), json!("[REDACTED]"));
    }

    let redacted = normalized
        .into_iter()
        .map(|(key, value)| {
            if should_redact_env_var(&key, secure_keys) {
                (key, json!("[REDACTED]"))
            } else {
                (key, value)
            }
        })
        .collect();

    Value::Object(redacted)
}

fn build_env_var_entries(env: &Value, secure_keys: &HashSet<String>) -> Vec<AppEnvVarEntry> {
    let normalized = normalize_environment_object(env);
    let mut keys: BTreeSet<String> = normalized.keys().cloned().collect();
    keys.extend(secure_keys.iter().cloned());

    keys.into_iter()
        .map(|name| {
            let secure = secure_keys.contains(&name);
            let redacted = should_redact_env_var(&name, secure_keys);
            let value = if redacted {
                "[REDACTED]".to_string()
            } else {
                stringify_env_value(normalized.get(&name))
            };

            AppEnvVarEntry {
                name,
                value,
                secure,
                redacted,
                source: if secure {
                    "vault".to_string()
                } else {
                    "project".to_string()
                },
            }
        })
        .collect()
}

fn should_redact_env_var(name: &str, secure_keys: &HashSet<String>) -> bool {
    secure_keys.contains(name) || is_sensitive_env_var_name(name)
}

fn is_sensitive_env_var_name(name: &str) -> bool {
    const SENSITIVE_PATTERNS: &[&str] = &[
        "password",
        "passwd",
        "username",
        "secret",
        "token",
        "key",
        "auth",
        "credential",
        "api_key",
        "apikey",
        "private",
        "cert",
        "jwt",
        "bearer",
        "access_token",
        "refresh_token",
    ];

    let key_lower = name.to_lowercase();
    SENSITIVE_PATTERNS
        .iter()
        .any(|pattern| key_lower.contains(pattern))
}

fn normalize_environment_object(env: &Value) -> Map<String, Value> {
    normalize_json_env(env)
        .into_iter()
        .map(|(key, value)| (key, Value::String(value)))
        .collect()
}

fn stringify_env_value(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(text)) => text.clone(),
        Some(other) => other.to_string(),
        None => String::new(),
    }
}

/// Validate environment variable name
fn is_valid_env_var_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }

    let mut chars = name.chars();

    // First character must be a letter or underscore
    if let Some(first) = chars.next() {
        if !first.is_ascii_alphabetic() && first != '_' {
            return false;
        }
    }

    // Rest must be alphanumeric or underscore
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Basic domain validation
fn is_valid_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 {
        return false;
    }

    // Simple regex-like check
    let parts: Vec<&str> = domain.split('.').collect();
    if parts.len() < 2 {
        return false;
    }

    for part in parts {
        if part.is_empty() || part.len() > 63 {
            return false;
        }
        if !part.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return false;
        }
        if part.starts_with('-') || part.ends_with('-') {
            return false;
        }
    }

    true
}

// =============================================================================
// Vault Configuration Tools
// =============================================================================

/// Get app configuration from Vault
pub struct GetVaultConfigTool;

#[async_trait]
impl ToolHandler for GetVaultConfigTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        use crate::services::VaultService;

        #[derive(Deserialize)]
        struct Args {
            deployment_hash: String,
            app_code: String,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        // Verify deployment ownership via deployment table
        let deployment =
            db::deployment::fetch_by_deployment_hash(&context.pg_pool, &params.deployment_hash)
                .await
                .map_err(|e| format!("Failed to fetch deployment: {}", e))?
                .ok_or_else(|| "Deployment not found".to_string())?;

        if deployment.user_id.as_deref() != Some(context.user.id.as_str()) {
            return Err("Deployment not found".to_string());
        }

        // Initialize Vault service
        let vault = VaultService::from_env()
            .map_err(|e| format!("Vault error: {}", e))?
            .ok_or_else(|| {
                "Vault not configured. Contact support to enable config management.".to_string()
            })?;

        // Fetch config from Vault
        match vault
            .fetch_app_config(&params.deployment_hash, &params.app_code)
            .await
        {
            Ok(config) => {
                let result = json!({
                    "deployment_hash": params.deployment_hash,
                    "app_code": params.app_code,
                    "config": {
                        "content": config.content,
                        "content_type": config.content_type,
                        "destination_path": config.destination_path,
                        "file_mode": config.file_mode,
                        "owner": config.owner,
                        "group": config.group,
                    },
                    "source": "vault",
                });

                tracing::info!(
                    user_id = %context.user.id,
                    deployment_hash = %params.deployment_hash,
                    app_code = %params.app_code,
                    "Fetched Vault config via MCP"
                );

                Ok(ToolContent::Text {
                    text: serde_json::to_string_pretty(&result)
                        .unwrap_or_else(|_| result.to_string()),
                })
            }
            Err(crate::services::VaultError::NotFound(_)) => {
                let result = json!({
                    "deployment_hash": params.deployment_hash,
                    "app_code": params.app_code,
                    "config": null,
                    "message": format!("No configuration found in Vault for app '{}'", params.app_code),
                });
                Ok(ToolContent::Text {
                    text: serde_json::to_string_pretty(&result)
                        .unwrap_or_else(|_| result.to_string()),
                })
            }
            Err(e) => Err(format!("Failed to fetch config from Vault: {}", e)),
        }
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "get_vault_config".to_string(),
            description: "Get app configuration file from Vault for a deployment. Returns the config content, type, and destination path.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "deployment_hash": {
                        "type": "string",
                        "description": "The deployment hash"
                    },
                    "app_code": {
                        "type": "string",
                        "description": "The app code (e.g., 'nginx', 'app', 'redis')"
                    }
                },
                "required": ["deployment_hash", "app_code"]
            }),
        }
    }
}

/// Store app configuration in Vault
pub struct SetVaultConfigTool;

#[async_trait]
impl ToolHandler for SetVaultConfigTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        use crate::services::{AppConfig, VaultService};

        #[derive(Deserialize)]
        struct Args {
            deployment_hash: String,
            app_code: String,
            content: String,
            content_type: Option<String>,
            destination_path: String,
            file_mode: Option<String>,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        // Verify deployment ownership
        let deployment =
            db::deployment::fetch_by_deployment_hash(&context.pg_pool, &params.deployment_hash)
                .await
                .map_err(|e| format!("Failed to fetch deployment: {}", e))?
                .ok_or_else(|| "Deployment not found".to_string())?;

        if deployment.user_id.as_deref() != Some(&context.user.id as &str) {
            return Err("Deployment not found".to_string());
        }

        // Validate destination path
        if params.destination_path.is_empty() || !params.destination_path.starts_with('/') {
            return Err("destination_path must be an absolute path (starting with /)".to_string());
        }

        // Initialize Vault service
        let vault = VaultService::from_env()
            .map_err(|e| format!("Vault error: {}", e))?
            .ok_or_else(|| {
                "Vault not configured. Contact support to enable config management.".to_string()
            })?;

        let config = AppConfig {
            content: params.content.clone(),
            content_type: params.content_type.unwrap_or_else(|| "text".to_string()),
            destination_path: params.destination_path.clone(),
            file_mode: params.file_mode.unwrap_or_else(|| "0644".to_string()),
            owner: None,
            group: None,
        };

        // Store in Vault
        vault
            .store_app_config(&params.deployment_hash, &params.app_code, &config)
            .await
            .map_err(|e| format!("Failed to store config in Vault: {}", e))?;

        let result = json!({
            "success": true,
            "deployment_hash": params.deployment_hash,
            "app_code": params.app_code,
            "destination_path": params.destination_path,
            "content_type": config.content_type,
            "content_length": params.content.len(),
            "message": "Configuration stored in Vault. Use apply_vault_config to write to the deployment server.",
        });

        tracing::info!(
            user_id = %context.user.id,
            deployment_hash = %params.deployment_hash,
            app_code = %params.app_code,
            destination = %params.destination_path,
            "Stored Vault config via MCP"
        );

        Ok(ToolContent::Text {
            text: serde_json::to_string_pretty(&result).unwrap_or_else(|_| result.to_string()),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "set_vault_config".to_string(),
            description: "Store app configuration file in Vault for a deployment. The config will be written to the server on next apply.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "deployment_hash": {
                        "type": "string",
                        "description": "The deployment hash"
                    },
                    "app_code": {
                        "type": "string",
                        "description": "The app code (e.g., 'nginx', 'app', 'redis')"
                    },
                    "content": {
                        "type": "string",
                        "description": "The configuration file content"
                    },
                    "content_type": {
                        "type": "string",
                        "enum": ["json", "yaml", "env", "text"],
                        "description": "The content type (default: text)"
                    },
                    "destination_path": {
                        "type": "string",
                        "description": "Absolute path where the config should be written on the server"
                    },
                    "file_mode": {
                        "type": "string",
                        "description": "File permissions (default: 0644)"
                    }
                },
                "required": ["deployment_hash", "app_code", "content", "destination_path"]
            }),
        }
    }
}

/// List all app configs stored in Vault for a deployment
pub struct ListVaultConfigsTool;

#[async_trait]
impl ToolHandler for ListVaultConfigsTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        use crate::services::VaultService;

        #[derive(Deserialize)]
        struct Args {
            deployment_hash: String,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        // Verify deployment ownership
        let deployment =
            db::deployment::fetch_by_deployment_hash(&context.pg_pool, &params.deployment_hash)
                .await
                .map_err(|e| format!("Failed to fetch deployment: {}", e))?
                .ok_or_else(|| "Deployment not found".to_string())?;

        if deployment.user_id.as_deref() != Some(&context.user.id as &str) {
            return Err("Deployment not found".to_string());
        }

        // Initialize Vault service
        let vault = VaultService::from_env()
            .map_err(|e| format!("Vault error: {}", e))?
            .ok_or_else(|| {
                "Vault not configured. Contact support to enable config management.".to_string()
            })?;

        // List configs
        let apps = vault
            .list_app_configs(&params.deployment_hash)
            .await
            .map_err(|e| format!("Failed to list configs: {}", e))?;

        let result = json!({
            "deployment_hash": params.deployment_hash,
            "apps": apps,
            "count": apps.len(),
        });

        tracing::info!(
            user_id = %context.user.id,
            deployment_hash = %params.deployment_hash,
            count = apps.len(),
            "Listed Vault configs via MCP"
        );

        Ok(ToolContent::Text {
            text: serde_json::to_string_pretty(&result).unwrap_or_else(|_| result.to_string()),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "list_vault_configs".to_string(),
            description: "List all app configurations stored in Vault for a deployment."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "deployment_hash": {
                        "type": "string",
                        "description": "The deployment hash"
                    }
                },
                "required": ["deployment_hash"]
            }),
        }
    }
}

/// Apply app configuration from Vault to the deployment server
pub struct ApplyVaultConfigTool;

#[async_trait]
impl ToolHandler for ApplyVaultConfigTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        use crate::services::agent_dispatcher::AgentDispatcher;

        #[derive(Deserialize)]
        struct Args {
            deployment_hash: String,
            app_code: String,
            #[serde(default)]
            restart_after: bool,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        // Verify deployment ownership
        let deployment =
            db::deployment::fetch_by_deployment_hash(&context.pg_pool, &params.deployment_hash)
                .await
                .map_err(|e| format!("Failed to fetch deployment: {}", e))?
                .ok_or_else(|| "Deployment not found".to_string())?;

        if deployment.user_id.as_deref() != Some(&context.user.id as &str) {
            return Err("Deployment not found".to_string());
        }

        // Queue the apply_config command to the Status Panel agent
        let command_payload = json!({
            "deployment_hash": params.deployment_hash,
            "app_code": params.app_code,
            "restart_after": params.restart_after,
        });

        let dispatcher = AgentDispatcher::new(&context.pg_pool);
        let command_id = dispatcher
            .queue_command(deployment.id, "apply_config", command_payload)
            .await
            .map_err(|e| format!("Failed to queue command: {}", e))?;

        let result = json!({
            "success": true,
            "command_id": command_id,
            "deployment_hash": params.deployment_hash,
            "app_code": params.app_code,
            "restart_after": params.restart_after,
            "message": format!(
                "Configuration apply command queued. The agent will fetch config from Vault and write to disk{}.",
                if params.restart_after { ", then restart the container" } else { "" }
            ),
            "status": "queued",
        });

        tracing::info!(
            user_id = %context.user.id,
            deployment_hash = %params.deployment_hash,
            app_code = %params.app_code,
            command_id = %command_id,
            "Queued apply_config command via MCP"
        );

        Ok(ToolContent::Text {
            text: serde_json::to_string_pretty(&result).unwrap_or_else(|_| result.to_string()),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "apply_vault_config".to_string(),
            description: "Apply app configuration from Vault to the deployment server. The Status Panel agent will fetch the config and write it to disk. Optionally restarts the container after applying.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "deployment_hash": {
                        "type": "string",
                        "description": "The deployment hash"
                    },
                    "app_code": {
                        "type": "string",
                        "description": "The app code (e.g., 'nginx', 'app', 'redis')"
                    },
                    "restart_after": {
                        "type": "boolean",
                        "description": "Whether to restart the container after applying the config (default: false)"
                    }
                },
                "required": ["deployment_hash", "app_code"]
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_env_var_name() {
        assert!(is_valid_env_var_name("DATABASE_URL"));
        assert!(is_valid_env_var_name("LOG_LEVEL"));
        assert!(is_valid_env_var_name("_PRIVATE"));
        assert!(is_valid_env_var_name("var1"));

        assert!(!is_valid_env_var_name(""));
        assert!(!is_valid_env_var_name("1VAR"));
        assert!(!is_valid_env_var_name("VAR-NAME"));
        assert!(!is_valid_env_var_name("VAR.NAME"));
    }

    #[test]
    fn test_is_valid_domain() {
        assert!(is_valid_domain("example.com"));
        assert!(is_valid_domain("sub.example.com"));
        assert!(is_valid_domain("my-app.example.co.uk"));

        assert!(!is_valid_domain(""));
        assert!(!is_valid_domain("example"));
        assert!(!is_valid_domain("-example.com"));
        assert!(!is_valid_domain("example-.com"));
    }

    #[test]
    fn test_redact_sensitive_env_vars() {
        let env = json!({
            "DATABASE_URL": "postgres://localhost",
            "DB_PASSWORD": "secret123",
            "API_KEY": "key-abc-123",
            "REGISTRY_USERNAME": "registry-user",
            "VAULT_TOKEN": "vault-token-value",
            "INTERNAL_SERVICES_ACCESS_KEY": "internal-access-key",
            "LOG_LEVEL": "debug",
            "PORT": "8080"
        });

        let redacted = redact_sensitive_env_vars(&env);
        let obj = redacted.as_object().unwrap();

        assert_eq!(obj.get("DATABASE_URL").unwrap(), "postgres://localhost");
        assert_eq!(obj.get("DB_PASSWORD").unwrap(), "[REDACTED]");
        assert_eq!(obj.get("API_KEY").unwrap(), "[REDACTED]");
        assert_eq!(obj.get("REGISTRY_USERNAME").unwrap(), "[REDACTED]");
        assert_eq!(obj.get("VAULT_TOKEN").unwrap(), "[REDACTED]");
        assert_eq!(
            obj.get("INTERNAL_SERVICES_ACCESS_KEY").unwrap(),
            "[REDACTED]"
        );
        assert_eq!(obj.get("LOG_LEVEL").unwrap(), "debug");
        assert_eq!(obj.get("PORT").unwrap(), "8080");
    }

    #[test]
    fn test_redact_secure_vault_vars_even_without_sensitive_name() {
        let env = json!({
            "LOG_LEVEL": "debug"
        });
        let secure_keys = HashSet::from([String::from("MYSECURE_PASSPHRASE")]);

        let redacted = redact_sensitive_env_vars_with_secure_keys(&env, &secure_keys);
        let obj = redacted.as_object().unwrap();

        assert_eq!(obj.get("LOG_LEVEL").unwrap(), "debug");
        assert_eq!(obj.get("MYSECURE_PASSPHRASE").unwrap(), "[REDACTED]");
    }

    #[test]
    fn test_build_env_var_entries_marks_vault_vars_secure() {
        let env = json!({
            "LOG_LEVEL": "debug",
            "MYSECURE_TOKEN": "ignored-local"
        });
        let secure_keys = HashSet::from([String::from("MYSECURE_PASSPHRASE")]);

        let entries = build_env_var_entries(&env, &secure_keys);

        assert!(entries.contains(&AppEnvVarEntry {
            name: "LOG_LEVEL".to_string(),
            value: "debug".to_string(),
            secure: false,
            redacted: false,
            source: "project".to_string(),
        }));
        assert!(entries.contains(&AppEnvVarEntry {
            name: "MYSECURE_PASSPHRASE".to_string(),
            value: "[REDACTED]".to_string(),
            secure: true,
            redacted: true,
            source: "vault".to_string(),
        }));
        assert!(entries.contains(&AppEnvVarEntry {
            name: "MYSECURE_TOKEN".to_string(),
            value: "[REDACTED]".to_string(),
            secure: false,
            redacted: true,
            source: "project".to_string(),
        }));
    }
}
