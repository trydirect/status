use async_trait::async_trait;
use serde_json::{json, Value};

use crate::db;
use crate::helpers::project::builder::{parse_compose_services, ExtractedService};
use crate::mcp::protocol::{Tool, ToolContent};
use crate::mcp::registry::{ToolContext, ToolHandler};
use serde::Deserialize;

/// Delete a project
pub struct DeleteProjectTool;

#[async_trait]
impl ToolHandler for DeleteProjectTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            project_id: i32,
        }

        let args: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        let project = db::project::fetch(&context.pg_pool, args.project_id)
            .await
            .map_err(|e| format!("Project not found: {}", e))?
            .ok_or_else(|| "Project not found".to_string())?;

        if project.user_id != context.user.id {
            return Err("Unauthorized: You do not own this project".to_string());
        }

        db::project::delete(&context.pg_pool, args.project_id, &context.user.id)
            .await
            .map_err(|e| format!("Failed to delete project: {}", e))?;

        let response = serde_json::json!({
            "project_id": args.project_id,
            "message": "Project deleted successfully"
        });

        tracing::info!(
            "Deleted project {} for user {}",
            args.project_id,
            context.user.id
        );

        Ok(ToolContent::Text {
            text: response.to_string(),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "delete_project".to_string(),
            description: "Delete a project permanently".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "project_id": {
                        "type": "number",
                        "description": "Project ID to delete"
                    }
                },
                "required": ["project_id"]
            }),
        }
    }
}

/// Clone a project
pub struct CloneProjectTool;

#[async_trait]
impl ToolHandler for CloneProjectTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            project_id: i32,
            new_name: String,
        }

        let args: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        if args.new_name.trim().is_empty() {
            return Err("New project name cannot be empty".to_string());
        }

        if args.new_name.len() > 255 {
            return Err("Project name must be 255 characters or less".to_string());
        }

        let project = db::project::fetch(&context.pg_pool, args.project_id)
            .await
            .map_err(|e| format!("Project not found: {}", e))?
            .ok_or_else(|| "Project not found".to_string())?;

        if project.user_id != context.user.id {
            return Err("Unauthorized: You do not own this project".to_string());
        }

        // Create new project with cloned data
        let cloned_project = crate::models::Project::new(
            context.user.id.clone(),
            args.new_name.clone(),
            project.metadata.clone(),
            project.request_json.clone(),
        );

        let cloned_project = db::project::insert(&context.pg_pool, cloned_project)
            .await
            .map_err(|e| format!("Failed to clone project: {}", e))?;

        let response = serde_json::json!({
            "original_id": args.project_id,
            "cloned_id": cloned_project.id,
            "cloned_name": cloned_project.name,
            "message": "Project cloned successfully"
        });

        tracing::info!(
            "Cloned project {} to {} for user {}",
            args.project_id,
            cloned_project.id,
            context.user.id
        );

        Ok(ToolContent::Text {
            text: response.to_string(),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "clone_project".to_string(),
            description: "Clone/duplicate an existing project with a new name".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "project_id": {
                        "type": "number",
                        "description": "Project ID to clone"
                    },
                    "new_name": {
                        "type": "string",
                        "description": "Name for the cloned project (max 255 chars)"
                    }
                },
                "required": ["project_id", "new_name"]
            }),
        }
    }
}

/// Validate a project's stack configuration before deployment
pub struct ValidateStackConfigTool;

#[async_trait]
impl ToolHandler for ValidateStackConfigTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            project_id: i32,
        }

        let args: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        // Fetch project
        let project = db::project::fetch(&context.pg_pool, args.project_id)
            .await
            .map_err(|e| format!("Project not found: {}", e))?
            .ok_or_else(|| "Project not found".to_string())?;

        // Check ownership
        if project.user_id != context.user.id {
            return Err("Project not found".to_string());
        }

        // Fetch all apps in the project
        let apps = db::project_app::fetch_by_project(&context.pg_pool, args.project_id)
            .await
            .map_err(|e| format!("Failed to fetch project apps: {}", e))?;

        let mut errors: Vec<Value> = Vec::new();
        let mut warnings: Vec<Value> = Vec::new();
        let mut info: Vec<Value> = Vec::new();

        // Validation checks

        // 1. Check if project has any apps
        if apps.is_empty() {
            errors.push(json!({
                "code": "NO_APPS",
                "message": "Project has no applications configured. Add at least one app to deploy.",
                "severity": "error"
            }));
        }

        // 2. Check each app for required configuration
        let mut used_ports: std::collections::HashMap<u16, String> =
            std::collections::HashMap::new();
        let mut has_web_app = false;

        for app in &apps {
            let app_code = &app.code;

            // Check for image
            if app.image.is_empty() {
                errors.push(json!({
                    "code": "MISSING_IMAGE",
                    "app": app_code,
                    "message": format!("App '{}' has no Docker image configured.", app_code),
                    "severity": "error"
                }));
            }

            // Check for port conflicts
            if let Some(ports) = &app.ports {
                if let Some(ports_array) = ports.as_array() {
                    for port_config in ports_array {
                        if let Some(host_port) = port_config.get("host").and_then(|v| v.as_u64()) {
                            let host_port = host_port as u16;
                            if let Some(existing_app) = used_ports.get(&host_port) {
                                errors.push(json!({
                                    "code": "PORT_CONFLICT",
                                    "app": app_code,
                                    "port": host_port,
                                    "message": format!("Port {} is used by both '{}' and '{}'.", host_port, existing_app, app_code),
                                    "severity": "error"
                                }));
                            } else {
                                used_ports.insert(host_port, app_code.to_string());
                            }

                            // Check for common ports
                            if host_port == 80 || host_port == 443 {
                                has_web_app = true;
                            }
                        }
                    }
                }
            }

            // Check for common misconfigurations
            if let Some(env) = &app.environment {
                if let Some(env_obj) = env.as_object() {
                    // PostgreSQL specific checks
                    if app_code.contains("postgres") || app.image.contains("postgres") {
                        if !env_obj.contains_key("POSTGRES_PASSWORD")
                            && !env_obj.contains_key("POSTGRES_HOST_AUTH_METHOD")
                        {
                            warnings.push(json!({
                                "code": "MISSING_DB_PASSWORD",
                                "app": app_code,
                                "message": "PostgreSQL requires POSTGRES_PASSWORD or POSTGRES_HOST_AUTH_METHOD environment variable.",
                                "severity": "warning",
                                "suggestion": "Set POSTGRES_PASSWORD to a secure value."
                            }));
                        }
                    }

                    // MySQL/MariaDB specific checks
                    if app_code.contains("mysql") || app_code.contains("mariadb") {
                        if !env_obj.contains_key("MYSQL_ROOT_PASSWORD")
                            && !env_obj.contains_key("MYSQL_ALLOW_EMPTY_PASSWORD")
                        {
                            warnings.push(json!({
                                "code": "MISSING_DB_PASSWORD",
                                "app": app_code,
                                "message": "MySQL/MariaDB requires MYSQL_ROOT_PASSWORD environment variable.",
                                "severity": "warning",
                                "suggestion": "Set MYSQL_ROOT_PASSWORD to a secure value."
                            }));
                        }
                    }
                }
            }

            // Check for domain configuration on web apps
            if (app_code.contains("nginx")
                || app_code.contains("apache")
                || app_code.contains("traefik"))
                && app.domain.is_none()
            {
                info.push(json!({
                    "code": "NO_DOMAIN",
                    "app": app_code,
                    "message": format!("Web server '{}' has no domain configured. It will only be accessible via IP address.", app_code),
                    "severity": "info"
                }));
            }
        }

        // 3. Check for recommended practices
        if !has_web_app && !apps.is_empty() {
            info.push(json!({
                "code": "NO_WEB_PORT",
                "message": "No application is configured on port 80 or 443. The stack may not be accessible from a web browser.",
                "severity": "info"
            }));
        }

        // Build validation result
        let is_valid = errors.is_empty();
        let result = json!({
            "project_id": args.project_id,
            "project_name": project.name,
            "is_valid": is_valid,
            "apps_count": apps.len(),
            "errors": errors,
            "warnings": warnings,
            "info": info,
            "summary": {
                "error_count": errors.len(),
                "warning_count": warnings.len(),
                "info_count": info.len()
            },
            "recommendation": if is_valid {
                if warnings.is_empty() {
                    "Stack configuration looks good! Ready for deployment.".to_string()
                } else {
                    format!("Stack can be deployed but has {} warning(s) to review.", warnings.len())
                }
            } else {
                format!("Stack has {} error(s) that must be fixed before deployment.", errors.len())
            }
        });

        tracing::info!(
            user_id = %context.user.id,
            project_id = args.project_id,
            is_valid = is_valid,
            errors = errors.len(),
            warnings = warnings.len(),
            "Validated stack configuration via MCP"
        );

        Ok(ToolContent::Text {
            text: serde_json::to_string_pretty(&result).unwrap_or_else(|_| result.to_string()),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "validate_stack_config".to_string(),
            description: "Validate a project's stack configuration before deployment. Checks for missing images, port conflicts, required environment variables, and other common issues.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "project_id": {
                        "type": "number",
                        "description": "Project ID to validate"
                    }
                },
                "required": ["project_id"]
            }),
        }
    }
}

/// Discover all services from a multi-service docker-compose stack
/// Parses the compose file and creates individual project_app entries for each service
pub struct DiscoverStackServicesTool;

#[async_trait]
impl ToolHandler for DiscoverStackServicesTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            /// Project ID containing the parent app
            project_id: i32,
            /// App code of the parent stack (e.g., "komodo")
            parent_app_code: String,
            /// Compose content (YAML string). If not provided, fetches from project_app's compose
            compose_content: Option<String>,
            /// Whether to create project_app entries for discovered services
            #[serde(default)]
            create_apps: bool,
        }

        let args: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        // Verify project ownership
        let project = db::project::fetch(&context.pg_pool, args.project_id)
            .await
            .map_err(|e| format!("Project not found: {}", e))?
            .ok_or_else(|| "Project not found".to_string())?;

        if project.user_id != context.user.id {
            return Err("Unauthorized: You do not own this project".to_string());
        }

        // Get compose content - either from args or from existing project_app
        let compose_yaml = if let Some(content) = args.compose_content {
            content
        } else {
            // Fetch parent app to get its compose
            let _parent_app = db::project_app::fetch_by_project_and_code(
                &context.pg_pool,
                args.project_id,
                &args.parent_app_code,
            )
            .await
            .map_err(|e| format!("Failed to fetch parent app: {}", e))?
            .ok_or_else(|| format!("Parent app '{}' not found in project", args.parent_app_code))?;

            // Try to get compose from config_files or stored compose
            // For now, require compose_content to be provided
            return Err(
                "compose_content is required when parent app doesn't have stored compose. \
                Please provide the docker-compose.yml content."
                    .to_string(),
            );
        };

        // Parse the compose file to extract services
        let services: Vec<ExtractedService> = parse_compose_services(&compose_yaml)?;

        if services.is_empty() {
            return Ok(ToolContent::Text {
                text: json!({
                    "success": false,
                    "message": "No services found in compose file",
                    "services": []
                })
                .to_string(),
            });
        }

        let mut created_apps: Vec<Value> = Vec::new();
        let mut discovered_services: Vec<Value> = Vec::new();

        for svc in &services {
            let service_info = json!({
                "name": svc.name,
                "image": svc.image,
                "ports": svc.ports,
                "volumes": svc.volumes,
                "networks": svc.networks,
                "depends_on": svc.depends_on,
                "environment_count": svc.environment.len(),
                "has_healthcheck": svc.healthcheck.is_some(),
                "has_command": svc.command.is_some(),
                "has_entrypoint": svc.entrypoint.is_some(),
                "labels_count": svc.labels.len(),
            });
            discovered_services.push(service_info);

            // Create project_app entries if requested
            if args.create_apps {
                // Generate unique code: parent_code-service_name
                let app_code = format!("{}-{}", args.parent_app_code, svc.name);

                // Check if already exists
                let existing = db::project_app::fetch_by_project_and_code(
                    &context.pg_pool,
                    args.project_id,
                    &app_code,
                )
                .await
                .ok()
                .flatten();

                if existing.is_some() {
                    created_apps.push(json!({
                        "code": app_code,
                        "status": "already_exists",
                        "service": svc.name,
                    }));
                    continue;
                }

                // Create new project_app for this service
                let mut new_app = crate::models::ProjectApp::new(
                    args.project_id,
                    app_code.clone(),
                    svc.name.clone(),
                    svc.image.clone().unwrap_or_else(|| "unknown".to_string()),
                );

                // Set parent reference
                new_app.parent_app_code = Some(args.parent_app_code.clone());

                // Convert environment to JSON object
                if !svc.environment.is_empty() {
                    let mut env_map = serde_json::Map::new();
                    for env_str in &svc.environment {
                        if let Some((k, v)) = env_str.split_once('=') {
                            env_map.insert(k.to_string(), json!(v));
                        }
                    }
                    new_app.environment = Some(json!(env_map));
                }

                // Convert ports to JSON array
                if !svc.ports.is_empty() {
                    new_app.ports = Some(json!(svc.ports));
                }

                // Convert volumes to JSON array
                if !svc.volumes.is_empty() {
                    new_app.volumes = Some(json!(svc.volumes));
                }

                // Set networks
                if !svc.networks.is_empty() {
                    new_app.networks = Some(json!(svc.networks));
                }

                // Set depends_on
                if !svc.depends_on.is_empty() {
                    new_app.depends_on = Some(json!(svc.depends_on));
                }

                // Set command
                new_app.command = svc.command.clone();
                new_app.entrypoint = svc.entrypoint.clone();
                new_app.restart_policy = svc.restart.clone();
                new_app.healthcheck = svc.healthcheck.clone();

                // Convert labels to JSON
                if !svc.labels.is_empty() {
                    let labels_map: serde_json::Map<String, Value> = svc
                        .labels
                        .iter()
                        .map(|(k, v)| (k.clone(), json!(v)))
                        .collect();
                    new_app.labels = Some(json!(labels_map));
                }

                // Insert into database
                match db::project_app::insert(&context.pg_pool, &new_app).await {
                    Ok(created) => {
                        created_apps.push(json!({
                            "code": app_code,
                            "id": created.id,
                            "status": "created",
                            "service": svc.name,
                            "image": svc.image,
                        }));
                    }
                    Err(e) => {
                        created_apps.push(json!({
                            "code": app_code,
                            "status": "error",
                            "error": e.to_string(),
                            "service": svc.name,
                        }));
                    }
                }
            }
        }

        let result = json!({
            "success": true,
            "project_id": args.project_id,
            "parent_app_code": args.parent_app_code,
            "services_count": services.len(),
            "discovered_services": discovered_services,
            "created_apps": if args.create_apps { Some(created_apps) } else { None },
            "message": format!(
                "Discovered {} services from compose file{}",
                services.len(),
                if args.create_apps { ", created project_app entries" } else { "" }
            )
        });

        tracing::info!(
            user_id = %context.user.id,
            project_id = args.project_id,
            parent_app = %args.parent_app_code,
            services_count = services.len(),
            create_apps = args.create_apps,
            "Discovered stack services via MCP"
        );

        Ok(ToolContent::Text {
            text: serde_json::to_string_pretty(&result).unwrap_or_else(|_| result.to_string()),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "discover_stack_services".to_string(),
            description: "Parse a docker-compose file to discover all services in a multi-service stack. \
                Can optionally create individual project_app entries for each service, linked to a parent app. \
                Use this for complex stacks like Komodo that have multiple containers (core, ferretdb, periphery).".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "project_id": {
                        "type": "number",
                        "description": "Project ID containing the stack"
                    },
                    "parent_app_code": {
                        "type": "string",
                        "description": "App code of the parent stack (e.g., 'komodo')"
                    },
                    "compose_content": {
                        "type": "string",
                        "description": "Docker-compose YAML content to parse. If not provided, attempts to fetch from parent app."
                    },
                    "create_apps": {
                        "type": "boolean",
                        "description": "If true, creates project_app entries for each discovered service with parent_app_code reference"
                    }
                },
                "required": ["project_id", "parent_app_code"]
            }),
        }
    }
}
