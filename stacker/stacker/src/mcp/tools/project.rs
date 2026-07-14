use async_trait::async_trait;
use serde_json::{json, Value};

use crate::connectors::user_service::UserServiceClient;
use crate::db;
use crate::mcp::protocol::{Tool, ToolContent};
use crate::mcp::registry::{ToolContext, ToolHandler};
use crate::services::ProjectAppService;
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

fn build_project_payload(
    name: &str,
    description: Option<&str>,
    apps: &[Value],
) -> (serde_json::Value, serde_json::Value) {
    let mut stack_code = crate::models::sanitize_project_name(name);
    if stack_code.len() < 3 {
        stack_code = "app-stack".to_string();
    }

    let project_name = if name.trim().is_empty() {
        "New project".to_string()
    } else {
        name.to_string()
    };

    let network_id = Uuid::new_v4().simple().to_string()[..16].to_string();

    let metadata = json!({
        "custom": {
            "web": [],
            "feature": [],
            "service": [],
            "networks": [
                {
                    "id": network_id,
                    "ipam": null,
                    "name": "default_network",
                    "driver": null,
                    "labels": null,
                    "external": null,
                    "internal": null,
                    "attachable": null,
                    "driver_opts": null,
                    "enable_ipv6": null
                }
            ],
            "project_name": project_name,
            "project_git_url": null,
            "project_overview": description,
            "custom_stack_code": stack_code,
            "project_description": description,
            "custom_stack_category": null,
            "custom_stack_description": null,
            "custom_stack_short_description": null,
            "apps": apps
        }
    });

    let request_json = json!({
        "ssl": "letsencrypt",
        "custom": {
            "web": [],
            "code": stack_code,
            "feature": [],
            "service": [],
            "networks": [
                {
                    "id": network_id,
                    "name": "default_network"
                }
            ],
            "project_name": project_name,
            "connection_mode": "ssh",
            "project_git_url": null,
            "project_overview": description,
            "custom_stack_code": stack_code,
            "project_description": description,
            "custom_stack_category": null,
            "custom_stack_description": null,
            "custom_stack_short_description": null,
            "apps": apps
        }
    });

    (metadata, request_json)
}

/// List user's projects
pub struct ListProjectsTool;

#[async_trait]
impl ToolHandler for ListProjectsTool {
    async fn execute(&self, _args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        let projects = db::project::fetch_by_user(&context.pg_pool, &context.user.id)
            .await
            .map_err(|e| {
                tracing::error!("Failed to fetch projects: {}", e);
                format!("Database error: {}", e)
            })?;

        let result =
            serde_json::to_string(&projects).map_err(|e| format!("Serialization error: {}", e))?;

        tracing::info!(
            "Listed {} projects for user {}",
            projects.len(),
            context.user.id
        );

        Ok(ToolContent::Text { text: result })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "list_projects".to_string(),
            description: "List all projects owned by the authenticated user".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {},
                "required": []
            }),
        }
    }
}

/// Get a specific project by ID
pub struct GetProjectTool;

#[async_trait]
impl ToolHandler for GetProjectTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            id: i32,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        let project = db::project::fetch(&context.pg_pool, params.id)
            .await
            .map_err(|e| {
                tracing::error!("Failed to fetch project {}: {}", params.id, e);
                format!("Database error: {}", e)
            })?;

        let result =
            serde_json::to_string(&project).map_err(|e| format!("Serialization error: {}", e))?;

        Ok(ToolContent::Text { text: result })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "get_project".to_string(),
            description: "Get details of a specific project by ID".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "id": {
                        "type": "number",
                        "description": "Project ID"
                    }
                },
                "required": ["id"]
            }),
        }
    }
}

/// Create a new project
pub struct CreateProjectTool;

#[async_trait]
impl ToolHandler for CreateProjectTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct CreateArgs {
            name: String,
            #[serde(default)]
            description: Option<String>,
            #[serde(default)]
            apps: Vec<Value>,
        }

        let params: CreateArgs =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        if params.name.trim().is_empty() {
            return Err("Project name cannot be empty".to_string());
        }

        if params.name.len() > 255 {
            return Err("Project name too long (max 255 characters)".to_string());
        }

        let (metadata, request_json) =
            build_project_payload(&params.name, params.description.as_deref(), &params.apps);

        // Create a new Project model with normalized metadata/request payload
        let project = crate::models::Project::new(
            context.user.id.clone(),
            params.name.clone(),
            metadata,
            request_json,
        );

        let project = db::project::insert(&context.pg_pool, project)
            .await
            .map_err(|e| {
                tracing::error!("Failed to create project: {}", e);
                format!("Failed to create project: {}", e)
            })?;

        let result =
            serde_json::to_string(&project).map_err(|e| format!("Serialization error: {}", e))?;

        tracing::info!(
            "Created project {} for user {}",
            project.id,
            context.user.id
        );

        Ok(ToolContent::Text { text: result })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "create_project".to_string(),
            description: "Create a new application stack project with services and configuration"
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Project name (required, max 255 chars)"
                    },
                    "description": {
                        "type": "string",
                        "description": "Project description (optional)"
                    },
                    "apps": {
                        "type": "array",
                        "description": "List of applications/services to include",
                        "items": {
                            "type": "object",
                            "properties": {
                                "name": {
                                    "type": "string",
                                    "description": "Service name"
                                },
                                "dockerImage": {
                                    "type": "object",
                                    "properties": {
                                        "namespace": { "type": "string" },
                                        "repository": {
                                            "type": "string",
                                            "description": "Docker image repository"
                                        },
                                        "tag": { "type": "string" }
                                    },
                                    "required": ["repository"]
                                }
                            }
                        }
                    }
                },
                "required": ["name"]
            }),
        }
    }
}

/// Create or update an app in a project (custom service)
pub struct CreateProjectAppTool;

#[async_trait]
impl ToolHandler for CreateProjectAppTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            #[serde(default)]
            project_id: Option<i32>,
            #[serde(alias = "app_code")]
            code: String,
            #[serde(default)]
            image: Option<String>,
            #[serde(default)]
            name: Option<String>,
            #[serde(default, alias = "environment")]
            env: Option<Value>,
            #[serde(default)]
            ports: Option<Value>,
            #[serde(default)]
            volumes: Option<Value>,
            #[serde(default)]
            config_files: Option<Value>,
            #[serde(default)]
            domain: Option<String>,
            #[serde(default)]
            ssl_enabled: Option<bool>,
            #[serde(default)]
            resources: Option<Value>,
            #[serde(default)]
            restart_policy: Option<String>,
            #[serde(default)]
            command: Option<String>,
            #[serde(default)]
            entrypoint: Option<String>,
            #[serde(default)]
            networks: Option<Value>,
            #[serde(default)]
            depends_on: Option<Value>,
            #[serde(default)]
            healthcheck: Option<Value>,
            #[serde(default)]
            labels: Option<Value>,
            #[serde(default)]
            enabled: Option<bool>,
            #[serde(default)]
            deploy_order: Option<i32>,
            #[serde(default)]
            deployment_hash: Option<String>,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        let code = params.code.trim();
        if code.is_empty() {
            return Err("app code is required".to_string());
        }

        let project_id = if let Some(project_id) = params.project_id {
            let project = db::project::fetch(&context.pg_pool, project_id)
                .await
                .map_err(|e| format!("Database error: {}", e))?
                .ok_or_else(|| "Project not found".to_string())?;

            if project.user_id != context.user.id {
                return Err("Project not found".to_string());
            }
            project_id
        } else if let Some(ref deployment_hash) = params.deployment_hash {
            let deployment =
                db::deployment::fetch_by_deployment_hash(&context.pg_pool, deployment_hash)
                    .await
                    .map_err(|e| format!("Failed to lookup deployment: {}", e))?
                    .ok_or_else(|| "Deployment not found".to_string())?;

            if deployment.user_id != Some(context.user.id.clone()) {
                return Err("Deployment not found".to_string());
            }
            deployment.project_id
        } else {
            return Err("project_id or deployment_hash is required".to_string());
        };

        let project = db::project::fetch(&context.pg_pool, project_id)
            .await
            .map_err(|e| format!("Database error: {}", e))?
            .ok_or_else(|| "Project not found".to_string())?;

        if project.user_id != context.user.id {
            return Err("Project not found".to_string());
        }

        let mut resolved_image = params.image.unwrap_or_default().trim().to_string();
        let mut resolved_name = params.name.clone();
        let mut resolved_ports = params.ports.clone();
        let mut resolved_env = params.env.clone();
        let mut resolved_config_files = params.config_files.clone();

        // Use enriched catalog endpoint for correct Docker image + default configs
        if resolved_image.is_empty()
            || resolved_name.is_none()
            || resolved_ports.is_none()
            || resolved_env.is_none()
        {
            let client = UserServiceClient::new_public(&context.settings.user_service_url);
            let token = context.user.access_token.as_deref().unwrap_or("");

            // Try catalog endpoint first (has correct Docker image + default env/config)
            // Gracefully handle total failure — proceed with defaults if User Service is unreachable
            let catalog_app = match client.fetch_app_catalog(token, code).await {
                Ok(app) => app,
                Err(e) => {
                    tracing::warn!(
                        "Could not fetch app catalog for code={}: {}, proceeding with defaults",
                        code,
                        e
                    );
                    None
                }
            };

            if let Some(app) = catalog_app {
                if resolved_image.is_empty() {
                    if let Some(image) = app.docker_image.as_ref().filter(|s| !s.is_empty()) {
                        resolved_image = image.clone();
                    }
                }

                if resolved_name.is_none() {
                    if let Some(name) = app.name.clone() {
                        resolved_name = Some(name);
                    }
                }

                if resolved_ports.is_none() {
                    // Prefer default_ports (structured) from catalog
                    if let Some(ports) = &app.default_ports {
                        if let Some(arr) = ports.as_array() {
                            if !arr.is_empty() {
                                let port_strings: Vec<serde_json::Value> = arr
                                    .iter()
                                    .filter_map(|p| {
                                        let port = p
                                            .get("port")
                                            .and_then(|v| v.as_i64())
                                            .or_else(|| p.as_i64());
                                        port.map(|p| {
                                            serde_json::Value::String(format!("{0}:{0}", p))
                                        })
                                    })
                                    .collect();
                                if !port_strings.is_empty() {
                                    resolved_ports = Some(json!(port_strings));
                                }
                            }
                        }
                    }
                    // Fallback to default_port scalar
                    if resolved_ports.is_none() {
                        if let Some(port) = app.default_port {
                            if port > 0 {
                                resolved_ports = Some(json!([format!("{0}:{0}", port)]));
                            }
                        }
                    }
                }

                // Populate default environment from catalog if not provided by user
                if resolved_env.is_none() {
                    if let Some(env_obj) = &app.default_env {
                        if let Some(obj) = env_obj.as_object() {
                            if !obj.is_empty() {
                                // Convert { "KEY": "value" } to [{ "name": "KEY", "value": "value" }]
                                let env_arr: Vec<serde_json::Value> = obj
                                    .iter()
                                    .map(|(k, v)| {
                                        json!({
                                            "name": k,
                                            "value": v.as_str().unwrap_or("")
                                        })
                                    })
                                    .collect();
                                resolved_env = Some(json!(env_arr));
                            }
                        }
                    }
                }

                // Populate default config_files from catalog if not provided
                if resolved_config_files.is_none() {
                    if let Some(cf) = &app.default_config_files {
                        if let Some(arr) = cf.as_array() {
                            if !arr.is_empty() {
                                resolved_config_files = Some(cf.clone());
                            }
                        }
                    }
                }
            }
        }

        if resolved_image.is_empty() {
            return Err("image is required (no default found)".to_string());
        }

        let mut app = crate::models::ProjectApp::default();
        app.project_id = project_id;
        app.code = code.to_string();
        app.name = resolved_name.unwrap_or_else(|| code.to_string());
        app.image = resolved_image;
        app.environment = resolved_env;
        app.ports = resolved_ports;
        app.volumes = params.volumes.clone();
        app.domain = params.domain.clone();
        app.ssl_enabled = params.ssl_enabled;
        app.resources = params.resources.clone();
        app.restart_policy = params.restart_policy.clone();
        app.command = params.command.clone();
        app.entrypoint = params.entrypoint.clone();
        app.networks = params.networks.clone();
        app.depends_on = params.depends_on.clone();
        app.healthcheck = params.healthcheck.clone();
        app.labels = params.labels.clone();
        app.enabled = params.enabled.or(Some(true));
        app.deploy_order = params.deploy_order;

        if let Some(config_files) = resolved_config_files {
            let mut labels = app.labels.clone().unwrap_or(json!({}));
            if let Some(obj) = labels.as_object_mut() {
                obj.insert("config_files".to_string(), config_files);
            }
            app.labels = Some(labels);
        }

        let service = if params.deployment_hash.is_some() {
            ProjectAppService::new(Arc::new(context.pg_pool.clone()))
                .map_err(|e| format!("Failed to create app service: {}", e))?
        } else {
            ProjectAppService::new_without_sync(Arc::new(context.pg_pool.clone()))
                .map_err(|e| format!("Failed to create app service: {}", e))?
        };

        let deployment_hash = params.deployment_hash.unwrap_or_default();
        let created = service
            .upsert(&app, &project, &deployment_hash)
            .await
            .map_err(|e| format!("Failed to save app: {}", e))?;

        let result =
            serde_json::to_string(&created).map_err(|e| format!("Serialization error: {}", e))?;

        Ok(ToolContent::Text { text: result })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "create_project_app".to_string(),
            description:
                "Create or update a custom app/service within a project (writes to project_app)."
                    .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "project_id": { "type": "number", "description": "Project ID (optional if deployment_hash is provided)" },
                    "code": { "type": "string", "description": "App code (or app_code)" },
                    "app_code": { "type": "string", "description": "Alias for code" },
                    "name": { "type": "string", "description": "Display name" },
                    "image": { "type": "string", "description": "Docker image (optional: uses catalog default if omitted)" },
                    "env": { "type": "object", "description": "Environment variables" },
                    "ports": {
                        "type": "array",
                        "description": "Port mappings",
                        "items": { "type": "string" }
                    },
                    "volumes": {
                        "type": "array",
                        "description": "Volume mounts",
                        "items": { "type": "string" }
                    },
                    "config_files": {
                        "type": "array",
                        "description": "Additional config files",
                        "items": {
                            "type": "object",
                            "properties": {
                                "name": { "type": "string" },
                                "content": { "type": "string" },
                                "destination_path": { "type": "string" }
                            }
                        }
                    },
                    "domain": { "type": "string", "description": "Domain name" },
                    "ssl_enabled": { "type": "boolean", "description": "Enable SSL" },
                    "resources": { "type": "object", "description": "Resource limits" },
                    "restart_policy": { "type": "string", "description": "Restart policy" },
                    "command": { "type": "string", "description": "Command override" },
                    "entrypoint": { "type": "string", "description": "Entrypoint override" },
                    "networks": {
                        "type": "array",
                        "description": "Networks",
                        "items": { "type": "string" }
                    },
                    "depends_on": {
                        "type": "array",
                        "description": "Dependencies",
                        "items": { "type": "string" }
                    },
                    "healthcheck": { "type": "object", "description": "Healthcheck" },
                    "labels": { "type": "object", "description": "Container labels" },
                    "enabled": { "type": "boolean", "description": "Enable app" },
                    "deploy_order": { "type": "number", "description": "Deployment order" },
                    "deployment_hash": { "type": "string", "description": "Deployment hash (optional; required if project_id is omitted)" }
                },
                "required": ["code"]
            }),
        }
    }
}

/// List all project apps (containers) for the current user
/// Returns apps across all user's projects with their configuration
pub struct ListProjectAppsTool;

#[async_trait]
impl ToolHandler for ListProjectAppsTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            /// Optional: filter by project ID
            #[serde(default)]
            project_id: Option<i32>,
            /// Optional: filter by deployment hash
            #[serde(default)]
            deployment_hash: Option<String>,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        let mut all_apps: Vec<serde_json::Value> = Vec::new();

        // If project_id is provided, fetch apps for that project
        if let Some(project_id) = params.project_id {
            // Verify user owns this project
            let project = db::project::fetch(&context.pg_pool, project_id)
                .await
                .map_err(|e| format!("Failed to fetch project: {}", e))?
                .ok_or_else(|| "Project not found".to_string())?;

            if project.user_id != context.user.id {
                return Err("Unauthorized: You do not own this project".to_string());
            }

            let apps = db::project_app::fetch_by_project(&context.pg_pool, project_id)
                .await
                .map_err(|e| format!("Failed to fetch apps: {}", e))?;

            for app in apps {
                all_apps.push(json!({
                    "project_id": app.project_id,
                    "project_name": project.name,
                    "code": app.code,
                    "name": app.name,
                    "image": app.image,
                    "ports": app.ports,
                    "volumes": app.volumes,
                    "networks": app.networks,
                    "domain": app.domain,
                    "ssl_enabled": app.ssl_enabled,
                    "environment": app.environment,
                    "enabled": app.enabled,
                    "parent_app_code": app.parent_app_code,
                    "config_version": app.config_version,
                }));
            }
        } else if let Some(deployment_hash) = &params.deployment_hash {
            // Fetch by deployment hash
            if let Ok(Some(deployment)) =
                db::deployment::fetch_by_deployment_hash(&context.pg_pool, deployment_hash).await
            {
                let project = db::project::fetch(&context.pg_pool, deployment.project_id)
                    .await
                    .map_err(|e| format!("Failed to fetch project: {}", e))?
                    .ok_or_else(|| "Project not found".to_string())?;

                if project.user_id != context.user.id {
                    return Err("Unauthorized: You do not own this deployment".to_string());
                }

                let apps =
                    db::project_app::fetch_by_project(&context.pg_pool, deployment.project_id)
                        .await
                        .map_err(|e| format!("Failed to fetch apps: {}", e))?;

                for app in apps {
                    all_apps.push(json!({
                        "project_id": app.project_id,
                        "project_name": project.name,
                        "deployment_hash": deployment_hash,
                        "code": app.code,
                        "name": app.name,
                        "image": app.image,
                        "ports": app.ports,
                        "volumes": app.volumes,
                        "networks": app.networks,
                        "domain": app.domain,
                        "ssl_enabled": app.ssl_enabled,
                        "environment": app.environment,
                        "enabled": app.enabled,
                        "parent_app_code": app.parent_app_code,
                        "config_version": app.config_version,
                    }));
                }
            }
        } else {
            // Fetch all projects and their apps for the user
            let projects = db::project::fetch_by_user(&context.pg_pool, &context.user.id)
                .await
                .map_err(|e| format!("Failed to fetch projects: {}", e))?;

            for project in projects {
                let apps = db::project_app::fetch_by_project(&context.pg_pool, project.id)
                    .await
                    .unwrap_or_default();

                // Get deployment hash if exists
                let deployment_hash =
                    db::deployment::fetch_by_project_id(&context.pg_pool, project.id)
                        .await
                        .ok()
                        .flatten()
                        .map(|d| d.deployment_hash);

                for app in apps {
                    all_apps.push(json!({
                        "project_id": app.project_id,
                        "project_name": project.name.clone(),
                        "deployment_hash": deployment_hash,
                        "code": app.code,
                        "name": app.name,
                        "image": app.image,
                        "ports": app.ports,
                        "volumes": app.volumes,
                        "networks": app.networks,
                        "domain": app.domain,
                        "ssl_enabled": app.ssl_enabled,
                        "environment": app.environment,
                        "enabled": app.enabled,
                        "parent_app_code": app.parent_app_code,
                        "config_version": app.config_version,
                    }));
                }
            }
        }

        let result = json!({
            "apps_count": all_apps.len(),
            "apps": all_apps,
        });

        tracing::info!(
            user_id = %context.user.id,
            apps_count = all_apps.len(),
            "Listed project apps via MCP"
        );

        Ok(ToolContent::Text {
            text: serde_json::to_string_pretty(&result).unwrap_or_else(|_| result.to_string()),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "list_project_apps".to_string(),
            description: "List all app configurations (containers) for the current user. Returns apps with their ports, volumes, networks, domains, and environment variables. Can filter by project_id or deployment_hash.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "project_id": {
                        "type": "number",
                        "description": "Filter by specific project ID"
                    },
                    "deployment_hash": {
                        "type": "string",
                        "description": "Filter by deployment hash"
                    }
                },
                "required": []
            }),
        }
    }
}

/// Get detailed resource configuration (volumes, networks, ports) for a deployment
pub struct GetDeploymentResourcesTool;

#[async_trait]
impl ToolHandler for GetDeploymentResourcesTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            #[serde(default)]
            deployment_id: Option<i64>,
            #[serde(default)]
            deployment_hash: Option<String>,
            #[serde(default)]
            project_id: Option<i32>,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        // Determine project_id from various sources
        let project_id = if let Some(pid) = params.project_id {
            // Verify ownership
            let project = db::project::fetch(&context.pg_pool, pid)
                .await
                .map_err(|e| format!("Failed to fetch project: {}", e))?
                .ok_or_else(|| "Project not found".to_string())?;

            if project.user_id != context.user.id {
                return Err("Unauthorized: You do not own this project".to_string());
            }
            pid
        } else if let Some(ref hash) = params.deployment_hash {
            let deployment = db::deployment::fetch_by_deployment_hash(&context.pg_pool, hash)
                .await
                .map_err(|e| format!("Failed to lookup deployment: {}", e))?
                .ok_or_else(|| "Deployment not found".to_string())?;
            deployment.project_id
        } else if let Some(_deployment_id) = params.deployment_id {
            // Legacy: try to find project by deployment ID
            // This would need a User Service lookup - for now return error
            return Err("Please provide deployment_hash or project_id".to_string());
        } else {
            return Err(
                "Either deployment_hash, project_id, or deployment_id is required".to_string(),
            );
        };

        // Fetch all apps for this project
        let apps = db::project_app::fetch_by_project(&context.pg_pool, project_id)
            .await
            .map_err(|e| format!("Failed to fetch apps: {}", e))?;

        // Collect all resources
        let mut all_volumes: Vec<serde_json::Value> = Vec::new();
        let mut all_networks: Vec<serde_json::Value> = Vec::new();
        let mut all_ports: Vec<serde_json::Value> = Vec::new();
        let mut apps_summary: Vec<serde_json::Value> = Vec::new();

        for app in &apps {
            // Collect volumes
            if let Some(volumes) = &app.volumes {
                if let Some(vol_arr) = volumes.as_array() {
                    for vol in vol_arr {
                        all_volumes.push(json!({
                            "app_code": app.code,
                            "volume": vol,
                        }));
                    }
                }
            }

            // Collect networks
            if let Some(networks) = &app.networks {
                if let Some(net_arr) = networks.as_array() {
                    for net in net_arr {
                        all_networks.push(json!({
                            "app_code": app.code,
                            "network": net,
                        }));
                    }
                }
            }

            // Collect ports
            if let Some(ports) = &app.ports {
                if let Some(port_arr) = ports.as_array() {
                    for port in port_arr {
                        all_ports.push(json!({
                            "app_code": app.code,
                            "port": port,
                            "domain": app.domain,
                            "ssl_enabled": app.ssl_enabled,
                        }));
                    }
                }
            }

            apps_summary.push(json!({
                "code": app.code,
                "name": app.name,
                "image": app.image,
                "domain": app.domain,
                "ssl_enabled": app.ssl_enabled,
                "parent_app_code": app.parent_app_code,
                "enabled": app.enabled,
            }));
        }

        let result = json!({
            "project_id": project_id,
            "apps_count": apps.len(),
            "apps": apps_summary,
            "volumes": {
                "count": all_volumes.len(),
                "items": all_volumes,
            },
            "networks": {
                "count": all_networks.len(),
                "items": all_networks,
            },
            "ports": {
                "count": all_ports.len(),
                "items": all_ports,
            },
            "hint": "Use these app_codes for configure_proxy, get_container_logs, restart_container, etc."
        });

        tracing::info!(
            user_id = %context.user.id,
            project_id = project_id,
            apps_count = apps.len(),
            "Retrieved deployment resources via MCP"
        );

        Ok(ToolContent::Text {
            text: serde_json::to_string_pretty(&result).unwrap_or_else(|_| result.to_string()),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "get_deployment_resources".to_string(),
            description: "Get all volumes, networks, and ports configured for a deployment. Use this to discover available resources before configuring proxies or troubleshooting.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "deployment_id": {
                        "type": "number",
                        "description": "Deployment/installation ID (legacy)"
                    },
                    "deployment_hash": {
                        "type": "string",
                        "description": "Deployment hash (preferred)"
                    },
                    "project_id": {
                        "type": "number",
                        "description": "Project ID"
                    }
                },
                "required": []
            }),
        }
    }
}
