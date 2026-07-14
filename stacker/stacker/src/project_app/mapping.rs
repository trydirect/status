use serde_json::json;

use crate::models::ProjectApp;

/// Parse .env file content into a JSON object
/// Supports KEY=value format (standard .env) and KEY: value format (YAML-like)
/// Lines starting with # are treated as comments and ignored
fn parse_env_file_content(content: &str) -> serde_json::Value {
    let mut env_map = serde_json::Map::new();

    for line in content.lines() {
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Try KEY=value format first
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim();
            let value = value.trim();
            if !key.is_empty() {
                env_map.insert(
                    key.to_string(),
                    serde_json::Value::String(value.to_string()),
                );
            }
        }
        // Try KEY: value format (YAML-like, seen in user data)
        else if let Some((key, value)) = line.split_once(':') {
            let key = key.trim();
            let value = value.trim();
            if !key.is_empty() {
                env_map.insert(
                    key.to_string(),
                    serde_json::Value::String(value.to_string()),
                );
            }
        }
    }

    serde_json::Value::Object(env_map)
}

/// Check if a filename is a .env file
fn is_env_file(file_name: &str) -> bool {
    matches!(
        file_name,
        ".env" | "env" | ".env.local" | ".env.production" | ".env.development"
    )
}

/// Parse image from docker-compose.yml content
/// Extracts the first image found in services section
fn parse_image_from_compose(content: &str) -> Option<String> {
    // Try to parse as YAML
    if let Ok(yaml) = serde_yaml::from_str::<serde_json::Value>(content) {
        // Look for services.<service>.image
        if let Some(services) = yaml.get("services").and_then(|s| s.as_object()) {
            // Get first service that has an image
            for (_name, service) in services {
                if let Some(image) = service.get("image").and_then(|i| i.as_str()) {
                    return Some(image.to_string());
                }
            }
        }
    }

    // Fallback: regex-like line scanning for "image:"
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with("image:") {
            let value = line.trim_start_matches("image:").trim();
            // Remove quotes if present
            let value = value.trim_matches('"').trim_matches('\'');
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }

    None
}

/// Intermediate struct for mapping POST parameters to ProjectApp fields
#[derive(Debug, Default)]
pub(crate) struct ProjectAppPostArgs {
    pub(crate) name: Option<String>,
    pub(crate) image: Option<String>,
    pub(crate) environment: Option<serde_json::Value>,
    pub(crate) ports: Option<serde_json::Value>,
    pub(crate) volumes: Option<serde_json::Value>,
    pub(crate) config_files: Option<serde_json::Value>,
    pub(crate) compose_content: Option<String>,
    pub(crate) domain: Option<String>,
    pub(crate) ssl_enabled: Option<bool>,
    pub(crate) resources: Option<serde_json::Value>,
    pub(crate) restart_policy: Option<String>,
    pub(crate) command: Option<String>,
    pub(crate) entrypoint: Option<String>,
    pub(crate) networks: Option<serde_json::Value>,
    pub(crate) depends_on: Option<serde_json::Value>,
    pub(crate) healthcheck: Option<serde_json::Value>,
    pub(crate) labels: Option<serde_json::Value>,
    pub(crate) enabled: Option<bool>,
    pub(crate) deploy_order: Option<i32>,
}

impl From<&serde_json::Value> for ProjectAppPostArgs {
    fn from(params: &serde_json::Value) -> Self {
        let mut args = ProjectAppPostArgs::default();

        // Basic fields
        if let Some(name) = params.get("name").and_then(|v| v.as_str()) {
            args.name = Some(name.to_string());
        }
        if let Some(image) = params.get("image").and_then(|v| v.as_str()) {
            args.image = Some(image.to_string());
        }

        // Environment variables - check params.env first
        let env_from_params = params.get("env");
        let env_is_empty = env_from_params
            .and_then(|e| e.as_object())
            .map(|o| o.is_empty())
            .unwrap_or(true);

        // Config files - extract compose content, .env content, and store remaining files
        let mut env_from_config_file: Option<serde_json::Value> = None;
        if let Some(config_files) = params.get("config_files").and_then(|v| v.as_array()) {
            let mut non_compose_files = Vec::new();
            for file in config_files {
                let file_name = file.get("name").and_then(|n| n.as_str()).unwrap_or("");
                if super::is_compose_filename(file_name) {
                    // Extract compose content
                    if let Some(content) = file.get("content").and_then(|c| c.as_str()) {
                        args.compose_content = Some(content.to_string());
                    }
                } else if is_env_file(file_name) {
                    // Extract .env file content and parse it
                    if let Some(content) = file.get("content").and_then(|c| c.as_str()) {
                        if !content.trim().is_empty() {
                            let parsed = parse_env_file_content(content);
                            if let Some(obj) = parsed.as_object() {
                                let var_count = obj.len();
                                if var_count > 0 {
                                    env_from_config_file = Some(parsed);
                                    tracing::info!(
                                        "Parsed {} environment variables from .env config file",
                                        var_count
                                    );
                                }
                            }
                        }
                    }
                    // Still add .env to non_compose_files so it's stored in config_files
                    non_compose_files.push(file.clone());
                } else {
                    non_compose_files.push(file.clone());
                }
            }
            if !non_compose_files.is_empty() {
                args.config_files = Some(serde_json::Value::Array(non_compose_files));
            }
        }

        // If no image was provided in params, try to extract from compose content
        if args.image.is_none() {
            tracing::info!(
                "[MAPPING] No image in params, checking compose content (has_compose: {})",
                args.compose_content.is_some()
            );
            if let Some(compose) = &args.compose_content {
                tracing::debug!(
                    "[MAPPING] Compose content (first 500 chars): {}",
                    &compose[..compose.len().min(500)]
                );
                if let Some(image) = parse_image_from_compose(compose) {
                    tracing::info!("[MAPPING] Extracted image '{}' from compose content", image);
                    args.image = Some(image);
                } else {
                    tracing::warn!("[MAPPING] Could not extract image from compose content");
                }
            } else {
                tracing::warn!("[MAPPING] No compose content provided, image will be empty!");
            }
        } else {
            tracing::info!("[MAPPING] Image provided in params: {:?}", args.image);
        }

        // Merge environment: prefer params.env if non-empty, otherwise use parsed .env file
        if !env_is_empty {
            // User provided env vars via form - use those
            args.environment = env_from_params.cloned();
        } else if let Some(parsed_env) = env_from_config_file {
            // User edited .env config file - use parsed values
            args.environment = Some(parsed_env);
        }

        // Port mappings
        if let Some(ports) = params.get("ports") {
            args.ports = Some(ports.clone());
        }

        // Volume mounts (separate from config_files)
        if let Some(volumes) = params.get("volumes") {
            args.volumes = Some(volumes.clone());
        }

        // Domain and SSL
        if let Some(domain) = params.get("domain").and_then(|v| v.as_str()) {
            args.domain = Some(domain.to_string());
        }
        if let Some(ssl) = params.get("ssl_enabled").and_then(|v| v.as_bool()) {
            args.ssl_enabled = Some(ssl);
        }

        // Resources
        if let Some(resources) = params.get("resources") {
            args.resources = Some(resources.clone());
        }

        // Container settings
        if let Some(restart_policy) = params.get("restart_policy").and_then(|v| v.as_str()) {
            args.restart_policy = Some(restart_policy.to_string());
        }
        if let Some(command) = params.get("command").and_then(|v| v.as_str()) {
            args.command = Some(command.to_string());
        }
        if let Some(entrypoint) = params.get("entrypoint").and_then(|v| v.as_str()) {
            args.entrypoint = Some(entrypoint.to_string());
        }

        // Networks and dependencies
        if let Some(networks) = params.get("networks") {
            args.networks = Some(networks.clone());
        }
        if let Some(depends_on) = params.get("depends_on") {
            args.depends_on = Some(depends_on.clone());
        }

        // Healthcheck
        if let Some(healthcheck) = params.get("healthcheck") {
            args.healthcheck = Some(healthcheck.clone());
        }

        // Labels
        if let Some(labels) = params.get("labels") {
            args.labels = Some(labels.clone());
        }

        // Deployment settings
        if let Some(enabled) = params.get("enabled").and_then(|v| v.as_bool()) {
            args.enabled = Some(enabled);
        }
        if let Some(deploy_order) = params.get("deploy_order").and_then(|v| v.as_i64()) {
            args.deploy_order = Some(deploy_order as i32);
        }

        args
    }
}

/// Context for converting ProjectAppPostArgs to ProjectApp
pub(crate) struct ProjectAppContext<'a> {
    pub(crate) app_code: &'a str,
    pub(crate) project_id: i32,
}

impl ProjectAppPostArgs {
    /// Convert to ProjectApp with the given context
    pub(crate) fn into_project_app(self, ctx: ProjectAppContext<'_>) -> ProjectApp {
        let mut app = ProjectApp::default();
        app.project_id = ctx.project_id;
        app.code = ctx.app_code.to_string();
        app.name = self.name.unwrap_or_else(|| ctx.app_code.to_string());
        app.image = self.image.unwrap_or_default();
        app.environment = self.environment;
        app.ports = self.ports;
        app.volumes = self.volumes;
        app.domain = self.domain;
        app.ssl_enabled = self.ssl_enabled;
        app.resources = self.resources;
        app.restart_policy = self.restart_policy;
        app.command = self.command;
        app.entrypoint = self.entrypoint;
        app.networks = self.networks;
        app.depends_on = self.depends_on;
        app.healthcheck = self.healthcheck;
        app.labels = self.labels;
        app.enabled = self.enabled.or(Some(true));
        app.deploy_order = self.deploy_order;

        // Store non-compose config files in labels
        if let Some(config_files) = self.config_files {
            let mut labels = app.labels.clone().unwrap_or(json!({}));
            if let Some(obj) = labels.as_object_mut() {
                obj.insert("config_files".to_string(), config_files);
            }
            app.labels = Some(labels);
        }

        app
    }
}

/// Map POST parameters to ProjectApp
/// Also returns the compose_content separately for Vault storage
pub(crate) fn project_app_from_post(
    app_code: &str,
    project_id: i32,
    params: &serde_json::Value,
) -> (ProjectApp, Option<String>) {
    let args = ProjectAppPostArgs::from(params);
    let compose_content = args.compose_content.clone();

    let ctx = ProjectAppContext {
        app_code,
        project_id,
    };
    let app = args.into_project_app(ctx);

    (app, compose_content)
}

/// Merge two ProjectApp instances, preferring non-null incoming values over existing
/// This allows deploy_app with minimal params to not wipe out saved configuration
pub(crate) fn merge_project_app(existing: ProjectApp, incoming: ProjectApp) -> ProjectApp {
    ProjectApp {
        id: existing.id,
        project_id: existing.project_id,
        code: existing.code, // Keep existing code
        name: if incoming.name.is_empty() {
            existing.name
        } else {
            incoming.name
        },
        image: if incoming.image.is_empty() {
            existing.image
        } else {
            incoming.image
        },
        environment: incoming.environment.or(existing.environment),
        ports: incoming.ports.or(existing.ports),
        volumes: incoming.volumes.or(existing.volumes),
        domain: incoming.domain.or(existing.domain),
        ssl_enabled: incoming.ssl_enabled.or(existing.ssl_enabled),
        resources: incoming.resources.or(existing.resources),
        restart_policy: incoming.restart_policy.or(existing.restart_policy),
        command: incoming.command.or(existing.command),
        entrypoint: incoming.entrypoint.or(existing.entrypoint),
        networks: incoming.networks.or(existing.networks),
        depends_on: incoming.depends_on.or(existing.depends_on),
        healthcheck: incoming.healthcheck.or(existing.healthcheck),
        labels: incoming.labels.or(existing.labels),
        config_files: incoming.config_files.or(existing.config_files),
        template_source: incoming.template_source.or(existing.template_source),
        enabled: incoming.enabled.or(existing.enabled),
        deploy_order: incoming.deploy_order.or(existing.deploy_order),
        created_at: existing.created_at,
        updated_at: chrono::Utc::now(),
        config_version: existing.config_version.map(|v| v + 1).or(Some(1)),
        vault_synced_at: existing.vault_synced_at,
        vault_sync_version: existing.vault_sync_version,
        config_hash: existing.config_hash,
        parent_app_code: incoming.parent_app_code.or(existing.parent_app_code),
        deployment_id: incoming.deployment_id.or(existing.deployment_id),
    }
}
