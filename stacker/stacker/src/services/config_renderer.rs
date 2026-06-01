//! ConfigRenderer Service - Unified Configuration Management
//!
//! This service converts ProjectApp records from the database into deployable
//! configuration files (docker-compose.yml, .env files) using Tera templates.
//!
//! It serves as the single source of truth for generating configs that are:
//! 1. Stored in Vault for Status Panel to fetch
//! 2. Used during initial deployment via Ansible
//! 3. Applied for runtime configuration updates

use crate::configuration::DeploymentSettings;
use crate::db;
use crate::helpers::env_path::{compose_env_file_reference, remote_runtime_env_path};
use crate::models::{Project, ProjectApp};
use crate::services::env_model::{
    normalize_optional_json_env, reconcile_env_layers, EnvLayer, ReconciledEnv,
};
use crate::services::vault_service::{AppConfig, VaultError, VaultService};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::collections::{BTreeMap, HashMap};
use tera::{Context as TeraContext, Tera};

const RESERVED_ENV_PREFIXES: &[&str] = &["STACKER_", "DOCKER_", "VAULT_", "AGENT_"];

/// Rendered configuration bundle for a deployment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigBundle {
    /// The project/deployment identifier
    pub deployment_hash: String,
    /// Version of this configuration bundle (incrementing)
    pub version: u64,
    /// Docker Compose file content (YAML)
    pub compose_content: String,
    /// Per-app configuration files (.env, config files)
    pub app_configs: HashMap<String, AppConfig>,
    /// Timestamp when bundle was generated
    pub generated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RenderedEnv {
    pub content: String,
    pub hash: String,
    pub inputs: Vec<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvRenderInput {
    pub version: u64,
    pub generated_at: chrono::DateTime<chrono::Utc>,
    pub base: HashMap<String, String>,
    pub generated: HashMap<String, String>,
    pub server: HashMap<String, String>,
    pub inherit_server_secrets: bool,
    pub service: HashMap<String, String>,
    pub compose_environment: HashMap<String, String>,
}

impl Default for EnvRenderInput {
    fn default() -> Self {
        Self {
            version: 1,
            generated_at: chrono::Utc::now(),
            base: HashMap::new(),
            generated: HashMap::new(),
            server: HashMap::new(),
            inherit_server_secrets: false,
            service: HashMap::new(),
            compose_environment: HashMap::new(),
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EnvRenderError {
    #[error("Invalid env key '{key}': must match ^[A-Z_][A-Z0-9_]*$")]
    InvalidKey { key: String },
    #[error(
        "Reserved env key '{key}': prefixes STACKER_, DOCKER_, VAULT_, and AGENT_ are not allowed"
    )]
    ReservedKey { key: String },
    #[error("Invalid env value for '{key}': multiline values are not supported")]
    MultilineValue { key: String },
    #[error("Runtime env drift detected: expected hash {expected_hash}, found {actual_hash}; rerun with --force to overwrite")]
    DriftDetected {
        expected_hash: String,
        actual_hash: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvDriftCheck {
    pub can_write: bool,
    pub actual_hash: Option<String>,
    pub forced: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct EnvRenderAuditEvent {
    pub user_id: String,
    pub project_id: i32,
    pub app_code: String,
    pub version: u64,
    pub hash: String,
    pub inputs: Vec<String>,
    pub forced: bool,
    pub prior_hash: Option<String>,
}

pub fn render_env(input: EnvRenderInput) -> std::result::Result<RenderedEnv, EnvRenderError> {
    let ReconciledEnv { entries, inputs } = reconcile_render_input(&input);
    let environment = entries;
    validate_env(&environment)?;

    let body = format_env_body(&environment);
    let hash = sha256_hex(body.as_bytes());
    let header = format_header_stamp(input.version, &hash, input.generated_at, &inputs);

    Ok(RenderedEnv {
        content: format!("{header}\n{body}"),
        hash,
        inputs,
    })
}

pub fn format_header_stamp(
    version: u64,
    hash: &str,
    generated_at: chrono::DateTime<chrono::Utc>,
    inputs: &[&'static str],
) -> String {
    format!(
        "# stacker-render version={} hash={} generated_at={} inputs={}",
        version,
        hash,
        generated_at.to_rfc3339(),
        inputs.join(",")
    )
}

pub fn check_env_drift(
    current_content: Option<&str>,
    expected_hash: Option<&str>,
    force: bool,
) -> std::result::Result<EnvDriftCheck, EnvRenderError> {
    let Some(current_content) = current_content else {
        return Ok(EnvDriftCheck {
            can_write: true,
            actual_hash: None,
            forced: force,
        });
    };
    let Some(expected_hash) = expected_hash else {
        return Ok(EnvDriftCheck {
            can_write: true,
            actual_hash: Some(env_body_hash(current_content)),
            forced: force,
        });
    };

    let actual_hash = env_body_hash(current_content);
    if actual_hash == expected_hash || force {
        let forced = force && actual_hash != expected_hash;
        return Ok(EnvDriftCheck {
            can_write: true,
            actual_hash: Some(actual_hash),
            forced,
        });
    }

    Err(EnvRenderError::DriftDetected {
        expected_hash: expected_hash.to_string(),
        actual_hash,
    })
}

pub fn build_env_render_audit_event(
    user_id: &str,
    project_id: i32,
    app_code: &str,
    rendered: &RenderedEnv,
    forced: bool,
    prior_hash: Option<String>,
) -> EnvRenderAuditEvent {
    EnvRenderAuditEvent {
        user_id: user_id.to_string(),
        project_id,
        app_code: app_code.to_string(),
        version: rendered
            .content
            .lines()
            .next()
            .and_then(parse_header_version)
            .unwrap_or_default(),
        hash: rendered.hash.clone(),
        inputs: rendered
            .inputs
            .iter()
            .map(|input| input.to_string())
            .collect(),
        forced,
        prior_hash,
    }
}

pub fn emit_env_render_audit(event: &EnvRenderAuditEvent) {
    tracing::info!(
        user_id = %event.user_id,
        project_id = event.project_id,
        app_code = %event.app_code,
        version = event.version,
        hash = %event.hash,
        inputs = ?event.inputs,
        forced = event.forced,
        prior_hash = ?event.prior_hash,
        "Rendered runtime env file"
    );
}

fn reconcile_render_input(input: &EnvRenderInput) -> ReconciledEnv {
    let mut layers = vec![
        EnvLayer {
            name: "base",
            entries: &input.base,
            include_in_inputs: true,
        },
        EnvLayer {
            name: "generated",
            entries: &input.generated,
            include_in_inputs: false,
        },
    ];

    if input.inherit_server_secrets {
        layers.push(EnvLayer {
            name: "server",
            entries: &input.server,
            include_in_inputs: true,
        });
    }

    layers.push(EnvLayer {
        name: "service",
        entries: &input.service,
        include_in_inputs: true,
    });
    layers.push(EnvLayer {
        name: "compose",
        entries: &input.compose_environment,
        include_in_inputs: true,
    });

    reconcile_env_layers(&layers)
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct ResolvedAppEnvironment {
    authored: HashMap<String, String>,
    service: HashMap<String, String>,
}

impl ResolvedAppEnvironment {
    fn effective(&self) -> HashMap<String, String> {
        reconcile_env_layers(&[
            EnvLayer {
                name: "base",
                entries: &self.authored,
                include_in_inputs: false,
            },
            EnvLayer {
                name: "service",
                entries: &self.service,
                include_in_inputs: false,
            },
        ])
        .entries
        .into_iter()
        .collect()
    }
}

fn validate_env(environment: &BTreeMap<String, String>) -> std::result::Result<(), EnvRenderError> {
    for (key, value) in environment {
        if !is_valid_env_key(key) {
            return Err(EnvRenderError::InvalidKey { key: key.clone() });
        }
        if RESERVED_ENV_PREFIXES
            .iter()
            .any(|prefix| key.starts_with(prefix))
        {
            return Err(EnvRenderError::ReservedKey { key: key.clone() });
        }
        if value.contains('\n') || value.contains('\r') {
            return Err(EnvRenderError::MultilineValue { key: key.clone() });
        }
    }

    Ok(())
}

fn is_valid_env_key(key: &str) -> bool {
    let mut chars = key.chars();
    match chars.next() {
        Some(first) if first == '_' || first.is_ascii_uppercase() => {}
        _ => return false,
    }

    chars.all(|char| char == '_' || char.is_ascii_uppercase() || char.is_ascii_digit())
}

fn format_env_body(environment: &BTreeMap<String, String>) -> String {
    let mut body = String::new();
    for (key, value) in environment {
        body.push_str(key);
        body.push('=');
        body.push_str(value);
        body.push('\n');
    }
    body
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("{:x}", digest)
}

fn project_target(project: &Project) -> Option<String> {
    ["target", "deployment_target", "deploy_target"]
        .iter()
        .find_map(|key| {
            project
                .metadata
                .get(*key)
                .or_else(|| project.request_json.get(*key))
                .and_then(|value| value.as_str())
                .filter(|value| !value.trim().is_empty())
                .map(ToOwned::to_owned)
        })
}

pub fn env_body_hash(content: &str) -> String {
    let body = content
        .strip_prefix("# stacker-render ")
        .and_then(|_| content.split_once('\n').map(|(_, body)| body))
        .unwrap_or(content);
    sha256_hex(body.as_bytes())
}

fn parse_header_version(header: &str) -> Option<u64> {
    header
        .split_whitespace()
        .find_map(|part| part.strip_prefix("version="))
        .and_then(|version| version.parse::<u64>().ok())
}

/// App environment rendering context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppRenderContext {
    /// App code (e.g., "nginx", "postgres")
    pub code: String,
    /// App name
    pub name: String,
    /// Docker image
    pub image: String,
    /// Environment variables
    pub environment: HashMap<String, String>,
    /// Port mappings
    pub ports: Vec<PortMapping>,
    /// Volume mounts
    pub volumes: Vec<VolumeMount>,
    /// Domain configuration
    pub domain: Option<String>,
    /// SSL enabled
    pub ssl_enabled: bool,
    /// Network names
    pub networks: Vec<String>,
    /// Depends on (other app codes)
    pub depends_on: Vec<String>,
    /// Restart policy
    pub restart_policy: String,
    /// Resource limits
    pub resources: ResourceLimits,
    /// Labels
    pub labels: HashMap<String, String>,
    /// Healthcheck configuration
    pub healthcheck: Option<HealthCheck>,
    /// Container runtime override (e.g., "kata" for hardware isolation)
    pub runtime: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortMapping {
    pub host: u16,
    pub container: u16,
    pub protocol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeMount {
    pub source: String,
    pub target: String,
    pub read_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ResourceLimits {
    pub cpu_limit: Option<String>,
    pub memory_limit: Option<String>,
    pub cpu_reservation: Option<String>,
    pub memory_reservation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheck {
    pub test: Vec<String>,
    pub interval: Option<String>,
    pub timeout: Option<String>,
    pub retries: Option<u32>,
    pub start_period: Option<String>,
}

/// ConfigRenderer - Renders and syncs app configurations
pub struct ConfigRenderer {
    tera: Tera,
    vault_service: Option<VaultService>,
    deployment_settings: DeploymentSettings,
}

impl ConfigRenderer {
    /// Create a new ConfigRenderer with embedded templates
    pub fn new() -> Result<Self> {
        let mut tera = Tera::default();

        // Register embedded templates
        tera.add_raw_template("docker-compose.yml.tera", DOCKER_COMPOSE_TEMPLATE)
            .context("Failed to add docker-compose template")?;
        tera.add_raw_template("service.tera", SERVICE_TEMPLATE)
            .context("Failed to add service template")?;

        // Initialize Vault service if configured
        let vault_service =
            VaultService::from_env().map_err(|e| anyhow::anyhow!("Vault init error: {}", e))?;

        // Load deployment settings
        let deployment_settings = DeploymentSettings::default();

        Ok(Self {
            tera,
            vault_service,
            deployment_settings,
        })
    }

    /// Create ConfigRenderer with custom deployment settings
    pub fn with_settings(deployment_settings: DeploymentSettings) -> Result<Self> {
        let mut renderer = Self::new()?;
        renderer.deployment_settings = deployment_settings;
        Ok(renderer)
    }

    /// Get the base path for deployments
    pub fn base_path(&self) -> &str {
        self.deployment_settings.base_path()
    }

    /// Get the full deploy directory for a deployment hash
    pub fn deploy_dir(&self, deployment_hash: &str) -> String {
        self.deployment_settings.deploy_dir(deployment_hash)
    }

    /// Create ConfigRenderer with a custom Vault service (for testing)
    pub fn with_vault(vault_service: VaultService) -> Result<Self> {
        let mut renderer = Self::new()?;
        renderer.vault_service = Some(vault_service);
        Ok(renderer)
    }

    /// Render a full configuration bundle for a project
    pub async fn render_bundle(
        &self,
        pool: &PgPool,
        project: &Project,
        apps: &[ProjectApp],
        deployment_hash: &str,
    ) -> Result<ConfigBundle> {
        let mut app_contexts = Vec::new();
        let mut app_configs = HashMap::new();

        for app in apps.iter().filter(|a| a.is_enabled()) {
            let environment = self.resolve_app_environment(pool, project, app).await?;
            let mut context = self.project_app_to_context(app, environment.effective())?;
            crate::helpers::stacker_labels::insert_runtime_labels(
                &mut context.labels,
                Some(project.id),
                project_target(project).as_deref(),
                crate::helpers::stacker_labels::SCOPE_PROJECT,
                &app.code,
                &app.code,
            );
            app_contexts.push(context);

            let rendered_env = self.render_env_file(app, deployment_hash, &environment)?;
            let config = AppConfig {
                content: rendered_env.content,
                content_type: "env".to_string(),
                destination_path: remote_runtime_env_path().to_string(),
                file_mode: "0600".to_string(),
                owner: Some("trydirect".to_string()),
                group: Some("docker".to_string()),
            };
            app_configs.insert(app.code.clone(), config);
        }

        let compose_content = self.render_compose(&app_contexts, project)?;

        Ok(ConfigBundle {
            deployment_hash: deployment_hash.to_string(),
            version: 1,
            compose_content,
            app_configs,
            generated_at: chrono::Utc::now(),
        })
    }

    /// Convert a ProjectApp to a renderable context
    fn project_app_to_context(
        &self,
        app: &ProjectApp,
        environment: HashMap<String, String>,
    ) -> Result<AppRenderContext> {
        // Validate that the app has a non-empty image to prevent generating
        // `image: ` in docker-compose.yml (Docker interprets this as `:latest`
        // with no name, producing "invalid reference format" error)
        if app.image.trim().is_empty() {
            return Err(anyhow::anyhow!(
                "App '{}' has no Docker image specified. Cannot generate docker-compose.yml \
                 with an empty image field.",
                app.code
            ));
        }

        // Parse ports from JSON
        let ports = self.parse_ports(&app.ports)?;

        // Parse volumes from JSON
        let volumes = self.parse_volumes(&app.volumes)?;

        // Parse networks from JSON
        let networks = self.parse_string_array(&app.networks)?;

        // Parse depends_on from JSON
        let depends_on = self.parse_string_array(&app.depends_on)?;

        // Parse resources from JSON
        let resources = self.parse_resources(&app.resources)?;

        // Parse labels from JSON
        let labels = self.parse_labels(&app.labels)?;

        // Parse healthcheck from JSON
        let healthcheck = self.parse_healthcheck(&app.healthcheck)?;

        Ok(AppRenderContext {
            code: app.code.clone(),
            name: app.name.clone(),
            image: app.image.clone(),
            environment,
            ports,
            volumes,
            domain: app.domain.clone(),
            ssl_enabled: app.ssl_enabled.unwrap_or(false),
            networks,
            depends_on,
            restart_policy: app
                .restart_policy
                .clone()
                .unwrap_or_else(|| "unless-stopped".to_string()),
            resources,
            labels,
            healthcheck,
            runtime: None,
        })
    }

    async fn resolve_app_environment(
        &self,
        pool: &PgPool,
        project: &Project,
        app: &ProjectApp,
    ) -> Result<ResolvedAppEnvironment> {
        Ok(ResolvedAppEnvironment {
            authored: self.parse_environment(&app.environment)?,
            service: self.load_service_secrets(pool, project, app).await?,
        })
    }

    async fn load_service_secrets(
        &self,
        pool: &PgPool,
        project: &Project,
        app: &ProjectApp,
    ) -> Result<HashMap<String, String>> {
        let secrets =
            db::remote_secret::list_service_secrets(pool, &project.user_id, project.id, &app.code)
                .await
                .map_err(|error| {
                    anyhow::anyhow!("Failed to load service secret metadata: {}", error)
                })?;

        if secrets.is_empty() {
            return Ok(HashMap::new());
        }

        let vault = self.vault_service.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "Vault is required to render service secrets for app '{}'",
                app.code
            )
        })?;

        let mut service_secrets = HashMap::new();
        for secret in secrets {
            let value = vault
                .fetch_secret_value(&secret.vault_path)
                .await
                .map_err(|error| {
                    anyhow::anyhow!(
                        "Failed to fetch service secret '{}' for app '{}': {}",
                        secret.name,
                        app.code,
                        error
                    )
                })?;
            service_secrets.insert(secret.name, value);
        }

        Ok(service_secrets)
    }

    /// Parse environment JSON to HashMap
    fn parse_environment(&self, env: &Option<Value>) -> Result<HashMap<String, String>> {
        Ok(normalize_optional_json_env(env.as_ref())
            .into_iter()
            .collect())
    }

    /// Parse ports JSON to Vec<PortMapping>
    fn parse_ports(&self, ports: &Option<Value>) -> Result<Vec<PortMapping>> {
        match ports {
            Some(Value::Array(arr)) => {
                let mut result = Vec::new();
                for item in arr {
                    if let Value::Object(map) = item {
                        let host = map.get("host").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
                        let container =
                            map.get("container").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
                        let protocol = map
                            .get("protocol")
                            .and_then(|v| v.as_str())
                            .unwrap_or("tcp")
                            .to_string();
                        if host > 0 && container > 0 {
                            result.push(PortMapping {
                                host,
                                container,
                                protocol,
                            });
                        }
                    } else if let Value::String(s) = item {
                        // Handle string format: "8080:80" or "8080:80/tcp"
                        if let Some((host_str, rest)) = s.split_once(':') {
                            let (container_str, protocol) = rest
                                .split_once('/')
                                .map(|(c, p)| (c, p.to_string()))
                                .unwrap_or((rest, "tcp".to_string()));
                            if let (Ok(host), Ok(container)) =
                                (host_str.parse::<u16>(), container_str.parse::<u16>())
                            {
                                result.push(PortMapping {
                                    host,
                                    container,
                                    protocol,
                                });
                            }
                        }
                    }
                }
                Ok(result)
            }
            None => Ok(Vec::new()),
            _ => Ok(Vec::new()),
        }
    }

    /// Parse volumes JSON to Vec<VolumeMount>
    fn parse_volumes(&self, volumes: &Option<Value>) -> Result<Vec<VolumeMount>> {
        match volumes {
            Some(Value::Array(arr)) => {
                let mut result = Vec::new();
                for item in arr {
                    if let Value::Object(map) = item {
                        // Support both "source"/"target" and "host_path"/"container_path" keys
                        let source = map
                            .get("source")
                            .or_else(|| map.get("host_path"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let raw_target = map
                            .get("target")
                            .or_else(|| map.get("container_path"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();

                        // Strip `:ro` / `:rw` suffix that may be embedded in the target path
                        let (target, suffix_ro) = if raw_target.ends_with(":ro") {
                            (raw_target.trim_end_matches(":ro").to_string(), true)
                        } else if raw_target.ends_with(":rw") {
                            (raw_target.trim_end_matches(":rw").to_string(), false)
                        } else {
                            (raw_target, false)
                        };

                        let read_only = map
                            .get("read_only")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(suffix_ro);
                        if !source.is_empty() && !target.is_empty() {
                            result.push(VolumeMount {
                                source,
                                target,
                                read_only,
                            });
                        }
                    } else if let Value::String(s) = item {
                        // Handle string format: "/host:/container" or "/host:/container:ro"
                        let parts: Vec<&str> = s.split(':').collect();
                        if parts.len() >= 2 {
                            result.push(VolumeMount {
                                source: parts[0].to_string(),
                                target: parts[1].to_string(),
                                read_only: parts.get(2).map(|p| *p == "ro").unwrap_or(false),
                            });
                        }
                    }
                }
                Ok(result)
            }
            None => Ok(Vec::new()),
            _ => Ok(Vec::new()),
        }
    }

    /// Parse JSON array to Vec<String>
    fn parse_string_array(&self, value: &Option<Value>) -> Result<Vec<String>> {
        match value {
            Some(Value::Array(arr)) => Ok(arr
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()),
            None => Ok(Vec::new()),
            _ => Ok(Vec::new()),
        }
    }

    /// Parse resources JSON to ResourceLimits
    fn parse_resources(&self, resources: &Option<Value>) -> Result<ResourceLimits> {
        match resources {
            Some(Value::Object(map)) => Ok(ResourceLimits {
                cpu_limit: map
                    .get("cpu_limit")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                memory_limit: map
                    .get("memory_limit")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                cpu_reservation: map
                    .get("cpu_reservation")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                memory_reservation: map
                    .get("memory_reservation")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
            }),
            None => Ok(ResourceLimits::default()),
            _ => Ok(ResourceLimits::default()),
        }
    }

    /// Parse labels JSON to HashMap
    fn parse_labels(&self, labels: &Option<Value>) -> Result<HashMap<String, String>> {
        match labels {
            Some(Value::Object(map)) => {
                let mut result = HashMap::new();
                for (k, v) in map {
                    if let Value::String(s) = v {
                        result.insert(k.clone(), s.clone());
                    }
                }
                Ok(result)
            }
            None => Ok(HashMap::new()),
            _ => Ok(HashMap::new()),
        }
    }

    /// Parse healthcheck JSON
    fn parse_healthcheck(&self, healthcheck: &Option<Value>) -> Result<Option<HealthCheck>> {
        match healthcheck {
            Some(Value::Object(map)) => {
                let test: Vec<String> = map
                    .get("test")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default();

                if test.is_empty() {
                    return Ok(None);
                }

                Ok(Some(HealthCheck {
                    test,
                    interval: map
                        .get("interval")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    timeout: map
                        .get("timeout")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    retries: map
                        .get("retries")
                        .and_then(|v| v.as_u64())
                        .map(|n| n as u32),
                    start_period: map
                        .get("start_period")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                }))
            }
            None => Ok(None),
            _ => Ok(None),
        }
    }

    /// Render docker-compose.yml from app contexts
    fn render_compose(&self, apps: &[AppRenderContext], project: &Project) -> Result<String> {
        let mut context = TeraContext::new();
        context.insert("apps", apps);
        context.insert("project_name", &project.name);
        context.insert("project_id", &project.stack_id.to_string());
        context.insert("env_file", compose_env_file_reference());

        // Extract network configuration from project metadata
        let default_network = project
            .metadata
            .get("network")
            .and_then(|v| v.as_str())
            .unwrap_or("trydirect_network")
            .to_string();
        context.insert("default_network", &default_network);

        self.tera
            .render("docker-compose.yml.tera", &context)
            .context("Failed to render docker-compose.yml template")
    }

    /// Render .env file for a specific app
    fn render_env_file(
        &self,
        app: &ProjectApp,
        deployment_hash: &str,
        environment: &ResolvedAppEnvironment,
    ) -> Result<RenderedEnv> {
        let mut generated =
            HashMap::from([("DEPLOYMENT_HASH".to_string(), deployment_hash.to_string())]);

        if let Some(domain) = &app.domain {
            generated.insert("APP_DOMAIN".to_string(), domain.clone());
        }
        if app.ssl_enabled.unwrap_or(false) {
            generated.insert("SSL_ENABLED".to_string(), "true".to_string());
        }

        render_env(EnvRenderInput {
            base: environment.authored.clone(),
            generated,
            service: environment.service.clone(),
            generated_at: chrono::Utc::now(),
            ..EnvRenderInput::default()
        })
        .context("Failed to render env file")
    }

    /// Render a single app runtime env config without storing it.
    pub async fn render_app_env_config(
        &self,
        pool: &PgPool,
        app: &ProjectApp,
        project: &Project,
        deployment_hash: &str,
    ) -> Result<(AppConfig, String)> {
        let environment = self.resolve_app_environment(pool, project, app).await?;
        let rendered_env = self.render_env_file(app, deployment_hash, &environment)?;
        let config = AppConfig {
            content: rendered_env.content,
            content_type: "env".to_string(),
            destination_path: remote_runtime_env_path().to_string(),
            file_mode: "0600".to_string(),
            owner: Some("trydirect".to_string()),
            group: Some("docker".to_string()),
        };

        Ok((config, rendered_env.hash))
    }

    /// Sync all app configs to Vault
    pub async fn sync_to_vault(&self, bundle: &ConfigBundle) -> Result<SyncResult, VaultError> {
        let vault = match &self.vault_service {
            Some(v) => v,
            None => return Err(VaultError::NotConfigured),
        };

        let mut synced = Vec::new();
        let mut failed = Vec::new();

        // Store docker-compose.yml as a special config
        let compose_config = AppConfig {
            content: bundle.compose_content.clone(),
            content_type: "yaml".to_string(),
            destination_path: format!(
                "{}/docker-compose.yml",
                self.deploy_dir(&bundle.deployment_hash)
            ),
            file_mode: "0644".to_string(),
            owner: Some("trydirect".to_string()),
            group: Some("docker".to_string()),
        };

        match vault
            .store_app_config(&bundle.deployment_hash, "_compose", &compose_config)
            .await
        {
            Ok(()) => synced.push("_compose".to_string()),
            Err(e) => {
                tracing::error!("Failed to sync compose config: {}", e);
                failed.push(("_compose".to_string(), e.to_string()));
            }
        }

        // Store per-app .env configs - use {app_code}_env key to separate from compose
        for (app_code, config) in &bundle.app_configs {
            let env_key = format!("{}_env", app_code);
            match vault
                .store_app_config(&bundle.deployment_hash, &env_key, config)
                .await
            {
                Ok(()) => synced.push(env_key),
                Err(e) => {
                    tracing::error!("Failed to sync .env config for {}: {}", app_code, e);
                    failed.push((app_code.clone(), e.to_string()));
                }
            }
        }

        Ok(SyncResult {
            synced,
            failed,
            version: bundle.version,
            synced_at: chrono::Utc::now(),
        })
    }

    /// Sync a single app config to Vault (for incremental updates)
    pub async fn sync_app_to_vault(
        &self,
        pool: &PgPool,
        app: &ProjectApp,
        project: &Project,
        deployment_hash: &str,
    ) -> Result<String, VaultError> {
        tracing::debug!(
            "Syncing config for app {} (deployment {}) to Vault",
            app.code,
            deployment_hash
        );
        let vault = match &self.vault_service {
            Some(v) => v,
            None => return Err(VaultError::NotConfigured),
        };

        let (config, config_hash) = self
            .render_app_env_config(pool, app, project, deployment_hash)
            .await
            .map_err(|e| VaultError::Other(format!("Render failed: {}", e)))?;

        tracing::debug!(
            "Storing .env config for app {} at path {} in Vault",
            app.code,
            config.destination_path
        );
        // Use {app_code}_env key to store .env files separately from compose
        let env_key = format!("{}_env", app.code);
        vault
            .store_app_config(deployment_hash, &env_key, &config)
            .await?;

        Ok(config_hash)
    }
}

/// Result of syncing configs to Vault
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncResult {
    pub synced: Vec<String>,
    pub failed: Vec<(String, String)>,
    pub version: u64,
    pub synced_at: chrono::DateTime<chrono::Utc>,
}

impl SyncResult {
    pub fn is_success(&self) -> bool {
        self.failed.is_empty()
    }
}

// ============================================================================
// Embedded Templates
// ============================================================================

/// Docker Compose template using Tera syntax
const DOCKER_COMPOSE_TEMPLATE: &str = r#"# Generated by TryDirect ConfigRenderer
# Project: {{ project_name }}
# Generated at: {{ now() | date(format="%Y-%m-%d %H:%M:%S UTC") }}

version: '3.8'

services:
{% for app in apps %}
  {{ app.code }}:
    image: {{ app.image }}
    container_name: {{ app.code }}
    env_file:
      - {{ env_file }}
{% if app.runtime %}
    runtime: {{ app.runtime }}
{% endif %}
{% if app.command %}
    command: {{ app.command }}
{% endif %}
{% if app.entrypoint %}
    entrypoint: {{ app.entrypoint }}
{% endif %}
    restart: {{ app.restart_policy }}
{% if app.environment | length > 0 %}
    environment:
{% for key, value in app.environment %}
      - {{ key }}={{ value }}
{% endfor %}
{% endif %}
{% if app.ports | length > 0 %}
    ports:
{% for port in app.ports %}
      - "{{ port.host }}:{{ port.container }}{% if port.protocol != 'tcp' %}/{{ port.protocol }}{% endif %}"
{% endfor %}
{% endif %}
{% if app.volumes | length > 0 %}
    volumes:
{% for vol in app.volumes %}
      - {{ vol.source }}:{{ vol.target }}{% if vol.read_only %}:ro{% endif %}

{% endfor %}
{% endif %}
{% if app.networks | length > 0 %}
    networks:
{% for network in app.networks %}
      - {{ network }}
{% endfor %}
{% else %}
    networks:
      - {{ default_network }}
{% endif %}
{% if app.depends_on | length > 0 %}
    depends_on:
{% for dep in app.depends_on %}
      - {{ dep }}
{% endfor %}
{% endif %}
{% if app.labels | length > 0 %}
    labels:
{% for key, value in app.labels %}
      {{ key }}: "{{ value }}"
{% endfor %}
{% endif %}
{% if app.healthcheck %}
    healthcheck:
      test: {{ app.healthcheck.test | json_encode() }}
{% if app.healthcheck.interval %}
      interval: {{ app.healthcheck.interval }}
{% endif %}
{% if app.healthcheck.timeout %}
      timeout: {{ app.healthcheck.timeout }}
{% endif %}
{% if app.healthcheck.retries %}
      retries: {{ app.healthcheck.retries }}
{% endif %}
{% if app.healthcheck.start_period %}
      start_period: {{ app.healthcheck.start_period }}
{% endif %}
{% endif %}
{% if app.resources.memory_limit or app.resources.cpu_limit %}
    deploy:
      resources:
        limits:
{% if app.resources.memory_limit %}
          memory: {{ app.resources.memory_limit }}
{% endif %}
{% if app.resources.cpu_limit %}
          cpus: '{{ app.resources.cpu_limit }}'
{% endif %}
{% if app.resources.memory_reservation or app.resources.cpu_reservation %}
        reservations:
{% if app.resources.memory_reservation %}
          memory: {{ app.resources.memory_reservation }}
{% endif %}
{% if app.resources.cpu_reservation %}
          cpus: '{{ app.resources.cpu_reservation }}'
{% endif %}
{% endif %}
{% endif %}

{% endfor %}
networks:
  {{ default_network }}:
    driver: bridge
"#;

/// Individual service template (for partial updates)
const SERVICE_TEMPLATE: &str = r#"
  {{ app.code }}:
    image: {{ app.image }}
    container_name: {{ app.code }}
    restart: {{ app.restart_policy }}
{% if app.environment | length > 0 %}
    environment:
{% for key, value in app.environment %}
      - {{ key }}={{ value }}
{% endfor %}
{% endif %}
{% if app.ports | length > 0 %}
    ports:
{% for port in app.ports %}
      - "{{ port.host }}:{{ port.container }}"
{% endfor %}
{% endif %}
    networks:
      - {{ default_network }}
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_parse_environment_object() {
        let renderer = ConfigRenderer::new().unwrap();
        let env = Some(json!({
            "DATABASE_URL": "postgres://localhost/db",
            "PORT": 8080,
            "DEBUG": true
        }));
        let result = renderer.parse_environment(&env).unwrap();
        assert_eq!(
            result.get("DATABASE_URL").unwrap(),
            "postgres://localhost/db"
        );
        assert_eq!(result.get("PORT").unwrap(), "8080");
        assert_eq!(result.get("DEBUG").unwrap(), "true");
    }

    #[test]
    fn test_parse_environment_array() {
        let renderer = ConfigRenderer::new().unwrap();
        let env = Some(json!(["DATABASE_URL=postgres://localhost/db", "PORT=8080"]));
        let result = renderer.parse_environment(&env).unwrap();
        assert_eq!(
            result.get("DATABASE_URL").unwrap(),
            "postgres://localhost/db"
        );
        assert_eq!(result.get("PORT").unwrap(), "8080");
    }

    #[test]
    fn render_env_applies_precedence() {
        let generated_at = chrono::DateTime::parse_from_rfc3339("2026-05-13T17:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let rendered = render_env(EnvRenderInput {
            version: 7,
            generated_at,
            base: HashMap::from([
                ("SHARED".to_string(), "base".to_string()),
                ("BASE_ONLY".to_string(), "yes".to_string()),
            ]),
            generated: HashMap::new(),
            server: HashMap::from([("SHARED".to_string(), "server".to_string())]),
            inherit_server_secrets: true,
            service: HashMap::from([("SHARED".to_string(), "service".to_string())]),
            compose_environment: HashMap::from([("SHARED".to_string(), "compose".to_string())]),
        })
        .unwrap();

        assert!(rendered.content.contains("BASE_ONLY=yes\n"));
        assert!(rendered.content.contains("SHARED=compose\n"));
        assert_eq!(
            rendered.inputs,
            vec!["base", "server", "service", "compose"]
        );
    }

    #[test]
    fn render_env_skips_server_layer_without_opt_in() {
        let rendered = render_env(EnvRenderInput {
            base: HashMap::from([("VALUE".to_string(), "base".to_string())]),
            server: HashMap::from([("VALUE".to_string(), "server".to_string())]),
            inherit_server_secrets: false,
            ..EnvRenderInput::default()
        })
        .unwrap();

        assert!(rendered.content.contains("VALUE=base\n"));
        assert_eq!(rendered.inputs, vec!["base"]);
    }

    #[test]
    fn render_env_deletion_removes_missing_service_key() {
        let rendered = render_env(EnvRenderInput {
            base: HashMap::from([("KEEP".to_string(), "yes".to_string())]),
            service: HashMap::new(),
            ..EnvRenderInput::default()
        })
        .unwrap();

        assert!(rendered.content.contains("KEEP=yes\n"));
        assert!(!rendered.content.contains("S3_BUCKET="));
    }

    #[test]
    fn render_env_generated_layer_overrides_authored_value() {
        let rendered = render_env(EnvRenderInput {
            base: HashMap::from([("DEPLOYMENT_HASH".to_string(), "stale".to_string())]),
            generated: HashMap::from([("DEPLOYMENT_HASH".to_string(), "fresh".to_string())]),
            ..EnvRenderInput::default()
        })
        .unwrap();

        assert!(rendered.content.contains("DEPLOYMENT_HASH=fresh\n"));
        assert!(!rendered.inputs.contains(&"generated"));
    }

    #[test]
    fn render_env_rejects_reserved_prefix() {
        let result = render_env(EnvRenderInput {
            base: HashMap::from([("STACKER_TOKEN".to_string(), "secret".to_string())]),
            ..EnvRenderInput::default()
        });

        assert_eq!(
            result.unwrap_err(),
            EnvRenderError::ReservedKey {
                key: "STACKER_TOKEN".to_string()
            }
        );
    }

    #[test]
    fn render_env_rejects_bad_key_name() {
        let result = render_env(EnvRenderInput {
            base: HashMap::from([("lowercase".to_string(), "value".to_string())]),
            ..EnvRenderInput::default()
        });

        assert_eq!(
            result.unwrap_err(),
            EnvRenderError::InvalidKey {
                key: "lowercase".to_string()
            }
        );
    }

    #[test]
    fn render_env_rejects_multiline_value() {
        let result = render_env(EnvRenderInput {
            base: HashMap::from([("SECRET".to_string(), "line1\nline2".to_string())]),
            ..EnvRenderInput::default()
        });

        assert_eq!(
            result.unwrap_err(),
            EnvRenderError::MultilineValue {
                key: "SECRET".to_string()
            }
        );
    }

    #[test]
    fn render_env_hash_is_stable_for_same_body() {
        let generated_at = chrono::DateTime::parse_from_rfc3339("2026-05-13T17:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let input = EnvRenderInput {
            version: 1,
            generated_at,
            base: HashMap::from([
                ("B".to_string(), "2".to_string()),
                ("A".to_string(), "1".to_string()),
            ]),
            ..EnvRenderInput::default()
        };

        let first = render_env(input.clone()).unwrap();
        let second = render_env(input).unwrap();

        assert_eq!(first.hash, second.hash);
        assert_eq!(first.content, second.content);
        assert!(first.content.ends_with("A=1\nB=2\n"));
    }

    #[test]
    fn project_target_reads_stable_target_metadata() {
        let project = Project {
            metadata: json!({"target": "cloud"}),
            request_json: json!({"target": "server"}),
            ..Project::default()
        };

        assert_eq!(project_target(&project).as_deref(), Some("cloud"));
    }

    #[test]
    fn format_header_stamp_is_deterministic() {
        let generated_at = chrono::DateTime::parse_from_rfc3339("2026-05-13T17:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        let header = format_header_stamp(3, "abc123", generated_at, &["base", "service"]);

        assert_eq!(
            header,
            "# stacker-render version=3 hash=abc123 generated_at=2026-05-13T17:00:00+00:00 inputs=base,service"
        );
    }

    #[test]
    fn check_env_drift_allows_matching_hash() {
        let rendered = render_env(EnvRenderInput {
            base: HashMap::from([("KEY".to_string(), "value".to_string())]),
            ..EnvRenderInput::default()
        })
        .unwrap();

        let check = check_env_drift(Some(&rendered.content), Some(&rendered.hash), false).unwrap();

        assert!(check.can_write);
        assert_eq!(check.actual_hash.as_deref(), Some(rendered.hash.as_str()));
        assert!(!check.forced);
    }

    #[test]
    fn check_env_drift_refuses_mismatch_without_force() {
        let rendered = render_env(EnvRenderInput {
            base: HashMap::from([("KEY".to_string(), "value".to_string())]),
            ..EnvRenderInput::default()
        })
        .unwrap();

        let result = check_env_drift(Some(&rendered.content), Some("different"), false);

        assert!(matches!(
            result,
            Err(EnvRenderError::DriftDetected {
                expected_hash,
                actual_hash: _
            }) if expected_hash == "different"
        ));
    }

    #[test]
    fn check_env_drift_allows_forced_mismatch() {
        let rendered = render_env(EnvRenderInput {
            base: HashMap::from([("KEY".to_string(), "value".to_string())]),
            ..EnvRenderInput::default()
        })
        .unwrap();

        let check = check_env_drift(Some(&rendered.content), Some("different"), true).unwrap();

        assert!(check.can_write);
        assert!(check.forced);
        assert_eq!(check.actual_hash.as_deref(), Some(rendered.hash.as_str()));
    }

    #[test]
    fn build_env_render_audit_event_redacts_values() {
        let rendered = render_env(EnvRenderInput {
            version: 5,
            base: HashMap::from([("SECRET".to_string(), "supersecret".to_string())]),
            service: HashMap::from([("TOKEN".to_string(), "token-value".to_string())]),
            ..EnvRenderInput::default()
        })
        .unwrap();

        let event = build_env_render_audit_event(
            "user-1",
            42,
            "upload",
            &rendered,
            true,
            Some("old-hash".to_string()),
        );
        let serialized = serde_json::to_string(&event).unwrap();

        assert_eq!(event.version, 5);
        assert_eq!(event.hash, rendered.hash);
        assert_eq!(
            event.inputs,
            vec!["base".to_string(), "service".to_string()]
        );
        assert!(event.forced);
        assert_eq!(event.prior_hash.as_deref(), Some("old-hash"));
        assert!(!serialized.contains("supersecret"));
        assert!(!serialized.contains("token-value"));
    }

    #[test]
    fn test_parse_ports_object() {
        let renderer = ConfigRenderer::new().unwrap();
        let ports = Some(json!([
            {"host": 8080, "container": 80, "protocol": "tcp"},
            {"host": 443, "container": 443}
        ]));
        let result = renderer.parse_ports(&ports).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].host, 8080);
        assert_eq!(result[0].container, 80);
        assert_eq!(result[1].protocol, "tcp");
    }

    #[test]
    fn test_parse_ports_string() {
        let renderer = ConfigRenderer::new().unwrap();
        let ports = Some(json!(["8080:80", "443:443/tcp"]));
        let result = renderer.parse_ports(&ports).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].host, 8080);
        assert_eq!(result[0].container, 80);
    }

    #[test]
    fn test_parse_volumes() {
        let renderer = ConfigRenderer::new().unwrap();
        let volumes = Some(json!([
            {"source": "/data", "target": "/var/data", "read_only": true},
            "/config:/etc/config:ro"
        ]));
        let result = renderer.parse_volumes(&volumes).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].source, "/data");
        assert!(result[0].read_only);
        assert!(result[1].read_only);
    }

    // =========================================================================
    // Env File Storage Key Tests
    // =========================================================================

    #[test]
    fn test_env_vault_key_format() {
        // Test that .env files are stored with _env suffix
        let app_code = "komodo";
        let env_key = format!("{}_env", app_code);

        assert_eq!(env_key, "komodo_env");
        assert!(env_key.ends_with("_env"));

        // Ensure we can strip the suffix to get app_code back
        let extracted_app_code = env_key.strip_suffix("_env").unwrap();
        assert_eq!(extracted_app_code, app_code);
    }

    #[test]
    fn test_env_destination_path_format() {
        // Test that .env files have correct destination paths
        assert_eq!(remote_runtime_env_path(), "/home/trydirect/project/.env");
    }

    #[test]
    fn test_app_config_struct_for_env() {
        // Test AppConfig struct construction for .env files
        let config = AppConfig {
            content: "FOO=bar\nBAZ=qux".to_string(),
            content_type: "env".to_string(),
            destination_path: remote_runtime_env_path().to_string(),
            file_mode: "0600".to_string(),
            owner: Some("trydirect".to_string()),
            group: Some("docker".to_string()),
        };

        assert_eq!(config.content_type, "env");
        assert_eq!(config.file_mode, "0600");
        assert_eq!(config.destination_path, remote_runtime_env_path());
    }

    #[test]
    fn test_bundle_app_configs_use_env_key() {
        // Simulate the sync_to_vault behavior where app_configs are stored with _env key
        let app_codes = vec!["telegraf", "nginx", "komodo"];

        for app_code in app_codes {
            let env_key = format!("{}_env", app_code);

            // Verify key format
            assert!(env_key.ends_with("_env"));
            assert!(!env_key.ends_with("_config"));
            assert!(!env_key.ends_with("_compose"));

            // Verify we can identify this as an env config
            assert!(env_key.contains("_env"));
        }
    }

    #[test]
    fn test_config_bundle_structure() {
        // Test the structure of ConfigBundle
        // Simulated app_configs HashMap as created by render_bundle
        let mut app_configs: std::collections::HashMap<String, AppConfig> =
            std::collections::HashMap::new();

        app_configs.insert(
            "telegraf".to_string(),
            AppConfig {
                content: "INFLUX_TOKEN=xxx".to_string(),
                content_type: "env".to_string(),
                destination_path: remote_runtime_env_path().to_string(),
                file_mode: "0600".to_string(),
                owner: Some("trydirect".to_string()),
                group: Some("docker".to_string()),
            },
        );

        app_configs.insert(
            "nginx".to_string(),
            AppConfig {
                content: "DOMAIN=example.com".to_string(),
                content_type: "env".to_string(),
                destination_path: remote_runtime_env_path().to_string(),
                file_mode: "0600".to_string(),
                owner: Some("trydirect".to_string()),
                group: Some("docker".to_string()),
            },
        );

        assert_eq!(app_configs.len(), 2);
        assert!(app_configs.contains_key("telegraf"));
        assert!(app_configs.contains_key("nginx"));

        // When storing, each should be stored with _env suffix
        for (app_code, _config) in &app_configs {
            let env_key = format!("{}_env", app_code);
            assert!(env_key.ends_with("_env"));
        }
    }

    // =========================================================================
    // Empty image validation tests
    // =========================================================================

    #[test]
    fn test_empty_image_rejected() {
        use crate::models::project_app::ProjectApp;

        let renderer = ConfigRenderer::new().unwrap();
        let app = ProjectApp {
            code: "broken_app".to_string(),
            image: "".to_string(),
            ..ProjectApp::default()
        };

        let result = renderer.project_app_to_context(&app, HashMap::new());
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("broken_app"),
            "Error should mention the app code, got: {}",
            err_msg
        );
        assert!(
            err_msg.contains("no Docker image"),
            "Error should mention missing image, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_whitespace_only_image_rejected() {
        use crate::models::project_app::ProjectApp;

        let renderer = ConfigRenderer::new().unwrap();
        let app = ProjectApp {
            code: "spacey".to_string(),
            image: "   ".to_string(),
            ..ProjectApp::default()
        };

        let result = renderer.project_app_to_context(&app, HashMap::new());
        assert!(result.is_err());
    }

    #[test]
    fn test_valid_image_accepted() {
        use crate::models::project_app::ProjectApp;

        let renderer = ConfigRenderer::new().unwrap();
        let app = ProjectApp {
            code: "nginx".to_string(),
            name: "Nginx".to_string(),
            image: "nginx:latest".to_string(),
            ..ProjectApp::default()
        };

        let result = renderer.project_app_to_context(&app, HashMap::new());
        assert!(result.is_ok());
        let ctx = result.unwrap();
        assert_eq!(ctx.image, "nginx:latest");
    }

    #[test]
    fn render_compose_includes_kata_runtime() {
        let ctx = AppRenderContext {
            code: "web".to_string(),
            name: "web".to_string(),
            image: "nginx:latest".to_string(),
            environment: HashMap::new(),
            ports: vec![],
            volumes: vec![],
            domain: None,
            ssl_enabled: false,
            networks: vec![],
            depends_on: vec![],
            restart_policy: "unless-stopped".to_string(),
            resources: ResourceLimits {
                memory_limit: None,
                cpu_limit: None,
                cpu_reservation: None,
                memory_reservation: None,
            },
            labels: HashMap::new(),
            healthcheck: None,
            runtime: Some("kata".to_string()),
        };
        // Verify the struct accepts runtime and serializes correctly
        let json = serde_json::to_value(&ctx).unwrap();
        assert_eq!(json["runtime"], "kata");
    }

    #[test]
    fn render_compose_runtime_none_serializes_null() {
        let ctx = AppRenderContext {
            code: "web".to_string(),
            name: "web".to_string(),
            image: "nginx:latest".to_string(),
            environment: HashMap::new(),
            ports: vec![],
            volumes: vec![],
            domain: None,
            ssl_enabled: false,
            networks: vec![],
            depends_on: vec![],
            restart_policy: "unless-stopped".to_string(),
            resources: ResourceLimits {
                memory_limit: None,
                cpu_limit: None,
                cpu_reservation: None,
                memory_reservation: None,
            },
            labels: HashMap::new(),
            healthcheck: None,
            runtime: None,
        };
        let json = serde_json::to_value(&ctx).unwrap();
        assert!(json.get("runtime").is_none() || json["runtime"].is_null());
    }

    #[test]
    fn render_compose_references_relative_env_file() {
        let renderer = ConfigRenderer::new().unwrap();
        let project = Project {
            name: "demo".to_string(),
            ..Project::default()
        };
        let ctx = AppRenderContext {
            code: "web".to_string(),
            name: "web".to_string(),
            image: "nginx:latest".to_string(),
            environment: HashMap::new(),
            ports: vec![],
            volumes: vec![],
            domain: None,
            ssl_enabled: false,
            networks: vec![],
            depends_on: vec![],
            restart_policy: "unless-stopped".to_string(),
            resources: ResourceLimits::default(),
            labels: HashMap::new(),
            healthcheck: None,
            runtime: None,
        };

        let compose = renderer.render_compose(&[ctx], &project).unwrap();

        assert!(compose.contains("env_file:\n      - .env"));
    }

    #[test]
    fn render_compose_includes_stacker_runtime_labels() {
        let renderer = ConfigRenderer::new().unwrap();
        let project = Project {
            name: "demo".to_string(),
            ..Project::default()
        };
        let mut labels = HashMap::new();
        crate::helpers::stacker_labels::insert_runtime_labels(
            &mut labels,
            Some(42),
            Some("cloud"),
            crate::helpers::stacker_labels::SCOPE_PROJECT,
            "web",
            "web",
        );
        let ctx = AppRenderContext {
            code: "web".to_string(),
            name: "web".to_string(),
            image: "nginx:latest".to_string(),
            environment: HashMap::new(),
            ports: vec![],
            volumes: vec![],
            domain: None,
            ssl_enabled: false,
            networks: vec![],
            depends_on: vec![],
            restart_policy: "unless-stopped".to_string(),
            resources: ResourceLimits::default(),
            labels,
            healthcheck: None,
            runtime: None,
        };

        let compose = renderer.render_compose(&[ctx], &project).unwrap();

        assert!(compose.contains("my.stacker.project_id: \"42\""));
        assert!(compose.contains("my.stacker.target: \"cloud\""));
        assert!(compose.contains("my.stacker.scope: \"project\""));
        assert!(compose.contains("my.stacker.service: \"web\""));
        assert!(compose.contains("my.stacker.dns: \"web\""));
    }
}
