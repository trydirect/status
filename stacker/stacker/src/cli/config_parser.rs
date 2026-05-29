use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Deserializer, Serialize};
use serde_valid::Validate;

use crate::cli::error::{CliError, Severity, ValidationIssue};

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// AppType — discoverable project types
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AppType {
    Static,
    Node,
    Python,
    Rust,
    Go,
    Php,
    Custom,
}

impl fmt::Display for AppType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Static => write!(f, "static"),
            Self::Node => write!(f, "node"),
            Self::Python => write!(f, "python"),
            Self::Rust => write!(f, "rust"),
            Self::Go => write!(f, "go"),
            Self::Php => write!(f, "php"),
            Self::Custom => write!(f, "custom"),
        }
    }
}

impl Default for AppType {
    fn default() -> Self {
        Self::Static
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// DeployTarget — where to deploy
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeployTarget {
    Local,
    Cloud,
    Server,
}

impl fmt::Display for DeployTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Local => write!(f, "local"),
            Self::Cloud => write!(f, "cloud"),
            Self::Server => write!(f, "server"),
        }
    }
}

impl Default for DeployTarget {
    fn default() -> Self {
        Self::Local
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// ProxyType — reverse proxy flavors
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProxyType {
    Nginx,
    NginxProxyManager,
    Traefik,
    None,
}

impl fmt::Display for ProxyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Nginx => write!(f, "nginx"),
            Self::NginxProxyManager => write!(f, "nginx-proxy-manager"),
            Self::Traefik => write!(f, "traefik"),
            Self::None => write!(f, "none"),
        }
    }
}

impl Default for ProxyType {
    fn default() -> Self {
        Self::None
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// SslMode — certificate handling
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SslMode {
    Auto,
    Manual,
    Off,
}

impl Default for SslMode {
    fn default() -> Self {
        Self::Off
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// AiProviderType — supported LLM providers
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AiProviderType {
    Openai,
    Anthropic,
    Ollama,
    Custom,
}

impl fmt::Display for AiProviderType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Openai => write!(f, "openai"),
            Self::Anthropic => write!(f, "anthropic"),
            Self::Ollama => write!(f, "ollama"),
            Self::Custom => write!(f, "custom"),
        }
    }
}

impl Default for AiProviderType {
    fn default() -> Self {
        Self::Openai
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// CloudProvider — supported cloud infrastructure providers
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CloudProvider {
    Hetzner,
    Digitalocean,
    Aws,
    Linode,
    Vultr,
    Contabo,
}

/// Cloud orchestration mode.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum CloudOrchestrator {
    Local,
    #[default]
    Remote,
}

impl fmt::Display for CloudProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hetzner => write!(f, "hetzner"),
            Self::Digitalocean => write!(f, "digitalocean"),
            Self::Aws => write!(f, "aws"),
            Self::Linode => write!(f, "linode"),
            Self::Vultr => write!(f, "vultr"),
            Self::Contabo => write!(f, "contabo"),
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Configuration structs — nested sections of stacker.yml
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Application source configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppSource {
    #[serde(rename = "type", default)]
    pub app_type: AppType,

    #[serde(default = "default_app_path")]
    pub path: PathBuf,

    #[serde(default)]
    pub dockerfile: Option<PathBuf>,

    #[serde(default)]
    pub image: Option<String>,

    #[serde(default)]
    pub build: Option<BuildConfig>,

    /// Explicit port mappings (e.g. `"8080:80"`).  When empty the CLI
    /// derives a default from `app_type`.
    #[serde(default)]
    pub ports: Vec<String>,

    /// Volume mounts (e.g. `"./data:/app/data"`).
    #[serde(default)]
    pub volumes: Vec<String>,

    /// Per-app environment variables.  Merged with the top-level `env:`
    /// section (app-level wins on conflict).
    #[serde(default)]
    pub environment: HashMap<String, String>,
}

fn default_app_path() -> PathBuf {
    PathBuf::from(".")
}

/// Docker build configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BuildConfig {
    #[serde(default = "default_build_context")]
    pub context: String,

    #[serde(default)]
    pub args: HashMap<String, String>,
}

fn default_build_context() -> String {
    ".".to_string()
}

/// Additional container service alongside the app.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceDefinition {
    pub name: String,
    pub image: String,

    #[serde(default)]
    pub ports: Vec<String>,

    #[serde(default)]
    pub environment: HashMap<String, String>,

    #[serde(default)]
    pub volumes: Vec<String>,

    #[serde(default)]
    pub depends_on: Vec<String>,
}

fn deserialize_services<'de, D>(deserializer: D) -> Result<Vec<ServiceDefinition>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = serde_yaml::Value::deserialize(deserializer)?;

    match value {
        serde_yaml::Value::Null => Ok(Vec::new()),
        serde_yaml::Value::Sequence(_) => {
            serde_yaml::from_value(value).map_err(serde::de::Error::custom)
        }
        serde_yaml::Value::Mapping(map) => {
            let mut services = Vec::new();

            for (key, service_value) in map {
                let service_key = key
                    .as_str()
                    .ok_or_else(|| serde::de::Error::custom("services map key must be a string"))?
                    .to_string();

                let mut service_map = match service_value {
                    serde_yaml::Value::Mapping(m) => m,
                    _ => {
                        return Err(serde::de::Error::custom(
                            "each services map item must be an object",
                        ));
                    }
                };

                let has_name = service_map.keys().any(|k| k.as_str() == Some("name"));
                if !has_name {
                    service_map.insert(
                        serde_yaml::Value::String("name".to_string()),
                        serde_yaml::Value::String(service_key),
                    );
                }

                let service: ServiceDefinition =
                    serde_yaml::from_value(serde_yaml::Value::Mapping(service_map))
                        .map_err(serde::de::Error::custom)?;
                services.push(service);
            }

            Ok(services)
        }
        _ => Err(serde::de::Error::custom(
            "services must be a sequence or map",
        )),
    }
}

/// Proxy/ingress configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProxyConfig {
    #[serde(rename = "type", default)]
    pub proxy_type: ProxyType,

    #[serde(default = "default_auto_detect")]
    pub auto_detect: bool,

    #[serde(default)]
    pub domains: Vec<DomainConfig>,

    #[serde(default)]
    pub config: Option<PathBuf>,
}

fn default_auto_detect() -> bool {
    true
}

/// Per-domain routing and SSL settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainConfig {
    pub domain: String,

    #[serde(default)]
    pub ssl: SslMode,

    pub upstream: String,
}

/// Docker registry credentials for pulling private images during deployment.
///
/// TODO: Currently these credentials are passed through on every deploy (env vars or stacker.yml).
/// In the future, store docker credentials server-side (similar to how `cloud_token` is persisted
/// in the `clouds` table) or in HashiCorp Vault, so users only need to provide them once.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RegistryConfig {
    /// Docker registry username (or from env `STACKER_DOCKER_USERNAME`).
    #[serde(default)]
    pub username: Option<String>,

    /// Docker registry password (or from env `STACKER_DOCKER_PASSWORD`).
    #[serde(default)]
    pub password: Option<String>,

    /// Docker registry server URL (default: docker.io).
    /// Use for private registries like `ghcr.io`, `registry.example.com`.
    #[serde(default)]
    pub server: Option<String>,
}

/// Per-target deployment profile in multi-target configs.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DeployProfileConfig {
    #[serde(default)]
    pub environment: Option<String>,

    #[serde(default)]
    pub compose_file: Option<PathBuf>,

    #[serde(default)]
    pub deployment_hash: Option<String>,

    #[serde(default)]
    pub cloud: Option<CloudConfig>,

    #[serde(default)]
    pub server: Option<ServerConfig>,

    #[serde(default)]
    pub registry: Option<RegistryConfig>,
}

impl DeployProfileConfig {
    fn inferred_target(&self, profile_name: &str) -> Result<DeployTarget, CliError> {
        match (self.server.is_some(), self.cloud.is_some()) {
            (true, true) => Err(CliError::ConfigValidation(format!(
                "deploy.targets.{profile_name} cannot define both 'server' and 'cloud'"
            ))),
            (true, false) => Ok(DeployTarget::Server),
            (false, true) => Ok(DeployTarget::Cloud),
            (false, false) => Ok(DeployTarget::Local),
        }
    }
}

/// Deployment target configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DeployConfig {
    #[serde(default)]
    pub target: DeployTarget,

    #[serde(default)]
    pub environment: Option<String>,

    #[serde(default)]
    pub compose_file: Option<PathBuf>,

    #[serde(default)]
    pub deployment_hash: Option<String>,

    #[serde(default)]
    pub cloud: Option<CloudConfig>,

    #[serde(default)]
    pub server: Option<ServerConfig>,

    /// Docker registry credentials for pulling private images.
    #[serde(default)]
    pub registry: Option<RegistryConfig>,

    /// Default named target when `deploy.targets` is used.
    #[serde(default)]
    pub default_target: Option<String>,

    /// Named deploy profiles. When present, commands resolve one target profile
    /// to the legacy single-target shape before executing.
    #[serde(default)]
    pub targets: BTreeMap<String, DeployProfileConfig>,
}

impl DeployConfig {
    pub fn uses_named_targets(&self) -> bool {
        !self.targets.is_empty()
    }

    fn parse_legacy_target_override(value: &str) -> Result<DeployTarget, CliError> {
        let json = format!("\"{}\"", value.trim().to_lowercase());
        serde_json::from_str::<DeployTarget>(&json).map_err(|_| {
            CliError::ConfigValidation(format!(
                "Unknown deploy target '{}'. Valid targets: local, cloud, server",
                value
            ))
        })
    }

    fn resolve_named_target_name(&self, requested: Option<&str>) -> Result<String, CliError> {
        if let Some(requested_name) = requested.map(str::trim).filter(|value| !value.is_empty()) {
            if self.targets.contains_key(requested_name) {
                return Ok(requested_name.to_string());
            }

            return Err(CliError::ConfigValidation(format!(
                "Unknown deploy target profile '{}'. Available targets: {}",
                requested_name,
                self.targets.keys().cloned().collect::<Vec<_>>().join(", ")
            )));
        }

        if let Some(default_target) = self
            .default_target
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            if self.targets.contains_key(default_target) {
                return Ok(default_target.to_string());
            }

            return Err(CliError::ConfigValidation(format!(
                "deploy.default_target '{}' does not match any entry in deploy.targets",
                default_target
            )));
        }

        if self.targets.len() == 1 {
            return Ok(self
                .targets
                .keys()
                .next()
                .expect("single target must have a name")
                .clone());
        }

        Err(CliError::ConfigValidation(
            "deploy.default_target is required when deploy.targets defines multiple entries"
                .to_string(),
        ))
    }

    pub fn resolve(&self, requested: Option<&str>) -> Result<DeployConfig, CliError> {
        if !self.uses_named_targets() {
            let mut resolved = self.clone();
            if let Some(target_name) = requested.map(str::trim).filter(|value| !value.is_empty()) {
                resolved.target = Self::parse_legacy_target_override(target_name)?;
            }
            return Ok(resolved);
        }

        let profile_name = self.resolve_named_target_name(requested)?;
        let profile = self.targets.get(&profile_name).expect("target exists");
        let inferred_target = profile.inferred_target(&profile_name)?;

        Ok(DeployConfig {
            target: inferred_target,
            environment: profile
                .environment
                .clone()
                .or_else(|| self.environment.clone()),
            compose_file: profile.compose_file.clone(),
            deployment_hash: profile.deployment_hash.clone(),
            cloud: profile.cloud.clone(),
            server: profile.server.clone(),
            registry: profile.registry.clone(),
            default_target: self.default_target.clone(),
            targets: self.targets.clone(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EnvironmentConfig {
    #[serde(default)]
    pub compose_file: Option<PathBuf>,

    #[serde(default)]
    pub env_file: Option<PathBuf>,
}

/// Cloud provider settings for cloud deployments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudConfig {
    pub provider: CloudProvider,

    #[serde(default)]
    pub orchestrator: CloudOrchestrator,

    #[serde(default)]
    pub region: Option<String>,

    #[serde(default)]
    pub size: Option<String>,

    #[serde(default)]
    pub install_image: Option<String>,

    #[serde(default)]
    pub remote_payload_file: Option<PathBuf>,

    #[serde(default)]
    pub ssh_key: Option<PathBuf>,

    /// Name of saved cloud credential on the Stacker server.
    /// Used with `stacker deploy --key devops` or `deploy.cloud.key: devops` in stacker.yml.
    /// When set, the CLI looks up saved credentials by provider instead of requiring env vars.
    #[serde(default)]
    pub key: Option<String>,

    /// Name of a saved server on the Stacker server.
    /// Used with `stacker deploy --server bastion` or `deploy.cloud.server: bastion` in stacker.yml.
    /// When set, the CLI passes the server_id to the deploy form so it is reused.
    #[serde(default)]
    pub server: Option<String>,
}

/// Remote server settings for server deployments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,

    #[serde(default = "default_ssh_user")]
    pub user: String,

    #[serde(default)]
    pub ssh_key: Option<PathBuf>,

    #[serde(default = "default_ssh_port")]
    pub port: u16,
}

fn default_ssh_user() -> String {
    "root".to_string()
}

fn default_ssh_port() -> u16 {
    22
}

/// Default AI request timeout in seconds.
fn default_ai_timeout() -> u64 {
    300
}

/// AI/LLM assistant configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AiConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub provider: AiProviderType,

    #[serde(default)]
    pub model: Option<String>,

    #[serde(default)]
    pub api_key: Option<String>,

    #[serde(default)]
    pub endpoint: Option<String>,

    /// Request timeout in seconds. Default: 300 (5 minutes).
    /// Can be overridden via `STACKER_AI_TIMEOUT` env var.
    #[serde(default = "default_ai_timeout")]
    pub timeout: u64,

    #[serde(default)]
    pub tasks: Vec<String>,
}

/// Monitoring and health check configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MonitoringConfig {
    #[serde(default)]
    pub status_panel: bool,

    #[serde(default)]
    pub healthcheck: Option<HealthcheckConfig>,

    #[serde(default)]
    pub metrics: Option<MetricsConfig>,
}

/// Healthcheck settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthcheckConfig {
    #[serde(default = "default_health_endpoint")]
    pub endpoint: String,

    #[serde(default = "default_health_interval")]
    pub interval: String,
}

fn default_health_endpoint() -> String {
    "/health".to_string()
}

fn default_health_interval() -> String {
    "30s".to_string()
}

/// Metrics collection settings.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MetricsConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub telegraf: bool,
}

/// Lifecycle hook commands.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HookConfig {
    #[serde(default)]
    pub pre_build: Option<PathBuf>,

    #[serde(default)]
    pub post_deploy: Option<PathBuf>,

    #[serde(default)]
    pub on_failure: Option<PathBuf>,
}

/// Project identity metadata.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProjectConfig {
    /// Registered User Service identity used as remote deploy payload `stack_code`.
    #[serde(default)]
    pub identity: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConfigContract {
    #[serde(default)]
    pub services: BTreeMap<String, TargetConfigContract>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TargetConfigContract {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required: Vec<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub optional: Vec<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secret: Vec<String>,
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// StackerConfig — the root configuration type
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone, Serialize, Deserialize, Default, Validate)]
pub struct StackerConfig {
    #[validate(min_length = 1)]
    #[validate(max_length = 128)]
    pub name: String,

    #[serde(default)]
    pub version: Option<String>,

    #[serde(default)]
    pub organization: Option<String>,

    #[serde(default)]
    pub project: ProjectConfig,

    #[serde(default)]
    pub app: AppSource,

    #[serde(default, deserialize_with = "deserialize_services")]
    pub services: Vec<ServiceDefinition>,

    #[serde(default)]
    pub proxy: ProxyConfig,

    #[serde(default)]
    pub deploy: DeployConfig,

    #[serde(default)]
    pub environments: BTreeMap<String, EnvironmentConfig>,

    #[serde(default)]
    pub ai: AiConfig,

    #[serde(default, alias = "monitors")]
    pub monitoring: MonitoringConfig,

    #[serde(default)]
    pub hooks: HookConfig,

    #[serde(default)]
    pub env_file: Option<PathBuf>,

    #[serde(default)]
    pub env: HashMap<String, String>,

    #[serde(default)]
    pub config_contract: ConfigContract,
}

impl StackerConfig {
    /// Load config from a file path, resolving `${VAR}` environment variable
    /// references and validating the result.
    ///
    /// Use this when you need the **resolved** values (e.g. for deployment,
    /// validation, or sending to the server).  If you plan to mutate the
    /// config and write it back to disk, use [`from_file_raw`] instead so
    /// that `${VAR}` placeholders are preserved.
    pub fn from_file(path: &Path) -> Result<Self, CliError> {
        if !path.exists() {
            return Err(CliError::ConfigNotFound {
                path: path.to_path_buf(),
            });
        }

        let raw_content = std::fs::read_to_string(path)?;
        let mut parsed: serde_yaml::Value = serde_yaml::from_str(&raw_content)?;
        let env_file_vars = load_env_file_vars_from_yaml(path, &raw_content);
        resolve_env_placeholders_in_value(&mut parsed, &env_file_vars)?;
        deserialize_config_value(parsed)
    }

    /// Load config from a file path **without** resolving `${VAR}` placeholders.
    ///
    /// Use this when you need to modify the config and write it back to disk
    /// (e.g. `stacker service add`, `stacker config fix`).  The `${VAR}`
    /// references are kept as-is so they are not replaced with sensitive
    /// values when the file is serialized back.
    pub fn from_file_raw(path: &Path) -> Result<Self, CliError> {
        if !path.exists() {
            return Err(CliError::ConfigNotFound {
                path: path.to_path_buf(),
            });
        }

        let raw_content = std::fs::read_to_string(path)?;
        let parsed: serde_yaml::Value = serde_yaml::from_str(&raw_content)?;
        deserialize_config_value(parsed)
    }

    /// Load config from a YAML string (useful for tests).
    pub fn from_str(yaml: &str) -> Result<Self, CliError> {
        let mut parsed: serde_yaml::Value = serde_yaml::from_str(yaml)?;
        resolve_env_placeholders_in_value(&mut parsed, &HashMap::new())?;
        deserialize_config_value(parsed)
    }

    /// Return a cloned config with `deploy` flattened to one selected target.
    ///
    /// Legacy configs keep working as before. Multi-target configs resolve one
    /// named profile into the existing single-target fields.
    pub fn with_resolved_deploy_target(&self, requested: Option<&str>) -> Result<Self, CliError> {
        let mut config = self.clone();
        config.deploy = self.deploy.resolve(requested)?;
        Ok(config)
    }

    pub fn selected_environment(&self, override_environment: Option<&str>) -> Option<String> {
        override_environment
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .or_else(|| self.deploy.environment.clone())
    }

    pub fn resolve_environment_config(
        &self,
        override_environment: Option<&str>,
    ) -> Result<Option<(String, EnvironmentConfig)>, CliError> {
        let Some(environment) = self.selected_environment(override_environment) else {
            return Ok(None);
        };

        let configured = self.environments.get(&environment).cloned();
        let compose_file = configured
            .as_ref()
            .and_then(|config| config.compose_file.clone())
            .or_else(|| self.deploy.compose_file.clone())
            .or_else(|| Some(PathBuf::from(format!("docker/{environment}/compose.yml"))));
        let env_file = configured
            .as_ref()
            .and_then(|config| config.env_file.clone())
            .or_else(|| self.env_file.clone());

        Ok(Some((
            environment,
            EnvironmentConfig {
                compose_file,
                env_file,
            },
        )))
    }

    /// Validate cross-field semantic constraints beyond serde deserialization.
    /// Returns a list of issues (errors, warnings, info).
    pub fn validate_semantics(&self) -> Vec<ValidationIssue> {
        let mut issues = Vec::new();

        if self.deploy.uses_named_targets() {
            if self.deploy.targets.len() > 1
                && self
                    .deploy
                    .default_target
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .is_none()
            {
                issues.push(ValidationIssue {
                    severity: Severity::Error,
                    code: "E004".to_string(),
                    message: "deploy.default_target is required when deploy.targets defines multiple entries".to_string(),
                    field: Some("deploy.default_target".to_string()),
                });
            }

            if let Some(default_target) = self
                .deploy
                .default_target
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                if !self.deploy.targets.contains_key(default_target) {
                    issues.push(ValidationIssue {
                        severity: Severity::Error,
                        code: "E005".to_string(),
                        message: format!(
                            "deploy.default_target '{}' does not match any entry in deploy.targets",
                            default_target
                        ),
                        field: Some("deploy.default_target".to_string()),
                    });
                }
            }

            for (name, profile) in &self.deploy.targets {
                let field_prefix = format!("deploy.targets.{name}");
                match profile.inferred_target(name) {
                    Ok(target) => {
                        let deploy = DeployConfig {
                            target,
                            environment: profile.environment.clone(),
                            compose_file: profile.compose_file.clone(),
                            deployment_hash: profile.deployment_hash.clone(),
                            cloud: profile.cloud.clone(),
                            server: profile.server.clone(),
                            registry: profile.registry.clone(),
                            default_target: None,
                            targets: BTreeMap::new(),
                        };
                        validate_deploy_semantics(
                            &mut issues,
                            &self.project,
                            &deploy,
                            Some(field_prefix),
                        );
                    }
                    Err(_) => issues.push(ValidationIssue {
                        severity: Severity::Error,
                        code: "E006".to_string(),
                        message: format!(
                            "deploy.targets.{name} cannot define both 'server' and 'cloud'"
                        ),
                        field: Some(field_prefix),
                    }),
                }
            }
        } else {
            validate_deploy_semantics(
                &mut issues,
                &self.project,
                &self.deploy,
                Some("deploy".into()),
            );
        }

        // Custom app type with no image and no dockerfile
        if self.app.app_type == AppType::Custom
            && self.app.image.is_none()
            && self.app.dockerfile.is_none()
        {
            issues.push(ValidationIssue {
                severity: Severity::Error,
                code: "E003".to_string(),
                message: "Custom app type requires either 'image' or 'dockerfile'".to_string(),
                field: Some("app".to_string()),
            });
        }

        // Port conflict detection across services
        let mut port_map: HashMap<String, Vec<String>> = HashMap::new();
        for svc in &self.services {
            for port_str in &svc.ports {
                let host_port = extract_host_port(port_str);
                port_map
                    .entry(host_port.clone())
                    .or_default()
                    .push(svc.name.clone());
            }
        }
        for (port, services) in &port_map {
            if services.len() > 1 {
                issues.push(ValidationIssue {
                    severity: Severity::Warning,
                    code: "W001".to_string(),
                    message: format!(
                        "Port {} is used by multiple services: {}",
                        port,
                        services.join(", ")
                    ),
                    field: Some("services.ports".to_string()),
                });
            }
        }

        issues
    }
}

fn deserialize_config_value(parsed: serde_yaml::Value) -> Result<StackerConfig, CliError> {
    let rendered = serde_yaml::to_string(&parsed)?;
    let deserializer = serde_yaml::Deserializer::from_str(&rendered);

    serde_path_to_error::deserialize::<_, StackerConfig>(deserializer).map_err(|err| {
        let field_path = err.path().to_string();
        let source = err.into_inner();
        let message = format_config_parse_message(&field_path, &source);
        CliError::ConfigParseFailed {
            source: <serde_yaml::Error as serde::de::Error>::custom(message),
        }
    })
}

fn format_config_parse_message(field_path: &str, source: &serde_yaml::Error) -> String {
    let source_message = source.to_string();
    let normalized_field = if field_path.is_empty() || field_path == "." {
        None
    } else {
        Some(field_path)
    };

    if let Some(field) = normalized_field {
        if source_message.contains("expected path string") {
            let example = if field == "app.path" {
                "`.` or `./app`"
            } else {
                "`./path/to/file`"
            };

            if source_message.contains("invalid type: unit value") {
                return format!(
                    "invalid empty path at `{field}`. Remove the key or set it to a quoted path string like {example}"
                );
            }

            return format!(
                "invalid path at `{field}`. Expected a quoted path string like {example}. Original parser error: {source_message}"
            );
        }

        return format!("invalid value at `{field}`: {source_message}");
    }

    source_message
}

fn validate_deploy_semantics(
    issues: &mut Vec<ValidationIssue>,
    project: &ProjectConfig,
    deploy: &DeployConfig,
    field_prefix: Option<String>,
) {
    let field = |suffix: &str| -> String {
        match &field_prefix {
            Some(prefix) => format!("{prefix}.{suffix}"),
            None => suffix.to_string(),
        }
    };

    if deploy.target == DeployTarget::Cloud && deploy.cloud.is_none() {
        issues.push(ValidationIssue {
            severity: Severity::Error,
            code: "E001".to_string(),
            message: "Cloud provider configuration is required for cloud deployment".to_string(),
            field: Some(field("cloud.provider")),
        });
    }

    if deploy.target == DeployTarget::Server && deploy.server.is_none() {
        issues.push(ValidationIssue {
            severity: Severity::Error,
            code: "E002".to_string(),
            message: "Server host is required for server deployment".to_string(),
            field: Some(field("server.host")),
        });
    }

    if deploy.target == DeployTarget::Cloud {
        if let Some(cloud) = &deploy.cloud {
            if cloud.orchestrator == CloudOrchestrator::Remote {
                let identity_empty = project
                    .identity
                    .as_ref()
                    .map(|v| v.trim().is_empty())
                    .unwrap_or(true);

                if identity_empty {
                    issues.push(ValidationIssue {
                        severity: Severity::Info,
                        code: "I001".to_string(),
                        message: "project.identity is not set; remote deploy will use default stack_code 'custom-stack'".to_string(),
                        field: Some("project.identity".to_string()),
                    });
                }
            }
        }
    }
}

fn load_env_file_vars_from_yaml(path: &Path, raw_content: &str) -> HashMap<String, String> {
    let parsed: serde_yaml::Value = match serde_yaml::from_str(raw_content) {
        Ok(v) => v,
        Err(_) => return HashMap::new(),
    };

    let env_file_value = parsed
        .get("env_file")
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty());

    let env_file = match env_file_value {
        Some(v) => v,
        None => return HashMap::new(),
    };

    let config_dir = path.parent().unwrap_or_else(|| Path::new("."));
    let env_file_path = Path::new(env_file);
    let resolved_path = if env_file_path.is_absolute() {
        env_file_path.to_path_buf()
    } else {
        config_dir.join(env_file_path)
    };

    let content = match std::fs::read_to_string(&resolved_path) {
        Ok(c) => c,
        Err(_) => return HashMap::new(),
    };

    let mut vars = HashMap::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if let Some((key, value)) = trimmed.split_once('=') {
            let key = key.trim();
            if key.is_empty() {
                continue;
            }

            let mut value = value.trim().to_string();
            if (value.starts_with('"') && value.ends_with('"'))
                || (value.starts_with('\'') && value.ends_with('\''))
            {
                if value.len() >= 2 {
                    value = value[1..value.len() - 1].to_string();
                }
            }
            vars.insert(key.to_string(), value);
        }
    }

    vars
}

/// Extract the host port from a port mapping string like "8080:80" → "8080".
fn extract_host_port(port_str: &str) -> String {
    port_str.split(':').next().unwrap_or(port_str).to_string()
}

/// Resolve `${VAR_NAME}` references in a string using process environment.
#[allow(dead_code)]
fn resolve_env_vars(content: &str) -> Result<String, CliError> {
    resolve_env_vars_with_fallback(content, &HashMap::new())
}

fn resolve_env_placeholders_in_value(
    value: &mut serde_yaml::Value,
    fallback_vars: &HashMap<String, String>,
) -> Result<(), CliError> {
    match value {
        serde_yaml::Value::String(raw) => {
            let resolved = resolve_env_vars_with_fallback(raw, fallback_vars)?;
            *raw = resolved;
        }
        serde_yaml::Value::Sequence(items) => {
            for item in items.iter_mut() {
                resolve_env_placeholders_in_value(item, fallback_vars)?;
            }
        }
        serde_yaml::Value::Mapping(map) => {
            for (_key, map_value) in map.iter_mut() {
                resolve_env_placeholders_in_value(map_value, fallback_vars)?;
            }
        }
        _ => {}
    }

    Ok(())
}

fn resolve_env_vars_with_fallback(
    content: &str,
    fallback_vars: &HashMap<String, String>,
) -> Result<String, CliError> {
    let mut result = content.to_string();
    let re = regex::Regex::new(r"\$\{([^}]+)\}").expect("valid regex");

    // Collect all matches first to avoid borrow issues
    let captures: Vec<(String, String)> = re
        .captures_iter(content)
        .map(|cap| {
            let full_match = cap[0].to_string();
            let var_name = cap[1].to_string();
            (full_match, var_name)
        })
        .collect();

    for (full_match, var_name) in captures {
        let value =
            match std::env::var(&var_name) {
                Ok(v) => v,
                Err(_) => fallback_vars.get(&var_name).cloned().ok_or_else(|| {
                    CliError::EnvVarNotFound {
                        var_name: var_name.clone(),
                    }
                })?,
            };
        result = result.replace(&full_match, &value);
    }

    Ok(result)
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// ConfigBuilder — fluent builder for programmatic construction
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Default)]
pub struct ConfigBuilder {
    name: Option<String>,
    version: Option<String>,
    organization: Option<String>,
    project_identity: Option<String>,
    app_type: Option<AppType>,
    app_path: Option<PathBuf>,
    app_image: Option<String>,
    app_dockerfile: Option<PathBuf>,
    build_args: HashMap<String, String>,
    services: Vec<ServiceDefinition>,
    proxy: Option<ProxyConfig>,
    deploy_target: Option<DeployTarget>,
    cloud: Option<CloudConfig>,
    server: Option<ServerConfig>,
    registry: Option<RegistryConfig>,
    ai: Option<AiConfig>,
    monitoring: Option<MonitoringConfig>,
    hooks: Option<HookConfig>,
    env: HashMap<String, String>,
    env_file: Option<PathBuf>,
}

impl ConfigBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn name<S: Into<String>>(mut self, name: S) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn version<S: Into<String>>(mut self, version: S) -> Self {
        self.version = Some(version.into());
        self
    }

    pub fn organization<S: Into<String>>(mut self, org: S) -> Self {
        self.organization = Some(org.into());
        self
    }

    pub fn project_identity<S: Into<String>>(mut self, identity: S) -> Self {
        self.project_identity = Some(identity.into());
        self
    }

    pub fn app_type(mut self, app_type: AppType) -> Self {
        self.app_type = Some(app_type);
        self
    }

    pub fn app_path<P: Into<PathBuf>>(mut self, path: P) -> Self {
        self.app_path = Some(path.into());
        self
    }

    pub fn app_image<S: Into<String>>(mut self, image: S) -> Self {
        self.app_image = Some(image.into());
        self
    }

    pub fn app_dockerfile<P: Into<PathBuf>>(mut self, path: P) -> Self {
        self.app_dockerfile = Some(path.into());
        self
    }

    pub fn build_arg<K: Into<String>, V: Into<String>>(mut self, key: K, value: V) -> Self {
        self.build_args.insert(key.into(), value.into());
        self
    }

    pub fn add_service(mut self, service: ServiceDefinition) -> Self {
        self.services.push(service);
        self
    }

    pub fn proxy(mut self, proxy: ProxyConfig) -> Self {
        self.proxy = Some(proxy);
        self
    }

    pub fn deploy_target(mut self, target: DeployTarget) -> Self {
        self.deploy_target = Some(target);
        self
    }

    pub fn cloud(mut self, cloud: CloudConfig) -> Self {
        self.cloud = Some(cloud);
        self
    }

    pub fn server(mut self, server: ServerConfig) -> Self {
        self.server = Some(server);
        self
    }

    pub fn registry(mut self, registry: RegistryConfig) -> Self {
        self.registry = Some(registry);
        self
    }

    pub fn ai(mut self, ai: AiConfig) -> Self {
        self.ai = Some(ai);
        self
    }

    pub fn monitoring(mut self, monitoring: MonitoringConfig) -> Self {
        self.monitoring = Some(monitoring);
        self
    }

    pub fn hooks(mut self, hooks: HookConfig) -> Self {
        self.hooks = Some(hooks);
        self
    }

    pub fn env<K: Into<String>, V: Into<String>>(mut self, key: K, value: V) -> Self {
        self.env.insert(key.into(), value.into());
        self
    }

    pub fn env_file<P: Into<PathBuf>>(mut self, path: P) -> Self {
        self.env_file = Some(path.into());
        self
    }

    /// Consume the builder, validate required fields, and produce StackerConfig.
    pub fn build(self) -> Result<StackerConfig, CliError> {
        let name = self
            .name
            .ok_or_else(|| CliError::ConfigValidation("name is required".into()))?;

        let build_config = if self.build_args.is_empty() {
            None
        } else {
            Some(BuildConfig {
                context: ".".to_string(),
                args: self.build_args,
            })
        };

        Ok(StackerConfig {
            name,
            version: self.version,
            organization: self.organization,
            project: ProjectConfig {
                identity: self.project_identity,
            },
            app: AppSource {
                app_type: self.app_type.unwrap_or_default(),
                path: self.app_path.unwrap_or_else(|| PathBuf::from(".")),
                dockerfile: self.app_dockerfile,
                image: self.app_image,
                build: build_config,
                ports: Vec::new(),
                volumes: Vec::new(),
                environment: HashMap::new(),
            },
            services: self.services,
            proxy: self.proxy.unwrap_or_default(),
            deploy: DeployConfig {
                target: self.deploy_target.unwrap_or_default(),
                environment: None,
                compose_file: None,
                deployment_hash: None,
                cloud: self.cloud,
                server: self.server,
                registry: self.registry,
                default_target: None,
                targets: BTreeMap::new(),
            },
            environments: BTreeMap::new(),
            ai: self.ai.unwrap_or_default(),
            monitoring: self.monitoring.unwrap_or_default(),
            hooks: self.hooks.unwrap_or_default(),
            env_file: self.env_file,
            env: self.env,
            config_contract: ConfigContract::default(),
        })
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Tests — Phase 1: Config parser + builder
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_parse_minimal_config() {
        let yaml = r#"
name: my-site
app:
  type: static
  path: ./public
"#;
        let config = StackerConfig::from_str(yaml).unwrap();
        assert_eq!(config.name, "my-site");
        assert_eq!(config.app.app_type, AppType::Static);
        assert_eq!(config.app.path, PathBuf::from("./public"));
        assert!(config.services.is_empty());
        assert_eq!(config.proxy.proxy_type, ProxyType::None);
        assert_eq!(config.deploy.target, DeployTarget::Local);
        assert!(!config.ai.enabled);
        assert!(!config.monitoring.status_panel);
    }

    #[test]
    fn test_parse_full_config() {
        let yaml = r#"
name: full-app
version: "2.0"
organization: test-org
app:
  type: node
  path: ./src
  build:
    context: .
    args:
      NODE_ENV: production
services:
  - name: postgres
    image: postgres:16
    ports: ["5432:5432"]
    environment:
      POSTGRES_DB: testdb
  - name: redis
    image: redis:7-alpine
    ports: ["6379:6379"]
proxy:
  type: nginx
  domains:
    - domain: test.example.com
      ssl: auto
      upstream: app:3000
deploy:
  target: local
ai:
  enabled: true
  provider: ollama
  model: llama3
  endpoint: http://localhost:11434
  tasks: [dockerfile, troubleshoot]
monitoring:
  status_panel: true
  healthcheck:
    endpoint: /health
    interval: 30s
env:
  APP_PORT: "3000"
  LOG_LEVEL: debug
"#;
        let config = StackerConfig::from_str(yaml).unwrap();
        assert_eq!(config.name, "full-app");
        assert_eq!(config.version, Some("2.0".to_string()));
        assert_eq!(config.organization, Some("test-org".to_string()));
        assert_eq!(config.app.app_type, AppType::Node);
        assert_eq!(config.services.len(), 2);
        assert_eq!(config.services[0].name, "postgres");
        assert_eq!(config.services[1].name, "redis");
        assert_eq!(config.proxy.proxy_type, ProxyType::Nginx);
        assert_eq!(config.proxy.domains.len(), 1);
        assert_eq!(config.proxy.domains[0].domain, "test.example.com");
        assert_eq!(config.proxy.domains[0].ssl, SslMode::Auto);
        assert!(config.ai.enabled);
        assert_eq!(config.ai.provider, AiProviderType::Ollama);
        assert!(config.monitoring.status_panel);
        assert_eq!(config.env.get("APP_PORT").unwrap(), "3000");
    }

    #[test]
    fn test_parse_multi_target_config_and_resolve_default() {
        let yaml = r#"
name: multi-target-app
app:
  type: static
deploy:
  default_target: dev-server
  targets:
    local:
      compose_file: docker/local/compose.yml
    dev-server:
      server:
        host: 10.0.0.8
        user: deploy
        ssh_key: ~/.ssh/id_ed25519
"#;

        let config = StackerConfig::from_str(yaml).unwrap();
        assert!(config.deploy.uses_named_targets());
        assert_eq!(config.deploy.targets.len(), 2);

        let resolved = config.with_resolved_deploy_target(None).unwrap();
        assert_eq!(resolved.deploy.target, DeployTarget::Server);
        assert!(resolved.deploy.environment.is_none());
        assert_eq!(
            resolved
                .deploy
                .server
                .as_ref()
                .map(|server| server.host.as_str()),
            Some("10.0.0.8")
        );
    }

    #[test]
    fn test_resolve_named_target_override() {
        let yaml = r#"
name: multi-target-app
app:
  type: static
deploy:
  default_target: local
  targets:
    local:
      compose_file: docker/local/compose.yml
    prod:
      cloud:
        provider: aws
"#;

        let config = StackerConfig::from_str(yaml).unwrap();
        let resolved = config.with_resolved_deploy_target(Some("prod")).unwrap();

        assert_eq!(resolved.deploy.target, DeployTarget::Cloud);
        assert_eq!(
            resolved.deploy.cloud.as_ref().map(|cloud| cloud.provider),
            Some(CloudProvider::Aws)
        );
        assert!(resolved.deploy.compose_file.is_none());
    }

    #[test]
    fn test_parse_environment_config_and_default_selection() {
        let yaml = r#"
name: environment-app
app:
  type: static
deploy:
  target: cloud
  environment: production
environments:
  production:
    compose_file: docker/production/compose.yml
    env_file: docker/production/.env
"#;

        let config = StackerConfig::from_str(yaml).unwrap();
        assert_eq!(config.deploy.environment.as_deref(), Some("production"));
        assert_eq!(
            config
                .environments
                .get("production")
                .and_then(|environment| environment.compose_file.as_ref()),
            Some(&PathBuf::from("docker/production/compose.yml"))
        );

        let (environment, environment_config) = config
            .resolve_environment_config(None)
            .unwrap()
            .expect("environment should resolve");
        assert_eq!(environment, "production");
        assert_eq!(
            environment_config.compose_file,
            Some(PathBuf::from("docker/production/compose.yml"))
        );
        assert_eq!(
            environment_config.env_file,
            Some(PathBuf::from("docker/production/.env"))
        );
    }

    #[test]
    fn test_environment_override_uses_conventional_compose_path() {
        let yaml = r#"
name: environment-app
app:
  type: static
deploy:
  target: cloud
"#;

        let config = StackerConfig::from_str(yaml).unwrap();
        let (environment, environment_config) = config
            .resolve_environment_config(Some("staging"))
            .unwrap()
            .expect("environment should resolve");

        assert_eq!(environment, "staging");
        assert_eq!(
            environment_config.compose_file,
            Some(PathBuf::from("docker/staging/compose.yml"))
        );
    }

    #[test]
    fn test_monitors_alias_for_monitoring() {
        let yaml = r#"
name: monitors-alias-test
monitors:
  status_panel: true
  healthcheck:
    endpoint: /healthz
    interval: 10s
"#;
        let config = StackerConfig::from_str(yaml).unwrap();
        assert!(config.monitoring.status_panel);
        assert!(config.monitoring.healthcheck.is_some());
        let hc = config.monitoring.healthcheck.unwrap();
        assert_eq!(hc.endpoint, "/healthz");
        assert_eq!(hc.interval, "10s");
    }

    #[test]
    fn test_parse_env_var_interpolation() {
        env::set_var("STACKER_TEST_DB_PASS", "secret123");
        let yaml = r#"
name: env-test
app:
  type: static
env:
  DB_PASSWORD: ${STACKER_TEST_DB_PASS}
"#;
        let config = StackerConfig::from_str(yaml).unwrap();
        assert_eq!(config.env.get("DB_PASSWORD").unwrap(), "secret123");
        env::remove_var("STACKER_TEST_DB_PASS");
    }

    #[test]
    fn test_parse_env_var_missing_returns_error() {
        // Ensure the var definitely doesn't exist
        env::remove_var("STACKER_TEST_NONEXISTENT_VAR_12345");
        let yaml = r#"
name: env-test
env:
  KEY: ${STACKER_TEST_NONEXISTENT_VAR_12345}
"#;
        let result = StackerConfig::from_str(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("STACKER_TEST_NONEXISTENT_VAR_12345"),
            "Expected var name in error: {msg}"
        );
    }

    #[test]
    fn test_from_str_ignores_env_placeholders_in_comments() {
        let yaml = r#"
name: comment-test
app:
  type: static
# DATABASE_URL: postgres://user:${STACKER_TEST_NONEXISTENT_VAR_54321}@db:5432/app
"#;

        let config = StackerConfig::from_str(yaml).unwrap();
        assert_eq!(config.name, "comment-test");
        assert_eq!(config.app.app_type, AppType::Static);
    }

    #[test]
    fn test_from_file_resolves_env_from_env_file() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(".env"), "DOCKER_IMAGE=node:14-alpine\n").unwrap();

        let yaml = r#"
name: env-file-test
env_file: .env
app:
    type: custom
    path: .
    image: ${DOCKER_IMAGE}
deploy:
    target: local
"#;
        let config_path = dir.path().join("stacker.yml");
        fs::write(&config_path, yaml).unwrap();

        let config = StackerConfig::from_file(&config_path).unwrap();
        assert_eq!(config.app.image.as_deref(), Some("node:14-alpine"));
    }

    #[test]
    fn test_parse_invalid_app_type_returns_error() {
        let yaml = r#"
name: bad-type
app:
  type: cobol
"#;
        let result = StackerConfig::from_str(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_missing_name_returns_error() {
        let yaml = r#"
app:
  type: static
"#;
        // name is a required field — serde fails deserialization if missing
        let result = StackerConfig::from_str(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_services_array() {
        let yaml = r#"
name: svc-test
services:
  - name: postgres
    image: postgres:16
    ports: ["5432:5432"]
  - name: redis
    image: redis:7-alpine
  - name: minio
    image: minio/minio
    ports: ["9000:9000", "9001:9001"]
"#;
        let config = StackerConfig::from_str(yaml).unwrap();
        assert_eq!(config.services.len(), 3);
        assert_eq!(config.services[0].name, "postgres");
        assert_eq!(config.services[0].image, "postgres:16");
        assert_eq!(config.services[0].ports, vec!["5432:5432"]);
        assert_eq!(config.services[2].name, "minio");
        assert_eq!(config.services[2].ports.len(), 2);
    }

    #[test]
    fn test_parse_services_map() {
        let yaml = r#"
name: svc-map-test
services:
    web:
        name: web
        image: nginx:alpine
        ports: ["8080:80"]
    redis:
        name: redis
        image: redis:7-alpine
"#;

        let config = StackerConfig::from_str(yaml).unwrap();
        assert_eq!(config.services.len(), 2);
        assert!(config
            .services
            .iter()
            .any(|s| s.name == "web" && s.image == "nginx:alpine"));
        assert!(config
            .services
            .iter()
            .any(|s| s.name == "redis" && s.image == "redis:7-alpine"));
    }

    #[test]
    fn test_parse_services_map_infers_name_from_key() {
        let yaml = r#"
name: svc-map-key-test
services:
    web:
        image: nginx:alpine
        ports: ["8080:80"]
"#;

        let config = StackerConfig::from_str(yaml).unwrap();
        assert_eq!(config.services.len(), 1);
        assert_eq!(config.services[0].name, "web");
        assert_eq!(config.services[0].image, "nginx:alpine");
    }

    #[test]
    fn test_parse_proxy_domains() {
        let yaml = r#"
name: proxy-test
proxy:
  type: nginx
  domains:
    - domain: app.example.com
      ssl: auto
      upstream: app:3000
    - domain: api.example.com
      ssl: off
      upstream: app:8080
"#;
        let config = StackerConfig::from_str(yaml).unwrap();
        assert_eq!(config.proxy.proxy_type, ProxyType::Nginx);
        assert_eq!(config.proxy.domains.len(), 2);
        assert_eq!(config.proxy.domains[0].ssl, SslMode::Auto);
        assert_eq!(config.proxy.domains[0].upstream, "app:3000");
        assert_eq!(config.proxy.domains[1].ssl, SslMode::Off);
    }

    #[test]
    fn test_parse_ai_section_with_ollama() {
        let yaml = r#"
name: ai-test
ai:
  enabled: true
  provider: ollama
  model: llama3
  endpoint: http://localhost:11434
  tasks: [dockerfile, compose]
"#;
        let config = StackerConfig::from_str(yaml).unwrap();
        assert!(config.ai.enabled);
        assert_eq!(config.ai.provider, AiProviderType::Ollama);
        assert_eq!(config.ai.model, Some("llama3".to_string()));
        assert_eq!(
            config.ai.endpoint,
            Some("http://localhost:11434".to_string())
        );
        assert_eq!(config.ai.tasks, vec!["dockerfile", "compose"]);
    }

    #[test]
    fn test_default_deploy_target_is_local() {
        let yaml = "name: minimal\n";
        let config = StackerConfig::from_str(yaml).unwrap();
        assert_eq!(config.deploy.target, DeployTarget::Local);
    }

    #[test]
    fn test_default_proxy_type_is_none() {
        let yaml = "name: minimal\n";
        let config = StackerConfig::from_str(yaml).unwrap();
        assert_eq!(config.proxy.proxy_type, ProxyType::None);
    }

    #[test]
    fn test_config_file_not_found() {
        let result = StackerConfig::from_file(Path::new("/nonexistent/stacker.yml"));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, CliError::ConfigNotFound { .. }),
            "Expected ConfigNotFound, got: {err:?}"
        );
    }

    #[test]
    fn test_config_invalid_yaml_syntax() {
        let result = StackerConfig::from_str("{{invalid: yaml: :::");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, CliError::ConfigParseFailed { .. }),
            "Expected ConfigParseFailed, got: {err:?}"
        );
    }

    #[test]
    fn test_config_invalid_path_reports_field_name() {
        let yaml = r#"
name: bad-path
app:
  type: custom
  path: {}
"#;
        let err = StackerConfig::from_str(yaml).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("app.path"), "unexpected message: {msg}");
        assert!(
            msg.contains("quoted path string"),
            "unexpected message: {msg}"
        );
    }

    #[test]
    fn test_validate_semantics_cloud_without_provider() {
        let config = ConfigBuilder::new()
            .name("test")
            .deploy_target(DeployTarget::Cloud)
            .build()
            .unwrap();

        let issues = config.validate_semantics();
        let errors: Vec<_> = issues
            .iter()
            .filter(|i| i.severity == Severity::Error)
            .collect();
        assert!(
            !errors.is_empty(),
            "Expected validation error for missing cloud provider"
        );
        assert!(
            errors
                .iter()
                .any(|e| e.field.as_deref() == Some("deploy.cloud.provider")),
            "Expected field reference to deploy.cloud.provider"
        );
    }

    #[test]
    fn test_validate_semantics_server_without_host() {
        let config = ConfigBuilder::new()
            .name("test")
            .deploy_target(DeployTarget::Server)
            .build()
            .unwrap();

        let issues = config.validate_semantics();
        let errors: Vec<_> = issues
            .iter()
            .filter(|i| i.severity == Severity::Error)
            .collect();
        assert!(
            !errors.is_empty(),
            "Expected validation error for missing server host"
        );
        assert!(
            errors.iter().any(|e| e.message.contains("host")),
            "Expected 'host' mentioned in error"
        );
    }

    #[test]
    fn test_validate_semantics_port_conflict() {
        let config = StackerConfig::from_str(
            r#"
name: port-conflict
services:
  - name: web1
    image: nginx
    ports: ["8080:80"]
  - name: web2
    image: httpd
    ports: ["8080:80"]
"#,
        )
        .unwrap();

        let issues = config.validate_semantics();
        let warnings: Vec<_> = issues
            .iter()
            .filter(|i| i.severity == Severity::Warning)
            .collect();
        assert!(!warnings.is_empty(), "Expected warning about port conflict");
        assert!(
            warnings.iter().any(|w| w.message.contains("8080")),
            "Expected port 8080 in warning"
        );
    }

    #[test]
    fn test_validate_semantics_no_image_no_dockerfile_custom() {
        let config = ConfigBuilder::new()
            .name("test")
            .app_type(AppType::Custom)
            .build()
            .unwrap();

        let issues = config.validate_semantics();
        let errors: Vec<_> = issues
            .iter()
            .filter(|i| i.severity == Severity::Error)
            .collect();
        assert!(
            !errors.is_empty(),
            "Expected error for custom type without image or dockerfile"
        );
    }

    #[test]
    fn test_validate_semantics_happy_path() {
        let config = ConfigBuilder::new()
            .name("valid-app")
            .app_type(AppType::Static)
            .build()
            .unwrap();

        let issues = config.validate_semantics();
        let errors: Vec<_> = issues
            .iter()
            .filter(|i| i.severity == Severity::Error)
            .collect();
        assert!(errors.is_empty(), "Expected no errors, got: {errors:?}");
    }

    #[test]
    fn test_validate_semantics_multi_target_requires_default_for_multiple_profiles() {
        let config = StackerConfig::from_str(
            r#"
name: multi-target-app
app:
  type: static
deploy:
  targets:
    local:
      compose_file: docker/local/compose.yml
    prod:
      server:
        host: 10.0.0.8
        user: deploy
        ssh_key: ~/.ssh/id_ed25519
"#,
        )
        .unwrap();

        let issues = config.validate_semantics();
        assert!(issues.iter().any(|issue| issue.code == "E004"));
    }

    #[test]
    fn test_validate_semantics_multi_target_rejects_ambiguous_profile() {
        let config = StackerConfig::from_str(
            r#"
name: multi-target-app
app:
  type: static
deploy:
  default_target: hybrid
  targets:
    hybrid:
      cloud:
        provider: aws
      server:
        host: 10.0.0.8
        user: deploy
        ssh_key: ~/.ssh/id_ed25519
"#,
        )
        .unwrap();

        let issues = config.validate_semantics();
        assert!(issues.iter().any(|issue| issue.code == "E006"));
    }

    #[test]
    fn test_validate_semantics_remote_cloud_defaults_stack_code_without_project_identity() {
        let config = ConfigBuilder::new()
            .name("remote-app")
            .deploy_target(DeployTarget::Cloud)
            .cloud(CloudConfig {
                provider: CloudProvider::Hetzner,
                orchestrator: CloudOrchestrator::Remote,
                region: Some("nbg1".to_string()),
                size: Some("cpx11".to_string()),
                install_image: None,
                remote_payload_file: None,
                ssh_key: None,
                key: None,
                server: None,
            })
            .build()
            .unwrap();

        let issues = config.validate_semantics();
        let errors: Vec<_> = issues
            .iter()
            .filter(|i| i.severity == Severity::Error)
            .collect();
        let infos: Vec<_> = issues
            .iter()
            .filter(|i| i.severity == Severity::Info)
            .collect();
        assert!(
            errors.is_empty(),
            "Expected no blocking errors, got: {errors:?}"
        );
        assert!(
            infos
                .iter()
                .any(|e| e.field.as_deref() == Some("project.identity")),
            "Expected project.identity informational hint"
        );
    }

    // ━━━ ConfigBuilder tests ━━━

    #[test]
    fn test_config_builder_minimal() {
        let config = ConfigBuilder::new().name("test").build().unwrap();
        assert_eq!(config.name, "test");
        assert_eq!(config.app.app_type, AppType::Static);
        assert_eq!(config.app.path, PathBuf::from("."));
        assert_eq!(config.deploy.target, DeployTarget::Local);
        assert_eq!(config.project.identity, None);
    }

    #[test]
    fn test_config_builder_project_identity() {
        let config = ConfigBuilder::new()
            .name("test")
            .project_identity("registered-stack-code")
            .build()
            .unwrap();
        assert_eq!(
            config.project.identity.as_deref(),
            Some("registered-stack-code")
        );
    }

    #[test]
    fn test_config_builder_fluent_chain() {
        let config = ConfigBuilder::new()
            .name("my-app")
            .version("1.0")
            .organization("acme")
            .app_type(AppType::Node)
            .app_path("./src")
            .add_service(ServiceDefinition {
                name: "postgres".to_string(),
                image: "postgres:16".to_string(),
                ports: vec!["5432:5432".to_string()],
                environment: HashMap::new(),
                volumes: vec![],
                depends_on: vec![],
            })
            .deploy_target(DeployTarget::Cloud)
            .cloud(CloudConfig {
                provider: CloudProvider::Hetzner,
                orchestrator: CloudOrchestrator::Local,
                region: Some("fsn1".to_string()),
                size: Some("cpx21".to_string()),
                install_image: None,
                remote_payload_file: None,
                ssh_key: None,
                key: None,
                server: None,
            })
            .build()
            .unwrap();

        assert_eq!(config.name, "my-app");
        assert_eq!(config.version, Some("1.0".to_string()));
        assert_eq!(config.organization, Some("acme".to_string()));
        assert_eq!(config.app.app_type, AppType::Node);
        assert_eq!(config.app.path, PathBuf::from("./src"));
        assert_eq!(config.services.len(), 1);
        assert_eq!(config.deploy.target, DeployTarget::Cloud);
        assert!(config.deploy.cloud.is_some());
    }

    #[test]
    fn test_config_builder_missing_name_returns_error() {
        let result = ConfigBuilder::new().app_type(AppType::Static).build();
        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("name"), "Expected 'name' in error: {msg}");
    }

    #[test]
    fn test_config_builder_default_app_type_is_static() {
        let config = ConfigBuilder::new().name("x").build().unwrap();
        assert_eq!(config.app.app_type, AppType::Static);
    }

    #[test]
    fn test_config_builder_to_yaml_roundtrip() {
        let original = ConfigBuilder::new()
            .name("roundtrip")
            .app_type(AppType::Python)
            .app_path("./app")
            .env("PORT", "8000")
            .build()
            .unwrap();

        let yaml = serde_yaml::to_string(&original).unwrap();
        let parsed = StackerConfig::from_str(&yaml).unwrap();

        assert_eq!(original.name, parsed.name);
        assert_eq!(original.app.app_type, parsed.app.app_type);
        assert_eq!(original.app.path, parsed.app.path);
        assert_eq!(original.env.get("PORT"), parsed.env.get("PORT"));
    }

    #[test]
    fn test_config_builder_multiple_services() {
        let config = ConfigBuilder::new()
            .name("multi")
            .add_service(ServiceDefinition {
                name: "pg".to_string(),
                image: "postgres:16".to_string(),
                ports: vec![],
                environment: HashMap::new(),
                volumes: vec![],
                depends_on: vec![],
            })
            .add_service(ServiceDefinition {
                name: "redis".to_string(),
                image: "redis:7".to_string(),
                ports: vec![],
                environment: HashMap::new(),
                volumes: vec![],
                depends_on: vec![],
            })
            .add_service(ServiceDefinition {
                name: "minio".to_string(),
                image: "minio/minio".to_string(),
                ports: vec![],
                environment: HashMap::new(),
                volumes: vec![],
                depends_on: vec![],
            })
            .build()
            .unwrap();

        assert_eq!(config.services.len(), 3);
    }

    // ━━━ Enum tests ━━━

    #[test]
    fn test_app_type_display() {
        assert_eq!(format!("{}", AppType::Static), "static");
        assert_eq!(format!("{}", AppType::Node), "node");
        assert_eq!(format!("{}", AppType::Python), "python");
        assert_eq!(format!("{}", AppType::Rust), "rust");
        assert_eq!(format!("{}", AppType::Go), "go");
        assert_eq!(format!("{}", AppType::Php), "php");
        assert_eq!(format!("{}", AppType::Custom), "custom");
    }

    #[test]
    fn test_app_type_serde_roundtrip() {
        let json = serde_json::to_string(&AppType::Node).unwrap();
        assert_eq!(json, "\"node\"");
        let parsed: AppType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, AppType::Node);
    }

    #[test]
    fn test_app_type_default_is_static() {
        assert_eq!(AppType::default(), AppType::Static);
    }

    #[test]
    fn test_deploy_target_display() {
        assert_eq!(format!("{}", DeployTarget::Local), "local");
        assert_eq!(format!("{}", DeployTarget::Cloud), "cloud");
        assert_eq!(format!("{}", DeployTarget::Server), "server");
    }

    #[test]
    fn test_deploy_target_default_is_local() {
        assert_eq!(DeployTarget::default(), DeployTarget::Local);
    }

    #[test]
    fn test_proxy_type_display() {
        assert_eq!(format!("{}", ProxyType::Nginx), "nginx");
        assert_eq!(
            format!("{}", ProxyType::NginxProxyManager),
            "nginx-proxy-manager"
        );
        assert_eq!(format!("{}", ProxyType::Traefik), "traefik");
        assert_eq!(format!("{}", ProxyType::None), "none");
    }

    #[test]
    fn test_proxy_type_default_is_none() {
        assert_eq!(ProxyType::default(), ProxyType::None);
    }
}
