use anyhow::{bail, Context, Result};
#[cfg(feature = "docker")]
use chrono::{SecondsFormat, Utc};
#[cfg(feature = "docker")]
use regex::Regex;
use serde::Deserialize;
#[cfg(any(feature = "docker", test))]
use serde_json::json;
#[cfg(feature = "docker")]
use serde_json::Value;
#[cfg(feature = "docker")]
use std::collections::HashMap;
#[cfg(feature = "docker")]
use std::sync::OnceLock;

#[cfg(feature = "docker")]
use crate::transport::CommandError;
use crate::transport::{Command as AgentCommand, CommandResult};

#[cfg(feature = "docker")]
use crate::agent::docker;

const LOGS_DEFAULT_LIMIT: usize = 400;
const LOGS_MAX_LIMIT: usize = 1000;

#[derive(Debug, Clone)]
pub enum StackerCommand {
    Health(HealthCommand),
    Logs(LogsCommand),
    Restart(RestartCommand),
    Stop(StopCommand),
    Start(StartCommand),
    ErrorSummary(ErrorSummaryCommand),
    FetchConfig(FetchConfigCommand),
    ApplyConfig(ApplyConfigCommand),
    DeployApp(DeployAppCommand),
    RemoveApp(RemoveAppCommand),
    FetchAllConfigs(FetchAllConfigsCommand),
    DeployWithConfigs(DeployWithConfigsCommand),
    ConfigDiff(ConfigDiffCommand),
    ConfigureProxy(ConfigureProxyCommand),
}

#[cfg_attr(not(feature = "docker"), allow(dead_code))]
#[derive(Debug, Clone, Deserialize)]
pub struct HealthCommand {
    #[serde(default)]
    deployment_hash: String,
    #[serde(default)]
    app_code: String,
    #[serde(default = "default_true")]
    include_metrics: bool,
    /// When true and app_code is "system" or empty, return system containers (status_panel, compose-agent)
    #[serde(default)]
    include_system: bool,
}

#[cfg_attr(not(feature = "docker"), allow(dead_code))]
#[derive(Debug, Clone, Deserialize)]
pub struct LogsCommand {
    #[serde(default)]
    deployment_hash: String,
    #[serde(default)]
    app_code: String,
    cursor: Option<String>,
    #[serde(default = "default_logs_limit")]
    limit: usize,
    #[serde(default)]
    streams: Option<Vec<String>>,
    #[serde(default = "default_true")]
    redact: bool,
}

#[cfg_attr(not(feature = "docker"), allow(dead_code))]
#[derive(Debug, Clone, Deserialize)]
pub struct RestartCommand {
    #[serde(default)]
    deployment_hash: String,
    #[serde(default)]
    app_code: String,
    #[serde(default)]
    force: bool,
}

#[cfg_attr(not(feature = "docker"), allow(dead_code))]
#[derive(Debug, Clone, Deserialize)]
pub struct StopCommand {
    #[serde(default)]
    deployment_hash: String,
    #[serde(default)]
    app_code: String,
    #[serde(default = "default_stop_timeout")]
    timeout: u32,
}

#[cfg_attr(not(feature = "docker"), allow(dead_code))]
#[derive(Debug, Clone, Deserialize)]
pub struct StartCommand {
    #[serde(default)]
    deployment_hash: String,
    #[serde(default)]
    app_code: String,
}

#[cfg_attr(not(feature = "docker"), allow(dead_code))]
#[derive(Debug, Clone, Deserialize)]
pub struct ErrorSummaryCommand {
    #[serde(default)]
    deployment_hash: String,
    #[serde(default)]
    app_code: String,
    #[serde(default = "default_hours")]
    hours: u32,
    #[serde(default = "default_true")]
    redact: bool,
}

/// Command to fetch app configuration from Vault
#[cfg_attr(not(feature = "docker"), allow(dead_code))]
#[derive(Debug, Clone, Deserialize)]
pub struct FetchConfigCommand {
    #[serde(default)]
    deployment_hash: String,
    #[serde(default)]
    app_code: String,
    /// If true, also write the config to the destination path
    #[serde(default)]
    apply: bool,
}

/// Command to apply configuration from Vault to the filesystem and restart container
#[cfg_attr(not(feature = "docker"), allow(dead_code))]
#[derive(Debug, Clone, Deserialize)]
pub struct ApplyConfigCommand {
    #[serde(default)]
    deployment_hash: String,
    #[serde(default)]
    app_code: String,
    /// Optional: override the config content (instead of fetching from Vault)
    #[serde(default)]
    config_content: Option<String>,
    /// Optional: override the destination path
    #[serde(default)]
    destination_path: Option<String>,
    /// Whether to restart the container after applying config
    #[serde(default = "default_true")]
    restart_after: bool,
}

/// Command to deploy a new app container via docker compose
#[cfg_attr(not(feature = "docker"), allow(dead_code))]
#[derive(Debug, Clone, Deserialize)]
pub struct DeployAppCommand {
    #[serde(default)]
    deployment_hash: String,
    #[serde(default)]
    app_code: String,
    /// Optional: docker-compose.yml content (generated from J2 template)
    /// If provided, will be written to disk before deploying
    #[serde(default)]
    compose_content: Option<String>,
    /// Optional: specific image to use (overrides compose file)
    #[serde(default)]
    image: Option<String>,
    /// Optional: environment variables to set
    #[serde(default)]
    env_vars: Option<std::collections::HashMap<String, String>>,
    /// Whether to pull the image before starting (default: true)
    #[serde(default = "default_true")]
    pull: bool,
    /// Whether to remove existing container before deploying
    #[serde(default)]
    force_recreate: bool,
    /// Optional: config files to write before deploying (uses existing AppConfig struct)
    #[serde(default)]
    config_files: Option<Vec<crate::security::vault_client::AppConfig>>,
}

/// Command to remove an app container and associated config
#[cfg_attr(not(feature = "docker"), allow(dead_code))]
#[derive(Debug, Clone, Deserialize)]
pub struct RemoveAppCommand {
    #[serde(default)]
    deployment_hash: String,
    #[serde(default)]
    app_code: String,
    #[serde(default = "default_true")]
    delete_config: bool,
    #[serde(default)]
    remove_volumes: bool,
    #[serde(default)]
    remove_image: bool,
}

/// Command to fetch all app configurations from Vault for a deployment
#[cfg_attr(not(feature = "docker"), allow(dead_code))]
#[derive(Debug, Clone, Deserialize)]
pub struct FetchAllConfigsCommand {
    #[serde(default)]
    deployment_hash: String,
    /// Optional: specific app codes to fetch (if empty, fetches all)
    #[serde(default)]
    app_codes: Vec<String>,
    /// Whether to apply configs to disk after fetching
    #[serde(default)]
    apply: bool,
    /// Whether to create a ZIP archive of all configs
    #[serde(default)]
    archive: bool,
}

/// Command to fetch configs and deploy an app in one operation
#[cfg_attr(not(feature = "docker"), allow(dead_code))]
#[derive(Debug, Clone, Deserialize)]
pub struct DeployWithConfigsCommand {
    #[serde(default)]
    deployment_hash: String,
    #[serde(default)]
    app_code: String,
    /// Whether to pull the image before starting
    #[serde(default = "default_true")]
    pull: bool,
    /// Whether to force recreate the container
    #[serde(default)]
    force_recreate: bool,
    /// Whether to apply all project configs before deploying
    #[serde(default = "default_true")]
    apply_configs: bool,
}

/// Command to detect configuration drift between Vault and deployed files
#[cfg_attr(not(feature = "docker"), allow(dead_code))]
#[derive(Debug, Clone, Deserialize)]
pub struct ConfigDiffCommand {
    #[serde(default)]
    deployment_hash: String,
    /// Optional: specific app codes to check (if empty, checks all)
    #[serde(default)]
    app_codes: Vec<String>,
    /// Whether to include full diff content in response
    #[serde(default)]
    include_diff: bool,
}

/// Command to configure nginx proxy manager for an app
#[cfg_attr(not(feature = "docker"), allow(dead_code))]
#[derive(Debug, Clone, Deserialize)]
pub struct ConfigureProxyCommand {
    #[serde(default)]
    deployment_hash: String,
    #[serde(default)]
    app_code: String,
    /// Domain name(s) to proxy (e.g., ["komodo.example.com"])
    #[serde(default)]
    domain_names: Vec<String>,
    /// Container/service name to forward to (defaults to app_code)
    #[serde(default)]
    forward_host: Option<String>,
    /// Port on the container to forward to
    forward_port: u16,
    /// Enable SSL with Let's Encrypt
    #[serde(default = "default_true")]
    ssl_enabled: bool,
    /// Force HTTPS redirect
    #[serde(default = "default_true")]
    ssl_forced: bool,
    /// HTTP/2 support
    #[serde(default = "default_true")]
    http2_support: bool,
    /// Action: "create", "update", "delete"
    #[serde(default = "default_create_action")]
    action: String,
    /// NPM admin credentials (optional, can use defaults from config)
    #[serde(default)]
    npm_host: Option<String>,
    #[serde(default)]
    npm_email: Option<String>,
    #[serde(default)]
    npm_password: Option<String>,
}

fn default_create_action() -> String {
    "create".to_string()
}

pub fn parse_stacker_command(cmd: &AgentCommand) -> Result<Option<StackerCommand>> {
    let normalized = cmd.name.trim().to_lowercase();
    match normalized.as_str() {
        "health" | "stacker.health" => {
            let payload: HealthCommand =
                serde_json::from_value(cmd.params.clone()).context("invalid health payload")?;
            let payload = payload.normalize().with_command_context(cmd);
            payload.validate()?;
            Ok(Some(StackerCommand::Health(payload)))
        }
        "logs" | "stacker.logs" => {
            let payload: LogsCommand =
                serde_json::from_value(cmd.params.clone()).context("invalid logs payload")?;
            let payload = payload.normalize().with_command_context(cmd);
            payload.validate()?;
            Ok(Some(StackerCommand::Logs(payload)))
        }
        "restart" | "stacker.restart" => {
            let payload: RestartCommand =
                serde_json::from_value(cmd.params.clone()).context("invalid restart payload")?;
            let payload = payload.normalize().with_command_context(cmd);
            payload.validate()?;
            Ok(Some(StackerCommand::Restart(payload)))
        }
        "stop" | "stacker.stop" => {
            let payload: StopCommand =
                serde_json::from_value(cmd.params.clone()).context("invalid stop payload")?;
            let payload = payload.normalize().with_command_context(cmd);
            payload.validate()?;
            Ok(Some(StackerCommand::Stop(payload)))
        }
        "start" | "stacker.start" => {
            let payload: StartCommand =
                serde_json::from_value(cmd.params.clone()).context("invalid start payload")?;
            let payload = payload.normalize().with_command_context(cmd);
            payload.validate()?;
            Ok(Some(StackerCommand::Start(payload)))
        }
        "error_summary" | "stacker.error_summary" => {
            let payload: ErrorSummaryCommand = serde_json::from_value(cmd.params.clone())
                .context("invalid error_summary payload")?;
            let payload = payload.normalize().with_command_context(cmd);
            payload.validate()?;
            Ok(Some(StackerCommand::ErrorSummary(payload)))
        }
        "fetch_config" | "stacker.fetch_config" => {
            let payload: FetchConfigCommand = serde_json::from_value(cmd.params.clone())
                .context("invalid fetch_config payload")?;
            let payload = payload.normalize().with_command_context(cmd);
            payload.validate()?;
            Ok(Some(StackerCommand::FetchConfig(payload)))
        }
        "apply_config" | "stacker.apply_config" => {
            let payload: ApplyConfigCommand = serde_json::from_value(cmd.params.clone())
                .context("invalid apply_config payload")?;
            let payload = payload.normalize().with_command_context(cmd);
            payload.validate()?;
            Ok(Some(StackerCommand::ApplyConfig(payload)))
        }
        "deploy_app" | "stacker.deploy_app" => {
            let payload: DeployAppCommand =
                serde_json::from_value(cmd.params.clone()).context("invalid deploy_app payload")?;
            let payload = payload.normalize().with_command_context(cmd);
            payload.validate()?;
            Ok(Some(StackerCommand::DeployApp(payload)))
        }
        "remove_app" | "stacker.remove_app" => {
            let payload: RemoveAppCommand =
                serde_json::from_value(cmd.params.clone()).context("invalid remove_app payload")?;
            let payload = payload.normalize().with_command_context(cmd);
            payload.validate()?;
            Ok(Some(StackerCommand::RemoveApp(payload)))
        }
        "fetch_all_configs" | "stacker.fetch_all_configs" => {
            let payload: FetchAllConfigsCommand = serde_json::from_value(cmd.params.clone())
                .context("invalid fetch_all_configs payload")?;
            let payload = payload.normalize().with_command_context(cmd);
            payload.validate()?;
            Ok(Some(StackerCommand::FetchAllConfigs(payload)))
        }
        "deploy_with_configs" | "stacker.deploy_with_configs" => {
            let payload: DeployWithConfigsCommand = serde_json::from_value(cmd.params.clone())
                .context("invalid deploy_with_configs payload")?;
            let payload = payload.normalize().with_command_context(cmd);
            payload.validate()?;
            Ok(Some(StackerCommand::DeployWithConfigs(payload)))
        }
        "config_diff" | "stacker.config_diff" => {
            let payload: ConfigDiffCommand = serde_json::from_value(cmd.params.clone())
                .context("invalid config_diff payload")?;
            let payload = payload.normalize().with_command_context(cmd);
            payload.validate()?;
            Ok(Some(StackerCommand::ConfigDiff(payload)))
        }
        "configure_proxy" | "stacker.configure_proxy" => {
            let payload: ConfigureProxyCommand = serde_json::from_value(cmd.params.clone())
                .context("invalid configure_proxy payload")?;
            let payload = payload.normalize().with_command_context(cmd);
            payload.validate()?;
            Ok(Some(StackerCommand::ConfigureProxy(payload)))
        }
        _ => Ok(None),
    }
}

pub async fn execute_stacker_command(
    agent_cmd: &AgentCommand,
    command: &StackerCommand,
) -> Result<CommandResult> {
    #[cfg(feature = "docker")]
    {
        execute_with_docker(agent_cmd, command).await
    }
    #[cfg(not(feature = "docker"))]
    {
        let _ = (agent_cmd, command);
        bail!("docker feature not enabled for stacker commands")
    }
}

fn default_true() -> bool {
    true
}

fn default_logs_limit() -> usize {
    LOGS_DEFAULT_LIMIT
}

fn default_stop_timeout() -> u32 {
    30 // 30 seconds default graceful shutdown
}

fn default_hours() -> u32 {
    24 // Default to last 24 hours for error summary
}

impl HealthCommand {
    fn normalize(mut self) -> Self {
        self.deployment_hash = trimmed(&self.deployment_hash);
        self.app_code = trimmed(&self.app_code);
        self
    }

    fn with_command_context(mut self, agent_cmd: &AgentCommand) -> Self {
        if self.deployment_hash.is_empty() {
            if let Some(hash) = &agent_cmd.deployment_hash {
                self.deployment_hash = hash.clone();
            }
        }
        if self.app_code.is_empty() {
            if let Some(code) = &agent_cmd.app_code {
                self.app_code = code.clone();
            }
        }
        self
    }

    fn validate(&self) -> Result<()> {
        if self.deployment_hash.is_empty() {
            bail!("deployment_hash is required");
        }
        if self.app_code.is_empty() {
            bail!("app_code is required");
        }
        Ok(())
    }
}

impl LogsCommand {
    fn normalize(mut self) -> Self {
        self.deployment_hash = trimmed(&self.deployment_hash);
        self.app_code = trimmed(&self.app_code);
        self.limit = self.limit.clamp(1, LOGS_MAX_LIMIT);
        if let Some(streams) = &mut self.streams {
            let filtered: Vec<String> = streams
                .iter()
                .filter_map(|s| {
                    let normalized = s.trim().to_lowercase();
                    match normalized.as_str() {
                        "stdout" | "stderr" => Some(normalized),
                        _ => None,
                    }
                })
                .collect();
            self.streams = if filtered.is_empty() {
                None
            } else {
                Some(filtered)
            };
        }
        self
    }

    fn with_command_context(mut self, agent_cmd: &AgentCommand) -> Self {
        if self.deployment_hash.is_empty() {
            if let Some(hash) = &agent_cmd.deployment_hash {
                self.deployment_hash = hash.clone();
            }
        }
        if self.app_code.is_empty() {
            if let Some(code) = &agent_cmd.app_code {
                self.app_code = code.clone();
            }
        }
        self
    }

    fn validate(&self) -> Result<()> {
        if self.deployment_hash.is_empty() {
            bail!("deployment_hash is required");
        }
        if self.app_code.is_empty() {
            bail!("app_code is required");
        }
        Ok(())
    }

    #[cfg(feature = "docker")]
    fn includes_stream(&self, stream: &str) -> bool {
        match &self.streams {
            Some(allowed) => allowed.iter().any(|s| s == stream),
            None => true,
        }
    }
}

impl RestartCommand {
    fn normalize(mut self) -> Self {
        self.deployment_hash = trimmed(&self.deployment_hash);
        self.app_code = trimmed(&self.app_code);
        self
    }

    fn with_command_context(mut self, agent_cmd: &AgentCommand) -> Self {
        if self.deployment_hash.is_empty() {
            if let Some(hash) = &agent_cmd.deployment_hash {
                self.deployment_hash = hash.clone();
            }
        }
        if self.app_code.is_empty() {
            if let Some(code) = &agent_cmd.app_code {
                self.app_code = code.clone();
            }
        }
        self
    }

    fn validate(&self) -> Result<()> {
        if self.deployment_hash.is_empty() {
            bail!("deployment_hash is required");
        }
        if self.app_code.is_empty() {
            bail!("app_code is required");
        }
        Ok(())
    }
}

impl StopCommand {
    fn normalize(mut self) -> Self {
        self.deployment_hash = trimmed(&self.deployment_hash);
        self.app_code = trimmed(&self.app_code);
        self.timeout = self.timeout.clamp(1, 300); // Max 5 minutes
        self
    }

    fn with_command_context(mut self, agent_cmd: &AgentCommand) -> Self {
        if self.deployment_hash.is_empty() {
            if let Some(hash) = &agent_cmd.deployment_hash {
                self.deployment_hash = hash.clone();
            }
        }
        if self.app_code.is_empty() {
            if let Some(code) = &agent_cmd.app_code {
                self.app_code = code.clone();
            }
        }
        self
    }

    fn validate(&self) -> Result<()> {
        if self.deployment_hash.is_empty() {
            bail!("deployment_hash is required");
        }
        if self.app_code.is_empty() {
            bail!("app_code is required");
        }
        Ok(())
    }
}

impl StartCommand {
    fn normalize(mut self) -> Self {
        self.deployment_hash = trimmed(&self.deployment_hash);
        self.app_code = trimmed(&self.app_code);
        self
    }

    fn with_command_context(mut self, agent_cmd: &AgentCommand) -> Self {
        if self.deployment_hash.is_empty() {
            if let Some(hash) = &agent_cmd.deployment_hash {
                self.deployment_hash = hash.clone();
            }
        }
        if self.app_code.is_empty() {
            if let Some(code) = &agent_cmd.app_code {
                self.app_code = code.clone();
            }
        }
        self
    }

    fn validate(&self) -> Result<()> {
        if self.deployment_hash.is_empty() {
            bail!("deployment_hash is required");
        }
        if self.app_code.is_empty() {
            bail!("app_code is required");
        }
        Ok(())
    }
}

impl ErrorSummaryCommand {
    fn normalize(mut self) -> Self {
        self.deployment_hash = trimmed(&self.deployment_hash);
        self.app_code = trimmed(&self.app_code);
        self.hours = self.hours.clamp(1, 168); // Max 7 days
        self
    }

    fn with_command_context(mut self, agent_cmd: &AgentCommand) -> Self {
        if self.deployment_hash.is_empty() {
            if let Some(hash) = &agent_cmd.deployment_hash {
                self.deployment_hash = hash.clone();
            }
        }
        if self.app_code.is_empty() {
            if let Some(code) = &agent_cmd.app_code {
                self.app_code = code.clone();
            }
        }
        self
    }

    fn validate(&self) -> Result<()> {
        if self.deployment_hash.is_empty() {
            bail!("deployment_hash is required");
        }
        // app_code is optional for error_summary - if empty, analyze all containers
        Ok(())
    }
}

impl FetchConfigCommand {
    fn normalize(mut self) -> Self {
        self.deployment_hash = trimmed(&self.deployment_hash);
        self.app_code = trimmed(&self.app_code);
        self
    }

    fn with_command_context(mut self, agent_cmd: &AgentCommand) -> Self {
        if self.deployment_hash.is_empty() {
            if let Some(hash) = &agent_cmd.deployment_hash {
                self.deployment_hash = hash.clone();
            }
        }
        if self.app_code.is_empty() {
            if let Some(code) = &agent_cmd.app_code {
                self.app_code = code.clone();
            }
        }
        self
    }

    fn validate(&self) -> Result<()> {
        if self.deployment_hash.is_empty() {
            bail!("deployment_hash is required");
        }
        if self.app_code.is_empty() {
            bail!("app_code is required");
        }
        Ok(())
    }
}

impl ApplyConfigCommand {
    fn normalize(mut self) -> Self {
        self.deployment_hash = trimmed(&self.deployment_hash);
        self.app_code = trimmed(&self.app_code);
        if let Some(path) = &self.destination_path {
            self.destination_path = Some(trimmed(path));
        }
        self
    }

    fn with_command_context(mut self, agent_cmd: &AgentCommand) -> Self {
        if self.deployment_hash.is_empty() {
            if let Some(hash) = &agent_cmd.deployment_hash {
                self.deployment_hash = hash.clone();
            }
        }
        if self.app_code.is_empty() {
            if let Some(code) = &agent_cmd.app_code {
                self.app_code = code.clone();
            }
        }
        self
    }

    fn validate(&self) -> Result<()> {
        if self.deployment_hash.is_empty() {
            bail!("deployment_hash is required");
        }
        if self.app_code.is_empty() {
            bail!("app_code is required");
        }
        // Either config_content must be provided OR we fetch from Vault
        // destination_path is optional if we're fetching from Vault (it has the path)
        Ok(())
    }
}

impl DeployAppCommand {
    fn normalize(mut self) -> Self {
        self.deployment_hash = trimmed(&self.deployment_hash);
        self.app_code = trimmed(&self.app_code);
        if let Some(img) = &self.image {
            self.image = Some(trimmed(img));
        }
        self
    }

    fn with_command_context(mut self, agent_cmd: &AgentCommand) -> Self {
        if self.deployment_hash.is_empty() {
            if let Some(hash) = &agent_cmd.deployment_hash {
                self.deployment_hash = hash.clone();
            }
        }
        if self.app_code.is_empty() {
            if let Some(code) = &agent_cmd.app_code {
                self.app_code = code.clone();
            }
        }
        self
    }

    fn validate(&self) -> Result<()> {
        if self.deployment_hash.is_empty() {
            bail!("deployment_hash is required");
        }
        if self.app_code.is_empty() {
            bail!("app_code is required");
        }
        Ok(())
    }
}

impl RemoveAppCommand {
    fn normalize(mut self) -> Self {
        self.deployment_hash = trimmed(&self.deployment_hash);
        self.app_code = trimmed(&self.app_code);
        self
    }

    fn with_command_context(mut self, agent_cmd: &AgentCommand) -> Self {
        if self.deployment_hash.is_empty() {
            if let Some(hash) = &agent_cmd.deployment_hash {
                self.deployment_hash = hash.clone();
            }
        }
        if self.app_code.is_empty() {
            if let Some(code) = &agent_cmd.app_code {
                self.app_code = code.clone();
            }
        }
        self
    }

    fn validate(&self) -> Result<()> {
        if self.deployment_hash.is_empty() {
            bail!("deployment_hash is required");
        }
        if self.app_code.is_empty() {
            bail!("app_code is required");
        }
        Ok(())
    }
}

impl FetchAllConfigsCommand {
    fn normalize(mut self) -> Self {
        self.deployment_hash = trimmed(&self.deployment_hash);
        self.app_codes = self
            .app_codes
            .into_iter()
            .map(|s| trimmed(&s))
            .filter(|s| !s.is_empty())
            .collect();
        self
    }

    fn with_command_context(mut self, agent_cmd: &AgentCommand) -> Self {
        if self.deployment_hash.is_empty() {
            if let Some(hash) = &agent_cmd.deployment_hash {
                self.deployment_hash = hash.clone();
            }
        }
        self
    }

    fn validate(&self) -> Result<()> {
        if self.deployment_hash.is_empty() {
            bail!("deployment_hash is required");
        }
        Ok(())
    }
}

impl DeployWithConfigsCommand {
    fn normalize(mut self) -> Self {
        self.deployment_hash = trimmed(&self.deployment_hash);
        self.app_code = trimmed(&self.app_code);
        self
    }

    fn with_command_context(mut self, agent_cmd: &AgentCommand) -> Self {
        if self.deployment_hash.is_empty() {
            if let Some(hash) = &agent_cmd.deployment_hash {
                self.deployment_hash = hash.clone();
            }
        }
        if self.app_code.is_empty() {
            if let Some(code) = &agent_cmd.app_code {
                self.app_code = code.clone();
            }
        }
        self
    }

    fn validate(&self) -> Result<()> {
        if self.deployment_hash.is_empty() {
            bail!("deployment_hash is required");
        }
        if self.app_code.is_empty() {
            bail!("app_code is required");
        }
        Ok(())
    }
}

impl ConfigDiffCommand {
    fn normalize(mut self) -> Self {
        self.deployment_hash = trimmed(&self.deployment_hash);
        self.app_codes = self
            .app_codes
            .into_iter()
            .map(|s| trimmed(&s))
            .filter(|s| !s.is_empty())
            .collect();
        self
    }

    fn with_command_context(mut self, agent_cmd: &AgentCommand) -> Self {
        if self.deployment_hash.is_empty() {
            if let Some(hash) = &agent_cmd.deployment_hash {
                self.deployment_hash = hash.clone();
            }
        }
        self
    }

    fn validate(&self) -> Result<()> {
        if self.deployment_hash.is_empty() {
            bail!("deployment_hash is required");
        }
        Ok(())
    }
}

impl ConfigureProxyCommand {
    fn normalize(mut self) -> Self {
        self.deployment_hash = trimmed(&self.deployment_hash);
        self.app_code = trimmed(&self.app_code);
        self.domain_names = self
            .domain_names
            .into_iter()
            .map(|s| trimmed(&s))
            .filter(|s| !s.is_empty())
            .collect();
        self.action = trimmed(&self.action).to_lowercase();
        if self.action.is_empty() {
            self.action = "create".to_string();
        }
        self
    }

    fn with_command_context(mut self, agent_cmd: &AgentCommand) -> Self {
        if self.deployment_hash.is_empty() {
            if let Some(hash) = &agent_cmd.deployment_hash {
                self.deployment_hash = hash.clone();
            }
        }
        self
    }

    fn validate(&self) -> Result<()> {
        if self.deployment_hash.is_empty() {
            bail!("deployment_hash is required");
        }
        if self.app_code.is_empty() {
            bail!("app_code is required");
        }
        if self.domain_names.is_empty() {
            bail!("at least one domain_name is required");
        }
        if self.forward_port == 0 {
            bail!("forward_port is required and must be > 0");
        }
        if !["create", "update", "delete"].contains(&self.action.as_str()) {
            bail!("action must be one of: create, update, delete");
        }
        Ok(())
    }
}

fn trimmed(value: &str) -> String {
    value.trim().to_string()
}

#[cfg(feature = "docker")]
fn resolve_compose_paths(deployment_hash: &str, app_code: &str) -> (String, String) {
    use std::path::Path;

    if let Ok(dir) = std::env::var("COMPOSE_PROJECT_DIR") {
        let file = format!("{}/docker-compose.yml", dir);
        return (dir, file);
    }

    let hash_dir = format!("/home/trydirect/{}", deployment_hash);
    let hash_file = format!("{}/docker-compose.yml", hash_dir);
    if Path::new(&hash_file).exists() {
        return (hash_dir, hash_file);
    }

    let app_dir = format!("/home/trydirect/{}", app_code);
    let app_file = format!("{}/docker-compose.yml", app_dir);
    (app_dir, app_file)
}

/// Represents which compose command variant is available on the system.
#[cfg(feature = "docker")]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ComposeVariant {
    /// Docker Compose V2 plugin: `docker compose`
    Plugin,
    /// Standalone docker-compose binary: `docker-compose`
    Standalone,
}

/// Detect which docker compose variant is available on the system.
/// Tries `docker compose version` first (plugin), then `docker-compose version` (standalone).
/// Result is cached for the lifetime of the process.
#[cfg(feature = "docker")]
pub async fn detect_compose_variant() -> Option<ComposeVariant> {
    use tokio::process::Command;

    static COMPOSE_VARIANT: OnceLock<Option<ComposeVariant>> = OnceLock::new();

    // Return cached result if available
    if let Some(variant) = COMPOSE_VARIANT.get() {
        return *variant;
    }

    // Try docker compose (plugin) first
    let plugin_result = Command::new("docker")
        .arg("compose")
        .arg("version")
        .output()
        .await;

    if let Ok(output) = plugin_result {
        if output.status.success() {
            let _ = COMPOSE_VARIANT.set(Some(ComposeVariant::Plugin));
            return Some(ComposeVariant::Plugin);
        }
    }

    // Try docker-compose (standalone) as fallback
    let standalone_result = Command::new("docker-compose").arg("version").output().await;

    if let Ok(output) = standalone_result {
        if output.status.success() {
            let _ = COMPOSE_VARIANT.set(Some(ComposeVariant::Standalone));
            return Some(ComposeVariant::Standalone);
        }
    }

    // Neither is available
    let _ = COMPOSE_VARIANT.set(None);
    None
}

/// Build a compose command with the correct binary/syntax based on what's available.
/// Returns (command_program, initial_args) where initial_args should be prepended to actual args.
#[cfg(feature = "docker")]
pub fn build_compose_command(variant: ComposeVariant) -> (String, Vec<String>) {
    match variant {
        ComposeVariant::Plugin => ("docker".to_string(), vec!["compose".to_string()]),
        ComposeVariant::Standalone => ("docker-compose".to_string(), vec![]),
    }
}

#[cfg(feature = "docker")]
fn base_result(
    agent_cmd: &AgentCommand,
    deployment_hash: &str,
    app_code: &str,
    command_type: &str,
) -> CommandResult {
    CommandResult {
        command_id: agent_cmd.command_id.clone(),
        status: "success".into(),
        result: None,
        error: None,
        completed_at: now_timestamp(),
        deployment_hash: Some(deployment_hash.to_string()),
        app_code: Some(app_code.to_string()),
        command_type: Some(command_type.to_string()),
        ..CommandResult::default()
    }
}

#[cfg(feature = "docker")]
fn now_timestamp() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

#[cfg(feature = "docker")]
fn errors_value(errors: &[CommandError]) -> Value {
    serde_json::to_value(errors).unwrap_or_else(|_| json!([]))
}

#[cfg(feature = "docker")]
fn redact_message(message: &str, enabled: bool) -> (String, bool) {
    if !enabled || message.is_empty() {
        return (message.to_string(), false);
    }

    static REDACTION_RE: OnceLock<Regex> = OnceLock::new();
    let regex = REDACTION_RE.get_or_init(|| {
        Regex::new(r"(?i)(token|secret|password|key|credential)(\s*[=:]\s*)([^\s]+)").unwrap()
    });

    let mut redacted = false;
    let replaced = regex.replace_all(message, |caps: &regex::Captures| {
        redacted = true;
        format!("{}{}***", &caps[1], &caps[2])
    });
    (replaced.into_owned(), redacted)
}

#[cfg(feature = "docker")]
fn make_error(code: &str, message: impl Into<String>, details: Option<String>) -> CommandError {
    CommandError {
        code: code.to_string(),
        message: message.into(),
        details,
    }
}

#[cfg(feature = "docker")]
async fn execute_with_docker(
    agent_cmd: &AgentCommand,
    command: &StackerCommand,
) -> Result<CommandResult> {
    match command {
        StackerCommand::Health(data) => handle_health(agent_cmd, data).await,
        StackerCommand::Logs(data) => handle_logs(agent_cmd, data).await,
        StackerCommand::Restart(data) => handle_restart(agent_cmd, data).await,
        StackerCommand::Stop(data) => handle_stop(agent_cmd, data).await,
        StackerCommand::Start(data) => handle_start(agent_cmd, data).await,
        StackerCommand::ErrorSummary(data) => handle_error_summary(agent_cmd, data).await,
        StackerCommand::FetchConfig(data) => handle_fetch_config(agent_cmd, data).await,
        StackerCommand::ApplyConfig(data) => handle_apply_config(agent_cmd, data).await,
        StackerCommand::DeployApp(data) => handle_deploy_app(agent_cmd, data).await,
        StackerCommand::RemoveApp(data) => handle_remove_app(agent_cmd, data).await,
        StackerCommand::FetchAllConfigs(data) => handle_fetch_all_configs(agent_cmd, data).await,
        StackerCommand::DeployWithConfigs(data) => {
            handle_deploy_with_configs(agent_cmd, data).await
        }
        StackerCommand::ConfigDiff(data) => handle_config_diff(agent_cmd, data).await,
        StackerCommand::ConfigureProxy(data) => handle_configure_proxy(agent_cmd, data).await,
    }
}

#[cfg(feature = "docker")]
async fn handle_health(agent_cmd: &AgentCommand, data: &HealthCommand) -> Result<CommandResult> {
    let mut result = base_result(agent_cmd, &data.deployment_hash, &data.app_code, "health");
    let containers = match docker::list_container_health().await {
        Ok(list) => list,
        Err(e) => {
            let error = make_error(
                "health_unavailable",
                "Failed to query container health",
                Some(e.to_string()),
            );
            let errors = vec![error.clone()];
            let body = json!({
                "type": "health",
                "deployment_hash": data.deployment_hash.clone(),
                "app_code": data.app_code.clone(),
                "status": "unknown",
                "container_state": "unknown",
                "last_heartbeat_at": now_timestamp(),
                "errors": errors_value(&errors),
            });
            result.status = "failed".into();
            result.result = Some(body);
            result.errors = Some(errors);
            return Ok(result);
        }
    };

    // Handle system containers request (status_panel, compose-agent, etc.)
    if data.include_system && (data.app_code.is_empty() || data.app_code == "system") {
        let system_patterns = [
            "status",
            "status_panel",
            "status-panel",
            "compose-agent",
            "compose_agent",
        ];
        let system_containers: Vec<_> = containers
            .iter()
            .filter(|c| {
                let name = c.name.trim_start_matches('/').to_lowercase();
                system_patterns.iter().any(|p| name.contains(p))
            })
            .collect();

        let mut system_list = Vec::new();
        for entry in &system_containers {
            let container_state = map_container_state(&entry.status).to_string();
            let mut item = json!({
                "app_code": entry.name.trim_start_matches('/'),
                "container_name": entry.name.trim_start_matches('/'),
                "container_state": container_state,
                "status": derive_health_status(&container_state, false),
            });
            if data.include_metrics {
                item["metrics"] = build_metrics(entry);
            }
            system_list.push(item);
        }

        let body = json!({
            "type": "system_health",
            "deployment_hash": data.deployment_hash.clone(),
            "status": "ok",
            "last_heartbeat_at": now_timestamp(),
            "system_containers": system_list,
        });
        result.result = Some(body);
        return Ok(result);
    }

    let container = containers
        .iter()
        .find(|c| container_matches(&c.name, &data.app_code, &c.labels, &c.image));

    let mut errors: Vec<CommandError> = Vec::new();
    let container_state = if let Some(entry) = container {
        map_container_state(&entry.status).to_string()
    } else {
        errors.push(make_error(
            "container_not_found",
            format!("Container `{}` not found", data.app_code),
            None,
        ));
        "unknown".to_string()
    };

    let status_field = derive_health_status(&container_state, !errors.is_empty());
    let mut body = json!({
        "type": "health",
        "deployment_hash": data.deployment_hash.clone(),
        "app_code": data.app_code.clone(),
        "status": status_field,
        "container_state": container_state,
        "last_heartbeat_at": now_timestamp(),
    });

    if let Some(entry) = container.filter(|_| data.include_metrics) {
        body["metrics"] = build_metrics(entry);
    }

    if !errors.is_empty() {
        body["errors"] = errors_value(&errors);
        result.errors = Some(errors.clone());
        result.status = "failed".into();
    }

    result.result = Some(body);
    Ok(result)
}

#[cfg(feature = "docker")]
async fn handle_logs(agent_cmd: &AgentCommand, data: &LogsCommand) -> Result<CommandResult> {
    let mut result = base_result(agent_cmd, &data.deployment_hash, &data.app_code, "logs");
    let window = match docker::get_container_logs_window(
        &data.app_code,
        data.cursor.clone(),
        Some(data.limit),
    )
    .await
    {
        Ok(win) => win,
        Err(e) => {
            let error = make_error(
                "log_fetch_failed",
                "Failed to fetch container logs",
                Some(e.to_string()),
            );
            let errors = vec![error.clone()];
            let body = json!({
                "type": "logs",
                "deployment_hash": data.deployment_hash.clone(),
                "app_code": data.app_code.clone(),
                "cursor": data.cursor.clone(),
                "truncated": false,
                "lines": [],
                "errors": errors_value(&errors),
            });
            result.status = "failed".into();
            result.result = Some(body);
            result.errors = Some(errors);
            return Ok(result);
        }
    };

    let mut lines = Vec::new();
    for frame in window.frames {
        let stream = frame.stream.to_lowercase();
        if !data.includes_stream(&stream) {
            continue;
        }
        let (message, redacted) = redact_message(&frame.message, data.redact);
        let ts_value = frame.timestamp.clone().unwrap_or_else(now_timestamp);
        lines.push(json!({
            "ts": ts_value,
            "stream": stream,
            "message": message,
            "redacted": redacted,
        }));
    }

    let body = json!({
        "type": "logs",
        "deployment_hash": data.deployment_hash.clone(),
        "app_code": data.app_code.clone(),
        "cursor": window.next_cursor,
        "truncated": window.truncated,
        "lines": lines,
    });

    result.result = Some(body);
    Ok(result)
}

#[cfg(feature = "docker")]
async fn handle_restart(agent_cmd: &AgentCommand, data: &RestartCommand) -> Result<CommandResult> {
    let mut result = base_result(agent_cmd, &data.deployment_hash, &data.app_code, "restart");
    let mut errors: Vec<CommandError> = Vec::new();

    if let Err(e) = docker::restart(&data.app_code).await {
        errors.push(make_error(
            "restart_failed",
            format!("Restart failed for `{}`", data.app_code),
            Some(e.to_string()),
        ));

        if data.force {
            if let Err(stop_err) = docker::stop(&data.app_code).await {
                errors.push(make_error(
                    "force_stop_failed",
                    format!("Force stop failed for `{}`", data.app_code),
                    Some(stop_err.to_string()),
                ));
            } else if let Err(retry_err) = docker::restart(&data.app_code).await {
                errors.push(make_error(
                    "force_restart_failed",
                    format!("Forced restart failed for `{}`", data.app_code),
                    Some(retry_err.to_string()),
                ));
            } else {
                errors.clear();
            }
        }
    }

    let containers = match docker::list_container_health().await {
        Ok(list) => list,
        Err(e) => {
            errors.push(make_error(
                "health_unavailable",
                "Failed to query container status after restart",
                Some(e.to_string()),
            ));
            let body = json!({
                "type": "restart",
                "deployment_hash": data.deployment_hash.clone(),
                "app_code": data.app_code.clone(),
                "status": "failed",
                "container_state": "unknown",
                "errors": errors_value(&errors),
            });
            result.status = "failed".into();
            result.result = Some(body);
            result.errors = Some(errors);
            return Ok(result);
        }
    };
    let container = containers
        .iter()
        .find(|c| container_matches(&c.name, &data.app_code, &c.labels, &c.image));
    let container_state = container
        .map(|c| map_container_state(&c.status).to_string())
        .unwrap_or_else(|| "unknown".to_string());

    if container.is_none() && errors.is_empty() {
        errors.push(make_error(
            "container_not_found",
            format!("Container `{}` not found", data.app_code),
            None,
        ));
    }

    let status_label = if errors.is_empty() { "ok" } else { "failed" };

    let mut body = json!({
        "type": "restart",
        "deployment_hash": data.deployment_hash.clone(),
        "app_code": data.app_code.clone(),
        "status": status_label,
        "container_state": container_state,
    });

    if !errors.is_empty() {
        body["errors"] = errors_value(&errors);
        result.status = "failed".into();
        result.errors = Some(errors.clone());
    }

    result.result = Some(body);
    Ok(result)
}

#[cfg(feature = "docker")]
async fn handle_stop(agent_cmd: &AgentCommand, data: &StopCommand) -> Result<CommandResult> {
    let mut result = base_result(agent_cmd, &data.deployment_hash, &data.app_code, "stop");
    let mut errors: Vec<CommandError> = Vec::new();

    if let Err(e) = docker::stop_with_timeout(&data.app_code, data.timeout).await {
        errors.push(make_error(
            "stop_failed",
            format!("Stop failed for `{}`", data.app_code),
            Some(e.to_string()),
        ));
    }

    // Check final container state
    let containers = match docker::list_container_health().await {
        Ok(list) => list,
        Err(e) => {
            errors.push(make_error(
                "health_unavailable",
                "Failed to query container status after stop",
                Some(e.to_string()),
            ));
            let body = json!({
                "type": "stop",
                "deployment_hash": data.deployment_hash.clone(),
                "app_code": data.app_code.clone(),
                "status": "failed",
                "container_state": "unknown",
                "errors": errors_value(&errors),
            });
            result.status = "failed".into();
            result.result = Some(body);
            result.errors = Some(errors);
            return Ok(result);
        }
    };

    let container = containers
        .iter()
        .find(|c| container_matches(&c.name, &data.app_code, &c.labels, &c.image));
    let container_state = container
        .map(|c| map_container_state(&c.status).to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let status_label = if errors.is_empty() { "ok" } else { "failed" };

    let mut body = json!({
        "type": "stop",
        "deployment_hash": data.deployment_hash.clone(),
        "app_code": data.app_code.clone(),
        "status": status_label,
        "container_state": container_state,
    });

    if !errors.is_empty() {
        body["errors"] = errors_value(&errors);
        result.status = "failed".into();
        result.errors = Some(errors.clone());
    }

    result.result = Some(body);
    Ok(result)
}

#[cfg(feature = "docker")]
async fn handle_start(agent_cmd: &AgentCommand, data: &StartCommand) -> Result<CommandResult> {
    let mut result = base_result(agent_cmd, &data.deployment_hash, &data.app_code, "start");
    let mut errors: Vec<CommandError> = Vec::new();

    if let Err(e) = docker::start(&data.app_code).await {
        errors.push(make_error(
            "start_failed",
            format!("Start failed for `{}`", data.app_code),
            Some(e.to_string()),
        ));
    }

    // Check final container state
    let containers = match docker::list_container_health().await {
        Ok(list) => list,
        Err(e) => {
            errors.push(make_error(
                "health_unavailable",
                "Failed to query container status after start",
                Some(e.to_string()),
            ));
            let body = json!({
                "type": "start",
                "deployment_hash": data.deployment_hash.clone(),
                "app_code": data.app_code.clone(),
                "status": "failed",
                "container_state": "unknown",
                "errors": errors_value(&errors),
            });
            result.status = "failed".into();
            result.result = Some(body);
            result.errors = Some(errors);
            return Ok(result);
        }
    };

    let container = containers
        .iter()
        .find(|c| container_matches(&c.name, &data.app_code, &c.labels, &c.image));
    let container_state = container
        .map(|c| map_container_state(&c.status).to_string())
        .unwrap_or_else(|| "unknown".to_string());

    if container.is_none() && errors.is_empty() {
        errors.push(make_error(
            "container_not_found",
            format!("Container `{}` not found", data.app_code),
            None,
        ));
    }

    let status_label = if errors.is_empty() { "ok" } else { "failed" };

    let mut body = json!({
        "type": "start",
        "deployment_hash": data.deployment_hash.clone(),
        "app_code": data.app_code.clone(),
        "status": status_label,
        "container_state": container_state,
    });

    if !errors.is_empty() {
        body["errors"] = errors_value(&errors);
        result.status = "failed".into();
        result.errors = Some(errors.clone());
    }

    result.result = Some(body);
    Ok(result)
}

#[cfg(feature = "docker")]
async fn handle_error_summary(
    agent_cmd: &AgentCommand,
    data: &ErrorSummaryCommand,
) -> Result<CommandResult> {
    let mut result = base_result(
        agent_cmd,
        &data.deployment_hash,
        &data.app_code,
        "error_summary",
    );

    // Get list of containers to analyze
    let containers = match docker::list_container_health().await {
        Ok(list) => list,
        Err(e) => {
            let error = make_error(
                "health_unavailable",
                "Failed to list containers for error analysis",
                Some(e.to_string()),
            );
            let errors = vec![error.clone()];
            let body = json!({
                "type": "error_summary",
                "deployment_hash": data.deployment_hash.clone(),
                "app_code": data.app_code.clone(),
                "status": "failed",
                "errors": errors_value(&errors),
            });
            result.status = "failed".into();
            result.result = Some(body);
            result.errors = Some(errors);
            return Ok(result);
        }
    };

    // Filter containers if app_code specified
    let target_containers: Vec<_> = if data.app_code.is_empty() {
        containers.iter().collect()
    } else {
        containers
            .iter()
            .filter(|c| container_matches(&c.name, &data.app_code, &c.labels, &c.image))
            .collect()
    };

    // Error patterns to search for
    static ERROR_PATTERNS: &[&str] = &[
        "error",
        "Error",
        "ERROR",
        "exception",
        "Exception",
        "EXCEPTION",
        "failed",
        "Failed",
        "FAILED",
        "fatal",
        "Fatal",
        "FATAL",
        "panic",
        "PANIC",
        "crash",
        "crashed",
        "denied",
        "refused",
        "timeout",
        "timed out",
        "connection refused",
        "no such file",
        "permission denied",
        "out of memory",
        "OOM",
    ];

    let mut summary = json!({
        "type": "error_summary",
        "deployment_hash": data.deployment_hash.clone(),
        "app_code": data.app_code.clone(),
        "hours_analyzed": data.hours,
        "containers_analyzed": target_containers.len(),
        "apps": [],
        "total_errors": 0,
        "total_warnings": 0,
    });

    let mut apps_summary: Vec<Value> = Vec::new();
    let mut total_errors = 0u64;
    let mut total_warnings = 0u64;

    for container in target_containers {
        // Get logs for this container
        let logs_result =
            docker::get_container_logs_window(&container.name, None, Some(LOGS_MAX_LIMIT)).await;

        let mut error_count = 0u64;
        let mut warning_count = 0u64;
        let mut sample_errors: Vec<Value> = Vec::new();
        let mut error_categories: HashMap<String, u64> = HashMap::new();

        if let Ok(window) = logs_result {
            for frame in &window.frames {
                let msg_lower = frame.message.to_lowercase();

                // Check for errors
                let is_error = ERROR_PATTERNS.iter().any(|p| frame.message.contains(p));
                let is_warning = msg_lower.contains("warn") || msg_lower.contains("warning");

                if is_error {
                    error_count += 1;

                    // Categorize error
                    let category = categorize_error(&frame.message);
                    *error_categories.entry(category).or_insert(0) += 1;

                    // Collect samples (max 5)
                    if sample_errors.len() < 5 {
                        let (redacted_msg, _) = redact_message(&frame.message, data.redact);
                        sample_errors.push(json!({
                            "timestamp": frame.timestamp.clone(),
                            "stream": frame.stream.clone(),
                            "message": redacted_msg,
                        }));
                    }
                } else if is_warning {
                    warning_count += 1;
                }
            }
        }

        total_errors += error_count;
        total_warnings += warning_count;

        let app_code = extract_app_code(&container.name, &container.labels);
        apps_summary.push(json!({
            "app_code": app_code,
            "container_name": container.name,
            "error_count": error_count,
            "warning_count": warning_count,
            "error_categories": error_categories,
            "sample_errors": sample_errors,
            "status": container.status,
        }));
    }

    summary["apps"] = json!(apps_summary);
    summary["total_errors"] = json!(total_errors);
    summary["total_warnings"] = json!(total_warnings);

    // Generate recommendations based on findings
    let recommendations = generate_recommendations(total_errors, &apps_summary);
    summary["recommendations"] = json!(recommendations);

    summary["status"] = json!(if total_errors > 0 {
        "issues_found"
    } else {
        "ok"
    });

    result.result = Some(summary);
    Ok(result)
}

#[cfg(feature = "docker")]
fn categorize_error(message: &str) -> String {
    let msg_lower = message.to_lowercase();

    if msg_lower.contains("connection refused") || msg_lower.contains("connection reset") {
        "connection".to_string()
    } else if msg_lower.contains("timeout") || msg_lower.contains("timed out") {
        "timeout".to_string()
    } else if msg_lower.contains("out of memory") || msg_lower.contains("oom") {
        "memory".to_string()
    } else if msg_lower.contains("permission denied") || msg_lower.contains("access denied") {
        "permission".to_string()
    } else if msg_lower.contains("no such file") || msg_lower.contains("not found") {
        "not_found".to_string()
    } else if msg_lower.contains("database") || msg_lower.contains("sql") {
        "database".to_string()
    } else if msg_lower.contains("network") || msg_lower.contains("dns") {
        "network".to_string()
    } else if msg_lower.contains("authentication") || msg_lower.contains("unauthorized") {
        "auth".to_string()
    } else {
        "general".to_string()
    }
}

#[cfg(feature = "docker")]
fn extract_app_code(name: &str, labels: &HashMap<String, String>) -> String {
    if let Some(service) = labels.get("com.docker.compose.service") {
        return service.clone();
    }
    // Fall back to extracting from container name
    name.trim_start_matches('/').to_string()
}

#[cfg(feature = "docker")]
fn generate_recommendations(total_errors: u64, apps: &[Value]) -> Vec<String> {
    let mut recs = Vec::new();

    if total_errors == 0 {
        recs.push("No errors detected. System appears healthy.".to_string());
        return recs;
    }

    // Analyze error patterns across apps
    for app in apps {
        let app_code = app["app_code"].as_str().unwrap_or("unknown");
        let error_count = app["error_count"].as_u64().unwrap_or(0);

        if error_count == 0 {
            continue;
        }

        if let Some(categories) = app["error_categories"].as_object() {
            if categories.contains_key("connection") {
                recs.push(format!(
                    "{}: Check if dependent services are running and network connectivity is working.",
                    app_code
                ));
            }
            if categories.contains_key("timeout") {
                recs.push(format!(
                    "{}: Consider increasing timeout settings or optimizing slow operations.",
                    app_code
                ));
            }
            if categories.contains_key("memory") {
                recs.push(format!(
                    "{}: Container may need more memory. Consider increasing memory limits.",
                    app_code
                ));
            }
            if categories.contains_key("database") {
                recs.push(format!(
                    "{}: Check database connection settings and database server health.",
                    app_code
                ));
            }
            if categories.contains_key("permission") {
                recs.push(format!(
                    "{}: File permission issues detected. Check volume mounts and user permissions.",
                    app_code
                ));
            }
        }

        if error_count > 50 {
            recs.push(format!(
                "{}: High error rate ({}). Consider restarting the container.",
                app_code, error_count
            ));
        }
    }

    if recs.is_empty() {
        recs.push("Review the sample errors above to diagnose the issues.".to_string());
    }

    recs
}

// =========================================================================
// Config Management Handlers
// =========================================================================

#[cfg(feature = "docker")]
async fn handle_fetch_config(
    agent_cmd: &AgentCommand,
    data: &FetchConfigCommand,
) -> Result<CommandResult> {
    use crate::security::vault_client::VaultClient;

    let mut result = base_result(
        agent_cmd,
        &data.deployment_hash,
        &data.app_code,
        "fetch_config",
    );

    // Initialize Vault client
    let vault_client = match VaultClient::from_env() {
        Ok(Some(client)) => client,
        Ok(None) => {
            let error = make_error(
                "vault_not_configured",
                "Vault client not configured. Set VAULT_ADDRESS, VAULT_TOKEN, and VAULT_AGENT_PATH_PREFIX.",
                None,
            );
            result.status = "failed".into();
            result.error = Some(error.message.clone());
            result.errors = Some(vec![error]);
            return Ok(result);
        }
        Err(e) => {
            let error = make_error(
                "vault_init_failed",
                "Failed to initialize Vault client",
                Some(e.to_string()),
            );
            result.status = "failed".into();
            result.error = Some(error.message.clone());
            result.errors = Some(vec![error]);
            return Ok(result);
        }
    };

    // Fetch config from Vault
    match vault_client
        .fetch_app_config(&data.deployment_hash, &data.app_code)
        .await
    {
        Ok(config) => {
            let mut body = json!({
                "type": "fetch_config",
                "deployment_hash": data.deployment_hash.clone(),
                "app_code": data.app_code.clone(),
                "config": {
                    "content_type": config.content_type,
                    "destination_path": config.destination_path,
                    "file_mode": config.file_mode,
                    "content_length": config.content.len(),
                },
                "fetched_at": now_timestamp(),
            });

            // If apply=true, write config to disk
            if data.apply {
                match write_config_to_disk(&config).await {
                    Ok(()) => {
                        body["applied"] = json!(true);
                        body["applied_at"] = json!(now_timestamp());
                        tracing::info!(
                            deployment_hash = %data.deployment_hash,
                            app_code = %data.app_code,
                            destination = %config.destination_path,
                            "Config fetched and applied to disk"
                        );
                    }
                    Err(e) => {
                        let error = make_error(
                            "config_write_failed",
                            "Failed to write config to disk",
                            Some(e.to_string()),
                        );
                        body["applied"] = json!(false);
                        body["apply_error"] = json!(error.message);
                        result.errors = Some(vec![error]);
                    }
                }
            } else {
                // Include content in response (for preview)
                body["config"]["content"] = json!(config.content);
            }

            result.result = Some(body);
            Ok(result)
        }
        Err(e) => {
            let error = make_error(
                "vault_fetch_failed",
                format!(
                    "Failed to fetch config from Vault for {}/{}",
                    data.deployment_hash, data.app_code
                ),
                Some(e.to_string()),
            );
            result.status = "failed".into();
            result.error = Some(error.message.clone());
            result.errors = Some(vec![error]);
            Ok(result)
        }
    }
}

#[cfg(feature = "docker")]
async fn handle_apply_config(
    agent_cmd: &AgentCommand,
    data: &ApplyConfigCommand,
) -> Result<CommandResult> {
    use crate::security::vault_client::{AppConfig, VaultClient};

    let mut result = base_result(
        agent_cmd,
        &data.deployment_hash,
        &data.app_code,
        "apply_config",
    );

    // Get config - either from payload or Vault
    let config = if let Some(content) = &data.config_content {
        // Config provided directly in command
        let destination = data.destination_path.clone().ok_or_else(|| {
            anyhow::anyhow!("destination_path required when providing config_content")
        })?;

        AppConfig {
            content: content.clone(),
            content_type: "text".to_string(),
            destination_path: destination,
            file_mode: "0644".to_string(),
            owner: None,
            group: None,
        }
    } else {
        // Fetch from Vault
        let vault_client = match VaultClient::from_env() {
            Ok(Some(client)) => client,
            Ok(None) => {
                let error = make_error(
                    "vault_not_configured",
                    "Vault client not configured and no config_content provided.",
                    None,
                );
                result.status = "failed".into();
                result.error = Some(error.message.clone());
                result.errors = Some(vec![error]);
                return Ok(result);
            }
            Err(e) => {
                let error = make_error(
                    "vault_init_failed",
                    "Failed to initialize Vault client",
                    Some(e.to_string()),
                );
                result.status = "failed".into();
                result.error = Some(error.message.clone());
                result.errors = Some(vec![error]);
                return Ok(result);
            }
        };

        match vault_client
            .fetch_app_config(&data.deployment_hash, &data.app_code)
            .await
        {
            Ok(mut cfg) => {
                // Override destination if provided
                if let Some(dest) = &data.destination_path {
                    cfg.destination_path = dest.clone();
                }
                cfg
            }
            Err(e) => {
                let error = make_error(
                    "vault_fetch_failed",
                    format!(
                        "Failed to fetch config from Vault for {}/{}",
                        data.deployment_hash, data.app_code
                    ),
                    Some(e.to_string()),
                );
                result.status = "failed".into();
                result.error = Some(error.message.clone());
                result.errors = Some(vec![error]);
                return Ok(result);
            }
        }
    };

    let destination = config.destination_path.clone();

    // Write config to disk
    if let Err(e) = write_config_to_disk(&config).await {
        let error = make_error(
            "config_write_failed",
            "Failed to write config to disk",
            Some(e.to_string()),
        );
        result.status = "failed".into();
        result.error = Some(error.message.clone());
        result.errors = Some(vec![error]);
        return Ok(result);
    }

    let mut body = json!({
        "type": "apply_config",
        "deployment_hash": data.deployment_hash.clone(),
        "app_code": data.app_code.clone(),
        "destination_path": destination,
        "applied_at": now_timestamp(),
        "config_applied": true,
    });

    // Restart container if requested
    if data.restart_after {
        let containers = docker::list_container_health().await.unwrap_or_default();
        let container = containers
            .iter()
            .find(|c| container_matches(&c.name, &data.app_code, &c.labels, &c.image));

        if let Some(c) = container {
            match docker::restart(&c.name).await {
                Ok(()) => {
                    body["container_restarted"] = json!(true);
                    body["restarted_at"] = json!(now_timestamp());
                    tracing::info!(
                        deployment_hash = %data.deployment_hash,
                        app_code = %data.app_code,
                        container = %c.name,
                        "Config applied and container restarted"
                    );
                }
                Err(e) => {
                    body["container_restarted"] = json!(false);
                    body["restart_error"] = json!(e.to_string());
                    let error = make_error(
                        "restart_failed",
                        format!("Config applied but failed to restart container: {}", e),
                        None,
                    );
                    result.errors = Some(vec![error]);
                }
            }
        } else {
            body["container_restarted"] = json!(false);
            body["restart_error"] = json!("Container not found");
        }
    }

    result.result = Some(body);
    Ok(result)
}

/// Parse compose content and ensure all referenced env_file paths exist
/// Creates empty files if they don't exist to prevent docker compose failures
#[cfg(feature = "docker")]
async fn ensure_env_files_exist(
    compose_content: &str,
    compose_dir: &str,
    errors: &mut Vec<CommandError>,
) {
    use regex::Regex;
    use std::path::Path;

    // Match env_file entries in compose - handles both single file and list format
    // Examples:
    //   env_file: .env
    //   env_file: "/path/to/.env"
    //   env_file:
    //     - .env
    //     - "/path/to/other.env"
    let env_file_pattern = Regex::new(r#"env_file:\s*\n?\s*-?\s*["']?([^"'\n]+)["']?"#)
        .unwrap_or_else(|_| {
            // Fallback simple pattern
            Regex::new(r#"env_file:\s*["']?([^"'\n]+)["']?"#).unwrap()
        });

    // Also match list items under env_file:
    let list_item_pattern = Regex::new(r#"^\s*-\s*["']?([^"'\n]+)["']?\s*$"#).unwrap();

    let mut env_files: Vec<String> = Vec::new();

    // Find all env_file references
    for cap in env_file_pattern.captures_iter(compose_content) {
        if let Some(file_match) = cap.get(1) {
            let file_path = file_match.as_str().trim();
            if !file_path.is_empty() && !file_path.starts_with('-') {
                env_files.push(file_path.to_string());
            }
        }
    }

    // Also scan for list items following env_file:
    let mut in_env_file_section = false;
    for line in compose_content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("env_file:") {
            in_env_file_section = true;
            // Check for inline value
            let after_colon = trimmed.strip_prefix("env_file:").unwrap_or("").trim();
            if !after_colon.is_empty() && !after_colon.starts_with('-') {
                let clean = after_colon.trim_matches(|c| c == '"' || c == '\'');
                if !clean.is_empty() {
                    env_files.push(clean.to_string());
                }
            }
        } else if in_env_file_section {
            if let Some(cap) = list_item_pattern.captures(trimmed) {
                if let Some(file_match) = cap.get(1) {
                    env_files.push(file_match.as_str().trim().to_string());
                }
            } else if !trimmed.is_empty() && !trimmed.starts_with('#') {
                // End of env_file section
                in_env_file_section = false;
            }
        }
    }

    // Deduplicate
    env_files.sort();
    env_files.dedup();

    // Ensure each env file exists
    for env_file in env_files {
        let full_path = if env_file.starts_with('/') {
            env_file.clone()
        } else {
            format!("{}/{}", compose_dir, env_file)
        };

        let path = Path::new(&full_path);

        if !path.exists() {
            tracing::warn!(
                env_file = %full_path,
                "Compose references env_file that doesn't exist, creating empty file"
            );

            // Create parent directories if needed
            if let Some(parent) = path.parent() {
                if let Err(e) = tokio::fs::create_dir_all(parent).await {
                    errors.push(make_error(
                        "env_file_dir_warning",
                        format!(
                            "Failed to create directory for env file {}: {}",
                            full_path, e
                        ),
                        None,
                    ));
                    continue;
                }
            }

            // Create empty env file
            if let Err(e) = tokio::fs::write(&full_path, "# Auto-created empty env file\n").await {
                errors.push(make_error(
                    "env_file_create_warning",
                    format!("Failed to create empty env file {}: {}", full_path, e),
                    None,
                ));
            } else {
                tracing::info!(
                    env_file = %full_path,
                    "Created empty env file to prevent compose failure"
                );
            }
        }
    }
}

/// Write config file to disk with proper permissions
#[cfg(feature = "docker")]
pub async fn write_config_to_disk(config: &crate::security::vault_client::AppConfig) -> Result<()> {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    let path = Path::new(&config.destination_path);

    // Check if the destination path exists as a directory (Docker sometimes creates these)
    // If so, remove it first so we can write the file
    if path.exists() && path.is_dir() {
        tracing::warn!(
            path = %config.destination_path,
            "Destination path exists as directory, removing it to write file"
        );
        fs::remove_dir_all(path).context(format!(
            "Failed to remove directory at file destination: {}",
            config.destination_path
        ))?;
    }

    // Create parent directories if needed
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context(format!("Failed to create directory: {:?}", parent))?;
    }

    // Write the content
    fs::write(path, &config.content)
        .context(format!("Failed to write file: {}", config.destination_path))?;

    // Set file permissions
    if let Ok(mode) = u32::from_str_radix(config.file_mode.trim_start_matches('0'), 8) {
        let permissions = fs::Permissions::from_mode(mode);
        fs::set_permissions(path, permissions).context(format!(
            "Failed to set permissions on: {}",
            config.destination_path
        ))?;
    }

    tracing::info!(
        path = %config.destination_path,
        content_type = %config.content_type,
        size = config.content.len(),
        "Config file written to disk"
    );

    Ok(())
}

/// Handle deploy_app command - uses docker compose to deploy a new app/service
#[cfg(feature = "docker")]
async fn handle_deploy_app(
    agent_cmd: &AgentCommand,
    data: &DeployAppCommand,
) -> Result<CommandResult> {
    use tokio::process::Command;

    let mut result = base_result(
        agent_cmd,
        &data.deployment_hash,
        &data.app_code,
        "deploy_app",
    );
    let mut errors: Vec<CommandError> = Vec::new();

    // Determine the compose working directory
    // Standard TryDirect deployments use /home/trydirect/<deployment_hash>
    let (compose_dir, compose_file) = resolve_compose_paths(&data.deployment_hash, &data.app_code);

    // If compose_content is provided, write it to disk (for new deployments)
    if let Some(compose_content) = &data.compose_content {
        tracing::info!(
            deployment_hash = %data.deployment_hash,
            app_code = %data.app_code,
            compose_dir = %compose_dir,
            "Writing docker-compose.yml from command payload"
        );

        // Create the directory if it doesn't exist
        if let Err(e) = tokio::fs::create_dir_all(&compose_dir).await {
            let error = make_error(
                "dir_create_failed",
                format!("Failed to create directory {}: {}", compose_dir, e),
                None,
            );
            result.status = "failed".into();
            result.error = Some(error.message.clone());
            result.errors = Some(vec![error]);
            return Ok(result);
        }

        // Write the compose file
        if let Err(e) = tokio::fs::write(&compose_file, compose_content).await {
            let error = make_error(
                "compose_write_failed",
                format!("Failed to write docker-compose.yml: {}", e),
                None,
            );
            result.status = "failed".into();
            result.error = Some(error.message.clone());
            result.errors = Some(vec![error]);
            return Ok(result);
        }

        tracing::info!(
            compose_file = %compose_file,
            "docker-compose.yml written successfully"
        );
    }

    // Write config files if provided (e.g., telegraf.conf, nginx.conf, etc.)
    if let Some(config_files) = &data.config_files {
        for config in config_files {
            tracing::info!(
                app_code = %data.app_code,
                destination = %config.destination_path,
                "Writing config file from command payload"
            );
            if let Err(e) = write_config_to_disk(config).await {
                errors.push(make_error(
                    "config_write_warning",
                    format!(
                        "Failed to write config file {}: {}",
                        config.destination_path, e
                    ),
                    None,
                ));
                // Continue with other configs, don't fail entirely
            }
        }
    }

    // Write .env file from env_vars if provided
    // This handles the case where compose uses env_file: .env
    if let Some(env_vars) = &data.env_vars {
        if !env_vars.is_empty() {
            let env_file_path = format!("{}/.env", compose_dir);
            tracing::info!(
                app_code = %data.app_code,
                env_file = %env_file_path,
                var_count = env_vars.len(),
                "Writing .env file from env_vars"
            );

            // Generate .env content (KEY=VALUE format)
            let env_content: String = env_vars
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join("\n");

            if let Err(e) = tokio::fs::write(&env_file_path, &env_content).await {
                errors.push(make_error(
                    "env_file_warning",
                    format!("Failed to write .env file: {}", e),
                    None,
                ));
                // Continue anyway - compose might work without it
            } else {
                tracing::info!(
                    env_file = %env_file_path,
                    ".env file written successfully"
                );
            }
        }
    }

    // If compose_content references env_file, ensure those files exist
    // This prevents docker compose from failing due to missing env files
    if let Some(compose_content) = &data.compose_content {
        ensure_env_files_exist(compose_content, &compose_dir, &mut errors).await;
    }

    // Check if compose file exists
    if !std::path::Path::new(&compose_file).exists() {
        let error = make_error(
            "compose_not_found",
            format!("docker-compose.yml not found at {}", compose_file),
            None,
        );
        result.status = "failed".into();
        result.error = Some(error.message.clone());
        result.errors = Some(vec![error]);
        return Ok(result);
    }

    // Detect which compose variant is available (docker compose or docker-compose)
    let compose_variant = match detect_compose_variant().await {
        Some(variant) => {
            tracing::debug!(
                variant = ?variant,
                "Using compose variant"
            );
            variant
        }
        None => {
            let error = make_error(
                "compose_not_available",
                "Neither 'docker compose' (plugin) nor 'docker-compose' (standalone) is available on this system",
                Some("Install Docker Compose plugin with: apt-get install docker-compose-plugin".to_string()),
            );
            result.status = "failed".into();
            result.error = Some(error.message.clone());
            result.errors = Some(vec![error]);
            return Ok(result);
        }
    };

    let (compose_program, compose_base_args) = build_compose_command(compose_variant);

    // Step 1: Pull the image if requested
    if data.pull {
        tracing::info!(
            deployment_hash = %data.deployment_hash,
            app_code = %data.app_code,
            "Pulling docker image for service"
        );

        let mut pull_cmd = Command::new(&compose_program);
        for arg in &compose_base_args {
            pull_cmd.arg(arg);
        }
        // Don't specify service name - pull ALL services defined in compose file
        // The compose file may have services with different names than app_code
        let pull_result = pull_cmd
            .arg("-f")
            .arg(&compose_file)
            .arg("pull")
            .current_dir(&compose_dir)
            .output()
            .await;

        match pull_result {
            Ok(output) if !output.status.success() => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                errors.push(make_error(
                    "pull_warning",
                    format!("Image pull had issues (continuing): {}", stderr.trim()),
                    None,
                ));
                // Don't fail here - the image might already exist locally
            }
            Err(e) => {
                errors.push(make_error(
                    "pull_warning",
                    format!("Failed to pull image (continuing): {}", e),
                    None,
                ));
            }
            _ => {
                tracing::info!(app_code = %data.app_code, "Image pulled successfully");
            }
        }
    }

    // Step 2: If force_recreate, stop and remove existing container first
    if data.force_recreate {
        tracing::info!(
            app_code = %data.app_code,
            "Force recreating: stopping existing container"
        );

        // Don't specify service name - stop ALL services defined in compose file
        // The compose file may have services with different names than app_code
        let mut stop_cmd = Command::new(&compose_program);
        for arg in &compose_base_args {
            stop_cmd.arg(arg);
        }
        let _ = stop_cmd
            .arg("-f")
            .arg(&compose_file)
            .arg("stop")
            .current_dir(&compose_dir)
            .output()
            .await;

        let mut rm_cmd = Command::new(&compose_program);
        for arg in &compose_base_args {
            rm_cmd.arg(arg);
        }
        let _ = rm_cmd
            .arg("-f")
            .arg(&compose_file)
            .arg("rm")
            .arg("-f")
            .current_dir(&compose_dir)
            .output()
            .await;
    }

    // Step 3: Deploy using docker compose up
    tracing::info!(
        deployment_hash = %data.deployment_hash,
        app_code = %data.app_code,
        compose_dir = %compose_dir,
        "Deploying service with docker compose"
    );

    let mut compose_cmd = Command::new(&compose_program);
    for arg in &compose_base_args {
        compose_cmd.arg(arg);
    }
    // Don't specify service name - deploy ALL services defined in compose file
    // The compose file may have services with different names than app_code
    // Also removed --no-deps since we want all services to start properly
    compose_cmd
        .arg("-f")
        .arg(&compose_file)
        .arg("up")
        .arg("-d")
        .current_dir(&compose_dir);

    // Add environment variables if provided
    if let Some(env_vars) = &data.env_vars {
        for (key, value) in env_vars {
            compose_cmd.env(key, value);
        }
    }

    let deploy_result = compose_cmd.output().await;

    match deploy_result {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);

            if output.status.success() {
                tracing::info!(
                    deployment_hash = %data.deployment_hash,
                    app_code = %data.app_code,
                    "Service deployed successfully"
                );

                // Wait briefly for container to start
                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

                // Check container health
                let containers = docker::list_container_health().await.unwrap_or_default();
                let container = containers
                    .iter()
                    .find(|c| container_matches(&c.name, &data.app_code, &c.labels, &c.image));

                let container_state = if let Some(c) = container {
                    map_container_state(&c.status).to_string()
                } else {
                    "starting".to_string()
                };

                let body = json!({
                    "type": "deploy_app",
                    "deployment_hash": data.deployment_hash.clone(),
                    "app_code": data.app_code.clone(),
                    "status": "deployed",
                    "container_state": container_state,
                    "deployed_at": now_timestamp(),
                    "output": stdout.trim(),
                    "warnings": if errors.is_empty() { json!(null) } else { errors_value(&errors) },
                });

                result.result = Some(body);
                if !errors.is_empty() {
                    result.errors = Some(errors);
                }
            } else {
                let error = make_error(
                    "deploy_failed",
                    format!("Docker compose up failed: {}", stderr.trim()),
                    Some(format!(
                        "stdout: {}, stderr: {}",
                        stdout.trim(),
                        stderr.trim()
                    )),
                );
                errors.push(error.clone());

                let body = json!({
                    "type": "deploy_app",
                    "deployment_hash": data.deployment_hash.clone(),
                    "app_code": data.app_code.clone(),
                    "status": "failed",
                    "container_state": "failed",
                    "errors": errors_value(&errors),
                });

                result.status = "failed".into();
                result.error = Some(error.message);
                result.result = Some(body);
                result.errors = Some(errors);
            }
        }
        Err(e) => {
            let error = make_error(
                "deploy_exec_failed",
                format!("Failed to execute docker compose: {}", e),
                None,
            );
            errors.push(error.clone());

            let body = json!({
                "type": "deploy_app",
                "deployment_hash": data.deployment_hash.clone(),
                "app_code": data.app_code.clone(),
                "status": "failed",
                "container_state": "unknown",
                "errors": errors_value(&errors),
            });

            result.status = "failed".into();
            result.error = Some(error.message);
            result.result = Some(body);
            result.errors = Some(errors);
        }
    }

    Ok(result)
}

/// Handle remove_app command - stop and remove a service container and purge config
#[cfg(feature = "docker")]
async fn handle_remove_app(
    agent_cmd: &AgentCommand,
    data: &RemoveAppCommand,
) -> Result<CommandResult> {
    use std::path::Path;
    use tokio::process::Command;

    let mut result = base_result(
        agent_cmd,
        &data.deployment_hash,
        &data.app_code,
        "remove_app",
    );
    let mut errors: Vec<CommandError> = Vec::new();

    let (compose_dir, compose_file) = resolve_compose_paths(&data.deployment_hash, &data.app_code);

    if !Path::new(&compose_file).exists() {
        let error = make_error(
            "compose_not_found",
            format!("docker-compose.yml not found at {}", compose_file),
            None,
        );
        result.status = "failed".into();
        result.error = Some(error.message.clone());
        result.errors = Some(vec![error]);
        return Ok(result);
    }

    // Detect which compose variant is available
    let compose_variant = match detect_compose_variant().await {
        Some(variant) => variant,
        None => {
            let error = make_error(
                "compose_not_available",
                "Neither 'docker compose' (plugin) nor 'docker-compose' (standalone) is available",
                None,
            );
            result.status = "failed".into();
            result.error = Some(error.message.clone());
            result.errors = Some(vec![error]);
            return Ok(result);
        }
    };
    let (compose_program, compose_base_args) = build_compose_command(compose_variant);

    // Best-effort stop before removal
    let mut stop_cmd = Command::new(&compose_program);
    for arg in &compose_base_args {
        stop_cmd.arg(arg);
    }
    let _ = stop_cmd
        .arg("-f")
        .arg(&compose_file)
        .arg("stop")
        .arg(&data.app_code)
        .current_dir(&compose_dir)
        .output()
        .await;

    let mut rm_cmd = Command::new(&compose_program);
    for arg in &compose_base_args {
        rm_cmd.arg(arg);
    }
    rm_cmd.arg("-f").arg(&compose_file).arg("rm").arg("-f");
    if data.remove_volumes {
        rm_cmd.arg("-v");
    }
    rm_cmd.arg(&data.app_code).current_dir(&compose_dir);

    let mut removal_error: Option<CommandError> = None;
    match rm_cmd.output().await {
        Ok(output) => {
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                removal_error = Some(make_error(
                    "remove_failed",
                    format!("docker compose rm failed: {}", stderr.trim()),
                    None,
                ));
            }
        }
        Err(err) => {
            removal_error = Some(make_error(
                "remove_exec_failed",
                format!("Failed to execute docker compose rm: {}", err),
                None,
            ));
        }
    }

    if data.delete_config {
        match crate::security::vault_client::VaultClient::from_env() {
            Ok(Some(client)) => {
                if let Err(err) = client
                    .delete_app_config(&data.deployment_hash, &data.app_code)
                    .await
                {
                    errors.push(make_error(
                        "vault_cleanup_failed",
                        "App removed but failed to delete config from Vault",
                        Some(err.to_string()),
                    ));
                }
            }
            Ok(None) => {
                errors.push(make_error(
                    "vault_not_configured",
                    "Vault client not configured; skipped config cleanup",
                    None,
                ));
            }
            Err(err) => {
                errors.push(make_error(
                    "vault_init_failed",
                    "Failed to initialize Vault client for cleanup",
                    Some(err.to_string()),
                ));
            }
        }
    }

    if data.remove_image {
        let _ = Command::new("docker")
            .arg("image")
            .arg("rm")
            .arg(&data.app_code)
            .output()
            .await;
    }

    if let Some(err) = removal_error.clone() {
        errors.push(err.clone());
        result.status = "failed".into();
        result.error = Some(err.message.clone());
    }

    let body = json!({
        "type": "remove_app",
        "deployment_hash": data.deployment_hash.clone(),
        "app_code": data.app_code.clone(),
        "status": if removal_error.is_some() { "failed" } else { "removed" },
        "removed_at": now_timestamp(),
        "errors": if errors.is_empty() { json!(null) } else { errors_value(&errors) },
    });

    result.result = Some(body);
    if !errors.is_empty() {
        result.errors = Some(errors);
    }

    Ok(result)
}

/// Handle fetch_all_configs command - fetches all app configurations from Vault
#[cfg(feature = "docker")]
async fn handle_fetch_all_configs(
    agent_cmd: &AgentCommand,
    data: &FetchAllConfigsCommand,
) -> Result<CommandResult> {
    use crate::security::vault_client::VaultClient;

    let mut result = base_result(agent_cmd, &data.deployment_hash, "", "fetch_all_configs");
    let mut errors: Vec<CommandError> = Vec::new();

    // Initialize Vault client
    let vault_client = match VaultClient::from_env() {
        Ok(Some(client)) => client,
        Ok(None) => {
            let error = make_error(
                "vault_not_configured",
                "Vault client not configured. Set VAULT_ADDRESS, VAULT_TOKEN, and VAULT_AGENT_PATH_PREFIX.",
                None,
            );
            result.status = "failed".into();
            result.error = Some(error.message.clone());
            result.errors = Some(vec![error]);
            return Ok(result);
        }
        Err(e) => {
            let error = make_error(
                "vault_init_failed",
                "Failed to initialize Vault client",
                Some(e.to_string()),
            );
            result.status = "failed".into();
            result.error = Some(error.message.clone());
            result.errors = Some(vec![error]);
            return Ok(result);
        }
    };

    // Get list of apps to fetch - either from command or from Vault
    let app_codes: Vec<String> = if data.app_codes.is_empty() {
        // List all apps from Vault
        match vault_client.list_app_configs(&data.deployment_hash).await {
            Ok(apps) => apps,
            Err(e) => {
                let error = make_error(
                    "list_configs_failed",
                    "Failed to list app configs from Vault",
                    Some(e.to_string()),
                );
                result.status = "failed".into();
                result.error = Some(error.message.clone());
                result.errors = Some(vec![error]);
                return Ok(result);
            }
        }
    } else {
        data.app_codes.clone()
    };

    tracing::info!(
        deployment_hash = %data.deployment_hash,
        app_count = app_codes.len(),
        "Fetching all app configs from Vault"
    );

    // Fetch all configs
    let configs = vault_client
        .fetch_all_app_configs(&data.deployment_hash, &app_codes)
        .await
        .unwrap_or_default();

    let fetched_count = configs.len();
    let mut applied_count = 0;
    let mut config_summaries: Vec<serde_json::Value> = Vec::new();

    // Apply configs to disk if requested
    for (app_code, config) in &configs {
        let summary = json!({
            "app_code": app_code,
            "content_type": config.content_type,
            "destination_path": config.destination_path,
            "content_length": config.content.len(),
        });
        config_summaries.push(summary);

        if data.apply {
            match write_config_to_disk(config).await {
                Ok(()) => {
                    applied_count += 1;
                    tracing::info!(
                        app_code = %app_code,
                        destination = %config.destination_path,
                        "Config applied to disk"
                    );
                }
                Err(e) => {
                    errors.push(make_error(
                        "config_write_failed",
                        format!("Failed to write config for {}", app_code),
                        Some(e.to_string()),
                    ));
                }
            }
        }
    }

    // Create archive if requested
    let archive_path = if data.archive && !configs.is_empty() {
        let archive_dir = format!("/tmp/configs_{}", data.deployment_hash);
        let archive_file = format!("{}.tar.gz", archive_dir);

        // Create temp directory
        std::fs::create_dir_all(&archive_dir).ok();

        // Write configs to temp directory
        for (app_code, config) in &configs {
            let file_path = format!("{}/{}", archive_dir, app_code);
            if let Err(e) = std::fs::write(&file_path, &config.content) {
                tracing::warn!(
                    app_code = %app_code,
                    error = %e,
                    "Failed to write config to archive temp dir"
                );
            }
        }

        // Create tar.gz archive
        let tar_result = std::process::Command::new("tar")
            .args([
                "-czf",
                &archive_file,
                "-C",
                "/tmp",
                &format!("configs_{}", data.deployment_hash),
            ])
            .output();

        match tar_result {
            Ok(output) if output.status.success() => {
                // Clean up temp directory
                std::fs::remove_dir_all(&archive_dir).ok();
                Some(archive_file)
            }
            _ => {
                errors.push(make_error(
                    "archive_failed",
                    "Failed to create config archive",
                    None,
                ));
                None
            }
        }
    } else {
        None
    };

    let body = json!({
        "type": "fetch_all_configs",
        "deployment_hash": data.deployment_hash.clone(),
        "fetched_count": fetched_count,
        "applied_count": applied_count,
        "requested_count": app_codes.len(),
        "configs": config_summaries,
        "archive_path": archive_path,
        "fetched_at": now_timestamp(),
    });

    result.result = Some(body);
    if !errors.is_empty() {
        result.errors = Some(errors);
    }

    Ok(result)
}

/// Handle deploy_with_configs command - fetch configs then deploy the app
#[cfg(feature = "docker")]
async fn handle_deploy_with_configs(
    agent_cmd: &AgentCommand,
    data: &DeployWithConfigsCommand,
) -> Result<CommandResult> {
    use crate::security::vault_client::VaultClient;

    let mut result = base_result(
        agent_cmd,
        &data.deployment_hash,
        &data.app_code,
        "deploy_with_configs",
    );
    let mut errors: Vec<CommandError> = Vec::new();

    // Step 1: Fetch and apply configs if requested
    if data.apply_configs {
        tracing::info!(
            deployment_hash = %data.deployment_hash,
            app_code = %data.app_code,
            "Fetching and applying configs before deployment"
        );

        let vault_client = match VaultClient::from_env() {
            Ok(Some(client)) => Some(client),
            _ => {
                errors.push(make_error(
                    "vault_warning",
                    "Vault not configured, skipping config fetch",
                    None,
                ));
                None
            }
        };

        if let Some(vault) = vault_client {
            // Fetch compose config first (_compose special key)
            match vault
                .fetch_app_config(&data.deployment_hash, "_compose")
                .await
            {
                Ok(compose_config) => {
                    if let Err(e) = write_config_to_disk(&compose_config).await {
                        errors.push(make_error(
                            "compose_write_warning",
                            "Failed to write docker-compose.yml",
                            Some(e.to_string()),
                        ));
                    } else {
                        tracing::info!("docker-compose.yml updated from Vault");
                    }
                }
                Err(e) => {
                    tracing::debug!(
                        error = %e,
                        "No compose config found in Vault (using existing)"
                    );
                }
            }

            // Fetch app-specific config
            match vault
                .fetch_app_config(&data.deployment_hash, &data.app_code)
                .await
            {
                Ok(app_config) => {
                    if let Err(e) = write_config_to_disk(&app_config).await {
                        errors.push(make_error(
                            "config_write_warning",
                            format!("Failed to write config for {}", data.app_code),
                            Some(e.to_string()),
                        ));
                    } else {
                        tracing::info!(
                            app_code = %data.app_code,
                            "App config updated from Vault"
                        );
                    }
                }
                Err(e) => {
                    tracing::debug!(
                        app_code = %data.app_code,
                        error = %e,
                        "No app config found in Vault (continuing with deployment)"
                    );
                }
            }
        }
    }

    // Step 2: Deploy the app using the existing deploy_app handler
    let deploy_cmd = DeployAppCommand {
        deployment_hash: data.deployment_hash.clone(),
        app_code: data.app_code.clone(),
        compose_content: None, // Compose already written in step 1 from Vault
        image: None,
        env_vars: None,
        pull: data.pull,
        force_recreate: data.force_recreate,
        config_files: None, // Configs already written in step 1 from Vault
    };

    let deploy_result = handle_deploy_app(agent_cmd, &deploy_cmd).await?;

    // Merge results
    result.status = deploy_result.status;
    result.error = deploy_result.error;

    // Combine our config errors with deploy errors
    if let Some(deploy_errors) = deploy_result.errors {
        errors.extend(deploy_errors);
    }

    // Build combined result body
    let mut body = deploy_result.result.unwrap_or_else(|| json!({}));
    if let Some(obj) = body.as_object_mut() {
        obj.insert("type".into(), json!("deploy_with_configs"));
        obj.insert("configs_applied".into(), json!(data.apply_configs));
    }

    result.result = Some(body);
    if !errors.is_empty() {
        result.errors = Some(errors);
    }

    Ok(result)
}

/// Handle config_diff command - detect configuration drift between Vault and deployed files
#[cfg(feature = "docker")]
async fn handle_config_diff(
    agent_cmd: &AgentCommand,
    data: &ConfigDiffCommand,
) -> Result<CommandResult> {
    use crate::security::vault_client::VaultClient;
    use sha2::{Digest, Sha256};

    let mut result = base_result(agent_cmd, &data.deployment_hash, "", "config_diff");
    let mut errors: Vec<CommandError> = Vec::new();

    // Initialize Vault client
    let vault_client = match VaultClient::from_env() {
        Ok(Some(client)) => client,
        Ok(None) => {
            let error = make_error(
                "vault_not_configured",
                "Vault client not configured. Set VAULT_ADDRESS, VAULT_TOKEN, and VAULT_AGENT_PATH_PREFIX.",
                None,
            );
            result.status = "failed".into();
            result.error = Some(error.message.clone());
            result.errors = Some(vec![error]);
            return Ok(result);
        }
        Err(e) => {
            let error = make_error(
                "vault_init_failed",
                "Failed to initialize Vault client",
                Some(e.to_string()),
            );
            result.status = "failed".into();
            result.error = Some(error.message.clone());
            result.errors = Some(vec![error]);
            return Ok(result);
        }
    };

    // Get list of apps to check
    let app_codes: Vec<String> = if data.app_codes.is_empty() {
        match vault_client.list_app_configs(&data.deployment_hash).await {
            Ok(apps) => apps,
            Err(e) => {
                let error = make_error(
                    "list_configs_failed",
                    "Failed to list app configs from Vault",
                    Some(e.to_string()),
                );
                result.status = "failed".into();
                result.error = Some(error.message.clone());
                result.errors = Some(vec![error]);
                return Ok(result);
            }
        }
    } else {
        data.app_codes.clone()
    };

    tracing::info!(
        deployment_hash = %data.deployment_hash,
        app_count = app_codes.len(),
        "Checking config drift for apps"
    );

    let mut diffs: Vec<serde_json::Value> = Vec::new();
    let mut synced_count = 0;
    let mut drifted_count = 0;
    let mut missing_count = 0;

    for app_code in &app_codes {
        // Fetch expected config from Vault
        let vault_config = match vault_client
            .fetch_app_config(&data.deployment_hash, app_code)
            .await
        {
            Ok(config) => config,
            Err(e) => {
                errors.push(make_error(
                    "vault_fetch_failed",
                    format!("Failed to fetch config for {} from Vault", app_code),
                    Some(e.to_string()),
                ));
                continue;
            }
        };

        // Read deployed config from disk
        let deployed_content = std::fs::read_to_string(&vault_config.destination_path).ok();

        // Compute hashes for comparison
        let vault_hash = {
            let mut hasher = Sha256::new();
            hasher.update(vault_config.content.as_bytes());
            format!("{:x}", hasher.finalize())
        };

        let (deployed_hash, status, diff_content) = match &deployed_content {
            Some(content) => {
                let mut hasher = Sha256::new();
                hasher.update(content.as_bytes());
                let hash = format!("{:x}", hasher.finalize());

                if hash == vault_hash {
                    synced_count += 1;
                    (Some(hash), "synced", None)
                } else {
                    drifted_count += 1;
                    let diff = if data.include_diff {
                        // Simple line-by-line diff
                        let vault_lines: Vec<&str> = vault_config.content.lines().collect();
                        let deployed_lines: Vec<&str> = content.lines().collect();
                        Some(json!({
                            "vault_lines": vault_lines.len(),
                            "deployed_lines": deployed_lines.len(),
                            "vault_preview": vault_config.content.chars().take(500).collect::<String>(),
                            "deployed_preview": content.chars().take(500).collect::<String>(),
                        }))
                    } else {
                        None
                    };
                    (Some(hash), "drifted", diff)
                }
            }
            None => {
                missing_count += 1;
                (None, "missing", None)
            }
        };

        let mut diff_entry = json!({
            "app_code": app_code,
            "status": status,
            "destination_path": vault_config.destination_path,
            "vault_hash": vault_hash,
            "deployed_hash": deployed_hash,
        });

        if let Some(diff) = diff_content {
            diff_entry["diff"] = diff;
        }

        diffs.push(diff_entry);
    }

    let has_drift = drifted_count > 0 || missing_count > 0;

    let body = json!({
        "type": "config_diff",
        "deployment_hash": data.deployment_hash.clone(),
        "has_drift": has_drift,
        "summary": {
            "total": app_codes.len(),
            "synced": synced_count,
            "drifted": drifted_count,
            "missing": missing_count,
        },
        "configs": diffs,
        "checked_at": now_timestamp(),
    });

    result.result = Some(body);
    if !errors.is_empty() {
        result.errors = Some(errors);
    }

    Ok(result)
}

/// Handle configure_proxy command - manages nginx proxy manager proxy hosts
#[cfg(feature = "docker")]
async fn handle_configure_proxy(
    agent_cmd: &AgentCommand,
    data: &ConfigureProxyCommand,
) -> Result<CommandResult> {
    use reqwest::Client;

    let mut result = base_result(
        agent_cmd,
        &data.deployment_hash,
        &data.app_code,
        "configure_proxy",
    );

    // NPM connection settings with defaults
    let npm_host = data.npm_host.clone().unwrap_or_else(|| {
        std::env::var("NPM_HOST").unwrap_or_else(|_| "http://nginx-proxy-manager:81".to_string())
    });
    let npm_email = data.npm_email.clone().unwrap_or_else(|| {
        std::env::var("NPM_EMAIL").unwrap_or_else(|_| "admin@example.com".to_string())
    });
    let npm_password = data.npm_password.clone().unwrap_or_else(|| {
        std::env::var("NPM_PASSWORD").unwrap_or_else(|_| "changeme".to_string())
    });

    let client = Client::new();

    // Step 1: Authenticate with NPM
    tracing::info!(
        npm_host = %npm_host,
        action = %data.action,
        domains = ?data.domain_names,
        "Authenticating with Nginx Proxy Manager"
    );

    let token_response = match client
        .post(format!("{}/api/tokens", npm_host))
        .json(&json!({
            "identity": npm_email,
            "secret": npm_password
        }))
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            let error = make_error(
                "npm_connection_failed",
                "Failed to connect to Nginx Proxy Manager",
                Some(e.to_string()),
            );
            result.status = "error".to_string();
            result.error = Some(error.message.clone());
            return Ok(result);
        }
    };

    if !token_response.status().is_success() {
        let status = token_response.status();
        let body = token_response.text().await.unwrap_or_default();
        let error = make_error(
            "npm_auth_failed",
            format!("NPM authentication failed: {} - {}", status, body),
            None,
        );
        result.status = "error".to_string();
        result.error = Some(error.message.clone());
        return Ok(result);
    }

    let token_data: Value = token_response
        .json()
        .await
        .context("Failed to parse NPM token response")?;
    let token = token_data["token"]
        .as_str()
        .context("No token in NPM response")?;

    tracing::debug!("NPM authentication successful");

    // Determine forward_host (default to app_code if not specified)
    let forward_host = data
        .forward_host
        .clone()
        .unwrap_or_else(|| data.app_code.clone());

    match data.action.as_str() {
        "create" | "update" => {
            // Step 2: Create/Update proxy host
            let certificate_id: Value = if data.ssl_enabled {
                json!("new")
            } else {
                Value::Null
            };
            let proxy_host_payload = json!({
                "domain_names": data.domain_names,
                "forward_scheme": "http",
                "forward_host": forward_host,
                "forward_port": data.forward_port,
                "certificate_id": certificate_id,
                "ssl_forced": data.ssl_forced,
                "http2_support": data.http2_support,
                "block_exploits": true,
                "allow_websocket_upgrade": true,
                "access_list_id": 0,
                "meta": {
                    "letsencrypt_agree": true,
                    "dns_challenge": false
                },
                "locations": []
            });

            tracing::info!(
                forward_host = %forward_host,
                forward_port = %data.forward_port,
                ssl = %data.ssl_enabled,
                "Creating/updating proxy host in NPM"
            );

            let create_response = client
                .post(format!("{}/api/nginx/proxy-hosts", npm_host))
                .header("Authorization", format!("Bearer {}", token))
                .json(&proxy_host_payload)
                .send()
                .await;

            match create_response {
                Ok(resp) => {
                    let status = resp.status();
                    let body: Value = resp.json().await.unwrap_or(json!({}));

                    if status.is_success() {
                        tracing::info!(proxy_host_id = ?body["id"], "Proxy host created successfully");
                        result.result = Some(json!({
                            "type": "configure_proxy",
                            "action": data.action,
                            "deployment_hash": data.deployment_hash,
                            "app_code": data.app_code,
                            "status": "success",
                            "proxy_host_id": body["id"],
                            "domain_names": data.domain_names,
                            "forward_host": forward_host,
                            "forward_port": data.forward_port,
                            "ssl_enabled": data.ssl_enabled,
                            "created_at": now_timestamp(),
                        }));
                    } else {
                        let error = make_error(
                            "npm_create_failed",
                            format!("Failed to create proxy host: {} - {:?}", status, body),
                            None,
                        );
                        result.status = "error".to_string();
                        result.error = Some(error.message.clone());
                    }
                }
                Err(e) => {
                    let error = make_error(
                        "npm_request_failed",
                        "Failed to send request to NPM",
                        Some(e.to_string()),
                    );
                    result.status = "error".to_string();
                    result.error = Some(error.message.clone());
                }
            }
        }
        "delete" => {
            // Step 2: Find existing proxy host by domain
            let list_response = client
                .get(format!("{}/api/nginx/proxy-hosts", npm_host))
                .header("Authorization", format!("Bearer {}", token))
                .send()
                .await;

            match list_response {
                Ok(resp) => {
                    let hosts: Vec<Value> = resp.json().await.unwrap_or_default();

                    // Find the proxy host with matching domain
                    let matching_host = hosts.iter().find(|host| {
                        if let Some(domains) = host["domain_names"].as_array() {
                            domains.iter().any(|d| {
                                data.domain_names
                                    .iter()
                                    .any(|target| d.as_str().map(|s| s == target).unwrap_or(false))
                            })
                        } else {
                            false
                        }
                    });

                    if let Some(host) = matching_host {
                        let host_id = host["id"].as_i64().unwrap_or(0);

                        // Delete the proxy host
                        let delete_resp = client
                            .delete(format!("{}/api/nginx/proxy-hosts/{}", npm_host, host_id))
                            .header("Authorization", format!("Bearer {}", token))
                            .send()
                            .await;

                        match delete_resp {
                            Ok(resp) if resp.status().is_success() => {
                                tracing::info!(proxy_host_id = %host_id, "Proxy host deleted successfully");
                                result.result = Some(json!({
                                    "type": "configure_proxy",
                                    "action": "delete",
                                    "deployment_hash": data.deployment_hash,
                                    "app_code": data.app_code,
                                    "status": "success",
                                    "deleted_proxy_host_id": host_id,
                                    "deleted_at": now_timestamp(),
                                }));
                            }
                            Ok(resp) => {
                                let status = resp.status();
                                let body = resp.text().await.unwrap_or_default();
                                let error = make_error(
                                    "npm_delete_failed",
                                    format!("Failed to delete proxy host: {} - {}", status, body),
                                    None,
                                );
                                result.status = "error".to_string();
                                result.error = Some(error.message.clone());
                            }
                            Err(e) => {
                                let error = make_error(
                                    "npm_request_failed",
                                    "Failed to send delete request to NPM",
                                    Some(e.to_string()),
                                );
                                result.status = "error".to_string();
                                result.error = Some(error.message.clone());
                            }
                        }
                    } else {
                        // No matching proxy host found - consider it success (idempotent)
                        tracing::warn!(domains = ?data.domain_names, "No matching proxy host found to delete");
                        result.result = Some(json!({
                            "type": "configure_proxy",
                            "action": "delete",
                            "deployment_hash": data.deployment_hash,
                            "app_code": data.app_code,
                            "status": "success",
                            "message": "No matching proxy host found (already deleted?)",
                        }));
                    }
                }
                Err(e) => {
                    let error = make_error(
                        "npm_list_failed",
                        "Failed to list proxy hosts from NPM",
                        Some(e.to_string()),
                    );
                    result.status = "error".to_string();
                    result.error = Some(error.message.clone());
                }
            }
        }
        _ => {
            let error = make_error(
                "invalid_action",
                format!(
                    "Unknown action: {}. Valid actions: create, update, delete",
                    data.action
                ),
                None,
            );
            result.status = "error".to_string();
            result.error = Some(error.message.clone());
        }
    }

    Ok(result)
}

#[cfg(feature = "docker")]
fn build_metrics(container: &docker::ContainerHealth) -> Value {
    json!({
        "cpu_pct": container.cpu_pct,
        "mem_pct": container.mem_pct,
        "mem_usage_mb": (container.mem_usage_bytes as f64 / (1024.0 * 1024.0)),
        "mem_limit_bytes": container.mem_limit_bytes,
        "rx_bytes": container.rx_bytes,
        "tx_bytes": container.tx_bytes,
    })
}

#[cfg(feature = "docker")]
fn container_matches(
    name: &str,
    app_code: &str,
    labels: &HashMap<String, String>,
    image: &str,
) -> bool {
    if let Some(service) = labels.get("com.docker.compose.service") {
        if service == app_code {
            return true;
        }
    }

    let normalized_app = normalize_app_code(app_code);
    let normalized_image = image.to_lowercase();
    if !normalized_image.is_empty() && normalized_image.contains(&normalized_app) {
        return true;
    }

    let normalized = name.trim_start_matches('/');
    let normalized_name = normalize_app_code(normalized);
    normalized == app_code
        || normalized == format!("{}_1", app_code)
        || normalized.ends_with(&format!("-{}", app_code))
        || normalized.ends_with(&format!("_{}", app_code))
        || normalized.ends_with(&format!("_{}_1", app_code))
        || normalized.ends_with(&format!("-{}-1", app_code))
        || normalized_name == normalized_app
}

#[cfg(feature = "docker")]
fn normalize_app_code(value: &str) -> String {
    value
        .to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect()
}

#[cfg(feature = "docker")]
fn map_container_state(raw: &str) -> &'static str {
    let normalized = raw.trim().to_lowercase();
    if normalized.contains("running") {
        "running"
    } else if normalized.contains("restart") || normalized.contains("start") {
        "starting"
    } else if normalized.contains("exit") || normalized.contains("stop") {
        "exited"
    } else if normalized.contains("dead")
        || normalized.contains("kill")
        || normalized.contains("fail")
    {
        "failed"
    } else {
        "unknown"
    }
}

#[cfg(feature = "docker")]
fn derive_health_status(container_state: &str, has_errors: bool) -> &'static str {
    if has_errors {
        "unhealthy"
    } else {
        match container_state {
            "running" => "ok",
            "starting" | "exited" | "failed" => "unhealthy",
            _ => "unknown",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    macro_rules! stacker_test {
        ($name:ident, $cmd_name:expr, $payload:expr, $variant:path) => {
            #[test]
            fn $name() {
                let cmd = AgentCommand {
                    id: "cmd-test".into(),
                    command_id: "cmd-test".into(),
                    name: $cmd_name.into(),
                    params: $payload,
                    deployment_hash: Some("testhash".into()),
                    app_code: Some("testapp".into()),
                };
                let parsed = parse_stacker_command(&cmd).unwrap();
                match parsed {
                    Some($variant(_)) => {}
                    _ => panic!("Did not parse {} command correctly", $cmd_name),
                }
            }
        };
    }

    stacker_test!(
        parses_health_command,
        "health",
        json!({}),
        StackerCommand::Health
    );
    stacker_test!(
        parses_logs_command,
        "logs",
        json!({"container": "test"}),
        StackerCommand::Logs
    );
    stacker_test!(
        parses_restart_command,
        "restart",
        json!({"container": "test"}),
        StackerCommand::Restart
    );
    stacker_test!(
        parses_stop_command,
        "stop",
        json!({"container": "test"}),
        StackerCommand::Stop
    );
    stacker_test!(
        parses_start_command,
        "start",
        json!({"container": "test"}),
        StackerCommand::Start
    );
    stacker_test!(
        parses_error_summary_command,
        "error_summary",
        json!({}),
        StackerCommand::ErrorSummary
    );
    stacker_test!(
        parses_fetch_config_command,
        "fetch_config",
        json!({}),
        StackerCommand::FetchConfig
    );
    stacker_test!(
        parses_apply_config_command,
        "apply_config",
        json!({}),
        StackerCommand::ApplyConfig
    );
    stacker_test!(
        parses_deploy_app_command,
        "deploy_app",
        json!({
            "deployment_hash": "testhash",
            "app_code": "testapp",
            "image": "testimage:latest",
            "pull": true,
            "force_recreate": false
        }),
        StackerCommand::DeployApp
    );
    stacker_test!(
        parses_fetch_all_configs_command,
        "fetch_all_configs",
        json!({
            "deployment_hash": "testhash",
            "apply": true,
            "archive": false
        }),
        StackerCommand::FetchAllConfigs
    );
    stacker_test!(
        parses_deploy_with_configs_command,
        "deploy_with_configs",
        json!({
            "deployment_hash": "testhash",
            "app_code": "testapp",
            "pull": true,
            "apply_configs": true
        }),
        StackerCommand::DeployWithConfigs
    );
    stacker_test!(
        parses_config_diff_command,
        "config_diff",
        json!({
            "deployment_hash": "testhash",
            "include_diff": true
        }),
        StackerCommand::ConfigDiff
    );

    #[test]
    fn ignores_unknown_command() {
        let cmd = AgentCommand {
            id: "cmd-2".into(),
            command_id: "cmd-2".into(),
            name: "shell".into(),
            params: json!({}),
            deployment_hash: None,
            app_code: None,
        };

        let parsed = parse_stacker_command(&cmd).unwrap();
        assert!(parsed.is_none());
    }
}

#[cfg(all(test, feature = "docker"))]
mod write_config_tests {
    use super::write_config_to_disk;
    use crate::security::vault_client::AppConfig;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_write_config_to_disk_creates_file_and_sets_permissions() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.conf");
        let file_path_str = file_path.to_str().unwrap().to_string();
        let config = AppConfig {
            content: "key=value".to_string(),
            content_type: "env".to_string(),
            destination_path: file_path_str.clone(),
            file_mode: "0600".to_string(),
            owner: None,
            group: None,
        };

        write_config_to_disk(&config)
            .await
            .expect("write should succeed");

        println!("Test config written to: {}", file_path_str);
        // Pause for 10 seconds to allow manual inspection
        std::thread::sleep(std::time::Duration::from_secs(10));

        let written = fs::read_to_string(&file_path).expect("file should exist");
        assert_eq!(written, "key=value");

        let metadata = fs::metadata(&file_path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
