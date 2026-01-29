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
    FetchAllConfigs(FetchAllConfigsCommand),
    DeployWithConfigs(DeployWithConfigsCommand),
    ConfigDiff(ConfigDiffCommand),
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

fn trimmed(value: &str) -> String {
    value.trim().to_string()
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
        StackerCommand::FetchAllConfigs(data) => handle_fetch_all_configs(agent_cmd, data).await,
        StackerCommand::DeployWithConfigs(data) => {
            handle_deploy_with_configs(agent_cmd, data).await
        }
        StackerCommand::ConfigDiff(data) => handle_config_diff(agent_cmd, data).await,
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

/// Write config file to disk with proper permissions
#[cfg(feature = "docker")]
pub async fn write_config_to_disk(config: &crate::security::vault_client::AppConfig) -> Result<()> {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    let path = Path::new(&config.destination_path);

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
    let compose_dir = std::env::var("COMPOSE_PROJECT_DIR")
        .unwrap_or_else(|_| format!("/home/trydirect/{}", data.app_code));

    // Check if compose file exists
    let compose_file = format!("{}/docker-compose.yml", compose_dir);
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

    // Step 1: Pull the image if requested
    if data.pull {
        tracing::info!(
            deployment_hash = %data.deployment_hash,
            app_code = %data.app_code,
            "Pulling docker image for service"
        );

        let pull_result = Command::new("docker")
            .arg("compose")
            .arg("-f")
            .arg(&compose_file)
            .arg("pull")
            .arg(&data.app_code)
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

        let _ = Command::new("docker")
            .arg("compose")
            .arg("-f")
            .arg(&compose_file)
            .arg("stop")
            .arg(&data.app_code)
            .current_dir(&compose_dir)
            .output()
            .await;

        let _ = Command::new("docker")
            .arg("compose")
            .arg("-f")
            .arg(&compose_file)
            .arg("rm")
            .arg("-f")
            .arg(&data.app_code)
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

    let mut compose_cmd = Command::new("docker");
    compose_cmd
        .arg("compose")
        .arg("-f")
        .arg(&compose_file)
        .arg("up")
        .arg("-d")
        .arg("--no-deps") // Don't start linked services
        .arg(&data.app_code)
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
        image: None,
        env_vars: None,
        pull: data.pull,
        force_recreate: data.force_recreate,
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
