use anyhow::{bail, Context, Result};
use chrono::{SecondsFormat, Utc};
use regex::Regex;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::OnceLock;

use crate::transport::{Command as AgentCommand, CommandError, CommandResult};

#[cfg(feature = "docker")]
use crate::agent::docker;

const LOGS_DEFAULT_LIMIT: usize = 400;
const LOGS_MAX_LIMIT: usize = 1000;

#[derive(Debug, Clone)]
pub enum StackerCommand {
    Health(HealthCommand),
    Logs(LogsCommand),
    Restart(RestartCommand),
}

#[derive(Debug, Clone, Deserialize)]
struct HealthCommand {
    deployment_hash: String,
    app_code: String,
    #[serde(default = "default_true")]
    include_metrics: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct LogsCommand {
    deployment_hash: String,
    app_code: String,
    cursor: Option<String>,
    #[serde(default = "default_logs_limit")]
    limit: usize,
    #[serde(default)]
    streams: Option<Vec<String>>,
    #[serde(default = "default_true")]
    redact: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct RestartCommand {
    deployment_hash: String,
    app_code: String,
    #[serde(default)]
    force: bool,
}

pub fn parse_stacker_command(cmd: &AgentCommand) -> Result<Option<StackerCommand>> {
    let normalized = cmd.name.trim().to_lowercase();
    match normalized.as_str() {
        "health" | "stacker.health" => {
            let payload: HealthCommand =
                serde_json::from_value(cmd.params.clone()).context("invalid health payload")?;
            let payload = payload.normalize();
            payload.validate()?;
            Ok(Some(StackerCommand::Health(payload)))
        }
        "logs" | "stacker.logs" => {
            let payload: LogsCommand =
                serde_json::from_value(cmd.params.clone()).context("invalid logs payload")?;
            let payload = payload.normalize();
            payload.validate()?;
            Ok(Some(StackerCommand::Logs(payload)))
        }
        "restart" | "stacker.restart" => {
            let payload: RestartCommand =
                serde_json::from_value(cmd.params.clone()).context("invalid restart payload")?;
            let payload = payload.normalize();
            payload.validate()?;
            Ok(Some(StackerCommand::Restart(payload)))
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
        bail!("docker feature not enabled for stacker commands")
    }
}

fn default_true() -> bool {
    true
}

fn default_logs_limit() -> usize {
    LOGS_DEFAULT_LIMIT
}

impl HealthCommand {
    fn normalize(mut self) -> Self {
        self.deployment_hash = trimmed(&self.deployment_hash);
        self.app_code = trimmed(&self.app_code);
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
            self.streams = if filtered.is_empty() { None } else { Some(filtered) };
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

fn trimmed(value: &str) -> String {
    value.trim().to_string()
}

fn base_result(
    agent_cmd: &AgentCommand,
    deployment_hash: &str,
    app_code: &str,
    command_type: &str,
) -> CommandResult {
    CommandResult {
        command_id: agent_cmd.id.clone(),
        status: "success".into(),
        result: None,
        error: None,
        deployment_hash: Some(deployment_hash.to_string()),
        app_code: Some(app_code.to_string()),
        command_type: Some(command_type.to_string()),
        ..CommandResult::default()
    }
}

fn now_timestamp() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn errors_value(errors: &[CommandError]) -> Value {
    serde_json::to_value(errors).unwrap_or_else(|_| json!([]))
}

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
    }
}

#[cfg(feature = "docker")]
async fn handle_health(
    agent_cmd: &AgentCommand,
    data: &HealthCommand,
) -> Result<CommandResult> {
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
        .find(|c| container_matches(&c.name, &data.app_code));

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
    let window = match docker::get_container_logs_window(&data.app_code, data.cursor.clone(), Some(data.limit)).await {
        Ok(win) => win,
        Err(e) => {
            let error = make_error(
                "log_fetch_failed",
                "Failed to fetch container logs",
                Some(e.to_string()),
            );
            let errors = vec![error.clone()];
            let body = json!({
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
        "cursor": window.next_cursor,
        "truncated": window.truncated,
        "lines": lines,
    });

    result.result = Some(body);
    Ok(result)
}

#[cfg(feature = "docker")]
async fn handle_restart(
    agent_cmd: &AgentCommand,
    data: &RestartCommand,
) -> Result<CommandResult> {
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
        .find(|c| container_matches(&c.name, &data.app_code));
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
fn container_matches(name: &str, app_code: &str) -> bool {
    let normalized = name.trim_start_matches('/');
    normalized == app_code
        || normalized == format!("{}_1", app_code)
        || normalized.ends_with(&format!("-{}", app_code))
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
    } else if normalized.contains("dead") || normalized.contains("kill") || normalized.contains("fail")
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

    #[test]
    fn parses_health_command() {
        let cmd = AgentCommand {
            id: "cmd-1".into(),
            name: "health".into(),
            params: json!({
                "deployment_hash": "dep",
                "app_code": "web",
            }),
        };

        let parsed = parse_stacker_command(&cmd).unwrap();
        assert!(matches!(parsed, Some(StackerCommand::Health(_))));
    }

    #[test]
    fn ignores_unknown_command() {
        let cmd = AgentCommand {
            id: "cmd-2".into(),
            name: "shell".into(),
            params: json!({}),
        };

        let parsed = parse_stacker_command(&cmd).unwrap();
        assert!(parsed.is_none());
    }
}
