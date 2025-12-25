use tracing::{error, info, warn};

#[derive(Debug, Clone, Default)]
pub struct AuditLogger;

impl AuditLogger {
    pub fn new() -> Self {
        Self
    }

    pub fn auth_success(&self, agent_id: &str, request_id: Option<&str>, action: &str) {
        info!(target: "audit", event = "auth_success", agent_id, request_id = request_id.unwrap_or(""), action);
    }

    pub fn auth_failure(&self, agent_id: Option<&str>, request_id: Option<&str>, reason: &str) {
        warn!(target: "audit", event = "auth_failure", agent_id = agent_id.unwrap_or("") , request_id = request_id.unwrap_or(""), reason);
    }

    pub fn signature_invalid(&self, agent_id: Option<&str>, request_id: Option<&str>) {
        warn!(target: "audit", event = "signature_invalid", agent_id = agent_id.unwrap_or("") , request_id = request_id.unwrap_or(""));
    }

    pub fn rate_limited(&self, agent_id: &str, request_id: Option<&str>) {
        warn!(target: "audit", event = "rate_limited", agent_id, request_id = request_id.unwrap_or(""));
    }

    pub fn replay_detected(&self, agent_id: Option<&str>, request_id: Option<&str>) {
        warn!(target: "audit", event = "replay_detected", agent_id = agent_id.unwrap_or("") , request_id = request_id.unwrap_or(""));
    }

    pub fn scope_denied(&self, agent_id: &str, request_id: Option<&str>, scope: &str) {
        warn!(target: "audit", event = "scope_denied", agent_id, request_id = request_id.unwrap_or(""), scope);
    }

    pub fn command_executed(
        &self,
        agent_id: &str,
        request_id: Option<&str>,
        command_id: &str,
        name: &str,
    ) {
        info!(target: "audit", event = "command_executed", agent_id, request_id = request_id.unwrap_or(""), command_id, name);
    }

    pub fn token_rotated(&self, agent_id: &str, request_id: Option<&str>) {
        info!(target: "audit", event = "token_rotated", agent_id, request_id = request_id.unwrap_or(""));
    }

    pub fn internal_error(
        &self,
        agent_id: Option<&str>,
        request_id: Option<&str>,
        error_msg: &str,
    ) {
        error!(target: "audit", event = "internal_error", agent_id = agent_id.unwrap_or("") , request_id = request_id.unwrap_or(""), error = error_msg);
    }
}
