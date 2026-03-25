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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_logger_creation() {
        let logger = AuditLogger::new();
        // Verify Debug trait works
        let _ = format!("{:?}", logger);
    }

    #[test]
    fn audit_logger_default() {
        let logger = AuditLogger::default();
        let _ = format!("{:?}", logger);
    }

    #[test]
    fn audit_logger_auth_success_does_not_panic() {
        let logger = AuditLogger::new();
        logger.auth_success("agent-1", Some("req-1"), "login");
        logger.auth_success("agent-1", None, "login");
    }

    #[test]
    fn audit_logger_auth_failure_does_not_panic() {
        let logger = AuditLogger::new();
        logger.auth_failure(Some("agent-1"), Some("req-1"), "bad password");
        logger.auth_failure(None, None, "unknown agent");
    }

    #[test]
    fn audit_logger_signature_invalid_does_not_panic() {
        let logger = AuditLogger::new();
        logger.signature_invalid(Some("agent-1"), Some("req-1"));
        logger.signature_invalid(None, None);
    }

    #[test]
    fn audit_logger_rate_limited_does_not_panic() {
        let logger = AuditLogger::new();
        logger.rate_limited("agent-1", Some("req-1"));
        logger.rate_limited("agent-1", None);
    }

    #[test]
    fn audit_logger_replay_detected_does_not_panic() {
        let logger = AuditLogger::new();
        logger.replay_detected(Some("agent-1"), Some("req-1"));
        logger.replay_detected(None, None);
    }

    #[test]
    fn audit_logger_scope_denied_does_not_panic() {
        let logger = AuditLogger::new();
        logger.scope_denied("agent-1", Some("req-1"), "docker:restart");
        logger.scope_denied("agent-1", None, "admin");
    }

    #[test]
    fn audit_logger_command_executed_does_not_panic() {
        let logger = AuditLogger::new();
        logger.command_executed("agent-1", Some("req-1"), "cmd-1", "restart");
        logger.command_executed("agent-1", None, "cmd-2", "stop");
    }

    #[test]
    fn audit_logger_token_rotated_does_not_panic() {
        let logger = AuditLogger::new();
        logger.token_rotated("agent-1", Some("req-1"));
        logger.token_rotated("agent-1", None);
    }

    #[test]
    fn audit_logger_internal_error_does_not_panic() {
        let logger = AuditLogger::new();
        logger.internal_error(Some("agent-1"), Some("req-1"), "database timeout");
        logger.internal_error(None, None, "unknown error");
    }

    #[test]
    fn audit_logger_clone() {
        let logger = AuditLogger::new();
        let cloned = logger.clone();
        cloned.auth_success("agent-1", None, "test");
    }
}
