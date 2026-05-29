use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Agent {
    pub id: Uuid,
    pub deployment_hash: String,
    pub capabilities: Option<Value>,
    pub version: Option<String>,
    pub system_info: Option<Value>,
    pub last_heartbeat: Option<DateTime<Utc>>,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Agent {
    pub fn new(deployment_hash: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            deployment_hash,
            capabilities: Some(serde_json::json!([])),
            version: None,
            system_info: Some(serde_json::json!({})),
            last_heartbeat: None,
            status: "offline".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    pub fn is_online(&self) -> bool {
        self.status == "online"
    }

    pub fn mark_online(&mut self) {
        self.status = "online".to_string();
        self.last_heartbeat = Some(Utc::now());
        self.updated_at = Utc::now();
    }

    pub fn mark_offline(&mut self) {
        self.status = "offline".to_string();
        self.updated_at = Utc::now();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AuditLog {
    pub id: Uuid,
    pub agent_id: Option<Uuid>,
    pub deployment_hash: Option<String>,
    pub action: String,
    pub status: Option<String>,
    pub details: serde_json::Value,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl AuditLog {
    pub fn new(
        agent_id: Option<Uuid>,
        deployment_hash: Option<String>,
        action: String,
        status: Option<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            agent_id,
            deployment_hash,
            action,
            status,
            details: serde_json::json!({}),
            ip_address: None,
            user_agent: None,
            created_at: Utc::now(),
        }
    }

    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = details;
        self
    }

    pub fn with_ip(mut self, ip: String) -> Self {
        self.ip_address = Some(ip);
        self
    }

    pub fn with_user_agent(mut self, user_agent: String) -> Self {
        self.user_agent = Some(user_agent);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Agent tests
    #[test]
    fn test_agent_new() {
        let agent = Agent::new("deploy-hash-123".to_string());
        assert_eq!(agent.deployment_hash, "deploy-hash-123");
        assert_eq!(agent.status, "offline");
        assert!(agent.last_heartbeat.is_none());
        assert_eq!(agent.capabilities, Some(serde_json::json!([])));
        assert_eq!(agent.system_info, Some(serde_json::json!({})));
        assert!(agent.version.is_none());
    }

    #[test]
    fn test_agent_is_online_when_offline() {
        let agent = Agent::new("h".to_string());
        assert!(!agent.is_online());
    }

    #[test]
    fn test_agent_mark_online() {
        let mut agent = Agent::new("h".to_string());
        assert!(!agent.is_online());
        agent.mark_online();
        assert!(agent.is_online());
        assert!(agent.last_heartbeat.is_some());
    }

    #[test]
    fn test_agent_mark_offline() {
        let mut agent = Agent::new("h".to_string());
        agent.mark_online();
        assert!(agent.is_online());
        agent.mark_offline();
        assert!(!agent.is_online());
    }

    #[test]
    fn test_agent_online_offline_cycle() {
        let mut agent = Agent::new("h".to_string());
        for _ in 0..3 {
            agent.mark_online();
            assert!(agent.is_online());
            agent.mark_offline();
            assert!(!agent.is_online());
        }
    }

    // AuditLog tests
    #[test]
    fn test_audit_log_new() {
        let agent_id = Uuid::new_v4();
        let log = AuditLog::new(
            Some(agent_id),
            Some("hash-1".to_string()),
            "deploy".to_string(),
            Some("success".to_string()),
        );
        assert_eq!(log.agent_id, Some(agent_id));
        assert_eq!(log.deployment_hash, Some("hash-1".to_string()));
        assert_eq!(log.action, "deploy");
        assert_eq!(log.status, Some("success".to_string()));
        assert_eq!(log.details, serde_json::json!({}));
        assert!(log.ip_address.is_none());
        assert!(log.user_agent.is_none());
    }

    #[test]
    fn test_audit_log_new_minimal() {
        let log = AuditLog::new(None, None, "heartbeat".to_string(), None);
        assert!(log.agent_id.is_none());
        assert!(log.deployment_hash.is_none());
        assert!(log.status.is_none());
    }

    #[test]
    fn test_audit_log_with_details() {
        let log = AuditLog::new(None, None, "test".to_string(), None)
            .with_details(serde_json::json!({"error": "timeout"}));
        assert_eq!(log.details, serde_json::json!({"error": "timeout"}));
    }

    #[test]
    fn test_audit_log_with_ip() {
        let log =
            AuditLog::new(None, None, "test".to_string(), None).with_ip("192.168.1.1".to_string());
        assert_eq!(log.ip_address, Some("192.168.1.1".to_string()));
    }

    #[test]
    fn test_audit_log_with_user_agent() {
        let log = AuditLog::new(None, None, "test".to_string(), None)
            .with_user_agent("Mozilla/5.0".to_string());
        assert_eq!(log.user_agent, Some("Mozilla/5.0".to_string()));
    }

    #[test]
    fn test_audit_log_builder_chaining() {
        let log = AuditLog::new(None, None, "test".to_string(), None)
            .with_details(serde_json::json!({"key": "value"}))
            .with_ip("10.0.0.1".to_string())
            .with_user_agent("curl/7.68".to_string());
        assert_eq!(log.details, serde_json::json!({"key": "value"}));
        assert_eq!(log.ip_address, Some("10.0.0.1".to_string()));
        assert_eq!(log.user_agent, Some("curl/7.68".to_string()));
    }
}
