use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

// Store user deployment attempts for a specific project
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Deployment {
    pub id: i32,                 // id - is a unique identifier for the app project
    pub project_id: i32,         // external project ID
    pub deployment_hash: String, // unique hash for agent identification
    pub user_id: Option<String>, // user who created the deployment (nullable in db)
    pub deleted: Option<bool>,
    pub status: String,
    pub runtime: String, // container runtime: "runc" or "kata"
    pub metadata: Value, // renamed from 'body' to 'metadata'
    pub last_seen_at: Option<DateTime<Utc>>, // last heartbeat from agent
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Deployment {
    pub fn new(
        project_id: i32,
        user_id: Option<String>,
        deployment_hash: String,
        status: String,
        runtime: String,
        metadata: Value,
    ) -> Self {
        Self {
            id: 0,
            project_id,
            deployment_hash,
            user_id,
            deleted: Some(false),
            status,
            runtime,
            metadata,
            last_seen_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }
}

impl Default for Deployment {
    fn default() -> Self {
        Deployment {
            id: 0,
            project_id: 0,
            deployment_hash: String::new(),
            user_id: None,
            deleted: Some(false),
            status: "pending".to_string(),
            runtime: "runc".to_string(),
            metadata: Value::Null,
            last_seen_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deployment_new() {
        let deployment = Deployment::new(
            1,
            Some("user1".to_string()),
            "hash-abc".to_string(),
            "running".to_string(),
            "runc".to_string(),
            serde_json::json!({"apps": ["nginx"]}),
        );
        assert_eq!(deployment.id, 0);
        assert_eq!(deployment.project_id, 1);
        assert_eq!(deployment.user_id, Some("user1".to_string()));
        assert_eq!(deployment.deployment_hash, "hash-abc");
        assert_eq!(deployment.status, "running");
        assert_eq!(deployment.runtime, "runc");
        assert_eq!(deployment.deleted, Some(false));
        assert!(deployment.last_seen_at.is_none());
    }

    #[test]
    fn test_deployment_new_no_user() {
        let deployment = Deployment::new(
            2,
            None,
            "hash-xyz".to_string(),
            "pending".to_string(),
            "runc".to_string(),
            Value::Null,
        );
        assert!(deployment.user_id.is_none());
    }

    #[test]
    fn test_deployment_default() {
        let deployment = Deployment::default();
        assert_eq!(deployment.id, 0);
        assert_eq!(deployment.project_id, 0);
        assert_eq!(deployment.deployment_hash, "");
        assert!(deployment.user_id.is_none());
        assert_eq!(deployment.deleted, Some(false));
        assert_eq!(deployment.status, "pending");
        assert_eq!(deployment.runtime, "runc");
        assert_eq!(deployment.metadata, Value::Null);
    }

    #[test]
    fn test_deployment_serialization() {
        let deployment = Deployment::new(
            1,
            Some("user1".to_string()),
            "test-hash".to_string(),
            "active".to_string(),
            "kata".to_string(),
            serde_json::json!({}),
        );
        let json = serde_json::to_string(&deployment).unwrap();
        let deserialized: Deployment = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.project_id, 1);
        assert_eq!(deserialized.deployment_hash, "test-hash");
        assert_eq!(deserialized.status, "active");
    }
}
