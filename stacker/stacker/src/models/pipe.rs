use serde::{Deserialize, Serialize};
use sqlx::types::chrono::{DateTime, Utc};
use sqlx::types::uuid::Uuid;
use sqlx::types::JsonValue;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// PipeTemplate — reusable pipe definitions
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct PipeTemplate {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub source_app_type: String,
    pub source_endpoint: JsonValue,
    pub target_app_type: String,
    pub target_endpoint: JsonValue,
    pub target_external_url: Option<String>,
    pub field_mapping: JsonValue,
    pub config: Option<JsonValue>,
    pub is_public: Option<bool>,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl PipeTemplate {
    pub fn new(
        name: String,
        source_app_type: String,
        source_endpoint: JsonValue,
        target_app_type: String,
        target_endpoint: JsonValue,
        field_mapping: JsonValue,
        created_by: String,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            name,
            description: None,
            source_app_type,
            source_endpoint,
            target_app_type,
            target_endpoint,
            target_external_url: None,
            field_mapping,
            config: None,
            is_public: Some(false),
            created_by,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    pub fn with_description(mut self, description: String) -> Self {
        self.description = Some(description);
        self
    }

    pub fn with_external_url(mut self, url: String) -> Self {
        self.target_external_url = Some(url);
        self
    }

    pub fn with_config(mut self, config: JsonValue) -> Self {
        self.config = Some(config);
        self
    }

    pub fn with_public(mut self, is_public: bool) -> Self {
        self.is_public = Some(is_public);
        self
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// PipeStatus — pipe instance lifecycle states
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PipeStatus {
    Draft,
    Active,
    Paused,
    Error,
}

impl std::fmt::Display for PipeStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PipeStatus::Draft => write!(f, "draft"),
            PipeStatus::Active => write!(f, "active"),
            PipeStatus::Paused => write!(f, "paused"),
            PipeStatus::Error => write!(f, "error"),
        }
    }
}

impl Default for PipeStatus {
    fn default() -> Self {
        PipeStatus::Draft
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// PipeInstance — deployment-specific pipe activations
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct PipeInstance {
    pub id: Uuid,
    pub template_id: Option<Uuid>,
    pub deployment_hash: Option<String>,
    pub source_adapter: Option<JsonValue>,
    pub source_container: String,
    pub target_adapter: Option<JsonValue>,
    pub target_container: Option<String>,
    pub target_url: Option<String>,
    pub field_mapping_override: Option<JsonValue>,
    pub config_override: Option<JsonValue>,
    pub status: String,
    pub last_triggered_at: Option<DateTime<Utc>>,
    pub trigger_count: i64,
    pub error_count: i64,
    pub is_local: bool,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl PipeInstance {
    pub fn new(deployment_hash: String, source_container: String, created_by: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            template_id: None,
            deployment_hash: Some(deployment_hash),
            source_adapter: None,
            source_container,
            target_adapter: None,
            target_container: None,
            target_url: None,
            field_mapping_override: None,
            config_override: None,
            status: PipeStatus::Draft.to_string(),
            last_triggered_at: None,
            trigger_count: 0,
            error_count: 0,
            is_local: false,
            created_by,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    /// Create a local pipe instance (no deployment required).
    pub fn new_local(source_container: String, created_by: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            template_id: None,
            deployment_hash: None,
            source_adapter: None,
            source_container,
            target_adapter: None,
            target_container: None,
            target_url: None,
            field_mapping_override: None,
            config_override: None,
            status: PipeStatus::Draft.to_string(),
            last_triggered_at: None,
            trigger_count: 0,
            error_count: 0,
            is_local: true,
            created_by,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    pub fn with_template(mut self, template_id: Uuid) -> Self {
        self.template_id = Some(template_id);
        self
    }

    pub fn with_target_container(mut self, container: String) -> Self {
        self.target_container = Some(container);
        self
    }

    pub fn with_source_adapter(mut self, adapter: JsonValue) -> Self {
        self.source_adapter = Some(adapter);
        self
    }

    pub fn with_target_adapter(mut self, adapter: JsonValue) -> Self {
        self.target_adapter = Some(adapter);
        self
    }

    pub fn with_target_url(mut self, url: String) -> Self {
        self.target_url = Some(url);
        self
    }

    pub fn with_field_mapping_override(mut self, mapping: JsonValue) -> Self {
        self.field_mapping_override = Some(mapping);
        self
    }

    pub fn with_config_override(mut self, config: JsonValue) -> Self {
        self.config_override = Some(config);
        self
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// PipeExecution — full execution history for pipe triggers
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct PipeExecution {
    pub id: Uuid,
    pub pipe_instance_id: Uuid,
    pub deployment_hash: Option<String>,
    pub trigger_type: String,
    pub status: String,
    pub source_data: Option<JsonValue>,
    pub mapped_data: Option<JsonValue>,
    pub target_response: Option<JsonValue>,
    pub error: Option<String>,
    pub duration_ms: Option<i64>,
    pub replay_of: Option<Uuid>,
    pub is_local: bool,
    pub created_by: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

impl PipeExecution {
    pub fn new(
        pipe_instance_id: Uuid,
        deployment_hash: Option<String>,
        trigger_type: String,
        created_by: String,
    ) -> Self {
        let is_local = deployment_hash.is_none();
        Self {
            id: Uuid::new_v4(),
            pipe_instance_id,
            deployment_hash,
            trigger_type,
            status: "running".to_string(),
            source_data: None,
            mapped_data: None,
            target_response: None,
            error: None,
            duration_ms: None,
            replay_of: None,
            is_local,
            created_by,
            started_at: Utc::now(),
            completed_at: None,
        }
    }

    pub fn with_replay_of(mut self, original_id: Uuid) -> Self {
        self.replay_of = Some(original_id);
        self
    }

    pub fn complete_success(
        mut self,
        source_data: JsonValue,
        mapped_data: JsonValue,
        target_response: JsonValue,
    ) -> Self {
        let now = Utc::now();
        self.status = "success".to_string();
        self.source_data = Some(source_data);
        self.mapped_data = Some(mapped_data);
        self.target_response = Some(target_response);
        self.duration_ms = Some((now - self.started_at).num_milliseconds());
        self.completed_at = Some(now);
        self
    }

    pub fn complete_failure(mut self, error: String) -> Self {
        let now = Utc::now();
        self.status = "failed".to_string();
        self.error = Some(error);
        self.duration_ms = Some((now - self.started_at).num_milliseconds());
        self.completed_at = Some(now);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_pipe_status_display() {
        assert_eq!(PipeStatus::Draft.to_string(), "draft");
        assert_eq!(PipeStatus::Active.to_string(), "active");
        assert_eq!(PipeStatus::Paused.to_string(), "paused");
        assert_eq!(PipeStatus::Error.to_string(), "error");
    }

    #[test]
    fn test_pipe_status_default() {
        assert_eq!(PipeStatus::default(), PipeStatus::Draft);
    }

    #[test]
    fn test_pipe_status_serde_roundtrip() {
        let status = PipeStatus::Active;
        let serialized = serde_json::to_string(&status).unwrap();
        assert_eq!(serialized, "\"active\"");
        let deserialized: PipeStatus = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, PipeStatus::Active);
    }

    #[test]
    fn test_pipe_template_new() {
        let template = PipeTemplate::new(
            "wordpress-to-mailchimp".to_string(),
            "wordpress".to_string(),
            json!({"path": "/wp-json/wp/v2/users", "method": "POST"}),
            "mailchimp".to_string(),
            json!({"path": "/3.0/lists/{list_id}/members", "method": "POST"}),
            json!({"email": "$.user_email", "name": "$.display_name"}),
            "user123".to_string(),
        );

        assert_eq!(template.name, "wordpress-to-mailchimp");
        assert_eq!(template.source_app_type, "wordpress");
        assert_eq!(template.target_app_type, "mailchimp");
        assert!(template.description.is_none());
        assert!(template.target_external_url.is_none());
        assert_eq!(template.is_public, Some(false));
        assert_eq!(template.created_by, "user123");
    }

    #[test]
    fn test_pipe_template_builder() {
        let template = PipeTemplate::new(
            "test-pipe".to_string(),
            "wordpress".to_string(),
            json!({}),
            "slack".to_string(),
            json!({}),
            json!({}),
            "user1".to_string(),
        )
        .with_description("A test pipe".to_string())
        .with_external_url("https://hooks.slack.com/services/xxx".to_string())
        .with_config(json!({"retry_count": 3}))
        .with_public(true);

        assert_eq!(template.description, Some("A test pipe".to_string()));
        assert_eq!(
            template.target_external_url,
            Some("https://hooks.slack.com/services/xxx".to_string())
        );
        assert_eq!(template.config, Some(json!({"retry_count": 3})));
        assert_eq!(template.is_public, Some(true));
    }

    #[test]
    fn test_pipe_template_serialization() {
        let template = PipeTemplate::new(
            "test".to_string(),
            "app_a".to_string(),
            json!({"path": "/api"}),
            "app_b".to_string(),
            json!({"path": "/hook"}),
            json!({"field1": "$.field2"}),
            "creator".to_string(),
        );

        let json_str = serde_json::to_string(&template).unwrap();
        let deserialized: PipeTemplate = serde_json::from_str(&json_str).unwrap();
        assert_eq!(deserialized.name, "test");
        assert_eq!(deserialized.source_app_type, "app_a");
        assert_eq!(deserialized.target_app_type, "app_b");
    }

    #[test]
    fn test_pipe_instance_new() {
        let instance = PipeInstance::new(
            "deploy_abc123".to_string(),
            "wordpress_1".to_string(),
            "user456".to_string(),
        );

        assert_eq!(instance.deployment_hash, Some("deploy_abc123".to_string()));
        assert_eq!(instance.source_container, "wordpress_1");
        assert_eq!(instance.status, "draft");
        assert!(!instance.is_local);
        assert!(instance.template_id.is_none());
        assert!(instance.source_adapter.is_none());
        assert!(instance.target_adapter.is_none());
        assert!(instance.target_container.is_none());
        assert!(instance.target_url.is_none());
        assert_eq!(instance.trigger_count, 0);
        assert_eq!(instance.error_count, 0);
        assert!(instance.last_triggered_at.is_none());
    }

    #[test]
    fn test_pipe_instance_new_local() {
        let instance = PipeInstance::new_local("my_postgres".to_string(), "user789".to_string());

        assert!(instance.deployment_hash.is_none());
        assert_eq!(instance.source_container, "my_postgres");
        assert_eq!(instance.status, "draft");
        assert!(instance.is_local);
        assert_eq!(instance.created_by, "user789");
    }

    #[test]
    fn test_pipe_instance_builder() {
        let template_id = Uuid::new_v4();
        let instance = PipeInstance::new(
            "deploy_xyz".to_string(),
            "wordpress_1".to_string(),
            "user789".to_string(),
        )
        .with_template(template_id)
        .with_source_adapter(json!({"code": "imap"}))
        .with_target_adapter(json!({"code": "smtp"}))
        .with_target_container("mailchimp_1".to_string())
        .with_target_url("https://external.api/hook".to_string())
        .with_field_mapping_override(json!({"email": "$.custom_email"}))
        .with_config_override(json!({"timeout": 30}));

        assert_eq!(instance.template_id, Some(template_id));
        assert_eq!(instance.source_adapter, Some(json!({"code": "imap"})));
        assert_eq!(instance.target_adapter, Some(json!({"code": "smtp"})));
        assert_eq!(instance.target_container, Some("mailchimp_1".to_string()));
        assert_eq!(
            instance.target_url,
            Some("https://external.api/hook".to_string())
        );
        assert_eq!(
            instance.field_mapping_override,
            Some(json!({"email": "$.custom_email"}))
        );
        assert_eq!(instance.config_override, Some(json!({"timeout": 30})));
    }

    #[test]
    fn test_pipe_instance_serialization() {
        let instance = PipeInstance::new(
            "deploy_test".to_string(),
            "container_a".to_string(),
            "user_test".to_string(),
        );

        let json_str = serde_json::to_string(&instance).unwrap();
        let deserialized: PipeInstance = serde_json::from_str(&json_str).unwrap();
        assert_eq!(
            deserialized.deployment_hash,
            Some("deploy_test".to_string())
        );
        assert!(deserialized.source_adapter.is_none());
        assert!(deserialized.target_adapter.is_none());
        assert_eq!(deserialized.source_container, "container_a");
        assert_eq!(deserialized.status, "draft");
    }

    // ── PipeExecution tests ──

    #[test]
    fn test_pipe_execution_new() {
        let instance_id = Uuid::new_v4();
        let exec = PipeExecution::new(
            instance_id,
            Some("deploy_abc".to_string()),
            "manual".to_string(),
            "user1".to_string(),
        );

        assert_eq!(exec.pipe_instance_id, instance_id);
        assert_eq!(exec.deployment_hash, Some("deploy_abc".to_string()));
        assert_eq!(exec.trigger_type, "manual");
        assert_eq!(exec.status, "running");
        assert!(!exec.is_local);
        assert_eq!(exec.created_by, "user1");
        assert!(exec.source_data.is_none());
        assert!(exec.mapped_data.is_none());
        assert!(exec.target_response.is_none());
        assert!(exec.error.is_none());
        assert!(exec.duration_ms.is_none());
        assert!(exec.replay_of.is_none());
        assert!(exec.completed_at.is_none());
    }

    #[test]
    fn test_pipe_execution_complete_success() {
        let exec = PipeExecution::new(
            Uuid::new_v4(),
            Some("deploy_abc".to_string()),
            "webhook".to_string(),
            "user1".to_string(),
        )
        .complete_success(
            json!({"id": 1, "title": "Hello"}),
            json!({"subject": "Hello"}),
            json!({"status": 200, "id": "mc_123"}),
        );

        assert_eq!(exec.status, "success");
        assert_eq!(exec.source_data, Some(json!({"id": 1, "title": "Hello"})));
        assert_eq!(exec.mapped_data, Some(json!({"subject": "Hello"})));
        assert_eq!(
            exec.target_response,
            Some(json!({"status": 200, "id": "mc_123"}))
        );
        assert!(exec.error.is_none());
        assert!(exec.duration_ms.is_some());
        assert!(exec.completed_at.is_some());
    }

    #[test]
    fn test_pipe_execution_complete_failure() {
        let exec = PipeExecution::new(
            Uuid::new_v4(),
            Some("deploy_abc".to_string()),
            "poll".to_string(),
            "user1".to_string(),
        )
        .complete_failure("Connection refused".to_string());

        assert_eq!(exec.status, "failed");
        assert_eq!(exec.error, Some("Connection refused".to_string()));
        assert!(exec.source_data.is_none());
        assert!(exec.duration_ms.is_some());
        assert!(exec.completed_at.is_some());
    }

    #[test]
    fn test_pipe_execution_with_replay_of() {
        let original_id = Uuid::new_v4();
        let exec = PipeExecution::new(
            Uuid::new_v4(),
            Some("deploy_abc".to_string()),
            "replay".to_string(),
            "user1".to_string(),
        )
        .with_replay_of(original_id);

        assert_eq!(exec.replay_of, Some(original_id));
        assert_eq!(exec.trigger_type, "replay");
    }

    #[test]
    fn test_pipe_execution_serialization() {
        let exec = PipeExecution::new(
            Uuid::new_v4(),
            Some("deploy_test".to_string()),
            "manual".to_string(),
            "user_test".to_string(),
        )
        .complete_success(
            json!({"key": "value"}),
            json!({"mapped_key": "value"}),
            json!({"ok": true}),
        );

        let json_str = serde_json::to_string(&exec).unwrap();
        let deserialized: PipeExecution = serde_json::from_str(&json_str).unwrap();
        assert_eq!(
            deserialized.deployment_hash,
            Some("deploy_test".to_string())
        );
        assert_eq!(deserialized.trigger_type, "manual");
        assert_eq!(deserialized.status, "success");
        assert_eq!(deserialized.source_data, Some(json!({"key": "value"})));
    }

    #[test]
    fn test_pipe_instance_local_no_hash_and_is_local_flag() {
        let instance = PipeInstance::new_local("my-app".to_string(), "user1".to_string());
        assert!(instance.is_local);
        assert!(instance.deployment_hash.is_none());
        assert_eq!(instance.source_container, "my-app");
        assert_eq!(instance.created_by, "user1");
        assert_eq!(instance.status, "draft");
        assert_eq!(instance.trigger_count, 0);
        assert_eq!(instance.error_count, 0);
    }

    #[test]
    fn test_pipe_instance_new_remote_has_hash() {
        let instance = PipeInstance::new(
            "abc123hash".to_string(),
            "my-app".to_string(),
            "user1".to_string(),
        );
        assert!(!instance.is_local);
        assert_eq!(instance.deployment_hash, Some("abc123hash".to_string()));
    }

    #[test]
    fn test_pipe_instance_local_serialization_roundtrip() {
        let instance = PipeInstance::new_local("my-app".to_string(), "user1".to_string());
        let json_str = serde_json::to_string(&instance).unwrap();
        let deserialized: PipeInstance = serde_json::from_str(&json_str).unwrap();
        assert!(deserialized.is_local);
        assert!(deserialized.deployment_hash.is_none());
        assert_eq!(deserialized.source_container, "my-app");
    }

    #[test]
    fn test_pipe_execution_local_no_hash() {
        let exec = PipeExecution::new(
            Uuid::new_v4(),
            None,
            "manual".to_string(),
            "user1".to_string(),
        );
        assert!(exec.is_local);
        assert!(exec.deployment_hash.is_none());
        assert_eq!(exec.trigger_type, "manual");
        assert_eq!(exec.status, "running");
    }

    #[test]
    fn test_pipe_execution_remote_has_hash() {
        let exec = PipeExecution::new(
            Uuid::new_v4(),
            Some("hash123".to_string()),
            "webhook".to_string(),
            "user1".to_string(),
        );
        assert!(!exec.is_local);
        assert_eq!(exec.deployment_hash, Some("hash123".to_string()));
    }
}
