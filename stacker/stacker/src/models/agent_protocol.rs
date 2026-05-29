use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use uuid::Uuid;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Agent Protocol — AMQP message types for step execution
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Command sent from Stacker to agent-executor via AMQP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepCommand {
    pub execution_id: Uuid,
    pub step_id: Uuid,
    pub step_name: String,
    pub step_type: String,
    pub config: JsonValue,
    pub input_data: JsonValue,
    pub pipe_instance_id: Uuid,
    pub deployment_hash: String,
    #[serde(default)]
    pub retry_policy: Option<RetryPolicy>,
    pub timestamp: DateTime<Utc>,
}

/// Result sent from agent-executor back to Stacker via AMQP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepResultMsg {
    pub execution_id: Uuid,
    pub step_id: Uuid,
    pub status: StepStatus,
    #[serde(default)]
    pub output_data: Option<JsonValue>,
    #[serde(default)]
    pub error: Option<String>,
    pub duration_ms: i64,
    pub timestamp: DateTime<Utc>,
}

/// Retry policy configuration for step execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryPolicy {
    pub max_retries: u32,
    pub backoff_base_ms: u64,
    pub backoff_max_ms: u64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 3,
            backoff_base_ms: 1000,
            backoff_max_ms: 30_000,
        }
    }
}

/// Step execution status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepStatus {
    Completed,
    Failed,
    Skipped,
    Running,
}

impl std::fmt::Display for StepStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Completed => write!(f, "completed"),
            Self::Failed => write!(f, "failed"),
            Self::Skipped => write!(f, "skipped"),
            Self::Running => write!(f, "running"),
        }
    }
}

/// AMQP routing constants.
pub mod routing {
    pub const EXCHANGE: &str = "pipe_execution";
    pub const EXECUTE_PREFIX: &str = "pipe.step.execute";
    pub const RESULT_PREFIX: &str = "pipe.step.result";

    pub fn execute_key(deployment_hash: &str) -> String {
        format!("{}.{}", EXECUTE_PREFIX, deployment_hash)
    }

    pub fn result_key(deployment_hash: &str) -> String {
        format!("{}.{}", RESULT_PREFIX, deployment_hash)
    }

    pub fn agent_queue(deployment_hash: &str) -> String {
        format!("agent_executor_{}", deployment_hash)
    }
}

impl StepCommand {
    pub fn new(
        execution_id: Uuid,
        step_id: Uuid,
        step_name: String,
        step_type: String,
        config: JsonValue,
        input_data: JsonValue,
        pipe_instance_id: Uuid,
        deployment_hash: String,
    ) -> Self {
        Self {
            execution_id,
            step_id,
            step_name,
            step_type,
            config,
            input_data,
            pipe_instance_id,
            deployment_hash,
            retry_policy: Some(RetryPolicy::default()),
            timestamp: Utc::now(),
        }
    }
}

impl StepResultMsg {
    pub fn success(
        execution_id: Uuid,
        step_id: Uuid,
        output_data: JsonValue,
        duration_ms: i64,
    ) -> Self {
        Self {
            execution_id,
            step_id,
            status: StepStatus::Completed,
            output_data: Some(output_data),
            error: None,
            duration_ms,
            timestamp: Utc::now(),
        }
    }

    pub fn failure(execution_id: Uuid, step_id: Uuid, error: String, duration_ms: i64) -> Self {
        Self {
            execution_id,
            step_id,
            status: StepStatus::Failed,
            output_data: None,
            error: Some(error),
            duration_ms,
            timestamp: Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn step_command_serde_roundtrip() {
        let cmd = StepCommand::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "fetch_data".to_string(),
            "source".to_string(),
            json!({"url": "https://api.example.com/data"}),
            json!({}),
            Uuid::new_v4(),
            "deploy-abc".to_string(),
        );

        let serialized = serde_json::to_string(&cmd).unwrap();
        let deserialized: StepCommand = serde_json::from_str(&serialized).unwrap();

        assert_eq!(cmd.execution_id, deserialized.execution_id);
        assert_eq!(cmd.step_id, deserialized.step_id);
        assert_eq!(cmd.step_name, deserialized.step_name);
        assert_eq!(cmd.step_type, deserialized.step_type);
        assert_eq!(cmd.deployment_hash, deserialized.deployment_hash);
    }

    #[test]
    fn step_result_success_serde_roundtrip() {
        let result =
            StepResultMsg::success(Uuid::new_v4(), Uuid::new_v4(), json!({"rows": 42}), 150);

        let serialized = serde_json::to_string(&result).unwrap();
        let deserialized: StepResultMsg = serde_json::from_str(&serialized).unwrap();

        assert_eq!(result.execution_id, deserialized.execution_id);
        assert_eq!(result.status, StepStatus::Completed);
        assert_eq!(deserialized.duration_ms, 150);
        assert!(deserialized.error.is_none());
    }

    #[test]
    fn step_result_failure_serde_roundtrip() {
        let result = StepResultMsg::failure(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "connection refused".to_string(),
            500,
        );

        let serialized = serde_json::to_string(&result).unwrap();
        let deserialized: StepResultMsg = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.status, StepStatus::Failed);
        assert_eq!(deserialized.error.as_deref(), Some("connection refused"));
        assert!(deserialized.output_data.is_none());
    }

    #[test]
    fn retry_policy_defaults() {
        let policy = RetryPolicy::default();
        assert_eq!(policy.max_retries, 3);
        assert_eq!(policy.backoff_base_ms, 1000);
        assert_eq!(policy.backoff_max_ms, 30_000);
    }

    #[test]
    fn routing_keys() {
        assert_eq!(
            routing::execute_key("deploy-abc"),
            "pipe.step.execute.deploy-abc"
        );
        assert_eq!(
            routing::result_key("deploy-abc"),
            "pipe.step.result.deploy-abc"
        );
        assert_eq!(
            routing::agent_queue("deploy-abc"),
            "agent_executor_deploy-abc"
        );
    }

    #[test]
    fn step_status_display() {
        assert_eq!(StepStatus::Completed.to_string(), "completed");
        assert_eq!(StepStatus::Failed.to_string(), "failed");
        assert_eq!(StepStatus::Skipped.to_string(), "skipped");
        assert_eq!(StepStatus::Running.to_string(), "running");
    }

    #[test]
    fn step_command_without_retry_policy() {
        let json_str = r#"{
            "execution_id": "550e8400-e29b-41d4-a716-446655440000",
            "step_id": "550e8400-e29b-41d4-a716-446655440001",
            "step_name": "test",
            "step_type": "source",
            "config": {},
            "input_data": {},
            "pipe_instance_id": "550e8400-e29b-41d4-a716-446655440002",
            "deployment_hash": "test-hash",
            "timestamp": "2026-01-01T00:00:00Z"
        }"#;

        let cmd: StepCommand = serde_json::from_str(json_str).unwrap();
        assert!(cmd.retry_policy.is_none());
    }
}
