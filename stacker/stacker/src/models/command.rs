use serde::{Deserialize, Serialize};
use sqlx::types::chrono::{DateTime, Utc};
use sqlx::types::uuid::Uuid;
use sqlx::types::JsonValue;

/// Command status enum matching the database CHECK constraint
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "text")]
pub enum CommandStatus {
    #[serde(rename = "queued")]
    Queued,
    #[serde(rename = "sent")]
    Sent,
    #[serde(rename = "executing")]
    Executing,
    #[serde(rename = "completed")]
    Completed,
    #[serde(rename = "failed")]
    Failed,
    #[serde(rename = "cancelled")]
    Cancelled,
}

impl std::fmt::Display for CommandStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CommandStatus::Queued => write!(f, "queued"),
            CommandStatus::Sent => write!(f, "sent"),
            CommandStatus::Executing => write!(f, "executing"),
            CommandStatus::Completed => write!(f, "completed"),
            CommandStatus::Failed => write!(f, "failed"),
            CommandStatus::Cancelled => write!(f, "cancelled"),
        }
    }
}

/// Command priority enum matching the database CHECK constraint
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "text")]
pub enum CommandPriority {
    #[serde(rename = "low")]
    Low,
    #[serde(rename = "normal")]
    Normal,
    #[serde(rename = "high")]
    High,
    #[serde(rename = "critical")]
    Critical,
}

impl CommandPriority {
    /// Convert priority to integer for queue ordering
    pub fn to_int(&self) -> i32 {
        match self {
            CommandPriority::Low => 0,
            CommandPriority::Normal => 1,
            CommandPriority::High => 2,
            CommandPriority::Critical => 3,
        }
    }
}

impl std::fmt::Display for CommandPriority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CommandPriority::Low => write!(f, "low"),
            CommandPriority::Normal => write!(f, "normal"),
            CommandPriority::High => write!(f, "high"),
            CommandPriority::Critical => write!(f, "critical"),
        }
    }
}

/// Command model representing a command to be executed on an agent
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, Default)]
pub struct Command {
    pub id: Uuid,
    pub command_id: String,
    pub deployment_hash: String,
    pub r#type: String,
    pub status: String,
    pub priority: String,
    pub parameters: Option<JsonValue>,
    pub result: Option<JsonValue>,
    pub error: Option<JsonValue>,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub timeout_seconds: Option<i32>,
    pub metadata: Option<JsonValue>,
}

impl Command {
    /// Create a new command with defaults
    pub fn new(
        command_id: String,
        deployment_hash: String,
        command_type: String,
        created_by: String,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            command_id,
            deployment_hash,
            r#type: command_type,
            status: CommandStatus::Queued.to_string(),
            priority: CommandPriority::Normal.to_string(),
            parameters: None,
            result: None,
            error: None,
            created_by,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            timeout_seconds: Some(300), // Default 5 minutes
            metadata: None,
        }
    }

    /// Builder: Set priority
    pub fn with_priority(mut self, priority: CommandPriority) -> Self {
        self.priority = priority.to_string();
        self
    }

    /// Builder: Set parameters
    pub fn with_parameters(mut self, parameters: JsonValue) -> Self {
        self.parameters = Some(parameters);
        self
    }

    /// Builder: Set timeout in seconds
    pub fn with_timeout(mut self, seconds: i32) -> Self {
        self.timeout_seconds = Some(seconds);
        self
    }

    /// Builder: Set metadata
    pub fn with_metadata(mut self, metadata: JsonValue) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Mark command as sent
    pub fn mark_sent(mut self) -> Self {
        self.status = CommandStatus::Sent.to_string();
        self.updated_at = Utc::now();
        self
    }

    /// Mark command as executing
    pub fn mark_executing(mut self) -> Self {
        self.status = CommandStatus::Executing.to_string();
        self.updated_at = Utc::now();
        self
    }

    /// Mark command as completed
    pub fn mark_completed(mut self) -> Self {
        self.status = CommandStatus::Completed.to_string();
        self.updated_at = Utc::now();
        self
    }

    /// Mark command as failed
    pub fn mark_failed(mut self) -> Self {
        self.status = CommandStatus::Failed.to_string();
        self.updated_at = Utc::now();
        self
    }

    /// Mark command as cancelled
    pub fn mark_cancelled(mut self) -> Self {
        self.status = CommandStatus::Cancelled.to_string();
        self.updated_at = Utc::now();
        self
    }
}

/// Command result payload from agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResult {
    pub command_id: String,
    pub deployment_hash: String,
    pub status: CommandStatus,
    pub result: Option<JsonValue>,
    pub error: Option<CommandError>,
    pub metadata: Option<JsonValue>,
}

/// Command error details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandError {
    pub code: String,
    pub message: String,
    pub details: Option<JsonValue>,
}

/// Command queue entry for efficient polling
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct CommandQueueEntry {
    pub command_id: String,
    pub deployment_hash: String,
    pub priority: i32,
    pub created_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // CommandStatus tests
    #[test]
    fn test_command_status_display() {
        assert_eq!(CommandStatus::Queued.to_string(), "queued");
        assert_eq!(CommandStatus::Sent.to_string(), "sent");
        assert_eq!(CommandStatus::Executing.to_string(), "executing");
        assert_eq!(CommandStatus::Completed.to_string(), "completed");
        assert_eq!(CommandStatus::Failed.to_string(), "failed");
        assert_eq!(CommandStatus::Cancelled.to_string(), "cancelled");
    }

    #[test]
    fn test_command_status_serde() {
        let json = serde_json::to_string(&CommandStatus::Queued).unwrap();
        assert_eq!(json, "\"queued\"");
        let deserialized: CommandStatus = serde_json::from_str("\"completed\"").unwrap();
        assert_eq!(deserialized, CommandStatus::Completed);
    }

    // CommandPriority tests
    #[test]
    fn test_priority_to_int() {
        assert_eq!(CommandPriority::Low.to_int(), 0);
        assert_eq!(CommandPriority::Normal.to_int(), 1);
        assert_eq!(CommandPriority::High.to_int(), 2);
        assert_eq!(CommandPriority::Critical.to_int(), 3);
    }

    #[test]
    fn test_priority_display() {
        assert_eq!(CommandPriority::Low.to_string(), "low");
        assert_eq!(CommandPriority::Normal.to_string(), "normal");
        assert_eq!(CommandPriority::High.to_string(), "high");
        assert_eq!(CommandPriority::Critical.to_string(), "critical");
    }

    #[test]
    fn test_priority_serde() {
        let json = serde_json::to_string(&CommandPriority::High).unwrap();
        assert_eq!(json, "\"high\"");
        let deserialized: CommandPriority = serde_json::from_str("\"low\"").unwrap();
        assert_eq!(deserialized, CommandPriority::Low);
    }

    #[test]
    fn test_priority_ordering() {
        assert!(CommandPriority::Low.to_int() < CommandPriority::Normal.to_int());
        assert!(CommandPriority::Normal.to_int() < CommandPriority::High.to_int());
        assert!(CommandPriority::High.to_int() < CommandPriority::Critical.to_int());
    }

    // Command builder tests
    #[test]
    fn test_command_new_defaults() {
        let cmd = Command::new(
            "cmd-1".to_string(),
            "hash-abc".to_string(),
            "deploy".to_string(),
            "admin".to_string(),
        );
        assert_eq!(cmd.command_id, "cmd-1");
        assert_eq!(cmd.deployment_hash, "hash-abc");
        assert_eq!(cmd.r#type, "deploy");
        assert_eq!(cmd.created_by, "admin");
        assert_eq!(cmd.status, "queued");
        assert_eq!(cmd.priority, "normal");
        assert_eq!(cmd.timeout_seconds, Some(300));
        assert!(cmd.parameters.is_none());
        assert!(cmd.result.is_none());
        assert!(cmd.error.is_none());
        assert!(cmd.metadata.is_none());
    }

    #[test]
    fn test_command_with_priority() {
        let cmd = Command::new(
            "c".to_string(),
            "h".to_string(),
            "t".to_string(),
            "u".to_string(),
        )
        .with_priority(CommandPriority::Critical);
        assert_eq!(cmd.priority, "critical");
    }

    #[test]
    fn test_command_with_parameters() {
        let params = serde_json::json!({"key": "value"});
        let cmd = Command::new(
            "c".to_string(),
            "h".to_string(),
            "t".to_string(),
            "u".to_string(),
        )
        .with_parameters(params.clone());
        assert_eq!(cmd.parameters, Some(params));
    }

    #[test]
    fn test_command_with_timeout() {
        let cmd = Command::new(
            "c".to_string(),
            "h".to_string(),
            "t".to_string(),
            "u".to_string(),
        )
        .with_timeout(600);
        assert_eq!(cmd.timeout_seconds, Some(600));
    }

    #[test]
    fn test_command_with_metadata() {
        let meta = serde_json::json!({"retry_count": 3});
        let cmd = Command::new(
            "c".to_string(),
            "h".to_string(),
            "t".to_string(),
            "u".to_string(),
        )
        .with_metadata(meta.clone());
        assert_eq!(cmd.metadata, Some(meta));
    }

    #[test]
    fn test_command_builder_chaining() {
        let cmd = Command::new(
            "c".to_string(),
            "h".to_string(),
            "t".to_string(),
            "u".to_string(),
        )
        .with_priority(CommandPriority::High)
        .with_timeout(120)
        .with_parameters(serde_json::json!({"action": "restart"}))
        .with_metadata(serde_json::json!({"source": "api"}));

        assert_eq!(cmd.priority, "high");
        assert_eq!(cmd.timeout_seconds, Some(120));
        assert!(cmd.parameters.is_some());
        assert!(cmd.metadata.is_some());
    }

    // Command status transitions
    #[test]
    fn test_command_mark_sent() {
        let cmd = Command::new(
            "c".to_string(),
            "h".to_string(),
            "t".to_string(),
            "u".to_string(),
        )
        .mark_sent();
        assert_eq!(cmd.status, "sent");
    }

    #[test]
    fn test_command_mark_executing() {
        let cmd = Command::new(
            "c".to_string(),
            "h".to_string(),
            "t".to_string(),
            "u".to_string(),
        )
        .mark_executing();
        assert_eq!(cmd.status, "executing");
    }

    #[test]
    fn test_command_mark_completed() {
        let cmd = Command::new(
            "c".to_string(),
            "h".to_string(),
            "t".to_string(),
            "u".to_string(),
        )
        .mark_completed();
        assert_eq!(cmd.status, "completed");
    }

    #[test]
    fn test_command_mark_failed() {
        let cmd = Command::new(
            "c".to_string(),
            "h".to_string(),
            "t".to_string(),
            "u".to_string(),
        )
        .mark_failed();
        assert_eq!(cmd.status, "failed");
    }

    #[test]
    fn test_command_mark_cancelled() {
        let cmd = Command::new(
            "c".to_string(),
            "h".to_string(),
            "t".to_string(),
            "u".to_string(),
        )
        .mark_cancelled();
        assert_eq!(cmd.status, "cancelled");
    }

    #[test]
    fn test_command_status_transition_chain() {
        let cmd = Command::new(
            "c".to_string(),
            "h".to_string(),
            "t".to_string(),
            "u".to_string(),
        );
        assert_eq!(cmd.status, "queued");
        let cmd = cmd.mark_sent();
        assert_eq!(cmd.status, "sent");
        let cmd = cmd.mark_executing();
        assert_eq!(cmd.status, "executing");
        let cmd = cmd.mark_completed();
        assert_eq!(cmd.status, "completed");
    }

    // CommandResult and CommandError serde
    #[test]
    fn test_command_result_deserialization() {
        let json = r#"{
            "command_id": "cmd-1",
            "deployment_hash": "hash-1",
            "status": "completed",
            "result": {"output": "success"},
            "error": null,
            "metadata": null
        }"#;
        let result: CommandResult = serde_json::from_str(json).unwrap();
        assert_eq!(result.command_id, "cmd-1");
        assert_eq!(result.status, CommandStatus::Completed);
        assert!(result.error.is_none());
    }

    #[test]
    fn test_command_error_deserialization() {
        let json = r#"{
            "code": "TIMEOUT",
            "message": "Command timed out",
            "details": {"elapsed_seconds": 300}
        }"#;
        let error: CommandError = serde_json::from_str(json).unwrap();
        assert_eq!(error.code, "TIMEOUT");
        assert_eq!(error.message, "Command timed out");
    }
}
