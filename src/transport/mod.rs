pub mod http_polling;
pub mod websocket;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Command {
    pub id: String,
    pub name: String,
    pub params: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deployment_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_code: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CommandResult {
    pub command_id: String,
    pub status: String, // "success" | "failed" | "timeout"
    pub result: Option<serde_json::Value>,
    pub error: Option<String>,
    /// ISO 8601 timestamp when command execution completed
    pub completed_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deployment_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<CommandError>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandError {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

/// Minimal report payload for Stacker API (matches /api/v1/agent/commands/report spec)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackerCommandReport {
    pub command_id: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}
