pub mod http_polling;
pub mod websocket;

use serde::{Deserialize, Serialize};
use serde_json::Value;

fn empty_params() -> Value {
    serde_json::json!({})
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Command {
    #[serde(alias = "command_id")]
    pub id: String,
    #[serde(alias = "command_type", alias = "type")]
    pub name: String,
    #[serde(default = "empty_params", alias = "parameters")]
    pub params: Value,
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
