pub mod http_polling;
pub mod websocket;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Command {
    pub id: String,
    pub name: String,
    pub params: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResult {
    pub command_id: String,
    pub status: String, // "success" | "failed" | "timeout"
    pub result: Option<serde_json::Value>,
    pub error: Option<String>,
}
