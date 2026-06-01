use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::services::TypedErrorEnvelope;

/// JSON-RPC 2.0 Request structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String, // Must be "2.0"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

/// JSON-RPC 2.0 Response structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String, // Must be "2.0"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

impl JsonRpcResponse {
    pub fn success(id: Option<Value>, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn error(id: Option<Value>, error: JsonRpcError) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(error),
        }
    }
}

/// JSON-RPC 2.0 Error structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl JsonRpcError {
    pub fn parse_error() -> Self {
        Self {
            code: -32700,
            message: "Parse error".to_string(),
            data: None,
        }
    }

    pub fn invalid_request() -> Self {
        Self {
            code: -32600,
            message: "Invalid Request".to_string(),
            data: None,
        }
    }

    pub fn method_not_found(method: &str) -> Self {
        Self {
            code: -32601,
            message: format!("Method not found: {}", method),
            data: None,
        }
    }

    pub fn invalid_params(msg: &str) -> Self {
        Self {
            code: -32602,
            message: "Invalid params".to_string(),
            data: Some(serde_json::json!({ "error": msg })),
        }
    }

    pub fn internal_error(msg: &str) -> Self {
        Self {
            code: -32603,
            message: "Internal error".to_string(),
            data: Some(serde_json::json!({ "error": msg })),
        }
    }

    pub fn custom(code: i32, message: String, data: Option<Value>) -> Self {
        Self {
            code,
            message,
            data,
        }
    }
}

// MCP-specific types

/// MCP Tool definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tool {
    pub name: String,
    pub description: String,
    #[serde(rename = "inputSchema")]
    pub input_schema: Value, // JSON Schema for parameters
}

/// Response for tools/list method
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolListResponse {
    pub tools: Vec<Tool>,
}

/// Request for tools/call method
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallToolRequest {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Value>,
}

/// Response for tools/call method
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallToolResponse {
    pub content: Vec<ToolContent>,
    #[serde(rename = "isError", skip_serializing_if = "Option::is_none")]
    pub is_error: Option<bool>,
}

impl CallToolResponse {
    pub fn text(text: String) -> Self {
        Self {
            content: vec![ToolContent::Text { text }],
            is_error: None,
        }
    }

    pub fn error(text: String) -> Self {
        Self {
            content: vec![ToolContent::Text { text }],
            is_error: Some(true),
        }
    }

    pub fn typed_error(error: TypedErrorEnvelope) -> Self {
        Self {
            content: vec![ToolContent::Text {
                text: error.to_pretty_json(),
            }],
            is_error: Some(true),
        }
    }
}

/// Tool execution result content
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ToolContent {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(rename = "image")]
    Image {
        data: String, // base64 encoded
        #[serde(rename = "mimeType")]
        mime_type: String,
    },
}

/// MCP Initialize request parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitializeParams {
    #[serde(rename = "protocolVersion")]
    pub protocol_version: String,
    pub capabilities: ClientCapabilities,
    #[serde(rename = "clientInfo", skip_serializing_if = "Option::is_none")]
    pub client_info: Option<ClientInfo>,
}

/// Client information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientInfo {
    pub name: String,
    pub version: String,
}

/// Client capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientCapabilities {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub experimental: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sampling: Option<Value>,
}

/// MCP Initialize response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitializeResult {
    #[serde(rename = "protocolVersion")]
    pub protocol_version: String,
    pub capabilities: ServerCapabilities,
    #[serde(rename = "serverInfo")]
    pub server_info: ServerInfo,
}

/// Server capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerCapabilities {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<ToolsCapability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub experimental: Option<Value>,
}

/// Tools capability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolsCapability {
    #[serde(rename = "listChanged", skip_serializing_if = "Option::is_none")]
    pub list_changed: Option<bool>,
}

/// Server information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
}
