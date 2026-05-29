#[cfg(test)]
mod tests {
    use crate::mcp::{
        CallToolRequest, CallToolResponse, InitializeParams, InitializeResult, JsonRpcError,
        JsonRpcRequest, JsonRpcResponse, ServerCapabilities, ServerInfo, Tool, ToolContent,
        ToolsCapability,
    };
    use crate::services::TypedErrorEnvelope;

    #[test]
    fn test_json_rpc_request_deserialize() {
        let json = r#"{
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"test": "value"}
        }"#;

        let req: JsonRpcRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.jsonrpc, "2.0");
        assert_eq!(req.method, "initialize");
        assert!(req.params.is_some());
    }

    #[test]
    fn test_json_rpc_response_success() {
        let response = JsonRpcResponse::success(
            Some(serde_json::json!(1)),
            serde_json::json!({"result": "ok"}),
        );

        assert_eq!(response.jsonrpc, "2.0");
        assert!(response.result.is_some());
        assert!(response.error.is_none());
    }

    #[test]
    fn test_json_rpc_response_error() {
        let response = JsonRpcResponse::error(
            Some(serde_json::json!(1)),
            JsonRpcError::method_not_found("test_method"),
        );

        assert_eq!(response.jsonrpc, "2.0");
        assert!(response.result.is_none());
        assert!(response.error.is_some());

        let error = response.error.unwrap();
        assert_eq!(error.code, -32601);
        assert!(error.message.contains("test_method"));
    }

    #[test]
    fn test_json_rpc_error_codes() {
        assert_eq!(JsonRpcError::parse_error().code, -32700);
        assert_eq!(JsonRpcError::invalid_request().code, -32600);
        assert_eq!(JsonRpcError::method_not_found("test").code, -32601);
        assert_eq!(JsonRpcError::invalid_params("test").code, -32602);
        assert_eq!(JsonRpcError::internal_error("test").code, -32603);
    }

    #[test]
    fn test_tool_schema() {
        let tool = Tool {
            name: "test_tool".to_string(),
            description: "A test tool".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "param1": { "type": "string" }
                }
            }),
        };

        assert_eq!(tool.name, "test_tool");
        assert_eq!(tool.description, "A test tool");
    }

    #[test]
    fn test_call_tool_request_deserialize() {
        let json = r#"{
            "name": "create_project",
            "arguments": {"name": "Test Project"}
        }"#;

        let req: CallToolRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, "create_project");
        assert!(req.arguments.is_some());
    }

    #[test]
    fn test_call_tool_response() {
        let response = CallToolResponse::text("Success".to_string());

        assert_eq!(response.content.len(), 1);
        assert!(response.is_error.is_none());

        match &response.content[0] {
            ToolContent::Text { text } => assert_eq!(text, "Success"),
            _ => panic!("Expected text content"),
        }
    }

    #[test]
    fn test_call_tool_response_error() {
        let response = CallToolResponse::error("Failed".to_string());

        assert_eq!(response.content.len(), 1);
        assert_eq!(response.is_error, Some(true));
    }

    #[test]
    fn test_call_tool_response_typed_error() {
        let response = CallToolResponse::typed_error(TypedErrorEnvelope::deployment_not_found(
            "Deployment not found",
        ));

        assert_eq!(response.content.len(), 1);
        assert_eq!(response.is_error, Some(true));

        match &response.content[0] {
            ToolContent::Text { text } => {
                assert!(text.contains("deployment_not_found"));
                assert!(text.contains("schemaVersion"));
            }
            _ => panic!("Expected text content"),
        }
    }

    #[test]
    fn test_initialize_params_deserialize() {
        let json = r#"{
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "test-client",
                "version": "1.0.0"
            }
        }"#;

        let params: InitializeParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.protocol_version, "2024-11-05");
        assert!(params.client_info.is_some());

        let client_info = params.client_info.unwrap();
        assert_eq!(client_info.name, "test-client");
        assert_eq!(client_info.version, "1.0.0");
    }

    #[test]
    fn test_initialize_result_serialize() {
        let result = InitializeResult {
            protocol_version: "2024-11-05".to_string(),
            capabilities: ServerCapabilities {
                tools: Some(ToolsCapability {
                    list_changed: Some(false),
                }),
                experimental: None,
            },
            server_info: ServerInfo {
                name: "stacker-mcp".to_string(),
                version: "0.2.0".to_string(),
            },
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("stacker-mcp"));
        assert!(json.contains("2024-11-05"));
    }
}
