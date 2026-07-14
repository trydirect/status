use serde_json::Value as JsonValue;

pub mod pipe_proto {
    tonic::include_proto!("pipe");
}

use pipe_proto::pipe_service_client::PipeServiceClient;
use pipe_proto::{PipeMessage, SubscribeRequest};

/// Subscribe to a gRPC streaming source and read the first message.
/// If `config.output` is set, returns it directly (simulation mode for BDD tests).
pub async fn execute_grpc_source(
    config: &JsonValue,
    _input: &JsonValue,
) -> Result<JsonValue, String> {
    if let Some(output) = config.get("output") {
        return Ok(output.clone());
    }

    let endpoint = config
        .get("endpoint")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "grpc_source requires 'endpoint' in config".to_string())?;

    let pipe_instance_id = config
        .get("pipe_instance_id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let step_id = config
        .get("step_id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let mut client = PipeServiceClient::connect(endpoint.to_string())
        .await
        .map_err(|e| format!("grpc_source connect failed: {e}"))?;

    let request = tonic::Request::new(SubscribeRequest {
        pipe_instance_id,
        step_id,
        filters: Default::default(),
    });

    let mut stream = client
        .subscribe(request)
        .await
        .map_err(|e| format!("grpc_source subscribe failed: {e}"))?
        .into_inner();

    match stream.message().await {
        Ok(Some(msg)) => {
            let payload = msg
                .payload
                .map(|s| struct_to_json(&s))
                .unwrap_or_else(|| serde_json::json!({}));
            Ok(payload)
        }
        Ok(None) => Err("grpc_source: stream closed without data".to_string()),
        Err(e) => Err(format!("grpc_source read error: {e}")),
    }
}

/// Send data to a gRPC pipe target via unary RPC.
/// If `config.output` is set, returns it directly (simulation mode).
pub async fn execute_grpc_target(
    config: &JsonValue,
    input: &JsonValue,
) -> Result<JsonValue, String> {
    if let Some(output) = config.get("output") {
        return Ok(output.clone());
    }

    let endpoint = config
        .get("endpoint")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "grpc_target requires 'endpoint' in config".to_string())?;

    let pipe_instance_id = config
        .get("pipe_instance_id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let step_id = config
        .get("step_id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let mut client = PipeServiceClient::connect(endpoint.to_string())
        .await
        .map_err(|e| format!("grpc_target connect failed: {e}"))?;

    let payload_struct = json_to_struct(input);

    let request = tonic::Request::new(PipeMessage {
        pipe_instance_id,
        step_id,
        payload: Some(payload_struct),
        timestamp_ms: chrono::Utc::now().timestamp_millis(),
    });

    let response = client
        .send(request)
        .await
        .map_err(|e| format!("grpc_target send failed: {e}"))?
        .into_inner();

    Ok(serde_json::json!({
        "grpc_delivered": response.success,
        "message": response.message,
        "data": input,
    }))
}

// ── Conversion helpers: serde_json ↔ prost_types::Struct ──

fn json_to_struct(value: &JsonValue) -> prost_types::Struct {
    let fields = match value.as_object() {
        Some(map) => map
            .iter()
            .map(|(k, v)| (k.clone(), json_to_prost_value(v)))
            .collect(),
        None => Default::default(),
    };
    prost_types::Struct { fields }
}

fn json_to_prost_value(value: &JsonValue) -> prost_types::Value {
    use prost_types::value::Kind;
    let kind = match value {
        JsonValue::Null => Kind::NullValue(0),
        JsonValue::Bool(b) => Kind::BoolValue(*b),
        JsonValue::Number(n) => Kind::NumberValue(n.as_f64().unwrap_or(0.0)),
        JsonValue::String(s) => Kind::StringValue(s.clone()),
        JsonValue::Array(arr) => Kind::ListValue(prost_types::ListValue {
            values: arr.iter().map(json_to_prost_value).collect(),
        }),
        JsonValue::Object(_) => Kind::StructValue(json_to_struct(value)),
    };
    prost_types::Value { kind: Some(kind) }
}

fn struct_to_json(s: &prost_types::Struct) -> JsonValue {
    let map: serde_json::Map<String, JsonValue> = s
        .fields
        .iter()
        .map(|(k, v)| (k.clone(), prost_value_to_json(v)))
        .collect();
    JsonValue::Object(map)
}

fn prost_value_to_json(v: &prost_types::Value) -> JsonValue {
    use prost_types::value::Kind;
    match &v.kind {
        Some(Kind::NullValue(_)) => JsonValue::Null,
        Some(Kind::BoolValue(b)) => JsonValue::Bool(*b),
        Some(Kind::NumberValue(n)) => serde_json::json!(*n),
        Some(Kind::StringValue(s)) => JsonValue::String(s.clone()),
        Some(Kind::ListValue(list)) => {
            JsonValue::Array(list.values.iter().map(prost_value_to_json).collect())
        }
        Some(Kind::StructValue(s)) => struct_to_json(s),
        None => JsonValue::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_struct_roundtrip() {
        let original = serde_json::json!({"name": "test", "count": 42, "active": true});
        let proto_struct = json_to_struct(&original);
        let back = struct_to_json(&proto_struct);
        assert_eq!(back["name"], "test");
        assert_eq!(back["count"], 42.0);
        assert_eq!(back["active"], true);
    }

    #[tokio::test]
    async fn test_grpc_source_simulation() {
        let config = serde_json::json!({"output": {"metric": "cpu", "value": 72.1}});
        let input = serde_json::json!({});
        let result = execute_grpc_source(&config, &input).await.unwrap();
        assert_eq!(result["metric"], "cpu");
    }

    #[tokio::test]
    async fn test_grpc_target_simulation() {
        let config = serde_json::json!({"output": {"grpc_delivered": true}});
        let input = serde_json::json!({"data": 1});
        let result = execute_grpc_target(&config, &input).await.unwrap();
        assert!(result["grpc_delivered"].as_bool().unwrap());
    }
}
