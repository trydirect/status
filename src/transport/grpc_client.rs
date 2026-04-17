use anyhow::{Context, Result};
use serde_json::Value;
use std::time::Duration;
use tracing::info;

pub mod pipe_proto {
    tonic::include_proto!("pipe");
}

use pipe_proto::pipe_service_client::PipeServiceClient;
use pipe_proto::{PipeMessage, SubscribeRequest};

const GRPC_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const GRPC_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Subscribe to a gRPC pipe source and read the first message.
pub async fn grpc_fetch_source(
    endpoint: &str,
    pipe_instance_id: &str,
    step_id: &str,
) -> Result<Value> {
    info!(endpoint, "grpc_fetch_source: connecting");
    let channel = tonic::transport::Endpoint::from_shared(endpoint.to_string())
        .with_context(|| format!("invalid gRPC endpoint: {endpoint}"))?
        .connect_timeout(GRPC_CONNECT_TIMEOUT)
        .timeout(GRPC_REQUEST_TIMEOUT)
        .connect()
        .await
        .with_context(|| format!("gRPC connection failed: {endpoint}"))?;

    let mut client = PipeServiceClient::new(channel);

    let request = tonic::Request::new(SubscribeRequest {
        pipe_instance_id: pipe_instance_id.to_string(),
        step_id: step_id.to_string(),
        filters: Default::default(),
    });

    let mut stream = client
        .subscribe(request)
        .await
        .with_context(|| "gRPC subscribe failed")?
        .into_inner();

    match stream.message().await {
        Ok(Some(msg)) => {
            let payload = msg
                .payload
                .map(|s| struct_to_json(&s))
                .unwrap_or_else(|| serde_json::json!({}));
            Ok(payload)
        }
        Ok(None) => Err(anyhow::anyhow!("gRPC stream closed without data")),
        Err(e) => Err(anyhow::anyhow!("gRPC read error: {e}")),
    }
}

/// Send data to a gRPC pipe target via unary RPC.
pub async fn grpc_send_target(
    endpoint: &str,
    pipe_instance_id: &str,
    step_id: &str,
    data: &Value,
) -> Result<(u16, Value)> {
    info!(endpoint, "grpc_send_target: connecting");
    let channel = tonic::transport::Endpoint::from_shared(endpoint.to_string())
        .with_context(|| format!("invalid gRPC endpoint: {endpoint}"))?
        .connect_timeout(GRPC_CONNECT_TIMEOUT)
        .timeout(GRPC_REQUEST_TIMEOUT)
        .connect()
        .await
        .with_context(|| format!("gRPC connection failed: {endpoint}"))?;

    let mut client = PipeServiceClient::new(channel);

    let payload_struct =
        json_to_struct(data).with_context(|| "failed to convert payload to gRPC Struct")?;

    let request = tonic::Request::new(PipeMessage {
        pipe_instance_id: pipe_instance_id.to_string(),
        step_id: step_id.to_string(),
        payload: Some(payload_struct),
        timestamp_ms: chrono::Utc::now().timestamp_millis(),
    });

    let response = client
        .send(request)
        .await
        .with_context(|| "gRPC send failed")?
        .into_inner();

    let status = if response.success { 200 } else { 500 };
    Ok((
        status,
        serde_json::json!({
            "grpc_delivered": response.success,
            "message": response.message,
        }),
    ))
}

// ── Conversion helpers: serde_json ↔ prost_types::Struct ──

fn json_to_struct(value: &Value) -> Result<prost_types::Struct> {
    let fields = match value.as_object() {
        Some(map) => map
            .iter()
            .map(|(k, v)| Ok((k.clone(), json_to_prost_value(v)?)))
            .collect::<Result<_>>()?,
        None => {
            return Err(anyhow::anyhow!(
                "gRPC Struct conversion requires a JSON object, got: {}",
                match value {
                    Value::Array(_) => "array",
                    Value::String(_) => "string",
                    Value::Number(_) => "number",
                    Value::Bool(_) => "bool",
                    Value::Null => "null",
                    _ => "unknown",
                }
            ));
        }
    };
    Ok(prost_types::Struct { fields })
}

fn json_to_prost_value(value: &Value) -> Result<prost_types::Value> {
    use prost_types::value::Kind;
    let kind = match value {
        Value::Null => Kind::NullValue(0),
        Value::Bool(b) => Kind::BoolValue(*b),
        Value::Number(n) => Kind::NumberValue(
            n.as_f64()
                .ok_or_else(|| anyhow::anyhow!("number {n} cannot be represented as f64"))?,
        ),
        Value::String(s) => Kind::StringValue(s.clone()),
        Value::Array(arr) => Kind::ListValue(prost_types::ListValue {
            values: arr.iter().map(json_to_prost_value).collect::<Result<_>>()?,
        }),
        Value::Object(_) => Kind::StructValue(json_to_struct(value)?),
    };
    Ok(prost_types::Value { kind: Some(kind) })
}

fn struct_to_json(s: &prost_types::Struct) -> Value {
    let map: serde_json::Map<String, Value> = s
        .fields
        .iter()
        .map(|(k, v)| (k.clone(), prost_value_to_json(v)))
        .collect();
    Value::Object(map)
}

fn prost_value_to_json(v: &prost_types::Value) -> Value {
    use prost_types::value::Kind;
    match &v.kind {
        Some(Kind::NullValue(_)) => Value::Null,
        Some(Kind::BoolValue(b)) => Value::Bool(*b),
        Some(Kind::NumberValue(n)) => serde_json::json!(*n),
        Some(Kind::StringValue(s)) => Value::String(s.clone()),
        Some(Kind::ListValue(list)) => {
            Value::Array(list.values.iter().map(prost_value_to_json).collect())
        }
        Some(Kind::StructValue(s)) => struct_to_json(s),
        None => Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_struct_roundtrip() {
        let original = serde_json::json!({"name": "test", "count": 42, "active": true});
        let proto = json_to_struct(&original).unwrap();
        let back = struct_to_json(&proto);
        assert_eq!(back["name"], "test");
        assert_eq!(back["count"], 42.0);
        assert_eq!(back["active"], true);
    }

    #[test]
    fn test_json_to_struct_rejects_non_object() {
        assert!(json_to_struct(&serde_json::json!("string")).is_err());
        assert!(json_to_struct(&serde_json::json!(42)).is_err());
        assert!(json_to_struct(&serde_json::json!([1, 2])).is_err());
        assert!(json_to_struct(&serde_json::json!(null)).is_err());
    }
}
