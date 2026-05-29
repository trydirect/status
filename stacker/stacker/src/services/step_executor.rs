use serde_json::Value as JsonValue;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Step Executor — Pure step execution logic (no DB dependencies)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Execute a single DAG step given its type, config, and input data.
/// This function is DB-free and can be used by both the in-process DAG
/// executor and the standalone agent-executor binary.
pub async fn execute_step(
    step_type: &str,
    config: &JsonValue,
    input: &JsonValue,
) -> Result<JsonValue, String> {
    // Check for simulated failure (testing hook)
    if let Some(err_msg) = config.get("error").and_then(|e| e.as_str()) {
        return Err(err_msg.to_string());
    }

    match step_type {
        "source" => {
            if let Some(output) = config.get("output") {
                Ok(output.clone())
            } else {
                Ok(input.clone())
            }
        }
        "transform" => {
            if let Some(mapping) = config.get("mapping") {
                let mut result = input.clone();
                if let (Some(result_obj), Some(mapping_obj)) =
                    (result.as_object_mut(), mapping.as_object())
                {
                    for (key, _) in mapping_obj {
                        if let Some(val) = input.get(key) {
                            result_obj.insert(key.clone(), val.clone());
                        }
                    }
                }
                Ok(result)
            } else {
                Ok(input.clone())
            }
        }
        "condition" => {
            let passed = evaluate_condition(config, input);
            Ok(serde_json::json!({
                "condition_met": passed,
                "input": input,
            }))
        }
        "target" => Ok(serde_json::json!({
            "delivered": true,
            "data": input,
        })),
        "parallel_split" => Ok(input.clone()),
        "parallel_join" => Ok(input.clone()),
        "ws_source" => {
            if let Some(output) = config.get("output") {
                Ok(output.clone())
            } else {
                Ok(serde_json::json!({
                    "ws_connected": true,
                    "url": config.get("url").cloned().unwrap_or(serde_json::json!("unknown")),
                    "data": input,
                }))
            }
        }
        "ws_target" => {
            if let Some(output) = config.get("output") {
                Ok(output.clone())
            } else {
                Ok(serde_json::json!({
                    "ws_delivered": true,
                    "url": config.get("url").cloned().unwrap_or(serde_json::json!("unknown")),
                    "data": input,
                }))
            }
        }
        "http_stream_source" => {
            if let Some(output) = config.get("output") {
                Ok(output.clone())
            } else {
                Ok(serde_json::json!({
                    "stream_connected": true,
                    "url": config.get("url").cloned().unwrap_or(serde_json::json!("unknown")),
                    "event_filter": config.get("event_filter").cloned(),
                    "data": input,
                }))
            }
        }
        "grpc_source" => {
            if let Some(output) = config.get("output") {
                Ok(output.clone())
            } else {
                Ok(serde_json::json!({
                    "grpc_connected": true,
                    "endpoint": config.get("endpoint").cloned().unwrap_or(serde_json::json!("unknown")),
                    "data": input,
                }))
            }
        }
        "grpc_target" => {
            if let Some(output) = config.get("output") {
                Ok(output.clone())
            } else {
                Ok(serde_json::json!({
                    "grpc_delivered": true,
                    "endpoint": config.get("endpoint").cloned().unwrap_or(serde_json::json!("unknown")),
                    "data": input,
                }))
            }
        }
        "cdc_source" => {
            // CDC source produces change events from PostgreSQL WAL.
            // In simulation mode, returns config-defined output or a sample change event.
            if let Some(output) = config.get("output") {
                Ok(output.clone())
            } else {
                Ok(serde_json::json!({
                    "cdc_connected": true,
                    "replication_slot": config.get("replication_slot").cloned().unwrap_or(serde_json::json!("pipe_slot")),
                    "publication": config.get("publication").cloned().unwrap_or(serde_json::json!("pipe_pub")),
                    "tables": config.get("tables").cloned().unwrap_or(serde_json::json!([])),
                    "status": "listening",
                }))
            }
        }
        "amqp_source" => {
            if let Some(output) = config.get("output") {
                Ok(output.clone())
            } else {
                Ok(serde_json::json!({
                    "amqp_connected": true,
                    "queue": config.get("queue").cloned().unwrap_or(serde_json::json!("default")),
                    "exchange": config.get("exchange").cloned().unwrap_or(serde_json::json!("")),
                    "status": "consuming",
                    "data": input,
                }))
            }
        }
        "kafka_source" => {
            if let Some(output) = config.get("output") {
                Ok(output.clone())
            } else {
                Ok(serde_json::json!({
                    "kafka_connected": true,
                    "brokers": config.get("brokers").cloned().unwrap_or(serde_json::json!("localhost:9092")),
                    "topic": config.get("topic").cloned().unwrap_or(serde_json::json!("default")),
                    "group_id": config.get("group_id").cloned().unwrap_or(serde_json::json!("pipe_group")),
                    "status": "subscribed",
                    "data": input,
                }))
            }
        }
        _ => Err(format!("Unknown step type: {}", step_type)),
    }
}

/// Evaluates a condition config against input data.
/// Config format: {"field": "field_name", "operator": "gt|lt|eq|ne|gte|lte", "value": <val>}
pub fn evaluate_condition(config: &JsonValue, input: &JsonValue) -> bool {
    let field = match config.get("field").and_then(|f| f.as_str()) {
        Some(f) => f,
        None => return true, // No field = pass-through
    };

    let operator = match config.get("operator").and_then(|o| o.as_str()) {
        Some(o) => o,
        None => return true,
    };

    let threshold = match config.get("value") {
        Some(v) => v,
        None => return true,
    };

    let actual = match input.get(field) {
        Some(v) => v,
        None => return false, // Field missing = condition fails
    };

    match operator {
        "gt" => compare_values(actual, threshold) == Some(std::cmp::Ordering::Greater),
        "gte" => matches!(
            compare_values(actual, threshold),
            Some(std::cmp::Ordering::Greater) | Some(std::cmp::Ordering::Equal)
        ),
        "lt" => compare_values(actual, threshold) == Some(std::cmp::Ordering::Less),
        "lte" => matches!(
            compare_values(actual, threshold),
            Some(std::cmp::Ordering::Less) | Some(std::cmp::Ordering::Equal)
        ),
        "eq" => compare_values(actual, threshold) == Some(std::cmp::Ordering::Equal),
        "ne" => compare_values(actual, threshold) != Some(std::cmp::Ordering::Equal),
        _ => true,
    }
}

fn compare_values(a: &JsonValue, b: &JsonValue) -> Option<std::cmp::Ordering> {
    if let (Some(a_num), Some(b_num)) = (a.as_f64(), b.as_f64()) {
        return a_num.partial_cmp(&b_num);
    }
    if let (Some(a_str), Some(b_str)) = (a.as_str(), b.as_str()) {
        return Some(a_str.cmp(b_str));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn source_step_with_output() {
        let config = json!({"output": {"key": "value"}});
        let result = execute_step("source", &config, &json!({})).await.unwrap();
        assert_eq!(result, json!({"key": "value"}));
    }

    #[tokio::test]
    async fn source_step_passthrough() {
        let input = json!({"data": 42});
        let result = execute_step("source", &json!({}), &input).await.unwrap();
        assert_eq!(result, input);
    }

    #[tokio::test]
    async fn transform_step_with_mapping() {
        let config = json!({"mapping": {"name": true}});
        let input = json!({"name": "Alice", "age": 30});
        let result = execute_step("transform", &config, &input).await.unwrap();
        assert_eq!(result["name"], "Alice");
    }

    #[tokio::test]
    async fn transform_step_passthrough() {
        let input = json!({"x": 1});
        let result = execute_step("transform", &json!({}), &input).await.unwrap();
        assert_eq!(result, input);
    }

    #[tokio::test]
    async fn condition_step_passes() {
        let config = json!({"field": "score", "operator": "gt", "value": 50});
        let input = json!({"score": 75});
        let result = execute_step("condition", &config, &input).await.unwrap();
        assert_eq!(result["condition_met"], true);
    }

    #[tokio::test]
    async fn condition_step_fails() {
        let config = json!({"field": "score", "operator": "gt", "value": 50});
        let input = json!({"score": 25});
        let result = execute_step("condition", &config, &input).await.unwrap();
        assert_eq!(result["condition_met"], false);
    }

    #[tokio::test]
    async fn target_step() {
        let input = json!({"msg": "hello"});
        let result = execute_step("target", &json!({}), &input).await.unwrap();
        assert_eq!(result["delivered"], true);
    }

    #[tokio::test]
    async fn parallel_split_passthrough() {
        let input = json!({"data": [1, 2, 3]});
        let result = execute_step("parallel_split", &json!({}), &input)
            .await
            .unwrap();
        assert_eq!(result, input);
    }

    #[tokio::test]
    async fn parallel_join_passthrough() {
        let input = json!({"merged": true});
        let result = execute_step("parallel_join", &json!({}), &input)
            .await
            .unwrap();
        assert_eq!(result, input);
    }

    #[tokio::test]
    async fn ws_source_with_output() {
        let config = json!({"output": {"ws_data": "test"}});
        let result = execute_step("ws_source", &config, &json!({}))
            .await
            .unwrap();
        assert_eq!(result, json!({"ws_data": "test"}));
    }

    #[tokio::test]
    async fn ws_target_simulation() {
        let config = json!({"url": "ws://localhost:9999"});
        let result = execute_step("ws_target", &config, &json!({"msg": "hi"}))
            .await
            .unwrap();
        assert_eq!(result["ws_delivered"], true);
    }

    #[tokio::test]
    async fn grpc_source_with_output() {
        let config = json!({"output": {"grpc_data": "test"}});
        let result = execute_step("grpc_source", &config, &json!({}))
            .await
            .unwrap();
        assert_eq!(result, json!({"grpc_data": "test"}));
    }

    #[tokio::test]
    async fn grpc_target_simulation() {
        let config = json!({"endpoint": "http://localhost:50051"});
        let result = execute_step("grpc_target", &config, &json!({"val": 1}))
            .await
            .unwrap();
        assert_eq!(result["grpc_delivered"], true);
    }

    #[tokio::test]
    async fn http_stream_source_with_output() {
        let config = json!({"output": {"stream": "events"}});
        let result = execute_step("http_stream_source", &config, &json!({}))
            .await
            .unwrap();
        assert_eq!(result, json!({"stream": "events"}));
    }

    #[tokio::test]
    async fn cdc_source_default() {
        let config = json!({"replication_slot": "test_slot", "publication": "test_pub", "tables": ["users"]});
        let result = execute_step("cdc_source", &config, &json!({}))
            .await
            .unwrap();
        assert_eq!(result["cdc_connected"], true);
        assert_eq!(result["replication_slot"], "test_slot");
        assert_eq!(result["publication"], "test_pub");
        assert_eq!(result["status"], "listening");
    }

    #[tokio::test]
    async fn cdc_source_with_output() {
        let config = json!({"output": {"event": "insert", "table": "users"}});
        let result = execute_step("cdc_source", &config, &json!({}))
            .await
            .unwrap();
        assert_eq!(result["event"], "insert");
        assert_eq!(result["table"], "users");
    }

    #[tokio::test]
    async fn unknown_step_type_errors() {
        let result = execute_step("nonexistent", &json!({}), &json!({})).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unknown step type"));
    }

    #[tokio::test]
    async fn simulated_failure() {
        let config = json!({"error": "connection timeout"});
        let result = execute_step("source", &config, &json!({})).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "connection timeout");
    }

    #[test]
    fn condition_operators() {
        let config_gt = json!({"field": "x", "operator": "gt", "value": 5});
        assert!(evaluate_condition(&config_gt, &json!({"x": 10})));
        assert!(!evaluate_condition(&config_gt, &json!({"x": 3})));

        let config_eq = json!({"field": "x", "operator": "eq", "value": 5});
        assert!(evaluate_condition(&config_eq, &json!({"x": 5})));
        assert!(!evaluate_condition(&config_eq, &json!({"x": 6})));

        let config_ne = json!({"field": "x", "operator": "ne", "value": 5});
        assert!(evaluate_condition(&config_ne, &json!({"x": 6})));
        assert!(!evaluate_condition(&config_ne, &json!({"x": 5})));

        let config_lt = json!({"field": "x", "operator": "lt", "value": 5});
        assert!(evaluate_condition(&config_lt, &json!({"x": 3})));
        assert!(!evaluate_condition(&config_lt, &json!({"x": 7})));

        let config_gte = json!({"field": "x", "operator": "gte", "value": 5});
        assert!(evaluate_condition(&config_gte, &json!({"x": 5})));
        assert!(evaluate_condition(&config_gte, &json!({"x": 6})));
        assert!(!evaluate_condition(&config_gte, &json!({"x": 4})));

        let config_lte = json!({"field": "x", "operator": "lte", "value": 5});
        assert!(evaluate_condition(&config_lte, &json!({"x": 5})));
        assert!(evaluate_condition(&config_lte, &json!({"x": 4})));
        assert!(!evaluate_condition(&config_lte, &json!({"x": 6})));
    }

    #[test]
    fn condition_missing_field() {
        let config = json!({"field": "x", "operator": "gt", "value": 5});
        assert!(!evaluate_condition(&config, &json!({"y": 10})));
    }

    #[test]
    fn condition_no_field_passthrough() {
        let config = json!({"operator": "gt", "value": 5});
        assert!(evaluate_condition(&config, &json!({"x": 10})));
    }

    #[test]
    fn condition_string_comparison() {
        let config = json!({"field": "name", "operator": "eq", "value": "Alice"});
        assert!(evaluate_condition(&config, &json!({"name": "Alice"})));
        assert!(!evaluate_condition(&config, &json!({"name": "Bob"})));
    }
}
