use futures_util::{SinkExt, StreamExt};
use serde_json::Value as JsonValue;
use tokio_tungstenite::{connect_async, tungstenite::Message};

/// Connect to a WebSocket endpoint and read the first message as source data.
/// If `config.output` is set, returns it directly (simulation mode for BDD tests).
pub async fn execute_ws_source(
    config: &JsonValue,
    _input: &JsonValue,
) -> Result<JsonValue, String> {
    if let Some(output) = config.get("output") {
        return Ok(output.clone());
    }

    let url = config
        .get("url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "ws_source requires a 'url' in config".to_string())?;

    let (ws_stream, _) = connect_async(url)
        .await
        .map_err(|e| format!("ws_source connection failed: {e}"))?;

    let (_write, mut read) = ws_stream.split();

    match read.next().await {
        Some(Ok(Message::Text(text))) => serde_json::from_str::<JsonValue>(&text)
            .map_err(|e| format!("ws_source JSON parse error: {e}")),
        Some(Ok(Message::Binary(bin))) => serde_json::from_slice::<JsonValue>(&bin)
            .map_err(|e| format!("ws_source binary parse error: {e}")),
        Some(Ok(other)) => Ok(serde_json::json!({ "raw": other.to_string() })),
        Some(Err(e)) => Err(format!("ws_source read error: {e}")),
        None => Err("ws_source: stream closed without data".to_string()),
    }
}

/// Connect to a WebSocket endpoint and send the input data as a JSON message.
/// If `config.output` is set, returns it directly (simulation mode).
pub async fn execute_ws_target(config: &JsonValue, input: &JsonValue) -> Result<JsonValue, String> {
    if let Some(output) = config.get("output") {
        return Ok(output.clone());
    }

    let url = config
        .get("url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "ws_target requires a 'url' in config".to_string())?;

    let (ws_stream, _) = connect_async(url)
        .await
        .map_err(|e| format!("ws_target connection failed: {e}"))?;

    let (mut write, _read) = ws_stream.split();

    let payload =
        serde_json::to_string(input).map_err(|e| format!("ws_target serialize error: {e}"))?;

    write
        .send(Message::Text(payload))
        .await
        .map_err(|e| format!("ws_target send error: {e}"))?;

    Ok(serde_json::json!({
        "ws_delivered": true,
        "url": url,
        "data": input,
    }))
}

/// Connect to an SSE (Server-Sent Events) HTTP endpoint and read the first data event.
/// If `config.output` is set, returns it directly (simulation mode).
pub async fn execute_http_stream_source(
    config: &JsonValue,
    _input: &JsonValue,
) -> Result<JsonValue, String> {
    if let Some(output) = config.get("output") {
        return Ok(output.clone());
    }

    let url = config
        .get("url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "http_stream_source requires a 'url' in config".to_string())?;

    let event_filter = config
        .get("event_filter")
        .and_then(|v| v.as_str())
        .unwrap_or("message");

    let response = reqwest::get(url)
        .await
        .map_err(|e| format!("http_stream_source request failed: {e}"))?;

    let mut stream = response.bytes_stream();
    let mut buffer = String::new();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| format!("http_stream_source read error: {e}"))?;
        buffer.push_str(&String::from_utf8_lossy(&chunk));

        // Parse SSE: look for "event: <type>\ndata: <json>\n\n"
        if let Some(data) = parse_sse_event(&buffer, event_filter) {
            return serde_json::from_str::<JsonValue>(&data)
                .or_else(|_| Ok(serde_json::json!({ "raw": data })));
        }
    }

    Err("http_stream_source: stream ended without matching event".to_string())
}

fn parse_sse_event(buffer: &str, event_filter: &str) -> Option<String> {
    for block in buffer.split("\n\n") {
        let mut event_type = "message";
        let mut data_lines = Vec::new();

        for line in block.lines() {
            if let Some(rest) = line.strip_prefix("event:") {
                event_type = rest.trim();
            } else if let Some(rest) = line.strip_prefix("data:") {
                data_lines.push(rest.trim());
            }
        }

        if event_type == event_filter && !data_lines.is_empty() {
            return Some(data_lines.join("\n"));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sse_event_basic() {
        let buf = "event: data_update\ndata: {\"key\":\"val\"}\n\n";
        let result = parse_sse_event(buf, "data_update");
        assert_eq!(result, Some("{\"key\":\"val\"}".to_string()));
    }

    #[test]
    fn test_parse_sse_event_no_match() {
        let buf = "event: other\ndata: {}\n\n";
        assert!(parse_sse_event(buf, "data_update").is_none());
    }

    #[tokio::test]
    async fn test_ws_source_simulation() {
        let config = serde_json::json!({"output": {"sensor": "temp", "value": 42}});
        let input = serde_json::json!({});
        let result = execute_ws_source(&config, &input).await.unwrap();
        assert_eq!(result["sensor"], "temp");
        assert_eq!(result["value"], 42);
    }

    #[tokio::test]
    async fn test_ws_target_simulation() {
        let config = serde_json::json!({"output": {"delivered": true}});
        let input = serde_json::json!({"data": 1});
        let result = execute_ws_target(&config, &input).await.unwrap();
        assert!(result["delivered"].as_bool().unwrap());
    }

    #[tokio::test]
    async fn test_http_stream_source_simulation() {
        let config = serde_json::json!({"output": {"event": "tick"}});
        let input = serde_json::json!({});
        let result = execute_http_stream_source(&config, &input).await.unwrap();
        assert_eq!(result["event"], "tick");
    }
}
