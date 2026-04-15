use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use serde_json::Value;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tracing::{debug, info, warn};

/// Connect to a WebSocket endpoint and read the first message as pipe source data.
pub async fn ws_fetch_source(url: &str) -> Result<Value> {
    info!(url, "ws_fetch_source: connecting");
    let (ws_stream, _) = connect_async(url)
        .await
        .with_context(|| format!("WebSocket connection failed: {url}"))?;

    let (_write, mut read) = ws_stream.split();

    match read.next().await {
        Some(Ok(Message::Text(text))) => {
            debug!(len = text.len(), "ws_fetch_source: received text");
            serde_json::from_str::<Value>(&text)
                .with_context(|| "ws_fetch_source: failed to parse JSON")
        }
        Some(Ok(Message::Binary(bin))) => {
            debug!(len = bin.len(), "ws_fetch_source: received binary");
            serde_json::from_slice::<Value>(&bin)
                .with_context(|| "ws_fetch_source: failed to parse binary JSON")
        }
        Some(Ok(other)) => Ok(serde_json::json!({ "raw": other.to_string() })),
        Some(Err(e)) => Err(anyhow::anyhow!("ws_fetch_source read error: {e}")),
        None => Err(anyhow::anyhow!(
            "ws_fetch_source: stream closed without data"
        )),
    }
}

/// Send JSON data to a WebSocket endpoint (pipe target).
pub async fn ws_send_target(url: &str, data: &Value) -> Result<(u16, Value)> {
    info!(url, "ws_send_target: connecting");
    let (ws_stream, _) = connect_async(url)
        .await
        .with_context(|| format!("WebSocket connection failed: {url}"))?;

    let (mut write, _read) = ws_stream.split();

    let payload =
        serde_json::to_string(data).with_context(|| "ws_send_target: failed to serialize")?;

    write
        .send(Message::Text(payload))
        .await
        .with_context(|| "ws_send_target: failed to send")?;

    info!(url, "ws_send_target: data sent");
    Ok((200, serde_json::json!({"ws_delivered": true})))
}

/// Connect to a WebSocket endpoint for streaming logs/metrics/status.
/// Reads messages in a loop until the stream closes or an error occurs.
pub async fn connect_and_stream(ws_url: &str) -> Result<()> {
    info!(ws_url, "connect_and_stream: connecting");
    let (ws_stream, _) = connect_async(ws_url)
        .await
        .with_context(|| format!("WebSocket streaming connection failed: {ws_url}"))?;

    let (_write, mut read) = ws_stream.split();

    while let Some(msg) = read.next().await {
        match msg {
            Ok(Message::Text(text)) => {
                debug!(len = text.len(), "stream message received");
            }
            Ok(Message::Ping(_)) => {
                debug!("stream ping received");
            }
            Ok(Message::Close(_)) => {
                info!("stream closed by server");
                break;
            }
            Err(e) => {
                warn!(error = %e, "stream error");
                break;
            }
            _ => {}
        }
    }

    Ok(())
}
