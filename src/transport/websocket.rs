use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use serde_json::Value;
use std::time::Duration;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tracing::{debug, info, warn};

const WS_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Connect to a WebSocket endpoint and read the first message as pipe source data.
pub async fn ws_fetch_source(url: &str) -> Result<Value> {
    info!(url, "ws_fetch_source: connecting");
    let (ws_stream, _) = connect_async(url)
        .await
        .with_context(|| format!("WebSocket connection failed: {url}"))?;

    let (mut write, mut read) = ws_stream.split();

    loop {
        let msg = tokio::time::timeout(WS_READ_TIMEOUT, read.next())
            .await
            .with_context(|| format!("ws_fetch_source: timed out after {WS_READ_TIMEOUT:?}"))?;

        match msg {
            Some(Ok(Message::Text(text))) => {
                debug!(len = text.len(), "ws_fetch_source: received text");
                return serde_json::from_str::<Value>(&text)
                    .with_context(|| "ws_fetch_source: failed to parse JSON");
            }
            Some(Ok(Message::Binary(bin))) => {
                debug!(len = bin.len(), "ws_fetch_source: received binary");
                return serde_json::from_slice::<Value>(&bin)
                    .with_context(|| "ws_fetch_source: failed to parse binary JSON");
            }
            Some(Ok(Message::Ping(payload))) => {
                debug!(len = payload.len(), "ws_fetch_source: received ping");
                write
                    .send(Message::Pong(payload))
                    .await
                    .with_context(|| "ws_fetch_source: failed to send pong")?;
            }
            Some(Ok(Message::Pong(_))) => {
                debug!("ws_fetch_source: received pong, ignoring");
            }
            Some(Ok(Message::Close(frame))) => {
                return Err(anyhow::anyhow!(
                    "ws_fetch_source: stream closed before data: {frame:?}"
                ));
            }
            Some(Ok(other)) => {
                debug!(message = %other, "ws_fetch_source: ignoring non-data frame");
            }
            Some(Err(e)) => return Err(anyhow::anyhow!("ws_fetch_source read error: {e}")),
            None => {
                return Err(anyhow::anyhow!(
                    "ws_fetch_source: stream closed without data"
                ))
            }
        }
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
        .send(Message::Text(payload.into()))
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

    let (mut write, mut read) = ws_stream.split();

    while let Some(msg) = read.next().await {
        match msg {
            Ok(Message::Text(text)) => {
                debug!(len = text.len(), "stream message received");
            }
            Ok(Message::Ping(payload)) => {
                debug!(len = payload.len(), "stream ping received");
                if let Err(e) = write.send(Message::Pong(payload)).await {
                    warn!(error = %e, "failed to send pong");
                    break;
                }
            }
            Ok(Message::Close(frame)) => {
                info!("stream closed by server");
                if let Err(e) = write.send(Message::Close(frame)).await {
                    warn!(error = %e, "failed to acknowledge close frame");
                }
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
