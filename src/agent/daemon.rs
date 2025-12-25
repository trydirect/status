use std::sync::Arc;

use anyhow::Result;
use tokio::signal;
use tokio::sync::{broadcast, RwLock};
use tokio::time::Duration;
use tracing::info;

use crate::agent::config::Config;
use crate::monitoring::{spawn_heartbeat, MetricsCollector, MetricsSnapshot, MetricsStore};

pub async fn run(config_path: String) -> Result<()> {
    let cfg = Config::from_file(&config_path)?;
    info!(domain=?cfg.domain, "Agent daemon starting");

    let collector = Arc::new(MetricsCollector::new());
    let store: MetricsStore = Arc::new(RwLock::new(MetricsSnapshot::default()));
    let (tx, _) = broadcast::channel(32);
    let webhook = std::env::var("METRICS_WEBHOOK").ok();
    let interval = std::env::var("METRICS_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(10));

    let heartbeat_handle = spawn_heartbeat(collector, store, interval, tx, webhook.clone());
    info!(
        interval_secs = interval.as_secs(),
        webhook = webhook.as_deref().unwrap_or("none"),
        "metrics heartbeat started"
    );

    // Wait for shutdown signal (Ctrl+C) then stop the heartbeat loop
    signal::ctrl_c().await?;
    info!("shutdown signal received, stopping daemon");

    heartbeat_handle.abort();
    let _ = heartbeat_handle.await; // Ignore cancellation errors

    Ok(())
}
