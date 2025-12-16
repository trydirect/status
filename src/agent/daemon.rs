use anyhow::Result;
use tokio::time::{sleep, Duration};
use tracing::info;

use crate::agent::config::Config;

pub async fn run(config_path: String) -> Result<()> {
    let cfg = Config::from_file(&config_path)?;
    info!(domain=?cfg.domain, "Agent daemon starting");

    // @todo implement heartbeat, local API, metrics, module checks per GOAL.md
    loop {
        // Simulate heartbeat
        info!("heartbeat");
        sleep(Duration::from_secs(10)).await;
    }
}
