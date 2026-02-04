use reqwest::Client;
use serde::Serialize;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use sysinfo::{Disks, System};
use tokio::sync::broadcast;
use tokio::sync::{Mutex, RwLock};
use tokio::task::JoinHandle;
use tracing::info;

#[derive(Debug, Clone, Serialize, Default)]
pub struct MetricsSnapshot {
    pub timestamp_ms: u128,
    pub cpu_usage_pct: f32,
    pub memory_total_bytes: u64,
    pub memory_used_bytes: u64,
    pub memory_used_pct: f32,
    pub disk_total_bytes: u64,
    pub disk_used_bytes: u64,
    pub disk_used_pct: f32,
}

/// Control plane that executed a command
#[derive(Debug, Clone, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ControlPlane {
    StatusPanel,
    ComposeAgent,
}

impl std::fmt::Display for ControlPlane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ControlPlane::StatusPanel => write!(f, "status_panel"),
            ControlPlane::ComposeAgent => write!(f, "compose_agent"),
        }
    }
}

/// Metrics for command execution tracking by control plane
#[derive(Debug, Clone, Serialize, Default)]
pub struct CommandExecutionMetrics {
    pub status_panel_count: u64,
    pub compose_agent_count: u64,
    pub total_count: u64,
    pub last_control_plane: Option<String>,
    pub last_command_timestamp_ms: u128,
}

/// Store for command execution metrics
pub type CommandMetricsStore = Arc<RwLock<CommandExecutionMetrics>>;

impl CommandExecutionMetrics {
    /// Record a command execution from a specific control plane
    pub fn record_execution(&mut self, control_plane: ControlPlane) {
        match control_plane {
            ControlPlane::StatusPanel => self.status_panel_count += 1,
            ControlPlane::ComposeAgent => self.compose_agent_count += 1,
        }
        self.total_count += 1;
        self.last_control_plane = Some(control_plane.to_string());
        self.last_command_timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or_default();
    }
}

pub type MetricsStore = Arc<RwLock<MetricsSnapshot>>;
pub type MetricsTx = broadcast::Sender<MetricsSnapshot>;

/// Collects host metrics using sysinfo.
#[derive(Debug)]
pub struct MetricsCollector {
    system: Mutex<System>,
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsCollector {
    pub fn new() -> Self {
        let mut system = System::new_all();
        system.refresh_all();
        Self {
            system: Mutex::new(system),
        }
    }

    /// Capture a fresh snapshot of system metrics.
    pub async fn snapshot(&self) -> MetricsSnapshot {
        let mut system = self.system.lock().await;
        system.refresh_all();

        let cpu_usage_pct = system.global_cpu_info().cpu_usage();

        // sysinfo 0.30+ reports memory in bytes directly
        let memory_total_bytes = system.total_memory();
        let memory_used_bytes = system.used_memory();
        let memory_used_pct = if memory_total_bytes > 0 {
            (memory_used_bytes as f64 / memory_total_bytes as f64 * 100.0) as f32
        } else {
            0.0
        };

        let mut disk_total_bytes = 0u64;
        let mut disk_used_bytes = 0u64;

        let mut disks = Disks::new_with_refreshed_list();
        disks.refresh();
        for disk in disks.list() {
            let total = disk.total_space();
            let available = disk.available_space();
            disk_total_bytes = disk_total_bytes.saturating_add(total);
            disk_used_bytes = disk_used_bytes.saturating_add(total.saturating_sub(available));
        }
        let disk_used_pct = if disk_total_bytes > 0 {
            (disk_used_bytes as f64 / disk_total_bytes as f64 * 100.0) as f32
        } else {
            0.0
        };

        MetricsSnapshot {
            timestamp_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or_default(),
            cpu_usage_pct,
            memory_total_bytes,
            memory_used_bytes,
            memory_used_pct,
            disk_total_bytes,
            disk_used_bytes,
            disk_used_pct,
        }
    }
}

/// Periodically refresh metrics and log a lightweight heartbeat.
pub fn spawn_heartbeat(
    collector: Arc<MetricsCollector>,
    store: MetricsStore,
    interval: Duration,
    tx: MetricsTx,
    webhook: Option<String>,
) -> JoinHandle<()> {
    let client = webhook.as_ref().map(|_| Client::new());
    let agent_id = std::env::var("AGENT_ID").ok();
    tokio::spawn(async move {
        loop {
            let snapshot = collector.snapshot().await;

            {
                let mut guard = store.write().await;
                *guard = snapshot.clone();
            }

            // Broadcast to websocket subscribers; ignore if no receivers.
            let _ = tx.send(snapshot.clone());

            // Optional remote push
            if let (Some(url), Some(http)) = (webhook.as_ref(), client.as_ref()) {
                let http = http.clone();
                let url = url.clone();
                let payload = snapshot.clone();
                let agent = agent_id.clone();
                tokio::spawn(async move {
                    // Exponential backoff with jitter; stop on success or client 4xx
                    let max_retries: u8 = 5;
                    let mut delay = Duration::from_millis(500);
                    for attempt in 1..=max_retries {
                        let mut req = http.post(url.clone()).json(&payload);
                        if let Some(aid) = agent.as_ref() {
                            req = req.header("X-Agent-Id", aid);
                        }

                        match req.send().await {
                            Ok(resp) => {
                                let status = resp.status();
                                if status.is_success() {
                                    tracing::debug!(attempt, status = %status, "metrics webhook push succeeded");
                                    break;
                                } else if status.is_client_error() {
                                    // Do not retry on client-side errors (e.g., 401/403/404)
                                    tracing::warn!(attempt, status = %status, "metrics webhook push client error; not retrying");
                                    break;
                                } else {
                                    tracing::warn!(attempt, status = %status, "metrics webhook push server error; will retry");
                                }
                            }
                            Err(e) => {
                                tracing::warn!(attempt, error = %e, "metrics webhook push failed; will retry");
                            }
                        }

                        // Jitter derived from current time to avoid herd effects
                        let nanos = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .map(|d| d.subsec_nanos())
                            .unwrap_or(0);
                        let jitter = Duration::from_millis(50 + (nanos % 200) as u64);
                        tokio::time::sleep(delay + jitter).await;
                        // Exponential backoff capped at ~8s
                        delay = delay.saturating_mul(2).min(Duration::from_secs(8));
                    }
                });
            }

            info!(
                cpu = snapshot.cpu_usage_pct,
                mem_used_bytes = snapshot.memory_used_bytes,
                mem_total_bytes = snapshot.memory_total_bytes,
                disk_used_bytes = snapshot.disk_used_bytes,
                disk_total_bytes = snapshot.disk_total_bytes,
                "heartbeat metrics refreshed"
            );

            tokio::time::sleep(interval).await;
        }
    })
}
