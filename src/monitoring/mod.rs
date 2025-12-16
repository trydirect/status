use serde::Serialize;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, RwLock};
use tokio::task::JoinHandle;
use sysinfo::{Disks, System};
use tracing::info;
use tokio::sync::broadcast;
use reqwest::Client;

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

pub type MetricsStore = Arc<RwLock<MetricsSnapshot>>;
pub type MetricsTx = broadcast::Sender<MetricsSnapshot>;

/// Collects host metrics using sysinfo.
#[derive(Debug)]
pub struct MetricsCollector {
	system: Mutex<System>,
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

		// sysinfo reports memory in KiB; convert to bytes for clarity.
		let memory_total_bytes = system.total_memory() * 1024;
		let memory_used_bytes = system.used_memory() * 1024;
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
				tokio::spawn(async move {
					if let Err(e) = http.post(url).json(&payload).send().await {
						tracing::warn!("metrics webhook push failed: {}", e);
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
