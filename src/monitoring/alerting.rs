use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use reqwest::Client;
use serde::Serialize;
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::monitoring::MetricsSnapshot;

// ---- Types ----

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertSeverity {
    Warning,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertKind {
    HighCpu,
    HighMemory,
    HighDisk,
}

impl std::fmt::Display for AlertKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlertKind::HighCpu => write!(f, "high_cpu"),
            AlertKind::HighMemory => write!(f, "high_memory"),
            AlertKind::HighDisk => write!(f, "high_disk"),
        }
    }
}

/// An alert event ready for dispatch.
#[derive(Debug, Clone, Serialize)]
pub struct Alert {
    pub kind: AlertKind,
    pub severity: AlertSeverity,
    pub message: String,
    pub value: f32,
    pub threshold: f32,
    pub recovered: bool,
    pub timestamp_ms: u128,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
}

/// Threshold configuration for a single metric.
#[derive(Debug, Clone, Copy)]
pub struct Threshold {
    pub warning: f32,
    pub critical: f32,
}

impl Threshold {
    fn evaluate(&self, value: f32) -> Option<AlertSeverity> {
        if value >= self.critical {
            Some(AlertSeverity::Critical)
        } else if value >= self.warning {
            Some(AlertSeverity::Warning)
        } else {
            None
        }
    }
}

/// Alert system configuration.
#[derive(Debug, Clone)]
pub struct AlertConfig {
    pub webhook_url: Option<String>,
    pub cpu: Threshold,
    pub memory: Threshold,
    pub disk: Threshold,
}

impl AlertConfig {
    /// Build config from environment variables.
    ///
    /// | Variable | Default | Description |
    /// |----------|---------|-------------|
    /// | `ALERT_WEBHOOK_URL` | _(none)_ | Webhook endpoint; alerting disabled if unset |
    /// | `ALERT_CPU_WARNING` | 80 | CPU % warning threshold |
    /// | `ALERT_CPU_CRITICAL` | 95 | CPU % critical threshold |
    /// | `ALERT_MEMORY_WARNING` | 80 | Memory % warning threshold |
    /// | `ALERT_MEMORY_CRITICAL` | 95 | Memory % critical threshold |
    /// | `ALERT_DISK_WARNING` | 80 | Disk % warning threshold |
    /// | `ALERT_DISK_CRITICAL` | 95 | Disk % critical threshold |
    pub fn from_env() -> Self {
        let parse = |var: &str, default: f32| -> f32 {
            std::env::var(var)
                .ok()
                .and_then(|v| v.parse::<f32>().ok())
                .unwrap_or(default)
        };

        Self {
            webhook_url: std::env::var("ALERT_WEBHOOK_URL").ok(),
            cpu: Threshold {
                warning: parse("ALERT_CPU_WARNING", 80.0),
                critical: parse("ALERT_CPU_CRITICAL", 95.0),
            },
            memory: Threshold {
                warning: parse("ALERT_MEMORY_WARNING", 80.0),
                critical: parse("ALERT_MEMORY_CRITICAL", 95.0),
            },
            disk: Threshold {
                warning: parse("ALERT_DISK_WARNING", 80.0),
                critical: parse("ALERT_DISK_CRITICAL", 95.0),
            },
        }
    }
}

// ---- Alert State Tracker (deduplication + recovery) ----

/// Tracks which alerts are currently active so we avoid duplicates and detect recovery.
#[derive(Debug, Clone)]
struct ActiveAlert {
    severity: AlertSeverity,
    #[allow(dead_code)]
    fired_at_ms: u128,
}

/// Evaluates metrics against thresholds, deduplicates, and detects recovery.
#[derive(Debug)]
pub struct AlertManager {
    config: AlertConfig,
    active: RwLock<HashMap<AlertKind, ActiveAlert>>,
    agent_id: Option<String>,
}

pub type SharedAlertManager = Arc<AlertManager>;

impl AlertManager {
    pub fn new(config: AlertConfig) -> Self {
        let agent_id = std::env::var("AGENT_ID").ok();
        Self {
            config,
            active: RwLock::new(HashMap::new()),
            agent_id,
        }
    }

    /// Returns `true` if alerting is enabled (webhook URL configured).
    pub fn is_enabled(&self) -> bool {
        self.config
            .webhook_url
            .as_ref()
            .is_some_and(|u| !u.is_empty())
    }

    /// Read-only access to the alert configuration.
    pub fn config(&self) -> &AlertConfig {
        &self.config
    }

    /// Evaluate a metrics snapshot and return any new, escalated, or recovery alerts.
    pub async fn evaluate(&self, snapshot: &MetricsSnapshot) -> Vec<Alert> {
        let checks: [(AlertKind, f32, &Threshold); 3] = [
            (AlertKind::HighCpu, snapshot.cpu_usage_pct, &self.config.cpu),
            (
                AlertKind::HighMemory,
                snapshot.memory_used_pct,
                &self.config.memory,
            ),
            (
                AlertKind::HighDisk,
                snapshot.disk_used_pct,
                &self.config.disk,
            ),
        ];

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or_default();

        let mut alerts = Vec::new();
        let mut active = self.active.write().await;

        for (kind, value, threshold) in checks {
            match threshold.evaluate(value) {
                Some(severity) => {
                    // Check if already firing at this severity (dedup)
                    let should_fire = match active.get(&kind) {
                        Some(existing) => existing.severity != severity,
                        None => true,
                    };

                    if should_fire {
                        let label = match kind {
                            AlertKind::HighCpu => "CPU usage",
                            AlertKind::HighMemory => "Memory usage",
                            AlertKind::HighDisk => "Disk usage",
                        };
                        let threshold_val = match severity {
                            AlertSeverity::Warning => threshold.warning,
                            AlertSeverity::Critical => threshold.critical,
                        };
                        alerts.push(Alert {
                            kind,
                            severity,
                            message: format!(
                                "{} at {:.1}% (threshold: {:.0}%)",
                                label, value, threshold_val
                            ),
                            value,
                            threshold: threshold_val,
                            recovered: false,
                            timestamp_ms: now_ms,
                            agent_id: self.agent_id.clone(),
                        });

                        active.insert(
                            kind,
                            ActiveAlert {
                                severity,
                                fired_at_ms: now_ms,
                            },
                        );
                    }
                }
                None => {
                    // Value dropped below all thresholds — recovery
                    if active.remove(&kind).is_some() {
                        let label = match kind {
                            AlertKind::HighCpu => "CPU usage",
                            AlertKind::HighMemory => "Memory usage",
                            AlertKind::HighDisk => "Disk usage",
                        };
                        alerts.push(Alert {
                            kind,
                            severity: AlertSeverity::Warning,
                            message: format!("{} recovered to {:.1}%", label, value),
                            value,
                            threshold: threshold.warning,
                            recovered: true,
                            timestamp_ms: now_ms,
                            agent_id: self.agent_id.clone(),
                        });
                    }
                }
            }
        }

        alerts
    }
}

// ---- Webhook Dispatcher ----

/// Payload sent to the alert webhook.
#[derive(Debug, Serialize)]
struct WebhookPayload {
    alerts: Vec<Alert>,
    agent_id: Option<String>,
    timestamp_ms: u128,
}

/// Dispatch alerts to the configured webhook with retry and backoff.
pub async fn dispatch_alerts(
    client: &Client,
    webhook_url: &str,
    alerts: Vec<Alert>,
    agent_id: Option<String>,
) {
    if alerts.is_empty() {
        return;
    }

    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or_default();

    let payload = WebhookPayload {
        alerts,
        agent_id: agent_id.clone(),
        timestamp_ms: now_ms,
    };

    let max_retries: u8 = 3;
    let mut delay = Duration::from_secs(1);

    for attempt in 1..=max_retries {
        let mut req = client.post(webhook_url).json(&payload);
        if let Some(aid) = agent_id.as_ref() {
            req = req.header("X-Agent-Id", aid);
        }

        match req.send().await {
            Ok(resp) => {
                let status = resp.status();
                if status.is_success() {
                    info!(count = payload.alerts.len(), "alerts dispatched to webhook");
                    return;
                }
                if status.is_client_error() {
                    warn!(
                        attempt,
                        status = %status,
                        "alert webhook client error; not retrying"
                    );
                    return;
                }
                warn!(
                    attempt,
                    status = %status,
                    "alert webhook server error; retrying"
                );
            }
            Err(e) => {
                warn!(attempt, error = %e, "alert webhook dispatch failed; retrying");
            }
        }

        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(Duration::from_secs(16));
    }

    warn!("alert dispatch exhausted retries");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config(warning: f32, critical: f32) -> AlertConfig {
        AlertConfig {
            webhook_url: Some("http://test/alerts".into()),
            cpu: Threshold { warning, critical },
            memory: Threshold { warning, critical },
            disk: Threshold { warning, critical },
        }
    }

    fn snapshot_with(cpu: f32, mem: f32, disk: f32) -> MetricsSnapshot {
        MetricsSnapshot {
            timestamp_ms: 1700000000000,
            cpu_usage_pct: cpu,
            memory_total_bytes: 16_000_000_000,
            memory_used_bytes: 8_000_000_000,
            memory_used_pct: mem,
            disk_total_bytes: 500_000_000_000,
            disk_used_bytes: 250_000_000_000,
            disk_used_pct: disk,
        }
    }

    #[test]
    fn threshold_evaluate_below() {
        let t = Threshold {
            warning: 80.0,
            critical: 95.0,
        };
        assert_eq!(t.evaluate(50.0), None);
    }

    #[test]
    fn threshold_evaluate_warning() {
        let t = Threshold {
            warning: 80.0,
            critical: 95.0,
        };
        assert_eq!(t.evaluate(85.0), Some(AlertSeverity::Warning));
    }

    #[test]
    fn threshold_evaluate_critical() {
        let t = Threshold {
            warning: 80.0,
            critical: 95.0,
        };
        assert_eq!(t.evaluate(96.0), Some(AlertSeverity::Critical));
    }

    #[test]
    fn threshold_evaluate_exact_boundary() {
        let t = Threshold {
            warning: 80.0,
            critical: 95.0,
        };
        assert_eq!(t.evaluate(80.0), Some(AlertSeverity::Warning));
        assert_eq!(t.evaluate(95.0), Some(AlertSeverity::Critical));
    }

    #[tokio::test]
    async fn no_alerts_when_all_normal() {
        let mgr = AlertManager::new(test_config(80.0, 95.0));
        let snap = snapshot_with(30.0, 40.0, 50.0);
        let alerts = mgr.evaluate(&snap).await;
        assert!(alerts.is_empty());
    }

    #[tokio::test]
    async fn fires_warning_on_high_cpu() {
        let mgr = AlertManager::new(test_config(80.0, 95.0));
        let snap = snapshot_with(85.0, 40.0, 50.0);
        let alerts = mgr.evaluate(&snap).await;
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].kind, AlertKind::HighCpu);
        assert_eq!(alerts[0].severity, AlertSeverity::Warning);
        assert!(!alerts[0].recovered);
    }

    #[tokio::test]
    async fn fires_critical_on_high_memory() {
        let mgr = AlertManager::new(test_config(80.0, 95.0));
        let snap = snapshot_with(30.0, 96.0, 50.0);
        let alerts = mgr.evaluate(&snap).await;
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].kind, AlertKind::HighMemory);
        assert_eq!(alerts[0].severity, AlertSeverity::Critical);
    }

    #[tokio::test]
    async fn dedup_same_severity() {
        let mgr = AlertManager::new(test_config(80.0, 95.0));
        let snap = snapshot_with(85.0, 40.0, 50.0);

        let first = mgr.evaluate(&snap).await;
        assert_eq!(first.len(), 1);

        // Same severity again → deduplicated
        let second = mgr.evaluate(&snap).await;
        assert!(second.is_empty());
    }

    #[tokio::test]
    async fn escalation_fires_new_alert() {
        let mgr = AlertManager::new(test_config(80.0, 95.0));

        // Warning
        let alerts = mgr.evaluate(&snapshot_with(85.0, 40.0, 50.0)).await;
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].severity, AlertSeverity::Warning);

        // Escalate to critical
        let alerts = mgr.evaluate(&snapshot_with(96.0, 40.0, 50.0)).await;
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].severity, AlertSeverity::Critical);
    }

    #[tokio::test]
    async fn recovery_fires_alert() {
        let mgr = AlertManager::new(test_config(80.0, 95.0));

        // Fire
        let _ = mgr.evaluate(&snapshot_with(85.0, 40.0, 50.0)).await;

        // Recover
        let alerts = mgr.evaluate(&snapshot_with(50.0, 40.0, 50.0)).await;
        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].recovered);
        assert_eq!(alerts[0].kind, AlertKind::HighCpu);
    }

    #[tokio::test]
    async fn multiple_alerts_at_once() {
        let mgr = AlertManager::new(test_config(80.0, 95.0));
        let snap = snapshot_with(96.0, 90.0, 85.0);
        let alerts = mgr.evaluate(&snap).await;
        assert_eq!(alerts.len(), 3);
    }

    #[tokio::test]
    async fn recovery_only_fires_once() {
        let mgr = AlertManager::new(test_config(80.0, 95.0));

        let _ = mgr.evaluate(&snapshot_with(85.0, 40.0, 50.0)).await;
        let recovery = mgr.evaluate(&snapshot_with(50.0, 40.0, 50.0)).await;
        assert_eq!(recovery.len(), 1);

        // No more recovery alerts
        let again = mgr.evaluate(&snapshot_with(50.0, 40.0, 50.0)).await;
        assert!(again.is_empty());
    }

    #[test]
    fn alert_kind_display() {
        assert_eq!(AlertKind::HighCpu.to_string(), "high_cpu");
        assert_eq!(AlertKind::HighMemory.to_string(), "high_memory");
        assert_eq!(AlertKind::HighDisk.to_string(), "high_disk");
    }

    #[test]
    fn alert_serialization() {
        let alert = Alert {
            kind: AlertKind::HighCpu,
            severity: AlertSeverity::Critical,
            message: "CPU at 96%".into(),
            value: 96.0,
            threshold: 95.0,
            recovered: false,
            timestamp_ms: 1700000000000,
            agent_id: Some("agent-1".into()),
        };
        let json = serde_json::to_string(&alert).unwrap();
        assert!(json.contains("\"kind\":\"high_cpu\""));
        assert!(json.contains("\"severity\":\"critical\""));
        assert!(json.contains("\"recovered\":false"));
    }

    #[test]
    fn alert_config_defaults() {
        // Don't set env vars — test defaults
        let cfg = AlertConfig {
            webhook_url: None,
            cpu: Threshold {
                warning: 80.0,
                critical: 95.0,
            },
            memory: Threshold {
                warning: 80.0,
                critical: 95.0,
            },
            disk: Threshold {
                warning: 80.0,
                critical: 95.0,
            },
        };
        assert!(cfg.webhook_url.is_none());
        assert_eq!(cfg.cpu.warning, 80.0);
        assert_eq!(cfg.disk.critical, 95.0);
    }

    #[test]
    fn alert_manager_disabled_without_webhook() {
        let config = AlertConfig {
            webhook_url: None,
            cpu: Threshold {
                warning: 80.0,
                critical: 95.0,
            },
            memory: Threshold {
                warning: 80.0,
                critical: 95.0,
            },
            disk: Threshold {
                warning: 80.0,
                critical: 95.0,
            },
        };
        let mgr = AlertManager::new(config);
        assert!(!mgr.is_enabled());
    }

    #[test]
    fn alert_manager_enabled_with_webhook() {
        let config = AlertConfig {
            webhook_url: Some("http://hooks.example.com/alerts".into()),
            cpu: Threshold {
                warning: 80.0,
                critical: 95.0,
            },
            memory: Threshold {
                warning: 80.0,
                critical: 95.0,
            },
            disk: Threshold {
                warning: 80.0,
                critical: 95.0,
            },
        };
        let mgr = AlertManager::new(config);
        assert!(mgr.is_enabled());
    }
}
