use super::models::{ComponentHealth, ComponentStatus};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct MetricSnapshot {
    #[allow(dead_code)]
    pub timestamp: DateTime<Utc>,
    pub component: String,
    pub status: ComponentStatus,
    pub response_time_ms: Option<u64>,
}

pub struct HealthMetrics {
    snapshots: Arc<RwLock<Vec<MetricSnapshot>>>,
    max_snapshots: usize,
}

impl HealthMetrics {
    pub fn new(max_snapshots: usize) -> Self {
        Self {
            snapshots: Arc::new(RwLock::new(Vec::new())),
            max_snapshots,
        }
    }

    pub async fn record(&self, component: String, health: &ComponentHealth) {
        let snapshot = MetricSnapshot {
            timestamp: health.last_checked,
            component,
            status: health.status.clone(),
            response_time_ms: health.response_time_ms,
        };

        let mut snapshots = self.snapshots.write().await;
        snapshots.push(snapshot);

        if snapshots.len() > self.max_snapshots {
            snapshots.remove(0);
        }
    }

    pub async fn get_component_stats(
        &self,
        component: &str,
    ) -> Option<HashMap<String, serde_json::Value>> {
        let snapshots = self.snapshots.read().await;
        let component_snapshots: Vec<_> = snapshots
            .iter()
            .filter(|s| s.component == component)
            .collect();

        if component_snapshots.is_empty() {
            return None;
        }

        let total = component_snapshots.len();
        let healthy = component_snapshots
            .iter()
            .filter(|s| s.status == ComponentStatus::Healthy)
            .count();
        let degraded = component_snapshots
            .iter()
            .filter(|s| s.status == ComponentStatus::Degraded)
            .count();
        let unhealthy = component_snapshots
            .iter()
            .filter(|s| s.status == ComponentStatus::Unhealthy)
            .count();

        let response_times: Vec<u64> = component_snapshots
            .iter()
            .filter_map(|s| s.response_time_ms)
            .collect();

        let avg_response_time = if !response_times.is_empty() {
            response_times.iter().sum::<u64>() / response_times.len() as u64
        } else {
            0
        };

        let min_response_time = response_times.iter().min().copied();
        let max_response_time = response_times.iter().max().copied();

        let uptime_percentage = (healthy as f64 / total as f64) * 100.0;

        let mut stats = HashMap::new();
        stats.insert("total_checks".to_string(), serde_json::json!(total));
        stats.insert("healthy_count".to_string(), serde_json::json!(healthy));
        stats.insert("degraded_count".to_string(), serde_json::json!(degraded));
        stats.insert("unhealthy_count".to_string(), serde_json::json!(unhealthy));
        stats.insert(
            "uptime_percentage".to_string(),
            serde_json::json!(format!("{:.2}", uptime_percentage)),
        );
        stats.insert(
            "avg_response_time_ms".to_string(),
            serde_json::json!(avg_response_time),
        );

        if let Some(min) = min_response_time {
            stats.insert("min_response_time_ms".to_string(), serde_json::json!(min));
        }
        if let Some(max) = max_response_time {
            stats.insert("max_response_time_ms".to_string(), serde_json::json!(max));
        }

        Some(stats)
    }

    pub async fn get_all_stats(&self) -> HashMap<String, HashMap<String, serde_json::Value>> {
        let snapshots = self.snapshots.read().await;
        let mut components: std::collections::HashSet<String> = std::collections::HashSet::new();

        for snapshot in snapshots.iter() {
            components.insert(snapshot.component.clone());
        }

        let mut all_stats = HashMap::new();
        for component in components {
            if let Some(stats) = self.get_component_stats(&component).await {
                all_stats.insert(component, stats);
            }
        }

        all_stats
    }

    pub async fn clear(&self) {
        let mut snapshots = self.snapshots.write().await;
        snapshots.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_metrics_recording() {
        let metrics = HealthMetrics::new(100);
        let health = ComponentHealth::healthy(150);

        metrics.record("database".to_string(), &health).await;

        let stats = metrics.get_component_stats("database").await;
        assert!(stats.is_some());

        let stats = stats.unwrap();
        assert_eq!(stats.get("total_checks").unwrap(), &serde_json::json!(1));
        assert_eq!(stats.get("healthy_count").unwrap(), &serde_json::json!(1));
    }

    #[tokio::test]
    async fn test_metrics_limit() {
        let metrics = HealthMetrics::new(5);

        for i in 0..10 {
            let health = ComponentHealth::healthy(i * 10);
            metrics.record("test".to_string(), &health).await;
        }

        let snapshots = metrics.snapshots.read().await;
        assert_eq!(snapshots.len(), 5);
    }
}
