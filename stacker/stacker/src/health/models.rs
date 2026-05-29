use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ComponentStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHealth {
    pub status: ComponentStatus,
    pub message: Option<String>,
    pub response_time_ms: Option<u64>,
    pub last_checked: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<HashMap<String, serde_json::Value>>,
}

impl ComponentHealth {
    pub fn healthy(response_time_ms: u64) -> Self {
        Self {
            status: ComponentStatus::Healthy,
            message: None,
            response_time_ms: Some(response_time_ms),
            last_checked: Utc::now(),
            details: None,
        }
    }

    pub fn unhealthy(error: String) -> Self {
        Self {
            status: ComponentStatus::Unhealthy,
            message: Some(error),
            response_time_ms: None,
            last_checked: Utc::now(),
            details: None,
        }
    }

    pub fn degraded(message: String, response_time_ms: Option<u64>) -> Self {
        Self {
            status: ComponentStatus::Degraded,
            message: Some(message),
            response_time_ms,
            last_checked: Utc::now(),
            details: None,
        }
    }

    pub fn with_details(mut self, details: HashMap<String, serde_json::Value>) -> Self {
        self.details = Some(details);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckResponse {
    pub status: ComponentStatus,
    pub timestamp: DateTime<Utc>,
    pub version: String,
    pub uptime_seconds: u64,
    pub components: HashMap<String, ComponentHealth>,
}

impl HealthCheckResponse {
    pub fn new(version: String, uptime_seconds: u64) -> Self {
        Self {
            status: ComponentStatus::Healthy,
            timestamp: Utc::now(),
            version,
            uptime_seconds,
            components: HashMap::new(),
        }
    }

    pub fn add_component(&mut self, name: String, health: ComponentHealth) {
        if health.status == ComponentStatus::Unhealthy {
            self.status = ComponentStatus::Unhealthy;
        } else if health.status == ComponentStatus::Degraded
            && self.status != ComponentStatus::Unhealthy
        {
            self.status = ComponentStatus::Degraded;
        }
        self.components.insert(name, health);
    }

    pub fn is_healthy(&self) -> bool {
        self.status == ComponentStatus::Healthy
    }

    /// Returns true when the service can handle requests, even if some optional
    /// dependencies are unavailable (Degraded). Only Unhealthy (core DB down)
    /// returns false here.
    pub fn is_operational(&self) -> bool {
        self.status != ComponentStatus::Unhealthy
    }
}
