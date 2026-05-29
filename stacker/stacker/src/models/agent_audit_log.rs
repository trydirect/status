use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct AgentAuditLog {
    pub id: i64,
    pub installation_hash: String,
    pub event_type: String,
    pub payload: serde_json::Value,
    pub status_panel_id: Option<i64>,
    pub received_at: chrono::DateTime<chrono::Utc>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// One event in an incoming batch from the Status Panel.
#[derive(Debug, Deserialize)]
pub struct AuditBatchItem {
    pub id: i64,
    pub event_type: String,
    pub payload: serde_json::Value,
    /// Unix timestamp (seconds) from Status Panel
    pub created_at: i64,
}

/// Batch request body sent by the Status Panel.
#[derive(Debug, Deserialize)]
pub struct AuditBatchRequest {
    pub installation_hash: String,
    pub events: Vec<AuditBatchItem>,
}
