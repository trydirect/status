use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use uuid::Uuid;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// CDC Models — Change Data Capture event types
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// A CDC change operation type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum CdcOperation {
    Insert,
    Update,
    Delete,
}

impl std::fmt::Display for CdcOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Insert => write!(f, "INSERT"),
            Self::Update => write!(f, "UPDATE"),
            Self::Delete => write!(f, "DELETE"),
        }
    }
}

impl CdcOperation {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "INSERT" | "I" => Some(Self::Insert),
            "UPDATE" | "U" => Some(Self::Update),
            "DELETE" | "D" => Some(Self::Delete),
            _ => None,
        }
    }
}

/// A single CDC change event captured from PostgreSQL WAL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CdcChangeEvent {
    pub event_id: Uuid,
    pub source_id: Uuid,
    pub schema_name: String,
    pub table_name: String,
    pub operation: CdcOperation,
    /// Row data before the change (UPDATE old values, DELETE full row, INSERT = None).
    #[serde(default)]
    pub before: Option<JsonValue>,
    /// Row data after the change (INSERT full row, UPDATE new values, DELETE = None).
    #[serde(default)]
    pub after: Option<JsonValue>,
    /// PostgreSQL transaction ID for idempotency.
    pub xid: i64,
    /// WAL log sequence number for ordering.
    pub lsn: String,
    pub captured_at: DateTime<Utc>,
}

impl CdcChangeEvent {
    pub fn new(
        source_id: Uuid,
        schema_name: String,
        table_name: String,
        operation: CdcOperation,
        before: Option<JsonValue>,
        after: Option<JsonValue>,
        xid: i64,
        lsn: String,
    ) -> Self {
        Self {
            event_id: Uuid::new_v4(),
            source_id,
            schema_name,
            table_name,
            operation,
            before,
            after,
            xid,
            lsn,
            captured_at: Utc::now(),
        }
    }

    /// Get the "current" row data (after for INSERT/UPDATE, before for DELETE).
    pub fn row_data(&self) -> Option<&JsonValue> {
        match self.operation {
            CdcOperation::Insert | CdcOperation::Update => self.after.as_ref(),
            CdcOperation::Delete => self.before.as_ref(),
        }
    }

    /// Build a normalized payload suitable for pipe source_data.
    pub fn to_pipe_payload(&self) -> JsonValue {
        serde_json::json!({
            "event_id": self.event_id.to_string(),
            "source_id": self.source_id.to_string(),
            "schema": self.schema_name,
            "table": self.table_name,
            "operation": self.operation,
            "before": self.before,
            "after": self.after,
            "xid": self.xid,
            "lsn": self.lsn,
            "captured_at": self.captured_at.to_rfc3339(),
        })
    }
}

/// CDC source configuration stored in the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CdcSource {
    pub id: Uuid,
    pub deployment_hash: String,
    pub connection_url: String,
    pub replication_slot: String,
    pub publication_name: String,
    /// Tables to monitor: ["public.users", "public.orders"]
    pub monitored_tables: Vec<String>,
    /// Operations to capture: ["INSERT", "UPDATE", "DELETE"]
    pub capture_operations: Vec<String>,
    pub status: CdcSourceStatus,
    pub last_lsn: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// CDC source lifecycle status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CdcSourceStatus {
    Active,
    Paused,
    Error,
    Deleted,
}

impl std::fmt::Display for CdcSourceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Paused => write!(f, "paused"),
            Self::Error => write!(f, "error"),
            Self::Deleted => write!(f, "deleted"),
        }
    }
}

/// Configuration for a CDC-to-pipe trigger binding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CdcTriggerConfig {
    pub cdc_source_id: Uuid,
    pub pipe_template_id: Uuid,
    /// Filter by table name (optional — None means all monitored tables).
    #[serde(default)]
    pub table_filter: Option<String>,
    /// Filter by operation (optional — None means all captured operations).
    #[serde(default)]
    pub operation_filter: Option<Vec<CdcOperation>>,
    /// JSONPath condition on the change data (optional).
    #[serde(default)]
    pub condition: Option<JsonValue>,
}

/// AMQP routing constants for CDC events.
pub mod routing {
    pub const CDC_EXCHANGE: &str = "cdc_events";
    pub const CDC_EVENT_PREFIX: &str = "cdc.event";

    pub fn event_key(table: &str, operation: &str) -> String {
        format!(
            "{}.{}.{}",
            CDC_EVENT_PREFIX,
            table,
            operation.to_lowercase()
        )
    }

    pub fn cdc_queue(deployment_hash: &str) -> String {
        format!("cdc_listener_{}", deployment_hash)
    }

    pub fn wildcard_key(table: &str) -> String {
        format!("{}.{}.#", CDC_EVENT_PREFIX, table)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn cdc_operation_from_str() {
        assert_eq!(CdcOperation::from_str("INSERT"), Some(CdcOperation::Insert));
        assert_eq!(CdcOperation::from_str("update"), Some(CdcOperation::Update));
        assert_eq!(CdcOperation::from_str("D"), Some(CdcOperation::Delete));
        assert_eq!(CdcOperation::from_str("I"), Some(CdcOperation::Insert));
        assert_eq!(CdcOperation::from_str("bogus"), None);
    }

    #[test]
    fn cdc_operation_display() {
        assert_eq!(CdcOperation::Insert.to_string(), "INSERT");
        assert_eq!(CdcOperation::Update.to_string(), "UPDATE");
        assert_eq!(CdcOperation::Delete.to_string(), "DELETE");
    }

    #[test]
    fn cdc_operation_serde_roundtrip() {
        let ops = vec![
            CdcOperation::Insert,
            CdcOperation::Update,
            CdcOperation::Delete,
        ];
        let json_str = serde_json::to_string(&ops).unwrap();
        assert_eq!(json_str, r#"["INSERT","UPDATE","DELETE"]"#);
        let deserialized: Vec<CdcOperation> = serde_json::from_str(&json_str).unwrap();
        assert_eq!(deserialized, ops);
    }

    #[test]
    fn change_event_serde_roundtrip() {
        let event = CdcChangeEvent::new(
            Uuid::new_v4(),
            "public".to_string(),
            "users".to_string(),
            CdcOperation::Insert,
            None,
            Some(json!({"id": 1, "name": "Alice", "email": "alice@test.com"})),
            42,
            "0/16B3748".to_string(),
        );

        let serialized = serde_json::to_string(&event).unwrap();
        let deserialized: CdcChangeEvent = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.event_id, event.event_id);
        assert_eq!(deserialized.table_name, "users");
        assert_eq!(deserialized.operation, CdcOperation::Insert);
        assert_eq!(deserialized.xid, 42);
        assert!(deserialized.before.is_none());
        assert!(deserialized.after.is_some());
    }

    #[test]
    fn change_event_row_data_insert() {
        let after = json!({"id": 1});
        let event = CdcChangeEvent::new(
            Uuid::new_v4(),
            "public".to_string(),
            "users".to_string(),
            CdcOperation::Insert,
            None,
            Some(after.clone()),
            1,
            "0/1".to_string(),
        );
        assert_eq!(event.row_data(), Some(&after));
    }

    #[test]
    fn change_event_row_data_update() {
        let before = json!({"name": "old"});
        let after = json!({"name": "new"});
        let event = CdcChangeEvent::new(
            Uuid::new_v4(),
            "public".to_string(),
            "users".to_string(),
            CdcOperation::Update,
            Some(before),
            Some(after.clone()),
            2,
            "0/2".to_string(),
        );
        assert_eq!(event.row_data(), Some(&after));
    }

    #[test]
    fn change_event_row_data_delete() {
        let before = json!({"id": 1, "name": "Alice"});
        let event = CdcChangeEvent::new(
            Uuid::new_v4(),
            "public".to_string(),
            "users".to_string(),
            CdcOperation::Delete,
            Some(before.clone()),
            None,
            3,
            "0/3".to_string(),
        );
        assert_eq!(event.row_data(), Some(&before));
    }

    #[test]
    fn change_event_to_pipe_payload() {
        let event = CdcChangeEvent::new(
            Uuid::new_v4(),
            "public".to_string(),
            "orders".to_string(),
            CdcOperation::Insert,
            None,
            Some(json!({"id": 99, "total": 150.0})),
            10,
            "0/ABC".to_string(),
        );
        let payload = event.to_pipe_payload();
        assert_eq!(payload["table"], "orders");
        assert_eq!(payload["schema"], "public");
        assert_eq!(payload["operation"], "INSERT");
        assert_eq!(payload["xid"], 10);
        assert!(payload["after"].is_object());
        assert!(payload["before"].is_null());
    }

    #[test]
    fn cdc_source_status_display() {
        assert_eq!(CdcSourceStatus::Active.to_string(), "active");
        assert_eq!(CdcSourceStatus::Paused.to_string(), "paused");
        assert_eq!(CdcSourceStatus::Error.to_string(), "error");
        assert_eq!(CdcSourceStatus::Deleted.to_string(), "deleted");
    }

    #[test]
    fn cdc_routing_keys() {
        assert_eq!(
            routing::event_key("users", "INSERT"),
            "cdc.event.users.insert"
        );
        assert_eq!(
            routing::event_key("orders", "DELETE"),
            "cdc.event.orders.delete"
        );
        assert_eq!(routing::cdc_queue("deploy-xyz"), "cdc_listener_deploy-xyz");
        assert_eq!(routing::wildcard_key("users"), "cdc.event.users.#");
    }

    #[test]
    fn cdc_trigger_config_serde() {
        let config = CdcTriggerConfig {
            cdc_source_id: Uuid::new_v4(),
            pipe_template_id: Uuid::new_v4(),
            table_filter: Some("users".to_string()),
            operation_filter: Some(vec![CdcOperation::Insert, CdcOperation::Update]),
            condition: Some(json!({"field": "amount", "operator": "gt", "value": 100})),
        };

        let serialized = serde_json::to_string(&config).unwrap();
        let deserialized: CdcTriggerConfig = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.table_filter, Some("users".to_string()));
        assert_eq!(
            deserialized.operation_filter,
            Some(vec![CdcOperation::Insert, CdcOperation::Update])
        );
    }

    #[test]
    fn cdc_trigger_config_minimal() {
        let json_str = r#"{
            "cdc_source_id": "550e8400-e29b-41d4-a716-446655440000",
            "pipe_template_id": "550e8400-e29b-41d4-a716-446655440001"
        }"#;
        let config: CdcTriggerConfig = serde_json::from_str(json_str).unwrap();
        assert!(config.table_filter.is_none());
        assert!(config.operation_filter.is_none());
        assert!(config.condition.is_none());
    }
}
