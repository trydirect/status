use serde::{Deserialize, Serialize};
use sqlx::types::chrono::{DateTime, Utc};
use sqlx::types::uuid::Uuid;
use sqlx::types::JsonValue;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Dead Letter Queue entry
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

pub const VALID_DLQ_STATUSES: &[&str] =
    &["pending", "retrying", "exhausted", "resolved", "discarded"];

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct DeadLetterEntry {
    pub id: Uuid,
    pub pipe_instance_id: Uuid,
    pub pipe_execution_id: Option<Uuid>,
    pub dag_step_id: Option<Uuid>,
    pub payload: Option<JsonValue>,
    pub error: String,
    pub retry_count: i32,
    pub max_retries: i32,
    pub next_retry_at: Option<DateTime<Utc>>,
    pub status: String,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl DeadLetterEntry {
    pub fn new(pipe_instance_id: Uuid, error: String, created_by: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            pipe_instance_id,
            pipe_execution_id: None,
            dag_step_id: None,
            payload: None,
            error,
            retry_count: 0,
            max_retries: 3,
            next_retry_at: None,
            status: "pending".to_string(),
            created_by,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    pub fn with_execution(mut self, execution_id: Uuid) -> Self {
        self.pipe_execution_id = Some(execution_id);
        self
    }

    pub fn with_dag_step(mut self, step_id: Uuid) -> Self {
        self.dag_step_id = Some(step_id);
        self
    }

    pub fn with_payload(mut self, payload: JsonValue) -> Self {
        self.payload = Some(payload);
        self
    }

    pub fn with_max_retries(mut self, max: i32) -> Self {
        self.max_retries = max;
        self
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Circuit Breaker
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

pub const VALID_CB_STATES: &[&str] = &["closed", "open", "half_open"];

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct CircuitBreaker {
    pub id: Uuid,
    pub pipe_instance_id: Uuid,
    pub state: String,
    pub failure_count: i32,
    pub success_count: i32,
    pub failure_threshold: i32,
    pub recovery_timeout_seconds: i32,
    pub half_open_max_requests: i32,
    pub last_failure_at: Option<DateTime<Utc>>,
    pub opened_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl CircuitBreaker {
    pub fn new(pipe_instance_id: Uuid) -> Self {
        Self {
            id: Uuid::new_v4(),
            pipe_instance_id,
            state: "closed".to_string(),
            failure_count: 0,
            success_count: 0,
            failure_threshold: 5,
            recovery_timeout_seconds: 60,
            half_open_max_requests: 3,
            last_failure_at: None,
            opened_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    pub fn with_config(mut self, threshold: i32, timeout: i32, half_open_max: i32) -> Self {
        self.failure_threshold = threshold;
        self.recovery_timeout_seconds = timeout;
        self.half_open_max_requests = half_open_max;
        self
    }
}
