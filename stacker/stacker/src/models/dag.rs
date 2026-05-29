use serde::{Deserialize, Serialize};
use sqlx::types::chrono::{DateTime, Utc};
use sqlx::types::uuid::Uuid;
use sqlx::types::JsonValue;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// DagStep — individual step within a pipe template's DAG
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct DagStep {
    pub id: Uuid,
    pub pipe_template_id: Uuid,
    pub name: String,
    pub step_type: String,
    pub step_order: i32,
    pub config: JsonValue,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Valid step types for DAG nodes
pub const VALID_STEP_TYPES: &[&str] = &[
    "source",
    "transform",
    "condition",
    "target",
    "parallel_split",
    "parallel_join",
    "ws_source",
    "ws_target",
    "http_stream_source",
    "grpc_source",
    "grpc_target",
    "cdc_source",
    "amqp_source",
    "kafka_source",
];

impl DagStep {
    pub fn new(pipe_template_id: Uuid, name: String, step_type: String, config: JsonValue) -> Self {
        Self {
            id: Uuid::new_v4(),
            pipe_template_id,
            name,
            step_type,
            step_order: 0,
            config,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    pub fn with_order(mut self, order: i32) -> Self {
        self.step_order = order;
        self
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// DagEdge — directed connection between two steps
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct DagEdge {
    pub id: Uuid,
    pub pipe_template_id: Uuid,
    pub from_step_id: Uuid,
    pub to_step_id: Uuid,
    pub condition: Option<JsonValue>,
    pub created_at: DateTime<Utc>,
}

impl DagEdge {
    pub fn new(pipe_template_id: Uuid, from_step_id: Uuid, to_step_id: Uuid) -> Self {
        Self {
            id: Uuid::new_v4(),
            pipe_template_id,
            from_step_id,
            to_step_id,
            condition: None,
            created_at: Utc::now(),
        }
    }

    pub fn with_condition(mut self, condition: JsonValue) -> Self {
        self.condition = Some(condition);
        self
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// DagStepExecution — per-step execution tracking
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct DagStepExecution {
    pub id: Uuid,
    pub pipe_execution_id: Uuid,
    pub step_id: Uuid,
    pub status: String,
    pub input_data: Option<JsonValue>,
    pub output_data: Option<JsonValue>,
    pub error: Option<String>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl DagStepExecution {
    pub fn new(pipe_execution_id: Uuid, step_id: Uuid) -> Self {
        Self {
            id: Uuid::new_v4(),
            pipe_execution_id,
            step_id,
            status: "pending".to_string(),
            input_data: None,
            output_data: None,
            error: None,
            started_at: None,
            completed_at: None,
            created_at: Utc::now(),
        }
    }

    pub fn start(mut self) -> Self {
        self.status = "running".to_string();
        self.started_at = Some(Utc::now());
        self
    }

    pub fn complete_success(mut self, output: JsonValue) -> Self {
        self.status = "completed".to_string();
        self.output_data = Some(output);
        self.completed_at = Some(Utc::now());
        self
    }

    pub fn complete_failure(mut self, error: String) -> Self {
        self.status = "failed".to_string();
        self.error = Some(error);
        self.completed_at = Some(Utc::now());
        self
    }
}
