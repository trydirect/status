use lazy_static::lazy_static;
use prometheus::{
    register_counter_vec, register_gauge, register_histogram_vec, CounterVec, Gauge, HistogramVec,
};

lazy_static! {
    // ── HTTP Request Metrics ────────────────────────────────────
    pub static ref HTTP_REQUESTS_TOTAL: CounterVec = register_counter_vec!(
        "http_requests_total",
        "Total number of HTTP requests",
        &["method", "path", "status"]
    )
    .expect("Failed to register http_requests_total");

    pub static ref HTTP_REQUEST_DURATION: HistogramVec = register_histogram_vec!(
        "http_request_duration_seconds",
        "HTTP request duration in seconds",
        &["method", "path"],
        vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
    )
    .expect("Failed to register http_request_duration_seconds");

    // ── Pipe Execution Metrics ──────────────────────────────────
    pub static ref PIPE_EXECUTIONS_TOTAL: CounterVec = register_counter_vec!(
        "pipe_executions_total",
        "Total number of pipe executions",
        &["status", "trigger_type"]
    )
    .expect("Failed to register pipe_executions_total");

    pub static ref PIPE_EXECUTION_DURATION: HistogramVec = register_histogram_vec!(
        "pipe_execution_duration_seconds",
        "Pipe execution duration in seconds",
        &["trigger_type"],
        vec![0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0]
    )
    .expect("Failed to register pipe_execution_duration_seconds");

    // ── DAG Execution Metrics ───────────────────────────────────
    pub static ref DAG_EXECUTIONS_TOTAL: CounterVec = register_counter_vec!(
        "dag_executions_total",
        "Total number of DAG executions",
        &["status"]
    )
    .expect("Failed to register dag_executions_total");

    pub static ref DAG_STEPS_TOTAL: CounterVec = register_counter_vec!(
        "dag_steps_total",
        "Total number of DAG steps executed",
        &["status", "step_type"]
    )
    .expect("Failed to register dag_steps_total");

    // ── System Gauges ───────────────────────────────────────────
    pub static ref ACTIVE_PIPE_INSTANCES: Gauge = register_gauge!(
        "active_pipe_instances",
        "Number of currently active pipe instances"
    )
    .expect("Failed to register active_pipe_instances");

    pub static ref ACTIVE_AGENTS: Gauge = register_gauge!(
        "active_agents",
        "Number of currently active agents"
    )
    .expect("Failed to register active_agents");
}

/// Initialize all metrics (forces lazy_static registration).
pub fn init() {
    lazy_static::initialize(&HTTP_REQUESTS_TOTAL);
    lazy_static::initialize(&HTTP_REQUEST_DURATION);
    lazy_static::initialize(&PIPE_EXECUTIONS_TOTAL);
    lazy_static::initialize(&PIPE_EXECUTION_DURATION);
    lazy_static::initialize(&DAG_EXECUTIONS_TOTAL);
    lazy_static::initialize(&DAG_STEPS_TOTAL);
    lazy_static::initialize(&ACTIVE_PIPE_INSTANCES);
    lazy_static::initialize(&ACTIVE_AGENTS);

    // Pre-initialize CounterVec label combinations so they appear in /metrics output
    // even before first use (Prometheus best practice: expose all known label sets).
    PIPE_EXECUTIONS_TOTAL.with_label_values(&["success", "manual"]);
    PIPE_EXECUTIONS_TOTAL.with_label_values(&["failure", "manual"]);
    DAG_EXECUTIONS_TOTAL.with_label_values(&["success"]);
    DAG_EXECUTIONS_TOTAL.with_label_values(&["failure"]);
    DAG_STEPS_TOTAL.with_label_values(&["completed", "source"]);
    DAG_STEPS_TOTAL.with_label_values(&["failed", "source"]);
    PIPE_EXECUTION_DURATION.with_label_values(&["manual"]);
}
