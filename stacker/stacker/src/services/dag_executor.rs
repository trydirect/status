use crate::db;
use crate::models::dag::{DagEdge, DagStep, DagStepExecution};
use crate::services::step_executor;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sqlx::PgPool;
use std::collections::{HashMap, HashSet, VecDeque};
use uuid::Uuid;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// DAG Execution Result
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DagExecutionResult {
    pub execution_id: Uuid,
    pub status: String,
    pub total_steps: usize,
    pub completed_steps: usize,
    pub failed_steps: usize,
    pub skipped_steps: usize,
    pub execution_order: Vec<Uuid>,
    pub step_results: Vec<StepResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepResult {
    pub step_id: Uuid,
    pub step_name: String,
    pub step_type: String,
    pub status: String,
    pub output_data: Option<JsonValue>,
    pub error: Option<String>,
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Topological Sort (Kahn's algorithm)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Returns steps grouped by execution level (steps in same level can run in parallel).
pub fn topological_sort(steps: &[DagStep], edges: &[DagEdge]) -> Result<Vec<Vec<Uuid>>, String> {
    if steps.is_empty() {
        return Err("DAG must have at least one step".to_string());
    }

    let step_ids: HashSet<Uuid> = steps.iter().map(|s| s.id).collect();

    // Build adjacency list and in-degree map
    let mut in_degree: HashMap<Uuid, usize> = step_ids.iter().map(|&id| (id, 0)).collect();
    let mut adjacency: HashMap<Uuid, Vec<Uuid>> =
        step_ids.iter().map(|&id| (id, Vec::new())).collect();

    for edge in edges {
        if step_ids.contains(&edge.from_step_id) && step_ids.contains(&edge.to_step_id) {
            adjacency
                .entry(edge.from_step_id)
                .or_default()
                .push(edge.to_step_id);
            *in_degree.entry(edge.to_step_id).or_insert(0) += 1;
        }
    }

    // Kahn's: start with nodes having in-degree 0
    let mut queue: VecDeque<Uuid> = in_degree
        .iter()
        .filter(|(_, &deg)| deg == 0)
        .map(|(&id, _)| id)
        .collect();

    let mut levels: Vec<Vec<Uuid>> = Vec::new();
    let mut visited_count = 0;

    while !queue.is_empty() {
        let level: Vec<Uuid> = queue.drain(..).collect();
        visited_count += level.len();

        let mut next_queue = VecDeque::new();
        for &node in &level {
            if let Some(neighbors) = adjacency.get(&node) {
                for &neighbor in neighbors {
                    let deg = in_degree.get_mut(&neighbor).unwrap();
                    *deg -= 1;
                    if *deg == 0 {
                        next_queue.push_back(neighbor);
                    }
                }
            }
        }

        levels.push(level);
        queue = next_queue;
    }

    if visited_count != step_ids.len() {
        return Err("DAG contains a cycle".to_string());
    }

    Ok(levels)
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Step Executor (delegates to step_executor module)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Execute a single step — delegates to the shared step_executor module.
async fn execute_step(step: &DagStep, input: &JsonValue) -> Result<JsonValue, String> {
    step_executor::execute_step(&step.step_type, &step.config, input).await
}

/// Evaluate a condition — delegates to the shared step_executor module.
#[allow(dead_code)]
fn evaluate_condition(config: &JsonValue, input: &JsonValue) -> bool {
    step_executor::evaluate_condition(config, input)
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// DAG Validator
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

pub fn validate_dag(steps: &[DagStep], _edges: &[DagEdge]) -> Result<(), String> {
    if steps.is_empty() {
        return Err("DAG must have at least one step".to_string());
    }

    let source_types = [
        "source",
        "ws_source",
        "http_stream_source",
        "grpc_source",
        "cdc_source",
        "amqp_source",
        "kafka_source",
    ];
    let target_types = ["target", "ws_target", "grpc_target"];

    let has_source = steps
        .iter()
        .any(|s| source_types.contains(&s.step_type.as_str()));
    if !has_source {
        return Err("DAG must have at least one source step".to_string());
    }

    let has_target = steps
        .iter()
        .any(|s| target_types.contains(&s.step_type.as_str()));
    if !has_target {
        return Err("DAG must have at least one target step".to_string());
    }

    Ok(())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// DAG Execution Orchestrator
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

pub async fn execute_dag(
    pool: &PgPool,
    template_id: &Uuid,
    execution_id: Uuid,
    _input_data: &JsonValue,
) -> Result<DagExecutionResult, String> {
    let steps = db::dag::list_steps(pool, template_id).await?;
    let edges = db::dag::list_edges(pool, template_id).await?;

    // Validate
    validate_dag(&steps, &edges)?;

    // Topological sort
    let levels = topological_sort(&steps, &edges)?;

    // Build lookup maps
    let step_map: HashMap<Uuid, &DagStep> = steps.iter().map(|s| (s.id, s)).collect();

    // Build reverse adjacency: for each step, which steps feed into it?
    let mut incoming: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
    for edge in &edges {
        incoming
            .entry(edge.to_step_id)
            .or_default()
            .push(edge.from_step_id);
    }

    // Build edge condition map (from_step_id → condition) for condition-gated edges
    let mut edge_conditions: HashMap<(Uuid, Uuid), Option<JsonValue>> = HashMap::new();
    for edge in &edges {
        edge_conditions.insert((edge.from_step_id, edge.to_step_id), edge.condition.clone());
    }

    // Create step execution records
    let mut step_exec_ids: HashMap<Uuid, Uuid> = HashMap::new();
    for step in &steps {
        let exec = DagStepExecution::new(execution_id, step.id);
        let saved = db::dag::insert_step_execution(pool, &exec).await?;
        step_exec_ids.insert(step.id, saved.id);
    }

    // Track outputs and statuses
    let mut step_outputs: HashMap<Uuid, JsonValue> = HashMap::new();
    let mut step_statuses: HashMap<Uuid, String> = HashMap::new();
    let mut skipped_steps: HashSet<Uuid> = HashSet::new();
    let mut execution_order: Vec<Uuid> = Vec::new();
    let mut step_results: Vec<StepResult> = Vec::new();

    // Execute level by level
    for level in &levels {
        for &step_id in level {
            let step = step_map[&step_id];
            execution_order.push(step_id);

            // Check if any upstream step failed or was skipped
            let upstream_ids = incoming.get(&step_id).cloned().unwrap_or_default();
            let should_skip = upstream_ids.iter().any(|&up_id| {
                skipped_steps.contains(&up_id)
                    || step_statuses.get(&up_id).map_or(false, |s| s == "failed")
            });

            if should_skip {
                skipped_steps.insert(step_id);
                step_statuses.insert(step_id, "skipped".to_string());

                let exec_id = step_exec_ids[&step_id];
                db::dag::update_step_execution(pool, &exec_id, "skipped", None, None).await?;

                step_results.push(StepResult {
                    step_id,
                    step_name: step.name.clone(),
                    step_type: step.step_type.clone(),
                    status: "skipped".to_string(),
                    output_data: None,
                    error: Some("Upstream step failed or was skipped".to_string()),
                });
                continue;
            }

            // Mark as running
            let exec_id = step_exec_ids[&step_id];
            db::dag::update_step_execution(pool, &exec_id, "running", None, None).await?;

            // Aggregate input from upstream steps
            let input = if upstream_ids.is_empty() {
                serde_json::json!({})
            } else if upstream_ids.len() == 1 {
                step_outputs
                    .get(&upstream_ids[0])
                    .cloned()
                    .unwrap_or(serde_json::json!({}))
            } else {
                // Merge multiple upstream outputs
                let mut merged = serde_json::Map::new();
                for &up_id in &upstream_ids {
                    if let Some(out) = step_outputs.get(&up_id) {
                        if let Some(obj) = out.as_object() {
                            for (k, v) in obj {
                                merged.insert(k.clone(), v.clone());
                            }
                        }
                    }
                }
                JsonValue::Object(merged)
            };

            // Execute the step
            match execute_step(step, &input).await {
                Ok(output) => {
                    // For condition steps, check if condition passed
                    if step.step_type == "condition" {
                        let condition_met = output
                            .get("condition_met")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(true);

                        if !condition_met {
                            // Mark this step as completed but flag downstream for skipping
                            skipped_steps.insert(step_id);
                            step_statuses.insert(step_id, "completed".to_string());
                            step_outputs.insert(step_id, output.clone());

                            db::dag::update_step_execution(
                                pool,
                                &exec_id,
                                "completed",
                                Some(&output),
                                None,
                            )
                            .await?;

                            step_results.push(StepResult {
                                step_id,
                                step_name: step.name.clone(),
                                step_type: step.step_type.clone(),
                                status: "completed".to_string(),
                                output_data: Some(output),
                                error: None,
                            });
                            continue;
                        }
                    }

                    step_statuses.insert(step_id, "completed".to_string());
                    step_outputs.insert(step_id, output.clone());

                    db::dag::update_step_execution(
                        pool,
                        &exec_id,
                        "completed",
                        Some(&output),
                        None,
                    )
                    .await?;

                    step_results.push(StepResult {
                        step_id,
                        step_name: step.name.clone(),
                        step_type: step.step_type.clone(),
                        status: "completed".to_string(),
                        output_data: Some(output),
                        error: None,
                    });
                }
                Err(err) => {
                    step_statuses.insert(step_id, "failed".to_string());

                    db::dag::update_step_execution(pool, &exec_id, "failed", None, Some(&err))
                        .await?;

                    step_results.push(StepResult {
                        step_id,
                        step_name: step.name.clone(),
                        step_type: step.step_type.clone(),
                        status: "failed".to_string(),
                        output_data: None,
                        error: Some(err),
                    });
                }
            }
        }
    }

    // Compute final counts
    let completed_count = step_statuses.values().filter(|s| *s == "completed").count();
    let failed_count = step_statuses.values().filter(|s| *s == "failed").count();
    let skipped_count = step_statuses.values().filter(|s| *s == "skipped").count();

    let overall_status = if failed_count > 0 {
        "partial_failure".to_string()
    } else if skipped_count > 0 && completed_count > 0 {
        "completed".to_string()
    } else {
        "completed".to_string()
    };

    Ok(DagExecutionResult {
        execution_id,
        status: overall_status,
        total_steps: steps.len(),
        completed_steps: completed_count,
        failed_steps: failed_count,
        skipped_steps: skipped_count,
        execution_order,
        step_results,
    })
}
