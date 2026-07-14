use crate::models::dag::{DagEdge, DagStep, DagStepExecution};
use sqlx::PgPool;
use tracing::Instrument;
use uuid::Uuid;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// DagStep queries
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[tracing::instrument(name = "Insert DAG step", skip(pool))]
pub async fn insert_step(pool: &PgPool, step: &DagStep) -> Result<DagStep, String> {
    let span = tracing::info_span!("Saving DAG step to database");
    sqlx::query_as::<_, DagStep>(
        r#"
        INSERT INTO pipe_dag_steps (id, pipe_template_id, name, step_type, step_order, config, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING id, pipe_template_id, name, step_type, step_order, config, created_at, updated_at
        "#,
    )
    .bind(step.id)
    .bind(step.pipe_template_id)
    .bind(&step.name)
    .bind(&step.step_type)
    .bind(step.step_order)
    .bind(&step.config)
    .bind(step.created_at)
    .bind(step.updated_at)
    .fetch_one(pool)
    .instrument(span)
    .await
    .map_err(|err| {
        tracing::error!("Failed to insert DAG step: {:?}", err);
        format!("Failed to insert DAG step: {}", err)
    })
}

#[tracing::instrument(name = "Fetch DAG step by ID", skip(pool))]
pub async fn get_step(pool: &PgPool, step_id: &Uuid) -> Result<Option<DagStep>, String> {
    let span = tracing::info_span!("Fetching DAG step by ID");
    sqlx::query_as::<_, DagStep>(
        r#"
        SELECT id, pipe_template_id, name, step_type, step_order, config, created_at, updated_at
        FROM pipe_dag_steps WHERE id = $1
        "#,
    )
    .bind(step_id)
    .fetch_optional(pool)
    .instrument(span)
    .await
    .map_err(|err| {
        tracing::error!("Failed to fetch DAG step: {:?}", err);
        format!("Failed to fetch DAG step: {}", err)
    })
}

#[tracing::instrument(name = "List DAG steps for template", skip(pool))]
pub async fn list_steps(pool: &PgPool, template_id: &Uuid) -> Result<Vec<DagStep>, String> {
    let span = tracing::info_span!("Listing DAG steps");
    sqlx::query_as::<_, DagStep>(
        r#"
        SELECT id, pipe_template_id, name, step_type, step_order, config, created_at, updated_at
        FROM pipe_dag_steps WHERE pipe_template_id = $1
        ORDER BY step_order ASC, created_at ASC
        "#,
    )
    .bind(template_id)
    .fetch_all(pool)
    .instrument(span)
    .await
    .map_err(|err| {
        tracing::error!("Failed to list DAG steps: {:?}", err);
        format!("Failed to list DAG steps: {}", err)
    })
}

#[tracing::instrument(name = "Update DAG step", skip(pool))]
pub async fn update_step(
    pool: &PgPool,
    step_id: &Uuid,
    name: Option<&str>,
    config: Option<&serde_json::Value>,
    step_order: Option<i32>,
) -> Result<DagStep, String> {
    let span = tracing::info_span!("Updating DAG step");
    sqlx::query_as::<_, DagStep>(
        r#"
        UPDATE pipe_dag_steps SET
            name = COALESCE($2, name),
            config = COALESCE($3, config),
            step_order = COALESCE($4, step_order),
            updated_at = NOW()
        WHERE id = $1
        RETURNING id, pipe_template_id, name, step_type, step_order, config, created_at, updated_at
        "#,
    )
    .bind(step_id)
    .bind(name)
    .bind(config)
    .bind(step_order)
    .fetch_one(pool)
    .instrument(span)
    .await
    .map_err(|err| {
        tracing::error!("Failed to update DAG step: {:?}", err);
        format!("Failed to update DAG step: {}", err)
    })
}

#[tracing::instrument(name = "Delete DAG step", skip(pool))]
pub async fn delete_step(pool: &PgPool, step_id: &Uuid) -> Result<u64, String> {
    let span = tracing::info_span!("Deleting DAG step");
    let result = sqlx::query("DELETE FROM pipe_dag_steps WHERE id = $1")
        .bind(step_id)
        .execute(pool)
        .instrument(span)
        .await
        .map_err(|err| {
            tracing::error!("Failed to delete DAG step: {:?}", err);
            format!("Failed to delete DAG step: {}", err)
        })?;
    Ok(result.rows_affected())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// DagEdge queries
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[tracing::instrument(name = "Insert DAG edge", skip(pool))]
pub async fn insert_edge(pool: &PgPool, edge: &DagEdge) -> Result<DagEdge, String> {
    let span = tracing::info_span!("Saving DAG edge to database");
    sqlx::query_as::<_, DagEdge>(
        r#"
        INSERT INTO pipe_dag_edges (id, pipe_template_id, from_step_id, to_step_id, condition, created_at)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING id, pipe_template_id, from_step_id, to_step_id, condition, created_at
        "#,
    )
    .bind(edge.id)
    .bind(edge.pipe_template_id)
    .bind(edge.from_step_id)
    .bind(edge.to_step_id)
    .bind(&edge.condition)
    .bind(edge.created_at)
    .fetch_one(pool)
    .instrument(span)
    .await
    .map_err(|err| {
        tracing::error!("Failed to insert DAG edge: {:?}", err);
        format!("Failed to insert DAG edge: {}", err)
    })
}

#[tracing::instrument(name = "List DAG edges for template", skip(pool))]
pub async fn list_edges(pool: &PgPool, template_id: &Uuid) -> Result<Vec<DagEdge>, String> {
    let span = tracing::info_span!("Listing DAG edges");
    sqlx::query_as::<_, DagEdge>(
        r#"
        SELECT id, pipe_template_id, from_step_id, to_step_id, condition, created_at
        FROM pipe_dag_edges WHERE pipe_template_id = $1
        ORDER BY created_at ASC
        "#,
    )
    .bind(template_id)
    .fetch_all(pool)
    .instrument(span)
    .await
    .map_err(|err| {
        tracing::error!("Failed to list DAG edges: {:?}", err);
        format!("Failed to list DAG edges: {}", err)
    })
}

#[tracing::instrument(name = "Delete DAG edge", skip(pool))]
pub async fn delete_edge(pool: &PgPool, edge_id: &Uuid) -> Result<u64, String> {
    let span = tracing::info_span!("Deleting DAG edge");
    let result = sqlx::query("DELETE FROM pipe_dag_edges WHERE id = $1")
        .bind(edge_id)
        .execute(pool)
        .instrument(span)
        .await
        .map_err(|err| {
            tracing::error!("Failed to delete DAG edge: {:?}", err);
            format!("Failed to delete DAG edge: {}", err)
        })?;
    Ok(result.rows_affected())
}

/// Check if adding an edge from→to would create a cycle in the DAG.
/// Uses iterative DFS from `to_step_id` following existing edges.
#[tracing::instrument(name = "Check DAG cycle", skip(pool))]
pub async fn would_create_cycle(
    pool: &PgPool,
    template_id: &Uuid,
    from_step_id: &Uuid,
    to_step_id: &Uuid,
) -> Result<bool, String> {
    // If from == to, trivial cycle
    if from_step_id == to_step_id {
        return Ok(true);
    }

    let edges = list_edges(pool, template_id).await?;

    // DFS from to_step_id: can we reach from_step_id via existing edges?
    let mut visited = std::collections::HashSet::new();
    let mut stack = vec![*to_step_id];

    while let Some(current) = stack.pop() {
        if current == *from_step_id {
            return Ok(true);
        }
        if visited.contains(&current) {
            continue;
        }
        visited.insert(current);

        for edge in &edges {
            if edge.from_step_id == current {
                stack.push(edge.to_step_id);
            }
        }
    }

    Ok(false)
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// DagStepExecution queries
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[tracing::instrument(name = "Insert DAG step execution", skip(pool))]
pub async fn insert_step_execution(
    pool: &PgPool,
    exec: &DagStepExecution,
) -> Result<DagStepExecution, String> {
    let span = tracing::info_span!("Saving DAG step execution");
    sqlx::query_as::<_, DagStepExecution>(
        r#"
        INSERT INTO pipe_dag_step_executions
            (id, pipe_execution_id, step_id, status, input_data, output_data, error, started_at, completed_at, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        RETURNING id, pipe_execution_id, step_id, status, input_data, output_data, error, started_at, completed_at, created_at
        "#,
    )
    .bind(exec.id)
    .bind(exec.pipe_execution_id)
    .bind(exec.step_id)
    .bind(&exec.status)
    .bind(&exec.input_data)
    .bind(&exec.output_data)
    .bind(&exec.error)
    .bind(exec.started_at)
    .bind(exec.completed_at)
    .bind(exec.created_at)
    .fetch_one(pool)
    .instrument(span)
    .await
    .map_err(|err| {
        tracing::error!("Failed to insert DAG step execution: {:?}", err);
        format!("Failed to insert DAG step execution: {}", err)
    })
}

#[tracing::instrument(name = "List step executions for pipe execution", skip(pool))]
pub async fn list_step_executions(
    pool: &PgPool,
    pipe_execution_id: &Uuid,
) -> Result<Vec<DagStepExecution>, String> {
    let span = tracing::info_span!("Listing DAG step executions");
    sqlx::query_as::<_, DagStepExecution>(
        r#"
        SELECT id, pipe_execution_id, step_id, status, input_data, output_data, error, started_at, completed_at, created_at
        FROM pipe_dag_step_executions WHERE pipe_execution_id = $1
        ORDER BY created_at ASC
        "#,
    )
    .bind(pipe_execution_id)
    .fetch_all(pool)
    .instrument(span)
    .await
    .map_err(|err| {
        tracing::error!("Failed to list step executions: {:?}", err);
        format!("Failed to list step executions: {}", err)
    })
}

#[tracing::instrument(name = "Update step execution status", skip(pool))]
pub async fn update_step_execution(
    pool: &PgPool,
    exec_id: &Uuid,
    status: &str,
    output_data: Option<&serde_json::Value>,
    error: Option<&str>,
) -> Result<DagStepExecution, String> {
    let span = tracing::info_span!("Updating DAG step execution status");
    let now = chrono::Utc::now();
    sqlx::query_as::<_, DagStepExecution>(
        r#"
        UPDATE pipe_dag_step_executions SET
            status = $2,
            output_data = COALESCE($3, output_data),
            error = COALESCE($4, error),
            started_at = CASE WHEN $2 = 'running' AND started_at IS NULL THEN $5 ELSE started_at END,
            completed_at = CASE WHEN $2 IN ('completed', 'failed', 'skipped') THEN $5 ELSE completed_at END
        WHERE id = $1
        RETURNING id, pipe_execution_id, step_id, status, input_data, output_data, error, started_at, completed_at, created_at
        "#,
    )
    .bind(exec_id)
    .bind(status)
    .bind(output_data)
    .bind(error)
    .bind(now)
    .fetch_one(pool)
    .instrument(span)
    .await
    .map_err(|err| {
        tracing::error!("Failed to update step execution: {:?}", err);
        format!("Failed to update step execution: {}", err)
    })
}
