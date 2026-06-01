use crate::db;
use crate::helpers::JsonResponse;
use crate::models::dag::{DagEdge, DagStep, VALID_STEP_TYPES};
use crate::models::User;
use crate::services::dag_executor;
use actix_web::{delete, get, post, put, web, HttpResponse, Responder, Result};
use serde::Deserialize;
use serde_json::Value as JsonValue;
use sqlx::PgPool;
use std::sync::Arc;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Request types
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Deserialize)]
pub struct CreateStepRequest {
    pub name: String,
    pub step_type: String,
    #[serde(default)]
    pub step_order: Option<i32>,
    #[serde(default = "default_config")]
    pub config: JsonValue,
}

fn default_config() -> JsonValue {
    serde_json::json!({})
}

#[derive(Debug, Deserialize)]
pub struct UpdateStepRequest {
    pub name: Option<String>,
    pub config: Option<JsonValue>,
    pub step_order: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct CreateEdgeRequest {
    pub from_step_id: uuid::Uuid,
    pub to_step_id: uuid::Uuid,
    #[serde(default)]
    pub condition: Option<JsonValue>,
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Helper: verify template ownership
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async fn verify_template_owner(
    pool: &PgPool,
    template_id: &uuid::Uuid,
    user: &User,
) -> Result<(), actix_web::Error> {
    let template = db::pipe::get_template(pool, template_id)
        .await
        .map_err(|err| JsonResponse::<String>::internal_server_error(err))?;

    match template {
        Some(t) if t.created_by == user.id => Ok(()),
        Some(_) => Err(JsonResponse::<String>::not_found("Pipe template not found")),
        None => Err(JsonResponse::<String>::not_found("Pipe template not found")),
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Steps CRUD
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[tracing::instrument(name = "Add DAG step", skip_all)]
#[post("/{template_id}/dag/steps")]
pub async fn add_step_handler(
    user: web::ReqData<Arc<User>>,
    path: web::Path<uuid::Uuid>,
    req: web::Json<CreateStepRequest>,
    pg_pool: web::Data<PgPool>,
) -> Result<HttpResponse> {
    let template_id = path.into_inner();
    verify_template_owner(pg_pool.get_ref(), &template_id, &user).await?;

    if req.name.trim().is_empty() {
        return Err(JsonResponse::<()>::build().bad_request("name is required"));
    }
    if !VALID_STEP_TYPES.contains(&req.step_type.as_str()) {
        return Err(JsonResponse::<()>::build().bad_request(format!(
            "Invalid step_type. Must be one of: {}",
            VALID_STEP_TYPES.join(", ")
        )));
    }

    let step = DagStep::new(
        template_id,
        req.name.clone(),
        req.step_type.clone(),
        req.config.clone(),
    )
    .with_order(req.step_order.unwrap_or(0));

    let saved = db::dag::insert_step(pg_pool.get_ref(), &step)
        .await
        .map_err(|err| JsonResponse::<String>::internal_server_error(err))?;

    Ok(JsonResponse::build()
        .set_item(Some(saved))
        .created("DAG step created successfully"))
}

#[tracing::instrument(name = "List DAG steps", skip_all)]
#[get("/{template_id}/dag/steps")]
pub async fn list_steps_handler(
    user: web::ReqData<Arc<User>>,
    path: web::Path<uuid::Uuid>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    let template_id = path.into_inner();
    verify_template_owner(pg_pool.get_ref(), &template_id, &user).await?;

    let steps = db::dag::list_steps(pg_pool.get_ref(), &template_id)
        .await
        .map_err(|err| JsonResponse::<String>::internal_server_error(err))?;

    Ok(JsonResponse::build()
        .set_list(steps)
        .ok("DAG steps listed successfully"))
}

#[tracing::instrument(name = "Get DAG step", skip_all)]
#[get("/{template_id}/dag/steps/{step_id}")]
pub async fn get_step_handler(
    user: web::ReqData<Arc<User>>,
    path: web::Path<(uuid::Uuid, uuid::Uuid)>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    let (template_id, step_id) = path.into_inner();
    verify_template_owner(pg_pool.get_ref(), &template_id, &user).await?;

    let step = db::dag::get_step(pg_pool.get_ref(), &step_id)
        .await
        .map_err(|err| JsonResponse::<String>::internal_server_error(err))?;

    match step {
        Some(s) if s.pipe_template_id == template_id => Ok(JsonResponse::build()
            .set_item(Some(s))
            .ok("DAG step fetched successfully")),
        _ => Err(JsonResponse::<String>::not_found("DAG step not found")),
    }
}

#[tracing::instrument(name = "Update DAG step", skip_all)]
#[put("/{template_id}/dag/steps/{step_id}")]
pub async fn update_step_handler(
    user: web::ReqData<Arc<User>>,
    path: web::Path<(uuid::Uuid, uuid::Uuid)>,
    req: web::Json<UpdateStepRequest>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    let (template_id, step_id) = path.into_inner();
    verify_template_owner(pg_pool.get_ref(), &template_id, &user).await?;

    // Verify step belongs to this template
    let existing = db::dag::get_step(pg_pool.get_ref(), &step_id)
        .await
        .map_err(|err| JsonResponse::<String>::internal_server_error(err))?;

    match &existing {
        Some(s) if s.pipe_template_id == template_id => {}
        _ => return Err(JsonResponse::<String>::not_found("DAG step not found")),
    }

    let updated = db::dag::update_step(
        pg_pool.get_ref(),
        &step_id,
        req.name.as_deref(),
        req.config.as_ref(),
        req.step_order,
    )
    .await
    .map_err(|err| JsonResponse::<String>::internal_server_error(err))?;

    Ok(JsonResponse::build()
        .set_item(Some(updated))
        .ok("DAG step updated successfully"))
}

#[tracing::instrument(name = "Delete DAG step", skip_all)]
#[delete("/{template_id}/dag/steps/{step_id}")]
pub async fn delete_step_handler(
    user: web::ReqData<Arc<User>>,
    path: web::Path<(uuid::Uuid, uuid::Uuid)>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    let (template_id, step_id) = path.into_inner();
    verify_template_owner(pg_pool.get_ref(), &template_id, &user).await?;

    // Verify step belongs to this template
    let existing = db::dag::get_step(pg_pool.get_ref(), &step_id)
        .await
        .map_err(|err| JsonResponse::<String>::internal_server_error(err))?;

    match &existing {
        Some(s) if s.pipe_template_id == template_id => {}
        _ => return Err(JsonResponse::<String>::not_found("DAG step not found")),
    }

    db::dag::delete_step(pg_pool.get_ref(), &step_id)
        .await
        .map_err(|err| JsonResponse::<String>::internal_server_error(err))?;

    Ok(JsonResponse::<()>::build().ok("DAG step deleted successfully"))
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Edges CRUD
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[tracing::instrument(name = "Add DAG edge", skip_all)]
#[post("/{template_id}/dag/edges")]
pub async fn add_edge_handler(
    user: web::ReqData<Arc<User>>,
    path: web::Path<uuid::Uuid>,
    req: web::Json<CreateEdgeRequest>,
    pg_pool: web::Data<PgPool>,
) -> Result<HttpResponse> {
    let template_id = path.into_inner();
    verify_template_owner(pg_pool.get_ref(), &template_id, &user).await?;

    // Verify both steps belong to this template
    let from_step = db::dag::get_step(pg_pool.get_ref(), &req.from_step_id)
        .await
        .map_err(|err| JsonResponse::<String>::internal_server_error(err))?;
    let to_step = db::dag::get_step(pg_pool.get_ref(), &req.to_step_id)
        .await
        .map_err(|err| JsonResponse::<String>::internal_server_error(err))?;

    match (&from_step, &to_step) {
        (Some(f), Some(t))
            if f.pipe_template_id == template_id && t.pipe_template_id == template_id => {}
        _ => {
            return Err(
                JsonResponse::<()>::build().bad_request("Both steps must belong to this template")
            )
        }
    }

    // Check for cycles
    let would_cycle = db::dag::would_create_cycle(
        pg_pool.get_ref(),
        &template_id,
        &req.from_step_id,
        &req.to_step_id,
    )
    .await
    .map_err(|err| JsonResponse::<String>::internal_server_error(err))?;

    if would_cycle {
        return Err(
            JsonResponse::<()>::build().bad_request("Adding this edge would create a cycle")
        );
    }

    let mut edge = DagEdge::new(template_id, req.from_step_id, req.to_step_id);
    if let Some(cond) = &req.condition {
        edge = edge.with_condition(cond.clone());
    }

    let saved = db::dag::insert_edge(pg_pool.get_ref(), &edge)
        .await
        .map_err(|err| JsonResponse::<String>::internal_server_error(err))?;

    Ok(JsonResponse::build()
        .set_item(Some(saved))
        .created("DAG edge created successfully"))
}

#[tracing::instrument(name = "List DAG edges", skip_all)]
#[get("/{template_id}/dag/edges")]
pub async fn list_edges_handler(
    user: web::ReqData<Arc<User>>,
    path: web::Path<uuid::Uuid>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    let template_id = path.into_inner();
    verify_template_owner(pg_pool.get_ref(), &template_id, &user).await?;

    let edges = db::dag::list_edges(pg_pool.get_ref(), &template_id)
        .await
        .map_err(|err| JsonResponse::<String>::internal_server_error(err))?;

    Ok(JsonResponse::build()
        .set_list(edges)
        .ok("DAG edges listed successfully"))
}

#[tracing::instrument(name = "Delete DAG edge", skip_all)]
#[delete("/{template_id}/dag/edges/{edge_id}")]
pub async fn delete_edge_handler(
    user: web::ReqData<Arc<User>>,
    path: web::Path<(uuid::Uuid, uuid::Uuid)>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    let (template_id, edge_id) = path.into_inner();
    verify_template_owner(pg_pool.get_ref(), &template_id, &user).await?;

    db::dag::delete_edge(pg_pool.get_ref(), &edge_id)
        .await
        .map_err(|err| JsonResponse::<String>::internal_server_error(err))?;

    Ok(JsonResponse::<()>::build().ok("DAG edge deleted successfully"))
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Validate DAG
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(serde::Serialize)]
struct ValidateResponse {
    valid: bool,
    errors: Vec<String>,
    step_count: usize,
    edge_count: usize,
}

#[tracing::instrument(name = "Validate DAG", skip_all)]
#[post("/{template_id}/dag/validate")]
pub async fn validate_dag_handler(
    user: web::ReqData<Arc<User>>,
    path: web::Path<uuid::Uuid>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    let template_id = path.into_inner();
    verify_template_owner(pg_pool.get_ref(), &template_id, &user).await?;

    let steps = db::dag::list_steps(pg_pool.get_ref(), &template_id)
        .await
        .map_err(|err| JsonResponse::<String>::internal_server_error(err))?;
    let edges = db::dag::list_edges(pg_pool.get_ref(), &template_id)
        .await
        .map_err(|err| JsonResponse::<String>::internal_server_error(err))?;

    let mut errors = Vec::new();

    // Must have at least one step
    if steps.is_empty() {
        errors.push("DAG must have at least one step".to_string());
    }

    // Check for source step
    let has_source = steps.iter().any(|s| s.step_type == "source");
    if !has_source && !steps.is_empty() {
        errors.push("DAG must have at least one source step".to_string());
    }

    // Check for target step
    let has_target = steps.iter().any(|s| s.step_type == "target");
    if !has_target && !steps.is_empty() {
        errors.push("DAG must have at least one target step".to_string());
    }

    // Check connectivity: every non-source step should have at least one incoming edge
    let step_ids: std::collections::HashSet<uuid::Uuid> = steps.iter().map(|s| s.id).collect();
    let steps_with_incoming: std::collections::HashSet<uuid::Uuid> =
        edges.iter().map(|e| e.to_step_id).collect();
    let steps_with_outgoing: std::collections::HashSet<uuid::Uuid> =
        edges.iter().map(|e| e.from_step_id).collect();

    for step in &steps {
        if step.step_type != "source" && !steps_with_incoming.contains(&step.id) && steps.len() > 1
        {
            errors.push(format!("Step '{}' has no incoming edges", step.name));
        }
        if step.step_type != "target" && !steps_with_outgoing.contains(&step.id) && steps.len() > 1
        {
            errors.push(format!("Step '{}' has no outgoing edges", step.name));
        }
    }

    // Verify edge references are valid
    for edge in &edges {
        if !step_ids.contains(&edge.from_step_id) {
            errors.push(format!(
                "Edge references non-existent from_step {}",
                edge.from_step_id
            ));
        }
        if !step_ids.contains(&edge.to_step_id) {
            errors.push(format!(
                "Edge references non-existent to_step {}",
                edge.to_step_id
            ));
        }
    }

    let resp = ValidateResponse {
        valid: errors.is_empty(),
        errors,
        step_count: steps.len(),
        edge_count: edges.len(),
    };

    Ok(JsonResponse::build()
        .set_item(Some(resp))
        .ok("DAG validation complete"))
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Execute DAG
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Deserialize)]
pub struct ExecuteDagRequest {
    #[serde(default = "default_input")]
    pub input_data: JsonValue,
}

fn default_input() -> JsonValue {
    serde_json::json!({})
}

#[tracing::instrument(name = "Execute DAG", skip_all)]
#[post("/instances/{instance_id}/dag/execute")]
pub async fn execute_dag_handler(
    user: web::ReqData<Arc<User>>,
    path: web::Path<uuid::Uuid>,
    req: web::Json<ExecuteDagRequest>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    let instance_id = path.into_inner();

    // Verify instance ownership
    let instance = db::pipe::get_instance(pg_pool.get_ref(), &instance_id)
        .await
        .map_err(|err| JsonResponse::<String>::internal_server_error(err))?;

    let instance = match instance {
        Some(i) => i,
        None => return Err(JsonResponse::<String>::not_found("Pipe instance not found")),
    };

    super::verify_pipe_owner(pg_pool.get_ref(), &instance, &user.id).await?;

    let template_id = instance.template_id.ok_or_else(|| {
        JsonResponse::<String>::bad_request("Pipe instance has no template".to_string())
    })?;

    // Create a pipe_execution record for FK compliance
    let pipe_exec = crate::models::pipe::PipeExecution::new(
        instance_id,
        instance.deployment_hash.clone(),
        "dag".to_string(),
        user.id.clone(),
    );

    let pipe_exec = db::pipe::insert_execution(pg_pool.get_ref(), &pipe_exec)
        .await
        .map_err(|err| JsonResponse::<String>::internal_server_error(err))?;

    match dag_executor::execute_dag(
        pg_pool.get_ref(),
        &template_id,
        pipe_exec.id,
        &req.input_data,
    )
    .await
    {
        Ok(result) => Ok(JsonResponse::build()
            .set_item(Some(result))
            .ok("DAG executed successfully")),
        Err(err) => Err(JsonResponse::<()>::build().bad_request(err)),
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// List Step Executions
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[tracing::instrument(name = "List DAG step executions", skip_all)]
#[get("/{template_id}/dag/executions/{execution_id}/steps")]
pub async fn list_step_executions_handler(
    user: web::ReqData<Arc<User>>,
    path: web::Path<(uuid::Uuid, uuid::Uuid)>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    let (template_id, execution_id) = path.into_inner();
    verify_template_owner(pg_pool.get_ref(), &template_id, &user).await?;

    let step_executions = db::dag::list_step_executions(pg_pool.get_ref(), &execution_id)
        .await
        .map_err(|err| JsonResponse::<String>::internal_server_error(err))?;

    Ok(JsonResponse::build()
        .set_list(step_executions)
        .ok("Step executions listed successfully"))
}
