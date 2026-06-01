use crate::db;
use crate::helpers::{AgentPgPool, JsonResponse};
use crate::models::pipe::PipeExecution;
use crate::models::{Command, CommandPriority, User};
use actix_web::{get, post, web, Responder, Result};
use serde::Deserialize;
use sqlx::PgPool;
use std::sync::Arc;

fn build_replay_trigger_params(original: &PipeExecution) -> serde_json::Value {
    serde_json::json!({
        "pipe_instance_id": original.pipe_instance_id.to_string(),
        "input_data": original.source_data,
        "trigger_type": "replay"
    })
}

#[derive(Debug, Deserialize)]
pub struct PaginationQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    20
}

/// List executions for a pipe instance (paginated, newest first)
#[tracing::instrument(name = "List pipe executions", skip_all)]
#[get("/instances/{instance_id}/executions")]
pub async fn list_executions_handler(
    user: web::ReqData<Arc<User>>,
    path: web::Path<uuid::Uuid>,
    query: web::Query<PaginationQuery>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    let instance_id = path.into_inner();

    // Fetch instance and verify ownership
    let instance = db::pipe::get_instance(pg_pool.get_ref(), &instance_id)
        .await
        .map_err(|err| JsonResponse::internal_server_error(err))?;

    let instance = match instance {
        Some(i) => i,
        None => return Err(JsonResponse::not_found("Pipe instance not found")),
    };

    super::verify_pipe_owner(pg_pool.get_ref(), &instance, &user.id).await?;

    let limit = query.limit.clamp(1, 100);
    let offset = query.offset.max(0);

    let executions = db::pipe::list_executions(pg_pool.get_ref(), &instance_id, limit, offset)
        .await
        .map_err(|err| {
            tracing::error!("Failed to list pipe executions: {}", err);
            JsonResponse::internal_server_error(err)
        })?;

    Ok(JsonResponse::build()
        .set_list(executions)
        .ok("Pipe executions fetched successfully"))
}

/// Get a single pipe execution by ID
#[tracing::instrument(name = "Get pipe execution", skip_all)]
#[get("/executions/{execution_id}")]
pub async fn get_execution_handler(
    user: web::ReqData<Arc<User>>,
    path: web::Path<uuid::Uuid>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    let execution_id = path.into_inner();

    let execution = db::pipe::get_execution(pg_pool.get_ref(), &execution_id)
        .await
        .map_err(|err| {
            tracing::error!("Failed to fetch pipe execution: {}", err);
            JsonResponse::internal_server_error(err)
        })?;

    match execution {
        Some(exec) => {
            // Verify ownership: execution -> instance -> user
            let instance = db::pipe::get_instance(pg_pool.get_ref(), &exec.pipe_instance_id)
                .await
                .map_err(|err| JsonResponse::internal_server_error(err))?;

            match instance {
                Some(i) => {
                    super::verify_pipe_owner(pg_pool.get_ref(), &i, &user.id).await?;
                }
                None => return Err(JsonResponse::not_found("Pipe execution not found")),
            }

            Ok(JsonResponse::build()
                .set_item(Some(exec))
                .ok("Pipe execution fetched successfully"))
        }
        None => Err(JsonResponse::not_found("Pipe execution not found")),
    }
}

/// Replay a previous pipe execution
#[tracing::instrument(name = "Replay pipe execution", skip_all)]
#[post("/executions/{execution_id}/replay")]
pub async fn replay_execution_handler(
    user: web::ReqData<Arc<User>>,
    path: web::Path<uuid::Uuid>,
    pg_pool: web::Data<PgPool>,
    agent_pool: web::Data<AgentPgPool>,
) -> Result<impl Responder> {
    let execution_id = path.into_inner();

    // Fetch original execution
    let original = db::pipe::get_execution(pg_pool.get_ref(), &execution_id)
        .await
        .map_err(|err| {
            tracing::error!("Failed to fetch pipe execution for replay: {}", err);
            JsonResponse::internal_server_error(err)
        })?;

    let original = match original {
        Some(exec) => exec,
        None => return Err(JsonResponse::not_found("Pipe execution not found")),
    };

    // Verify ownership via instance -> user
    let instance = db::pipe::get_instance(pg_pool.get_ref(), &original.pipe_instance_id)
        .await
        .map_err(|err| JsonResponse::internal_server_error(err))?;

    let instance = match instance {
        Some(i) => i,
        None => return Err(JsonResponse::not_found("Pipe instance not found")),
    };

    super::verify_pipe_owner(pg_pool.get_ref(), &instance, &user.id).await?;

    // Create a new execution record for the replay
    let replay_execution = PipeExecution::new(
        original.pipe_instance_id,
        original.deployment_hash.clone(),
        "replay".to_string(),
        user.id.clone(),
    )
    .with_replay_of(execution_id);

    let replay_execution = db::pipe::insert_execution(pg_pool.get_ref(), &replay_execution)
        .await
        .map_err(|err| {
            tracing::error!("Failed to create replay execution: {}", err);
            JsonResponse::internal_server_error(err)
        })?;

    // Enqueue trigger_pipe command (only for remote pipes with a deployment)
    let command_id = if let Some(hash) = &instance.deployment_hash {
        let trigger_params = build_replay_trigger_params(&original);

        let command_id_str = format!("cmd_{}", uuid::Uuid::new_v4());
        let command = Command::new(
            command_id_str.clone(),
            hash.clone(),
            "trigger_pipe".to_string(),
            user.id.clone(),
        )
        .with_priority(CommandPriority::Normal)
        .with_parameters(trigger_params);

        match db::command::insert(agent_pool.as_ref(), &command).await {
            Ok(saved) => {
                let _ = db::command::add_to_queue(
                    agent_pool.as_ref(),
                    &saved.command_id,
                    &saved.deployment_hash,
                    &CommandPriority::Normal,
                )
                .await;
                Some(saved.command_id)
            }
            Err(e) => {
                tracing::warn!("Failed to enqueue replay trigger_pipe command: {}", e);
                None
            }
        }
    } else {
        // Local pipe — no agent dispatch
        tracing::info!(
            "Replay for local pipe instance {}, skipping agent dispatch",
            instance.id
        );
        None
    };

    Ok(JsonResponse::build()
        .set_item(Some(serde_json::json!({
            "execution_id": replay_execution.id,
            "replay_of": execution_id,
            "command_id": command_id,
            "status": replay_execution.status,
        })))
        .ok("Replay initiated"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_trigger_params_mark_replay_trigger_type() {
        let execution = PipeExecution::new(
            uuid::Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
            Some("dep-123".to_string()),
            "manual".to_string(),
            "user-1".to_string(),
        )
        .complete_success(
            serde_json::json!({ "invoice_id": "inv-replay" }),
            serde_json::json!({ "customer_id": "cust-1" }),
            serde_json::json!({ "queued": true }),
        );

        let params = build_replay_trigger_params(&execution);
        assert_eq!(params["trigger_type"], "replay");
        assert_eq!(params["input_data"]["invoice_id"], "inv-replay");
    }
}
