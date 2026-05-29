use std::sync::Arc;

use actix_web::{delete, get, post, put, web, Responder, Result};
use serde::Deserialize;
use sqlx::PgPool;

use crate::db;
use crate::helpers::JsonResponse;
use crate::models::resilience::DeadLetterEntry;
use crate::models::User;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Ownership helper
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async fn verify_instance_owner(
    pool: &PgPool,
    instance_id: &uuid::Uuid,
    user_id: &str,
) -> Result<(), actix_web::Error> {
    let instance = db::pipe::get_instance(pool, instance_id)
        .await
        .map_err(|err| JsonResponse::<String>::internal_server_error(err))?;

    let instance = match instance {
        Some(i) => i,
        None => return Err(JsonResponse::<String>::not_found("Pipe instance not found")),
    };

    super::verify_pipe_owner(pool, &instance, user_id).await
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// DLQ Routes
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Deserialize)]
pub struct CreateDlqRequest {
    pub pipe_execution_id: Option<uuid::Uuid>,
    pub dag_step_id: Option<uuid::Uuid>,
    pub payload: Option<serde_json::Value>,
    pub error: Option<String>,
    pub max_retries: Option<i32>,
}

/// List DLQ entries for a pipe instance
#[tracing::instrument(name = "List DLQ entries", skip_all)]
#[get("/instances/{instance_id}/dlq")]
pub async fn list_dlq_handler(
    user: web::ReqData<Arc<User>>,
    path: web::Path<uuid::Uuid>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    let instance_id = path.into_inner();
    verify_instance_owner(pg_pool.get_ref(), &instance_id, &user.id).await?;

    let entries = db::resilience::list_dlq_entries(pg_pool.get_ref(), &instance_id)
        .await
        .map_err(|err| {
            tracing::error!("Failed to list DLQ entries: {}", err);
            JsonResponse::<String>::internal_server_error(err)
        })?;

    Ok(JsonResponse::build()
        .set_list(entries)
        .ok("DLQ entries fetched successfully"))
}

/// Push a failed execution into the DLQ
#[tracing::instrument(name = "Create DLQ entry", skip_all)]
#[post("/instances/{instance_id}/dlq")]
pub async fn create_dlq_handler(
    user: web::ReqData<Arc<User>>,
    path: web::Path<uuid::Uuid>,
    body: web::Json<CreateDlqRequest>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    let instance_id = path.into_inner();
    verify_instance_owner(pg_pool.get_ref(), &instance_id, &user.id).await?;

    let error_msg = body.error.clone().unwrap_or_default();
    let mut entry = DeadLetterEntry::new(instance_id, error_msg, user.id.clone());

    if let Some(exec_id) = body.pipe_execution_id {
        entry = entry.with_execution(exec_id);
    }
    if let Some(step_id) = body.dag_step_id {
        entry = entry.with_dag_step(step_id);
    }
    if let Some(payload) = &body.payload {
        entry = entry.with_payload(payload.clone());
    }
    if let Some(max) = body.max_retries {
        entry = entry.with_max_retries(max);
    }

    let saved = db::resilience::insert_dlq_entry(pg_pool.get_ref(), &entry)
        .await
        .map_err(|err| {
            tracing::error!("Failed to create DLQ entry: {}", err);
            JsonResponse::<String>::internal_server_error(err)
        })?;

    Ok(JsonResponse::build()
        .set_item(Some(saved))
        .created("DLQ entry created successfully"))
}

/// Get a single DLQ entry
#[tracing::instrument(name = "Get DLQ entry", skip_all)]
#[get("/dlq/{entry_id}")]
pub async fn get_dlq_handler(
    user: web::ReqData<Arc<User>>,
    path: web::Path<uuid::Uuid>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    let entry_id = path.into_inner();

    let entry = db::resilience::get_dlq_entry(pg_pool.get_ref(), &entry_id)
        .await
        .map_err(|err| JsonResponse::<String>::internal_server_error(err))?;

    let entry = match entry {
        Some(e) => e,
        None => return Err(JsonResponse::<String>::not_found("DLQ entry not found")),
    };

    // Verify ownership
    verify_instance_owner(pg_pool.get_ref(), &entry.pipe_instance_id, &user.id).await?;

    Ok(JsonResponse::build()
        .set_item(Some(entry))
        .ok("DLQ entry fetched successfully"))
}

/// Retry a DLQ entry
#[tracing::instrument(name = "Retry DLQ entry", skip_all)]
#[post("/dlq/{entry_id}/retry")]
pub async fn retry_dlq_handler(
    user: web::ReqData<Arc<User>>,
    path: web::Path<uuid::Uuid>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    let entry_id = path.into_inner();

    let entry = db::resilience::get_dlq_entry(pg_pool.get_ref(), &entry_id)
        .await
        .map_err(|err| JsonResponse::<String>::internal_server_error(err))?;

    let entry = match entry {
        Some(e) => e,
        None => return Err(JsonResponse::<String>::not_found("DLQ entry not found")),
    };

    verify_instance_owner(pg_pool.get_ref(), &entry.pipe_instance_id, &user.id).await?;

    let updated = db::resilience::retry_dlq_entry(pg_pool.get_ref(), &entry_id)
        .await
        .map_err(|err| {
            tracing::error!("Failed to retry DLQ entry: {}", err);
            JsonResponse::<String>::internal_server_error(err)
        })?;

    Ok(JsonResponse::build()
        .set_item(Some(updated))
        .ok("DLQ entry retried successfully"))
}

/// Discard a DLQ entry
#[tracing::instrument(name = "Discard DLQ entry", skip_all)]
#[delete("/dlq/{entry_id}")]
pub async fn discard_dlq_handler(
    user: web::ReqData<Arc<User>>,
    path: web::Path<uuid::Uuid>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    let entry_id = path.into_inner();

    let entry = db::resilience::get_dlq_entry(pg_pool.get_ref(), &entry_id)
        .await
        .map_err(|err| JsonResponse::<String>::internal_server_error(err))?;

    let entry = match entry {
        Some(e) => e,
        None => return Err(JsonResponse::<String>::not_found("DLQ entry not found")),
    };

    verify_instance_owner(pg_pool.get_ref(), &entry.pipe_instance_id, &user.id).await?;

    db::resilience::discard_dlq_entry(pg_pool.get_ref(), &entry_id)
        .await
        .map_err(|err| {
            tracing::error!("Failed to discard DLQ entry: {}", err);
            JsonResponse::<String>::internal_server_error(err)
        })?;

    Ok(JsonResponse::<String>::build().ok("DLQ entry discarded successfully"))
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Circuit Breaker Routes
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Deserialize)]
pub struct UpdateCircuitBreakerRequest {
    pub failure_threshold: Option<i32>,
    pub recovery_timeout_seconds: Option<i32>,
    pub half_open_max_requests: Option<i32>,
}

/// Get circuit breaker status for a pipe instance
#[tracing::instrument(name = "Get circuit breaker status", skip_all)]
#[get("/instances/{instance_id}/circuit-breaker")]
pub async fn get_circuit_breaker_handler(
    user: web::ReqData<Arc<User>>,
    path: web::Path<uuid::Uuid>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    let instance_id = path.into_inner();
    verify_instance_owner(pg_pool.get_ref(), &instance_id, &user.id).await?;

    let cb = db::resilience::get_or_create_circuit_breaker(pg_pool.get_ref(), &instance_id)
        .await
        .map_err(|err| {
            tracing::error!("Failed to get circuit breaker: {}", err);
            JsonResponse::<String>::internal_server_error(err)
        })?;

    Ok(JsonResponse::build()
        .set_item(Some(cb))
        .ok("Circuit breaker status fetched"))
}

/// Update circuit breaker configuration
#[tracing::instrument(name = "Update circuit breaker config", skip_all)]
#[put("/instances/{instance_id}/circuit-breaker")]
pub async fn update_circuit_breaker_handler(
    user: web::ReqData<Arc<User>>,
    path: web::Path<uuid::Uuid>,
    body: web::Json<UpdateCircuitBreakerRequest>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    let instance_id = path.into_inner();
    verify_instance_owner(pg_pool.get_ref(), &instance_id, &user.id).await?;

    let threshold = body.failure_threshold.unwrap_or(5);
    let timeout = body.recovery_timeout_seconds.unwrap_or(60);
    let half_open = body.half_open_max_requests.unwrap_or(3);

    if threshold < 1 {
        return Err(JsonResponse::<()>::build().bad_request("failure_threshold must be >= 1"));
    }

    let cb = db::resilience::update_circuit_breaker_config(
        pg_pool.get_ref(),
        &instance_id,
        threshold,
        timeout,
        half_open,
    )
    .await
    .map_err(|err| {
        tracing::error!("Failed to update circuit breaker config: {}", err);
        JsonResponse::<String>::internal_server_error(err)
    })?;

    Ok(JsonResponse::build()
        .set_item(Some(cb))
        .ok("Circuit breaker config updated"))
}

/// Record a circuit breaker failure
#[tracing::instrument(name = "Record circuit breaker failure", skip_all)]
#[post("/instances/{instance_id}/circuit-breaker/failure")]
pub async fn record_failure_handler(
    user: web::ReqData<Arc<User>>,
    path: web::Path<uuid::Uuid>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    let instance_id = path.into_inner();
    verify_instance_owner(pg_pool.get_ref(), &instance_id, &user.id).await?;

    let cb = db::resilience::record_circuit_breaker_failure(pg_pool.get_ref(), &instance_id)
        .await
        .map_err(|err| {
            tracing::error!("Failed to record failure: {}", err);
            JsonResponse::<String>::internal_server_error(err)
        })?;

    Ok(JsonResponse::build()
        .set_item(Some(cb))
        .ok("Failure recorded"))
}

/// Record a circuit breaker success
#[tracing::instrument(name = "Record circuit breaker success", skip_all)]
#[post("/instances/{instance_id}/circuit-breaker/success")]
pub async fn record_success_handler(
    user: web::ReqData<Arc<User>>,
    path: web::Path<uuid::Uuid>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    let instance_id = path.into_inner();
    verify_instance_owner(pg_pool.get_ref(), &instance_id, &user.id).await?;

    let cb = db::resilience::record_circuit_breaker_success(pg_pool.get_ref(), &instance_id)
        .await
        .map_err(|err| {
            tracing::error!("Failed to record success: {}", err);
            JsonResponse::<String>::internal_server_error(err)
        })?;

    Ok(JsonResponse::build()
        .set_item(Some(cb))
        .ok("Success recorded"))
}

/// Reset circuit breaker to closed state
#[tracing::instrument(name = "Reset circuit breaker", skip_all)]
#[post("/instances/{instance_id}/circuit-breaker/reset")]
pub async fn reset_circuit_breaker_handler(
    user: web::ReqData<Arc<User>>,
    path: web::Path<uuid::Uuid>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    let instance_id = path.into_inner();
    verify_instance_owner(pg_pool.get_ref(), &instance_id, &user.id).await?;

    let cb = db::resilience::reset_circuit_breaker(pg_pool.get_ref(), &instance_id)
        .await
        .map_err(|err| {
            tracing::error!("Failed to reset circuit breaker: {}", err);
            JsonResponse::<String>::internal_server_error(err)
        })?;

    Ok(JsonResponse::build()
        .set_item(Some(cb))
        .ok("Circuit breaker reset to closed"))
}
