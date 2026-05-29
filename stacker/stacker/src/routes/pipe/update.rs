use crate::db;
use crate::helpers::JsonResponse;
use crate::models::User;
use actix_web::{put, web, Responder, Result};
use serde::Deserialize;
use sqlx::PgPool;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct UpdatePipeStatusRequest {
    pub status: String,
}

const VALID_STATUSES: &[&str] = &["draft", "active", "paused", "error"];

#[tracing::instrument(name = "Update pipe instance status", skip_all)]
#[put("/instances/{instance_id}/status")]
pub async fn update_instance_status_handler(
    user: web::ReqData<Arc<User>>,
    path: web::Path<uuid::Uuid>,
    body: web::Json<UpdatePipeStatusRequest>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    let instance_id = path.into_inner();

    if !VALID_STATUSES.contains(&body.status.as_str()) {
        return Err(JsonResponse::<()>::build()
            .bad_request("Invalid status. Must be one of: draft, active, paused, error"));
    }

    let instance = db::pipe::get_instance(pg_pool.get_ref(), &instance_id)
        .await
        .map_err(|err| {
            tracing::error!("Failed to fetch pipe instance: {}", err);
            JsonResponse::<()>::build().internal_server_error(err)
        })?;

    match &instance {
        Some(i) => {
            super::verify_pipe_owner(pg_pool.get_ref(), i, &user.id).await?;
        }
        None => {
            return Err(JsonResponse::not_found("Pipe instance not found"));
        }
    }

    let updated = db::pipe::update_instance_status(pg_pool.get_ref(), &instance_id, &body.status)
        .await
        .map_err(|err| {
            tracing::error!("Failed to update pipe instance status: {}", err);
            JsonResponse::<()>::build().internal_server_error(err)
        })?;

    Ok(JsonResponse::build()
        .set_item(Some(updated))
        .ok("Pipe instance status updated successfully"))
}
