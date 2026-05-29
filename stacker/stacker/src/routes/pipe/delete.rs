use crate::db;
use crate::helpers::JsonResponse;
use crate::models::User;
use actix_web::{delete, web, Responder, Result};
use serde::Serialize;
use sqlx::PgPool;
use std::sync::Arc;

#[derive(Debug, Serialize)]
struct DeleteResponse {
    deleted: bool,
}

#[tracing::instrument(name = "Delete pipe template", skip_all)]
#[delete("/templates/{template_id}")]
pub async fn delete_template_handler(
    user: web::ReqData<Arc<User>>,
    path: web::Path<uuid::Uuid>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    let template_id = path.into_inner();

    // Verify the template belongs to the requesting user
    let template = db::pipe::get_template(pg_pool.get_ref(), &template_id)
        .await
        .map_err(|err| {
            tracing::error!("Failed to fetch pipe template: {}", err);
            JsonResponse::<()>::build().internal_server_error(err)
        })?;

    match &template {
        Some(t) if t.created_by == user.id => {}
        Some(_) => {
            return Err(JsonResponse::not_found("Pipe template not found"));
        }
        None => {
            return Err(JsonResponse::not_found("Pipe template not found"));
        }
    }

    let deleted = db::pipe::delete_template(pg_pool.get_ref(), &template_id)
        .await
        .map_err(|err| {
            tracing::error!("Failed to delete pipe template: {}", err);
            JsonResponse::<()>::build().internal_server_error(err)
        })?;

    if deleted {
        Ok(JsonResponse::build()
            .set_item(Some(DeleteResponse { deleted: true }))
            .ok("Pipe template deleted successfully"))
    } else {
        Err(JsonResponse::not_found("Pipe template not found"))
    }
}

#[tracing::instrument(name = "Delete pipe instance", skip_all)]
#[delete("/instances/{instance_id}")]
pub async fn delete_instance_handler(
    user: web::ReqData<Arc<User>>,
    path: web::Path<uuid::Uuid>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    let instance_id = path.into_inner();

    // Verify the instance belongs to the requesting user via deployment ownership
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

    let deleted = db::pipe::delete_instance(pg_pool.get_ref(), &instance_id)
        .await
        .map_err(|err| {
            tracing::error!("Failed to delete pipe instance: {}", err);
            JsonResponse::<()>::build().internal_server_error(err)
        })?;

    if deleted {
        Ok(JsonResponse::build()
            .set_item(Some(DeleteResponse { deleted: true }))
            .ok("Pipe instance deleted successfully"))
    } else {
        Err(JsonResponse::not_found("Pipe instance not found"))
    }
}
