use crate::db;
use crate::helpers::JsonResponse;
use crate::models::User;
use actix_web::{get, web, Responder, Result};
use sqlx::PgPool;
use std::sync::Arc;

#[tracing::instrument(name = "Get pipe template by ID", skip_all)]
#[get("/templates/{template_id}")]
pub async fn get_template_handler(
    user: web::ReqData<Arc<User>>,
    path: web::Path<uuid::Uuid>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    let template_id = path.into_inner();

    let template = db::pipe::get_template(pg_pool.get_ref(), &template_id)
        .await
        .map_err(|err| {
            tracing::error!("Failed to fetch pipe template: {}", err);
            JsonResponse::internal_server_error(err)
        })?;

    match template {
        Some(t) => {
            // Only allow access to own templates or public ones
            if !t.is_public.unwrap_or(false) && t.created_by != user.id {
                return Err(JsonResponse::not_found("Pipe template not found"));
            }
            Ok(JsonResponse::build()
                .set_item(Some(t))
                .ok("Pipe template fetched successfully"))
        }
        None => Err(JsonResponse::not_found("Pipe template not found")),
    }
}

#[tracing::instrument(name = "Get pipe instance by ID", skip_all)]
#[get("/instances/detail/{instance_id}")]
pub async fn get_instance_handler(
    user: web::ReqData<Arc<User>>,
    path: web::Path<uuid::Uuid>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    let instance_id = path.into_inner();

    let instance = db::pipe::get_instance(pg_pool.get_ref(), &instance_id)
        .await
        .map_err(|err| {
            tracing::error!("Failed to fetch pipe instance: {}", err);
            JsonResponse::internal_server_error(err)
        })?;

    match instance {
        Some(i) => {
            super::verify_pipe_owner(pg_pool.get_ref(), &i, &user.id).await?;

            Ok(JsonResponse::build()
                .set_item(Some(i))
                .ok("Pipe instance fetched successfully"))
        }
        None => Err(JsonResponse::not_found("Pipe instance not found")),
    }
}
