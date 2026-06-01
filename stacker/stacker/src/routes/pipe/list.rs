use crate::db;
use crate::helpers::JsonResponse;
use crate::models::User;
use actix_web::{get, web, Responder, Result};
use serde::Deserialize;
use sqlx::PgPool;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct ListTemplatesQuery {
    pub source_app_type: Option<String>,
    pub target_app_type: Option<String>,
    #[serde(default)]
    pub public_only: bool,
}

#[tracing::instrument(name = "List pipe templates", skip_all)]
#[get("/templates")]
pub async fn list_templates_handler(
    user: web::ReqData<Arc<User>>,
    query: web::Query<ListTemplatesQuery>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    // Show user's own templates + public templates (never other users' private templates)
    let templates = db::pipe::list_templates_for_user(
        pg_pool.get_ref(),
        &user.id,
        query.source_app_type.as_deref(),
        query.target_app_type.as_deref(),
        query.public_only,
    )
    .await
    .map_err(|err| {
        tracing::error!("Failed to list pipe templates: {}", err);
        JsonResponse::internal_server_error(err)
    })?;

    Ok(JsonResponse::build()
        .set_list(templates)
        .ok("Pipe templates fetched successfully"))
}

#[tracing::instrument(name = "List pipe instances for deployment", skip_all)]
#[get("/instances/{deployment_hash}")]
pub async fn list_instances_handler(
    user: web::ReqData<Arc<User>>,
    path: web::Path<String>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    let deployment_hash = path.into_inner();

    // Verify deployment belongs to the requesting user
    let deployment = db::deployment::fetch_by_deployment_hash(pg_pool.get_ref(), &deployment_hash)
        .await
        .map_err(|err| JsonResponse::internal_server_error(err))?;

    match &deployment {
        Some(d) if d.user_id.as_deref() == Some(&user.id) => {}
        _ => {
            return Err(JsonResponse::not_found("Deployment not found"));
        }
    }

    let instances = db::pipe::list_instances(pg_pool.get_ref(), &deployment_hash)
        .await
        .map_err(|err| {
            tracing::error!("Failed to list pipe instances: {}", err);
            JsonResponse::internal_server_error(err)
        })?;

    Ok(JsonResponse::build()
        .set_list(instances)
        .ok("Pipe instances fetched successfully"))
}

#[tracing::instrument(name = "List local pipe instances", skip_all)]
#[get("/instances/local")]
pub async fn list_local_instances_handler(
    user: web::ReqData<Arc<User>>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    let instances = db::pipe::list_local_instances_by_user(pg_pool.get_ref(), &user.id)
        .await
        .map_err(|err| {
            tracing::error!("Failed to list local pipe instances: {}", err);
            JsonResponse::internal_server_error(err)
        })?;

    Ok(JsonResponse::build()
        .set_list(instances)
        .ok("Local pipe instances fetched successfully"))
}
