use crate::db;
use crate::helpers::JsonResponse;
use crate::models;
use actix_web::{get, web, Responder, Result};
use sqlx::PgPool;
use std::sync::Arc;
// use tracing::Instrument;

// workflow
// add, update, list, get(user_id), ACL,
// ACL - access to func for a user
// ACL - access to objects for a user

#[tracing::instrument(name = "Get server.", skip_all)]
#[get("/{id}")]
pub async fn item(
    path: web::Path<(i32,)>,
    user: web::ReqData<Arc<models::User>>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    let id = path.0;
    db::server::fetch(pg_pool.get_ref(), id)
        .await
        .map_err(|_err| JsonResponse::<models::Server>::build().internal_server_error(""))
        .and_then(|server| match server {
            Some(project) if project.user_id != user.id => {
                Err(JsonResponse::not_found("not found"))
            }
            Some(server) => Ok(JsonResponse::build().set_item(Some(server)).ok("OK")),
            None => Err(JsonResponse::not_found("not found")),
        })
}

#[tracing::instrument(name = "Get all servers.", skip_all)]
#[get("")]
pub async fn list(
    _path: web::Path<()>,
    user: web::ReqData<Arc<models::User>>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    db::server::fetch_by_user_with_provider(pg_pool.get_ref(), user.id.as_ref())
        .await
        .map(|servers| JsonResponse::build().set_list(servers).ok("OK"))
        .map_err(|_err| {
            JsonResponse::<models::ServerWithProvider>::build().internal_server_error("")
        })
}

#[tracing::instrument(name = "Get servers by project.", skip_all)]
#[get("/project/{project_id}")]
pub async fn list_by_project(
    path: web::Path<(i32,)>,
    user: web::ReqData<Arc<models::User>>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    let project_id = path.0;

    // Verify user owns the project
    let _project = db::project::fetch(pg_pool.get_ref(), project_id)
        .await
        .map_err(|_err| JsonResponse::<models::Server>::build().internal_server_error(""))
        .and_then(|p| match p {
            Some(proj) if proj.user_id != user.id => {
                Err(JsonResponse::<models::Server>::build().not_found("Project not found"))
            }
            Some(proj) => Ok(proj),
            None => Err(JsonResponse::<models::Server>::build().not_found("Project not found")),
        })?;

    db::server::fetch_by_project(pg_pool.get_ref(), project_id)
        .await
        .map(|servers| JsonResponse::build().set_list(servers).ok("OK"))
        .map_err(|_err| JsonResponse::<models::Server>::build().internal_server_error(""))
}
