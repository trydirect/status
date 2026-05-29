use crate::db;
use crate::helpers::JsonResponse;
use crate::models;
use actix_web::{get, web, Responder, Result};
use sqlx::PgPool;
use std::sync::Arc;

#[tracing::instrument(name = "Get logged user project.", skip_all)]
#[get("/{id}")]
pub async fn item(
    user: web::ReqData<Arc<models::User>>,
    path: web::Path<(i32,)>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    // Get project apps of logged user only
    let id = path.0;

    db::project::fetch(pg_pool.get_ref(), id)
        .await
        .map_err(|err| JsonResponse::internal_server_error(err.to_string()))
        .and_then(|project| match project {
            Some(project) if project.user_id != user.id => {
                Err(JsonResponse::not_found("not found"))
            }
            Some(project) => Ok(JsonResponse::build().set_item(Some(project)).ok("OK")),
            None => Err(JsonResponse::not_found("not found")),
        })
}

#[tracing::instrument(name = "Get shared project list.", skip_all)]
#[get("/shared")]
pub async fn shared_list(
    user: web::ReqData<Arc<models::User>>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    db::project::fetch_shared_by_user(pg_pool.get_ref(), &user.id)
        .await
        .map_err(|err| JsonResponse::internal_server_error(err))
        .map(|projects| JsonResponse::build().set_list(projects).ok("OK"))
}

#[tracing::instrument(name = "Get project list.", skip_all)]
#[get("")]
pub async fn list(
    user: web::ReqData<Arc<models::User>>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    db::project::fetch_by_user(pg_pool.get_ref(), &user.id)
        .await
        .map_err(|err| JsonResponse::internal_server_error(err))
        .map(|projects| JsonResponse::build().set_list(projects).ok("OK"))
}

//admin's endpoint
#[tracing::instrument(name = "Get user's project list.", skip_all)]
#[get("/user/{id}")]
pub async fn admin_list(
    _user: web::ReqData<Arc<models::User>>,
    path: web::Path<(String,)>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    // This is admin endpoint, used by a client app, client app is confidential
    // it should return projects by user id
    // in order to pass validation at external deployment service
    let user_id = path.into_inner().0;

    db::project::fetch_by_user(pg_pool.get_ref(), &user_id)
        .await
        .map_err(|err| JsonResponse::internal_server_error(err))
        .map(|projects| JsonResponse::build().set_list(projects).ok("OK"))
}
