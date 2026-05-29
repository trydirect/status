use crate::db;
use crate::helpers::JsonResponse;
use crate::models;
use actix_web::{get, web, Responder, Result};
use sqlx::PgPool;
use std::sync::Arc;

#[tracing::instrument(name = "Get agreement by id.", skip_all)]
#[get("/{id}")]
pub async fn get_handler(
    _user: web::ReqData<Arc<models::User>>,
    path: web::Path<(i32,)>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    let id = path.0;

    db::agreement::fetch(pg_pool.get_ref(), id)
        .await
        .map_err(|err| JsonResponse::internal_server_error(err.to_string()))
        .and_then(|item| match item {
            Some(item) => Ok(JsonResponse::build().set_item(Some(item)).ok("OK")),
            None => Err(JsonResponse::not_found("not found")),
        })
}

#[tracing::instrument(name = "Check if agreement signed/accepted.", skip_all)]
#[get("/accepted/{id}")]
pub async fn accept_handler(
    user: web::ReqData<Arc<models::User>>,
    path: web::Path<(i32,)>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    let id = path.0;

    db::agreement::fetch_by_user_and_agreement(pg_pool.get_ref(), user.id.as_ref(), id)
        .await
        .map_err(|err| JsonResponse::internal_server_error(err.to_string()))
        .and_then(|item| match item {
            Some(item) => Ok(JsonResponse::build().set_item(Some(item)).ok("OK")),
            None => Err(JsonResponse::not_found("not found")),
        })
}
