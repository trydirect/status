use crate::configuration::Settings;
use crate::db;
use crate::helpers;
use crate::helpers::JsonResponse;
use crate::models;
use actix_web::{put, web, Responder, Result};
use sqlx::PgPool;
use std::sync::Arc;

#[tracing::instrument(name = "User enable client.", skip_all)]
#[put("/{id}/enable")]
pub async fn enable_handler(
    user: web::ReqData<Arc<models::User>>,
    _settings: web::Data<Settings>,
    pg_pool: web::Data<PgPool>,
    path: web::Path<(i32,)>,
) -> Result<impl Responder> {
    let client_id = path.0;
    let client = db::client::fetch(pg_pool.get_ref(), client_id)
        .await
        .map_err(|msg| JsonResponse::<models::Client>::build().internal_server_error(msg))?
        .ok_or_else(|| JsonResponse::<models::Client>::build().not_found("not found"))?;

    if client.user_id != user.id {
        return Err(JsonResponse::<models::Client>::build().not_found("not found"));
    }

    enable_client(pg_pool.get_ref(), client).await
}

#[tracing::instrument(name = "Admin enable client.", skip_all)]
#[put("/{id}/enable")]
pub async fn admin_enable_handler(
    _user: web::ReqData<Arc<models::User>>,
    _settings: web::Data<Settings>,
    pg_pool: web::Data<PgPool>,
    path: web::Path<(i32,)>,
) -> Result<impl Responder> {
    let client_id = path.0;
    let client = db::client::fetch(pg_pool.get_ref(), client_id)
        .await
        .map_err(|msg| JsonResponse::<models::Client>::build().internal_server_error(msg))?
        .ok_or_else(|| JsonResponse::<models::Client>::build().not_found("not found"))?;

    enable_client(pg_pool.get_ref(), client).await
}

async fn enable_client(pg_pool: &PgPool, mut client: models::Client) -> Result<impl Responder> {
    if client.secret.is_some() {
        return Err(JsonResponse::<models::Client>::build().bad_request("client is already active"));
    }

    client.secret = helpers::client::generate_secret(pg_pool, 255)
        .await
        .map(|secret| Some(secret))
        .map_err(|err| JsonResponse::<models::Client>::build().bad_request(err))?;

    db::client::update(pg_pool, client)
        .await
        .map(|client| JsonResponse::build().set_item(client).ok("success"))
        .map_err(|err| JsonResponse::<models::Client>::build().bad_request(err))
}
