use crate::configuration::Settings;
use crate::db;
use crate::helpers::JsonResponse;
use crate::models;
use actix_web::{put, web, Responder, Result};
use sqlx::PgPool;
use std::sync::Arc;

#[tracing::instrument(name = "User disable client.", skip_all)]
#[put("/{id}/disable")]
pub async fn disable_handler(
    user: web::ReqData<Arc<models::User>>,
    _settings: web::Data<Settings>,
    pg_pool: web::Data<PgPool>,
    path: web::Path<(i32,)>,
) -> Result<impl Responder> {
    let client_id = path.0;
    let client = db::client::fetch(pg_pool.get_ref(), client_id)
        .await
        .map_err(|msg| JsonResponse::<models::Client>::build().internal_server_error(msg))
        .and_then(|client| match client {
            Some(client) if client.user_id != user.id => {
                Err(JsonResponse::<models::Client>::build().not_found("not found"))
            }
            Some(client) => Ok(client),
            None => Err(JsonResponse::<models::Client>::build().not_found("not found")),
        })?;

    disable_client(pg_pool.get_ref(), client).await
}

#[tracing::instrument(name = "Admin disable client.", skip_all)]
#[put("/{id}/disable")]
pub async fn admin_disable_handler(
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

    disable_client(pg_pool.get_ref(), client).await
}

async fn disable_client(pg_pool: &PgPool, mut client: models::Client) -> Result<impl Responder> {
    if client.secret.is_none() {
        return Err(JsonResponse::<models::Client>::build().bad_request("client is not active"));
    }

    client.secret = None;
    db::client::update(pg_pool, client)
        .await
        .map(|client| JsonResponse::build().set_item(client).ok("success"))
        .map_err(|msg| JsonResponse::<models::Client>::build().bad_request(msg))
}
