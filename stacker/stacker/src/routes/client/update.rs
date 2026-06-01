use crate::db;
use crate::helpers::client;
use crate::models;
use crate::{configuration::Settings, helpers::JsonResponse};
use actix_web::{put, web, Responder, Result};
use sqlx::PgPool;
use std::sync::Arc;

#[tracing::instrument(name = "User update client.", skip_all)]
#[put("/{id}")]
pub async fn update_handler(
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

    update_client(pg_pool.get_ref(), client).await
}

#[tracing::instrument(name = "Admin update client.", skip_all)]
#[put("/{id}")]
pub async fn admin_update_handler(
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

    update_client(pg_pool.get_ref(), client).await
}

async fn update_client(pg_pool: &PgPool, mut client: models::Client) -> Result<impl Responder> {
    if client.secret.is_none() {
        return Err(JsonResponse::<models::Client>::build().bad_request("client is not active"));
    }

    client.secret = client::generate_secret(pg_pool, 255)
        .await
        .map(|s| Some(s))
        .map_err(|msg| JsonResponse::<models::Client>::build().bad_request(msg))?;

    db::client::update(pg_pool, client)
        .await
        .map(|client| {
            JsonResponse::<models::Client>::build()
                .set_item(client)
                .ok("success")
        })
        .map_err(|err| {
            tracing::error!("Failed to execute query: {:?}", err);
            JsonResponse::<models::Client>::build().internal_server_error("")
        })
}
