use crate::configuration::Settings;
use crate::db;
use crate::helpers::client;
use crate::helpers::JsonResponse;
use crate::models;
use actix_web::{post, web, Responder, Result};
use sqlx::PgPool;
use std::sync::Arc;

#[tracing::instrument(name = "Add client.", skip_all)]
#[post("")]
pub async fn add_handler(
    user: web::ReqData<Arc<models::User>>,
    settings: web::Data<Settings>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    add_handler_inner(&user.id, settings, pg_pool)
        .await
        .map(|client| JsonResponse::build().set_item(client).ok("Ok"))
        .map_err(|err| JsonResponse::<models::Client>::build().bad_request(err))
}

pub async fn add_handler_inner(
    user_id: &String,
    settings: web::Data<Settings>,
    pg_pool: web::Data<PgPool>,
) -> Result<models::Client, String> {
    let client_count = db::client::count_by_user(pg_pool.get_ref(), user_id).await?;
    if client_count >= settings.max_clients_number {
        return Err("Too many clients created".to_string());
    }

    let client = create_client(pg_pool.get_ref(), user_id).await?;
    db::client::insert(pg_pool.get_ref(), client).await
}

async fn create_client(pg_pool: &PgPool, user_id: &String) -> Result<models::Client, String> {
    let mut client = models::Client::default();
    client.user_id = user_id.clone();
    client.secret = client::generate_secret(pg_pool, 255)
        .await
        .map(|s| Some(s))?;

    Ok(client)
}
