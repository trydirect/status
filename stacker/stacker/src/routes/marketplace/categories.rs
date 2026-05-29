use crate::db;
use crate::helpers::JsonResponse;
use crate::models;
use actix_web::{get, web, Responder, Result};
use sqlx::PgPool;

#[tracing::instrument(name = "List categories", skip_all)]
#[get("/categories")]
pub async fn list_handler(pg_pool: web::Data<PgPool>) -> Result<impl Responder> {
    db::marketplace::get_categories(pg_pool.get_ref())
        .await
        .map_err(|err| {
            JsonResponse::<Vec<models::StackCategory>>::build().internal_server_error(err)
        })
        .map(|categories| JsonResponse::build().set_list(categories).ok("OK"))
}
