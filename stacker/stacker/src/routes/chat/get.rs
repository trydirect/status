use crate::db;
use crate::helpers::JsonResponse;
use crate::models;
use actix_web::{get, web, Responder, Result};
use serde::Deserialize;
use sqlx::PgPool;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct Query {
    pub project_id: Option<i32>,
}

/// GET /chat/history?project_id={id}
/// Returns the saved chat conversation for the logged-in user.
/// project_id is optional; omit for canvas/onboarding mode.
#[tracing::instrument(name = "Get chat history.", skip_all)]
#[get("/history")]
pub async fn item(
    user: web::ReqData<Arc<models::User>>,
    query: web::Query<Query>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    db::chat::fetch(pg_pool.get_ref(), &user.id, query.project_id)
        .await
        .map_err(|err| JsonResponse::internal_server_error(err.to_string()))
        .and_then(|conv| match conv {
            Some(c) => Ok(JsonResponse::build().set_item(Some(c)).ok("OK")),
            None => Err(JsonResponse::not_found("No chat history found")),
        })
}
