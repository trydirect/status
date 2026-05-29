use crate::db;
use crate::helpers::JsonResponse;
use crate::models;
use actix_web::{delete, web, Responder, Result};
use serde::Deserialize;
use sqlx::PgPool;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct Query {
    pub project_id: Option<i32>,
}

/// DELETE /chat/history?project_id={id}
/// Clears the stored chat conversation for the logged-in user.
#[tracing::instrument(name = "Delete chat history.", skip_all)]
#[delete("/history")]
pub async fn item(
    user: web::ReqData<Arc<models::User>>,
    query: web::Query<Query>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    db::chat::delete(pg_pool.get_ref(), &user.id, query.project_id)
        .await
        .map_err(|err| JsonResponse::internal_server_error(err.to_string()))
        .map(|_| JsonResponse::<models::ChatConversation>::build().ok("OK"))
}
