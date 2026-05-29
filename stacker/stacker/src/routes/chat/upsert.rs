use crate::db;
use crate::helpers::JsonResponse;
use crate::models;
use actix_web::{put, web, Responder, Result};
use serde::Deserialize;
use serde_json::Value;
use sqlx::PgPool;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct ChatHistoryRequest {
    pub project_id: Option<i32>,
    pub messages: Value,
}

/// PUT /chat/history
/// Upserts the chat conversation for the logged-in user.
#[tracing::instrument(name = "Upsert chat history.", skip_all)]
#[put("/history")]
pub async fn item(
    user: web::ReqData<Arc<models::User>>,
    web::Json(body): web::Json<ChatHistoryRequest>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    db::chat::upsert(pg_pool.get_ref(), &user.id, body.project_id, body.messages)
        .await
        .map(|conv| JsonResponse::build().set_item(conv).ok("OK"))
        .map_err(|err| JsonResponse::internal_server_error(err.to_string()))
}
