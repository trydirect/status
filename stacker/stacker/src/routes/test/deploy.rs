use crate::helpers::JsonResponse;
use crate::models::Client;
use actix_web::{post, web, Responder, Result};
use serde::Serialize;
use std::sync::Arc;

#[derive(Serialize)]
#[allow(dead_code)]
struct DeployResponse {
    status: String,
    client: Arc<Client>,
}

#[tracing::instrument(name = "Test deploy.", skip_all)]
#[post("/deploy")]
pub async fn handler(client: web::ReqData<Arc<Client>>) -> Result<impl Responder> {
    Ok(JsonResponse::build()
        .set_item(client.into_inner())
        .ok("success"))
}
