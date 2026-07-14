use actix_web::{get, web, Responder, Result};
use sqlx::PgPool;
use std::sync::Arc;

use crate::{
    helpers::JsonResponse,
    models,
    services::{ApiTypedError, DeploymentEventFeed, TypedErrorEnvelope},
};

#[tracing::instrument(name = "Get deployment events by hash", skip_all)]
#[get("/{deployment_hash}/events")]
pub async fn events_handler(
    path: web::Path<String>,
    user: web::ReqData<Arc<models::User>>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder, ApiTypedError> {
    let deployment_hash = path.into_inner();
    let deployment =
        crate::db::deployment::fetch_by_deployment_hash(pg_pool.get_ref(), &deployment_hash)
            .await
            .map_err(|_| {
                ApiTypedError::internal(TypedErrorEnvelope::internal_error(
                    "Failed to load deployment events",
                ))
            })?
            .ok_or_else(|| {
                ApiTypedError::not_found(TypedErrorEnvelope::deployment_not_found(
                    "Deployment not found",
                ))
            })?;

    if deployment.user_id.as_deref() != Some(&user.id) {
        return Err(ApiTypedError::not_found(
            TypedErrorEnvelope::deployment_not_found("Deployment not found"),
        ));
    }

    let feed = DeploymentEventFeed::for_deployment_hash(pg_pool.get_ref(), &deployment_hash)
        .await
        .map_err(|_| {
            ApiTypedError::internal(TypedErrorEnvelope::internal_error(
                "Failed to build deployment events",
            ))
        })?
        .ok_or_else(|| {
            ApiTypedError::not_found(TypedErrorEnvelope::deployment_not_found(
                "Deployment not found",
            ))
        })?;

    Ok(JsonResponse::build()
        .set_item(feed)
        .ok("Deployment events fetched"))
}
