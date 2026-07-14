use actix_web::{get, web, Responder, Result};
use sqlx::PgPool;
use std::sync::Arc;

use crate::{
    helpers::JsonResponse,
    models,
    services::{ApiTypedError, DeploymentState, TypedErrorEnvelope},
};

#[tracing::instrument(name = "Get canonical deployment state by hash", skip_all)]
#[get("/{deployment_hash}/state")]
pub async fn state_handler(
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
                    "Failed to load deployment state",
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

    let state = DeploymentState::for_deployment_hash(pg_pool.get_ref(), &deployment_hash)
        .await
        .map_err(|_| {
            ApiTypedError::internal(TypedErrorEnvelope::internal_error(
                "Failed to build deployment state",
            ))
        })?;

    match state {
        Some(state) => Ok(JsonResponse::build()
            .set_item(state)
            .ok("Deployment state fetched")),
        None => Err(ApiTypedError::not_found(
            TypedErrorEnvelope::deployment_not_found("Deployment not found"),
        )),
    }
}
