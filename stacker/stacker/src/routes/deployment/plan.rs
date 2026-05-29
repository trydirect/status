use actix_web::{get, web, Responder, Result};
use serde::Deserialize;
use sqlx::PgPool;
use std::sync::Arc;

use crate::{
    models,
    services::{
        build_deploy_plan, build_rollback_plan, resolve_rollback_plan_context, ApiTypedError,
        DeployPlanOperation, DeploymentState, TypedErrorCode, TypedErrorEnvelope,
    },
};

#[derive(Debug, Deserialize)]
pub struct DeploymentPlanQuery {
    #[serde(default)]
    pub operation: Option<DeployPlanOperation>,
    #[serde(default, rename = "appCode")]
    pub app_code: Option<String>,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default, rename = "expectedFingerprint")]
    pub expected_fingerprint: Option<String>,
    #[serde(default, rename = "rollbackTarget")]
    pub rollback_target: Option<String>,
}

#[tracing::instrument(name = "Get deployment plan by hash", skip_all)]
#[get("/{deployment_hash}/plan")]
pub async fn plan_handler(
    path: web::Path<String>,
    query: web::Query<DeploymentPlanQuery>,
    user: web::ReqData<Arc<models::User>>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder, ApiTypedError> {
    let deployment_hash = path.into_inner();
    let deployment =
        crate::db::deployment::fetch_by_deployment_hash(pg_pool.get_ref(), &deployment_hash)
            .await
            .map_err(|_| {
                ApiTypedError::internal(TypedErrorEnvelope::internal_error(
                    "Failed to load deployment for plan",
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
                "Failed to build deployment plan state",
            ))
        })?
        .ok_or_else(|| {
            ApiTypedError::not_found(TypedErrorEnvelope::deployment_not_found(
                "Deployment not found",
            ))
        })?;

    let operation = query
        .operation
        .clone()
        .unwrap_or(DeployPlanOperation::Deploy);
    let target = query.target.as_deref().unwrap_or("cloud");
    let plan = match operation {
        DeployPlanOperation::RollbackDeploy => {
            let requested_target = query.rollback_target.as_deref().ok_or_else(|| {
                ApiTypedError::bad_request(TypedErrorEnvelope::invalid_request(
                    "rollbackTarget is required for rollback plans",
                ))
            })?;
            let rollback =
                resolve_rollback_plan_context(pg_pool.get_ref(), &deployment, requested_target)
                    .await
                    .map_err(ApiTypedError::bad_request)?;
            build_rollback_plan(
                &state,
                target,
                rollback,
                query.expected_fingerprint.as_deref(),
            )
        }
        _ => build_deploy_plan(
            &state,
            operation,
            target,
            query.app_code.as_deref(),
            query.expected_fingerprint.as_deref(),
        ),
    }
    .map_err(|error| match error.code {
        TypedErrorCode::PlanStale => ApiTypedError::conflict(error),
        TypedErrorCode::InvalidRequest => ApiTypedError::bad_request(error),
        TypedErrorCode::RollbackTargetUnavailable => ApiTypedError::bad_request(error),
        _ => ApiTypedError::internal(error),
    })?;

    Ok(crate::helpers::JsonResponse::build()
        .set_item(plan)
        .ok("Deployment plan fetched"))
}
