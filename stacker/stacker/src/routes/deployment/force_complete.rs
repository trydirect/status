use actix_web::{post, web, Responder, Result};
use serde::Deserialize;
use sqlx::PgPool;
use std::sync::Arc;

use crate::{db, helpers::JsonResponse, models};

use super::status::DeploymentStatusResponse;

/// Statuses resolvable without `--force`.
const FORCE_COMPLETE_ALLOWED: &[&str] = &["paused", "error"];

#[derive(Debug, Deserialize, Default)]
pub struct ForceCompleteQuery {
    #[serde(default)]
    pub force: bool,
}

/// `POST /api/v1/deployments/{id}/force-complete[?force=true]`
///
/// Transition a stuck deployment to `completed`.
/// Without `?force=true`: only `paused` or `error` are accepted.
/// With `?force=true`: `in_progress` is also accepted.
/// Only the owning user may invoke this.
#[tracing::instrument(name = "Force-complete deployment", skip_all)]
#[post("/{id}/force-complete")]
pub async fn force_complete_handler(
    path: web::Path<i32>,
    query: web::Query<ForceCompleteQuery>,
    user: web::ReqData<Arc<models::User>>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    let deployment_id = path.into_inner();

    let deployment = db::deployment::fetch(pg_pool.get_ref(), deployment_id)
        .await
        .map_err(|err| {
            JsonResponse::<DeploymentStatusResponse>::build().internal_server_error(err)
        })?;

    let mut deployment = match deployment {
        Some(d) => {
            if d.user_id.as_deref() != Some(&user.id) {
                return Err(JsonResponse::<DeploymentStatusResponse>::build()
                    .not_found("Deployment not found"));
            }
            d
        }
        None => {
            return Err(
                JsonResponse::<DeploymentStatusResponse>::build().not_found("Deployment not found")
            );
        }
    };

    let status_ok = query.force || FORCE_COMPLETE_ALLOWED.contains(&deployment.status.as_str());

    if !status_ok {
        return Err(JsonResponse::<DeploymentStatusResponse>::build().bad_request(format!(
            "Cannot force-complete deployment with status '{}'. Only paused or error deployments can be force-completed.",
            deployment.status
        )));
    }

    let previous_status = deployment.status.clone();
    deployment.status = "completed".to_string();

    // Record the override in metadata for audit trail
    if let Some(obj) = deployment.metadata.as_object_mut() {
        obj.insert(
            "force_completed_from".into(),
            serde_json::Value::String(previous_status),
        );
        if query.force {
            obj.insert("force_override".into(), serde_json::Value::Bool(true));
        }
    }

    let deployment = db::deployment::update(pg_pool.get_ref(), deployment)
        .await
        .map_err(|err| {
            JsonResponse::<DeploymentStatusResponse>::build().internal_server_error(err)
        })?;

    tracing::info!(
        "Force-completed deployment {} (was '{}')",
        deployment_id,
        deployment
            .metadata
            .get("force_completed_from")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
    );

    let resp: DeploymentStatusResponse = deployment.into();
    Ok(JsonResponse::build()
        .set_item(resp)
        .ok("Deployment force-completed"))
}
