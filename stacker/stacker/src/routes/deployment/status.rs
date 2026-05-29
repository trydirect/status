use actix_web::{get, web, Responder, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;

use crate::routes::legacy_installations::{resolve_owned_deployment_by_hash, OwnedDeployment};
use crate::{configuration::Settings, db, helpers::JsonResponse, models};

async fn can_view_project_deployments(
    pool: &PgPool,
    user_id: &str,
    project_id: i32,
) -> Result<bool, String> {
    let project = db::project::fetch(pool, project_id).await?;
    match project {
        Some(project) if project.user_id == user_id => Ok(true),
        Some(_) => Ok(db::project_member::fetch(pool, project_id, user_id)
            .await?
            .is_some()),
        None => Ok(false),
    }
}

/// Public-facing deployment status response (hides internal metadata).
#[derive(Debug, Clone, Serialize, Default)]
pub struct DeploymentStatusResponse {
    pub id: i32,
    pub project_id: i32,
    pub deployment_hash: String,
    pub status: String,
    /// Human-readable status/error message from the deployment pipeline.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_message: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct DeploymentListQuery {
    pub project_id: Option<i32>,
    pub limit: Option<i64>,
}

impl From<models::Deployment> for DeploymentStatusResponse {
    fn from(d: models::Deployment) -> Self {
        let status_message = d
            .metadata
            .get("status_message")
            .and_then(|v| v.as_str())
            .map(String::from);

        Self {
            id: d.id,
            project_id: d.project_id,
            deployment_hash: d.deployment_hash,
            status: d.status,
            status_message,
            created_at: d.created_at,
            updated_at: d.updated_at,
        }
    }
}

/// `GET /api/v1/deployments/hash/{hash}`
///
/// Fetch a deployment by its deployment hash string.
#[tracing::instrument(name = "Get deployment status by hash", skip_all)]
#[get("/hash/{hash}")]
pub async fn status_by_hash_handler(
    path: web::Path<String>,
    user: web::ReqData<Arc<models::User>>,
    pg_pool: web::Data<PgPool>,
    settings: web::Data<Settings>,
) -> Result<impl Responder> {
    let hash = path.into_inner();

    match resolve_owned_deployment_by_hash(
        pg_pool.get_ref(),
        settings.get_ref(),
        user.as_ref(),
        &hash,
    )
    .await?
    {
        OwnedDeployment::Native(deployment) => {
            let resp: DeploymentStatusResponse = deployment.into();
            Ok(JsonResponse::build()
                .set_item(resp)
                .ok("Deployment status fetched"))
        }
        OwnedDeployment::Legacy(installation) => {
            let resp = DeploymentStatusResponse {
                id: installation
                    .id
                    .and_then(|value| i32::try_from(value).ok())
                    .unwrap_or_default(),
                project_id: 0,
                deployment_hash: installation.deployment_hash.unwrap_or(hash),
                status: installation.status.unwrap_or_else(|| "unknown".to_string()),
                status_message: installation.domain,
                created_at: parse_legacy_timestamp(installation.created_at.as_deref()),
                updated_at: parse_legacy_timestamp(installation.updated_at.as_deref()),
            };

            Ok(JsonResponse::build()
                .set_item(resp)
                .ok("Deployment status fetched"))
        }
    }
}

fn parse_legacy_timestamp(value: Option<&str>) -> DateTime<Utc> {
    value
        .and_then(|raw| DateTime::parse_from_rfc3339(raw).ok())
        .map(|parsed| parsed.with_timezone(&Utc))
        .unwrap_or_else(Utc::now)
}

/// `GET /api/v1/deployments/{id}`
///
/// Fetch deployment status by deployment ID.
/// Requires authentication (inherited from the `/api` scope middleware).
#[tracing::instrument(name = "Get deployment status by ID", skip_all)]
#[get("/{id}")]
pub async fn status_handler(
    path: web::Path<i32>,
    user: web::ReqData<Arc<models::User>>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    let deployment_id = path.into_inner();

    let deployment = db::deployment::fetch(pg_pool.get_ref(), deployment_id)
        .await
        .map_err(|err| {
            JsonResponse::<DeploymentStatusResponse>::build().internal_server_error(err)
        })?;

    match deployment {
        Some(d) => {
            // Verify the deployment belongs to the requesting user
            if d.user_id.as_deref() != Some(&user.id) {
                return Err(JsonResponse::<DeploymentStatusResponse>::build()
                    .not_found("Deployment not found"));
            }
            let resp: DeploymentStatusResponse = d.into();
            Ok(JsonResponse::build()
                .set_item(resp)
                .ok("Deployment status fetched"))
        }
        None => {
            Err(JsonResponse::<DeploymentStatusResponse>::build().not_found("Deployment not found"))
        }
    }
}

/// `GET /api/v1/deployments`
///
/// List deployments for the authenticated user.
#[tracing::instrument(name = "List deployments", skip_all)]
#[get("")]
pub async fn list_handler(
    user: web::ReqData<Arc<models::User>>,
    query: web::Query<DeploymentListQuery>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    let limit = query.limit.unwrap_or(50).max(1).min(500);
    let deployments = if let Some(project_id) = query.project_id {
        if !can_view_project_deployments(pg_pool.get_ref(), &user.id, project_id)
            .await
            .map_err(|err| {
                JsonResponse::<DeploymentStatusResponse>::build().internal_server_error(err)
            })?
        {
            return Err(
                JsonResponse::<DeploymentStatusResponse>::build().not_found("Project not found")
            );
        }

        let project = db::project::fetch(pg_pool.get_ref(), project_id)
            .await
            .map_err(|err| {
                JsonResponse::<DeploymentStatusResponse>::build().internal_server_error(err)
            })?
            .ok_or_else(|| {
                JsonResponse::<DeploymentStatusResponse>::build().not_found("Project not found")
            })?;

        if project.user_id == user.id {
            db::deployment::fetch_by_user_and_project(
                pg_pool.get_ref(),
                &user.id,
                project_id,
                limit,
            )
            .await
            .map_err(|err| {
                JsonResponse::<DeploymentStatusResponse>::build().internal_server_error(err)
            })?
        } else {
            db::deployment::fetch_by_project(pg_pool.get_ref(), project_id, limit)
                .await
                .map_err(|err| {
                    JsonResponse::<DeploymentStatusResponse>::build().internal_server_error(err)
                })?
        }
    } else {
        db::deployment::fetch_by_user(pg_pool.get_ref(), &user.id, limit)
            .await
            .map_err(|err| {
                JsonResponse::<DeploymentStatusResponse>::build().internal_server_error(err)
            })?
    };

    let list: Vec<DeploymentStatusResponse> = deployments
        .into_iter()
        .map(DeploymentStatusResponse::from)
        .collect();

    Ok(JsonResponse::build()
        .set_list(list)
        .ok("Deployments fetched"))
}

/// `GET /api/v1/deployments/project/{project_id}`
///
/// Fetch the latest deployment status for a project.
/// Returns the most recent (non-deleted) deployment.
#[tracing::instrument(name = "Get deployment status by project ID", skip_all)]
#[get("/project/{project_id}")]
pub async fn status_by_project_handler(
    path: web::Path<i32>,
    user: web::ReqData<Arc<models::User>>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    let project_id = path.into_inner();

    let deployment = db::deployment::fetch_by_project_id(pg_pool.get_ref(), project_id)
        .await
        .map_err(|err| {
            JsonResponse::<DeploymentStatusResponse>::build().internal_server_error(err)
        })?;

    match deployment {
        Some(d) => {
            if d.user_id.as_deref() != Some(&user.id)
                && !db::project_member::fetch(pg_pool.get_ref(), project_id, &user.id)
                    .await
                    .map_err(|err| {
                        JsonResponse::<DeploymentStatusResponse>::build().internal_server_error(err)
                    })?
                    .is_some()
            {
                return Err(JsonResponse::<DeploymentStatusResponse>::build()
                    .not_found("No deployment found for this project"));
            }
            let resp: DeploymentStatusResponse = d.into();
            Ok(JsonResponse::build()
                .set_item(resp)
                .ok("Deployment status fetched"))
        }
        None => Err(JsonResponse::<DeploymentStatusResponse>::build()
            .not_found("No deployment found for this project")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deployment_to_status_response() {
        let d = models::Deployment::new(
            42,
            Some("user123".to_string()),
            "deployment_abc".to_string(),
            "in_progress".to_string(),
            "runc".to_string(),
            serde_json::json!({}),
        );
        let resp: DeploymentStatusResponse = d.into();
        assert_eq!(resp.project_id, 42);
        assert_eq!(resp.deployment_hash, "deployment_abc");
        assert_eq!(resp.status, "in_progress");
    }
}
