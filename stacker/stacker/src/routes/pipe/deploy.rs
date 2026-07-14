use crate::db;
use crate::helpers::JsonResponse;
use crate::models::{PipeInstance, User};
use actix_web::{post, web, Responder, Result};
use serde::Deserialize;
use sqlx::PgPool;
use std::sync::Arc;

use super::verify_pipe_owner;

#[derive(Debug, Deserialize)]
pub struct DeployPipeRequest {
    pub deployment_hash: String,
}

/// Deploy (promote) a local pipe instance to a remote deployment.
///
/// `POST /instances/{instance_id}/deploy`
///
/// Clones the local pipe's configuration to a new remote instance
/// linked to the specified deployment.
#[tracing::instrument(name = "Deploy local pipe to remote", skip_all)]
#[post("/instances/{instance_id}/deploy")]
pub async fn deploy_pipe_handler(
    user: web::ReqData<Arc<User>>,
    path: web::Path<String>,
    req: web::Json<DeployPipeRequest>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    let instance_id = path.into_inner();
    let deployment_hash = req.deployment_hash.trim();

    if deployment_hash.is_empty() {
        return Err(JsonResponse::<()>::build().bad_request("deployment_hash is required"));
    }

    // 1. Fetch the source (local) instance
    let instance_uuid = uuid::Uuid::parse_str(&instance_id)
        .map_err(|_| JsonResponse::<()>::build().bad_request("Invalid instance ID format"))?;

    let source_instance = db::pipe::get_instance(pg_pool.get_ref(), &instance_uuid)
        .await
        .map_err(|err| {
            tracing::error!("Failed to fetch pipe instance: {}", err);
            JsonResponse::internal_server_error(err)
        })?
        .ok_or_else(|| JsonResponse::not_found("Pipe instance not found"))?;

    // 2. Verify ownership
    verify_pipe_owner(pg_pool.get_ref(), &source_instance, &user.id).await?;

    // 3. Verify it's a local instance
    if !source_instance.is_local {
        return Err(JsonResponse::<()>::build().bad_request(
            "Only local pipe instances can be deployed. This instance is already remote.",
        ));
    }

    // 4. Verify target deployment exists and belongs to user
    let deployment = db::deployment::fetch_by_deployment_hash(pg_pool.get_ref(), deployment_hash)
        .await
        .map_err(|err| JsonResponse::internal_server_error(err))?;

    match &deployment {
        Some(d) if d.user_id.as_deref() == Some(&user.id) => {}
        _ => {
            return Err(JsonResponse::not_found("Deployment not found"));
        }
    }

    // 5. Create new remote instance cloned from local
    let mut remote = PipeInstance::new(
        deployment_hash.to_string(),
        source_instance.source_container.clone(),
        user.id.clone(),
    );
    remote.source_adapter = source_instance.source_adapter.clone();
    remote.target_adapter = source_instance.target_adapter.clone();
    remote.target_container = source_instance.target_container.clone();
    remote.target_url = source_instance.target_url.clone();
    remote.template_id = source_instance.template_id;
    remote.field_mapping_override = source_instance.field_mapping_override.clone();
    remote.config_override = source_instance.config_override.clone();

    let saved = db::pipe::insert_instance(pg_pool.get_ref(), &remote)
        .await
        .map_err(|err| {
            tracing::error!("Failed to deploy pipe instance: {}", err);
            JsonResponse::internal_server_error(err)
        })?;

    tracing::info!(
        source_id = %instance_id,
        remote_id = %saved.id,
        deployment_hash = %deployment_hash,
        "Local pipe deployed to remote by user {}",
        user.id
    );

    Ok(JsonResponse::build()
        .set_item(Some(saved))
        .created("Pipe deployed to remote successfully"))
}
