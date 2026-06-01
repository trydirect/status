use crate::configuration::Settings;
use crate::db;
use crate::helpers::JsonResponse;
use crate::models::User;
use crate::routes::legacy_installations::resolve_owned_deployment_by_hash;
use actix_web::{get, web, Responder, Result};
use sqlx::PgPool;
use std::sync::Arc;

#[tracing::instrument(name = "Get command by ID", skip_all)]
#[get("/{deployment_hash}/{command_id}")]
pub async fn get_handler(
    user: web::ReqData<Arc<User>>,
    path: web::Path<(String, String)>,
    pg_pool: web::Data<PgPool>,
    settings: web::Data<Settings>,
) -> Result<impl Responder> {
    let (deployment_hash, command_id) = path.into_inner();

    resolve_owned_deployment_by_hash(
        pg_pool.get_ref(),
        settings.get_ref(),
        user.as_ref(),
        &deployment_hash,
    )
    .await?;

    // Fetch command by its string command_id (e.g. "cmd_<uuid>"), not the row UUID
    let command = db::command::fetch_by_command_id(pg_pool.get_ref(), &command_id)
        .await
        .map_err(|err| {
            tracing::error!("Failed to fetch command: {}", err);
            JsonResponse::internal_server_error(err)
        })?;

    match command {
        Some(cmd) => {
            // Verify deployment_hash matches (authorization check)
            if cmd.deployment_hash != deployment_hash {
                tracing::warn!(
                    "Deployment hash mismatch: expected {}, got {}",
                    deployment_hash,
                    cmd.deployment_hash
                );
                return Err(JsonResponse::not_found(
                    "Command not found for this deployment",
                ));
            }

            tracing::info!(
                "Fetched command {} for deployment {} by user {}",
                command_id,
                deployment_hash,
                user.id
            );

            Ok(JsonResponse::build()
                .set_item(Some(cmd))
                .ok("Command fetched successfully"))
        }
        None => {
            tracing::warn!("Command not found: {}", command_id);
            Err(JsonResponse::not_found("Command not found"))
        }
    }
}
