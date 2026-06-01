use crate::db;
use crate::helpers::JsonResponse;
use crate::models::User;
use actix_web::{post, web, Responder, Result};
use sqlx::PgPool;
use std::sync::Arc;

#[tracing::instrument(name = "Cancel command", skip_all)]
#[post("/{deployment_hash}/{command_id}/cancel")]
pub async fn cancel_handler(
    user: web::ReqData<Arc<User>>,
    path: web::Path<(String, String)>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    let (deployment_hash, command_id) = path.into_inner();

    // Fetch command first to verify it exists and belongs to this deployment
    let command = db::command::fetch_by_id(pg_pool.get_ref(), &command_id)
        .await
        .map_err(|err| {
            tracing::error!("Failed to fetch command: {}", err);
            JsonResponse::internal_server_error(err)
        })?;

    let command = match command {
        Some(cmd) => cmd,
        None => {
            tracing::warn!("Command not found: {}", command_id);
            return Err(JsonResponse::not_found("Command not found"));
        }
    };

    // Verify deployment_hash matches
    if command.deployment_hash != deployment_hash {
        tracing::warn!(
            "Deployment hash mismatch: expected {}, got {}",
            deployment_hash,
            command.deployment_hash
        );
        return Err(JsonResponse::not_found(
            "Command not found for this deployment",
        ));
    }

    // Check if command can be cancelled (only queued or sent commands)
    if command.status != "queued" && command.status != "sent" {
        tracing::warn!(
            "Cannot cancel command {} with status {}",
            command_id,
            command.status
        );
        return Err(JsonResponse::bad_request(format!(
            "Cannot cancel command with status '{}'",
            command.status
        )));
    }

    // Cancel the command (remove from queue and update status)
    let cancelled_command = db::command::cancel(pg_pool.get_ref(), &command_id)
        .await
        .map_err(|err| {
            tracing::error!("Failed to cancel command: {}", err);
            JsonResponse::internal_server_error(err)
        })?;

    tracing::info!(
        "Cancelled command {} for deployment {} by user {}",
        command_id,
        deployment_hash,
        user.id
    );

    Ok(JsonResponse::build()
        .set_item(Some(cancelled_command))
        .ok("Command cancelled successfully"))
}
