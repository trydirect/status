use crate::db;
use crate::helpers::{JsonResponse, VaultClient};
use crate::models;
use crate::models::Server;
use actix_web::{delete, get, web, Responder, Result};
use sqlx::PgPool;
use std::sync::Arc;

/// Preview what would be deleted if the server is removed.
/// Returns: ssh_key_shared, affected_deployments, agent_count
#[tracing::instrument(name = "Preview server deletion impact.", skip_all)]
#[get("/{id}/delete-preview")]
pub async fn delete_preview(
    user: web::ReqData<Arc<models::User>>,
    path: web::Path<(i32,)>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    let (id,) = path.into_inner();

    let server = db::server::fetch(pg_pool.get_ref(), id)
        .await
        .map_err(|err| JsonResponse::<Server>::build().internal_server_error(err))
        .and_then(|server| match server {
            Some(server) if server.user_id != user.id => {
                Err(JsonResponse::<Server>::build().not_found(""))
            }
            Some(server) => Ok(server),
            None => Err(JsonResponse::<Server>::build().not_found("")),
        })?;

    // Check if SSH key is shared with other servers
    let ssh_key_shared = if let Some(ref vault_path) = server.vault_key_path {
        let user_servers = db::server::fetch_by_user(pg_pool.get_ref(), &user.id)
            .await
            .unwrap_or_default();

        user_servers
            .iter()
            .any(|s| s.id != server.id && s.vault_key_path.as_deref() == Some(vault_path.as_str()))
    } else {
        false
    };

    // Find affected deployments via project
    let mut affected_deployments: Vec<serde_json::Value> = Vec::new();
    let mut agent_count: usize = 0;

    if let Ok(Some(deployment)) =
        db::deployment::fetch_by_project_id(pg_pool.get_ref(), server.project_id).await
    {
        affected_deployments.push(serde_json::json!({
            "deployment_hash": deployment.deployment_hash,
            "status": deployment.status,
        }));

        // Check for agent
        if let Ok(Some(_agent)) =
            db::agent::fetch_by_deployment_hash(pg_pool.get_ref(), &deployment.deployment_hash)
                .await
        {
            agent_count += 1;
        }
    }

    Ok(JsonResponse::<serde_json::Value>::build()
        .set_item(serde_json::json!({
            "ssh_key_shared": ssh_key_shared,
            "affected_deployments": affected_deployments,
            "agent_count": agent_count,
        }))
        .ok("Delete preview"))
}

#[tracing::instrument(name = "Delete user's server with cleanup.", skip_all)]
#[delete("/{id}")]
pub async fn item(
    user: web::ReqData<Arc<models::User>>,
    path: web::Path<(i32,)>,
    pg_pool: web::Data<PgPool>,
    vault_client: web::Data<VaultClient>,
) -> Result<impl Responder> {
    let (id,) = path.into_inner();

    let server = db::server::fetch(pg_pool.get_ref(), id)
        .await
        .map_err(|err| JsonResponse::<Server>::build().internal_server_error(err))
        .and_then(|server| match server {
            Some(server) if server.user_id != user.id => {
                Err(JsonResponse::<Server>::build().not_found(""))
            }
            Some(server) => Ok(server),
            None => Err(JsonResponse::<Server>::build().not_found("")),
        })?;

    // 1. Check if SSH key is shared before cleaning up
    let ssh_key_shared = if let Some(ref vault_path) = server.vault_key_path {
        let user_servers = db::server::fetch_by_user(pg_pool.get_ref(), &user.id)
            .await
            .unwrap_or_default();

        user_servers
            .iter()
            .any(|s| s.id != server.id && s.vault_key_path.as_deref() == Some(vault_path.as_str()))
    } else {
        false
    };

    // 2. Delete SSH key from Vault if not shared and key exists
    if !ssh_key_shared && server.vault_key_path.is_some() {
        if let Err(e) = vault_client.delete_ssh_key(&user.id, server.id).await {
            tracing::warn!(
                "Failed to delete SSH key from Vault for server {}: {}. Continuing with server deletion.",
                server.id,
                e
            );
        }
    }

    // 3. Clean up agents linked via deployment → project
    if let Ok(Some(deployment)) =
        db::deployment::fetch_by_project_id(pg_pool.get_ref(), server.project_id).await
    {
        // Delete agent record
        if let Ok(Some(agent)) =
            db::agent::fetch_by_deployment_hash(pg_pool.get_ref(), &deployment.deployment_hash)
                .await
        {
            // Delete agent token from Vault
            if let Err(e) = vault_client
                .delete_agent_token(&deployment.deployment_hash)
                .await
            {
                tracing::warn!(
                    "Failed to delete agent token from Vault for deployment {}: {}",
                    deployment.deployment_hash,
                    e
                );
            }

            // Delete agent record from DB
            if let Err(e) = db::agent::delete(pg_pool.get_ref(), agent.id).await {
                tracing::warn!(
                    "Failed to delete agent record for deployment {}: {}",
                    deployment.deployment_hash,
                    e
                );
            }
        }
    }

    // 4. Delete server record from DB
    db::server::delete(pg_pool.get_ref(), server.id, &user.id)
        .await
        .map_err(|err| JsonResponse::<Server>::build().internal_server_error(err))
        .and_then(|result| match result {
            true => Ok(JsonResponse::<Server>::build().ok("Item deleted")),
            _ => Err(JsonResponse::<Server>::build().bad_request("Could not delete")),
        })
}
