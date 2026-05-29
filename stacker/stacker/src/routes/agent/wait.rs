use crate::{configuration::Settings, db, helpers, helpers::AgentPgPool, models};
use actix_web::{get, web, HttpRequest, Responder, Result};
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, serde::Deserialize)]
pub struct WaitQuery {
    pub timeout: Option<u64>,
    pub interval: Option<u64>,
}

#[tracing::instrument(name = "Agent poll for commands", skip_all)]
#[get("/commands/wait/{deployment_hash}")]
pub async fn wait_handler(
    agent: web::ReqData<Arc<models::Agent>>,
    path: web::Path<String>,
    query: web::Query<WaitQuery>,
    agent_pool: web::Data<AgentPgPool>,
    settings: web::Data<Settings>,
    _req: HttpRequest,
) -> Result<impl Responder> {
    let deployment_hash = path.into_inner();

    // Verify agent is authorized for this deployment_hash
    if agent.deployment_hash != deployment_hash {
        return Err(helpers::JsonResponse::forbidden(
            "Not authorized for this deployment",
        ));
    }

    // Update agent heartbeat - acquire and release connection quickly
    let _ = db::agent::update_heartbeat(agent_pool.as_ref(), agent.id, "online").await;

    // Log poll event - acquire and release connection quickly
    let audit_log = models::AuditLog::new(
        Some(agent.id),
        Some(deployment_hash.clone()),
        "agent.command_polled".to_string(),
        Some("success".to_string()),
    );
    let _ = db::agent::log_audit(agent_pool.as_ref(), audit_log).await;

    // Long-polling: Check for pending commands with retries
    // IMPORTANT: Each check acquires and releases DB connection to avoid pool exhaustion
    let timeout_seconds = query
        .timeout
        .unwrap_or(settings.agent_command_poll_timeout_secs)
        .clamp(5, 120);
    let interval_seconds = query
        .interval
        .unwrap_or(settings.agent_command_poll_interval_secs)
        .clamp(1, 10);
    let check_interval = Duration::from_secs(interval_seconds);
    let max_checks = (timeout_seconds / interval_seconds).max(1);

    for i in 0..max_checks {
        // Acquire connection only for query, then release immediately
        match db::command::fetch_next_for_deployment(agent_pool.as_ref(), &deployment_hash).await {
            Ok(Some(command)) => {
                tracing::info!(
                    "Found command {} for agent {} (deployment {})",
                    command.command_id,
                    agent.id,
                    deployment_hash
                );

                // Update command status to 'sent' - separate connection
                let updated_command = db::command::update_status(
                    agent_pool.as_ref(),
                    &command.command_id,
                    &models::CommandStatus::Sent,
                )
                .await
                .map_err(|err| {
                    tracing::error!("Failed to update command status: {}", err);
                    helpers::JsonResponse::internal_server_error(err)
                })?;

                // Remove from queue - separate connection
                let _ =
                    db::command::remove_from_queue(agent_pool.as_ref(), &command.command_id).await;

                return Ok(helpers::JsonResponse::<Option<models::Command>>::build()
                    .set_item(Some(updated_command))
                    .set_meta(json!({ "next_poll_secs": interval_seconds }))
                    .ok("Command available"));
            }
            Ok(None) => {
                // No command yet, sleep WITHOUT holding DB connection
                if i < max_checks - 1 {
                    tokio::time::sleep(check_interval).await;
                }
            }
            Err(err) => {
                tracing::error!("Failed to fetch command from queue: {}", err);
                return Err(helpers::JsonResponse::internal_server_error(err));
            }
        }
    }

    // No commands available after timeout
    tracing::debug!(
        "No commands available for agent {} after {} seconds",
        agent.id,
        timeout_seconds
    );
    Ok(helpers::JsonResponse::<Option<models::Command>>::build()
        .set_item(None)
        .set_meta(json!({ "next_poll_secs": interval_seconds }))
        .ok("No command available"))
}
