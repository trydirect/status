use crate::configuration::Settings;
use crate::db;
use crate::forms::status_panel;
use crate::helpers::{
    extract_capabilities, has_capability, has_capability_value, AgentPgPool, JsonResponse,
    NPM_CREDENTIAL_SOURCE_KEY,
};
use crate::models::{Command, CommandPriority, User};
use crate::routes::command::enrich_deploy_app_with_compose;
use crate::routes::legacy_installations::{resolve_owned_deployment_by_hash, OwnedDeployment};
use actix_web::{post, web, Responder, Result};
use serde::Deserialize;
use std::sync::Arc;

const CONFIGURE_PROXY_CAPABILITY_MODE_ENV: &str = "STACKER_CONFIGURE_PROXY_CAPABILITY_MODE";
const PIPE_COMMAND_TYPES: &[&str] = &["activate_pipe", "deactivate_pipe", "trigger_pipe"];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConfigureProxyCapabilityMode {
    Warn,
    Enforce,
}

impl ConfigureProxyCapabilityMode {
    fn from_env() -> Self {
        Self::from_value(
            std::env::var(CONFIGURE_PROXY_CAPABILITY_MODE_ENV)
                .ok()
                .as_deref(),
        )
    }

    fn from_value(value: Option<&str>) -> Self {
        match value.unwrap_or("warn").trim().to_ascii_lowercase().as_str() {
            "enforce" | "true" | "1" => Self::Enforce,
            _ => Self::Warn,
        }
    }
}

fn configure_proxy_requires_vault_capability(capabilities: &[String]) -> bool {
    has_capability_value(capabilities, NPM_CREDENTIAL_SOURCE_KEY, "vault")
}

fn command_requires_pipes_capability(command_type: &str) -> bool {
    PIPE_COMMAND_TYPES.contains(&command_type)
}

#[derive(Debug, Deserialize)]
pub struct EnqueueRequest {
    pub deployment_hash: String,
    pub command_type: String,
    #[serde(default)]
    pub priority: Option<String>,
    #[serde(default)]
    pub parameters: Option<serde_json::Value>,
    #[serde(default)]
    pub timeout_seconds: Option<i32>,
}

#[tracing::instrument(name = "Agent enqueue command", skip_all)]
#[post("/commands/enqueue")]
pub async fn enqueue_handler(
    user: web::ReqData<Arc<User>>,
    payload: web::Json<EnqueueRequest>,
    agent_pool: web::Data<AgentPgPool>,
    settings: web::Data<Settings>,
) -> Result<impl Responder> {
    if payload.deployment_hash.trim().is_empty() {
        return Err(JsonResponse::<()>::build().bad_request("deployment_hash is required"));
    }

    if payload.command_type.trim().is_empty() {
        return Err(JsonResponse::<()>::build().bad_request("command_type is required"));
    }

    let owned_deployment = resolve_owned_deployment_by_hash(
        agent_pool.as_ref(),
        settings.get_ref(),
        user.as_ref(),
        &payload.deployment_hash,
    )
    .await?;
    let project_id = project_id_from_owned_deployment(&owned_deployment);

    // Validate parameters
    let validated_parameters =
        status_panel::validate_command_parameters(&payload.command_type, &payload.parameters)
            .map_err(|err| JsonResponse::<()>::build().bad_request(err))?;

    let requires_pipes_capability = command_requires_pipes_capability(&payload.command_type);

    let agent = if payload.command_type == "configure_proxy"
        || requires_pipes_capability
        || validated_parameters
            .as_ref()
            .and_then(|params| params.get("runtime"))
            .and_then(|value| value.as_str())
            == Some("kata")
    {
        db::agent::fetch_by_deployment_hash(agent_pool.as_ref(), &payload.deployment_hash)
            .await
            .map_err(|err| {
                tracing::error!("Failed to fetch agent: {}", err);
                JsonResponse::<()>::build().internal_server_error(err)
            })?
    } else {
        None
    };

    // If runtime=kata requested, verify agent supports it
    if let Some(ref params) = validated_parameters {
        if params.get("runtime").and_then(|v| v.as_str()) == Some("kata") {
            let has_kata = agent
                .as_ref()
                .map(|agent| extract_capabilities(agent.capabilities.clone()))
                .map(|capabilities| has_capability(&capabilities, "kata"))
                .unwrap_or(false);

            if !has_kata {
                return Err(JsonResponse::<()>::build().bad_request(
                    "Agent does not support Kata runtime. Check agent capabilities at GET /deployments/{hash}/capabilities"
                ));
            }
        }
    }

    if requires_pipes_capability {
        let capabilities = agent
            .as_ref()
            .map(|agent| extract_capabilities(agent.capabilities.clone()))
            .unwrap_or_default();

        if !has_capability(&capabilities, "pipes") {
            return Err(JsonResponse::<()>::build().bad_request(
                "Agent does not support pipe commands. Check agent capabilities at GET /deployments/{hash}/capabilities"
            ));
        }
    }

    if payload.command_type == "configure_proxy" {
        let capabilities = agent
            .as_ref()
            .map(|agent| extract_capabilities(agent.capabilities.clone()))
            .unwrap_or_default();

        if !configure_proxy_requires_vault_capability(&capabilities) {
            let message = "Agent does not advertise npm_credential_source=vault. Re-link the Status Panel agent or update the installer before running configure_proxy.";
            match ConfigureProxyCapabilityMode::from_env() {
                ConfigureProxyCapabilityMode::Warn => {
                    tracing::warn!(
                        deployment_hash = %payload.deployment_hash,
                        capabilities = ?capabilities,
                        "configure_proxy queued without Vault capability: {}",
                        message
                    );
                }
                ConfigureProxyCapabilityMode::Enforce => {
                    return Err(JsonResponse::<()>::build().bad_request(message));
                }
            }
        }
    }

    let final_parameters = if payload.command_type == "deploy_app" {
        enrich_deploy_app_with_compose(
            &payload.deployment_hash,
            validated_parameters,
            &settings.vault,
            agent_pool.as_ref(),
            project_id,
        )
        .await
        .map_err(|error| {
            tracing::error!(
                deployment_hash = %payload.deployment_hash,
                error = %error,
                "Failed to enrich deploy_app command before enqueue"
            );
            JsonResponse::<()>::build().internal_server_error(error)
        })?
    } else {
        validated_parameters
    };

    // Generate command ID
    let command_id = format!("cmd_{}", uuid::Uuid::new_v4());

    // Parse priority
    let priority = payload
        .priority
        .as_ref()
        .and_then(|p| match p.to_lowercase().as_str() {
            "low" => Some(CommandPriority::Low),
            "normal" => Some(CommandPriority::Normal),
            "high" => Some(CommandPriority::High),
            "critical" => Some(CommandPriority::Critical),
            _ => None,
        })
        .unwrap_or(CommandPriority::Normal);

    // Build command
    let mut command = Command::new(
        command_id.clone(),
        payload.deployment_hash.clone(),
        payload.command_type.clone(),
        user.id.clone(),
    )
    .with_priority(priority.clone());

    if let Some(params) = &final_parameters {
        command = command.with_parameters(params.clone());
    }

    if let Some(timeout) = payload.timeout_seconds {
        command = command.with_timeout(timeout);
    }

    // Insert command
    let saved = db::command::insert(agent_pool.as_ref(), &command)
        .await
        .map_err(|err| {
            tracing::error!("Failed to insert command: {}", err);
            JsonResponse::<()>::build().internal_server_error(err)
        })?;

    // Add to queue - agent will poll and pick it up
    db::command::add_to_queue(
        agent_pool.as_ref(),
        &saved.command_id,
        &saved.deployment_hash,
        &priority,
    )
    .await
    .map_err(|err| {
        tracing::error!("Failed to add command to queue: {}", err);
        JsonResponse::<()>::build().internal_server_error(err)
    })?;

    // Extract runtime for tracing
    let runtime = final_parameters
        .as_ref()
        .and_then(|p| p.get("runtime"))
        .and_then(|v| v.as_str())
        .unwrap_or("runc");

    tracing::info!(
        command_id = %saved.command_id,
        deployment_hash = %saved.deployment_hash,
        command_type = %payload.command_type,
        runtime = %runtime,
        "Command enqueued, agent will poll"
    );

    Ok(JsonResponse::build()
        .set_item(Some(saved))
        .created("Command enqueued"))
}

fn project_id_from_owned_deployment(deployment: &OwnedDeployment) -> Option<i32> {
    match deployment {
        OwnedDeployment::Native(deployment) => Some(deployment.project_id),
        OwnedDeployment::Legacy(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configure_proxy_capability_mode_defaults_to_warn() {
        assert_eq!(
            ConfigureProxyCapabilityMode::from_value(None),
            ConfigureProxyCapabilityMode::Warn
        );
    }

    #[test]
    fn configure_proxy_capability_mode_accepts_enforce_flag() {
        assert_eq!(
            ConfigureProxyCapabilityMode::from_value(Some("enforce")),
            ConfigureProxyCapabilityMode::Enforce
        );
    }

    #[test]
    fn configure_proxy_requires_vault_capability_marker() {
        assert!(configure_proxy_requires_vault_capability(&[
            "npm_credential_source=vault".to_string()
        ]));
        assert!(!configure_proxy_requires_vault_capability(&[
            "status_panel".to_string()
        ]));
    }

    #[test]
    fn pipe_commands_require_pipe_capability() {
        assert!(command_requires_pipes_capability("activate_pipe"));
        assert!(command_requires_pipes_capability("deactivate_pipe"));
        assert!(command_requires_pipes_capability("trigger_pipe"));
        assert!(!command_requires_pipes_capability("restart"));
    }

    #[test]
    fn native_owned_deployment_exposes_project_id_for_deploy_app_enrichment() {
        let deployment = crate::models::Deployment::new(
            65,
            Some("user-1".to_string()),
            "deployment_test".to_string(),
            "active".to_string(),
            "runc".to_string(),
            serde_json::json!({}),
        );

        assert_eq!(
            project_id_from_owned_deployment(&OwnedDeployment::Native(deployment)),
            Some(65)
        );
    }
}
