use std::collections::HashSet;

use actix_web::{get, web, Responder, Result};
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;
use std::sync::Arc;

use crate::{
    db,
    helpers::{
        extract_capabilities, has_capability, has_capability_value, JsonResponse,
        NPM_CREDENTIAL_SOURCE_KEY,
    },
    models::Agent,
};

#[derive(Debug, Clone, Serialize, Default)]
pub struct CapabilityCommand {
    pub command_type: String,
    pub label: String,
    pub icon: String,
    pub scope: String,
    pub requires: String,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct CapabilityFeatures {
    pub kata_runtime: bool,
    pub compose: bool,
    pub backup: bool,
    pub pipes: bool,
    pub proxy_credentials_vault: bool,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct CapabilitiesResponse {
    pub deployment_hash: String,
    pub agent_id: Option<String>,
    pub status: String,
    pub last_heartbeat: Option<DateTime<Utc>>,
    pub version: Option<String>,
    pub system_info: Option<serde_json::Value>,
    pub capabilities: Vec<String>,
    pub commands: Vec<CapabilityCommand>,
    pub features: CapabilityFeatures,
}

async fn can_view_capabilities(
    pool: &PgPool,
    user: &crate::models::User,
    deployment_hash: &str,
) -> Result<bool> {
    if user.role == "agent" {
        return Ok(user.id == deployment_hash);
    }

    let deployment = db::deployment::fetch_by_deployment_hash(pool, deployment_hash)
        .await
        .map_err(|err| JsonResponse::<CapabilitiesResponse>::build().internal_server_error(err))?;

    let Some(deployment) = deployment else {
        return Ok(false);
    };

    if deployment.user_id.as_deref() == Some(&user.id) {
        return Ok(true);
    }

    Ok(
        db::project_member::fetch(pool, deployment.project_id, &user.id)
            .await
            .map_err(|err| {
                JsonResponse::<CapabilitiesResponse>::build().internal_server_error(err)
            })?
            .is_some(),
    )
}

struct CommandMetadata {
    command_type: &'static str,
    requires: &'static str,
    scope: &'static str,
    label: &'static str,
    icon: &'static str,
}

const COMMAND_CATALOG: &[CommandMetadata] = &[
    CommandMetadata {
        command_type: "restart",
        requires: "docker",
        scope: "container",
        label: "Restart",
        icon: "fas fa-redo",
    },
    CommandMetadata {
        command_type: "start",
        requires: "docker",
        scope: "container",
        label: "Start",
        icon: "fas fa-play",
    },
    CommandMetadata {
        command_type: "stop",
        requires: "docker",
        scope: "container",
        label: "Stop",
        icon: "fas fa-stop",
    },
    CommandMetadata {
        command_type: "pause",
        requires: "docker",
        scope: "container",
        label: "Pause",
        icon: "fas fa-pause",
    },
    CommandMetadata {
        command_type: "logs",
        requires: "logs",
        scope: "container",
        label: "Logs",
        icon: "fas fa-file-alt",
    },
    CommandMetadata {
        command_type: "rebuild",
        requires: "compose",
        scope: "deployment",
        label: "Rebuild Stack",
        icon: "fas fa-sync",
    },
    CommandMetadata {
        command_type: "backup",
        requires: "backup",
        scope: "deployment",
        label: "Backup",
        icon: "fas fa-download",
    },
    CommandMetadata {
        command_type: "activate_pipe",
        requires: "pipes",
        scope: "deployment",
        label: "Activate Pipe",
        icon: "fas fa-play-circle",
    },
    CommandMetadata {
        command_type: "deactivate_pipe",
        requires: "pipes",
        scope: "deployment",
        label: "Deactivate Pipe",
        icon: "fas fa-stop-circle",
    },
    CommandMetadata {
        command_type: "trigger_pipe",
        requires: "pipes",
        scope: "deployment",
        label: "Trigger Pipe",
        icon: "fas fa-bolt",
    },
];

#[tracing::instrument(name = "Get agent capabilities", skip_all)]
#[get("/{deployment_hash}/capabilities")]
pub async fn capabilities_handler(
    path: web::Path<String>,
    user: web::ReqData<Arc<crate::models::User>>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    let deployment_hash = path.into_inner();

    if !can_view_capabilities(pg_pool.get_ref(), user.as_ref(), &deployment_hash).await? {
        return Err(JsonResponse::<CapabilitiesResponse>::build().not_found("Deployment not found"));
    }

    let agent = db::agent::fetch_by_deployment_hash(pg_pool.get_ref(), &deployment_hash)
        .await
        .map_err(|err| JsonResponse::<CapabilitiesResponse>::build().internal_server_error(err))?;

    let payload = build_capabilities_payload(deployment_hash, agent);

    Ok(JsonResponse::build()
        .set_item(payload)
        .ok("Capabilities fetched successfully"))
}

fn build_capabilities_payload(
    deployment_hash: String,
    agent: Option<Agent>,
) -> CapabilitiesResponse {
    match agent {
        Some(agent) => {
            let capabilities = extract_capabilities(agent.capabilities.clone());
            let commands = filter_commands(&capabilities);
            let features = CapabilityFeatures {
                kata_runtime: has_capability(&capabilities, "kata"),
                compose: has_capability(&capabilities, "compose"),
                backup: has_capability(&capabilities, "backup"),
                pipes: has_capability(&capabilities, "pipes"),
                proxy_credentials_vault: has_capability_value(
                    &capabilities,
                    NPM_CREDENTIAL_SOURCE_KEY,
                    "vault",
                ),
            };

            CapabilitiesResponse {
                deployment_hash,
                agent_id: Some(agent.id.to_string()),
                status: agent.status,
                last_heartbeat: agent.last_heartbeat,
                version: agent.version,
                system_info: agent.system_info,
                capabilities,
                commands,
                features,
            }
        }
        None => CapabilitiesResponse {
            deployment_hash,
            status: "offline".to_string(),
            ..Default::default()
        },
    }
}

fn filter_commands(capabilities: &[String]) -> Vec<CapabilityCommand> {
    if capabilities.is_empty() {
        return Vec::new();
    }

    let capability_set: HashSet<&str> = capabilities.iter().map(|c| c.as_str()).collect();

    COMMAND_CATALOG
        .iter()
        .filter(|meta| capability_set.contains(meta.requires))
        .map(|meta| CapabilityCommand {
            command_type: meta.command_type.to_string(),
            label: meta.label.to_string(),
            icon: meta.icon.to_string(),
            scope: meta.scope.to_string(),
            requires: meta.requires.to_string(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_commands_by_capabilities() {
        let capabilities = vec![
            "docker".to_string(),
            "logs".to_string(),
            "irrelevant".to_string(),
        ];

        let commands = filter_commands(&capabilities);
        let command_types: HashSet<&str> =
            commands.iter().map(|c| c.command_type.as_str()).collect();

        assert!(command_types.contains("restart"));
        assert!(command_types.contains("logs"));
        assert!(!command_types.contains("backup"));
    }

    #[test]
    fn build_payload_handles_missing_agent() {
        let payload = build_capabilities_payload("hash".to_string(), None);
        assert_eq!(payload.status, "offline");
        assert!(payload.commands.is_empty());
    }

    #[test]
    fn build_payload_includes_agent_data() {
        let mut agent = Agent::new("hash".to_string());
        agent.status = "online".to_string();
        agent.capabilities = Some(serde_json::json!(["docker", "logs"]));

        let payload = build_capabilities_payload("hash".to_string(), Some(agent));
        assert_eq!(payload.status, "online");
        assert_eq!(payload.commands.len(), 5); // docker (4) + logs (1)
    }

    #[test]
    fn capabilities_features_include_kata() {
        let mut agent = Agent::new("hash".to_string());
        agent.capabilities = Some(serde_json::json!(["docker", "kata"]));

        let payload = build_capabilities_payload("hash".to_string(), Some(agent));
        assert!(payload.features.kata_runtime);
        assert!(!payload.features.compose);
        assert!(!payload.features.backup);
        assert!(!payload.features.pipes);
        assert!(!payload.features.proxy_credentials_vault);
    }

    #[test]
    fn capabilities_features_default_no_kata() {
        let mut agent = Agent::new("hash".to_string());
        agent.capabilities = Some(serde_json::json!(["docker", "logs"]));

        let payload = build_capabilities_payload("hash".to_string(), Some(agent));
        assert!(!payload.features.kata_runtime);
    }

    #[test]
    fn capabilities_features_offline_all_false() {
        let payload = build_capabilities_payload("hash".to_string(), None);
        assert!(!payload.features.kata_runtime);
        assert!(!payload.features.compose);
        assert!(!payload.features.backup);
        assert!(!payload.features.pipes);
        assert!(!payload.features.proxy_credentials_vault);
    }

    #[test]
    fn pipe_capabilities_surface_pipe_commands() {
        let mut agent = Agent::new("hash".to_string());
        agent.capabilities = Some(serde_json::json!(["pipes"]));

        let payload = build_capabilities_payload("hash".to_string(), Some(agent));
        let command_types: HashSet<&str> = payload
            .commands
            .iter()
            .map(|c| c.command_type.as_str())
            .collect();

        assert!(payload.features.pipes);
        assert!(command_types.contains("activate_pipe"));
        assert!(command_types.contains("deactivate_pipe"));
        assert!(command_types.contains("trigger_pipe"));
    }

    #[test]
    fn capabilities_features_include_vault_proxy_credentials() {
        let mut agent = Agent::new("hash".to_string());
        agent.capabilities = Some(serde_json::json!(["npm_credential_source=vault"]));

        let payload = build_capabilities_payload("hash".to_string(), Some(agent));
        assert!(payload.features.proxy_credentials_vault);
    }
}
