use crate::db;
use crate::forms::status_panel::HealthCommandReport;
use crate::helpers::{AgentPgPool, JsonResponse};
use crate::models::{Command, ProjectApp};
use crate::project_app::is_platform_managed_app_code;
use actix_web::{get, web, Responder, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Default)]
pub struct SnapshotResponse {
    pub agent: Option<AgentSnapshot>,
    pub commands: Vec<Command>,
    pub containers: Vec<ContainerSnapshot>,
    pub apps: Vec<ProjectApp>,
}

#[derive(Debug, Serialize, Default)]
pub struct AgentSnapshot {
    pub id: Option<Uuid>,
    pub version: Option<String>,
    pub capabilities: Option<serde_json::Value>,
    pub system_info: Option<serde_json::Value>,
    pub status: Option<String>,
    pub last_heartbeat: Option<chrono::DateTime<chrono::Utc>>,
    pub deployment_hash: Option<String>,
}

#[derive(Debug, Serialize, Default)]
pub struct ContainerSnapshot {
    pub id: Option<String>,
    pub app: Option<String>,
    pub state: Option<String>,
    pub image: Option<String>,
    pub name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SnapshotQuery {
    #[serde(default = "default_command_limit")]
    pub command_limit: i64,
    #[serde(default)]
    pub include_command_results: bool,
}

fn default_command_limit() -> i64 {
    50
}

fn visible_project_apps(apps: Vec<ProjectApp>) -> Vec<ProjectApp> {
    apps.into_iter()
        .filter(|app| !is_platform_managed_app_code(&app.code))
        .collect()
}

#[tracing::instrument(name = "Get deployment snapshot", skip_all)]
#[get("/deployments/{deployment_hash}")]
pub async fn snapshot_handler(
    path: web::Path<String>,
    query: web::Query<SnapshotQuery>,
    agent_pool: web::Data<AgentPgPool>,
) -> Result<impl Responder> {
    tracing::info!(
        "[SNAPSHOT HANDLER] Called for deployment_hash: {}, limit: {}, include_results: {}",
        path,
        query.command_limit,
        query.include_command_results
    );
    let deployment_hash = path.into_inner();

    // Fetch agent
    let agent = db::agent::fetch_by_deployment_hash(agent_pool.get_ref(), &deployment_hash)
        .await
        .ok()
        .flatten();

    tracing::debug!("[SNAPSHOT HANDLER] Agent : {:?}", agent);
    // Fetch recent commands with optional result exclusion to reduce payload size
    let commands = db::command::fetch_recent_by_deployment(
        agent_pool.get_ref(),
        &deployment_hash,
        query.command_limit,
        !query.include_command_results,
    )
    .await
    .unwrap_or_default();

    tracing::debug!("[SNAPSHOT HANDLER] Commands : {:?}", commands);
    // Fetch deployment to get project_id
    let deployment =
        db::deployment::fetch_by_deployment_hash(agent_pool.get_ref(), &deployment_hash)
            .await
            .ok()
            .flatten();

    tracing::debug!("[SNAPSHOT HANDLER] Deployment : {:?}", deployment);
    // Fetch apps scoped to this specific deployment (falls back to project-level if no deployment-scoped apps)
    let apps = if let Some(deployment) = &deployment {
        db::project_app::fetch_by_deployment(
            agent_pool.get_ref(),
            deployment.project_id,
            deployment.id,
        )
        .await
        .unwrap_or_default()
    } else {
        vec![]
    };
    let apps = visible_project_apps(apps);

    tracing::debug!("[SNAPSHOT HANDLER] Apps : {:?}", apps);

    // Fetch recent health commands WITH results to populate container states
    // (we always need health results for container status, even if include_command_results=false)
    let health_commands = db::command::fetch_recent_by_deployment(
        agent_pool.get_ref(),
        &deployment_hash,
        10,    // Fetch last 10 health checks
        false, // Always include results for health commands
    )
    .await
    .unwrap_or_default();

    // Extract container states from recent health check commands
    // Use a HashMap to keep only the most recent health check per app_code
    let mut container_map: std::collections::HashMap<String, ContainerSnapshot> =
        std::collections::HashMap::new();

    for cmd in health_commands.iter() {
        if cmd.r#type == "health" && cmd.status == "completed" {
            if let Some(result) = &cmd.result {
                if let Ok(health) = serde_json::from_value::<HealthCommandReport>(result.clone()) {
                    // Serialize ContainerState enum to string using serde
                    let state = serde_json::to_value(&health.container_state)
                        .ok()
                        .and_then(|v| v.as_str().map(String::from))
                        .map(|s| s.to_lowercase());

                    let container = ContainerSnapshot {
                        id: None,
                        app: Some(health.app_code.clone()),
                        state,
                        image: None,
                        name: None,
                    };

                    // Only insert if we don't have this app yet (keeps most recent due to DESC order)
                    container_map
                        .entry(health.app_code.clone())
                        .or_insert(container);
                }
            }
        }
    }

    let containers: Vec<ContainerSnapshot> = container_map.into_values().collect();

    tracing::debug!(
        "[SNAPSHOT HANDLER] Containers extracted from {} health checks: {:?}",
        health_commands.len(),
        containers
    );

    // Derive effective status: if heartbeat is stale (>5 min), override to "offline"
    let agent_snapshot = agent.map(|a| {
        let effective_status = match a.last_heartbeat {
            Some(hb) => {
                let stale_threshold = chrono::Duration::seconds(300); // 5 minutes
                if chrono::Utc::now() - hb > stale_threshold {
                    "offline".to_string()
                } else {
                    a.status.clone()
                }
            }
            None => "offline".to_string(), // Never had a heartbeat
        };
        AgentSnapshot {
            id: Some(a.id),
            version: a.version,
            capabilities: a.capabilities,
            system_info: a.system_info,
            status: Some(effective_status),
            last_heartbeat: a.last_heartbeat,
            deployment_hash: Some(a.deployment_hash),
        }
    });
    tracing::debug!("[SNAPSHOT HANDLER] Agent Snapshot : {:?}", agent_snapshot);

    let resp = SnapshotResponse {
        agent: agent_snapshot,
        commands,
        containers,
        apps,
    };

    tracing::info!("[SNAPSHOT HANDLER] Snapshot response prepared: {:?}", resp);
    Ok(JsonResponse::build()
        .set_item(resp)
        .ok("Snapshot fetched successfully"))
}

/// Returns the snapshot for the most recently active agent in a project.
/// Used by the CLI as a stable project-scoped alternative to deployment-hash lookup.
#[tracing::instrument(name = "Get project agent snapshot", skip_all)]
#[get("/project/{project_id}")]
pub async fn project_snapshot_handler(
    path: web::Path<i32>,
    agent_pool: web::Data<AgentPgPool>,
) -> Result<impl Responder> {
    let project_id = path.into_inner();

    let agent = db::agent::fetch_active_by_project(agent_pool.get_ref(), project_id)
        .await
        .ok()
        .flatten();

    let agent_snapshot = match agent {
        None => {
            return Ok(JsonResponse::build()
                .set_item(SnapshotResponse::default())
                .ok("No active agent found for project"));
        }
        Some(a) => {
            let effective_status = match a.last_heartbeat {
                Some(hb) => {
                    let stale_threshold = chrono::Duration::seconds(300);
                    if chrono::Utc::now() - hb > stale_threshold {
                        "offline".to_string()
                    } else {
                        a.status.clone()
                    }
                }
                None => "offline".to_string(),
            };
            let deployment_hash = a.deployment_hash.clone();

            let snap = AgentSnapshot {
                id: Some(a.id),
                version: a.version,
                capabilities: a.capabilities,
                system_info: a.system_info,
                status: Some(effective_status),
                last_heartbeat: a.last_heartbeat,
                deployment_hash: Some(deployment_hash.clone()),
            };
            (snap, deployment_hash)
        }
    };

    let (agent_snap, deployment_hash) = agent_snapshot;

    let commands =
        db::command::fetch_recent_by_deployment(agent_pool.get_ref(), &deployment_hash, 50, true)
            .await
            .unwrap_or_default();

    let deployment =
        db::deployment::fetch_by_deployment_hash(agent_pool.get_ref(), &deployment_hash)
            .await
            .ok()
            .flatten();

    let apps = if let Some(dep) = &deployment {
        db::project_app::fetch_by_deployment(agent_pool.get_ref(), dep.project_id, dep.id)
            .await
            .unwrap_or_default()
    } else {
        vec![]
    };
    let apps = visible_project_apps(apps);

    let health_commands =
        db::command::fetch_recent_by_deployment(agent_pool.get_ref(), &deployment_hash, 10, false)
            .await
            .unwrap_or_default();

    let mut container_map: std::collections::HashMap<String, ContainerSnapshot> =
        std::collections::HashMap::new();

    for cmd in health_commands.iter() {
        if cmd.r#type == "health" && cmd.status == "completed" {
            if let Some(result) = &cmd.result {
                if let Ok(health) = serde_json::from_value::<HealthCommandReport>(result.clone()) {
                    let state = serde_json::to_value(&health.container_state)
                        .ok()
                        .and_then(|v| v.as_str().map(String::from))
                        .map(|s| s.to_lowercase());

                    let container = ContainerSnapshot {
                        id: None,
                        app: Some(health.app_code.clone()),
                        state,
                        image: None,
                        name: None,
                    };

                    container_map
                        .entry(health.app_code.clone())
                        .or_insert(container);
                }
            }
        }
    }

    let containers: Vec<ContainerSnapshot> = container_map.into_values().collect();

    let resp = SnapshotResponse {
        agent: Some(agent_snap),
        commands,
        containers,
        apps,
    };

    Ok(JsonResponse::build()
        .set_item(resp)
        .ok("Snapshot fetched successfully"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app(code: &str) -> ProjectApp {
        ProjectApp {
            code: code.to_string(),
            ..ProjectApp::default()
        }
    }

    #[test]
    fn visible_project_apps_excludes_platform_managed_apps() {
        let apps = visible_project_apps(vec![
            app("coolify"),
            app("nginx_proxy_manager"),
            app("statuspanel"),
        ]);

        let codes = apps.iter().map(|app| app.code.as_str()).collect::<Vec<_>>();
        assert_eq!(codes, vec!["coolify"]);
    }
}
