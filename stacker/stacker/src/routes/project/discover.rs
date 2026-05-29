//! Container Discovery & Import API
//!
//! Endpoints for discovering running containers and importing them into project_app table.
//! This allows users to register containers that are running but not tracked in the database.

use crate::db;
use crate::helpers::JsonResponse;
use crate::models::{self, ProjectApp};
use crate::project_app::{is_platform_managed_app_code, normalize_app_code};
use actix_web::{get, post, web, Responder, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::PgPool;
use std::sync::Arc;

const BLOCKED_SYSTEM_CONTAINERS: [&str; 6] = [
    "nginx_proxy_manager",
    "status",
    "status_agent",
    "statuspanel",
    "statuspanel_agent",
    "telegraf",
];

/// Discovered container that's not registered in project_app
#[derive(Debug, Serialize, Clone)]
pub struct DiscoveredContainer {
    /// Actual Docker container name
    pub container_name: String,
    /// Docker image
    pub image: String,
    /// Container status (running, stopped, etc.)
    pub status: String,
    /// Suggested app_code based on container name heuristics
    pub suggested_code: String,
    /// Suggested display name
    pub suggested_name: String,
}

/// Response for container discovery endpoint
#[derive(Debug, Serialize, Default)]
pub struct DiscoverResponse {
    /// Containers that are registered in project_app
    pub registered: Vec<RegisteredContainerInfo>,
    /// Containers running but not in database
    pub unregistered: Vec<DiscoveredContainer>,
    /// Registered apps with no matching running container
    pub missing_containers: Vec<MissingContainerInfo>,
}

#[derive(Debug, Serialize)]
pub struct RegisteredContainerInfo {
    pub app_code: String,
    pub app_name: String,
    pub container_name: String,
    pub status: String,
}

#[derive(Debug, Serialize)]
pub struct MissingContainerInfo {
    pub app_code: String,
    pub app_name: String,
    pub expected_pattern: String,
}

/// Request to import discovered containers
#[derive(Debug, Deserialize)]
pub struct ImportContainersRequest {
    pub containers: Vec<ContainerImport>,
}

#[derive(Debug, Deserialize)]
pub struct ContainerImport {
    /// Actual Docker container name
    pub container_name: String,
    /// App code to assign (user can override suggested)
    pub app_code: String,
    /// Display name
    pub name: String,
    /// Docker image
    pub image: String,
}

/// Discover running containers for a deployment
///
/// This endpoint compares running Docker containers (from recent health checks)
/// with registered project_app records to identify:
/// - Registered apps with running containers (synced)
/// - Running containers not in database (unregistered, can be imported)
/// - Database apps with no running container (stopped or name mismatch)
#[tracing::instrument(name = "Discover containers", skip_all)]
#[get("/{project_id}/containers/discover")]
pub async fn discover_containers(
    user: web::ReqData<Arc<models::User>>,
    path: web::Path<i32>,
    query: web::Query<DiscoverQuery>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    let project_id = path.into_inner();

    // Verify project ownership
    let project = db::project::fetch(pg_pool.get_ref(), project_id)
        .await
        .map_err(|e| JsonResponse::internal_server_error(e))?
        .ok_or_else(|| JsonResponse::not_found("Project not found"))?;

    if project.user_id != user.id {
        return Err(JsonResponse::not_found("Project not found"));
    }

    // Get deployment_hash from query, the active project agent, or the latest
    // deployment record. Active agent state is preferred because command
    // history is keyed by the hash currently heartbeating, while the latest
    // deployment row may be newer and still lack command results.
    let deployment_hash = match &query.deployment_hash {
        Some(hash) => hash.clone(),
        None => {
            if let Some(agent) = db::agent::fetch_active_by_project(pg_pool.get_ref(), project_id)
                .await
                .map_err(|e| JsonResponse::internal_server_error(e))?
            {
                agent.deployment_hash
            } else {
                let deployment = db::deployment::fetch_by_project_id(pg_pool.get_ref(), project_id)
                    .await
                    .map_err(|e| JsonResponse::internal_server_error(e))?;

                deployment.map(|d| d.deployment_hash).ok_or_else(|| {
                    JsonResponse::not_found(
                        "No deployment found for project. Please provide deployment_hash",
                    )
                })?
            }
        }
    };

    // Fetch all apps registered in this project
    let registered_apps = db::project_app::fetch_by_project(pg_pool.get_ref(), project_id)
        .await
        .map_err(|e| JsonResponse::internal_server_error(e))?;

    // Fetch recent list_containers commands to get ALL running containers
    let container_commands = db::command::fetch_recent_by_deployment(
        pg_pool.get_ref(),
        &deployment_hash,
        50,    // Last 50 commands to find list_containers results
        false, // Include results
    )
    .await
    .unwrap_or_default();

    // Extract running containers from list_containers or health commands
    let mut running_containers: Vec<ContainerInfo> = Vec::new();

    // First, try to find a list_containers result (has ALL containers)
    for cmd in container_commands.iter() {
        if cmd.r#type == "list_containers" && cmd.status == "completed" {
            if let Some(result) = &cmd.result {
                // Parse list_containers result which contains array of all containers
                if let Some(containers_arr) = result.get("containers").and_then(|c| c.as_array()) {
                    for c in containers_arr {
                        let name = c
                            .get("name")
                            .and_then(|n| n.as_str())
                            .unwrap_or("")
                            .to_string();
                        if name.is_empty() {
                            continue;
                        }
                        let status = c
                            .get("status")
                            .and_then(|s| s.as_str())
                            .unwrap_or("unknown")
                            .to_string();
                        let image = c
                            .get("image")
                            .and_then(|i| i.as_str())
                            .unwrap_or("")
                            .to_string();

                        if !running_containers.iter().any(|rc| rc.name == name) {
                            running_containers.push(ContainerInfo {
                                name: name.clone(),
                                image,
                                status,
                                app_code: None, // Will be matched later
                            });
                        }
                    }
                }
            }
            // Found list_containers result, prefer this over health checks
            if !running_containers.is_empty() {
                break;
            }
        }
    }

    // Fallback: If no list_containers found, try health check results
    if running_containers.is_empty() {
        for cmd in container_commands.iter() {
            if cmd.r#type == "health" && cmd.status == "completed" {
                if let Some(result) = &cmd.result {
                    // Try to extract from system_containers array first
                    if let Some(system_arr) =
                        result.get("system_containers").and_then(|c| c.as_array())
                    {
                        for c in system_arr {
                            let name = c
                                .get("container_name")
                                .or_else(|| c.get("app_code"))
                                .and_then(|n| n.as_str())
                                .unwrap_or("")
                                .to_string();
                            if name.is_empty() {
                                continue;
                            }
                            let status = c
                                .get("container_state")
                                .or_else(|| c.get("status"))
                                .and_then(|s| s.as_str())
                                .unwrap_or("unknown")
                                .to_string();

                            if !running_containers.iter().any(|rc| rc.name == name) {
                                running_containers.push(ContainerInfo {
                                    name: name.clone(),
                                    image: String::new(),
                                    status,
                                    app_code: c
                                        .get("app_code")
                                        .and_then(|a| a.as_str())
                                        .map(|s| s.to_string()),
                                });
                            }
                        }
                    }

                    // Also try app_code from single-app health checks
                    if let Some(app_code) = result.get("app_code").and_then(|a| a.as_str()) {
                        let status = result
                            .get("container_state")
                            .and_then(|s| s.as_str())
                            .unwrap_or("unknown")
                            .to_string();

                        if !running_containers.iter().any(|c| c.name == app_code) {
                            running_containers.push(ContainerInfo {
                                name: app_code.to_string(),
                                image: String::new(),
                                status,
                                app_code: Some(app_code.to_string()),
                            });
                        }
                    }
                }
            }
        }
    }

    tracing::info!(
        project_id = project_id,
        deployment_hash = %deployment_hash,
        registered_count = registered_apps.len(),
        running_count = running_containers.len(),
        "Discovered containers"
    );

    // Exclude system containers from discovery/import candidates
    running_containers.retain(|container| {
        !is_blocked_system_container(
            &container.name,
            &container.image,
            container.app_code.as_deref(),
        )
    });

    // Classify containers
    let mut registered = Vec::new();
    let mut unregistered = Vec::new();
    let mut missing_containers = Vec::new();

    // Find registered apps with running containers
    for app in &registered_apps {
        let matching_container = running_containers.iter().find(|c| {
            // Try to match by app_code first
            c.app_code.as_ref() == Some(&app.code) ||
                // Or by container name matching app code
                container_matches_app(&c.name, &app.code)
        });

        if let Some(container) = matching_container {
            registered.push(RegisteredContainerInfo {
                app_code: app.code.clone(),
                app_name: app.name.clone(),
                container_name: container.name.clone(),
                status: container.status.clone(),
            });
        } else {
            // App exists but no container found
            missing_containers.push(MissingContainerInfo {
                app_code: app.code.clone(),
                app_name: app.name.clone(),
                expected_pattern: app.code.clone(),
            });
        }
    }

    // Find running containers not registered
    for container in &running_containers {
        let is_registered = registered_apps.iter().any(|app| {
            app.code == container.app_code.clone().unwrap_or_default()
                || container_matches_app(&container.name, &app.code)
        });

        if !is_registered {
            let (suggested_code, suggested_name) =
                suggest_app_info(&container.name, &container.image);

            unregistered.push(DiscoveredContainer {
                container_name: container.name.clone(),
                image: container.image.clone(),
                status: container.status.clone(),
                suggested_code,
                suggested_name,
            });
        }
    }

    let response = DiscoverResponse {
        registered,
        unregistered,
        missing_containers,
    };

    tracing::info!(
        project_id = project_id,
        registered = response.registered.len(),
        unregistered = response.unregistered.len(),
        missing = response.missing_containers.len(),
        "Container discovery complete"
    );

    Ok(JsonResponse::build()
        .set_item(response)
        .ok("Containers discovered"))
}

/// Import unregistered containers into project_app
#[tracing::instrument(name = "Import containers", skip_all)]
#[post("/{project_id}/containers/import")]
pub async fn import_containers(
    user: web::ReqData<Arc<models::User>>,
    path: web::Path<i32>,
    body: web::Json<ImportContainersRequest>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    let project_id = path.into_inner();

    // Verify project ownership
    let project = db::project::fetch(pg_pool.get_ref(), project_id)
        .await
        .map_err(|e| JsonResponse::internal_server_error(e))?
        .ok_or_else(|| JsonResponse::not_found("Project not found"))?;

    if project.user_id != user.id {
        return Err(JsonResponse::not_found("Project not found"));
    }

    let mut imported = Vec::new();
    let mut errors = Vec::new();

    for container in &body.containers {
        if is_blocked_system_container(
            &container.container_name,
            &container.image,
            Some(&container.app_code),
        ) {
            errors.push(format!(
                "Container '{}' is a system container and cannot be imported",
                container.container_name
            ));
            continue;
        }

        // Check if app_code already exists
        let existing = db::project_app::fetch_by_project_and_code(
            pg_pool.get_ref(),
            project_id,
            &container.app_code,
        )
        .await
        .ok()
        .flatten();

        if existing.is_some() {
            errors.push(format!(
                "App code '{}' already exists in project",
                container.app_code
            ));
            continue;
        }

        // Create new project_app entry
        let app = ProjectApp {
            id: 0, // Will be set by database
            project_id,
            code: container.app_code.clone(),
            name: container.name.clone(),
            image: container.image.clone(),
            environment: Some(json!({})),
            ports: Some(json!([])),
            volumes: Some(json!([])),
            domain: None,
            ssl_enabled: Some(false),
            resources: Some(json!({})),
            restart_policy: Some("unless-stopped".to_string()),
            command: None,
            entrypoint: None,
            networks: Some(json!([])),
            depends_on: Some(json!([])),
            healthcheck: Some(json!({})),
            labels: Some(json!({})),
            config_files: Some(json!([])),
            template_source: None,
            enabled: Some(true),
            deploy_order: Some(100), // Default order
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            config_version: Some(1),
            vault_synced_at: None,
            vault_sync_version: None,
            config_hash: None,
            parent_app_code: None,
            deployment_id: None,
        };

        match db::project_app::insert(pg_pool.get_ref(), &app).await {
            Ok(created) => {
                imported.push(json!({
                    "code": created.code,
                    "name": created.name,
                    "container_name": container.container_name,
                }));

                tracing::info!(
                    user_id = %user.id,
                    project_id = project_id,
                    app_code = %created.code,
                    container_name = %container.container_name,
                    "Imported container"
                );
            }
            Err(e) => {
                let error_msg = format!("Failed to import '{}': {}", container.app_code, e);
                errors.push(error_msg);
            }
        }
    }

    Ok(JsonResponse::build()
        .set_item(Some(json!({
            "imported": imported,
            "errors": errors,
            "success_count": imported.len(),
            "error_count": errors.len(),
        })))
        .ok("Import complete"))
}

// Helper structs

#[derive(Debug, Deserialize)]
pub struct DiscoverQuery {
    pub deployment_hash: Option<String>,
}

#[derive(Debug)]
struct ContainerInfo {
    name: String,
    image: String,
    status: String,
    app_code: Option<String>,
}

// Helper functions

/// Check if a container name matches an app code
fn container_matches_app(container_name: &str, app_code: &str) -> bool {
    // Exact match
    if container_name == app_code {
        return true;
    }

    // Container ends with app_code (e.g., "statuspanel_agent" matches "agent")
    if container_name.ends_with(app_code) {
        return true;
    }

    // Container is {app_code}_{number} or {app_code}-{number}
    if container_name.starts_with(app_code) {
        let suffix = &container_name[app_code.len()..];
        if suffix.starts_with('_') || suffix.starts_with('-') {
            if let Some(rest) = suffix.get(1..) {
                if rest.chars().all(|c| c.is_numeric()) {
                    return true;
                }
            }
        }
    }

    // Container is {project}-{app_code}-{number}
    let parts: Vec<&str> = container_name.split('-').collect();
    if parts.len() >= 2 && parts[parts.len() - 2] == app_code {
        return true;
    }

    false
}

/// Suggest app_code and name from container name and image
fn suggest_app_info(container_name: &str, image: &str) -> (String, String) {
    // Try to extract service name from Docker Compose pattern: {project}_{service}_{replica}
    if let Some(parts) = extract_compose_service(container_name) {
        let code = parts.service.to_string();
        let name = capitalize(&code);
        return (code, name);
    }

    // Try to extract from project-service-replica pattern
    let parts: Vec<&str> = container_name.split('-').collect();
    if parts.len() >= 2 {
        let service = parts[parts.len() - 2];
        if !service.chars().all(|c| c.is_numeric()) {
            return (service.to_string(), capitalize(service));
        }
    }

    // Extract from image name (last part before tag)
    if let Some(img_name) = image.split('/').last() {
        if let Some(name_without_tag) = img_name.split(':').next() {
            return (name_without_tag.to_string(), capitalize(name_without_tag));
        }
    }

    // Fallback: use container name
    (container_name.to_string(), capitalize(container_name))
}

struct ComposeServiceParts {
    service: String,
}

fn extract_compose_service(container_name: &str) -> Option<ComposeServiceParts> {
    let parts: Vec<&str> = container_name.split('_').collect();
    if parts.len() >= 2 {
        // Last part should be replica number
        if parts.last()?.chars().all(|c| c.is_numeric()) {
            // Service is second to last
            let service = parts[parts.len() - 2].to_string();
            return Some(ComposeServiceParts { service });
        }
    }
    None
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().chain(c).collect(),
    }
}

fn is_blocked_system_container(container_name: &str, image: &str, app_code: Option<&str>) -> bool {
    let mut candidates: Vec<String> = vec![normalize_app_code(container_name)];

    if let Some(code) = app_code {
        candidates.push(normalize_app_code(code));
    }

    if let Some(compose_parts) = extract_compose_service(container_name) {
        candidates.push(normalize_app_code(&compose_parts.service));
    }

    if let Some(img_name) = image.split('/').last() {
        if let Some(name_without_tag) = img_name.split(':').next() {
            candidates.push(normalize_app_code(name_without_tag));
        }
    }

    candidates.iter().any(|candidate| {
        BLOCKED_SYSTEM_CONTAINERS.contains(&candidate.as_str())
            || is_platform_managed_app_code(candidate)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_platform_managed_nginx_proxy_manager_container() {
        assert!(is_blocked_system_container(
            "nginx-proxy-manager",
            "jc21/nginx-proxy-manager:latest",
            None,
        ));
        assert!(is_blocked_system_container(
            "project-nginx_proxy_manager-1",
            "jc21/nginx-proxy-manager:latest",
            Some("nginx_proxy_manager"),
        ));
    }

    #[test]
    fn does_not_block_regular_application_container() {
        assert!(!is_blocked_system_container(
            "project-coolify-1",
            "coollabsio/coolify:latest",
            Some("coolify"),
        ));
    }
}
