use crate::configuration::Settings;
use crate::db;
use crate::forms::status_panel;
use crate::helpers::project::builder::parse_compose_services;
use crate::helpers::JsonResponse;
use crate::models::{Command, CommandPriority, User};
use crate::project_app::{
    is_platform_managed_app_code, normalize_app_code, parse_registry_auth_config,
    store_configs_to_vault_from_params, store_registry_auth_command_to_vault,
    upsert_app_config_for_deploy, REGISTRY_AUTH_VAULT_KEY,
};
use crate::services::env_model::reconcile_env_file_content;
use crate::services::{AppConfig, ConfigRenderer, ProjectAppService, VaultService};
use actix_web::{post, web, Responder, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::PgPool;
use std::collections::HashSet;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct CreateCommandRequest {
    pub deployment_hash: String,
    pub command_type: String,
    #[serde(default)]
    pub priority: Option<String>,
    #[serde(default)]
    pub parameters: Option<serde_json::Value>,
    #[serde(default)]
    pub timeout_seconds: Option<i32>,
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Default)]
pub struct CreateCommandResponse {
    pub command_id: String,
    pub deployment_hash: String,
    pub status: String,
}

#[tracing::instrument(name = "Create command", skip_all)]
#[post("")]
pub async fn create_handler(
    user: web::ReqData<Arc<User>>,
    req: web::Json<CreateCommandRequest>,
    pg_pool: web::Data<PgPool>,
    settings: web::Data<Settings>,
) -> Result<impl Responder> {
    tracing::info!(
        "[CREATE COMMAND HANDLER] User: {}, Deployment: {}, Command Type: {}",
        user.id,
        req.deployment_hash,
        req.command_type
    );
    if req.deployment_hash.trim().is_empty() {
        return Err(JsonResponse::<()>::build().bad_request("deployment_hash is required"));
    }

    if req.command_type.trim().is_empty() {
        return Err(JsonResponse::<()>::build().bad_request("command_type is required"));
    }

    let validated_parameters =
        status_panel::validate_command_parameters(&req.command_type, &req.parameters).map_err(
            |err| {
                tracing::warn!("Invalid command payload: {}", err);
                JsonResponse::<()>::build().bad_request(err)
            },
        )?;

    // For deploy_app commands, upsert app config and sync to Vault before enriching parameters
    let final_parameters = if req.command_type == "deploy_app" {
        if let Some(registry_auth) = extract_registry_auth_from_params(&validated_parameters) {
            store_registry_auth_command_to_vault(
                &req.deployment_hash,
                &registry_auth,
                &settings.vault,
            )
            .await;
        }

        // Try to get deployment_id from parameters, or look it up by deployment_hash
        // If no deployment exists, auto-create project and deployment records
        let deployment_id = match req
            .parameters
            .as_ref()
            .and_then(|p| p.get("deployment_id"))
            .and_then(|v| v.as_i64())
            .map(|v| v as i32)
        {
            Some(id) => Some(id),
            None => {
                // Auto-lookup project_id from deployment_hash
                match crate::db::deployment::fetch_by_deployment_hash(
                    pg_pool.get_ref(),
                    &req.deployment_hash,
                )
                .await
                {
                    Ok(Some(deployment)) => {
                        tracing::debug!(
                            "Auto-resolved project_id {} from deployment_hash {}",
                            deployment.project_id,
                            &req.deployment_hash
                        );
                        Some(deployment.project_id)
                    }
                    Ok(None) => {
                        // No deployment found - auto-create project and deployment
                        tracing::info!(
                            "No deployment found for hash {}, auto-creating project and deployment",
                            &req.deployment_hash
                        );

                        // Get app_code to use as project name
                        let app_code_for_name = req
                            .parameters
                            .as_ref()
                            .and_then(|p| p.get("app_code"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("project");

                        // Create project
                        let project = crate::models::Project::new(
                            user.id.clone(),
                            app_code_for_name.to_string(),
                            serde_json::json!({"auto_created": true, "deployment_hash": &req.deployment_hash}),
                            req.parameters.clone().unwrap_or(serde_json::json!({})),
                        );

                        match crate::db::project::insert(pg_pool.get_ref(), project).await {
                            Ok(created_project) => {
                                tracing::info!(
                                    "Auto-created project {} (id={}) for deployment_hash {}",
                                    created_project.name,
                                    created_project.id,
                                    &req.deployment_hash
                                );

                                // Create deployment linked to this project
                                let deployment = crate::models::Deployment::new(
                                    created_project.id,
                                    Some(user.id.clone()),
                                    req.deployment_hash.clone(),
                                    "pending".to_string(),
                                    "runc".to_string(),
                                    serde_json::json!({"auto_created": true}),
                                );

                                match crate::db::deployment::insert(pg_pool.get_ref(), deployment)
                                    .await
                                {
                                    Ok(created_deployment) => {
                                        tracing::info!(
                                            "Auto-created deployment (id={}) linked to project {}",
                                            created_deployment.id,
                                            created_project.id
                                        );
                                        Some(created_project.id)
                                    }
                                    Err(e) => {
                                        tracing::warn!("Failed to auto-create deployment: {}", e);
                                        // Project was created, return its ID anyway
                                        Some(created_project.id)
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::warn!("Failed to auto-create project: {}", e);
                                None
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to lookup deployment by hash: {}", e);
                        None
                    }
                }
            }
        };

        let app_code = req
            .parameters
            .as_ref()
            .and_then(|p| p.get("app_code"))
            .and_then(|v| v.as_str());
        let app_params = req.parameters.as_ref().and_then(|p| p.get("parameters"));

        tracing::info!(
            "[DEPLOY_APP] deployment_id: {:?}, app_code: {:?}, has_app_params: {}, has_parameters: {}",
            deployment_id,
            app_code,
            app_params.is_some(),
            req.parameters.is_some()
        );

        if let Some(params) = app_params.or(req.parameters.as_ref()) {
            tracing::info!(
                "[DEPLOY_APP] Parameters contain - env: {}, config_files: {}, image: {}",
                params
                    .get("env")
                    .and_then(|v| v.as_object())
                    .map(|env| format!("{} keys", env.len()))
                    .unwrap_or_else(|| "None".to_string()),
                params
                    .get("config_files")
                    .map(|v| format!("{} files", v.as_array().map(|a| a.len()).unwrap_or(0)))
                    .unwrap_or_else(|| "None".to_string()),
                params
                    .get("image")
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "None".to_string())
            );
        }

        tracing::debug!(
            "deploy_app command detected, upserting app config for deployment_id: {:?}, app_code: {:?}",
            deployment_id,
            app_code
        );
        if let (Some(deployment_id), Some(app_code), Some(app_params)) =
            (deployment_id, app_code, app_params)
        {
            upsert_app_config_for_deploy(
                pg_pool.get_ref(),
                deployment_id,
                app_code,
                app_params,
                &req.deployment_hash,
            )
            .await;
        } else if let (Some(deployment_id), Some(app_code)) = (deployment_id, app_code) {
            // Have deployment_id and app_code but no nested parameters - use top-level parameters
            if let Some(params) = req.parameters.as_ref() {
                upsert_app_config_for_deploy(
                    pg_pool.get_ref(),
                    deployment_id,
                    app_code,
                    params,
                    &req.deployment_hash,
                )
                .await;
            }
        } else if let Some(app_code) = app_code {
            // No deployment_id available (auto-create failed), just store to Vault
            if let Some(params) = req.parameters.as_ref() {
                store_configs_to_vault_from_params(
                    params,
                    &req.deployment_hash,
                    app_code,
                    &settings.vault,
                    &settings.deployment,
                )
                .await;
            }
        } else {
            tracing::warn!("Missing app_code in deploy_app arguments");
        }

        let enriched_params = enrich_deploy_app_with_compose(
            &req.deployment_hash,
            validated_parameters,
            &settings.vault,
            pg_pool.get_ref(),
            deployment_id,
        )
        .await
        .map_err(|error| {
            tracing::error!(
                deployment_hash = %req.deployment_hash,
                error = %error,
                "Failed to enrich deploy_app command"
            );
            JsonResponse::<()>::build().internal_server_error(error)
        })?;

        // Auto-discover child services from multi-service compose files
        if let (Some(project_id), Some(app_code)) = (deployment_id, app_code) {
            if let Some(compose_content) = enriched_params
                .as_ref()
                .and_then(|p| p.get("compose_content"))
                .and_then(|c| c.as_str())
            {
                discover_and_register_child_services(
                    pg_pool.get_ref(),
                    project_id,
                    app_code,
                    compose_content,
                    &req.deployment_hash,
                )
                .await;
            }
        }

        enriched_params
    } else {
        validated_parameters
    };

    // Generate unique command ID
    let command_id = format!("cmd_{}", uuid::Uuid::new_v4());

    // Parse priority or default to Normal
    let priority = req
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
        req.deployment_hash.clone(),
        req.command_type.clone(),
        user.id.clone(),
    )
    .with_priority(priority.clone());

    if let Some(params) = &final_parameters {
        command = command.with_parameters(params.clone());
    }

    if let Some(timeout) = req.timeout_seconds {
        command = command.with_timeout(timeout);
    }

    if let Some(metadata) = &req.metadata {
        command = command.with_metadata(metadata.clone());
    }

    // Insert command into database
    let saved_command = db::command::insert(pg_pool.get_ref(), &command)
        .await
        .map_err(|err| {
            tracing::error!("Failed to create command: {}", err);
            JsonResponse::<()>::build().internal_server_error(err)
        })?;

    // Add to queue - agent will poll and pick it up
    db::command::add_to_queue(
        pg_pool.get_ref(),
        &saved_command.command_id,
        &saved_command.deployment_hash,
        &priority,
    )
    .await
    .map_err(|err| {
        tracing::error!("Failed to add command to queue: {}", err);
        JsonResponse::<()>::build().internal_server_error(err)
    })?;

    tracing::info!(
        command_id = %saved_command.command_id,
        deployment_hash = %saved_command.deployment_hash,
        "Command created and queued, agent will poll"
    );

    let response = CreateCommandResponse {
        command_id: saved_command.command_id,
        deployment_hash: saved_command.deployment_hash,
        status: saved_command.status,
    };

    Ok(JsonResponse::build()
        .set_item(Some(response))
        .created("Command created successfully"))
}

fn extract_registry_auth_from_params(
    params: &Option<serde_json::Value>,
) -> Option<status_panel::RegistryAuthCommandRequest> {
    let value = params.as_ref()?.get("registry_auth")?.clone();
    serde_json::from_value(value).ok()
}

/// Enrich deploy_app command parameters with compose_content and config_files from Vault
/// Falls back to fetching templates from Install Service if not in Vault
/// If compose_content is already provided in the request, keep it as-is
pub(crate) async fn enrich_deploy_app_with_compose(
    deployment_hash: &str,
    params: Option<serde_json::Value>,
    vault_settings: &crate::configuration::VaultSettings,
    pg_pool: &PgPool,
    project_id: Option<i32>,
) -> Result<Option<serde_json::Value>, String> {
    let mut params = params.unwrap_or_else(|| json!({}));

    // Get app_code from parameters - compose is stored under app_code key in Vault
    // Clone to avoid borrowing params while we need to mutate it later
    let app_code = params
        .get("app_code")
        .and_then(|v| v.as_str())
        .unwrap_or("_compose")
        .to_string();

    // Initialize Vault client
    let vault = match VaultService::from_settings(vault_settings) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                "Failed to initialize Vault: {}, cannot enrich deploy_app",
                e
            );
            return Ok(Some(params));
        }
    };

    if params.get("registry_auth").is_none() {
        match vault
            .fetch_app_config(deployment_hash, REGISTRY_AUTH_VAULT_KEY)
            .await
        {
            Ok(registry_config) => match parse_registry_auth_config(&registry_config) {
                Ok(registry_auth) => {
                    tracing::info!(
                        deployment_hash = %deployment_hash,
                        "Enriched deploy_app command with stored registry auth"
                    );
                    if let Some(obj) = params.as_object_mut() {
                        obj.insert("registry_auth".to_string(), json!(registry_auth));
                    }
                }
                Err(error) => {
                    tracing::warn!(
                        deployment_hash = %deployment_hash,
                        error = %error,
                        "Failed to parse stored registry auth from Vault"
                    );
                }
            },
            Err(crate::services::vault_service::VaultError::NotFound(_)) => {
                tracing::debug!(
                    deployment_hash = %deployment_hash,
                    "No stored registry auth found for deploy_app enrichment"
                );
            }
            Err(error) => {
                tracing::warn!(
                    deployment_hash = %deployment_hash,
                    error = %error,
                    "Failed to fetch registry auth from Vault during deploy_app enrichment"
                );
            }
        }
    }

    // If compose_content is not already provided, fetch from Vault
    if params
        .get("compose_content")
        .and_then(|v| v.as_str())
        .is_none()
    {
        tracing::debug!(
            deployment_hash = %deployment_hash,
            app_code = %app_code,
            "Looking up compose content in Vault"
        );

        if let Some(rendered_compose) =
            render_project_compose_for_deploy_app(pg_pool, project_id, deployment_hash, &app_code)
                .await
        {
            tracing::info!(
                deployment_hash = %deployment_hash,
                app_code = %app_code,
                "Enriched deploy_app command with freshly rendered project compose"
            );
            if let Some(obj) = params.as_object_mut() {
                obj.insert("compose_content".to_string(), json!(rendered_compose));
            }
        } else if let Ok(compose_config) = vault.fetch_app_config(deployment_hash, &app_code).await
        {
            tracing::info!(
                deployment_hash = %deployment_hash,
                app_code = %app_code,
                "Enriched deploy_app command with app compose_content from Vault"
            );
            if let Some(obj) = params.as_object_mut() {
                obj.insert("compose_content".to_string(), json!(compose_config.content));
            }
        } else {
            // Fallback to the deployment-level compose generated during full sync.
            match vault.fetch_app_config(deployment_hash, "_compose").await {
                Ok(compose_config) => {
                    tracing::info!(
                        deployment_hash = %deployment_hash,
                        "Enriched deploy_app command with deployment compose_content from Vault"
                    );
                    if let Some(obj) = params.as_object_mut() {
                        obj.insert("compose_content".to_string(), json!(compose_config.content));
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        deployment_hash = %deployment_hash,
                        app_code = %app_code,
                        error = %e,
                        "Failed to fetch compose from Vault, deploy_app may fail if compose not on disk"
                    );
                }
            }
        }
    } else {
        tracing::debug!("deploy_app already has compose_content, skipping Vault fetch");
    }

    // Collect config files from Vault (bundled configs, legacy single config, and .env files)
    let mut config_files: Vec<serde_json::Value> = Vec::new();

    // If config_files already provided, use them
    if let Some(existing_configs) = params.get("config_files").and_then(|v| v.as_array()) {
        config_files.extend(existing_configs.iter().cloned());
    }

    // Try to fetch bundled config files from Vault (new format: "{app_code}_configs")
    let configs_key = format!("{}_configs", app_code);
    tracing::debug!(
        deployment_hash = %deployment_hash,
        configs_key = %configs_key,
        "Looking up bundled config files in Vault"
    );

    match vault.fetch_app_config(deployment_hash, &configs_key).await {
        Ok(bundle_config) => {
            // Parse the JSON array of configs
            if let Ok(configs_array) =
                serde_json::from_str::<Vec<serde_json::Value>>(&bundle_config.content)
            {
                tracing::info!(
                    deployment_hash = %deployment_hash,
                    app_code = %app_code,
                    config_count = configs_array.len(),
                    "Found bundled config files in Vault"
                );
                config_files.extend(configs_array);
            } else {
                tracing::warn!(
                    deployment_hash = %deployment_hash,
                    app_code = %app_code,
                    "Failed to parse bundled config files from Vault"
                );
            }
        }
        Err(_) => {
            // Fall back to legacy single config format ("{app_code}_config")
            let config_key = format!("{}_config", app_code);
            tracing::debug!(
                deployment_hash = %deployment_hash,
                config_key = %config_key,
                "Looking up legacy single config file in Vault"
            );

            match vault.fetch_app_config(deployment_hash, &config_key).await {
                Ok(app_config) => {
                    tracing::info!(
                        deployment_hash = %deployment_hash,
                        app_code = %app_code,
                        destination = %app_config.destination_path,
                        "Found app config file in Vault"
                    );
                    // Convert AppConfig to the format expected by status panel
                    let config_file = json!({
                        "content": app_config.content,
                        "content_type": app_config.content_type,
                        "destination_path": app_config.destination_path,
                        "file_mode": app_config.file_mode,
                        "owner": app_config.owner,
                        "group": app_config.group,
                    });
                    config_files.push(config_file);
                }
                Err(e) => {
                    tracing::debug!(
                        deployment_hash = %deployment_hash,
                        config_key = %config_key,
                        error = %e,
                        "No app config found in Vault (this is normal for apps without config files)"
                    );
                }
            }
        }
    }

    // Also fetch .env file from Vault (stored under "{app_code}_env" key)
    let env_key = format!("{}_env", app_code);
    let force_config_overwrite = params
        .get("force_config_overwrite")
        .or_else(|| params.get("force_recreate"))
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    tracing::debug!(
        deployment_hash = %deployment_hash,
        env_key = %env_key,
        "Looking up .env file in Vault"
    );

    if let Some((env_config, _config_hash)) = render_project_env_for_deploy_app(
        pg_pool,
        project_id,
        deployment_hash,
        &app_code,
        vault_settings,
    )
    .await?
    {
        tracing::info!(
            deployment_hash = %deployment_hash,
            app_code = %app_code,
            destination = %env_config.destination_path,
            "Enriched deploy_app command with freshly rendered runtime env"
        );
        let merged_into_bundle = merge_rendered_env_into_app_env_files(
            &mut config_files,
            params
                .get("compose_content")
                .and_then(|value| value.as_str()),
            &app_code,
            &env_config.content,
        );
        if merged_into_bundle > 0 {
            tracing::info!(
                deployment_hash = %deployment_hash,
                app_code = %app_code,
                merged_file_count = merged_into_bundle,
                "Merged rendered runtime env into deploy_app config bundle env files"
            );
        }

        let env_file = json!({
            "content": env_config.content,
            "content_type": env_config.content_type,
            "destination_path": env_config.destination_path,
            "file_mode": env_config.file_mode,
            "owner": env_config.owner,
            "group": env_config.group,
            "force_overwrite": force_config_overwrite,
            "drift_check": {
                "enabled": true,
                "hash_source": "stacker-render-header"
            },
        });
        config_files.push(env_file);
    } else {
        match vault.fetch_app_config(deployment_hash, &env_key).await {
            Ok(env_config) => {
                tracing::info!(
                    deployment_hash = %deployment_hash,
                    app_code = %app_code,
                    destination = %env_config.destination_path,
                    "Found .env file in Vault"
                );
                // Convert AppConfig to the format expected by status panel
                let env_file = json!({
                    "content": env_config.content,
                    "content_type": env_config.content_type,
                    "destination_path": env_config.destination_path,
                    "file_mode": env_config.file_mode,
                    "owner": env_config.owner,
                    "group": env_config.group,
                    "force_overwrite": force_config_overwrite,
                    "drift_check": {
                        "enabled": true,
                        "hash_source": "stacker-render-header"
                    },
                });
                config_files.push(env_file);
            }
            Err(e) => {
                tracing::debug!(
                    deployment_hash = %deployment_hash,
                    env_key = %env_key,
                    error = %e,
                    "No .env file found in Vault (this is normal for apps without environment config)"
                );
            }
        }
    }

    // Insert config_files into params if we found any
    if !config_files.is_empty() {
        tracing::info!(
            deployment_hash = %deployment_hash,
            app_code = %app_code,
            config_count = config_files.len(),
            "Enriched deploy_app command with config_files from Vault"
        );
        if let Some(obj) = params.as_object_mut() {
            obj.insert("config_files".to_string(), json!(config_files));
        }
    }

    Ok(Some(params))
}

fn merge_rendered_env_into_app_env_files(
    config_files: &mut [serde_json::Value],
    compose_content: Option<&str>,
    app_code: &str,
    rendered_env_content: &str,
) -> usize {
    let compose_env_paths = compose_content
        .map(|content| compose_env_file_destinations_for_app(content, app_code))
        .unwrap_or_default();
    let mut merged = 0;

    for config_file in config_files {
        let Some(destination_path) = config_file
            .get("destination_path")
            .and_then(|value| value.as_str())
            .map(ToOwned::to_owned)
        else {
            continue;
        };

        if !is_app_env_config_file(&destination_path, app_code, &compose_env_paths) {
            continue;
        }

        let existing_content = config_file
            .get("content")
            .and_then(|value| value.as_str())
            .unwrap_or_default();
        let merged_content = reconcile_env_file_content(existing_content, rendered_env_content);

        if let Some(obj) = config_file.as_object_mut() {
            obj.insert("content".to_string(), json!(merged_content));
            obj.insert("content_type".to_string(), json!("text/plain"));
            obj.entry("file_mode".to_string()).or_insert(json!("0600"));
            obj.entry("owner".to_string()).or_insert(json!("trydirect"));
            obj.entry("group".to_string()).or_insert(json!("docker"));
        }
        merged += 1;
    }

    merged
}

fn is_app_env_config_file(
    destination_path: &str,
    app_code: &str,
    compose_env_paths: &HashSet<String>,
) -> bool {
    if !destination_path.ends_with(".env") {
        return false;
    }

    if compose_env_paths.contains(destination_path) {
        return true;
    }

    destination_path.contains(&format!("/{app_code}/docker/"))
}

fn compose_env_file_destinations_for_app(compose_content: &str, app_code: &str) -> HashSet<String> {
    let Ok(doc) = serde_yaml::from_str::<serde_yaml::Value>(compose_content) else {
        return HashSet::new();
    };
    let Some(env_file_value) = doc
        .as_mapping()
        .and_then(|root| root.get(serde_yaml::Value::String("services".to_string())))
        .and_then(serde_yaml::Value::as_mapping)
        .and_then(|services| services.get(serde_yaml::Value::String(app_code.to_string())))
        .and_then(serde_yaml::Value::as_mapping)
        .and_then(|service| service.get(serde_yaml::Value::String("env_file".to_string())))
    else {
        return HashSet::new();
    };

    let mut paths = HashSet::new();
    collect_env_file_destinations(env_file_value, &mut paths);
    paths
}

fn collect_env_file_destinations(value: &serde_yaml::Value, paths: &mut HashSet<String>) {
    match value {
        serde_yaml::Value::String(path) => {
            paths.insert(path.clone());
        }
        serde_yaml::Value::Sequence(values) => {
            for value in values {
                collect_env_file_destinations(value, paths);
            }
        }
        serde_yaml::Value::Mapping(map) => {
            if let Some(path) = map
                .get(serde_yaml::Value::String("path".to_string()))
                .and_then(serde_yaml::Value::as_str)
            {
                paths.insert(path.to_string());
            }
        }
        _ => {}
    }
}

async fn render_project_env_for_deploy_app(
    pg_pool: &PgPool,
    project_id: Option<i32>,
    deployment_hash: &str,
    app_code: &str,
    vault_settings: &crate::configuration::VaultSettings,
) -> Result<Option<(AppConfig, String)>, String> {
    let Some(project_id) = project_id else {
        return Ok(None);
    };
    let project = match db::project::fetch(pg_pool, project_id).await {
        Ok(Some(project)) => project,
        Ok(None) => {
            tracing::warn!(
                project_id,
                app_code,
                "Cannot render deploy_app env because project was not found"
            );
            return Ok(None);
        }
        Err(error) => {
            tracing::warn!(
                project_id,
                app_code,
                error = %error,
                "Cannot render deploy_app env because project fetch failed"
            );
            return Err(format!(
                "failed to fetch project for deploy_app env render: {error}"
            ));
        }
    };

    let app = match db::project_app::fetch_by_project_and_code(pg_pool, project_id, app_code).await
    {
        Ok(Some(app)) if app.is_enabled() => app,
        Ok(Some(_)) | Ok(None) => {
            tracing::warn!(
                project_id,
                app_code,
                "Cannot render deploy_app env because enabled app was not found"
            );
            return Ok(None);
        }
        Err(error) => {
            tracing::warn!(
                project_id,
                app_code,
                error = %error,
                "Cannot render deploy_app env because app fetch failed"
            );
            return Err(format!(
                "failed to fetch deploy_app target '{app_code}' for env render: {error}"
            ));
        }
    };

    let vault = match VaultService::from_settings(vault_settings) {
        Ok(vault) => vault,
        Err(error) => {
            tracing::warn!(
                project_id,
                app_code,
                error = %error,
                "Cannot render deploy_app env because Vault initialization failed"
            );
            return Err(format!(
                "failed to initialize Vault for deploy_app env render: {error}"
            ));
        }
    };
    let renderer = match ConfigRenderer::with_vault(vault) {
        Ok(renderer) => renderer,
        Err(error) => {
            tracing::warn!(
                project_id,
                app_code,
                error = %error,
                "Cannot render deploy_app env because ConfigRenderer initialization failed"
            );
            return Err(format!(
                "failed to initialize config renderer for deploy_app env render: {error}"
            ));
        }
    };

    match renderer
        .render_app_env_config(pg_pool, &app, &project, deployment_hash)
        .await
    {
        Ok(config) => Ok(Some(config)),
        Err(error) => {
            tracing::warn!(
                project_id,
                app_code,
                error = %error,
                "Cannot render deploy_app env"
            );
            Err(deploy_app_env_render_error(app_code, &error))
        }
    }
}

fn deploy_app_env_render_error(
    app_code: &str,
    error: &(dyn std::fmt::Display + Send + Sync),
) -> String {
    format!("failed to render deploy_app runtime env for target '{app_code}': {error}")
}

async fn render_project_compose_for_deploy_app(
    pg_pool: &PgPool,
    project_id: Option<i32>,
    deployment_hash: &str,
    app_code: &str,
) -> Option<String> {
    let project_id = project_id?;
    let project = match db::project::fetch(pg_pool, project_id).await {
        Ok(Some(project)) => project,
        Ok(None) => {
            tracing::warn!(
                project_id,
                app_code,
                "Cannot render deploy_app compose because project was not found"
            );
            return None;
        }
        Err(error) => {
            tracing::warn!(
                project_id,
                app_code,
                error = %error,
                "Cannot render deploy_app compose because project fetch failed"
            );
            return None;
        }
    };

    let service = match ProjectAppService::new(Arc::new(pg_pool.clone())) {
        Ok(service) => service,
        Err(error) => {
            tracing::warn!(
                project_id,
                app_code,
                error = %error,
                "Cannot render deploy_app compose because ProjectAppService init failed"
            );
            return None;
        }
    };

    let apps = match service.list_by_project(project_id).await {
        Ok(apps) => apps,
        Err(error) => {
            tracing::warn!(
                project_id,
                app_code,
                error = %error,
                "Cannot render deploy_app compose because project apps could not be loaded"
            );
            return None;
        }
    };

    if !apps
        .iter()
        .any(|app| app.code == app_code && app.is_enabled())
    {
        tracing::warn!(
            project_id,
            app_code,
            "Cannot render deploy_app compose because enabled app was not found"
        );
        return None;
    }

    match service
        .preview_bundle(&project, &apps, deployment_hash)
        .await
    {
        Ok(bundle) => Some(bundle.compose_content),
        Err(error) => {
            tracing::warn!(
                project_id,
                app_code,
                error = %error,
                "Cannot render deploy_app compose preview"
            );
            None
        }
    }
}

/// Discover child services from a multi-service compose file and register them as project_apps.
/// This is called after deploy_app enrichment to auto-create entries for stacks like Komodo
/// that have multiple services (core, ferretdb, periphery).
///
/// Returns the number of child services discovered and registered.
pub async fn discover_and_register_child_services(
    pg_pool: &PgPool,
    project_id: i32,
    parent_app_code: &str,
    compose_content: &str,
    deployment_hash: &str,
) -> usize {
    // Resolve actual deployment ID from hash for scoping apps per deployment
    let actual_deployment_id =
        match crate::db::deployment::fetch_by_deployment_hash(pg_pool, deployment_hash).await {
            Ok(Some(dep)) => Some(dep.id),
            _ => None,
        };

    // Parse the compose file to extract services
    let services = match parse_compose_services(compose_content) {
        Ok(svcs) => svcs,
        Err(e) => {
            tracing::debug!(
                parent_app = %parent_app_code,
                error = %e,
                "Failed to parse compose for service discovery (may be single-service)"
            );
            return 0;
        }
    };

    // If only 1 service, no child discovery needed
    if services.len() <= 1 {
        tracing::debug!(
            parent_app = %parent_app_code,
            services_count = services.len(),
            "Single service compose, no child discovery needed"
        );
        return 0;
    }

    tracing::info!(
        parent_app = %parent_app_code,
        services_count = services.len(),
        services = ?services.iter().map(|s| &s.name).collect::<Vec<_>>(),
        "Multi-service compose detected, auto-discovering child services"
    );

    let mut registered_count = 0;

    for svc in &services {
        if is_platform_managed_compose_service(&svc.name, svc.image.as_deref()) {
            tracing::debug!(
                parent_app = %parent_app_code,
                service = %svc.name,
                image = ?svc.image,
                "Skipping platform-managed compose service"
            );
            continue;
        }

        // Generate unique code: parent_code-service_name
        let app_code = format!("{}-{}", parent_app_code, svc.name);

        // Check if already exists
        match db::project_app::fetch_by_project_and_code(pg_pool, project_id, &app_code).await {
            Ok(Some(_)) => {
                tracing::debug!(
                    app_code = %app_code,
                    "Child service already registered, skipping"
                );
                continue;
            }
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(
                    app_code = %app_code,
                    error = %e,
                    "Failed to check if child service exists"
                );
                continue;
            }
        }

        tracing::debug!(
            app_code = %app_code,
            service = %svc.name,
            project_id = %project_id,
            "Processing child service for registration"
        );
        // Create new project_app for this service
        let mut new_app = crate::models::ProjectApp::new(
            project_id,
            app_code.clone(),
            svc.name.clone(),
            svc.image.clone().unwrap_or_else(|| "unknown".to_string()),
        );

        // Set parent reference
        new_app.parent_app_code = Some(parent_app_code.to_string());

        // Scope to this specific deployment
        new_app.deployment_id = actual_deployment_id;

        // Convert environment to JSON object
        if !svc.environment.is_empty() {
            let mut env_map = serde_json::Map::new();
            for env_str in &svc.environment {
                if let Some((k, v)) = env_str.split_once('=') {
                    env_map.insert(k.to_string(), json!(v));
                }
            }
            new_app.environment = Some(json!(env_map));
        }

        // Convert ports to JSON array
        if !svc.ports.is_empty() {
            new_app.ports = Some(json!(svc.ports));
        }

        // Convert volumes to JSON array
        if !svc.volumes.is_empty() {
            new_app.volumes = Some(json!(svc.volumes));
        }

        // Set networks
        if !svc.networks.is_empty() {
            new_app.networks = Some(json!(svc.networks));
        }

        // Set depends_on
        if !svc.depends_on.is_empty() {
            new_app.depends_on = Some(json!(svc.depends_on));
        }

        // Set command and entrypoint
        new_app.command = svc.command.clone();
        new_app.entrypoint = svc.entrypoint.clone();
        new_app.restart_policy = svc.restart.clone();
        new_app.healthcheck = svc.healthcheck.clone();

        // Convert labels to JSON
        if !svc.labels.is_empty() {
            let labels_map: serde_json::Map<String, serde_json::Value> = svc
                .labels
                .iter()
                .map(|(k, v)| (k.clone(), json!(v)))
                .collect();
            new_app.labels = Some(json!(labels_map));
        }

        // Insert into database
        match db::project_app::insert(pg_pool, &new_app).await {
            Ok(created) => {
                tracing::info!(
                    app_code = %app_code,
                    id = created.id,
                    service = %svc.name,
                    image = ?svc.image,
                    "Auto-registered child service from compose"
                );
                registered_count += 1;
            }
            Err(e) => {
                tracing::warn!(
                    app_code = %app_code,
                    service = %svc.name,
                    error = %e,
                    "Failed to register child service"
                );
            }
        }
    }

    if registered_count > 0 {
        tracing::info!(
            parent_app = %parent_app_code,
            registered_count = registered_count,
            "Successfully auto-registered child services"
        );
    }

    registered_count
}

fn is_platform_managed_compose_service(service_name: &str, image: Option<&str>) -> bool {
    let mut candidates = vec![normalize_app_code(service_name)];

    if let Some(image) = image {
        if let Some(image_name) = image.split('/').last() {
            if let Some(name_without_tag) = image_name.split(':').next() {
                candidates.push(normalize_app_code(name_without_tag));
            }
        }
    }

    candidates
        .iter()
        .any(|candidate| is_platform_managed_app_code(candidate))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_managed_compose_service_matches_nginx_proxy_manager_name_or_image() {
        assert!(is_platform_managed_compose_service(
            "nginx_proxy_manager",
            None
        ));
        assert!(is_platform_managed_compose_service(
            "proxy",
            Some("jc21/nginx-proxy-manager:latest")
        ));
    }

    #[test]
    fn platform_managed_compose_service_allows_regular_service() {
        assert!(!is_platform_managed_compose_service(
            "postgres",
            Some("postgres:16-alpine")
        ));
    }

    #[test]
    fn extract_registry_auth_from_params_reads_command_payload() {
        let params = Some(serde_json::json!({
            "app_code": "upload",
            "registry_auth": {
                "registry": "docker.io",
                "username": "optimum",
                "password": "secret"
            }
        }));

        let auth = extract_registry_auth_from_params(&params).expect("registry auth");

        assert_eq!(auth.registry, "docker.io");
        assert_eq!(auth.username, "optimum");
        assert_eq!(auth.password, "secret");
    }

    #[test]
    fn extract_registry_auth_from_params_ignores_missing_payload() {
        assert!(extract_registry_auth_from_params(&Some(serde_json::json!({
            "app_code": "upload"
        })))
        .is_none());
    }

    #[test]
    fn merge_rendered_env_updates_app_local_compose_env_file() {
        let compose_content = r#"
services:
  device-api:
    image: syncopia/device-api:prod
    env_file:
      - /opt/stacker/deployments/prod/files/device-api/docker/prod/.env
  upload:
    image: syncopia/upload:prod
    env_file:
      - /opt/stacker/deployments/prod/files/upload/docker/prod/.env
"#;
        let mut config_files = vec![
            json!({
                "content": "# Auto-created empty env file\n",
                "destination_path": "/opt/stacker/deployments/prod/files/device-api/docker/prod/.env"
            }),
            json!({
                "content": "UPLOAD_ONLY=true\n",
                "destination_path": "/opt/stacker/deployments/prod/files/upload/docker/prod/.env"
            }),
        ];

        let merged = merge_rendered_env_into_app_env_files(
            &mut config_files,
            Some(compose_content),
            "device-api",
            "# stacker-render version=1 hash=abc generated_at=now inputs=service\nS3_SECRET_KEY=supersecret\n",
        );

        assert_eq!(merged, 1);
        let device_env = config_files[0]
            .get("content")
            .and_then(|value| value.as_str())
            .expect("device env content");
        assert!(device_env.contains("# Auto-created empty env file"));
        assert!(device_env.contains("S3_SECRET_KEY=supersecret"));
        let upload_env = config_files[1]
            .get("content")
            .and_then(|value| value.as_str())
            .expect("upload env content");
        assert!(!upload_env.contains("S3_SECRET_KEY"));
    }

    #[test]
    fn merge_rendered_env_preserves_local_env_and_appends_rendered_block_once() {
        let mut config_files = vec![json!({
            "content": "RUST_LOG=debug\n",
            "content_type": "text/plain",
            "destination_path": "/opt/stacker/deployments/prod/files/device-api/docker/prod/.env",
            "file_mode": "0644"
        })];

        let merged = merge_rendered_env_into_app_env_files(
            &mut config_files,
            Some(
                r#"
services:
  device-api:
    env_file: /opt/stacker/deployments/prod/files/device-api/docker/prod/.env
"#,
            ),
            "device-api",
            "# stacker-render version=1 hash=abc generated_at=now inputs=service\nS3_BUCKET=superbucket\n",
        );

        assert_eq!(merged, 1);
        let env_content = config_files[0]["content"].as_str().expect("content");
        assert_eq!(
            env_content,
            "RUST_LOG=debug\n\n# stacker-render version=1 hash=abc generated_at=now inputs=service\nS3_BUCKET=superbucket\n"
        );
        assert_eq!(config_files[0]["content_type"], "text/plain");
        assert_eq!(config_files[0]["file_mode"], "0644");
    }

    #[test]
    fn merge_rendered_env_replaces_previous_rendered_block() {
        let mut config_files = vec![json!({
            "content": "RUST_LOG=debug\n\n# stacker-render version=1 hash=old generated_at=now inputs=service\nOLD_SECRET=outdated\n",
            "destination_path": "/opt/stacker/deployments/prod/files/device-api/docker/prod/.env"
        })];

        let merged = merge_rendered_env_into_app_env_files(
            &mut config_files,
            Some(
                r#"
services:
  device-api:
    env_file: /opt/stacker/deployments/prod/files/device-api/docker/prod/.env
"#,
            ),
            "device-api",
            "# stacker-render version=2 hash=new generated_at=now inputs=service\nNEW_SECRET=fresh\n",
        );

        assert_eq!(merged, 1);
        let env_content = config_files[0]["content"].as_str().expect("content");
        assert_eq!(
            env_content,
            "RUST_LOG=debug\n\n# stacker-render version=2 hash=new generated_at=now inputs=service\nNEW_SECRET=fresh\n"
        );
        assert!(!env_content.contains("OLD_SECRET=outdated"));
    }

    #[test]
    fn merge_rendered_env_removes_authored_key_overridden_by_rendered_block() {
        let mut config_files = vec![json!({
            "content": "RUST_LOG=debug\nS3_BUCKET=local\n",
            "destination_path": "/opt/stacker/deployments/prod/files/device-api/docker/prod/.env"
        })];

        let merged = merge_rendered_env_into_app_env_files(
            &mut config_files,
            Some(
                r#"
services:
  device-api:
    env_file: /opt/stacker/deployments/prod/files/device-api/docker/prod/.env
"#,
            ),
            "device-api",
            "# stacker-render version=2 hash=new generated_at=now inputs=service\nS3_BUCKET=remote\n",
        );

        assert_eq!(merged, 1);
        let env_content = config_files[0]["content"].as_str().expect("content");
        assert_eq!(
            env_content,
            "RUST_LOG=debug\n\n# stacker-render version=2 hash=new generated_at=now inputs=service\nS3_BUCKET=remote\n"
        );
        assert!(!env_content.contains("S3_BUCKET=local"));
    }

    #[test]
    fn merge_rendered_env_matches_app_local_env_by_destination_when_compose_uses_relative_env_file()
    {
        let mut config_files = vec![
            json!({
                "content": "RUST_LOG=debug\n",
                "destination_path": "/opt/stacker/deployments/prod/files/device-api/docker/prod/.env"
            }),
            json!({
                "content": "SHARED=true\n",
                "destination_path": "/opt/stacker/deployments/prod/files/shared/docker/prod/.env"
            }),
        ];

        let merged = merge_rendered_env_into_app_env_files(
            &mut config_files,
            Some(
                r#"
services:
  device-api:
    env_file: .env
"#,
            ),
            "device-api",
            "# stacker-render version=1 hash=abc generated_at=now inputs=service\nS3_BUCKET=superbucket\n",
        );

        assert_eq!(merged, 1);
        assert!(config_files[0]["content"]
            .as_str()
            .expect("device content")
            .contains("S3_BUCKET=superbucket"));
        assert!(!config_files[1]["content"]
            .as_str()
            .expect("shared content")
            .contains("S3_BUCKET=superbucket"));
    }

    #[test]
    fn merge_rendered_env_does_not_touch_non_env_config_files() {
        let mut config_files = vec![json!({
            "content": "port = 5050\n",
            "destination_path": "/opt/stacker/deployments/prod/files/device-api/docker/prod/default.toml"
        })];

        let merged = merge_rendered_env_into_app_env_files(
            &mut config_files,
            Some("services:\n  device-api:\n    env_file: .env\n"),
            "device-api",
            "# stacker-render version=1 hash=abc generated_at=now inputs=service\nS3_BUCKET=superbucket\n",
        );

        assert_eq!(merged, 0);
        assert_eq!(config_files[0]["content"], "port = 5050\n");
    }

    #[tokio::test]
    async fn render_project_env_without_project_id_skips_without_error() {
        let pg_pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://postgres:postgres@localhost/stacker_test")
            .expect("lazy pool");
        let vault_settings = crate::configuration::VaultSettings::default();

        let rendered = render_project_env_for_deploy_app(
            &pg_pool,
            None,
            "deployment_test",
            "device-api",
            &vault_settings,
        )
        .await
        .expect("missing project id should be non-fatal");

        assert!(rendered.is_none());
    }

    #[test]
    fn deploy_app_env_render_error_names_target_without_secret_values() {
        let error = deploy_app_env_render_error(
            "device-api",
            &std::io::Error::new(std::io::ErrorKind::PermissionDenied, "vault denied access"),
        );

        assert_eq!(
            error,
            "failed to render deploy_app runtime env for target 'device-api': vault denied access"
        );
        assert!(!error.contains("S3_BUCKET=superbucket"));
    }

    #[test]
    fn compose_env_file_destinations_supports_compose_mapping_syntax() {
        let compose_content = r#"
services:
  device-api:
    env_file:
      - path: /opt/stacker/deployments/prod/files/device-api/docker/prod/.env
        required: false
"#;

        let destinations = compose_env_file_destinations_for_app(compose_content, "device-api");

        assert!(destinations
            .contains("/opt/stacker/deployments/prod/files/device-api/docker/prod/.env"));
    }
}
