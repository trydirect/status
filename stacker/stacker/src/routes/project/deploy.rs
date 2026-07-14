use crate::configuration::Settings;
use crate::connectors::{
    app_service_catalog, install_service::InstallServiceConnector,
    user_service::UserServiceConnector,
};
use crate::db;
use crate::forms;
use crate::helpers::project::builder::DcBuilder;
use crate::helpers::{JsonResponse, MqManager, VaultClient};
use crate::models;
use crate::services;
use actix_web::{post, web, web::Data, Responder, Result};
use serde::Deserialize;
use serde_valid::Validate;
use sqlx::PgPool;
use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

const MANAGED_NGINX_PROXY_MANAGER_FEATURE: &str = "nginx_proxy_manager";
const STATUS_PANEL_FEATURE: &str = "statuspanel";
const STATUS_PANEL_CONNECTION_MODE: &str = "status_panel";
const STATUS_PANEL_NPM_CREDENTIALS_SECRET: &str = "npm_credentials";
const DEFAULT_STATUS_PANEL_NPM_HOST: &str = "http://nginx-proxy-manager:81";
const DEFAULT_STATUS_PANEL_NPM_EMAIL: &str = "admin@example.com";
const DEFAULT_STATUS_PANEL_NPM_PASSWORD: &str = "changeme";
const DEFAULT_STATUS_PANEL_NPM_AUTH_MODE: &str = "email_password";

fn parse_template_requirements(
    template: &models::StackTemplate,
) -> Result<models::InfrastructureRequirements, String> {
    serde_json::from_value(template.infrastructure_requirements.clone()).map_err(|err| {
        tracing::error!(
            "Failed to parse infrastructure requirements for template {}: {}",
            template.id,
            err
        );
        "Template infrastructure requirements are invalid".to_string()
    })
}

fn validate_template_target_requirements(
    template: &models::StackTemplate,
    requirements: &models::InfrastructureRequirements,
    provider: &str,
    os: Option<&str>,
) -> Result<(), String> {
    let mut mismatches = Vec::new();

    if !requirements.supported_clouds.is_empty() {
        let supported: HashSet<String> = requirements
            .supported_clouds
            .iter()
            .map(|cloud| cloud.to_ascii_lowercase())
            .collect();
        if !supported.contains(&provider.to_ascii_lowercase()) {
            mismatches.push(format!(
                "cloud provider '{}' is not supported (allowed: {})",
                provider,
                requirements.supported_clouds.join(", ")
            ));
        }
    }

    if !requirements.supported_os.is_empty() {
        match os {
            Some(target_os)
                if requirements
                    .supported_os
                    .iter()
                    .any(|supported_os| supported_os.eq_ignore_ascii_case(target_os)) => {}
            Some(target_os) => mismatches.push(format!(
                "operating system '{}' is not supported (allowed: {})",
                target_os,
                requirements.supported_os.join(", ")
            )),
            None => mismatches.push(format!(
                "operating system is required (allowed: {})",
                requirements.supported_os.join(", ")
            )),
        }
    }

    if mismatches.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "Template '{}' cannot be deployed to this target: {}",
            template.slug,
            mismatches.join("; ")
        ))
    }
}

fn validate_min_ram_requirement(
    template: &models::StackTemplate,
    server_slug: &str,
    minimum_ram_mb: i32,
    server_capacity: &app_service_catalog::ServerCapacity,
) -> Result<(), String> {
    match server_capacity.ram_mb {
        Some(available_ram_mb) if available_ram_mb >= minimum_ram_mb => Ok(()),
        Some(available_ram_mb) => Err(format!(
            "Template '{}' cannot be deployed to this target: selected server '{}' does not meet minimum RAM requirement (required: {} MB, available: {} MB)",
            template.slug, server_slug, minimum_ram_mb, available_ram_mb
        )),
        None => Err(format!(
            "Template '{}' cannot be deployed to this target: selected server '{}' is missing RAM metadata",
            template.slug, server_slug
        )),
    }
}

fn validate_min_disk_requirement(
    template: &models::StackTemplate,
    server_slug: &str,
    minimum_disk_gb: i32,
    server_capacity: &app_service_catalog::ServerCapacity,
) -> Result<(), String> {
    match server_capacity.disk_gb {
        Some(available_disk_gb) if available_disk_gb >= minimum_disk_gb => Ok(()),
        Some(available_disk_gb) => Err(format!(
            "Template '{}' cannot be deployed to this target: selected server '{}' does not meet minimum disk requirement (required: {} GB, available: {} GB)",
            template.slug, server_slug, minimum_disk_gb, available_disk_gb
        )),
        None => Err(format!(
            "Template '{}' cannot be deployed to this target: selected server '{}' is missing disk metadata",
            template.slug, server_slug
        )),
    }
}

fn validate_min_cpu_requirement(
    template: &models::StackTemplate,
    server_slug: &str,
    minimum_cpu_cores: i32,
    server_capacity: &app_service_catalog::ServerCapacity,
) -> Result<(), String> {
    match server_capacity.cpu_cores {
        Some(available_cpu_cores) if available_cpu_cores >= minimum_cpu_cores => Ok(()),
        Some(available_cpu_cores) => Err(format!(
            "Template '{}' cannot be deployed to this target: selected server '{}' does not meet minimum CPU requirement (required: {} cores, available: {} cores)",
            template.slug, server_slug, minimum_cpu_cores, available_cpu_cores
        )),
        None => Err(format!(
            "Template '{}' cannot be deployed to this target: selected server '{}' is missing CPU metadata",
            template.slug, server_slug
        )),
    }
}

fn project_locked_cloud_provider(project: &models::Project) -> Option<&str> {
    project
        .request_json
        .get("custom")
        .and_then(|custom| custom.get("locked_cloud_provider"))
        .and_then(|provider| provider.as_str())
        .map(str::trim)
        .filter(|provider| !provider.is_empty())
}

fn validate_project_locked_cloud_provider(
    project: &models::Project,
    provider: &str,
) -> Result<(), String> {
    let provider = provider.trim();
    let Some(locked_provider) = project_locked_cloud_provider(project) else {
        return Ok(());
    };

    if locked_provider.eq_ignore_ascii_case(provider) {
        return Ok(());
    }

    Err(format!(
        "This project is locked to cloud provider '{}'. Deploying with '{}' is not allowed.",
        locked_provider, provider
    ))
}

fn normalized_provider(provider: &str) -> String {
    provider.trim().to_ascii_lowercase()
}

fn is_hetzner_provider(provider: &str) -> bool {
    matches!(normalized_provider(provider).as_str(), "htz" | "hetzner")
}

fn server_display_name(server: &models::Server) -> String {
    server
        .name
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| server.srv_ip.clone())
        .unwrap_or_else(|| format!("server #{}", server.id))
}

fn reveal_cloud_credentials(cloud: &models::Cloud) -> models::Cloud {
    if cloud.save_token == Some(true) {
        forms::cloud::CloudForm::decode_model(cloud.clone(), true)
    } else {
        cloud.clone()
    }
}

#[derive(Debug, Deserialize)]
struct HetznerServersResponse {
    #[serde(default)]
    servers: Vec<HetznerServer>,
}

#[derive(Debug, Deserialize)]
struct HetznerServer {
    name: String,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    public_net: Option<HetznerPublicNet>,
}

#[derive(Debug, Deserialize)]
struct HetznerPublicNet {
    #[serde(default)]
    ipv4: Option<HetznerIpv4>,
}

#[derive(Debug, Deserialize)]
struct HetznerIpv4 {
    ip: String,
}

fn hetzner_api_base_url() -> String {
    std::env::var("STACKER_HETZNER_API_URL")
        .unwrap_or_else(|_| "https://api.hetzner.cloud/v1".to_string())
        .trim_end_matches('/')
        .to_string()
}

fn hetzner_server_ip(server: &HetznerServer) -> Option<&str> {
    server
        .public_net
        .as_ref()?
        .ipv4
        .as_ref()
        .map(|ipv4| ipv4.ip.as_str())
}

fn find_matching_hetzner_server<'a>(
    servers: &'a [HetznerServer],
    stacker_server: &models::Server,
) -> Option<&'a HetznerServer> {
    let expected_name = stacker_server
        .name
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty());
    let expected_ip = stacker_server
        .srv_ip
        .as_deref()
        .map(str::trim)
        .filter(|ip| !ip.is_empty());

    servers.iter().find(|server| {
        expected_name.is_some_and(|name| server.name == name)
            || expected_ip.is_some_and(|ip| hetzner_server_ip(server) == Some(ip))
    })
}

async fn verify_tcp_reachable(host: &str, port: i32, timeout_secs: u64) -> Result<(), String> {
    let port = u16::try_from(port).map_err(|_| format!("invalid SSH port {}", port))?;
    let address = (host, port);

    match tokio::time::timeout(
        Duration::from_secs(timeout_secs),
        tokio::net::TcpStream::connect(address),
    )
    .await
    {
        Ok(Ok(_stream)) => Ok(()),
        Ok(Err(err)) => Err(err.to_string()),
        Err(_) => Err(format!("connection timed out after {}s", timeout_secs)),
    }
}

async fn validate_hetzner_reused_server(
    cloud: &models::Cloud,
    server: &models::Server,
) -> Result<(), String> {
    let display_name = server_display_name(server);
    let cloud = reveal_cloud_credentials(cloud);
    let token = cloud
        .cloud_token
        .as_deref()
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .ok_or_else(|| {
            "Could not verify connected Hetzner server because cloud credentials are unavailable. Re-add the cloud credential and retry.".to_string()
        })?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
        .map_err(|err| format!("Could not initialize Hetzner API client: {}", err))?;
    let response = client
        .get(format!("{}/servers", hetzner_api_base_url()))
        .bearer_auth(token)
        .send()
        .await
        .map_err(|err| {
            format!(
                "Could not verify connected Hetzner server '{}': {}",
                display_name, err
            )
        })?;

    if !response.status().is_success() {
        return Err(format!(
            "Could not verify connected Hetzner server '{}': Hetzner API returned HTTP {}. Check the saved cloud credential and retry.",
            display_name,
            response.status().as_u16()
        ));
    }

    let body = response
        .json::<HetznerServersResponse>()
        .await
        .map_err(|err| {
            format!(
                "Could not verify connected Hetzner server '{}': invalid Hetzner API response ({})",
                display_name, err
            )
        })?;

    let provider_server = find_matching_hetzner_server(&body.servers, server).ok_or_else(|| {
        format!(
            "Connected cloud server '{}' no longer exists in Hetzner. Run `stacker deploy --force-new` to provision a new server, or remove/reconnect the stale server in Stacker.",
            display_name
        )
    })?;

    if let Some(status) = provider_server.status.as_deref() {
        if status != "running" {
            return Err(format!(
                "Connected cloud server '{}' exists in Hetzner but is '{}'. Start the server or run `stacker deploy --force-new` to provision a new one.",
                display_name, status
            ));
        }
    }

    if let Some(ip) = server
        .srv_ip
        .as_deref()
        .map(str::trim)
        .filter(|ip| !ip.is_empty())
    {
        let ssh_port = server.ssh_port.unwrap_or(22);
        verify_tcp_reachable(ip, ssh_port, 4)
            .await
            .map_err(|err| {
                format!(
                    "Connected cloud server '{}' exists in Hetzner but SSH is not reachable at {}:{} ({}). Fix the server/firewall or run `stacker deploy --force-new` to provision a new server.",
                    display_name, ip, ssh_port, err
                )
            })?;
    }

    Ok(())
}

async fn validate_reused_cloud_server(
    cloud: &models::Cloud,
    server: &models::Server,
) -> Result<(), String> {
    let provider = normalized_provider(&cloud.provider);
    let has_existing_ip = server
        .srv_ip
        .as_deref()
        .map(str::trim)
        .is_some_and(|ip| !ip.is_empty());

    if provider == "own" || !has_existing_ip {
        return Ok(());
    }

    if is_hetzner_provider(&provider) {
        return validate_hetzner_reused_server(cloud, server).await;
    }

    tracing::warn!(
        "Reused cloud server validation is not implemented for provider '{}'; proceeding with existing behavior",
        cloud.provider
    );
    Ok(())
}

async fn validate_template_server_capacity_requirements(
    template: &models::StackTemplate,
    requirements: &models::InfrastructureRequirements,
    provider: &str,
    cloud_id: Option<i32>,
    server_slug: Option<&str>,
    access_token: Option<&str>,
) -> Result<(), String> {
    if requirements.min_ram_mb.is_none()
        && requirements.min_disk_gb.is_none()
        && requirements.min_cpu_cores.is_none()
    {
        return Ok(());
    }

    if !app_service_catalog::is_supported_cloud_provider(provider) {
        return Ok(());
    }

    let server_slug = server_slug.ok_or_else(|| {
        format!(
            "Template '{}' cannot be deployed to this target: selected server is required for minimum RAM validation",
            template.slug
        )
    })?;

    let payload = app_service_catalog::fetch_catalog(provider, "servers", cloud_id, access_token)
        .await
        .map_err(|err| {
            format!(
                "Template '{}' cannot be deployed to this target: failed to load server catalog: {}",
                template.slug, err
            )
        })?;

    let server_capacity = app_service_catalog::resolve_server_capacity(&payload, server_slug)
        .ok_or_else(|| {
            format!(
                "Template '{}' cannot be deployed to this target: selected server '{}' was not found in the provider catalog",
                template.slug, server_slug
            )
        })?;

    if let Some(minimum_ram_mb) = requirements.min_ram_mb {
        validate_min_ram_requirement(template, server_slug, minimum_ram_mb, &server_capacity)?;
    }

    if let Some(minimum_disk_gb) = requirements.min_disk_gb {
        validate_min_disk_requirement(template, server_slug, minimum_disk_gb, &server_capacity)?;
    }

    if let Some(minimum_cpu_cores) = requirements.min_cpu_cores {
        validate_min_cpu_requirement(template, server_slug, minimum_cpu_cores, &server_capacity)?;
    }

    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct RollbackRequest {
    pub version: String,
}

fn build_rollback_project_payload(
    stack_definition: serde_json::Value,
) -> Result<(serde_json::Value, String), String> {
    let form: forms::project::ProjectForm = serde_json::from_value(stack_definition.clone())
        .map_err(|err| format!("Invalid marketplace template definition: {}", err))?;
    let stack_code = form.custom.custom_stack_code.clone();
    let metadata = serde_json::to_value(form).map_err(|err| {
        format!(
            "Failed to normalize marketplace template definition: {}",
            err
        )
    })?;
    Ok((metadata, stack_code))
}

fn build_rollback_deploy_form(template_stack_code: String) -> forms::project::Deploy {
    forms::project::Deploy {
        stack: forms::project::Stack {
            stack_code: Some(template_stack_code),
            ..Default::default()
        },
        ..Default::default()
    }
}

fn deploy_features_contain(features: Option<&Vec<serde_json::Value>>, expected: &str) -> bool {
    features.is_some_and(|items| {
        items.iter().any(|feature| {
            feature
                .as_str()
                .is_some_and(|value| value.eq_ignore_ascii_case(expected))
        })
    })
}

fn deploy_uses_managed_nginx_proxy_manager(form: &forms::project::Deploy) -> bool {
    deploy_features_contain(
        form.stack.extended_features.as_ref(),
        MANAGED_NGINX_PROXY_MANAGER_FEATURE,
    )
}

fn deploy_uses_status_panel_agent(form: &forms::project::Deploy) -> bool {
    form.server.connection_mode.as_deref() == Some(STATUS_PANEL_CONNECTION_MODE)
        || deploy_features_contain(
            form.stack.integrated_features.as_ref(),
            STATUS_PANEL_FEATURE,
        )
}

fn should_seed_default_status_panel_npm_credentials(form: &forms::project::Deploy) -> bool {
    deploy_uses_managed_nginx_proxy_manager(form) && deploy_uses_status_panel_agent(form)
}

fn default_status_panel_npm_credentials() -> serde_json::Value {
    serde_json::json!({
        "schema_version": 1,
        "host": DEFAULT_STATUS_PANEL_NPM_HOST,
        "email": DEFAULT_STATUS_PANEL_NPM_EMAIL,
        "password": DEFAULT_STATUS_PANEL_NPM_PASSWORD,
        "auth_mode": DEFAULT_STATUS_PANEL_NPM_AUTH_MODE
    })
}

async fn ensure_default_status_panel_npm_credentials(
    user: &models::User,
    form: &forms::project::Deploy,
    pg_pool: &PgPool,
    settings: &Settings,
    server: &models::Server,
) -> Result<bool, String> {
    if !should_seed_default_status_panel_npm_credentials(form) {
        return Ok(false);
    }

    if db::remote_secret::fetch_server_secret(
        pg_pool,
        &user.id,
        server.id,
        STATUS_PANEL_NPM_CREDENTIALS_SECRET,
    )
    .await?
    .is_some()
    {
        return Ok(false);
    }

    let vault = services::VaultService::from_settings(&settings.vault)
        .map_err(|error| error.to_string())?;
    let vault_path = vault.status_panel_npm_credentials_path(server.id);
    let default_credentials = default_status_panel_npm_credentials();

    vault
        .store_structured_secret_value(&vault_path, &default_credentials)
        .await
        .map_err(|error| error.to_string())?;

    db::remote_secret::upsert_server_secret(
        pg_pool,
        &user.id,
        server.id,
        STATUS_PANEL_NPM_CREDENTIALS_SECRET,
        &vault_path,
        &user.id,
        "synced",
    )
    .await?;

    tracing::info!(
        "Seeded default Nginx Proxy Manager credentials for server {} at {}",
        server.id,
        vault_path
    );

    Ok(true)
}

fn is_non_empty_json(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Null => false,
        serde_json::Value::Array(items) => !items.is_empty(),
        serde_json::Value::Object(map) => !map.is_empty(),
        serde_json::Value::String(value) => !value.trim().is_empty(),
        _ => true,
    }
}

fn normalize_optional_secret(value: &Option<String>) -> Option<String> {
    value
        .as_ref()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn resolve_provided_ssh_keypair(
    form: &forms::server::ServerForm,
) -> Result<Option<(String, String)>, String> {
    let private_key = match normalize_optional_secret(&form.ssh_private_key) {
        Some(key) => key,
        None => return Ok(None),
    };

    let public_key = match normalize_optional_secret(&form.public_key) {
        Some(key) => key,
        None => {
            let private = ssh_key::PrivateKey::from_openssh(&private_key)
                .map_err(|err| format!("Invalid SSH private key: {}", err))?;
            private
                .public_key()
                .to_openssh()
                .map_err(|err| format!("Failed to derive SSH public key: {}", err))?
        }
    };

    Ok(Some((public_key, private_key)))
}

fn ensure_root_object(
    value: &mut serde_json::Value,
) -> &mut serde_json::Map<String, serde_json::Value> {
    if !value.is_object() {
        *value = serde_json::json!({});
    }

    value
        .as_object_mut()
        .expect("root value should be normalized to object")
}

fn ensure_custom_object(
    value: &mut serde_json::Value,
) -> &mut serde_json::Map<String, serde_json::Value> {
    let root = ensure_root_object(value);
    let custom = root
        .entry("custom".to_string())
        .or_insert_with(|| serde_json::json!({}));
    if !custom.is_object() {
        *custom = serde_json::json!({});
    }

    custom
        .as_object_mut()
        .expect("custom value should be normalized to object")
}

fn custom_field(value: &serde_json::Value, field: &str) -> Option<serde_json::Value> {
    value
        .get("custom")
        .and_then(|custom| custom.get(field))
        .cloned()
}

fn template_version_field(
    template_version: &models::StackTemplateVersion,
    field: &str,
) -> Option<serde_json::Value> {
    let value = match field {
        "marketplace_config_files" => &template_version.config_files,
        "marketplace_assets" => &template_version.assets,
        "marketplace_seed_jobs" => &template_version.seed_jobs,
        "marketplace_post_deploy_hooks" => &template_version.post_deploy_hooks,
        _ => &serde_json::Value::Null,
    };

    is_non_empty_json(value).then(|| value.clone())
}

fn upsert_custom_field(target: &mut serde_json::Value, field: &str, value: &serde_json::Value) {
    let custom = ensure_custom_object(target);
    if !custom.contains_key(field) {
        custom.insert(field.to_string(), value.clone());
    }
}

fn sanitize_runtime_bundle_filename(raw_filename: &str) -> Option<String> {
    let normalized = raw_filename.trim().replace('\\', "/");
    if normalized.is_empty() {
        return None;
    }

    Path::new(&normalized)
        .file_name()
        .and_then(|filename| filename.to_str())
        .map(str::trim)
        .filter(|filename| !filename.is_empty() && *filename != "." && *filename != "..")
        .map(|filename| filename.to_string())
}

fn select_runtime_bundle_asset(custom: &serde_json::Value) -> Option<models::MarketplaceAsset> {
    custom
        .get("marketplace_assets")
        .and_then(|assets| assets.as_array())
        .and_then(|assets| {
            assets.iter().find_map(|asset| {
                let parsed =
                    serde_json::from_value::<models::MarketplaceAsset>(asset.clone()).ok()?;
                let filename = parsed.filename.to_ascii_lowercase();
                let content_type = parsed.content_type.to_ascii_lowercase();
                if filename.ends_with(".tgz")
                    || filename.ends_with(".tar.gz")
                    || content_type == "application/gzip"
                    || content_type == "application/x-gzip"
                    || content_type == "application/x-tar"
                {
                    Some(parsed)
                } else {
                    None
                }
            })
        })
}

fn preserve_marketplace_runtime_artifacts(
    project: &mut models::Project,
    template_version: Option<&models::StackTemplateVersion>,
) -> Result<(), String> {
    for field in [
        "marketplace_config_files",
        "marketplace_assets",
        "marketplace_seed_jobs",
        "marketplace_post_deploy_hooks",
    ] {
        let value = custom_field(&project.metadata, field)
            .or_else(|| custom_field(&project.request_json, field))
            .or_else(|| {
                template_version.and_then(|version| template_version_field(version, field))
            });

        if let Some(value) = value {
            upsert_custom_field(&mut project.metadata, field, &value);
            upsert_custom_field(&mut project.request_json, field, &value);
        }
    }

    Ok(())
}

fn build_runtime_artifact_bundle(
    settings: &Settings,
    custom: &serde_json::Value,
) -> Result<Option<serde_json::Value>, String> {
    let config_files = custom
        .get("marketplace_config_files")
        .cloned()
        .unwrap_or_else(|| serde_json::json!([]));
    let assets = custom
        .get("marketplace_assets")
        .cloned()
        .unwrap_or_else(|| serde_json::json!([]));
    let seed_jobs = custom
        .get("marketplace_seed_jobs")
        .cloned()
        .unwrap_or_else(|| serde_json::json!([]));
    let post_deploy_hooks = custom
        .get("marketplace_post_deploy_hooks")
        .cloned()
        .unwrap_or_else(|| serde_json::json!([]));

    if !is_non_empty_json(&config_files)
        && !is_non_empty_json(&assets)
        && !is_non_empty_json(&seed_jobs)
        && !is_non_empty_json(&post_deploy_hooks)
    {
        return Ok(None);
    }

    let mut bundle = serde_json::json!({
        "archive_format": "tar.gz",
        "config_files_count": config_files.as_array().map(|items| items.len()).unwrap_or(0),
        "asset_count": assets.as_array().map(|items| items.len()).unwrap_or(0),
        "seed_jobs_count": seed_jobs.as_array().map(|items| items.len()).unwrap_or(0),
        "post_deploy_hooks_count": post_deploy_hooks.as_array().map(|items| items.len()).unwrap_or(0),
        "seed_jobs_execution": "deferred",
        "post_deploy_execution": "deferred",
    });

    if let Some(asset) = select_runtime_bundle_asset(custom) {
        let safe_filename = sanitize_runtime_bundle_filename(&asset.filename)
            .unwrap_or_else(|| "runtime-artifacts.tar.gz".to_string());
        if let Some(bundle_object) = bundle.as_object_mut() {
            bundle_object.insert("filename".to_string(), serde_json::json!(safe_filename));
            bundle_object.insert("sha256".to_string(), serde_json::json!(asset.sha256));
            bundle_object.insert("size".to_string(), serde_json::json!(asset.size));
            bundle_object.insert(
                "content_type".to_string(),
                serde_json::json!(asset.content_type),
            );
            bundle_object.insert(
                "decompress".to_string(),
                serde_json::json!(asset.decompress),
            );
            if let Some(fetch_target) = asset.fetch_target.clone() {
                bundle_object.insert("fetch_target".to_string(), serde_json::json!(fetch_target));
            }
            if let Some(mount_path) = asset.mount_path.clone() {
                bundle_object.insert("mount_path".to_string(), serde_json::json!(mount_path));
            }
        }

        match services::presign_asset_download(&settings.marketplace_assets, &asset) {
            Ok(presigned) => {
                if let Some(bundle_object) = bundle.as_object_mut() {
                    bundle_object
                        .insert("download_url".to_string(), serde_json::json!(presigned.url));
                    bundle_object.insert(
                        "download_method".to_string(),
                        serde_json::json!(presigned.method),
                    );
                    bundle_object.insert(
                        "expires_in_seconds".to_string(),
                        serde_json::json!(presigned.expires_in_seconds),
                    );
                }
            }
            Err(err) => {
                tracing::warn!(
                    "Failed to presign runtime artifact bundle download: {}",
                    err
                );
                if let Some(bundle_object) = bundle.as_object_mut() {
                    bundle_object.insert(
                        "download_url_error".to_string(),
                        serde_json::json!(err.to_string()),
                    );
                }
            }
        }
    }

    Ok(Some(bundle))
}

fn sync_runtime_artifact_bundle(
    settings: &Settings,
    project: &mut models::Project,
) -> Result<(), String> {
    match build_runtime_artifact_bundle(settings, &project.metadata["custom"])? {
        Some(runtime_bundle) => {
            ensure_root_object(&mut project.metadata).insert(
                "runtime_artifact_bundle".to_string(),
                runtime_bundle.clone(),
            );
            ensure_root_object(&mut project.request_json)
                .insert("runtime_artifact_bundle".to_string(), runtime_bundle);
        }
        None => {
            ensure_root_object(&mut project.metadata).remove("runtime_artifact_bundle");
            ensure_root_object(&mut project.request_json).remove("runtime_artifact_bundle");
        }
    }

    Ok(())
}

fn upsert_root_field(target: &mut serde_json::Value, field: &str, value: &serde_json::Value) {
    ensure_root_object(target).insert(field.to_string(), value.clone());
}

fn upsert_deployment_artifact(
    target: &mut serde_json::Value,
    field: &str,
    value: &serde_json::Value,
) {
    let custom = ensure_custom_object(target);
    let deployment_artifacts = custom
        .entry("deployment_artifacts".to_string())
        .or_insert_with(|| serde_json::json!({}));
    if !deployment_artifacts.is_object() {
        *deployment_artifacts = serde_json::json!({});
    }

    deployment_artifacts
        .as_object_mut()
        .expect("deployment_artifacts should be normalized to an object")
        .insert(field.to_string(), value.clone());
}

fn basename_from_path(path: &str) -> Option<&str> {
    Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .map(str::trim)
        .filter(|name| !name.is_empty())
}

fn compose_content_from_config_files(
    config_files: &serde_json::Value,
) -> Result<Option<String>, String> {
    let files = config_files
        .as_array()
        .ok_or_else(|| "config_files must be an array".to_string())?;

    for file in files {
        let file_name = file
            .get("name")
            .and_then(|value| value.as_str())
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .or_else(|| {
                file.get("destination_path")
                    .and_then(|value| value.as_str())
                    .and_then(basename_from_path)
            });

        if let Some(file_name) = file_name {
            if crate::project_app::is_compose_filename(file_name) {
                let content = file
                    .get("content")
                    .and_then(|value| value.as_str())
                    .ok_or_else(|| {
                        format!(
                            "compose config file '{}' is missing string content",
                            file_name
                        )
                    })?;
                return Ok(Some(content.to_string()));
            }
        }
    }

    Ok(None)
}

fn runtime_config_files_from_deploy_config_files(
    config_files: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    let files = config_files
        .as_array()
        .ok_or_else(|| "config_files must be an array".to_string())?;
    let mut runtime_files = Vec::new();

    for file in files {
        let file_name = file
            .get("name")
            .and_then(|value| value.as_str())
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .or_else(|| {
                file.get("destination_path")
                    .and_then(|value| value.as_str())
                    .and_then(basename_from_path)
            });

        if file_name.is_some_and(crate::project_app::is_compose_filename) {
            continue;
        }

        let path = file
            .get("destination_path")
            .or_else(|| file.get("path"))
            .and_then(|value| value.as_str())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| "config file is missing destination_path".to_string())?;
        let content = file
            .get("content")
            .and_then(|value| value.as_str())
            .ok_or_else(|| format!("config file '{}' is missing string content", path))?;

        let mut runtime_file = serde_json::json!({
            "path": path,
            "content": content,
        });
        if let Some(mode) = file
            .get("file_mode")
            .or_else(|| file.get("mode"))
            .and_then(|value| value.as_str())
        {
            runtime_file["mode"] = serde_json::json!(mode);
        }
        runtime_files.push(runtime_file);
    }

    Ok(serde_json::Value::Array(runtime_files))
}

fn merge_marketplace_config_files(target: &mut serde_json::Value, generated: &serde_json::Value) {
    let Some(generated_files) = generated.as_array().filter(|files| !files.is_empty()) else {
        return;
    };

    let custom = ensure_custom_object(target);
    let existing = custom
        .entry("marketplace_config_files".to_string())
        .or_insert_with(|| serde_json::json!([]));
    if !existing.is_array() {
        *existing = serde_json::json!([]);
    }

    let existing_files = existing
        .as_array_mut()
        .expect("marketplace_config_files should be normalized to an array");
    for generated_file in generated_files {
        let generated_path = generated_file.get("path").and_then(|value| value.as_str());
        if let Some(path) = generated_path {
            existing_files
                .retain(|file| file.get("path").and_then(|value| value.as_str()) != Some(path));
        }
        existing_files.push(generated_file.clone());
    }
}

fn apply_deploy_bundle(
    project: &mut models::Project,
    form: &forms::project::Deploy,
) -> Result<Option<String>, String> {
    if let Some(environment) = form
        .environment
        .as_ref()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    {
        let environment_value = serde_json::Value::String(environment.to_string());
        upsert_root_field(&mut project.metadata, "environment", &environment_value);
        upsert_root_field(&mut project.request_json, "environment", &environment_value);
    }

    let compose_content = match form
        .config_files
        .as_ref()
        .filter(|value| is_non_empty_json(value))
    {
        Some(config_files) => {
            upsert_root_field(&mut project.metadata, "config_files", config_files);
            upsert_root_field(&mut project.request_json, "config_files", config_files);
            let runtime_config_files = runtime_config_files_from_deploy_config_files(config_files)?;
            merge_marketplace_config_files(&mut project.metadata, &runtime_config_files);
            merge_marketplace_config_files(&mut project.request_json, &runtime_config_files);
            compose_content_from_config_files(config_files)?
        }
        None => None,
    };

    if let Some(config_bundle) = form
        .config_bundle
        .as_ref()
        .filter(|value| is_non_empty_json(value))
    {
        upsert_root_field(&mut project.metadata, "config_bundle", config_bundle);
        upsert_root_field(&mut project.request_json, "config_bundle", config_bundle);

        let artifact_metadata = config_bundle
            .get("manifest")
            .cloned()
            .unwrap_or_else(|| config_bundle.clone());
        upsert_deployment_artifact(&mut project.metadata, "config_bundle", &artifact_metadata);
        upsert_deployment_artifact(
            &mut project.request_json,
            "config_bundle",
            &artifact_metadata,
        );
    }

    Ok(compose_content)
}

async fn load_project_template_version(
    pg_pool: &PgPool,
    project: &models::Project,
) -> Result<Option<models::StackTemplateVersion>, String> {
    let Some(template_id) = project.source_template_id else {
        return Ok(None);
    };

    let versions = db::marketplace::list_versions_by_template(pg_pool, template_id).await?;
    if let Some(target_version) = project.template_version.as_deref() {
        Ok(versions
            .into_iter()
            .find(|version| version.version == target_version))
    } else {
        Ok(versions
            .into_iter()
            .find(|version| version.is_latest.unwrap_or(false)))
    }
}

async fn execute_deployment(
    user: &models::User,
    mut project: models::Project,
    form: &forms::project::Deploy,
    pg_pool: &PgPool,
    mq_manager: &MqManager,
    install_service: &Arc<dyn InstallServiceConnector>,
    vault_client: &VaultClient,
    settings: &Settings,
    cloud: models::Cloud,
    server: models::Server,
) -> Result<(i32, i32)> {
    let deploy_compose = apply_deploy_bundle(&mut project, form)
        .map_err(|err| JsonResponse::<models::Project>::build().bad_request(err))?;
    let template_version = load_project_template_version(pg_pool, &project)
        .await
        .map_err(|err| JsonResponse::<models::Project>::build().internal_server_error(err))?;
    preserve_marketplace_runtime_artifacts(&mut project, template_version.as_ref())
        .map_err(|err| JsonResponse::<models::Project>::build().internal_server_error(err))?;
    sync_runtime_artifact_bundle(settings, &mut project)
        .map_err(|err| JsonResponse::<models::Project>::build().internal_server_error(err))?;

    let id = project.id;
    let dc = DcBuilder::new(project);
    let fc = match deploy_compose {
        Some(compose) => compose,
        None => dc
            .build()
            .map_err(|err| JsonResponse::<models::Project>::build().internal_server_error(err))?,
    };

    let mut new_public_key: Option<String> = None;
    let mut bootstrap_private_key: Option<String> = None;
    let provided_keypair = resolve_provided_ssh_keypair(&form.server)
        .map_err(|msg| JsonResponse::<models::Project>::build().bad_request(msg))?;
    if let Some((_, private_key)) = provided_keypair.as_ref() {
        bootstrap_private_key = Some(private_key.clone());
        tracing::info!(
            "Using provided SSH private key transiently for bootstrap on server {}",
            server.id
        );
    }

    let server = if server.key_status != "active" {
        match VaultClient::generate_ssh_keypair() {
            Ok((public_key, private_key)) => {
                match vault_client
                    .store_ssh_key(&user.id, server.id, &public_key, &private_key)
                    .await
                {
                    Ok(vault_path) => {
                        tracing::info!(
                            "Auto-generated SSH key for server {} (vault_key_path: {})",
                            server.id,
                            vault_path
                        );
                        new_public_key = Some(public_key);
                        db::server::update_ssh_key_status(
                            pg_pool,
                            server.id,
                            Some(vault_path),
                            "active",
                        )
                        .await
                        .unwrap_or_else(|e| {
                            tracing::warn!("Failed to update SSH key status: {}", e);
                            server
                        })
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Failed to store auto-generated SSH key in Vault for server {}: {}",
                            server.id,
                            e
                        );
                        server
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to auto-generate SSH keypair for server {}: {}",
                    server.id,
                    e
                );
                server
            }
        }
    } else {
        match vault_client.fetch_ssh_public_key(&user.id, server.id).await {
            Ok(pk) => {
                tracing::info!(
                    "Fetched existing public key from Vault for server {}",
                    server.id
                );
                new_public_key = Some(pk);
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to fetch public key from Vault for server {}: {}",
                    server.id,
                    e
                );
            }
        }
        server
    };

    let has_existing_ip = server.srv_ip.as_ref().map_or(false, |ip| !ip.is_empty());
    if has_existing_ip && new_public_key.is_none() && server.vault_key_path.is_none() {
        tracing::error!(
            "Cannot deploy to existing server {} (IP: {:?}): SSH key is not available. \
             vault_key_path is None and key generation failed.",
            server.id,
            server.srv_ip,
        );
        return Err(JsonResponse::<models::Project>::build().bad_request(
            "SSH key is not available for this server. \
             Please generate an SSH key first with `stacker ssh-key generate` \
             or re-add your server with SSH credentials.",
        ));
    }

    let json_request = dc.project.metadata.clone();
    let deployment_hash = format!("deployment_{}", Uuid::new_v4());
    let deployment = models::Deployment::new(
        dc.project.id,
        Some(user.id.clone()),
        deployment_hash.clone(),
        String::from("pending"),
        "runc".to_string(),
        json_request,
    );

    let saved_deployment = db::deployment::insert(pg_pool, deployment)
        .await
        .map_err(|_| {
            JsonResponse::<models::Project>::build().internal_server_error("Internal Server Error")
        })?;

    let deployment_id = saved_deployment.id;

    let new_private_key = if let Some(pk) = bootstrap_private_key {
        Some(pk)
    } else if server.vault_key_path.is_some() {
        match vault_client.fetch_ssh_key(&user.id, server.id).await {
            Ok(pk) => {
                tracing::info!(
                    "Fetched SSH private key from Vault for server {}",
                    server.id
                );
                Some(pk)
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to fetch SSH private key from Vault for server {}: {}",
                    server.id,
                    e
                );
                None
            }
        }
    } else {
        None
    };

    let deploy_result = install_service
        .deploy(
            user.id.clone(),
            user.email.clone(),
            id,
            deployment_id,
            deployment_hash.clone(),
            &dc.project,
            cloud,
            server,
            &form.stack,
            form.registry.clone(),
            fc,
            mq_manager,
            new_public_key,
            new_private_key,
        )
        .await
        .map_err(|err| JsonResponse::<models::Project>::build().internal_server_error(err))?;

    if let Some(registry) = form.registry.as_ref() {
        crate::project_app::store_registry_auth_to_vault(
            &deployment_hash,
            registry,
            &settings.vault,
        )
        .await;
    }

    Ok((deploy_result, deployment_id))
}

#[tracing::instrument(name = "Deploy for every user", skip_all)]
#[post("/{id}/deploy")]
pub async fn item(
    user: web::ReqData<Arc<models::User>>,
    path: web::Path<(i32,)>,
    mut form: web::Json<forms::project::Deploy>,
    pg_pool: Data<PgPool>,
    mq_manager: Data<MqManager>,
    sets: Data<Settings>,
    user_service: Data<Arc<dyn UserServiceConnector>>,
    install_service: Data<Arc<dyn InstallServiceConnector>>,
    vault_client: Data<VaultClient>,
) -> Result<impl Responder> {
    let id = path.0;
    tracing::debug!("User {} is deploying project: {}", user.id, id);
    form.cloud.provider = form.cloud.provider.trim().to_string();

    if !form.validate().is_ok() {
        let errors = form.validate().unwrap_err().to_string();
        let err_msg = format!("Invalid form data received {:?}", &errors);
        tracing::debug!(err_msg);

        return Err(JsonResponse::<models::Project>::build().form_error(errors));
    }

    // Validate project
    let project = db::project::fetch(pg_pool.get_ref(), id)
        .await
        .map_err(|err| JsonResponse::<models::Project>::build().internal_server_error(err))
        .and_then(|project| match project {
            Some(project) => Ok(project),
            None => Err(JsonResponse::<models::Project>::build().not_found("not found")),
        })?;

    validate_project_locked_cloud_provider(&project, &form.cloud.provider)
        .map_err(|msg| JsonResponse::<models::Project>::build().bad_request(msg))?;

    let marketplace_template = if let Some(template_id) = project.source_template_id {
        let template = db::marketplace::get_by_id(pg_pool.get_ref(), template_id)
            .await
            .map_err(|err| JsonResponse::<models::Project>::build().internal_server_error(err))?;

        if let Some(template) = template {
            if let Some(required_plan) = template.required_plan_name.as_deref() {
                let has_plan = user_service
                    .user_has_plan(&user.id, required_plan, user.access_token.as_deref())
                    .await
                    .map_err(|err| {
                        tracing::error!("Failed to validate plan: {:?}", err);
                        JsonResponse::<models::Project>::build()
                            .internal_server_error("Failed to validate subscription plan")
                    })?;

                if !has_plan {
                    tracing::warn!(
                        "User {} lacks required plan {} to deploy template {}",
                        user.id,
                        required_plan,
                        template_id
                    );
                    return Err(JsonResponse::<models::Project>::build().forbidden(format!(
                        "You require a '{}' subscription to deploy this template",
                        required_plan
                    )));
                }
            }

            Some(template)
        } else {
            None
        }
    } else {
        None
    };

    let id = project.id;

    form.cloud.user_id = Some(user.id.clone());
    form.cloud.project_id = Some(id);

    // Validate cloud credentials before encrypting/saving.
    // For cloud providers ("htz", "do", "lin", "aws", etc.) we need valid credentials.
    if form.cloud.provider != "own" {
        let token_empty = form
            .cloud
            .cloud_token
            .as_ref()
            .map_or(true, |t| t.is_empty());
        let key_empty = form.cloud.cloud_key.as_ref().map_or(true, |k| k.is_empty());
        let secret_empty = form
            .cloud
            .cloud_secret
            .as_ref()
            .map_or(true, |s| s.is_empty());

        if token_empty && (key_empty || secret_empty) {
            tracing::error!(
                "Deploy rejected: cloud provider '{}' requires credentials but none provided",
                form.cloud.provider
            );
            return Err(JsonResponse::<models::Project>::build().bad_request(
                "Cloud API credentials are required for cloud deployments. \
                 Please provide your cloud provider API token.",
            ));
        }
    }

    // Save cloud credentials if requested, capturing the returned cloud with its DB id
    let cloud_creds: models::Cloud = (&form.cloud).into();

    let cloud_creds = if Some(true) == cloud_creds.save_token {
        db::cloud::insert(pg_pool.get_ref(), cloud_creds.clone())
            .await
            .map_err(|_| {
                JsonResponse::<models::Cloud>::build()
                    .internal_server_error("Internal Server Error")
            })?
    } else {
        cloud_creds
    };

    // Handle server: if server_id provided, update existing; otherwise create new
    let server = if let Some(server_id) = form.server.server_id {
        // Update existing server
        let existing = db::server::fetch(pg_pool.get_ref(), server_id)
            .await
            .map_err(|_| {
                JsonResponse::<models::Server>::build()
                    .internal_server_error("Failed to fetch server")
            })?
            .ok_or_else(|| JsonResponse::<models::Server>::build().not_found("Server not found"))?;

        // Verify ownership
        if existing.user_id != user.id {
            return Err(JsonResponse::<models::Server>::build().not_found("Server not found"));
        }

        let mut server = existing;
        server.disk_type = form.server.disk_type.clone();
        server.region = form.server.region.clone();
        server.server = form.server.server.clone();
        server.zone = form.server.zone.clone().or(server.zone);
        server.os = form.server.os.clone();
        server.project_id = id;
        // Preserve existing srv_ip if form doesn't provide one
        server.srv_ip = form.server.srv_ip.clone().or(server.srv_ip);
        server.ssh_user = form.server.ssh_user.clone().or(server.ssh_user);
        server.ssh_port = form.server.ssh_port.or(server.ssh_port);
        server.name = form.server.name.clone().or(server.name);
        if form.server.connection_mode.is_some() {
            server.connection_mode = form.server.connection_mode.clone().unwrap();
        }

        db::server::update(pg_pool.get_ref(), server)
            .await
            .map_err(|_| {
                JsonResponse::<models::Server>::build()
                    .internal_server_error("Failed to update server")
            })?
    } else {
        // Create new server
        let mut server: models::Server = (&form.server).into();
        server.user_id = user.id.clone();
        server.project_id = id;
        // Set cloud_id from saved cloud credentials (if cloud was saved, it has a DB id)
        if cloud_creds.id != 0 {
            server.cloud_id = Some(cloud_creds.id);
        }

        db::server::insert(pg_pool.get_ref(), server)
            .await
            .map_err(|_| {
                JsonResponse::<models::Server>::build()
                    .internal_server_error("Internal Server Error")
            })?
    };

    validate_reused_cloud_server(&cloud_creds, &server)
        .await
        .map_err(|msg| JsonResponse::<models::Project>::build().bad_request(msg))?;

    ensure_default_status_panel_npm_credentials(
        user.as_ref(),
        &form,
        pg_pool.get_ref(),
        sets.get_ref(),
        &server,
    )
    .await
    .map_err(|err| JsonResponse::<models::Project>::build().internal_server_error(err))?;

    if let Some(template) = marketplace_template.as_ref() {
        let requirements = parse_template_requirements(template)
            .map_err(|msg| JsonResponse::<models::Project>::build().bad_request(msg))?;

        validate_template_target_requirements(
            template,
            &requirements,
            &form.cloud.provider,
            server.os.as_deref(),
        )
        .map_err(|msg| JsonResponse::<models::Project>::build().bad_request(msg))?;

        validate_template_server_capacity_requirements(
            template,
            &requirements,
            &form.cloud.provider,
            if cloud_creds.id != 0 {
                Some(cloud_creds.id)
            } else {
                None
            },
            server.server.as_deref(),
            user.access_token.as_deref(),
        )
        .await
        .map_err(|msg| JsonResponse::<models::Project>::build().bad_request(msg))?;
    }

    let (project_id, deployment_id) = execute_deployment(
        user.as_ref(),
        project,
        &form,
        pg_pool.get_ref(),
        mq_manager.get_ref(),
        install_service.get_ref(),
        vault_client.get_ref(),
        sets.get_ref(),
        cloud_creds,
        server,
    )
    .await?;

    Ok(JsonResponse::<models::Project>::build()
        .set_id(project_id)
        .set_meta(serde_json::json!({ "deployment_id": deployment_id }))
        .ok("Success"))
}
#[tracing::instrument(name = "Deploy, when cloud token is saved", skip_all)]
#[post("/{id}/deploy/{cloud_id}")]
pub async fn saved_item(
    user: web::ReqData<Arc<models::User>>,
    mut form: web::Json<forms::project::Deploy>,
    path: web::Path<(i32, i32)>,
    pg_pool: Data<PgPool>,
    mq_manager: Data<MqManager>,
    sets: Data<Settings>,
    user_service: Data<Arc<dyn UserServiceConnector>>,
    install_service: Data<Arc<dyn InstallServiceConnector>>,
    vault_client: Data<VaultClient>,
) -> Result<impl Responder> {
    let id = path.0;
    let cloud_id = path.1;

    tracing::debug!(
        "User {} is deploying project: {} to cloud: {}",
        user.id,
        id,
        cloud_id
    );

    // Validate project
    let project = db::project::fetch(pg_pool.get_ref(), id)
        .await
        .map_err(|err| JsonResponse::<models::Project>::build().internal_server_error(err))
        .and_then(|project| match project {
            Some(project) => Ok(project),
            None => Err(JsonResponse::<models::Project>::build().not_found("Project not found")),
        })?;

    let marketplace_template = if let Some(template_id) = project.source_template_id {
        let template = db::marketplace::get_by_id(pg_pool.get_ref(), template_id)
            .await
            .map_err(|err| JsonResponse::<models::Project>::build().internal_server_error(err))?;

        if let Some(template) = template {
            if let Some(required_plan) = template.required_plan_name.as_deref() {
                let has_plan = user_service
                    .user_has_plan(&user.id, required_plan, user.access_token.as_deref())
                    .await
                    .map_err(|err| {
                        tracing::error!("Failed to validate plan: {:?}", err);
                        JsonResponse::<models::Project>::build()
                            .internal_server_error("Failed to validate subscription plan")
                    })?;

                if !has_plan {
                    tracing::warn!(
                        "User {} lacks required plan {} to deploy template {}",
                        user.id,
                        required_plan,
                        template_id
                    );
                    return Err(JsonResponse::<models::Project>::build().forbidden(format!(
                        "You require a '{}' subscription to deploy this template",
                        required_plan
                    )));
                }
            }

            Some(template)
        } else {
            None
        }
    } else {
        None
    };

    let id = project.id;

    let cloud = match db::cloud::fetch(pg_pool.get_ref(), cloud_id).await {
        Ok(cloud) => match cloud {
            Some(cloud) => cloud,
            None => {
                return Err(
                    JsonResponse::<models::Project>::build().not_found("No cloud configured")
                );
            }
        },
        Err(_e) => {
            return Err(JsonResponse::<models::Project>::build().not_found("No cloud configured"));
        }
    };

    validate_project_locked_cloud_provider(&project, &cloud.provider)
        .map_err(|msg| JsonResponse::<models::Project>::build().bad_request(msg))?;

    form.cloud.provider = cloud.provider.trim().to_string();

    if !form.validate().is_ok() {
        let errors = form.validate().unwrap_err().to_string();
        let err_msg = format!("Invalid form data received {:?}", &errors);
        tracing::debug!(err_msg);

        return Err(JsonResponse::<models::Project>::build().form_error(errors));
    }

    // Validate that saved cloud credentials can be decrypted before proceeding.
    // When SECURITY_KEY changed or encryption is corrupted, decode() silently
    // returns "" which causes a 401 deep inside the Install Service. Catch it early.
    if cloud.provider != "own" {
        let test_cloud = forms::cloud::CloudForm::decode_model(cloud.clone(), true);
        let token_empty = test_cloud
            .cloud_token
            .as_ref()
            .map_or(true, |t| t.is_empty());
        let key_empty = test_cloud.cloud_key.as_ref().map_or(true, |k| k.is_empty());
        let secret_empty = test_cloud
            .cloud_secret
            .as_ref()
            .map_or(true, |s| s.is_empty());

        // Most providers need cloud_token; AWS needs cloud_key + cloud_secret
        if token_empty && (key_empty || secret_empty) {
            tracing::error!(
                "Cloud credentials for cloud_id={} (provider={}) could not be decrypted. \
                 Token empty: {}, Key empty: {}, Secret empty: {}",
                cloud_id,
                cloud.provider,
                token_empty,
                key_empty,
                secret_empty,
            );
            return Err(JsonResponse::<models::Project>::build().bad_request(
                "Cloud API credentials could not be decrypted. \
                 Please delete and re-add your cloud credentials in Settings → Cloud Providers.",
            ));
        }
    }

    // Handle server: if server_id provided, update existing; otherwise create new
    let server = if let Some(server_id) = form.server.server_id {
        // Update existing server
        let existing = db::server::fetch(pg_pool.get_ref(), server_id)
            .await
            .map_err(|_| {
                JsonResponse::<models::Server>::build()
                    .internal_server_error("Failed to fetch server")
            })?
            .ok_or_else(|| JsonResponse::<models::Server>::build().not_found("Server not found"))?;

        // Verify ownership
        if existing.user_id != user.id {
            return Err(JsonResponse::<models::Server>::build().not_found("Server not found"));
        }

        let mut server = existing;
        server.disk_type = form.server.disk_type.clone();
        server.region = form.server.region.clone();
        server.server = form.server.server.clone();
        server.zone = form.server.zone.clone().or(server.zone);
        server.os = form.server.os.clone();
        server.project_id = id;
        // Preserve existing srv_ip if form doesn't provide one
        server.srv_ip = form.server.srv_ip.clone().or(server.srv_ip);
        server.ssh_user = form.server.ssh_user.clone().or(server.ssh_user);
        server.ssh_port = form.server.ssh_port.or(server.ssh_port);
        server.name = form.server.name.clone().or(server.name);
        if form.server.connection_mode.is_some() {
            server.connection_mode = form.server.connection_mode.clone().unwrap();
        }
        server.cloud_id = Some(cloud_id);

        db::server::update(pg_pool.get_ref(), server)
            .await
            .map_err(|_| {
                JsonResponse::<models::Server>::build()
                    .internal_server_error("Failed to update server")
            })?
    } else {
        // Create new server
        let mut server: models::Server = (&form.server).into();
        server.user_id = user.id.clone();
        server.project_id = id;
        server.cloud_id = Some(cloud_id);

        db::server::insert(pg_pool.get_ref(), server)
            .await
            .map_err(|_| {
                JsonResponse::<models::Server>::build()
                    .internal_server_error("Failed to create server")
            })?
    };

    validate_reused_cloud_server(&cloud, &server)
        .await
        .map_err(|msg| JsonResponse::<models::Project>::build().bad_request(msg))?;

    ensure_default_status_panel_npm_credentials(
        user.as_ref(),
        &form,
        pg_pool.get_ref(),
        sets.get_ref(),
        &server,
    )
    .await
    .map_err(|err| JsonResponse::<models::Project>::build().internal_server_error(err))?;

    if let Some(template) = marketplace_template.as_ref() {
        let requirements = parse_template_requirements(template)
            .map_err(|msg| JsonResponse::<models::Project>::build().bad_request(msg))?;

        validate_template_target_requirements(
            template,
            &requirements,
            &cloud.provider,
            server.os.as_deref(),
        )
        .map_err(|msg| JsonResponse::<models::Project>::build().bad_request(msg))?;

        validate_template_server_capacity_requirements(
            template,
            &requirements,
            &cloud.provider,
            Some(cloud_id),
            server.server.as_deref(),
            user.access_token.as_deref(),
        )
        .await
        .map_err(|msg| JsonResponse::<models::Project>::build().bad_request(msg))?;
    }

    let (project_id, deployment_id) = execute_deployment(
        user.as_ref(),
        project,
        &form,
        pg_pool.get_ref(),
        mq_manager.get_ref(),
        install_service.get_ref(),
        vault_client.get_ref(),
        sets.get_ref(),
        cloud,
        server,
    )
    .await?;

    Ok(JsonResponse::<models::Project>::build()
        .set_id(project_id)
        .set_meta(serde_json::json!({ "deployment_id": deployment_id }))
        .ok("Success"))
}

#[tracing::instrument(name = "Rollback marketplace deployment", skip_all)]
#[post("/{id}/rollback")]
pub async fn rollback(
    user: web::ReqData<Arc<models::User>>,
    path: web::Path<(i32,)>,
    request: web::Json<RollbackRequest>,
    pg_pool: Data<PgPool>,
    mq_manager: Data<MqManager>,
    sets: Data<Settings>,
    install_service: Data<Arc<dyn InstallServiceConnector>>,
    vault_client: Data<VaultClient>,
) -> Result<impl Responder> {
    let id = path.0;

    let mut project = db::project::fetch(pg_pool.get_ref(), id)
        .await
        .map_err(|err| JsonResponse::<models::Project>::build().internal_server_error(err))
        .and_then(|project| match project {
            Some(project) if project.user_id != user.id => {
                Err(JsonResponse::<models::Project>::build().not_found("Project not found"))
            }
            Some(project) => Ok(project),
            None => Err(JsonResponse::<models::Project>::build().not_found("Project not found")),
        })?;

    let template_id = project.source_template_id.ok_or_else(|| {
        JsonResponse::<models::Project>::build()
            .bad_request("Rollback is only available for marketplace projects")
    })?;
    let template = db::marketplace::get_by_id(pg_pool.get_ref(), template_id)
        .await
        .map_err(|err| JsonResponse::<models::Project>::build().internal_server_error(err))?
        .ok_or_else(|| JsonResponse::<models::Project>::build().not_found("Template not found"))?;

    let target_version = db::marketplace::list_versions_by_template(pg_pool.get_ref(), template_id)
        .await
        .map_err(|err| JsonResponse::<models::Project>::build().internal_server_error(err))?
        .into_iter()
        .find(|version| version.version == request.version)
        .ok_or_else(|| {
            JsonResponse::<models::Project>::build().bad_request(format!(
                "Marketplace template version '{}' was not found",
                request.version
            ))
        })?;

    let servers = db::server::fetch_by_project(pg_pool.get_ref(), project.id)
        .await
        .map_err(|err| JsonResponse::<models::Project>::build().internal_server_error(err))?;
    if servers.len() != 1 {
        return Err(JsonResponse::<models::Project>::build()
            .bad_request("Rollback currently supports exactly one attached server"));
    }
    let server = servers.into_iter().next().expect("server count checked");
    let cloud_id = server.cloud_id.ok_or_else(|| {
        JsonResponse::<models::Project>::build()
            .bad_request("Rollback requires a saved cloud configuration on the attached server")
    })?;
    let cloud = db::cloud::fetch(pg_pool.get_ref(), cloud_id)
        .await
        .map_err(|err| JsonResponse::<models::Project>::build().internal_server_error(err))?
        .ok_or_else(|| JsonResponse::<models::Project>::build().not_found("No cloud configured"))?;

    let requirements = parse_template_requirements(&template)
        .map_err(|msg| JsonResponse::<models::Project>::build().bad_request(msg))?;
    validate_template_target_requirements(
        &template,
        &requirements,
        &cloud.provider,
        server.os.as_deref(),
    )
    .map_err(|msg| JsonResponse::<models::Project>::build().bad_request(msg))?;
    validate_template_server_capacity_requirements(
        &template,
        &requirements,
        &cloud.provider,
        Some(cloud_id),
        server.server.as_deref(),
        user.access_token.as_deref(),
    )
    .await
    .map_err(|msg| JsonResponse::<models::Project>::build().bad_request(msg))?;

    let (metadata, template_stack_code) =
        build_rollback_project_payload(target_version.stack_definition.clone())
            .map_err(|msg| JsonResponse::<models::Project>::build().bad_request(msg))?;
    let deploy_form = build_rollback_deploy_form(template_stack_code);

    validate_reused_cloud_server(&cloud, &server)
        .await
        .map_err(|msg| JsonResponse::<models::Project>::build().bad_request(msg))?;

    project.metadata = metadata;
    project.request_json = target_version.stack_definition;
    project.template_version = Some(target_version.version.clone());

    let (project_id, deployment_id) = execute_deployment(
        user.as_ref(),
        project.clone(),
        &deploy_form,
        pg_pool.get_ref(),
        mq_manager.get_ref(),
        install_service.get_ref(),
        vault_client.get_ref(),
        sets.get_ref(),
        cloud,
        server,
    )
    .await?;

    db::project::update(pg_pool.get_ref(), project)
        .await
        .map_err(|err| JsonResponse::<models::Project>::build().internal_server_error(err))?;

    Ok(JsonResponse::<models::Project>::build()
        .set_id(project_id)
        .set_meta(serde_json::json!({ "deployment_id": deployment_id }))
        .ok("Success"))
}

#[cfg(test)]
mod tests {
    use super::{
        apply_deploy_bundle, build_runtime_artifact_bundle, compose_content_from_config_files,
        default_status_panel_npm_credentials, find_matching_hetzner_server, hetzner_server_ip,
        preserve_marketplace_runtime_artifacts, resolve_provided_ssh_keypair,
        should_seed_default_status_panel_npm_credentials, sync_runtime_artifact_bundle,
        validate_min_cpu_requirement, validate_min_disk_requirement, validate_min_ram_requirement,
        HetznerIpv4, HetznerPublicNet, HetznerServer,
    };
    use crate::configuration::Settings;
    use crate::connectors::app_service_catalog::ServerCapacity;
    use crate::forms;
    use crate::models::{self, StackTemplateVersion};
    use serde_json::json;
    use uuid::Uuid;

    fn build_template(slug: &str) -> models::StackTemplate {
        models::StackTemplate {
            id: Uuid::new_v4(),
            creator_user_id: "creator".to_string(),
            creator_name: None,
            name: "Test template".to_string(),
            slug: slug.to_string(),
            short_description: None,
            long_description: None,
            category_code: None,
            product_id: None,
            tags: json!([]),
            tech_stack: json!({}),
            status: "approved".to_string(),
            is_configurable: None,
            view_count: None,
            deploy_count: None,
            required_plan_name: None,
            price: None,
            billing_cycle: None,
            currency: None,
            created_at: None,
            updated_at: None,
            approved_at: None,
            verifications: json!({}),
            infrastructure_requirements: json!({}),
            public_ports: None,
            vendor_url: None,
            version: None,
            changelog: None,
            config_files: json!(null),
            assets: json!(null),
            seed_jobs: json!(null),
            post_deploy_hooks: json!(null),
            update_mode_capabilities: None,
        }
    }

    fn htz_server(name: &str, ip: &str) -> HetznerServer {
        HetznerServer {
            name: name.to_string(),
            status: Some("running".to_string()),
            public_net: Some(HetznerPublicNet {
                ipv4: Some(HetznerIpv4 { ip: ip.to_string() }),
            }),
        }
    }

    #[test]
    fn status_panel_managed_proxy_deploy_seeds_default_npm_credentials() {
        let form = forms::project::Deploy {
            stack: forms::project::Stack {
                extended_features: Some(vec![json!("nginx_proxy_manager")]),
                ..Default::default()
            },
            server: forms::ServerForm {
                connection_mode: Some("status_panel".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };

        assert!(should_seed_default_status_panel_npm_credentials(&form));
    }

    #[test]
    fn deploy_without_status_panel_does_not_seed_default_npm_credentials() {
        let form = forms::project::Deploy {
            stack: forms::project::Stack {
                extended_features: Some(vec![json!("nginx_proxy_manager")]),
                ..Default::default()
            },
            ..Default::default()
        };

        assert!(!should_seed_default_status_panel_npm_credentials(&form));
    }

    #[test]
    fn default_status_panel_npm_credentials_match_cli_status_defaults() {
        let credentials = default_status_panel_npm_credentials();

        assert_eq!(credentials["schema_version"], 1);
        assert_eq!(credentials["host"], "http://nginx-proxy-manager:81");
        assert_eq!(credentials["email"], "admin@example.com");
        assert_eq!(credentials["password"], "changeme");
        assert_eq!(credentials["auth_mode"], "email_password");
    }

    #[test]
    fn hetzner_server_matching_prefers_name_or_ip() {
        let provider_servers = vec![
            htz_server("old-server", "203.0.113.10"),
            htz_server("coolify-current", "203.0.113.42"),
        ];
        let stacker_server = models::Server {
            name: Some("coolify-current".to_string()),
            srv_ip: Some("198.51.100.5".to_string()),
            ..Default::default()
        };

        let matched = find_matching_hetzner_server(&provider_servers, &stacker_server)
            .expect("server should match by name");

        assert_eq!(matched.name, "coolify-current");
        assert_eq!(hetzner_server_ip(matched), Some("203.0.113.42"));
    }

    #[test]
    fn hetzner_server_matching_returns_none_for_deleted_server() {
        let provider_servers = vec![htz_server("different", "203.0.113.10")];
        let stacker_server = models::Server {
            name: Some("deleted-server".to_string()),
            srv_ip: Some("203.0.113.42".to_string()),
            ..Default::default()
        };

        assert!(find_matching_hetzner_server(&provider_servers, &stacker_server).is_none());
    }

    #[test]
    fn min_ram_validation_allows_exact_capacity_match() {
        let template = build_template("exact-match");
        let server_capacity = ServerCapacity {
            id: "t3.medium".to_string(),
            ram_mb: Some(2048),
            cpu_cores: Some(2),
            disk_gb: Some(40),
        };

        assert_eq!(
            Ok(()),
            validate_min_ram_requirement(&template, "t3.medium", 2048, &server_capacity)
        );
    }

    #[test]
    fn min_ram_validation_rejects_lower_capacity() {
        let template = build_template("needs-more-ram");
        let server_capacity = ServerCapacity {
            id: "t3.small".to_string(),
            ram_mb: Some(1024),
            cpu_cores: Some(2),
            disk_gb: Some(20),
        };

        let err = validate_min_ram_requirement(&template, "t3.small", 2048, &server_capacity)
            .expect_err("lower RAM should be rejected");

        assert!(err.contains("minimum RAM requirement"));
        assert!(err.contains("2048"));
        assert!(err.contains("1024"));
    }

    #[test]
    fn min_disk_validation_allows_exact_capacity_match() {
        let template = build_template("disk-exact-match");
        let server_capacity = ServerCapacity {
            id: "t3.medium".to_string(),
            ram_mb: Some(2048),
            cpu_cores: Some(2),
            disk_gb: Some(40),
        };

        assert_eq!(
            Ok(()),
            validate_min_disk_requirement(&template, "t3.medium", 40, &server_capacity)
        );
    }

    #[test]
    fn min_disk_validation_rejects_lower_capacity() {
        let template = build_template("needs-more-disk");
        let server_capacity = ServerCapacity {
            id: "t3.small".to_string(),
            ram_mb: Some(2048),
            cpu_cores: Some(2),
            disk_gb: Some(20),
        };

        let err = validate_min_disk_requirement(&template, "t3.small", 40, &server_capacity)
            .expect_err("lower disk should be rejected");

        assert!(err.contains("minimum disk requirement"));
        assert!(err.contains("40"));
        assert!(err.contains("20"));
    }

    #[test]
    fn min_cpu_validation_allows_exact_capacity_match() {
        let template = build_template("cpu-exact-match");
        let server_capacity = ServerCapacity {
            id: "t3.medium".to_string(),
            ram_mb: Some(4096),
            cpu_cores: Some(4),
            disk_gb: Some(40),
        };

        assert_eq!(
            Ok(()),
            validate_min_cpu_requirement(&template, "t3.medium", 4, &server_capacity)
        );
    }

    #[test]
    fn min_cpu_validation_rejects_lower_capacity() {
        let template = build_template("needs-more-cpu");
        let server_capacity = ServerCapacity {
            id: "t3.small".to_string(),
            ram_mb: Some(4096),
            cpu_cores: Some(2),
            disk_gb: Some(80),
        };

        let err = validate_min_cpu_requirement(&template, "t3.small", 4, &server_capacity)
            .expect_err("lower CPU should be rejected");

        assert!(err.contains("minimum CPU requirement"));
        assert!(err.contains("4"));
        assert!(err.contains("2"));
    }

    #[test]
    fn compose_content_from_config_files_prefers_uploaded_compose() {
        let compose = compose_content_from_config_files(&json!([
            {
                "name": ".env",
                "content": "APP_ENV=production"
            },
            {
                "name": "docker-compose.yml",
                "content": "services:\n  website:\n    image: syncopiaapp/website:latest\n"
            }
        ]))
        .expect("config files should be valid")
        .expect("compose should be discovered");

        assert!(compose.contains("syncopiaapp/website:latest"));
    }

    #[test]
    fn apply_deploy_bundle_merges_runtime_fields_and_returns_compose() {
        let mut project = models::Project::new(
            "user-1".to_string(),
            "syncopia".to_string(),
            json!({
                "custom": {
                    "web": [],
                    "custom_stack_code": "syncopia"
                }
            }),
            json!({
                "custom": {
                    "web": [],
                    "custom_stack_code": "syncopia"
                }
            }),
        );
        let form = forms::project::Deploy {
            environment: Some("prod".to_string()),
            config_files: Some(json!([
                {
                    "name": "docker-compose.yml",
                    "content": "services:\n  website:\n    image: syncopiaapp/website:latest\n",
                    "destination_path": "docker-compose.yml"
                },
                {
                    "name": ".env",
                    "content": "WEBSITE_IMAGE=syncopiaapp/website:latest\n",
                    "destination_path": ".env",
                    "file_mode": "0644"
                }
            ])),
            config_bundle: Some(json!({
                "manifest": {
                    "environment": "prod",
                    "config_files": [
                        {
                            "destination_path": ".env"
                        }
                    ]
                }
            })),
            ..Default::default()
        };

        let compose = apply_deploy_bundle(&mut project, &form)
            .expect("bundle application should succeed")
            .expect("compose should be available");

        assert!(compose.contains("syncopiaapp/website:latest"));
        assert_eq!(project.metadata["environment"], json!("prod"));
        assert_eq!(project.request_json["environment"], json!("prod"));
        assert_eq!(
            project.metadata["config_files"][0]["name"],
            json!("docker-compose.yml")
        );
        assert_eq!(
            project.metadata["custom"]["deployment_artifacts"]["config_bundle"]["environment"],
            json!("prod")
        );
        assert_eq!(
            project.request_json["custom"]["deployment_artifacts"]["config_bundle"]["config_files"]
                [0]["destination_path"],
            json!(".env")
        );
        assert_eq!(
            project.metadata["custom"]["marketplace_config_files"][0]["path"],
            json!(".env")
        );
        assert_eq!(
            project.metadata["custom"]["marketplace_config_files"][0]["content"],
            json!("WEBSITE_IMAGE=syncopiaapp/website:latest\n")
        );
        assert_eq!(
            project.metadata["custom"]["marketplace_config_files"][0]["mode"],
            json!("0644")
        );
    }

    #[test]
    fn preserve_marketplace_runtime_artifacts_backfills_from_request_json_and_version() {
        let mut project = models::Project::new(
            "user-1".to_string(),
            "runtime-artifacts".to_string(),
            json!({
                "custom": {
                    "web": [],
                    "custom_stack_code": "runtime-artifacts"
                }
            }),
            json!({
                "custom": {
                    "web": [],
                    "custom_stack_code": "runtime-artifacts",
                    "marketplace_config_files": [
                        {"path": "config/app.env", "content": "APP_ENV=prod"}
                    ]
                }
            }),
        );
        let latest_version = StackTemplateVersion {
            config_files: json!([
                {"path": "config/app.env", "content": "APP_ENV=prod"}
            ]),
            assets: json!([
                {
                    "storage_provider": "hetzner-object-storage",
                    "bucket": "runtime-assets",
                    "key": "templates/runtime/runtime-bundle.tgz",
                    "filename": "runtime-bundle.tgz",
                    "sha256": "abc123",
                    "size": 42,
                    "content_type": "application/gzip",
                    "decompress": true
                }
            ]),
            seed_jobs: json!([{ "name": "seed-admin" }]),
            post_deploy_hooks: json!([{ "name": "notify" }]),
            ..StackTemplateVersion::default()
        };

        preserve_marketplace_runtime_artifacts(&mut project, Some(&latest_version))
            .expect("artifact preservation should succeed");

        assert_eq!(
            project.metadata["custom"]["marketplace_config_files"][0]["path"],
            json!("config/app.env")
        );
        assert_eq!(
            project.metadata["custom"]["marketplace_assets"][0]["filename"],
            json!("runtime-bundle.tgz")
        );
        assert_eq!(
            project.metadata["custom"]["marketplace_seed_jobs"][0]["name"],
            json!("seed-admin")
        );
        assert_eq!(
            project.metadata["custom"]["marketplace_post_deploy_hooks"][0]["name"],
            json!("notify")
        );
    }

    #[test]
    fn preserve_marketplace_runtime_artifacts_keeps_explicitly_cleared_fields() {
        let mut project = models::Project::new(
            "user-1".to_string(),
            "runtime-artifacts".to_string(),
            json!({
                "custom": {
                    "web": [],
                    "custom_stack_code": "runtime-artifacts",
                    "marketplace_assets": [],
                    "marketplace_seed_jobs": [],
                    "marketplace_post_deploy_hooks": []
                }
            }),
            json!({
                "custom": {
                    "web": [],
                    "custom_stack_code": "runtime-artifacts",
                    "marketplace_config_files": [],
                    "marketplace_assets": [],
                    "marketplace_seed_jobs": [],
                    "marketplace_post_deploy_hooks": []
                }
            }),
        );
        let latest_version = StackTemplateVersion {
            config_files: json!([
                {"path": "config/app.env", "content": "APP_ENV=prod"}
            ]),
            assets: json!([
                {
                    "storage_provider": "hetzner-object-storage",
                    "bucket": "runtime-assets",
                    "key": "templates/runtime/runtime-bundle.tgz",
                    "filename": "runtime-bundle.tgz",
                    "sha256": "abc123",
                    "size": 42,
                    "content_type": "application/gzip",
                    "decompress": true
                }
            ]),
            seed_jobs: json!([{ "name": "seed-admin" }]),
            post_deploy_hooks: json!([{ "name": "notify" }]),
            ..StackTemplateVersion::default()
        };

        preserve_marketplace_runtime_artifacts(&mut project, Some(&latest_version))
            .expect("artifact preservation should succeed");

        assert_eq!(
            project.metadata["custom"]["marketplace_config_files"],
            json!([])
        );
        assert_eq!(project.metadata["custom"]["marketplace_assets"], json!([]));
        assert_eq!(
            project.metadata["custom"]["marketplace_seed_jobs"],
            json!([])
        );
        assert_eq!(
            project.metadata["custom"]["marketplace_post_deploy_hooks"],
            json!([])
        );
    }

    #[test]
    fn build_runtime_artifact_bundle_selects_archive_and_defers_execution() {
        let mut settings = Settings::default();
        settings.marketplace_assets.enabled = true;
        settings.marketplace_assets.endpoint_url = "https://objects.trydirect.test".to_string();
        settings.marketplace_assets.region = "eu-central".to_string();
        settings.marketplace_assets.current_env = "test".to_string();
        settings.marketplace_assets.access_key_id = "marketplace-test-access".to_string();
        settings.marketplace_assets.secret_access_key = "marketplace-test-secret".to_string();
        settings.marketplace_assets.bucket_test = "marketplace-assets-test".to_string();

        let custom = json!({
            "marketplace_config_files": [
                {"path": "config/app.env", "content": "APP_ENV=prod"}
            ],
            "marketplace_assets": [
                {
                    "storage_provider": "hetzner-object-storage",
                    "bucket": "marketplace-assets-test",
                    "key": "templates/runtime/runtime-bundle.tgz",
                    "filename": "runtime-bundle.tgz",
                    "sha256": "abc123",
                    "size": 42,
                    "content_type": "application/gzip",
                    "decompress": true,
                    "fetch_target": "/opt/runtime"
                },
                {
                    "storage_provider": "hetzner-object-storage",
                    "bucket": "marketplace-assets-test",
                    "key": "templates/runtime/logo.png",
                    "filename": "logo.png",
                    "sha256": "def456",
                    "size": 7,
                    "content_type": "image/png",
                    "decompress": false
                }
            ],
            "marketplace_seed_jobs": [
                {"name": "seed-admin"}
            ],
            "marketplace_post_deploy_hooks": [
                {"name": "notify"}
            ]
        });

        let bundle = build_runtime_artifact_bundle(&settings, &custom)
            .expect("bundle build should succeed")
            .expect("bundle metadata should exist");

        assert_eq!(bundle["filename"], json!("runtime-bundle.tgz"));
        assert_eq!(bundle["config_files_count"], json!(1));
        assert_eq!(bundle["seed_jobs_execution"], json!("deferred"));
        assert_eq!(bundle["post_deploy_execution"], json!("deferred"));
        assert!(bundle["download_url"]
            .as_str()
            .expect("download url should exist")
            .contains("runtime-bundle.tgz"));
    }

    #[test]
    fn build_runtime_artifact_bundle_sanitizes_archive_filename() {
        let mut settings = Settings::default();
        settings.marketplace_assets.enabled = true;
        settings.marketplace_assets.endpoint_url = "https://objects.trydirect.test".to_string();
        settings.marketplace_assets.region = "eu-central".to_string();
        settings.marketplace_assets.current_env = "test".to_string();
        settings.marketplace_assets.access_key_id = "marketplace-test-access".to_string();
        settings.marketplace_assets.secret_access_key = "marketplace-test-secret".to_string();
        settings.marketplace_assets.bucket_test = "marketplace-assets-test".to_string();

        let custom = json!({
            "marketplace_assets": [
                {
                    "storage_provider": "hetzner-object-storage",
                    "bucket": "marketplace-assets-test",
                    "key": "templates/runtime/runtime-bundle.tgz",
                    "filename": "../../runtime-bundle.tgz",
                    "sha256": "abc123",
                    "size": 42,
                    "content_type": "application/gzip",
                    "decompress": true
                }
            ]
        });

        let bundle = build_runtime_artifact_bundle(&settings, &custom)
            .expect("bundle build should succeed")
            .expect("bundle metadata should exist");

        assert_eq!(bundle["filename"], json!("runtime-bundle.tgz"));
    }

    #[test]
    fn sync_runtime_artifact_bundle_removes_stale_bundle_when_artifacts_are_cleared() {
        let settings = Settings::default();
        let mut project = models::Project::new(
            "user-1".to_string(),
            "runtime-artifacts".to_string(),
            json!({
                "runtime_artifact_bundle": {
                    "filename": "stale-runtime-bundle.tgz"
                },
                "custom": {
                    "web": [],
                    "custom_stack_code": "runtime-artifacts",
                    "marketplace_config_files": [],
                    "marketplace_assets": [],
                    "marketplace_seed_jobs": [],
                    "marketplace_post_deploy_hooks": []
                }
            }),
            json!({
                "runtime_artifact_bundle": {
                    "filename": "stale-runtime-bundle.tgz"
                },
                "custom": {
                    "web": [],
                    "custom_stack_code": "runtime-artifacts",
                    "marketplace_config_files": [],
                    "marketplace_assets": [],
                    "marketplace_seed_jobs": [],
                    "marketplace_post_deploy_hooks": []
                }
            }),
        );

        sync_runtime_artifact_bundle(&settings, &mut project)
            .expect("runtime artifact sync should succeed");

        assert!(project.metadata.get("runtime_artifact_bundle").is_none());
        assert!(project
            .request_json
            .get("runtime_artifact_bundle")
            .is_none());
    }

    #[test]
    fn resolve_provided_ssh_keypair_derives_public_key_when_missing() {
        let (public_key, private_key) =
            crate::helpers::vault::VaultClient::generate_ssh_keypair().expect("test keypair");
        let form = forms::server::ServerForm {
            ssh_private_key: Some(private_key.clone()),
            ..Default::default()
        };

        let resolved = resolve_provided_ssh_keypair(&form)
            .expect("valid keypair")
            .expect("keypair should be present");

        assert_eq!(resolved.0, public_key);
        assert_eq!(resolved.1.trim(), private_key.trim());
    }
}
