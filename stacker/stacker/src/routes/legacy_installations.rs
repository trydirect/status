use sqlx::PgPool;

use crate::configuration::Settings;
use crate::connectors::config::UserServiceConfig;
use crate::connectors::user_service::install::{Installation, InstallationDetails};
use crate::connectors::user_service::UserServiceClient;
use crate::helpers::JsonResponse;
use crate::{db, models};

pub enum OwnedDeployment {
    Native(models::Deployment),
    Legacy(InstallationDetails),
}

fn build_user_service_client(settings: &Settings) -> Option<UserServiceClient> {
    let config = settings
        .connectors
        .user_service
        .clone()
        .unwrap_or_else(UserServiceConfig::default);

    if config.enabled {
        return Some(UserServiceClient::new(config));
    }

    if settings.user_service_url.trim().is_empty() {
        return None;
    }

    let mut fallback = UserServiceConfig::default();
    fallback.base_url = settings.user_service_url.trim_end_matches('/').to_string();
    Some(UserServiceClient::new(fallback))
}

fn user_access_token(user: &models::User) -> Option<&str> {
    user.access_token
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn map_installation_error(error: impl std::fmt::Display) -> actix_web::Error {
    JsonResponse::<String>::internal_server_error(error.to_string())
}

pub fn legacy_target_name(installation: &InstallationDetails) -> String {
    installation
        .domain
        .clone()
        .or_else(|| installation.stack_code.clone())
        .or_else(|| installation.deployment_hash.clone())
        .or_else(|| {
            installation
                .id
                .map(|id| format!("legacy-installation-{}", id))
        })
        .unwrap_or_else(|| "legacy-installation".to_string())
}

pub fn infer_legacy_target(installation: &InstallationDetails) -> String {
    if installation
        .cloud
        .as_ref()
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
    {
        "cloud".to_string()
    } else if installation
        .server_ip
        .as_ref()
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
    {
        "server".to_string()
    } else {
        "local".to_string()
    }
}

pub async fn resolve_owned_deployment_by_hash(
    pg_pool: &PgPool,
    settings: &Settings,
    user: &models::User,
    deployment_hash: &str,
) -> Result<OwnedDeployment, actix_web::Error> {
    let deployment = db::deployment::fetch_by_deployment_hash(pg_pool, deployment_hash)
        .await
        .map_err(JsonResponse::<String>::internal_server_error)?;

    if let Some(deployment) = deployment {
        if deployment.user_id.as_deref() == Some(&user.id) {
            return Ok(OwnedDeployment::Native(deployment));
        }
        return Err(JsonResponse::<String>::not_found("Deployment not found"));
    }

    let token = user_access_token(user)
        .ok_or_else(|| JsonResponse::<String>::not_found("Deployment not found"))?;
    let client = build_user_service_client(settings)
        .ok_or_else(|| JsonResponse::<String>::not_found("Deployment not found"))?;

    match client
        .get_installation_by_hash(token, deployment_hash)
        .await
    {
        Ok(installation) => Ok(OwnedDeployment::Legacy(installation)),
        Err(err) => {
            tracing::warn!(
                error = %err,
                deployment_hash = deployment_hash,
                "Direct legacy deployment lookup failed; falling back to installation list"
            );
            let installation = client
                .list_installations(token)
                .await
                .map_err(map_installation_error)?
                .into_iter()
                .find(|item| item.deployment_hash.as_deref() == Some(deployment_hash))
                .ok_or_else(|| JsonResponse::<String>::not_found("Deployment not found"))?;

            hydrate_legacy_installation(&client, token, installation).await
        }
    }
}

pub async fn resolve_owned_deployment_for_handoff(
    pg_pool: &PgPool,
    settings: &Settings,
    user: &models::User,
    deployment_id: Option<i64>,
    deployment_hash: Option<&str>,
) -> Result<OwnedDeployment, actix_web::Error> {
    if let Some(deployment_id) = deployment_id {
        if let Ok(native_id) = i32::try_from(deployment_id) {
            let deployment = db::deployment::fetch(pg_pool, native_id)
                .await
                .map_err(JsonResponse::<String>::internal_server_error)?;

            if let Some(deployment) = deployment {
                if deployment.user_id.as_deref() == Some(&user.id) {
                    return Ok(OwnedDeployment::Native(deployment));
                }
                return Err(JsonResponse::<String>::not_found("Deployment not found"));
            }
        }

        let token = user_access_token(user)
            .ok_or_else(|| JsonResponse::<String>::not_found("Deployment not found"))?;
        let client = build_user_service_client(settings)
            .ok_or_else(|| JsonResponse::<String>::not_found("Deployment not found"))?;

        let installation = client
            .get_installation(token, deployment_id)
            .await
            .map_err(map_installation_error)?;

        if let Some(expected_hash) = deployment_hash {
            if installation.deployment_hash.as_deref() != Some(expected_hash) {
                return Err(JsonResponse::<String>::not_found("Deployment not found"));
            }
        }

        return Ok(OwnedDeployment::Legacy(installation));
    }

    let deployment_hash = deployment_hash.ok_or_else(|| {
        JsonResponse::<String>::bad_request("deployment_id or deployment_hash is required")
    })?;
    resolve_owned_deployment_by_hash(pg_pool, settings, user, deployment_hash).await
}

async fn hydrate_legacy_installation(
    client: &UserServiceClient,
    token: &str,
    installation: Installation,
) -> Result<OwnedDeployment, actix_web::Error> {
    if let Some(installation_id) = installation.id {
        return client
            .get_installation(token, installation_id)
            .await
            .map(OwnedDeployment::Legacy)
            .map_err(map_installation_error);
    }

    Ok(OwnedDeployment::Legacy(InstallationDetails {
        id: installation.id,
        stack_code: installation.stack_code,
        status: installation.status,
        cloud: installation.cloud,
        deployment_hash: installation.deployment_hash,
        domain: installation.domain,
        server_ip: None,
        apps: None,
        agent_config: None,
        created_at: installation.created_at,
        updated_at: installation.updated_at,
    }))
}
