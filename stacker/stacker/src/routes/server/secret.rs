use crate::db;
use crate::forms::{RemoteSecretMetadataResponse, UpsertRemoteSecretRequest};
use crate::helpers::JsonResponse;
use crate::models;
use crate::services::VaultService;
use actix_web::{delete, get, put, web, Responder, Result};
use serde_json::json;
use serde_valid::Validate;
use sqlx::PgPool;
use std::sync::Arc;

const STATUS_PANEL_NPM_CREDENTIALS_SECRET: &str = "npm_credentials";

async fn fetch_owned_server(
    pool: &PgPool,
    user: &models::User,
    server_id: i32,
) -> Result<models::Server, actix_web::Error> {
    let server = db::server::fetch(pool, server_id)
        .await
        .map_err(JsonResponse::internal_server_error)?
        .ok_or_else(|| JsonResponse::not_found("Server not found"))?;

    if server.user_id != user.id {
        return Err(JsonResponse::not_found("Server not found"));
    }

    Ok(server)
}

fn build_vault(
    settings: &crate::configuration::Settings,
) -> Result<VaultService, actix_web::Error> {
    VaultService::from_settings(&settings.vault)
        .map_err(|error| JsonResponse::internal_server_error(error.to_string()))
}

fn uses_status_panel_npm_credentials_contract(name: &str) -> bool {
    name == STATUS_PANEL_NPM_CREDENTIALS_SECRET
}

fn server_secret_vault_path(
    vault: &VaultService,
    user_id: &str,
    server_id: i32,
    name: &str,
) -> String {
    if uses_status_panel_npm_credentials_contract(name) {
        vault.status_panel_npm_credentials_path(server_id)
    } else {
        vault.server_secret_path(user_id, server_id, name)
    }
}

#[tracing::instrument(name = "List server secrets", skip_all)]
#[get("/{server_id}/secrets")]
pub async fn list(
    user: web::ReqData<Arc<models::User>>,
    path: web::Path<(i32,)>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    let server_id = path.into_inner().0;
    let _server = fetch_owned_server(pg_pool.get_ref(), &user, server_id).await?;

    let items: Vec<RemoteSecretMetadataResponse> =
        db::remote_secret::list_server_secrets(pg_pool.get_ref(), &user.id, server_id)
            .await
            .map_err(JsonResponse::internal_server_error)?
            .into_iter()
            .map(Into::into)
            .collect();

    Ok(JsonResponse::build()
        .set_list(items)
        .set_meta(json!({
            "server_id": server_id
        }))
        .ok("OK"))
}

#[tracing::instrument(name = "Get server secret metadata", skip_all)]
#[get("/{server_id}/secrets/{name}")]
pub async fn item(
    user: web::ReqData<Arc<models::User>>,
    path: web::Path<(i32, String)>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    let (server_id, name) = path.into_inner();
    let _server = fetch_owned_server(pg_pool.get_ref(), &user, server_id).await?;

    let secret =
        db::remote_secret::fetch_server_secret(pg_pool.get_ref(), &user.id, server_id, &name)
            .await
            .map_err(JsonResponse::internal_server_error)?
            .ok_or_else(|| JsonResponse::not_found("Secret not found"))?;

    Ok(JsonResponse::build()
        .set_item(RemoteSecretMetadataResponse::from(secret))
        .ok("OK"))
}

#[tracing::instrument(name = "Upsert server secret", skip_all)]
#[put("/{server_id}/secrets/{name}")]
pub async fn upsert(
    user: web::ReqData<Arc<models::User>>,
    path: web::Path<(i32, String)>,
    body: web::Json<UpsertRemoteSecretRequest>,
    pg_pool: web::Data<PgPool>,
    settings: web::Data<crate::configuration::Settings>,
) -> Result<impl Responder> {
    let (server_id, name) = path.into_inner();
    let _server = fetch_owned_server(pg_pool.get_ref(), &user, server_id).await?;
    body.validate()
        .map_err(|e| JsonResponse::bad_request(e.to_string()))?;

    let vault = build_vault(settings.get_ref())?;
    let vault_path = server_secret_vault_path(&vault, &user.id, server_id, &name);
    if uses_status_panel_npm_credentials_contract(&name) {
        let parsed = serde_json::from_str::<serde_json::Value>(&body.value).map_err(|error| {
            JsonResponse::bad_request(format!(
                "npm_credentials body must be valid JSON: {}",
                error
            ))
        })?;
        if !parsed.is_object() {
            return Err(JsonResponse::bad_request(
                "npm_credentials body must be a JSON object".to_string(),
            ));
        }
        vault
            .store_structured_secret_value(&vault_path, &parsed)
            .await
            .map_err(|error| JsonResponse::internal_server_error(error.to_string()))?;
    } else {
        vault
            .store_secret_value(&vault_path, &body.value)
            .await
            .map_err(|error| JsonResponse::internal_server_error(error.to_string()))?;
    }

    let secret = db::remote_secret::upsert_server_secret(
        pg_pool.get_ref(),
        &user.id,
        server_id,
        &name,
        &vault_path,
        &user.id,
        "synced",
    )
    .await
    .map_err(JsonResponse::internal_server_error)?;

    Ok(JsonResponse::build()
        .set_item(RemoteSecretMetadataResponse::from(secret))
        .ok("OK"))
}

#[tracing::instrument(name = "Delete server secret", skip_all)]
#[delete("/{server_id}/secrets/{name}")]
pub async fn delete(
    user: web::ReqData<Arc<models::User>>,
    path: web::Path<(i32, String)>,
    pg_pool: web::Data<PgPool>,
    settings: web::Data<crate::configuration::Settings>,
) -> Result<impl Responder> {
    let (server_id, name) = path.into_inner();
    let _server = fetch_owned_server(pg_pool.get_ref(), &user, server_id).await?;

    let secret =
        db::remote_secret::fetch_server_secret(pg_pool.get_ref(), &user.id, server_id, &name)
            .await
            .map_err(JsonResponse::internal_server_error)?
            .ok_or_else(|| JsonResponse::not_found("Secret not found"))?;

    let vault = build_vault(settings.get_ref())?;
    vault
        .delete_secret_value(&secret.vault_path)
        .await
        .map_err(|error| JsonResponse::internal_server_error(error.to_string()))?;

    db::remote_secret::delete_secret_by_id(pg_pool.get_ref(), secret.id)
        .await
        .map_err(JsonResponse::internal_server_error)?;

    Ok(JsonResponse::<String>::build()
        .set_meta(json!({
            "deleted": true,
            "name": name,
            "scope": "server"
        }))
        .ok("OK"))
}
