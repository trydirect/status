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

async fn fetch_owned_project_and_app(
    pool: &PgPool,
    user: &models::User,
    project_id: i32,
    app_code: &str,
) -> Result<(models::Project, models::ProjectApp), actix_web::Error> {
    let project = db::project::fetch(pool, project_id)
        .await
        .map_err(JsonResponse::internal_server_error)?
        .ok_or_else(|| JsonResponse::not_found("Project not found"))?;

    if project.user_id != user.id {
        return Err(JsonResponse::not_found("Project not found"));
    }

    let app = db::project_app::fetch_by_project_and_code(pool, project_id, app_code)
        .await
        .map_err(JsonResponse::internal_server_error)?
        .ok_or_else(|| JsonResponse::not_found("App not found"))?;

    Ok((project, app))
}

fn build_vault(
    settings: &crate::configuration::Settings,
) -> Result<VaultService, actix_web::Error> {
    VaultService::from_settings(&settings.vault)
        .map_err(|error| JsonResponse::internal_server_error(error.to_string()))
}

#[tracing::instrument(name = "List service secrets", skip_all)]
#[get("/{project_id}/apps/{code}/secrets")]
pub async fn list(
    user: web::ReqData<Arc<models::User>>,
    path: web::Path<(i32, String)>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    let (project_id, code) = path.into_inner();
    let (_project, _app) =
        fetch_owned_project_and_app(pg_pool.get_ref(), &user, project_id, &code).await?;

    let items: Vec<RemoteSecretMetadataResponse> =
        db::remote_secret::list_service_secrets(pg_pool.get_ref(), &user.id, project_id, &code)
            .await
            .map_err(JsonResponse::internal_server_error)?
            .into_iter()
            .map(Into::into)
            .collect();

    Ok(JsonResponse::build()
        .set_list(items)
        .set_meta(json!({
            "project_id": project_id,
            "app_code": code
        }))
        .ok("OK"))
}

#[tracing::instrument(name = "Get service secret metadata", skip_all)]
#[get("/{project_id}/apps/{code}/secrets/{name}")]
pub async fn item(
    user: web::ReqData<Arc<models::User>>,
    path: web::Path<(i32, String, String)>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    let (project_id, code, name) = path.into_inner();
    let (_project, _app) =
        fetch_owned_project_and_app(pg_pool.get_ref(), &user, project_id, &code).await?;

    let secret = db::remote_secret::fetch_service_secret(
        pg_pool.get_ref(),
        &user.id,
        project_id,
        &code,
        &name,
    )
    .await
    .map_err(JsonResponse::internal_server_error)?
    .ok_or_else(|| JsonResponse::not_found("Secret not found"))?;

    Ok(JsonResponse::build()
        .set_item(RemoteSecretMetadataResponse::from(secret))
        .ok("OK"))
}

#[tracing::instrument(name = "Upsert service secret", skip_all)]
#[put("/{project_id}/apps/{code}/secrets/{name}")]
pub async fn upsert(
    user: web::ReqData<Arc<models::User>>,
    path: web::Path<(i32, String, String)>,
    body: web::Json<UpsertRemoteSecretRequest>,
    pg_pool: web::Data<PgPool>,
    settings: web::Data<crate::configuration::Settings>,
) -> Result<impl Responder> {
    let (project_id, code, name) = path.into_inner();
    let (_project, _app) =
        fetch_owned_project_and_app(pg_pool.get_ref(), &user, project_id, &code).await?;
    body.validate()
        .map_err(|e| JsonResponse::bad_request(e.to_string()))?;

    let vault = build_vault(settings.get_ref())?;
    let vault_path = vault.service_secret_path(&user.id, project_id, &code, &name);
    vault
        .store_secret_value(&vault_path, &body.value)
        .await
        .map_err(|error| JsonResponse::internal_server_error(error.to_string()))?;

    let secret = db::remote_secret::upsert_service_secret(
        pg_pool.get_ref(),
        &user.id,
        project_id,
        &code,
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

#[tracing::instrument(name = "Delete service secret", skip_all)]
#[delete("/{project_id}/apps/{code}/secrets/{name}")]
pub async fn delete(
    user: web::ReqData<Arc<models::User>>,
    path: web::Path<(i32, String, String)>,
    pg_pool: web::Data<PgPool>,
    settings: web::Data<crate::configuration::Settings>,
) -> Result<impl Responder> {
    let (project_id, code, name) = path.into_inner();
    let (_project, _app) =
        fetch_owned_project_and_app(pg_pool.get_ref(), &user, project_id, &code).await?;

    let secret = db::remote_secret::fetch_service_secret(
        pg_pool.get_ref(),
        &user.id,
        project_id,
        &code,
        &name,
    )
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
            "scope": "service"
        }))
        .ok("OK"))
}
