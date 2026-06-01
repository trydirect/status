use crate::db;
use crate::helpers::JsonResponse;
use crate::models::{PipeInstance, PipeTemplate, User};
use actix_web::{post, web, Responder, Result};
use pipe_adapter_sdk::PipeAdapterReference;
use serde::Deserialize;
use serde_json::Value as JsonValue;
use sqlx::PgPool;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct CreatePipeTemplateRequest {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub source_app_type: String,
    pub source_endpoint: JsonValue,
    pub target_app_type: String,
    pub target_endpoint: JsonValue,
    #[serde(default)]
    pub target_external_url: Option<String>,
    pub field_mapping: JsonValue,
    #[serde(default)]
    pub config: Option<JsonValue>,
    #[serde(default)]
    pub is_public: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct CreatePipeInstanceRequest {
    #[serde(default)]
    pub deployment_hash: Option<String>,
    #[serde(default)]
    pub source_adapter: Option<PipeAdapterReference>,
    pub source_container: String,
    #[serde(default)]
    pub target_adapter: Option<PipeAdapterReference>,
    #[serde(default)]
    pub target_container: Option<String>,
    #[serde(default)]
    pub target_url: Option<String>,
    #[serde(default)]
    pub template_id: Option<uuid::Uuid>,
    #[serde(default)]
    pub field_mapping_override: Option<JsonValue>,
    #[serde(default)]
    pub config_override: Option<JsonValue>,
}

#[tracing::instrument(name = "Create pipe template", skip_all)]
#[post("/templates")]
pub async fn create_template_handler(
    user: web::ReqData<Arc<User>>,
    req: web::Json<CreatePipeTemplateRequest>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    if req.name.trim().is_empty() {
        return Err(JsonResponse::<()>::build().bad_request("name is required"));
    }
    if req.source_app_type.trim().is_empty() {
        return Err(JsonResponse::<()>::build().bad_request("source_app_type is required"));
    }
    if req.target_app_type.trim().is_empty() {
        return Err(JsonResponse::<()>::build().bad_request("target_app_type is required"));
    }

    let mut template = PipeTemplate::new(
        req.name.trim().to_string(),
        req.source_app_type.trim().to_string(),
        req.source_endpoint.clone(),
        req.target_app_type.trim().to_string(),
        req.target_endpoint.clone(),
        req.field_mapping.clone(),
        user.id.clone(),
    );

    if let Some(desc) = &req.description {
        template = template.with_description(desc.clone());
    }
    if let Some(url) = &req.target_external_url {
        template = template.with_external_url(url.clone());
    }
    if let Some(config) = &req.config {
        template = template.with_config(config.clone());
    }
    if let Some(is_public) = req.is_public {
        template = template.with_public(is_public);
    }

    let saved = db::pipe::insert_template(pg_pool.get_ref(), &template)
        .await
        .map_err(|err| {
            tracing::error!("Failed to create pipe template: {}", err);
            JsonResponse::<()>::build().internal_server_error(err)
        })?;

    tracing::info!(
        template_id = %saved.id,
        name = %saved.name,
        "Pipe template created by user {}",
        user.id
    );

    Ok(JsonResponse::build()
        .set_item(Some(saved))
        .created("Pipe template created successfully"))
}

#[tracing::instrument(name = "Create pipe instance", skip_all)]
#[post("/instances")]
pub async fn create_instance_handler(
    user: web::ReqData<Arc<User>>,
    req: web::Json<CreatePipeInstanceRequest>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    // Reject explicitly-provided but empty deployment_hash (distinct from omitting the field)
    if let Some(hash) = &req.deployment_hash {
        if hash.trim().is_empty() {
            return Err(JsonResponse::<()>::build().bad_request("deployment_hash cannot be empty"));
        }
    }

    let deployment_hash = req
        .deployment_hash
        .as_deref()
        .map(|h| h.trim())
        .filter(|h| !h.is_empty());

    if req.source_container.trim().is_empty() {
        return Err(JsonResponse::<()>::build().bad_request("source_container is required"));
    }
    if req.target_container.is_none() && req.target_url.is_none() && req.target_adapter.is_none() {
        return Err(JsonResponse::<()>::build()
            .bad_request("either target_container, target_url, or target_adapter is required"));
    }

    // For remote pipes, verify deployment belongs to the requesting user
    if let Some(hash) = deployment_hash {
        let deployment = db::deployment::fetch_by_deployment_hash(pg_pool.get_ref(), hash)
            .await
            .map_err(|err| JsonResponse::<()>::build().internal_server_error(err))?;

        match &deployment {
            Some(d) if d.user_id.as_deref() == Some(&user.id) => {}
            _ => {
                return Err(JsonResponse::<()>::build().not_found("Deployment not found"));
            }
        }
    }

    // Verify template exists if provided
    if let Some(template_id) = &req.template_id {
        let template = db::pipe::get_template(pg_pool.get_ref(), template_id)
            .await
            .map_err(|err| {
                tracing::error!("Failed to lookup template: {}", err);
                JsonResponse::<()>::build().internal_server_error(err)
            })?;
        if template.is_none() {
            return Err(JsonResponse::<()>::build().bad_request("template_id not found"));
        }
    }

    let mut instance = match deployment_hash {
        Some(hash) => PipeInstance::new(
            hash.to_string(),
            req.source_container.trim().to_string(),
            user.id.clone(),
        ),
        None => PipeInstance::new_local(req.source_container.trim().to_string(), user.id.clone()),
    };

    if let Some(template_id) = req.template_id {
        instance = instance.with_template(template_id);
    }
    if let Some(adapter) = &req.source_adapter {
        let adapter = serde_json::to_value(adapter)
            .map_err(|err| JsonResponse::<()>::build().internal_server_error(err.to_string()))?;
        instance = instance.with_source_adapter(adapter);
    }
    if let Some(adapter) = &req.target_adapter {
        let adapter = serde_json::to_value(adapter)
            .map_err(|err| JsonResponse::<()>::build().internal_server_error(err.to_string()))?;
        instance = instance.with_target_adapter(adapter);
    }
    if let Some(target) = &req.target_container {
        instance = instance.with_target_container(target.clone());
    }
    if let Some(url) = &req.target_url {
        instance = instance.with_target_url(url.clone());
    }
    if let Some(mapping) = &req.field_mapping_override {
        instance = instance.with_field_mapping_override(mapping.clone());
    }
    if let Some(config) = &req.config_override {
        instance = instance.with_config_override(config.clone());
    }

    let saved = db::pipe::insert_instance(pg_pool.get_ref(), &instance)
        .await
        .map_err(|err| {
            tracing::error!("Failed to create pipe instance: {}", err);
            JsonResponse::<()>::build().internal_server_error(err)
        })?;

    tracing::info!(
        instance_id = %saved.id,
        deployment_hash = ?saved.deployment_hash,
        is_local = saved.is_local,
        "Pipe instance created by user {}",
        user.id
    );

    Ok(JsonResponse::build()
        .set_item(Some(saved))
        .created("Pipe instance created successfully"))
}
