use crate::configuration::Settings;
use crate::connectors::{MarketplaceWebhookSender, WebhookSenderConfig};
use crate::db;
use crate::helpers::JsonResponse;
use crate::models;
use crate::services;
use actix_web::{get, post, put, web, Responder, Result};
use sqlx::PgPool;
use std::sync::Arc;
use tracing::Instrument;
use uuid;

#[derive(Debug, serde::Deserialize)]
pub struct AnalyticsQuery {
    pub period: Option<String>,
    #[serde(rename = "startDate")]
    pub start_date: Option<String>,
    #[serde(rename = "endDate")]
    pub end_date: Option<String>,
    #[serde(rename = "templateId")]
    pub template_id: Option<String>,
}

fn build_vendor_profile_status_item(
    creator_user_id: &str,
    template_id: Option<uuid::Uuid>,
    vendor_profile: models::MarketplaceVendorProfile,
) -> serde_json::Value {
    let payout_ready = vendor_profile.verification_status == "verified"
        && vendor_profile.onboarding_status == "completed"
        && vendor_profile.payouts_enabled
        && vendor_profile.payout_provider.is_some();

    let mut item = serde_json::json!({
        "creator_user_id": creator_user_id,
        "payout_ready": payout_ready,
        "vendor_profile": {
            "creator_user_id": vendor_profile.creator_user_id,
            "verification_status": vendor_profile.verification_status,
            "onboarding_status": vendor_profile.onboarding_status,
            "payouts_enabled": vendor_profile.payouts_enabled,
            "payout_provider": vendor_profile.payout_provider,
            "metadata": vendor_profile.metadata,
            "created_at": vendor_profile.created_at,
            "updated_at": vendor_profile.updated_at
        }
    });

    if let Some(template_id) = template_id {
        item["template_id"] = serde_json::Value::String(template_id.to_string());
    }

    item
}

#[derive(Debug, serde::Deserialize)]
pub struct CreateTemplateRequest {
    pub name: String,
    pub slug: String,
    pub short_description: Option<String>,
    pub long_description: Option<String>,
    pub category_code: Option<String>,
    pub tags: Option<serde_json::Value>,
    pub tech_stack: Option<serde_json::Value>,
    pub version: Option<String>,
    pub stack_definition: Option<serde_json::Value>,
    pub definition_format: Option<String>,
    pub changelog: Option<String>,
    pub config_files: Option<serde_json::Value>,
    pub assets: Option<serde_json::Value>,
    pub seed_jobs: Option<serde_json::Value>,
    pub post_deploy_hooks: Option<serde_json::Value>,
    pub update_mode_capabilities: Option<serde_json::Value>,
    pub confirm_no_secrets: Option<bool>,
    /// Pricing: "free", "one_time", or "subscription"
    pub plan_type: Option<String>,
    pub required_plan_name: Option<String>,
    /// Price amount (e.g. 9.99). Ignored when plan_type is "free"
    pub price: Option<f64>,
    /// ISO 4217 currency code, default "USD"
    pub currency: Option<String>,
    pub infrastructure_requirements: Option<serde_json::Value>,
    /// Public ports: [{"name": "web", "port": 8080}, ...]
    pub public_ports: Option<serde_json::Value>,
    /// Vendor's page URL
    pub vendor_url: Option<String>,
}

#[tracing::instrument(name = "Create draft template", skip_all)]
#[post("")]
pub async fn create_handler(
    user: web::ReqData<Arc<models::User>>,
    pg_pool: web::Data<PgPool>,
    body: web::Json<CreateTemplateRequest>,
) -> Result<impl Responder> {
    let req = body.into_inner();

    let tags = req.tags.unwrap_or(serde_json::json!([]));
    let tech_stack = req.tech_stack.unwrap_or(serde_json::json!({}));
    let infrastructure_requirements = req
        .infrastructure_requirements
        .unwrap_or(serde_json::json!({}));
    let config_files = req.config_files.clone().unwrap_or(serde_json::json!([]));
    let assets = req.assets.clone().unwrap_or(serde_json::json!([]));
    let seed_jobs = req.seed_jobs.clone().unwrap_or(serde_json::json!([]));
    let post_deploy_hooks = req
        .post_deploy_hooks
        .clone()
        .unwrap_or(serde_json::json!([]));
    let update_mode_capabilities = req.update_mode_capabilities.clone();

    let creator_name = format!("{} {}", user.first_name, user.last_name);

    // Normalize pricing: plan_type "free" forces price to 0
    let billing_cycle = req.plan_type.unwrap_or_else(|| "free".to_string());
    let price = if billing_cycle == "free" {
        0.0
    } else {
        req.price.unwrap_or(0.0)
    };
    let currency = req.currency.unwrap_or_else(|| "USD".to_string());

    let existing = db::marketplace::get_by_slug_and_user(pg_pool.get_ref(), &req.slug, &user.id)
        .await
        .map_err(|err| JsonResponse::<models::StackTemplate>::build().internal_server_error(err))?;

    let template = if let Some(existing_template) = existing {
        // Update existing template
        tracing::info!("Updating existing template with slug: {}", req.slug);
        let updated = db::marketplace::update_metadata(
            pg_pool.get_ref(),
            &existing_template.id,
            Some(&req.name),
            req.short_description.as_deref(),
            req.long_description.as_deref(),
            req.category_code.as_deref(),
            Some(tags.clone()),
            Some(tech_stack.clone()),
            Some(infrastructure_requirements.clone()),
            Some(price),
            Some(billing_cycle.as_str()),
            req.required_plan_name.as_deref(),
            Some(currency.as_str()),
            req.public_ports.clone(),
            req.vendor_url.as_deref(),
        )
        .await
        .map_err(|err| JsonResponse::<models::StackTemplate>::build().internal_server_error(err))?;

        if !updated {
            return Err(JsonResponse::<models::StackTemplate>::build()
                .internal_server_error("Failed to update template"));
        }

        // Fetch updated template
        db::marketplace::get_by_id(pg_pool.get_ref(), existing_template.id)
            .await
            .map_err(|err| {
                JsonResponse::<models::StackTemplate>::build().internal_server_error(err)
            })?
            .ok_or_else(|| {
                JsonResponse::<models::StackTemplate>::build()
                    .not_found("Template not found after update")
            })?
    } else {
        // Create new template
        db::marketplace::create_draft(
            pg_pool.get_ref(),
            &user.id,
            Some(&creator_name),
            &req.name,
            &req.slug,
            req.short_description.as_deref(),
            req.long_description.as_deref(),
            req.category_code.as_deref(),
            tags,
            tech_stack,
            infrastructure_requirements,
            price,
            &billing_cycle,
            req.required_plan_name.as_deref(),
            &currency,
            req.public_ports.clone(),
            req.vendor_url.as_deref(),
        )
        .await
        .map_err(|err| match err {
            db::marketplace::CreateDraftError::DuplicateSlug { slug } => {
                JsonResponse::<models::StackTemplate>::build().conflict(format!(
                    "Template slug '{}' is already in use. Please choose a different slug.",
                    slug
                ))
            }
            db::marketplace::CreateDraftError::Internal => {
                JsonResponse::<models::StackTemplate>::build()
                    .internal_server_error("Internal Server Error")
            }
        })?
    };

    // Optional initial version
    if let Some(def) = req.stack_definition {
        let version = req.version.unwrap_or("1.0.0".to_string());
        db::marketplace::upsert_latest_version(
            pg_pool.get_ref(),
            &template.id,
            &version,
            def,
            req.definition_format.as_deref(),
            req.changelog.as_deref(),
            config_files,
            assets,
            seed_jobs,
            post_deploy_hooks,
            update_mode_capabilities,
        )
        .await
        .map_err(|err| JsonResponse::<models::StackTemplate>::build().bad_request(err))?;
    }

    Ok(JsonResponse::build()
        .set_item(Some(template))
        .created("Created"))
}

#[derive(Debug, serde::Deserialize)]
pub struct UpdateTemplateRequest {
    pub name: Option<String>,
    pub short_description: Option<String>,
    pub long_description: Option<String>,
    pub category_code: Option<String>,
    pub tags: Option<serde_json::Value>,
    pub tech_stack: Option<serde_json::Value>,
    pub version: Option<String>,
    pub stack_definition: Option<serde_json::Value>,
    pub definition_format: Option<String>,
    pub changelog: Option<String>,
    pub config_files: Option<serde_json::Value>,
    pub assets: Option<serde_json::Value>,
    pub seed_jobs: Option<serde_json::Value>,
    pub post_deploy_hooks: Option<serde_json::Value>,
    pub update_mode_capabilities: Option<serde_json::Value>,
    pub confirm_no_secrets: Option<bool>,
    pub infrastructure_requirements: Option<serde_json::Value>,
    pub plan_type: Option<String>,
    pub required_plan_name: Option<String>,
    pub price: Option<f64>,
    pub currency: Option<String>,
    pub public_ports: Option<serde_json::Value>,
    pub vendor_url: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
pub struct PresignAssetUploadRequest {
    pub filename: String,
    pub sha256: String,
    pub size: i64,
    pub content_type: Option<String>,
    pub mount_path: Option<String>,
    pub fetch_target: Option<String>,
    pub decompress: Option<bool>,
    pub executable: Option<bool>,
    pub immutable: Option<bool>,
}

#[derive(Debug, serde::Deserialize)]
pub struct FinalizeAssetRequest {
    pub storage_provider: Option<String>,
    pub bucket: String,
    pub key: String,
    pub filename: String,
    pub sha256: String,
    pub size: i64,
    pub content_type: Option<String>,
    pub mount_path: Option<String>,
    pub fetch_target: Option<String>,
    pub decompress: Option<bool>,
    pub executable: Option<bool>,
    pub immutable: Option<bool>,
}

#[derive(Debug, serde::Deserialize)]
pub struct PresignAssetDownloadRequest {
    pub key: String,
}

#[derive(Debug, serde::Deserialize)]
pub struct SubmitTemplateRequest {
    pub confirm_no_secrets: Option<bool>,
}

fn ensure_no_secrets_confirmation(confirmed: Option<bool>) -> Result<(), actix_web::Error> {
    if confirmed.unwrap_or(false) {
        Ok(())
    } else {
        Err(JsonResponse::<serde_json::Value>::build().bad_request(
            "Confirm that the template contains no secrets or API keys before submitting",
        ))
    }
}

fn ensure_template_owner(
    template: &models::StackTemplate,
    user_id: &str,
) -> Result<(), actix_web::Error> {
    if template.creator_user_id == user_id {
        Ok(())
    } else {
        Err(JsonResponse::<serde_json::Value>::build().forbidden("Forbidden"))
    }
}

fn ensure_template_assets_editable(
    template: &models::StackTemplate,
) -> Result<(), actix_web::Error> {
    if matches!(
        template.status.as_str(),
        "draft" | "rejected" | "needs_changes"
    ) {
        Ok(())
    } else {
        Err(JsonResponse::<serde_json::Value>::build()
            .bad_request("Template assets are read-only in the current status"))
    }
}

fn map_storage_error(error: services::MarketplaceAssetStorageError) -> actix_web::Error {
    match error {
        services::MarketplaceAssetStorageError::NotConfigured => {
            JsonResponse::<serde_json::Value>::build()
                .internal_server_error("Marketplace asset storage is not configured")
        }
        other => JsonResponse::<serde_json::Value>::build().bad_request(other.to_string()),
    }
}

fn normalize_optional_text(value: Option<String>) -> Option<String> {
    value.and_then(|entry| {
        let trimmed = entry.trim().to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    })
}

fn build_marketplace_asset(
    request: FinalizeAssetRequest,
) -> Result<models::MarketplaceAsset, actix_web::Error> {
    if request.size <= 0 {
        return Err(JsonResponse::<serde_json::Value>::build()
            .bad_request("Asset size must be a positive integer"));
    }

    let bucket = request.bucket.trim().to_string();
    let key = request.key.trim().to_string();
    let filename = request.filename.trim().to_string();
    let sha256 = request.sha256.trim().to_string();

    if bucket.is_empty() || key.is_empty() || filename.is_empty() || sha256.is_empty() {
        return Err(JsonResponse::<serde_json::Value>::build()
            .bad_request("bucket, key, filename, and sha256 are required"));
    }

    Ok(models::MarketplaceAsset {
        storage_provider: request
            .storage_provider
            .unwrap_or_else(|| services::MARKETPLACE_ASSET_STORAGE_PROVIDER.to_string()),
        bucket,
        key,
        filename,
        sha256,
        size: request.size,
        content_type: normalize_optional_text(request.content_type)
            .unwrap_or_else(|| "application/octet-stream".to_string()),
        mount_path: normalize_optional_text(request.mount_path),
        fetch_target: normalize_optional_text(request.fetch_target),
        decompress: request.decompress.unwrap_or(false),
        executable: request.executable.unwrap_or(false),
        immutable: request.immutable.unwrap_or(true),
    })
}

#[tracing::instrument(name = "Update template metadata", skip_all)]
#[put("/{id}")]
pub async fn update_handler(
    user: web::ReqData<Arc<models::User>>,
    path: web::Path<(String,)>,
    pg_pool: web::Data<PgPool>,
    body: web::Json<UpdateTemplateRequest>,
) -> Result<web::Json<crate::helpers::json::JsonResponse<serde_json::Value>>> {
    let id = uuid::Uuid::parse_str(&path.into_inner().0)
        .map_err(|_| actix_web::error::ErrorBadRequest("Invalid UUID"))?;

    // Ownership check
    let owner_id: String = sqlx::query_scalar!(
        r#"SELECT creator_user_id FROM stack_template WHERE id = $1"#,
        id
    )
    .fetch_one(pg_pool.get_ref())
    .await
    .map_err(|_| JsonResponse::<serde_json::Value>::build().not_found("Not Found"))?;

    if owner_id != user.id {
        return Err(JsonResponse::<serde_json::Value>::build().forbidden("Forbidden"));
    }

    let req = body.into_inner();
    let infrastructure_requirements = req.infrastructure_requirements.clone();

    // Normalize pricing: plan_type "free" forces price to 0
    let price = match req.plan_type.as_deref() {
        Some("free") => Some(0.0),
        _ => req.price,
    };

    let updated = db::marketplace::update_metadata(
        pg_pool.get_ref(),
        &id,
        req.name.as_deref(),
        req.short_description.as_deref(),
        req.long_description.as_deref(),
        req.category_code.as_deref(),
        req.tags,
        req.tech_stack,
        infrastructure_requirements,
        price,
        req.plan_type.as_deref(),
        req.required_plan_name.as_deref(),
        req.currency.as_deref(),
        req.public_ports.clone(),
        req.vendor_url.as_deref(),
    )
    .await
    .map_err(|err| JsonResponse::<serde_json::Value>::build().bad_request(err))?;

    if req.stack_definition.is_some()
        || req.version.is_some()
        || req.changelog.is_some()
        || req.config_files.is_some()
        || req.assets.is_some()
        || req.seed_jobs.is_some()
        || req.post_deploy_hooks.is_some()
        || req.update_mode_capabilities.is_some()
    {
        let latest_version = db::marketplace::get_latest_version_by_template(pg_pool.get_ref(), id)
            .await
            .map_err(|err| JsonResponse::<serde_json::Value>::build().bad_request(err))?;
        let current_version = latest_version.unwrap_or_default();
        let version = req
            .version
            .clone()
            .unwrap_or_else(|| current_version.version.clone());
        let stack_definition = req
            .stack_definition
            .clone()
            .unwrap_or_else(|| current_version.stack_definition.clone());
        let config_files = req
            .config_files
            .clone()
            .unwrap_or_else(|| current_version.config_files.clone());
        let assets = req
            .assets
            .clone()
            .unwrap_or_else(|| current_version.assets.clone());
        let seed_jobs = req
            .seed_jobs
            .clone()
            .unwrap_or_else(|| current_version.seed_jobs.clone());
        let post_deploy_hooks = req
            .post_deploy_hooks
            .clone()
            .unwrap_or_else(|| current_version.post_deploy_hooks.clone());
        let definition_format = req
            .definition_format
            .as_deref()
            .or(current_version.definition_format.as_deref());
        let changelog = req
            .changelog
            .as_deref()
            .or(current_version.changelog.as_deref());
        let update_mode_capabilities = req
            .update_mode_capabilities
            .clone()
            .or(current_version.update_mode_capabilities.clone());

        db::marketplace::upsert_latest_version(
            pg_pool.get_ref(),
            &id,
            if version.is_empty() {
                "1.0.0"
            } else {
                version.as_str()
            },
            stack_definition,
            definition_format,
            changelog,
            config_files,
            assets,
            seed_jobs,
            post_deploy_hooks,
            update_mode_capabilities,
        )
        .await
        .map_err(|err| JsonResponse::<serde_json::Value>::build().bad_request(err))?;
    }

    if updated {
        Ok(JsonResponse::<serde_json::Value>::build().ok("Updated"))
    } else {
        Err(JsonResponse::<serde_json::Value>::build().not_found("Not Found"))
    }
}

#[tracing::instrument(name = "Presign marketplace asset upload", skip_all)]
#[post("/{id}/assets/presign")]
pub async fn presign_asset_upload_handler(
    user: web::ReqData<Arc<models::User>>,
    path: web::Path<(String,)>,
    pg_pool: web::Data<PgPool>,
    settings: web::Data<Settings>,
    body: web::Json<PresignAssetUploadRequest>,
) -> Result<web::Json<crate::helpers::json::JsonResponse<serde_json::Value>>> {
    let id = uuid::Uuid::parse_str(&path.into_inner().0)
        .map_err(|_| actix_web::error::ErrorBadRequest("Invalid UUID"))?;

    let template = db::marketplace::get_by_id(pg_pool.get_ref(), id)
        .await
        .map_err(|err| JsonResponse::<serde_json::Value>::build().internal_server_error(err))?
        .ok_or_else(|| {
            JsonResponse::<serde_json::Value>::build().not_found("Template not found")
        })?;

    ensure_template_owner(&template, &user.id)?;
    ensure_template_assets_editable(&template)?;

    let latest_version = db::marketplace::get_latest_version_by_template(pg_pool.get_ref(), id)
        .await
        .map_err(|err| JsonResponse::<serde_json::Value>::build().internal_server_error(err))?
        .ok_or_else(|| {
            JsonResponse::<serde_json::Value>::build()
                .bad_request("Create a template version before uploading assets")
        })?;

    let presigned = services::presign_asset_upload(
        &settings.marketplace_assets,
        &id,
        &latest_version.version,
        services::MarketplaceAssetUploadRequest {
            filename: body.filename.clone(),
            sha256: body.sha256.clone(),
            size: body.size,
            content_type: body.content_type.clone(),
            mount_path: body.mount_path.clone(),
            fetch_target: body.fetch_target.clone(),
            decompress: body.decompress.unwrap_or(false),
            executable: body.executable.unwrap_or(false),
            immutable: body.immutable.unwrap_or(true),
        },
    )
    .map_err(map_storage_error)?;

    let payload = serde_json::to_value(presigned).map_err(|err| {
        JsonResponse::<serde_json::Value>::build().internal_server_error(err.to_string())
    })?;

    Ok(JsonResponse::<serde_json::Value>::build()
        .set_item(payload)
        .ok("OK"))
}

#[tracing::instrument(name = "Finalize marketplace asset upload", skip_all)]
#[post("/{id}/assets/finalize")]
pub async fn finalize_asset_upload_handler(
    user: web::ReqData<Arc<models::User>>,
    path: web::Path<(String,)>,
    pg_pool: web::Data<PgPool>,
    settings: web::Data<Settings>,
    body: web::Json<FinalizeAssetRequest>,
) -> Result<web::Json<crate::helpers::json::JsonResponse<serde_json::Value>>> {
    let id = uuid::Uuid::parse_str(&path.into_inner().0)
        .map_err(|_| actix_web::error::ErrorBadRequest("Invalid UUID"))?;

    let template = db::marketplace::get_by_id(pg_pool.get_ref(), id)
        .await
        .map_err(|err| JsonResponse::<serde_json::Value>::build().internal_server_error(err))?
        .ok_or_else(|| {
            JsonResponse::<serde_json::Value>::build().not_found("Template not found")
        })?;

    ensure_template_owner(&template, &user.id)?;
    ensure_template_assets_editable(&template)?;

    let latest_version = db::marketplace::get_latest_version_by_template(pg_pool.get_ref(), id)
        .await
        .map_err(|err| JsonResponse::<serde_json::Value>::build().internal_server_error(err))?
        .ok_or_else(|| {
            JsonResponse::<serde_json::Value>::build()
                .bad_request("Create a template version before finalizing assets")
        })?;

    let asset = build_marketplace_asset(body.into_inner())?;
    let expected_bucket = settings.marketplace_assets.active_bucket().to_string();
    let expected_key = services::marketplace_assets::build_asset_key(
        &id,
        &latest_version.version,
        &asset.sha256,
        &asset.filename,
    );
    if asset.bucket != expected_bucket || asset.key != expected_key {
        return Err(JsonResponse::<serde_json::Value>::build()
            .bad_request("Asset key does not match the server-issued upload descriptor"));
    }
    services::marketplace_assets::verify_asset_upload(&settings.marketplace_assets, &asset)
        .await
        .map_err(|err| JsonResponse::<serde_json::Value>::build().bad_request(err.to_string()))?;

    let persisted = db::marketplace::upsert_latest_version_asset(
        pg_pool.get_ref(),
        id,
        &serde_json::to_value(&asset).map_err(|err| {
            JsonResponse::<serde_json::Value>::build().internal_server_error(err.to_string())
        })?,
    )
    .await
    .map_err(|err| JsonResponse::<serde_json::Value>::build().internal_server_error(err))?;

    Ok(JsonResponse::<serde_json::Value>::build()
        .set_item(persisted)
        .ok("OK"))
}

#[tracing::instrument(name = "Presign marketplace asset download", skip_all)]
#[post("/{id}/assets/presign-download")]
pub async fn presign_asset_download_handler(
    user: web::ReqData<Arc<models::User>>,
    path: web::Path<(String,)>,
    pg_pool: web::Data<PgPool>,
    settings: web::Data<Settings>,
    body: web::Json<PresignAssetDownloadRequest>,
) -> Result<web::Json<crate::helpers::json::JsonResponse<serde_json::Value>>> {
    let id = uuid::Uuid::parse_str(&path.into_inner().0)
        .map_err(|_| actix_web::error::ErrorBadRequest("Invalid UUID"))?;

    let template = db::marketplace::get_by_id(pg_pool.get_ref(), id)
        .await
        .map_err(|err| JsonResponse::<serde_json::Value>::build().internal_server_error(err))?
        .ok_or_else(|| {
            JsonResponse::<serde_json::Value>::build().not_found("Template not found")
        })?;

    ensure_template_owner(&template, &user.id)?;

    let asset_value =
        db::marketplace::get_latest_version_asset_by_key(pg_pool.get_ref(), id, body.key.trim())
            .await
            .map_err(|err| JsonResponse::<serde_json::Value>::build().internal_server_error(err))?
            .ok_or_else(|| {
                JsonResponse::<serde_json::Value>::build()
                    .not_found("Asset not found for latest version")
            })?;

    let asset: models::MarketplaceAsset = serde_json::from_value(asset_value).map_err(|err| {
        JsonResponse::<serde_json::Value>::build().internal_server_error(err.to_string())
    })?;
    let presigned = services::presign_asset_download(&settings.marketplace_assets, &asset)
        .map_err(map_storage_error)?;
    let payload = serde_json::to_value(presigned).map_err(|err| {
        JsonResponse::<serde_json::Value>::build().internal_server_error(err.to_string())
    })?;

    Ok(JsonResponse::<serde_json::Value>::build()
        .set_item(payload)
        .ok("OK"))
}

#[tracing::instrument(name = "Submit template for review", skip_all)]
#[post("/{id}/submit")]
pub async fn submit_handler(
    user: web::ReqData<Arc<models::User>>,
    path: web::Path<(String,)>,
    pg_pool: web::Data<PgPool>,
    body: web::Json<SubmitTemplateRequest>,
) -> Result<web::Json<crate::helpers::json::JsonResponse<serde_json::Value>>> {
    let id = uuid::Uuid::parse_str(&path.into_inner().0)
        .map_err(|_| actix_web::error::ErrorBadRequest("Invalid UUID"))?;

    // Ownership check
    let owner_id: String = sqlx::query_scalar!(
        r#"SELECT creator_user_id FROM stack_template WHERE id = $1"#,
        id
    )
    .fetch_one(pg_pool.get_ref())
    .await
    .map_err(|_| JsonResponse::<serde_json::Value>::build().not_found("Not Found"))?;

    if owner_id != user.id {
        return Err(JsonResponse::<serde_json::Value>::build().forbidden("Forbidden"));
    }

    ensure_no_secrets_confirmation(body.into_inner().confirm_no_secrets)?;
    let latest_version = db::marketplace::get_latest_version_by_template(pg_pool.get_ref(), id)
        .await
        .map_err(|err| JsonResponse::<serde_json::Value>::build().internal_server_error(err))?;
    let has_empty_stack_definition = latest_version
        .as_ref()
        .map(|version| {
            version.stack_definition.is_null()
                || version
                    .stack_definition
                    .as_object()
                    .map(|definition| definition.is_empty())
                    .unwrap_or(false)
        })
        .unwrap_or(false);
    if has_empty_stack_definition {
        return Err(JsonResponse::<serde_json::Value>::build()
            .bad_request("Template must include a deployable stack definition before submission"));
    }

    let submitted = db::marketplace::submit_for_review(pg_pool.get_ref(), &id)
        .await
        .map_err(|err| JsonResponse::<serde_json::Value>::build().internal_server_error(err))?;

    if submitted {
        let template = db::marketplace::get_by_id(pg_pool.get_ref(), id)
            .await
            .map_err(|err| JsonResponse::<serde_json::Value>::build().internal_server_error(err))?
            .ok_or_else(|| {
                JsonResponse::<serde_json::Value>::build().not_found("Template not found")
            })?;

        let template_clone = template.clone();
        tokio::spawn(async move {
            match WebhookSenderConfig::from_env() {
                Ok(config) => {
                    let sender = MarketplaceWebhookSender::new(config);
                    let span = tracing::info_span!(
                        "send_submit_webhook",
                        template_id = %template_clone.id
                    );

                    if let Err(e) = sender
                        .send_template_submitted(
                            &template_clone,
                            &template_clone.creator_user_id,
                            template_clone.category_code.clone(),
                        )
                        .instrument(span)
                        .await
                    {
                        tracing::warn!("Failed to send template submitted webhook: {:?}", e);
                    }
                }
                Err(e) => {
                    tracing::warn!("Webhook sender config not available: {}", e);
                }
            }
        });

        Ok(JsonResponse::<serde_json::Value>::build().ok("Submitted"))
    } else {
        Err(JsonResponse::<serde_json::Value>::build().bad_request("Invalid status"))
    }
}

#[derive(Debug, serde::Deserialize)]
pub struct ResubmitRequest {
    pub name: Option<String>,
    pub short_description: Option<String>,
    pub long_description: Option<String>,
    pub category_code: Option<String>,
    pub tags: Option<serde_json::Value>,
    pub tech_stack: Option<serde_json::Value>,
    pub version: String,
    pub stack_definition: Option<serde_json::Value>,
    pub definition_format: Option<String>,
    pub changelog: Option<String>,
    pub infrastructure_requirements: Option<serde_json::Value>,
    pub plan_type: Option<String>,
    pub required_plan_name: Option<String>,
    pub price: Option<f64>,
    pub currency: Option<String>,
    pub public_ports: Option<serde_json::Value>,
    pub vendor_url: Option<String>,
    pub config_files: Option<serde_json::Value>,
    pub assets: Option<serde_json::Value>,
    pub seed_jobs: Option<serde_json::Value>,
    pub post_deploy_hooks: Option<serde_json::Value>,
    pub update_mode_capabilities: Option<serde_json::Value>,
    pub confirm_no_secrets: Option<bool>,
}

#[tracing::instrument(name = "Resubmit template with new version", skip_all)]
#[post("/{id}/resubmit")]
pub async fn resubmit_handler(
    user: web::ReqData<Arc<models::User>>,
    path: web::Path<(String,)>,
    pg_pool: web::Data<PgPool>,
    body: web::Json<ResubmitRequest>,
) -> Result<web::Json<crate::helpers::json::JsonResponse<serde_json::Value>>> {
    let id = uuid::Uuid::parse_str(&path.into_inner().0)
        .map_err(|_| actix_web::error::ErrorBadRequest("Invalid UUID"))?;

    // Ownership check
    let owner_id: String = sqlx::query_scalar!(
        r#"SELECT creator_user_id FROM stack_template WHERE id = $1"#,
        id
    )
    .fetch_one(pg_pool.get_ref())
    .await
    .map_err(|_| JsonResponse::<serde_json::Value>::build().not_found("Not Found"))?;

    if owner_id != user.id {
        return Err(JsonResponse::<serde_json::Value>::build().forbidden("Forbidden"));
    }

    let req = body.into_inner();
    ensure_no_secrets_confirmation(req.confirm_no_secrets)?;
    let current_version = db::marketplace::get_latest_version_by_template(pg_pool.get_ref(), id)
        .await
        .map_err(|err| JsonResponse::<serde_json::Value>::build().internal_server_error(err))?
        .ok_or_else(|| {
            JsonResponse::<serde_json::Value>::build().bad_request("Template has no latest version")
        })?;
    let price = match req.plan_type.as_deref() {
        Some("free") => Some(0.0),
        _ => req.price,
    };
    let stack_definition = req
        .stack_definition
        .clone()
        .unwrap_or_else(|| current_version.stack_definition.clone());
    let config_files = req
        .config_files
        .clone()
        .unwrap_or_else(|| current_version.config_files.clone());
    let assets = req
        .assets
        .clone()
        .unwrap_or_else(|| current_version.assets.clone());
    let seed_jobs = req
        .seed_jobs
        .clone()
        .unwrap_or_else(|| current_version.seed_jobs.clone());
    let post_deploy_hooks = req
        .post_deploy_hooks
        .clone()
        .unwrap_or_else(|| current_version.post_deploy_hooks.clone());
    let update_mode_capabilities = req
        .update_mode_capabilities
        .clone()
        .or(current_version.update_mode_capabilities.clone());

    let version = db::marketplace::resubmit_with_new_version(
        pg_pool.get_ref(),
        &id,
        req.name.as_deref(),
        req.short_description.as_deref(),
        req.long_description.as_deref(),
        req.category_code.as_deref(),
        req.tags.clone(),
        req.tech_stack.clone(),
        req.infrastructure_requirements.clone(),
        price,
        req.plan_type.as_deref(),
        req.required_plan_name.as_deref(),
        req.currency.as_deref(),
        req.public_ports.clone(),
        req.vendor_url.as_deref(),
        &req.version,
        stack_definition,
        req.definition_format.as_deref(),
        req.changelog.as_deref(),
        config_files,
        assets,
        seed_jobs,
        post_deploy_hooks,
        update_mode_capabilities,
    )
    .await
    .map_err(|err| JsonResponse::<serde_json::Value>::build().bad_request(err))?;

    let result = serde_json::json!({
        "template_id": id,
        "version": version,
        "status": "submitted"
    });

    let template = db::marketplace::get_by_id(pg_pool.get_ref(), id)
        .await
        .map_err(|err| JsonResponse::<serde_json::Value>::build().internal_server_error(err))?
        .ok_or_else(|| {
            JsonResponse::<serde_json::Value>::build().not_found("Template not found")
        })?;

    let template_clone = template.clone();
    tokio::spawn(async move {
        match WebhookSenderConfig::from_env() {
            Ok(config) => {
                let sender = MarketplaceWebhookSender::new(config);
                let span =
                    tracing::info_span!("send_resubmit_webhook", template_id = %template_clone.id);

                if let Err(e) = sender
                    .send_template_submitted(
                        &template_clone,
                        &template_clone.creator_user_id,
                        template_clone.category_code.clone(),
                    )
                    .instrument(span)
                    .await
                {
                    tracing::warn!("Failed to send template resubmitted webhook: {:?}", e);
                }
            }
            Err(e) => {
                tracing::warn!("Webhook sender config not available: {}", e);
            }
        }
    });

    Ok(JsonResponse::<serde_json::Value>::build()
        .set_item(result)
        .ok("Resubmitted for review"))
}

#[tracing::instrument(name = "List my templates", skip_all)]
#[get("/mine")]
pub async fn mine_handler(
    user: Option<web::ReqData<Arc<models::User>>>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    let user = user.ok_or_else(|| JsonResponse::<String>::forbidden("Authentication required"))?;
    db::marketplace::list_mine(pg_pool.get_ref(), &user.id)
        .await
        .map_err(|err| {
            JsonResponse::<Vec<models::StackTemplate>>::build().internal_server_error(err)
        })
        .map(|templates| JsonResponse::build().set_list(templates).ok("OK"))
}

#[tracing::instrument(name = "Get my marketplace analytics", skip_all)]
#[get("/mine/analytics")]
pub async fn analytics_handler(
    user: Option<web::ReqData<Arc<models::User>>>,
    query: web::Query<AnalyticsQuery>,
    pg_pool: web::Data<PgPool>,
) -> Result<web::Json<models::VendorAnalytics>> {
    let user = user.ok_or_else(|| JsonResponse::<String>::forbidden("Authentication required"))?;
    let start_date = parse_optional_analytics_date(query.start_date.as_deref())?;
    let end_date = parse_optional_analytics_date(query.end_date.as_deref())?;
    validate_optional_template_scope(pg_pool.get_ref(), &user.id, query.template_id.as_deref())
        .await?;

    db::marketplace::get_vendor_analytics_for_period(
        pg_pool.get_ref(),
        &user.id,
        query.period.as_deref().unwrap_or("30d"),
        start_date,
        end_date,
    )
    .await
    .map(web::Json)
    .map_err(|err| JsonResponse::<serde_json::Value>::build().internal_server_error(err))
}

async fn validate_optional_template_scope(
    pool: &PgPool,
    user_id: &str,
    template_id: Option<&str>,
) -> Result<()> {
    let Some(template_id) = template_id else {
        return Ok(());
    };
    let template_id = uuid::Uuid::parse_str(template_id).map_err(|_| {
        JsonResponse::<serde_json::Value>::build().bad_request("Invalid templateId")
    })?;
    let template = db::marketplace::get_by_id(pool, template_id)
        .await
        .map_err(|err| JsonResponse::<serde_json::Value>::build().internal_server_error(err))?
        .ok_or_else(|| {
            JsonResponse::<serde_json::Value>::build().not_found("Template not found")
        })?;

    if template.creator_user_id != user_id {
        return Err(JsonResponse::<serde_json::Value>::build().forbidden("Access denied"));
    }

    Ok(())
}

fn parse_optional_analytics_date(
    value: Option<&str>,
) -> Result<Option<chrono::DateTime<chrono::Utc>>> {
    value
        .map(|raw| {
            chrono::DateTime::parse_from_rfc3339(raw)
                .map(|date| date.with_timezone(&chrono::Utc))
                .map_err(|_| {
                    JsonResponse::<serde_json::Value>::build()
                        .bad_request("Invalid analytics date format")
                })
        })
        .transpose()
}

#[tracing::instrument(name = "List reviews for my template", skip_all)]
#[get("/{id}/reviews")]
pub async fn my_reviews_handler(
    user: Option<web::ReqData<Arc<models::User>>>,
    path: web::Path<(String,)>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    let user = user.ok_or_else(|| JsonResponse::<String>::forbidden("Authentication required"))?;
    let id = uuid::Uuid::parse_str(&path.into_inner().0)
        .map_err(|_| actix_web::error::ErrorBadRequest("Invalid UUID"))?;

    let template = db::marketplace::get_by_id(pg_pool.get_ref(), id)
        .await
        .map_err(|err| JsonResponse::<serde_json::Value>::build().internal_server_error(err))?
        .ok_or_else(|| {
            JsonResponse::<serde_json::Value>::build().not_found("Template not found")
        })?;

    if template.creator_user_id != user.id {
        return Err(JsonResponse::<serde_json::Value>::build().forbidden("Access denied"));
    }

    db::marketplace::list_reviews_by_template(pg_pool.get_ref(), id)
        .await
        .map_err(|err| JsonResponse::<serde_json::Value>::build().internal_server_error(err))
        .map(|reviews| JsonResponse::build().set_list(reviews).ok("OK"))
}

#[tracing::instrument(name = "Get my vendor profile status", skip_all)]
#[get("/{id}/vendor-profile-status")]
pub async fn vendor_profile_status_handler(
    user: Option<web::ReqData<Arc<models::User>>>,
    path: web::Path<(String,)>,
    pg_pool: web::Data<PgPool>,
) -> Result<web::Json<crate::helpers::json::JsonResponse<serde_json::Value>>> {
    let user = user.ok_or_else(|| JsonResponse::<String>::forbidden("Authentication required"))?;
    let id = uuid::Uuid::parse_str(&path.into_inner().0)
        .map_err(|_| actix_web::error::ErrorBadRequest("Invalid UUID"))?;

    let template = db::marketplace::get_by_id(pg_pool.get_ref(), id)
        .await
        .map_err(|err| JsonResponse::<serde_json::Value>::build().internal_server_error(err))?
        .ok_or_else(|| {
            JsonResponse::<serde_json::Value>::build().not_found("Template not found")
        })?;

    if template.creator_user_id != user.id {
        return Err(JsonResponse::<serde_json::Value>::build().forbidden("Access denied"));
    }

    let vendor_profile = db::marketplace::get_vendor_profile_by_creator(
        pg_pool.get_ref(),
        &template.creator_user_id,
    )
    .await
    .map_err(|err| JsonResponse::<serde_json::Value>::build().internal_server_error(err))?
    .unwrap_or_else(|| {
        models::MarketplaceVendorProfile::default_for_creator(&template.creator_user_id)
    });

    let result = build_vendor_profile_status_item(
        &template.creator_user_id,
        Some(template.id),
        vendor_profile,
    );

    Ok(JsonResponse::<serde_json::Value>::build()
        .set_item(result)
        .ok("OK"))
}

#[tracing::instrument(name = "Get my self vendor profile", skip_all)]
#[get("/mine/vendor-profile")]
pub async fn self_vendor_profile_handler(
    user: Option<web::ReqData<Arc<models::User>>>,
    pg_pool: web::Data<PgPool>,
) -> Result<web::Json<crate::helpers::json::JsonResponse<serde_json::Value>>> {
    let user = user.ok_or_else(|| JsonResponse::<String>::forbidden("Authentication required"))?;

    let vendor_profile =
        db::marketplace::get_vendor_profile_by_creator(pg_pool.get_ref(), &user.id)
            .await
            .map_err(|err| JsonResponse::<serde_json::Value>::build().internal_server_error(err))?
            .unwrap_or_else(|| models::MarketplaceVendorProfile::default_for_creator(&user.id));

    let result = build_vendor_profile_status_item(&user.id, None, vendor_profile);

    Ok(JsonResponse::<serde_json::Value>::build()
        .set_item(result)
        .ok("OK"))
}

#[tracing::instrument(name = "Create my vendor onboarding link", skip_all)]
#[post("/mine/vendor-profile/onboarding-link")]
pub async fn create_onboarding_link_handler(
    user: Option<web::ReqData<Arc<models::User>>>,
    pg_pool: web::Data<PgPool>,
) -> Result<web::Json<crate::helpers::json::JsonResponse<serde_json::Value>>> {
    let user = user.ok_or_else(|| JsonResponse::<String>::forbidden("Authentication required"))?;

    let generated_account_ref = format!("acct_mock_{}", uuid::Uuid::new_v4().simple());
    let (vendor_profile, linkage_created) = db::marketplace::ensure_vendor_onboarding_link(
        pg_pool.get_ref(),
        &user.id,
        "mock",
        &generated_account_ref,
    )
    .await
    .map_err(|err| JsonResponse::<serde_json::Value>::build().internal_server_error(err))?;

    let mut result = build_vendor_profile_status_item(&user.id, None, vendor_profile);
    result["linkage_created"] = serde_json::Value::Bool(linkage_created);

    Ok(JsonResponse::<serde_json::Value>::build()
        .set_item(result)
        .ok("OK"))
}

#[tracing::instrument(name = "Complete my vendor onboarding", skip_all)]
#[post("/mine/vendor-profile/onboarding-complete")]
pub async fn complete_onboarding_handler(
    user: Option<web::ReqData<Arc<models::User>>>,
    pg_pool: web::Data<PgPool>,
) -> Result<web::Json<crate::helpers::json::JsonResponse<serde_json::Value>>> {
    let user = user.ok_or_else(|| JsonResponse::<String>::forbidden("Authentication required"))?;

    let completion =
        db::marketplace::complete_vendor_onboarding(pg_pool.get_ref(), &user.id, "creator_api")
            .await
            .map_err(|err| JsonResponse::<serde_json::Value>::build().internal_server_error(err))?;

    let (vendor_profile, completion_recorded) = match completion {
        Some(result) => result,
        None => {
            return Err(JsonResponse::<serde_json::Value>::build()
                .conflict("Onboarding link must exist before completion"))
        }
    };

    let mut result = build_vendor_profile_status_item(&user.id, None, vendor_profile);
    result["completion_recorded"] = serde_json::Value::Bool(completion_recorded);

    Ok(JsonResponse::<serde_json::Value>::build()
        .set_item(result)
        .ok("OK"))
}
