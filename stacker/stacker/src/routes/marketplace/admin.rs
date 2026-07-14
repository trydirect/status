use crate::connectors::user_service::UserServiceConnector;
use crate::connectors::{MarketplaceWebhookSender, WebhookSenderConfig};
use crate::db;
use crate::helpers::security_validator;
use crate::helpers::JsonResponse;
use crate::models;
use actix_web::{get, patch, post, web, Responder, Result};
use sqlx::PgPool;
use std::sync::Arc;
use tracing::Instrument;
use uuid;

const ALLOWED_VENDOR_VERIFICATION_STATUSES: &[&str] =
    &["unverified", "pending", "verified", "rejected"];
const ALLOWED_VENDOR_ONBOARDING_STATUSES: &[&str] = &["not_started", "in_progress", "completed"];

#[tracing::instrument(name = "List submitted templates (admin)", skip_all)]
#[get("")]
pub async fn list_submitted_handler(
    _admin: web::ReqData<Arc<models::User>>, // role enforced by Casbin
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    db::marketplace::admin_list_submitted(pg_pool.get_ref())
        .await
        .map_err(|err| {
            JsonResponse::<Vec<models::StackTemplate>>::build().internal_server_error(err)
        })
        .map(|templates| JsonResponse::build().set_list(templates).ok("OK"))
}

#[tracing::instrument(name = "Get template detail (admin)", skip_all)]
#[get("/{id}")]
pub async fn detail_handler(
    _admin: web::ReqData<Arc<models::User>>,
    path: web::Path<(String,)>,
    pg_pool: web::Data<PgPool>,
) -> Result<web::Json<crate::helpers::json::JsonResponse<serde_json::Value>>> {
    let id = uuid::Uuid::parse_str(&path.into_inner().0)
        .map_err(|_| actix_web::error::ErrorBadRequest("Invalid UUID"))?;

    let template = db::marketplace::get_by_id(pg_pool.get_ref(), id)
        .await
        .map_err(|err| JsonResponse::<serde_json::Value>::build().internal_server_error(err))?
        .ok_or_else(|| {
            JsonResponse::<serde_json::Value>::build().not_found("Template not found")
        })?;

    let versions = db::marketplace::list_versions_by_template(pg_pool.get_ref(), id)
        .await
        .map_err(|err| JsonResponse::<serde_json::Value>::build().internal_server_error(err))?;

    let reviews = db::marketplace::list_reviews_by_template(pg_pool.get_ref(), id)
        .await
        .map_err(|err| JsonResponse::<serde_json::Value>::build().internal_server_error(err))?;

    let vendor_profile = db::marketplace::get_vendor_profile_by_creator(
        pg_pool.get_ref(),
        &template.creator_user_id,
    )
    .await
    .map_err(|err| JsonResponse::<serde_json::Value>::build().internal_server_error(err))?
    .unwrap_or_else(|| {
        models::MarketplaceVendorProfile::default_for_creator(&template.creator_user_id)
    });

    let mut detail = serde_json::to_value(&template).map_err(|err| {
        JsonResponse::<serde_json::Value>::build().internal_server_error(err.to_string())
    })?;
    detail["template"] = serde_json::to_value(template).map_err(|err| {
        JsonResponse::<serde_json::Value>::build().internal_server_error(err.to_string())
    })?;
    detail["versions"] = serde_json::to_value(versions).map_err(|err| {
        JsonResponse::<serde_json::Value>::build().internal_server_error(err.to_string())
    })?;
    detail["reviews"] = serde_json::to_value(reviews).map_err(|err| {
        JsonResponse::<serde_json::Value>::build().internal_server_error(err.to_string())
    })?;
    detail["vendor_profile"] = serde_json::to_value(vendor_profile).map_err(|err| {
        JsonResponse::<serde_json::Value>::build().internal_server_error(err.to_string())
    })?;

    Ok(JsonResponse::<serde_json::Value>::build()
        .set_item(detail)
        .ok("OK"))
}

#[derive(serde::Deserialize, Debug)]
pub struct AdminDecisionRequest {
    pub decision: String, // approved|rejected|needs_changes
    pub reason: Option<String>,
    pub verifications: Option<serde_json::Value>,
}

#[derive(serde::Deserialize, Debug)]
pub struct AdminReviewReasonRequest {
    pub reason: Option<String>,
}

#[tracing::instrument(name = "Approve template (admin)", skip_all)]
#[post("/{id}/approve")]
pub async fn approve_handler(
    admin: web::ReqData<Arc<models::User>>, // role enforced by Casbin
    path: web::Path<(String,)>,
    pg_pool: web::Data<PgPool>,
    body: web::Json<AdminDecisionRequest>,
) -> Result<web::Json<crate::helpers::json::JsonResponse<serde_json::Value>>> {
    let id = uuid::Uuid::parse_str(&path.into_inner().0)
        .map_err(|_| actix_web::error::ErrorBadRequest("Invalid UUID"))?;
    let req = body.into_inner();

    let updated = db::marketplace::admin_decide(
        pg_pool.get_ref(),
        &id,
        &admin.id,
        "approved",
        req.reason.as_deref(),
        req.verifications.as_ref(),
    )
    .await
    .map_err(|err| JsonResponse::<serde_json::Value>::build().internal_server_error(err))?;

    if !updated {
        return Err(JsonResponse::<serde_json::Value>::build().bad_request("Not updated"));
    }

    // Fetch template details for webhook
    let template = db::marketplace::get_by_id(pg_pool.get_ref(), id)
        .await
        .map_err(|err| {
            tracing::error!("Failed to fetch template for webhook: {:?}", err);
            JsonResponse::<serde_json::Value>::build().internal_server_error(err)
        })?
        .ok_or_else(|| {
            JsonResponse::<serde_json::Value>::build().not_found("Template not found")
        })?;

    // Send webhook asynchronously (non-blocking)
    // Don't fail the approval if webhook send fails - template is already approved
    let template_clone = template.clone();
    tokio::spawn(async move {
        match WebhookSenderConfig::from_env() {
            Ok(config) => {
                let sender = MarketplaceWebhookSender::new(config);
                let span =
                    tracing::info_span!("send_approval_webhook", template_id = %template_clone.id);

                if let Err(e) = sender
                    .send_template_published(
                        &template_clone,
                        &template_clone.creator_user_id,
                        template_clone.category_code.clone(),
                    )
                    .instrument(span)
                    .await
                {
                    tracing::warn!("Failed to send template approval webhook: {:?}", e);
                    // Log but don't block - approval already persisted
                }
            }
            Err(e) => {
                tracing::warn!("Webhook sender config not available: {}", e);
                // Gracefully handle missing config
            }
        }
    });

    Ok(JsonResponse::<serde_json::Value>::build().ok("Approved"))
}

#[tracing::instrument(name = "Reject template (admin)", skip_all)]
#[post("/{id}/reject")]
pub async fn reject_handler(
    admin: web::ReqData<Arc<models::User>>, // role enforced by Casbin
    path: web::Path<(String,)>,
    pg_pool: web::Data<PgPool>,
    body: web::Json<AdminDecisionRequest>,
) -> Result<web::Json<crate::helpers::json::JsonResponse<serde_json::Value>>> {
    let id = uuid::Uuid::parse_str(&path.into_inner().0)
        .map_err(|_| actix_web::error::ErrorBadRequest("Invalid UUID"))?;
    let req = body.into_inner();

    let updated = db::marketplace::admin_decide(
        pg_pool.get_ref(),
        &id,
        &admin.id,
        "rejected",
        req.reason.as_deref(),
        req.verifications.as_ref(),
    )
    .await
    .map_err(|err| JsonResponse::<serde_json::Value>::build().internal_server_error(err))?;

    if !updated {
        return Err(JsonResponse::<serde_json::Value>::build().bad_request("Not updated"));
    }

    let template = db::marketplace::get_by_id(pg_pool.get_ref(), id)
        .await
        .map_err(|err| {
            tracing::error!("Failed to fetch template for rejection webhook: {:?}", err);
            JsonResponse::<serde_json::Value>::build().internal_server_error(err)
        })?
        .ok_or_else(|| {
            JsonResponse::<serde_json::Value>::build().not_found("Template not found")
        })?;

    // Send webhook asynchronously (non-blocking)
    // Don't fail the rejection if webhook send fails - template is already rejected
    let template_clone = template.clone();
    let review_reason = req.reason.clone();
    tokio::spawn(async move {
        match WebhookSenderConfig::from_env() {
            Ok(config) => {
                let sender = MarketplaceWebhookSender::new(config);
                let span = tracing::info_span!(
                    "send_rejection_webhook",
                    template_id = %template_clone.id
                );

                if let Err(e) = sender
                    .send_template_review_rejected(
                        &template_clone,
                        &template_clone.creator_user_id,
                        review_reason.as_deref(),
                    )
                    .instrument(span)
                    .await
                {
                    tracing::warn!("Failed to send template rejection webhook: {:?}", e);
                    // Log but don't block - rejection already persisted
                }
            }
            Err(e) => {
                tracing::warn!("Webhook sender config not available: {}", e);
                // Gracefully handle missing config
            }
        }
    });

    Ok(JsonResponse::<serde_json::Value>::build().ok("Rejected"))
}

#[tracing::instrument(name = "Mark template as needs changes (admin)", skip_all)]
#[post("/{id}/needs-changes")]
pub async fn needs_changes_handler(
    admin: web::ReqData<Arc<models::User>>,
    path: web::Path<(String,)>,
    pg_pool: web::Data<PgPool>,
    body: web::Json<AdminReviewReasonRequest>,
) -> Result<web::Json<crate::helpers::json::JsonResponse<serde_json::Value>>> {
    let id = uuid::Uuid::parse_str(&path.into_inner().0)
        .map_err(|_| actix_web::error::ErrorBadRequest("Invalid UUID"))?;
    let req = body.into_inner();

    let template = db::marketplace::get_by_id(pg_pool.get_ref(), id)
        .await
        .map_err(|err| JsonResponse::<serde_json::Value>::build().internal_server_error(err))?
        .ok_or_else(|| {
            JsonResponse::<serde_json::Value>::build().not_found("Template not found")
        })?;

    if template.status != "submitted" && template.status != "under_review" {
        return Err(JsonResponse::<serde_json::Value>::build()
            .bad_request("Template cannot be marked as needs_changes from its current status"));
    }

    let updated = db::marketplace::admin_decide(
        pg_pool.get_ref(),
        &id,
        &admin.id,
        "needs_changes",
        req.reason.as_deref(),
        None,
    )
    .await
    .map_err(|err| JsonResponse::<serde_json::Value>::build().internal_server_error(err))?;

    if !updated {
        return Err(JsonResponse::<serde_json::Value>::build().bad_request("Not updated"));
    }

    let template_clone = template.clone();
    let review_reason = req.reason.clone();
    tokio::spawn(async move {
        match WebhookSenderConfig::from_env() {
            Ok(config) => {
                let sender = MarketplaceWebhookSender::new(config);
                let span = tracing::info_span!(
                    "send_needs_changes_webhook",
                    template_id = %template_clone.id
                );

                if let Err(e) = sender
                    .send_template_needs_changes(
                        &template_clone,
                        &template_clone.creator_user_id,
                        review_reason.as_deref(),
                        "Update the template based on the review feedback and resubmit it for review.",
                    )
                    .instrument(span)
                    .await
                {
                    tracing::warn!("Failed to send template needs-changes webhook: {:?}", e);
                }
            }
            Err(e) => {
                tracing::warn!("Webhook sender config not available: {}", e);
            }
        }
    });

    Ok(JsonResponse::<serde_json::Value>::build().ok("Needs changes requested"))
}

#[derive(serde::Deserialize, Debug)]
pub struct UnapproveRequest {
    pub reason: Option<String>,
}

#[tracing::instrument(name = "Unapprove template (admin)", skip_all)]
#[post("/{id}/unapprove")]
pub async fn unapprove_handler(
    admin: web::ReqData<Arc<models::User>>,
    path: web::Path<(String,)>,
    pg_pool: web::Data<PgPool>,
    body: web::Json<UnapproveRequest>,
) -> Result<web::Json<crate::helpers::json::JsonResponse<serde_json::Value>>> {
    let id = uuid::Uuid::parse_str(&path.into_inner().0)
        .map_err(|_| actix_web::error::ErrorBadRequest("Invalid UUID"))?;
    let req = body.into_inner();

    let updated =
        db::marketplace::admin_unapprove(pg_pool.get_ref(), &id, &admin.id, req.reason.as_deref())
            .await
            .map_err(|err| JsonResponse::<serde_json::Value>::build().internal_server_error(err))?;

    if !updated {
        return Err(JsonResponse::<serde_json::Value>::build()
            .bad_request("Template is not approved or not found"));
    }

    let template = db::marketplace::get_by_id(pg_pool.get_ref(), id)
        .await
        .map_err(|err| {
            tracing::error!("Failed to fetch template for unpublish webhook: {:?}", err);
            JsonResponse::<serde_json::Value>::build().internal_server_error(err)
        })?
        .ok_or_else(|| {
            JsonResponse::<serde_json::Value>::build().not_found("Template not found")
        })?;

    // Send webhook to unpublish from marketplace while preserving subscription state
    let template_clone = template.clone();
    tokio::spawn(async move {
        match WebhookSenderConfig::from_env() {
            Ok(config) => {
                let sender = MarketplaceWebhookSender::new(config);
                let span = tracing::info_span!(
                    "send_unapproval_webhook",
                    template_id = %template_clone.id
                );

                if let Err(e) = sender
                    .send_template_unpublished(&template_clone, &template_clone.creator_user_id)
                    .instrument(span)
                    .await
                {
                    tracing::warn!("Failed to send template unapproval webhook: {:?}", e);
                }
            }
            Err(e) => {
                tracing::warn!("Webhook sender config not available: {}", e);
            }
        }
    });

    Ok(JsonResponse::<serde_json::Value>::build()
        .ok("Template unapproved and hidden from marketplace"))
}

#[tracing::instrument(name = "Security scan template (admin)", skip_all)]
#[post("/{id}/security-scan")]
pub async fn security_scan_handler(
    admin: web::ReqData<Arc<models::User>>,
    path: web::Path<(String,)>,
    pg_pool: web::Data<PgPool>,
) -> Result<web::Json<crate::helpers::json::JsonResponse<serde_json::Value>>> {
    let id = uuid::Uuid::parse_str(&path.into_inner().0)
        .map_err(|_| actix_web::error::ErrorBadRequest("Invalid UUID"))?;

    // Fetch template
    let template = db::marketplace::get_by_id(pg_pool.get_ref(), id)
        .await
        .map_err(|err| JsonResponse::<serde_json::Value>::build().internal_server_error(err))?
        .ok_or_else(|| {
            JsonResponse::<serde_json::Value>::build().not_found("Template not found")
        })?;

    // Fetch versions to get latest stack_definition
    let versions = db::marketplace::list_versions_by_template(pg_pool.get_ref(), id)
        .await
        .map_err(|err| JsonResponse::<serde_json::Value>::build().internal_server_error(err))?;

    let latest = versions
        .iter()
        .find(|v| v.is_latest == Some(true))
        .or_else(|| versions.first())
        .ok_or_else(|| {
            JsonResponse::<serde_json::Value>::build()
                .bad_request("No versions found for this template")
        })?;

    // Run automated security validation
    let report = security_validator::validate_stack_security(&latest.stack_definition);

    // Save scan result as a review record
    let review = db::marketplace::save_security_scan(
        pg_pool.get_ref(),
        &id,
        &admin.id,
        report.to_checklist_json(),
    )
    .await
    .map_err(|err| JsonResponse::<serde_json::Value>::build().internal_server_error(err))?;

    // Always persist the hardened_images result (true/false) regardless of overall scan outcome.
    // security_reviewed is only set when the scan passes all gates.
    {
        let mut verif_patch = serde_json::json!({});
        verif_patch["hardened_images"] = serde_json::Value::Bool(report.hardened_images.passed);
        if report.overall_passed {
            verif_patch["security_reviewed"] = serde_json::Value::Bool(true);
        }
        if let Err(e) =
            db::marketplace::update_verifications(pg_pool.get_ref(), &id, verif_patch).await
        {
            tracing::warn!("Failed to auto-set verifications after scan: {}", e);
        }
    }

    let result = serde_json::json!({
        "template_id": template.id,
        "template_name": template.name,
        "version": latest.version,
        "review_id": review.id,
        "overall_passed": report.overall_passed,
        "risk_score": report.risk_score,
        "no_secrets": report.no_secrets,
        "no_hardcoded_creds": report.no_hardcoded_creds,
        "valid_docker_syntax": report.valid_docker_syntax,
        "no_malicious_code": report.no_malicious_code,
        "recommendations": report.recommendations,
    });

    Ok(JsonResponse::<serde_json::Value>::build()
        .set_item(result)
        .ok("Security scan completed"))
}

#[tracing::instrument(name = "List available plans from User Service", skip_all)]
#[get("/plans")]
pub async fn list_plans_handler(
    _admin: web::ReqData<Arc<models::User>>, // role enforced by Casbin
    user_service: web::Data<Arc<dyn UserServiceConnector>>,
) -> Result<impl Responder> {
    user_service
        .list_available_plans()
        .await
        .map_err(|err| {
            tracing::error!("Failed to fetch available plans: {:?}", err);
            JsonResponse::<serde_json::Value>::build()
                .internal_server_error("Failed to fetch available plans from User Service")
        })
        .map(|plans| {
            // Convert PlanDefinition to JSON for response
            let plan_json: Vec<serde_json::Value> = plans
                .iter()
                .map(|p| {
                    serde_json::json!({
                        "name": p.name,
                        "description": p.description,
                        "tier": p.tier,
                        "features": p.features
                    })
                })
                .collect();
            JsonResponse::build().set_list(plan_json).ok("OK")
        })
}

#[derive(serde::Deserialize, Debug)]
pub struct AdminPricingRequest {
    pub price: Option<f64>,
    pub billing_cycle: Option<String>,
    pub required_plan_name: Option<String>,
    pub currency: Option<String>,
}

#[tracing::instrument(name = "Admin update template pricing", skip_all)]
#[patch("/{id}/pricing")]
pub async fn pricing_handler(
    _admin: web::ReqData<Arc<models::User>>,
    path: web::Path<(String,)>,
    pg_pool: web::Data<PgPool>,
    body: web::Json<AdminPricingRequest>,
) -> Result<web::Json<crate::helpers::json::JsonResponse<serde_json::Value>>> {
    let id = uuid::Uuid::parse_str(&path.into_inner().0)
        .map_err(|_| actix_web::error::ErrorBadRequest("Invalid UUID"))?;

    let req = body.into_inner();
    let updated = db::marketplace::admin_update_pricing(
        pg_pool.get_ref(),
        &id,
        req.price,
        req.billing_cycle.as_deref(),
        req.required_plan_name.as_deref(),
        req.currency.as_deref(),
    )
    .await
    .map_err(|err| JsonResponse::<serde_json::Value>::build().bad_request(err))?;

    if updated {
        Ok(JsonResponse::<serde_json::Value>::build().ok("Updated"))
    } else {
        Err(JsonResponse::<serde_json::Value>::build().not_found("Template not found"))
    }
}

#[derive(serde::Deserialize, Debug)]
pub struct AdminVendorProfileRequest {
    pub verification_status: Option<String>,
    pub onboarding_status: Option<String>,
    pub payouts_enabled: Option<bool>,
    pub payout_provider: Option<String>,
    pub payout_account_ref: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

fn validate_vendor_status(
    field_name: &str,
    value: Option<&str>,
    allowed: &[&str],
) -> Result<(), actix_web::Error> {
    if let Some(value) = value {
        if !allowed.contains(&value) {
            return Err(
                JsonResponse::<serde_json::Value>::build().bad_request(format!(
                    "Invalid {} '{}'. Allowed values: {}",
                    field_name,
                    value,
                    allowed.join(", ")
                )),
            );
        }
    }

    Ok(())
}

#[tracing::instrument(name = "Admin update vendor profile", skip_all)]
#[patch("/{id}/vendor-profile")]
pub async fn update_vendor_profile_handler(
    _admin: web::ReqData<Arc<models::User>>,
    path: web::Path<(String,)>,
    pg_pool: web::Data<PgPool>,
    body: web::Json<AdminVendorProfileRequest>,
) -> Result<web::Json<crate::helpers::json::JsonResponse<serde_json::Value>>> {
    let id = uuid::Uuid::parse_str(&path.into_inner().0)
        .map_err(|_| actix_web::error::ErrorBadRequest("Invalid UUID"))?;

    let req = body.into_inner();

    if req.verification_status.is_none()
        && req.onboarding_status.is_none()
        && req.payouts_enabled.is_none()
        && req.payout_provider.is_none()
        && req.payout_account_ref.is_none()
        && req.metadata.is_none()
    {
        return Err(JsonResponse::<serde_json::Value>::build()
            .bad_request("No vendor profile fields provided"));
    }

    validate_vendor_status(
        "verification_status",
        req.verification_status.as_deref(),
        ALLOWED_VENDOR_VERIFICATION_STATUSES,
    )?;
    validate_vendor_status(
        "onboarding_status",
        req.onboarding_status.as_deref(),
        ALLOWED_VENDOR_ONBOARDING_STATUSES,
    )?;

    if let Some(metadata) = req.metadata.as_ref() {
        if !metadata.is_object() {
            return Err(JsonResponse::<serde_json::Value>::build()
                .bad_request("metadata must be a JSON object"));
        }
    }

    let template = db::marketplace::get_by_id(pg_pool.get_ref(), id)
        .await
        .map_err(|err| JsonResponse::<serde_json::Value>::build().internal_server_error(err))?
        .ok_or_else(|| {
            JsonResponse::<serde_json::Value>::build().not_found("Template not found")
        })?;

    db::marketplace::upsert_vendor_profile(
        pg_pool.get_ref(),
        &template.creator_user_id,
        req.verification_status.as_deref(),
        req.onboarding_status.as_deref(),
        req.payouts_enabled,
        req.payout_provider.as_deref(),
        req.payout_account_ref.as_deref(),
        req.metadata,
    )
    .await
    .map_err(|err| JsonResponse::<serde_json::Value>::build().internal_server_error(err))?;

    Ok(JsonResponse::<serde_json::Value>::build().ok("Vendor profile updated"))
}

/// Request body for PATCH /{id}/verifications.
/// Each key is a boolean flag. Unknown keys are accepted and stored as-is.
/// Omitted keys are not touched (partial update via JSONB `||`).
#[derive(serde::Deserialize, Debug)]
pub struct AdminVerificationsRequest {
    pub security_reviewed: Option<bool>,
    pub https_ready: Option<bool>,
    pub open_source: Option<bool>,
    pub maintained: Option<bool>,
    pub vulnerability_scanned: Option<bool>,
    /// Whether the stack uses hardened Docker images (auto-detected by security scan,
    /// but can also be set manually by the admin).
    pub hardened_images: Option<bool>,
}

#[tracing::instrument(name = "Admin update template verifications", skip_all)]
#[patch("/{id}/verifications")]
pub async fn update_verifications_handler(
    _admin: web::ReqData<Arc<models::User>>,
    path: web::Path<(String,)>,
    pg_pool: web::Data<PgPool>,
    body: web::Json<AdminVerificationsRequest>,
) -> Result<web::Json<crate::helpers::json::JsonResponse<serde_json::Value>>> {
    let id = uuid::Uuid::parse_str(&path.into_inner().0)
        .map_err(|_| actix_web::error::ErrorBadRequest("Invalid UUID"))?;

    let req = body.into_inner();

    // Build a partial JSONB patch containing only the supplied fields
    let mut patch = serde_json::Map::new();
    if let Some(v) = req.security_reviewed {
        patch.insert("security_reviewed".to_string(), serde_json::Value::Bool(v));
    }
    if let Some(v) = req.https_ready {
        patch.insert("https_ready".to_string(), serde_json::Value::Bool(v));
    }
    if let Some(v) = req.open_source {
        patch.insert("open_source".to_string(), serde_json::Value::Bool(v));
    }
    if let Some(v) = req.maintained {
        patch.insert("maintained".to_string(), serde_json::Value::Bool(v));
    }
    if let Some(v) = req.vulnerability_scanned {
        patch.insert(
            "vulnerability_scanned".to_string(),
            serde_json::Value::Bool(v),
        );
    }
    if let Some(v) = req.hardened_images {
        patch.insert("hardened_images".to_string(), serde_json::Value::Bool(v));
    }

    if patch.is_empty() {
        return Err(JsonResponse::<serde_json::Value>::build()
            .bad_request("No verification flags provided"));
    }

    let updated = db::marketplace::update_verifications(
        pg_pool.get_ref(),
        &id,
        serde_json::Value::Object(patch),
    )
    .await
    .map_err(|err| JsonResponse::<serde_json::Value>::build().internal_server_error(err))?;

    if updated {
        Ok(JsonResponse::<serde_json::Value>::build().ok("Verifications updated"))
    } else {
        Err(JsonResponse::<serde_json::Value>::build().not_found("Template not found"))
    }
}
