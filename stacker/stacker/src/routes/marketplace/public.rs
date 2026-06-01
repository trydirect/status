use crate::configuration::Settings;
use crate::db;
use crate::helpers::JsonResponse;
use actix_web::{get, post, web, HttpRequest, HttpResponse, Responder, Result};
use sqlx::PgPool;

#[tracing::instrument(name = "List approved templates (public)", skip_all)]
#[get("")]
pub async fn list_handler(
    query: web::Query<TemplateListQuery>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    let category = query.category.as_deref();
    let tag = query.tag.as_deref();
    let sort = query.sort.as_deref();

    db::marketplace::list_approved(pg_pool.get_ref(), category, tag, sort)
        .await
        .map_err(|err| {
            JsonResponse::<Vec<crate::models::StackTemplate>>::build().internal_server_error(err)
        })
        .map(|templates| JsonResponse::build().set_list(templates).ok("OK"))
}

#[tracing::instrument(name = "Generate install script", skip_all)]
#[get("/install/{purchase_token}")]
pub async fn install_script_handler(path: web::Path<String>) -> Result<HttpResponse> {
    let purchase_token = path.into_inner();
    let script = generate_install_script(&purchase_token);

    Ok(HttpResponse::Ok()
        .content_type("text/x-shellscript")
        .insert_header(("Content-Disposition", "inline; filename=\"install.sh\""))
        .body(script))
}

fn generate_install_script(purchase_token: &str) -> String {
    let stacker_url = std::env::var("STACKER_PUBLIC_URL")
        .unwrap_or_else(|_| "https://stacker.try.direct".to_string());

    format!(
        r#"#!/bin/sh
set -e

PURCHASE_TOKEN="{purchase_token}"
STACKER_URL="{stacker_url}"

echo "============================================"
echo "  TryDirect Marketplace Stack Installer"
echo "============================================"
echo ""

# 1. Install Stacker CLI
echo "[1/4] Installing Stacker CLI..."
if ! command -v stacker >/dev/null 2>&1; then
    curl -sSfL "$STACKER_URL/releases/stacker-cli/install.sh" | sh
else
    echo "  Stacker CLI already installed."
fi

# 2. Install Status Panel agent
echo "[2/4] Installing Status Panel agent..."
if ! command -v status-panel >/dev/null 2>&1; then
    curl -sSfL "$STACKER_URL/releases/status-panel/install.sh" | sh
else
    echo "  Status Panel already installed."
fi

# 3. Download stack archive
echo "[3/4] Downloading stack..."
STACK_DIR="/opt/stacker/marketplace/$PURCHASE_TOKEN"
mkdir -p "$STACK_DIR"
curl -sSfL "$STACKER_URL/api/v1/marketplace/download/$PURCHASE_TOKEN" -o "$STACK_DIR/stack.tar.gz"
cd "$STACK_DIR"
tar xzf stack.tar.gz
rm stack.tar.gz

# 4. Register agent and deploy
echo "[4/4] Registering agent and deploying stack..."
STACK_ID=$(cat "$STACK_DIR/stack.json" 2>/dev/null | grep -o '"stack_id"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | cut -d'"' -f4)
if [ -z "$STACK_ID" ]; then
    STACK_ID="unknown"
fi

status-panel register --token "$PURCHASE_TOKEN" --stack-id "$STACK_ID" --server "$STACKER_URL"

echo ""
echo "Deploying stack..."
cd "$STACK_DIR"
stacker deploy --target local

echo ""
echo "============================================"
echo "  Installation complete!"
echo "============================================"
echo ""
echo "Status Panel is running. Access it at:"
echo "  http://$(hostname -I | awk '{{print $1}}'):5000"
echo ""
echo "Your deployment is linked to your TryDirect dashboard."
echo ""
"#,
        purchase_token = purchase_token,
        stacker_url = stacker_url
    )
}

#[tracing::instrument(name = "Download stack archive", skip_all)]
#[get("/download/{purchase_token}")]
pub async fn download_stack_handler(
    path: web::Path<String>,
    _pg_pool: web::Data<PgPool>,
) -> Result<HttpResponse> {
    let purchase_token = path.into_inner();

    // TODO: Call User Service POST /marketplace/purchase-token/validate
    // to verify token and get stack_id, then locate and serve the archive.
    tracing::info!(
        "Stack download requested for purchase_token={}",
        purchase_token
    );

    Ok(HttpResponse::Ok()
        .content_type("application/gzip")
        .insert_header((
            "Content-Disposition",
            format!("attachment; filename=\"stack-{}.tar.gz\"", purchase_token),
        ))
        .body("stack archive placeholder"))
}

#[derive(Debug, serde::Deserialize)]
pub struct TemplateListQuery {
    pub category: Option<String>,
    pub tag: Option<String>,
    pub sort: Option<String>, // recent|popular|rating
}

#[derive(Debug, serde::Deserialize)]
pub struct DeployCompleteRequest {
    pub deployment_hash: String,
    pub purchase_token: String,
    pub server_ip: Option<String>,
    pub stack_id: String,
}

#[derive(Debug, serde::Deserialize)]
struct PurchaseTokenValidationResponse {
    valid: bool,
    stack_id: Option<String>,
}

#[derive(Debug, serde::Serialize)]
struct DeployCompleteResponse {
    success: bool,
    template_id: String,
    deployment_hash: String,
    deploy_count_incremented: bool,
}

fn require_stacker_service_auth(req: &HttpRequest) -> Result<()> {
    let expected_token = std::env::var("STACKER_SERVICE_TOKEN").unwrap_or_default();
    if expected_token.trim().is_empty() {
        return Err(JsonResponse::<serde_json::Value>::build()
            .internal_server_error("STACKER_SERVICE_TOKEN is not configured"));
    }

    let expected_bearer = format!("Bearer {}", expected_token);
    let actual_service_header = req
        .headers()
        .get("x-stacker-service-token")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let actual_header = req
        .headers()
        .get(actix_web::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");

    if actual_service_header != expected_token && actual_header != expected_bearer {
        return Err(JsonResponse::<serde_json::Value>::build().forbidden("Invalid service token"));
    }

    Ok(())
}

async fn validate_purchase_token_with_user_service(
    settings: &Settings,
    purchase_token: &str,
) -> Result<PurchaseTokenValidationResponse> {
    let service_token = std::env::var("STACKER_SERVICE_TOKEN").unwrap_or_default();
    let endpoint = format!(
        "{}/marketplace/purchase-token/validate",
        settings.user_service_url.trim_end_matches('/')
    );

    let response = reqwest::Client::new()
        .post(endpoint)
        .bearer_auth(service_token)
        .json(&serde_json::json!({ "token": purchase_token }))
        .send()
        .await
        .map_err(|err| {
            tracing::error!("purchase-token validation request failed: {:?}", err);
            JsonResponse::<serde_json::Value>::build()
                .internal_server_error("Purchase token validation request failed")
        })?;

    if !response.status().is_success() {
        tracing::warn!(
            "purchase-token validation rejected by User Service: status={}",
            response.status()
        );
        return Err(JsonResponse::<serde_json::Value>::build()
            .forbidden("Purchase token validation failed"));
    }

    let payload = response
        .json::<PurchaseTokenValidationResponse>()
        .await
        .map_err(|err| {
            tracing::error!(
                "purchase-token validation response decode failed: {:?}",
                err
            );
            JsonResponse::<serde_json::Value>::build()
                .internal_server_error("Invalid purchase token validation response")
        })?;

    if !payload.valid {
        return Err(
            JsonResponse::<serde_json::Value>::build().forbidden("Purchase token is not valid")
        );
    }

    Ok(payload)
}

#[tracing::instrument(name = "Marketplace deploy complete callback", skip_all)]
#[post("/deploy-complete")]
pub async fn deploy_complete_handler(
    req: HttpRequest,
    body: web::Json<DeployCompleteRequest>,
    pg_pool: web::Data<PgPool>,
    settings: web::Data<Settings>,
) -> Result<impl Responder> {
    require_stacker_service_auth(&req)?;

    let payload = body.into_inner();
    tracing::info!(
        deployment_hash = %payload.deployment_hash,
        stack_id = %payload.stack_id,
        server_ip = ?payload.server_ip,
        "marketplace deploy-complete callback received"
    );
    if payload.deployment_hash.trim().is_empty()
        || payload.purchase_token.trim().is_empty()
        || payload.stack_id.trim().is_empty()
    {
        return Err(JsonResponse::<serde_json::Value>::build()
            .bad_request("deployment_hash, purchase_token, and stack_id are required"));
    }

    let validation =
        validate_purchase_token_with_user_service(settings.get_ref(), &payload.purchase_token)
            .await?;
    let validated_stack_id = validation.stack_id.unwrap_or_default();
    if validated_stack_id != payload.stack_id {
        return Err(JsonResponse::<serde_json::Value>::build()
            .forbidden("stack_id does not match the validated purchase token"));
    }

    let template_id = uuid::Uuid::parse_str(&validated_stack_id)
        .map_err(|_| JsonResponse::<serde_json::Value>::build().bad_request("Invalid stack_id"))?;
    let deploy_count_incremented = db::marketplace::record_deploy_complete_once(
        pg_pool.get_ref(),
        &template_id,
        &payload.deployment_hash,
        payload.server_ip.as_deref(),
    )
    .await
    .map_err(|err| JsonResponse::<serde_json::Value>::build().internal_server_error(err))?;

    let Some(deploy_count_incremented) = deploy_count_incremented else {
        return Err(
            JsonResponse::<serde_json::Value>::build().not_found("Marketplace template not found")
        );
    };

    let response = DeployCompleteResponse {
        success: true,
        template_id: template_id.to_string(),
        deployment_hash: payload.deployment_hash,
        deploy_count_incremented,
    };

    Ok(JsonResponse::build()
        .set_item(response)
        .ok("Deploy complete processed"))
}

#[tracing::instrument(name = "Get template by slug (public)", skip_all)]
#[get("/{slug}")]
pub async fn detail_handler(
    path: web::Path<(String,)>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    let slug = path.into_inner().0;

    match db::marketplace::get_by_slug_with_latest(pg_pool.get_ref(), &slug).await {
        Ok((template, version)) => {
            // Increment view_count when template is viewed
            let _ = db::marketplace::increment_view_count(pg_pool.get_ref(), &template.id).await;

            let mut payload = serde_json::json!({
                "template": template,
            });
            if let Some(ver) = version {
                payload["latest_version"] = serde_json::to_value(ver).unwrap();
            }
            Ok(JsonResponse::build().set_item(Some(payload)).ok("OK"))
        }
        Err(err) => Err(JsonResponse::<serde_json::Value>::build().not_found(err)),
    }
}

/// Increment view_count for a marketplace template
#[tracing::instrument(name = "Increment template view count", skip_all)]
#[get("/{id}/increment-view-count")]
pub async fn increment_view_count_handler(
    path: web::Path<(String,)>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    let template_id_str = path.into_inner().0;
    let template_id = uuid::Uuid::parse_str(&template_id_str)
        .map_err(|_| JsonResponse::<serde_json::Value>::build().bad_request("Invalid UUID"))?;

    db::marketplace::increment_view_count(pg_pool.get_ref(), &template_id)
        .await
        .map_err(|err| JsonResponse::<serde_json::Value>::build().internal_server_error(err))
        .map(|_| JsonResponse::<serde_json::Value>::build().ok("View count incremented"))
}

/// Increment deploy_count for a marketplace template
#[tracing::instrument(name = "Increment template deploy count", skip_all)]
#[get("/{id}/increment-deploy-count")]
pub async fn increment_deploy_count_handler(
    path: web::Path<(String,)>,
    pg_pool: web::Data<PgPool>,
) -> Result<impl Responder> {
    let template_id_str = path.into_inner().0;
    let template_id = uuid::Uuid::parse_str(&template_id_str)
        .map_err(|_| JsonResponse::<serde_json::Value>::build().bad_request("Invalid UUID"))?;

    db::marketplace::increment_deploy_count(pg_pool.get_ref(), &template_id)
        .await
        .map_err(|err| JsonResponse::<serde_json::Value>::build().internal_server_error(err))
        .map(|_| JsonResponse::<serde_json::Value>::build().ok("Deploy count incremented"))
}
