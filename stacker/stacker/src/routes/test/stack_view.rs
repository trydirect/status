use crate::connectors::user_service::UserServiceClient;
use actix_web::{get, web, HttpResponse, Responder};

#[get("/stack_view")]
pub async fn test_stack_view(
    settings: web::Data<crate::configuration::Settings>,
) -> impl Responder {
    tracing::info!("Testing stack_view fetch from user service");

    let client = UserServiceClient::new_public(&settings.user_service_url);

    match client.search_stack_view("", None).await {
        Ok(apps) => {
            tracing::info!("Successfully fetched {} applications", apps.len());
            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "count": apps.len(),
                "message": format!("Successfully fetched {} applications from {}", apps.len(), settings.user_service_url)
            }))
        }
        Err(e) => {
            tracing::error!("Failed to fetch stack_view: {:?}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "success": false,
                "error": e.to_string(),
                "url": settings.user_service_url.clone()
            }))
        }
    }
}
