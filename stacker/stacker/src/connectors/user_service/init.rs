use actix_web::web;
use std::sync::Arc;

use crate::connectors::config::ConnectorConfig;
use crate::connectors::user_service::{mock, UserServiceClient, UserServiceConnector};

/// Initialize User Service connector with config from Settings
///
/// Returns configured connector wrapped in web::Data for injection into Actix app
/// Also spawns background task to sync categories from User Service
///
/// # Example
/// ```ignore
/// // In startup.rs
/// let user_service = connectors::user_service::init(&settings.connectors, pg_pool.clone());
/// App::new().app_data(user_service)
/// ```
pub fn init(
    connector_config: &ConnectorConfig,
    pg_pool: web::Data<sqlx::PgPool>,
) -> web::Data<Arc<dyn UserServiceConnector>> {
    let connector: Arc<dyn UserServiceConnector> = if let Some(user_service_config) =
        connector_config.user_service.as_ref().filter(|c| c.enabled)
    {
        let mut config = user_service_config.clone();
        // Load auth token from environment if not set in config
        if config.auth_token.is_none() {
            config.auth_token = std::env::var("USER_SERVICE_AUTH_TOKEN").ok();
        }
        tracing::info!("Initializing User Service connector: {}", config.base_url);
        Arc::new(UserServiceClient::new(config))
    } else {
        tracing::warn!("User Service connector disabled - using mock");
        Arc::new(mock::MockUserServiceConnector)
    };

    // Spawn background task to sync categories on startup
    let connector_clone = connector.clone();
    let pg_pool_clone = pg_pool.clone();
    tokio::spawn(async move {
        match connector_clone.get_categories().await {
            Ok(categories) => {
                tracing::info!("Fetched {} categories from User Service", categories.len());
                match crate::db::marketplace::sync_categories(pg_pool_clone.get_ref(), categories)
                    .await
                {
                    Ok(count) => tracing::info!("Successfully synced {} categories", count),
                    Err(e) => tracing::error!("Failed to sync categories to database: {}", e),
                }
            }
            Err(e) => tracing::warn!(
                "Failed to fetch categories from User Service (will retry later): {:?}",
                e
            ),
        }
    });

    web::Data::new(connector)
}
