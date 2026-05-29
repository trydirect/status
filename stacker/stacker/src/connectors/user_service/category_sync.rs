/// Category synchronization from User Service to local Stacker mirror
///
/// Implements automatic category sync on startup to keep local category table
/// in sync with User Service as the source of truth.
use sqlx::PgPool;
use std::sync::Arc;
use tracing::Instrument;

use super::{CategoryInfo, UserServiceConnector};

/// Sync categories from User Service to local database
///
/// Fetches categories from User Service and upserts them into local stack_category table.
/// This maintains a local mirror for fast lookups and offline capability.
///
/// # Arguments
/// * `connector` - User Service connector to fetch categories from
/// * `pool` - Database connection pool for local upsert
///
/// # Returns
/// Number of categories synced, or error if sync fails
pub async fn sync_categories_from_user_service(
    connector: Arc<dyn UserServiceConnector>,
    pool: &PgPool,
) -> Result<usize, String> {
    let span = tracing::info_span!("sync_categories_from_user_service");

    // Fetch categories from User Service
    let categories = connector
        .get_categories()
        .instrument(span.clone())
        .await
        .map_err(|e| format!("Failed to fetch categories from User Service: {:?}", e))?;

    tracing::info!("Fetched {} categories from User Service", categories.len());

    if categories.is_empty() {
        tracing::warn!("No categories returned from User Service");
        return Ok(0);
    }

    // Upsert categories to local database
    let synced_count = upsert_categories(pool, categories).instrument(span).await?;

    tracing::info!(
        "Successfully synced {} categories from User Service to local mirror",
        synced_count
    );

    Ok(synced_count)
}

/// Upsert categories into local database
async fn upsert_categories(pool: &PgPool, categories: Vec<CategoryInfo>) -> Result<usize, String> {
    let mut synced_count = 0;

    for category in categories {
        // Use INSERT ... ON CONFLICT DO UPDATE to upsert
        let result = sqlx::query(
            r#"
            INSERT INTO stack_category (id, name, title, metadata)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (id) DO UPDATE
            SET name = EXCLUDED.name,
                title = EXCLUDED.title,
                metadata = EXCLUDED.metadata
            "#,
        )
        .bind(category.id)
        .bind(&category.name)
        .bind(&category.title)
        .bind(serde_json::json!({"priority": category.priority}))
        .execute(pool)
        .await
        .map_err(|e| {
            tracing::error!("Failed to upsert category {}: {:?}", category.name, e);
            format!("Failed to upsert category: {}", e)
        })?;

        if result.rows_affected() > 0 {
            synced_count += 1;
            tracing::debug!("Synced category: {} ({})", category.name, category.title);
        }
    }

    Ok(synced_count)
}
