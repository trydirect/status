use crate::configuration::Settings;
use crate::db;
use crate::helpers::JsonResponse;
use crate::models::User;
use crate::routes::legacy_installations::resolve_owned_deployment_by_hash;
use actix_web::{get, web, Responder, Result};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use sqlx::PgPool;
use std::sync::Arc;
use tokio::time::{sleep, Duration, Instant};

#[derive(Debug, Deserialize)]
pub struct CommandListQuery {
    pub since: Option<String>,
    pub limit: Option<i64>,
    pub wait_ms: Option<u64>,
    #[serde(default)]
    pub include_results: bool,
}

#[tracing::instrument(name = "List commands for deployment", skip_all)]
#[get("/{deployment_hash}")]
pub async fn list_handler(
    user: web::ReqData<Arc<User>>,
    path: web::Path<String>,
    query: web::Query<CommandListQuery>,
    pg_pool: web::Data<PgPool>,
    settings: web::Data<Settings>,
) -> Result<impl Responder> {
    let deployment_hash = path.into_inner();
    let limit = query.limit.unwrap_or(50).max(1).min(500);

    resolve_owned_deployment_by_hash(
        pg_pool.get_ref(),
        settings.get_ref(),
        user.as_ref(),
        &deployment_hash,
    )
    .await?;

    let commands = if let Some(since_raw) = &query.since {
        let since = DateTime::parse_from_rfc3339(since_raw)
            .map_err(|_err| JsonResponse::bad_request("Invalid since timestamp"))?
            .with_timezone(&Utc);

        let wait_ms = query.wait_ms.unwrap_or(0).min(30_000);
        let deadline = Instant::now() + Duration::from_millis(wait_ms);

        loop {
            let updates = db::command::fetch_updates_by_deployment(
                pg_pool.get_ref(),
                &deployment_hash,
                since,
                limit,
            )
            .await
            .map_err(|err| {
                tracing::error!("Failed to fetch command updates: {}", err);
                JsonResponse::internal_server_error(err)
            })?;

            if !updates.is_empty() || wait_ms == 0 || Instant::now() >= deadline {
                break updates;
            }

            sleep(Duration::from_millis(500)).await;
        }
    } else {
        // Default behavior: fetch recent commands with limit
        // include_results defaults to false for performance, but can be enabled by client
        db::command::fetch_recent_by_deployment(
            pg_pool.get_ref(),
            &deployment_hash,
            limit,
            !query.include_results,
        )
        .await
        .map_err(|err| {
            tracing::error!("Failed to fetch commands: {}", err);
            JsonResponse::internal_server_error(err)
        })?
    };

    tracing::info!(
        "Fetched {} commands for deployment {} by user {}",
        commands.len(),
        deployment_hash,
        user.id
    );

    Ok(JsonResponse::build()
        .set_list(commands)
        .ok("Commands fetched successfully"))
}
