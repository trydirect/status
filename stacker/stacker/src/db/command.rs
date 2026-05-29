use crate::models::{Command, CommandPriority, CommandStatus};
use sqlx::types::JsonValue;
use sqlx::PgPool;
use tracing::Instrument;

/// Insert a new command into the database
#[tracing::instrument(name = "Insert command into database", skip(pool))]
pub async fn insert(pool: &PgPool, command: &Command) -> Result<Command, String> {
    let query_span = tracing::info_span!("Saving command to database");
    sqlx::query_as!(
        Command,
        r#"
        INSERT INTO commands (
            id, command_id, deployment_hash, type, status, priority,
            parameters, result, error, created_by, created_at, updated_at,
            timeout_seconds, metadata
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
        RETURNING id, command_id, deployment_hash, type, status, priority,
                  parameters, result, error, created_by, created_at, updated_at,
                  timeout_seconds, metadata
        "#,
        command.id,
        command.command_id,
        command.deployment_hash,
        command.r#type,
        command.status,
        command.priority,
        command.parameters,
        command.result,
        command.error,
        command.created_by,
        command.created_at,
        command.updated_at,
        command.timeout_seconds,
        command.metadata,
    )
    .fetch_one(pool)
    .instrument(query_span)
    .await
    .map_err(|err| {
        tracing::error!("Failed to insert command: {:?}", err);
        format!("Failed to insert command: {}", err)
    })
}

/// Add command to the queue
#[tracing::instrument(name = "Add command to queue", skip(pool))]
pub async fn add_to_queue(
    pool: &PgPool,
    command_id: &str,
    deployment_hash: &str,
    priority: &CommandPriority,
) -> Result<(), String> {
    let query_span = tracing::info_span!("Adding command to queue");
    sqlx::query!(
        r#"
        INSERT INTO command_queue (command_id, deployment_hash, priority)
        VALUES ($1, $2, $3)
        "#,
        command_id,
        deployment_hash,
        priority.to_int(),
    )
    .execute(pool)
    .instrument(query_span)
    .await
    .map_err(|err| {
        tracing::error!("Failed to add command to queue: {:?}", err);
        format!("Failed to add command to queue: {}", err)
    })
    .map(|_| ())
}

/// Fetch next command for a deployment (highest priority, oldest first)
#[tracing::instrument(name = "Fetch next command for deployment", skip(pool))]
pub async fn fetch_next_for_deployment(
    pool: &PgPool,
    deployment_hash: &str,
) -> Result<Option<Command>, String> {
    let query_span = tracing::info_span!("Fetching next command from queue");
    sqlx::query_as!(
        Command,
        r#"
        SELECT c.id, c.command_id, c.deployment_hash, c.type, c.status, c.priority,
               c.parameters, c.result, c.error, c.created_by, c.created_at, c.updated_at,
               c.timeout_seconds, c.metadata
        FROM commands c
        INNER JOIN command_queue q ON c.command_id = q.command_id
        WHERE q.deployment_hash = $1
        ORDER BY q.priority DESC, q.created_at ASC
        LIMIT 1
        "#,
        deployment_hash,
    )
    .fetch_optional(pool)
    .instrument(query_span)
    .await
    .map_err(|err| {
        tracing::error!("Failed to fetch next command: {:?}", err);
        format!("Failed to fetch next command: {}", err)
    })
}

/// Remove command from queue (after sending to agent)
#[tracing::instrument(name = "Remove command from queue", skip(pool))]
pub async fn remove_from_queue(pool: &PgPool, command_id: &str) -> Result<(), String> {
    let query_span = tracing::info_span!("Removing command from queue");
    sqlx::query!(
        r#"
        DELETE FROM command_queue
        WHERE command_id = $1
        "#,
        command_id,
    )
    .execute(pool)
    .instrument(query_span)
    .await
    .map_err(|err| {
        tracing::error!("Failed to remove command from queue: {:?}", err);
        format!("Failed to remove command from queue: {}", err)
    })
    .map(|_| ())
}

/// Update command status
#[tracing::instrument(name = "Update command status", skip(pool))]
pub async fn update_status(
    pool: &PgPool,
    command_id: &str,
    status: &CommandStatus,
) -> Result<Command, String> {
    let query_span = tracing::info_span!("Updating command status");
    sqlx::query_as!(
        Command,
        r#"
        UPDATE commands
        SET status = $2, updated_at = NOW()
        WHERE command_id = $1
        RETURNING id, command_id, deployment_hash, type, status, priority,
                  parameters, result, error, created_by, created_at, updated_at,
                  timeout_seconds, metadata
        "#,
        command_id,
        status.to_string(),
    )
    .fetch_one(pool)
    .instrument(query_span)
    .await
    .map_err(|err| {
        tracing::error!("Failed to update command status: {:?}", err);
        format!("Failed to update command status: {}", err)
    })
}

/// Update command result and status
#[tracing::instrument(name = "Update command result", skip(pool))]
pub async fn update_result(
    pool: &PgPool,
    command_id: &str,
    status: &CommandStatus,
    result: Option<JsonValue>,
    error: Option<JsonValue>,
) -> Result<Command, String> {
    let query_span = tracing::info_span!("Updating command result");
    sqlx::query_as!(
        Command,
        r#"
        UPDATE commands
        SET status = $2, result = $3, error = $4, updated_at = NOW()
        WHERE command_id = $1
        RETURNING id, command_id, deployment_hash, type, status, priority,
                  parameters, result, error, created_by, created_at, updated_at,
                  timeout_seconds, metadata
        "#,
        command_id,
        status.to_string(),
        result,
        error,
    )
    .fetch_one(pool)
    .instrument(query_span)
    .await
    .map_err(|err| {
        tracing::error!("Failed to update command result: {:?}", err);
        format!("Failed to update command result: {}", err)
    })
}

/// Update command result and merge metadata patch
#[tracing::instrument(name = "Update command result with metadata", skip(pool))]
pub async fn update_result_with_metadata(
    pool: &PgPool,
    command_id: &str,
    status: &CommandStatus,
    result: Option<JsonValue>,
    error: Option<JsonValue>,
    metadata: Option<JsonValue>,
) -> Result<Command, String> {
    let query_span = tracing::info_span!("Updating command result with metadata");
    sqlx::query_as::<_, Command>(
        r#"
        UPDATE commands
        SET status = $2,
            result = $3,
            error = $4,
            metadata = CASE
                WHEN $5 IS NULL THEN metadata
                ELSE COALESCE(metadata, '{}'::jsonb) || $5
            END,
            updated_at = NOW()
        WHERE command_id = $1
        RETURNING id, command_id, deployment_hash, type, status, priority,
                  parameters, result, error, created_by, created_at, updated_at,
                  timeout_seconds, metadata
        "#,
    )
    .bind(command_id)
    .bind(status.to_string())
    .bind(result)
    .bind(error)
    .bind(metadata)
    .fetch_one(pool)
    .instrument(query_span)
    .await
    .map_err(|err| {
        tracing::error!("Failed to update command result with metadata: {:?}", err);
        format!("Failed to update command result with metadata: {}", err)
    })
}

/// Fetch command by ID
#[tracing::instrument(name = "Fetch command by ID", skip(pool))]
pub async fn fetch_by_id(pool: &PgPool, id: &str) -> Result<Option<Command>, String> {
    let id = uuid::Uuid::parse_str(id).map_err(|err| {
        tracing::error!("Invalid ID format: {:?}", err);
        format!("Invalid ID format: {}", err)
    })?;

    let query_span = tracing::info_span!("Fetching command by ID");
    sqlx::query_as!(
        Command,
        r#"
        SELECT id, command_id, deployment_hash, type, status, priority,
               parameters, result, error, created_by, created_at, updated_at,
               timeout_seconds, metadata
        FROM commands
        WHERE id = $1
        "#,
        id,
    )
    .fetch_optional(pool)
    .instrument(query_span)
    .await
    .map_err(|err| {
        tracing::error!("Failed to fetch command: {:?}", err);
        format!("Failed to fetch command: {}", err)
    })
}

#[tracing::instrument(name = "Fetch command by command_id", skip(pool))]
pub async fn fetch_by_command_id(
    pool: &PgPool,
    command_id: &str,
) -> Result<Option<Command>, String> {
    let query_span = tracing::info_span!("Fetching command by command_id");
    sqlx::query_as!(
        Command,
        r#"
        SELECT id, command_id, deployment_hash, type, status, priority,
               parameters, result, error, created_by, created_at, updated_at,
               timeout_seconds, metadata
        FROM commands
        WHERE command_id = $1
        "#,
        command_id,
    )
    .fetch_optional(pool)
    .instrument(query_span)
    .await
    .map_err(|err| {
        tracing::error!("Failed to fetch command: {:?}", err);
        format!("Failed to fetch command: {}", err)
    })
}

/// Fetch all commands for a deployment
#[tracing::instrument(name = "Fetch commands for deployment", skip(pool))]
pub async fn fetch_by_deployment(
    pool: &PgPool,
    deployment_hash: &str,
) -> Result<Vec<Command>, String> {
    let query_span = tracing::info_span!("Fetching commands for deployment");
    sqlx::query_as!(
        Command,
        r#"
        SELECT id, command_id, deployment_hash, type, status, priority,
               parameters, result, error, created_by, created_at, updated_at,
               timeout_seconds, metadata
        FROM commands
        WHERE deployment_hash = $1
        ORDER BY created_at DESC
        "#,
        deployment_hash,
    )
    .fetch_all(pool)
    .instrument(query_span)
    .await
    .map_err(|err| {
        tracing::error!("Failed to fetch commands: {:?}", err);
        format!("Failed to fetch commands: {}", err)
    })
}

/// Fetch commands updated after a timestamp for a deployment
#[tracing::instrument(name = "Fetch command updates", skip(pool))]
pub async fn fetch_updates_by_deployment(
    pool: &PgPool,
    deployment_hash: &str,
    since: chrono::DateTime<chrono::Utc>,
    limit: i64,
) -> Result<Vec<Command>, String> {
    let query_span = tracing::info_span!("Fetching command updates for deployment");
    sqlx::query_as::<_, Command>(
        r#"
        SELECT id, command_id, deployment_hash, type, status, priority,
               parameters, result, error, created_by, created_at, updated_at,
               timeout_seconds, metadata
        FROM commands
        WHERE deployment_hash = $1
          AND updated_at > $2
        ORDER BY updated_at DESC
        LIMIT $3
        "#,
    )
    .bind(deployment_hash)
    .bind(since)
    .bind(limit)
    .fetch_all(pool)
    .instrument(query_span)
    .await
    .map_err(|err| {
        tracing::error!("Failed to fetch command updates: {:?}", err);
        format!("Failed to fetch command updates: {}", err)
    })
}

/// Fetch recent commands for a deployment with optional result exclusion
#[tracing::instrument(name = "Fetch recent commands for deployment", skip(pool))]
pub async fn fetch_recent_by_deployment(
    pool: &PgPool,
    deployment_hash: &str,
    limit: i64,
    exclude_results: bool,
) -> Result<Vec<Command>, String> {
    let query_span = tracing::info_span!("Fetching recent commands for deployment");

    if exclude_results {
        // Fetch commands without result/error fields to reduce payload size
        sqlx::query_as::<_, Command>(
            r#"
            SELECT id, command_id, deployment_hash, type, status, priority,
                   parameters, NULL as result, NULL as error, created_by, created_at, updated_at,
                   timeout_seconds, metadata
            FROM commands
            WHERE deployment_hash = $1
            ORDER BY created_at DESC
            LIMIT $2
            "#,
        )
        .bind(deployment_hash)
        .bind(limit)
        .fetch_all(pool)
        .instrument(query_span)
        .await
        .map_err(|err| {
            tracing::error!("Failed to fetch recent commands: {:?}", err);
            format!("Failed to fetch recent commands: {}", err)
        })
    } else {
        // Fetch commands with all fields including results
        sqlx::query_as::<_, Command>(
            r#"
            SELECT id, command_id, deployment_hash, type, status, priority,
                   parameters, result, error, created_by, created_at, updated_at,
                   timeout_seconds, metadata
            FROM commands
            WHERE deployment_hash = $1
            ORDER BY created_at DESC
            LIMIT $2
            "#,
        )
        .bind(deployment_hash)
        .bind(limit)
        .fetch_all(pool)
        .instrument(query_span)
        .await
        .map_err(|err| {
            tracing::error!("Failed to fetch recent commands: {:?}", err);
            format!("Failed to fetch recent commands: {}", err)
        })
    }
}

/// Cancel a command (remove from queue and mark as cancelled)
#[tracing::instrument(name = "Cancel command", skip(pool))]
pub async fn cancel(pool: &PgPool, command_id: &str) -> Result<Command, String> {
    // Start transaction
    let mut tx = pool.begin().await.map_err(|err| {
        tracing::error!("Failed to start transaction: {:?}", err);
        format!("Failed to start transaction: {}", err)
    })?;

    // Remove from queue (if exists)
    let _ = sqlx::query!(
        r#"
        DELETE FROM command_queue
        WHERE command_id = $1
        "#,
        command_id,
    )
    .execute(&mut *tx)
    .await;

    // Update status to cancelled
    let command = sqlx::query_as!(
        Command,
        r#"
        UPDATE commands
        SET status = 'cancelled', updated_at = NOW()
        WHERE command_id = $1
        RETURNING id, command_id, deployment_hash, type, status, priority,
                  parameters, result, error, created_by, created_at, updated_at,
                  timeout_seconds, metadata
        "#,
        command_id,
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(|err| {
        tracing::error!("Failed to cancel command: {:?}", err);
        format!("Failed to cancel command: {}", err)
    })?;

    // Commit transaction
    tx.commit().await.map_err(|err| {
        tracing::error!("Failed to commit transaction: {:?}", err);
        format!("Failed to commit transaction: {}", err)
    })?;

    Ok(command)
}
