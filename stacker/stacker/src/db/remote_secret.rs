use crate::models::RemoteSecret;
use sqlx::{PgPool, Row};

pub async fn fetch_service_secret(
    pool: &PgPool,
    user_id: &str,
    project_id: i32,
    app_code: &str,
    name: &str,
) -> Result<Option<RemoteSecret>, String> {
    sqlx::query_as::<_, RemoteSecret>(
        r#"
        SELECT *
        FROM remote_secret
        WHERE user_id = $1
          AND scope = 'service'
          AND project_id = $2
          AND app_code = $3
          AND name = $4
        LIMIT 1
        "#,
    )
    .bind(user_id)
    .bind(project_id)
    .bind(app_code)
    .bind(name)
    .fetch_optional(pool)
    .await
    .map_err(|e| format!("Failed to fetch service secret metadata: {}", e))
}

pub async fn list_service_secrets(
    pool: &PgPool,
    user_id: &str,
    project_id: i32,
    app_code: &str,
) -> Result<Vec<RemoteSecret>, String> {
    sqlx::query_as::<_, RemoteSecret>(
        r#"
        SELECT *
        FROM remote_secret
        WHERE user_id = $1
          AND scope = 'service'
          AND project_id = $2
          AND app_code = $3
        ORDER BY name ASC
        "#,
    )
    .bind(user_id)
    .bind(project_id)
    .bind(app_code)
    .fetch_all(pool)
    .await
    .map_err(|e| format!("Failed to list service secret metadata: {}", e))
}

pub async fn fetch_server_secret(
    pool: &PgPool,
    user_id: &str,
    server_id: i32,
    name: &str,
) -> Result<Option<RemoteSecret>, String> {
    sqlx::query_as::<_, RemoteSecret>(
        r#"
        SELECT *
        FROM remote_secret
        WHERE user_id = $1
          AND scope = 'server'
          AND server_id = $2
          AND name = $3
        LIMIT 1
        "#,
    )
    .bind(user_id)
    .bind(server_id)
    .bind(name)
    .fetch_optional(pool)
    .await
    .map_err(|e| format!("Failed to fetch server secret metadata: {}", e))
}

pub async fn list_server_secrets(
    pool: &PgPool,
    user_id: &str,
    server_id: i32,
) -> Result<Vec<RemoteSecret>, String> {
    sqlx::query_as::<_, RemoteSecret>(
        r#"
        SELECT *
        FROM remote_secret
        WHERE user_id = $1
          AND scope = 'server'
          AND server_id = $2
        ORDER BY name ASC
        "#,
    )
    .bind(user_id)
    .bind(server_id)
    .fetch_all(pool)
    .await
    .map_err(|e| format!("Failed to list server secret metadata: {}", e))
}

pub async fn upsert_service_secret(
    pool: &PgPool,
    user_id: &str,
    project_id: i32,
    app_code: &str,
    name: &str,
    vault_path: &str,
    updated_by: &str,
    last_sync_status: &str,
) -> Result<RemoteSecret, String> {
    sqlx::query_as::<_, RemoteSecret>(
        r#"
        INSERT INTO remote_secret (
            user_id,
            project_id,
            app_code,
            server_id,
            scope,
            name,
            vault_path,
            updated_by,
            last_sync_status
        )
        VALUES ($1, $2, $3, NULL, 'service', $4, $5, $6, $7)
        ON CONFLICT (user_id, project_id, app_code, name) WHERE scope = 'service'
        DO UPDATE SET
            vault_path = EXCLUDED.vault_path,
            updated_by = EXCLUDED.updated_by,
            last_sync_status = EXCLUDED.last_sync_status,
            updated_at = NOW()
        RETURNING *
        "#,
    )
    .bind(user_id)
    .bind(project_id)
    .bind(app_code)
    .bind(name)
    .bind(vault_path)
    .bind(updated_by)
    .bind(last_sync_status)
    .fetch_one(pool)
    .await
    .map_err(|e| format!("Failed to upsert service secret metadata: {}", e))
}

pub async fn upsert_server_secret(
    pool: &PgPool,
    user_id: &str,
    server_id: i32,
    name: &str,
    vault_path: &str,
    updated_by: &str,
    last_sync_status: &str,
) -> Result<RemoteSecret, String> {
    sqlx::query_as::<_, RemoteSecret>(
        r#"
        INSERT INTO remote_secret (
            user_id,
            project_id,
            app_code,
            server_id,
            scope,
            name,
            vault_path,
            updated_by,
            last_sync_status
        )
        VALUES ($1, NULL, NULL, $2, 'server', $3, $4, $5, $6)
        ON CONFLICT (user_id, server_id, name) WHERE scope = 'server'
        DO UPDATE SET
            vault_path = EXCLUDED.vault_path,
            updated_by = EXCLUDED.updated_by,
            last_sync_status = EXCLUDED.last_sync_status,
            updated_at = NOW()
        RETURNING *
        "#,
    )
    .bind(user_id)
    .bind(server_id)
    .bind(name)
    .bind(vault_path)
    .bind(updated_by)
    .bind(last_sync_status)
    .fetch_one(pool)
    .await
    .map_err(|e| format!("Failed to upsert server secret metadata: {}", e))
}

pub async fn delete_secret_by_id(pool: &PgPool, id: i32) -> Result<bool, String> {
    let deleted = sqlx::query("DELETE FROM remote_secret WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await
        .map_err(|e| format!("Failed to delete secret metadata: {}", e))?
        .rows_affected();

    Ok(deleted > 0)
}

pub async fn count_by_scope(pool: &PgPool, scope: &str) -> Result<i64, String> {
    sqlx::query("SELECT COUNT(*) AS count FROM remote_secret WHERE scope = $1")
        .bind(scope)
        .fetch_one(pool)
        .await
        .map(|row| row.get::<i64, _>("count"))
        .map_err(|e| format!("Failed to count remote secrets: {}", e))
}
