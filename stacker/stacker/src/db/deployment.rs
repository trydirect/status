use crate::models;
use sqlx::PgPool;
use sqlx::Row;
use tracing::Instrument;

pub async fn fetch(pool: &PgPool, id: i32) -> Result<Option<models::Deployment>, String> {
    tracing::info!("Fetch deployment {}", id);
    sqlx::query_as!(
        models::Deployment,
        r#"
        SELECT id, project_id, deployment_hash, user_id, deleted, status, runtime, metadata,
               last_seen_at, created_at, updated_at
        FROM deployment
        WHERE id=$1
        LIMIT 1
        "#,
        id
    )
    .fetch_one(pool)
    .await
    .map(|deployment| Some(deployment))
    .or_else(|err| match err {
        sqlx::Error::RowNotFound => Ok(None),
        e => {
            tracing::error!("Failed to fetch deployment, error: {:?}", e);
            Err("Could not fetch data".to_string())
        }
    })
}

pub async fn insert(
    pool: &PgPool,
    mut deployment: models::Deployment,
) -> Result<models::Deployment, String> {
    let query_span = tracing::info_span!("Saving new deployment into the database");
    sqlx::query!(
        r#"
        INSERT INTO deployment (
            project_id, user_id, deployment_hash, deleted, status, runtime, metadata, last_seen_at, created_at, updated_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        RETURNING id;
        "#,
        deployment.project_id,
        deployment.user_id,
        deployment.deployment_hash,
        deployment.deleted,
        deployment.status,
        deployment.runtime,
        deployment.metadata,
        deployment.last_seen_at,
        deployment.created_at,
        deployment.updated_at,
    )
        .fetch_one(pool)
        .instrument(query_span)
        .await
        .map(move |result| {
            deployment.id = result.id;
            deployment
        })
        .map_err(|e| {
            tracing::error!("Failed to execute query: {:?}", e);
            "Failed to insert".to_string()
        })
}

pub async fn update(
    pool: &PgPool,
    mut deployment: models::Deployment,
) -> Result<models::Deployment, String> {
    let query_span = tracing::info_span!("Updating user deployment into the database");
    sqlx::query_as!(
        models::Deployment,
        r#"
        UPDATE deployment
        SET
            project_id=$2,
            user_id=$3,
            deployment_hash=$4,
            deleted=$5,
            status=$6,
            runtime=$7,
            metadata=$8,
            last_seen_at=$9,
            updated_at=NOW() at time zone 'utc'
        WHERE id = $1
        RETURNING *
        "#,
        deployment.id,
        deployment.project_id,
        deployment.user_id,
        deployment.deployment_hash,
        deployment.deleted,
        deployment.status,
        deployment.runtime,
        deployment.metadata,
        deployment.last_seen_at,
    )
    .fetch_one(pool)
    .instrument(query_span)
    .await
    .map(|result| {
        tracing::info!("Deployment {} has been updated", deployment.id);
        deployment.updated_at = result.updated_at;
        deployment
    })
    .map_err(|err| {
        tracing::error!("Failed to execute query: {:?}", err);
        "".to_string()
    })
}

pub async fn fetch_by_deployment_hash(
    pool: &PgPool,
    deployment_hash: &str,
) -> Result<Option<models::Deployment>, String> {
    tracing::info!("Fetch deployment by hash: {}", deployment_hash);
    sqlx::query_as!(
        models::Deployment,
        r#"
        SELECT id, project_id, deployment_hash, user_id, deleted, status, runtime, metadata,
               last_seen_at, created_at, updated_at
        FROM deployment
        WHERE deployment_hash = $1
        LIMIT 1
        "#,
        deployment_hash
    )
    .fetch_one(pool)
    .await
    .map(Some)
    .or_else(|err| match err {
        sqlx::Error::RowNotFound => Ok(None),
        e => {
            tracing::error!("Failed to fetch deployment by hash: {:?}", e);
            Err("Could not fetch deployment".to_string())
        }
    })
}

/// Fetch deployment by project ID
pub async fn fetch_by_project_id(
    pool: &PgPool,
    project_id: i32,
) -> Result<Option<models::Deployment>, String> {
    tracing::debug!("Fetch deployment by project_id: {}", project_id);
    sqlx::query_as!(
        models::Deployment,
        r#"
        SELECT id, project_id, deployment_hash, user_id, deleted, status, runtime, metadata,
               last_seen_at, created_at, updated_at
        FROM deployment
        WHERE project_id = $1 AND deleted = false
        ORDER BY created_at DESC
        LIMIT 1
        "#,
        project_id
    )
    .fetch_one(pool)
    .await
    .map(Some)
    .or_else(|err| match err {
        sqlx::Error::RowNotFound => Ok(None),
        e => {
            tracing::error!("Failed to fetch deployment by project_id: {:?}", e);
            Err("Could not fetch deployment".to_string())
        }
    })
}

pub async fn fetch_by_user(
    pool: &PgPool,
    user_id: &str,
    limit: i64,
) -> Result<Vec<models::Deployment>, String> {
    tracing::debug!("Fetch deployments by user_id: {}", user_id);
    sqlx::query_as!(
        models::Deployment,
        r#"
        SELECT id, project_id, deployment_hash, user_id, deleted, status, runtime, metadata,
               last_seen_at, created_at, updated_at
        FROM deployment
        WHERE user_id = $1 AND deleted = false
        ORDER BY created_at DESC
        LIMIT $2
        "#,
        user_id,
        limit,
    )
    .fetch_all(pool)
    .await
    .map_err(|err| {
        tracing::error!("Failed to fetch deployments by user_id: {:?}", err);
        "Could not fetch deployments".to_string()
    })
}

pub async fn fetch_by_user_and_project(
    pool: &PgPool,
    user_id: &str,
    project_id: i32,
    limit: i64,
) -> Result<Vec<models::Deployment>, String> {
    tracing::debug!(
        "Fetch deployments by user_id: {} and project_id: {}",
        user_id,
        project_id
    );
    sqlx::query_as!(
        models::Deployment,
        r#"
        SELECT id, project_id, deployment_hash, user_id, deleted, status, runtime, metadata,
               last_seen_at, created_at, updated_at
        FROM deployment
        WHERE user_id = $1 AND project_id = $2 AND deleted = false
        ORDER BY created_at DESC
        LIMIT $3
        "#,
        user_id,
        project_id,
        limit,
    )
    .fetch_all(pool)
    .await
    .map_err(|err| {
        tracing::error!(
            "Failed to fetch deployments by user_id/project_id: {:?}",
            err
        );
        "Could not fetch deployments".to_string()
    })
}

pub async fn fetch_by_project(
    pool: &PgPool,
    project_id: i32,
    limit: i64,
) -> Result<Vec<models::Deployment>, String> {
    tracing::debug!("Fetch deployments by project_id: {}", project_id);
    sqlx::query(
        r#"
        SELECT id, project_id, deployment_hash, user_id, deleted, status, runtime, metadata,
               last_seen_at, created_at, updated_at
        FROM deployment
        WHERE project_id = $1 AND deleted = false
        ORDER BY created_at DESC
        LIMIT $2
        "#,
    )
    .bind(project_id)
    .bind(limit)
    .fetch_all(pool)
    .await
    .map(|rows| {
        rows.into_iter()
            .map(|row| models::Deployment {
                id: row.get("id"),
                project_id: row.get("project_id"),
                deployment_hash: row.get("deployment_hash"),
                user_id: row.get("user_id"),
                deleted: row.get("deleted"),
                status: row.get("status"),
                runtime: row.get("runtime"),
                metadata: row.get("metadata"),
                last_seen_at: row.get("last_seen_at"),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
            })
            .collect()
    })
    .map_err(|err| {
        tracing::error!("Failed to fetch deployments by project_id: {:?}", err);
        "Could not fetch deployments".to_string()
    })
}
