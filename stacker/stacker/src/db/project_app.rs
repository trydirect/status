//! Database operations for App configurations.
//!
//! Apps are container configurations within a project.
//! Each project can have multiple apps (nginx, postgres, redis, etc.)

use crate::models;
use sqlx::PgPool;
use tracing::Instrument;

/// Fetch a single app by ID
pub async fn fetch(pool: &PgPool, id: i32) -> Result<Option<models::ProjectApp>, String> {
    tracing::debug!("Fetching app by id: {}", id);
    sqlx::query_as!(
        models::ProjectApp,
        r#"
        SELECT * FROM project_app WHERE id = $1 LIMIT 1
        "#,
        id
    )
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        tracing::error!("Failed to fetch app: {:?}", e);
        format!("Failed to fetch app: {}", e)
    })
}

/// Fetch all apps for a project
pub async fn fetch_by_project(
    pool: &PgPool,
    project_id: i32,
) -> Result<Vec<models::ProjectApp>, String> {
    let query_span = tracing::info_span!("Fetch apps by project id");
    sqlx::query_as!(
        models::ProjectApp,
        r#"
        SELECT * FROM project_app 
        WHERE project_id = $1 
        ORDER BY deploy_order ASC NULLS LAST, id ASC
        "#,
        project_id
    )
    .fetch_all(pool)
    .instrument(query_span)
    .await
    .map_err(|e| {
        tracing::error!("Failed to fetch apps for project: {:?}", e);
        format!("Failed to fetch apps: {}", e)
    })
}

/// Fetch all apps for a specific deployment.
/// Falls back to project-level apps if no deployment-scoped apps exist (backward compatibility).
pub async fn fetch_by_deployment(
    pool: &PgPool,
    project_id: i32,
    deployment_id: i32,
) -> Result<Vec<models::ProjectApp>, String> {
    let query_span = tracing::info_span!("Fetch apps by deployment id");
    let apps = sqlx::query_as!(
        models::ProjectApp,
        r#"
        SELECT * FROM project_app 
        WHERE project_id = $1 AND deployment_id = $2
        ORDER BY deploy_order ASC NULLS LAST, id ASC
        "#,
        project_id,
        deployment_id
    )
    .fetch_all(pool)
    .instrument(query_span)
    .await
    .map_err(|e| {
        tracing::error!("Failed to fetch apps for deployment: {:?}", e);
        format!("Failed to fetch apps by deployment: {}", e)
    })?;

    // Backward compatibility: if no deployment-scoped apps, fall back to project-level (deployment_id IS NULL)
    if apps.is_empty() {
        tracing::debug!(
            "No deployment-scoped apps for deployment_id={}, falling back to project-level apps",
            deployment_id
        );
        return fetch_by_project(pool, project_id).await;
    }

    Ok(apps)
}

/// Fetch a single app by project ID and app code
pub async fn fetch_by_project_and_code(
    pool: &PgPool,
    project_id: i32,
    code: &str,
) -> Result<Option<models::ProjectApp>, String> {
    tracing::debug!("Fetching app by project {} and code {}", project_id, code);
    sqlx::query_as!(
        models::ProjectApp,
        r#"
        SELECT * FROM project_app 
        WHERE project_id = $1 AND code = $2 
        LIMIT 1
        "#,
        project_id,
        code
    )
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        tracing::error!("Failed to fetch app by code: {:?}", e);
        format!("Failed to fetch app: {}", e)
    })
}

/// Insert a new app
pub async fn insert(pool: &PgPool, app: &models::ProjectApp) -> Result<models::ProjectApp, String> {
    let query_span = tracing::info_span!("Inserting new app");
    sqlx::query_as!(
        models::ProjectApp,
        r#"
        INSERT INTO project_app (
            project_id, code, name, image, environment, ports, volumes,
            domain, ssl_enabled, resources, restart_policy, command,
            entrypoint, networks, depends_on, healthcheck, labels,
            config_files, template_source, enabled, deploy_order, parent_app_code,
            deployment_id, created_at, updated_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, NOW(), NOW())
        RETURNING *
        "#,
        app.project_id,
        app.code,
        app.name,
        app.image,
        app.environment,
        app.ports,
        app.volumes,
        app.domain,
        app.ssl_enabled,
        app.resources,
        app.restart_policy,
        app.command,
        app.entrypoint,
        app.networks,
        app.depends_on,
        app.healthcheck,
        app.labels,
        app.config_files,
        app.template_source,
        app.enabled,
        app.deploy_order,
        app.parent_app_code,
        app.deployment_id,
    )
    .fetch_one(pool)
    .instrument(query_span)
    .await
    .map_err(|e| {
        tracing::error!("Failed to insert app: {:?}", e);
        format!("Failed to insert app: {}", e)
    })
}

/// Update an existing app
pub async fn update(pool: &PgPool, app: &models::ProjectApp) -> Result<models::ProjectApp, String> {
    let query_span = tracing::info_span!("Updating app");
    sqlx::query_as!(
        models::ProjectApp,
        r#"
        UPDATE project_app SET
            code = $2,
            name = $3,
            image = $4,
            environment = $5,
            ports = $6,
            volumes = $7,
            domain = $8,
            ssl_enabled = $9,
            resources = $10,
            restart_policy = $11,
            command = $12,
            entrypoint = $13,
            networks = $14,
            depends_on = $15,
            healthcheck = $16,
            labels = $17,
            config_files = $18,
            template_source = $19,
            enabled = $20,
            deploy_order = $21,
            parent_app_code = $22,
            deployment_id = $23,
            config_version = COALESCE(config_version, 0) + 1,
            updated_at = NOW()
        WHERE id = $1
        RETURNING *
        "#,
        app.id,
        app.code,
        app.name,
        app.image,
        app.environment,
        app.ports,
        app.volumes,
        app.domain,
        app.ssl_enabled,
        app.resources,
        app.restart_policy,
        app.command,
        app.entrypoint,
        app.networks,
        app.depends_on,
        app.healthcheck,
        app.labels,
        app.config_files,
        app.template_source,
        app.enabled,
        app.deploy_order,
        app.parent_app_code,
        app.deployment_id,
    )
    .fetch_one(pool)
    .instrument(query_span)
    .await
    .map_err(|e| {
        tracing::error!("Failed to update app: {:?}", e);
        format!("Failed to update app: {}", e)
    })
}

/// Update metadata after a rendered app config is successfully stored in Vault.
pub async fn update_sync_metadata(
    pool: &PgPool,
    app_id: i32,
    config_hash: &str,
) -> Result<(), String> {
    let query_span = tracing::info_span!("Updating app config sync metadata");
    let result = sqlx::query(
        r#"
        UPDATE project_app
        SET
            vault_synced_at = NOW(),
            vault_sync_version = config_version,
            config_hash = $2,
            updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(app_id)
    .bind(config_hash)
    .execute(pool)
    .instrument(query_span)
    .await
    .map_err(|e| {
        tracing::error!("Failed to update app config sync metadata: {:?}", e);
        format!("Failed to update app config sync metadata: {}", e)
    })?;

    if result.rows_affected() == 0 {
        return Err(format!(
            "Failed to update app config sync metadata: app {} not found",
            app_id
        ));
    }

    Ok(())
}

/// Delete an app by ID
pub async fn delete(pool: &PgPool, id: i32) -> Result<bool, String> {
    let query_span = tracing::info_span!("Deleting app");
    let result = sqlx::query!(
        r#"
        DELETE FROM project_app WHERE id = $1
        "#,
        id
    )
    .execute(pool)
    .instrument(query_span)
    .await
    .map_err(|e| {
        tracing::error!("Failed to delete app: {:?}", e);
        format!("Failed to delete app: {}", e)
    })?;

    Ok(result.rows_affected() > 0)
}

/// Delete an app by project ID and app code
pub async fn delete_by_project_and_code(
    pool: &PgPool,
    project_id: i32,
    code: &str,
) -> Result<bool, String> {
    let query_span = tracing::info_span!("Deleting app by project and code");
    let result = sqlx::query("DELETE FROM project_app WHERE project_id = $1 AND code = $2")
        .bind(project_id)
        .bind(code)
        .execute(pool)
        .instrument(query_span)
        .await
        .map_err(|e| {
            tracing::error!("Failed to delete app by project and code: {:?}", e);
            format!("Failed to delete app: {}", e)
        })?;

    Ok(result.rows_affected() > 0)
}

/// Delete all apps for a project
pub async fn delete_by_project(pool: &PgPool, project_id: i32) -> Result<u64, String> {
    let query_span = tracing::info_span!("Deleting all apps for project");
    let result = sqlx::query!(
        r#"
        DELETE FROM project_app WHERE project_id = $1
        "#,
        project_id
    )
    .execute(pool)
    .instrument(query_span)
    .await
    .map_err(|e| {
        tracing::error!("Failed to delete apps: {:?}", e);
        format!("Failed to delete apps: {}", e)
    })?;

    Ok(result.rows_affected())
}

/// Count apps in a project
pub async fn count_by_project(pool: &PgPool, project_id: i32) -> Result<i64, String> {
    let result = sqlx::query_scalar!(
        r#"
        SELECT COUNT(*) as "count!" FROM project_app WHERE project_id = $1
        "#,
        project_id
    )
    .fetch_one(pool)
    .await
    .map_err(|e| {
        tracing::error!("Failed to count apps: {:?}", e);
        format!("Failed to count apps: {}", e)
    })?;

    Ok(result)
}

/// Check if an app with the given code exists in the project
pub async fn exists_by_project_and_code(
    pool: &PgPool,
    project_id: i32,
    code: &str,
) -> Result<bool, String> {
    let result = sqlx::query_scalar!(
        r#"
        SELECT EXISTS(SELECT 1 FROM project_app WHERE project_id = $1 AND code = $2) as "exists!"
        "#,
        project_id,
        code
    )
    .fetch_one(pool)
    .await
    .map_err(|e| {
        tracing::error!("Failed to check app existence: {:?}", e);
        format!("Failed to check app existence: {}", e)
    })?;

    Ok(result)
}
