use crate::models::pipe::{PipeExecution, PipeInstance, PipeTemplate};
use sqlx::PgPool;
use tracing::Instrument;
use uuid::Uuid;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// PipeTemplate queries
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Insert a new pipe template into the database
#[tracing::instrument(name = "Insert pipe template", skip(pool))]
pub async fn insert_template(
    pool: &PgPool,
    template: &PipeTemplate,
) -> Result<PipeTemplate, String> {
    let query_span = tracing::info_span!("Saving pipe template to database");
    sqlx::query_as::<_, PipeTemplate>(
        r#"
        INSERT INTO pipe_templates (
            id, name, description, source_app_type, source_endpoint,
            target_app_type, target_endpoint, target_external_url,
            field_mapping, config, is_public, created_by, created_at, updated_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
        RETURNING id, name, description, source_app_type, source_endpoint,
                  target_app_type, target_endpoint, target_external_url,
                  field_mapping, config, is_public, created_by, created_at, updated_at
        "#,
    )
    .bind(template.id)
    .bind(&template.name)
    .bind(&template.description)
    .bind(&template.source_app_type)
    .bind(&template.source_endpoint)
    .bind(&template.target_app_type)
    .bind(&template.target_endpoint)
    .bind(&template.target_external_url)
    .bind(&template.field_mapping)
    .bind(&template.config)
    .bind(template.is_public)
    .bind(&template.created_by)
    .bind(template.created_at)
    .bind(template.updated_at)
    .fetch_one(pool)
    .instrument(query_span)
    .await
    .map_err(|err| {
        tracing::error!("Failed to insert pipe template: {:?}", err);
        format!("Failed to insert pipe template: {}", err)
    })
}

/// Fetch a pipe template by ID
#[tracing::instrument(name = "Fetch pipe template by ID", skip(pool))]
pub async fn get_template(pool: &PgPool, id: &Uuid) -> Result<Option<PipeTemplate>, String> {
    let query_span = tracing::info_span!("Fetching pipe template by ID");
    sqlx::query_as::<_, PipeTemplate>(
        r#"
        SELECT id, name, description, source_app_type, source_endpoint,
               target_app_type, target_endpoint, target_external_url,
               field_mapping, config, is_public, created_by, created_at, updated_at
        FROM pipe_templates
        WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .instrument(query_span)
    .await
    .map_err(|err| {
        tracing::error!("Failed to fetch pipe template: {:?}", err);
        format!("Failed to fetch pipe template: {}", err)
    })
}

/// Fetch a pipe template by name
#[tracing::instrument(name = "Fetch pipe template by name", skip(pool))]
pub async fn get_template_by_name(
    pool: &PgPool,
    name: &str,
) -> Result<Option<PipeTemplate>, String> {
    let query_span = tracing::info_span!("Fetching pipe template by name");
    sqlx::query_as::<_, PipeTemplate>(
        r#"
        SELECT id, name, description, source_app_type, source_endpoint,
               target_app_type, target_endpoint, target_external_url,
               field_mapping, config, is_public, created_by, created_at, updated_at
        FROM pipe_templates
        WHERE name = $1
        "#,
    )
    .bind(name)
    .fetch_optional(pool)
    .instrument(query_span)
    .await
    .map_err(|err| {
        tracing::error!("Failed to fetch pipe template by name: {:?}", err);
        format!("Failed to fetch pipe template by name: {}", err)
    })
}

/// List pipe templates visible to a specific user (own templates + public templates)
#[tracing::instrument(name = "List pipe templates for user", skip(pool))]
pub async fn list_templates_for_user(
    pool: &PgPool,
    user_id: &str,
    source_app_type: Option<&str>,
    target_app_type: Option<&str>,
    public_only: bool,
) -> Result<Vec<PipeTemplate>, String> {
    let query_span = tracing::info_span!("Listing pipe templates for user");

    let mut sql = String::from(
        r#"
        SELECT id, name, description, source_app_type, source_endpoint,
               target_app_type, target_endpoint, target_external_url,
               field_mapping, config, is_public, created_by, created_at, updated_at
        FROM pipe_templates
        WHERE (created_by = $1 OR is_public = true)
        "#,
    );

    let mut param_idx = 2;
    if source_app_type.is_some() {
        sql.push_str(&format!(" AND source_app_type = ${}", param_idx));
        param_idx += 1;
    }
    if target_app_type.is_some() {
        sql.push_str(&format!(" AND target_app_type = ${}", param_idx));
        param_idx += 1;
    }
    if public_only {
        sql.push_str(&format!(" AND is_public = ${}", param_idx));
    }
    sql.push_str(" ORDER BY created_at DESC");

    let mut query = sqlx::query_as::<_, PipeTemplate>(&sql);
    query = query.bind(user_id.to_string());

    if let Some(source) = source_app_type {
        query = query.bind(source.to_string());
    }
    if let Some(target) = target_app_type {
        query = query.bind(target.to_string());
    }
    if public_only {
        query = query.bind(true);
    }

    query
        .fetch_all(pool)
        .instrument(query_span)
        .await
        .map_err(|err| {
            tracing::error!("Failed to list pipe templates for user: {:?}", err);
            format!("Failed to list pipe templates: {}", err)
        })
}

/// List pipe templates with optional filters
#[tracing::instrument(name = "List pipe templates", skip(pool))]
pub async fn list_templates(
    pool: &PgPool,
    source_app_type: Option<&str>,
    target_app_type: Option<&str>,
    public_only: bool,
) -> Result<Vec<PipeTemplate>, String> {
    let query_span = tracing::info_span!("Listing pipe templates");

    // Build dynamic query based on filters
    let mut sql = String::from(
        r#"
        SELECT id, name, description, source_app_type, source_endpoint,
               target_app_type, target_endpoint, target_external_url,
               field_mapping, config, is_public, created_by, created_at, updated_at
        FROM pipe_templates
        WHERE 1=1
        "#,
    );

    let mut param_idx = 1;
    if source_app_type.is_some() {
        sql.push_str(&format!(" AND source_app_type = ${}", param_idx));
        param_idx += 1;
    }
    if target_app_type.is_some() {
        sql.push_str(&format!(" AND target_app_type = ${}", param_idx));
        param_idx += 1;
    }
    if public_only {
        sql.push_str(&format!(" AND is_public = ${}", param_idx));
    }
    sql.push_str(" ORDER BY created_at DESC");

    let mut query = sqlx::query_as::<_, PipeTemplate>(&sql);

    if let Some(source) = source_app_type {
        query = query.bind(source.to_string());
    }
    if let Some(target) = target_app_type {
        query = query.bind(target.to_string());
    }
    if public_only {
        query = query.bind(true);
    }

    query
        .fetch_all(pool)
        .instrument(query_span)
        .await
        .map_err(|err| {
            tracing::error!("Failed to list pipe templates: {:?}", err);
            format!("Failed to list pipe templates: {}", err)
        })
}

/// Delete a pipe template by ID
#[tracing::instrument(name = "Delete pipe template", skip(pool))]
pub async fn delete_template(pool: &PgPool, id: &Uuid) -> Result<bool, String> {
    let query_span = tracing::info_span!("Deleting pipe template");
    let result = sqlx::query("DELETE FROM pipe_templates WHERE id = $1")
        .bind(id)
        .execute(pool)
        .instrument(query_span)
        .await
        .map_err(|err| {
            tracing::error!("Failed to delete pipe template: {:?}", err);
            format!("Failed to delete pipe template: {}", err)
        })?;

    Ok(result.rows_affected() > 0)
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// PipeInstance queries
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Insert a new pipe instance into the database
#[tracing::instrument(name = "Insert pipe instance", skip(pool))]
pub async fn insert_instance(
    pool: &PgPool,
    instance: &PipeInstance,
) -> Result<PipeInstance, String> {
    let query_span = tracing::info_span!("Saving pipe instance to database");
    sqlx::query_as::<_, PipeInstance>(
        r#"
        INSERT INTO pipe_instances (
            id, template_id, deployment_hash, source_adapter, source_container, target_adapter,
            target_container, target_url, field_mapping_override, config_override, status,
            last_triggered_at, trigger_count, error_count, is_local, created_by, created_at,
            updated_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
        RETURNING id, template_id, deployment_hash, source_adapter, source_container,
                  target_adapter, target_container, target_url, field_mapping_override,
                  config_override, status, last_triggered_at, trigger_count, error_count,
                  is_local, created_by, created_at, updated_at
        "#,
    )
    .bind(instance.id)
    .bind(instance.template_id)
    .bind(&instance.deployment_hash)
    .bind(&instance.source_adapter)
    .bind(&instance.source_container)
    .bind(&instance.target_adapter)
    .bind(&instance.target_container)
    .bind(&instance.target_url)
    .bind(&instance.field_mapping_override)
    .bind(&instance.config_override)
    .bind(&instance.status)
    .bind(instance.last_triggered_at)
    .bind(instance.trigger_count)
    .bind(instance.error_count)
    .bind(instance.is_local)
    .bind(&instance.created_by)
    .bind(instance.created_at)
    .bind(instance.updated_at)
    .fetch_one(pool)
    .instrument(query_span)
    .await
    .map_err(|err| {
        tracing::error!("Failed to insert pipe instance: {:?}", err);
        format!("Failed to insert pipe instance: {}", err)
    })
}

/// Fetch a pipe instance by ID
#[tracing::instrument(name = "Fetch pipe instance by ID", skip(pool))]
pub async fn get_instance(pool: &PgPool, id: &Uuid) -> Result<Option<PipeInstance>, String> {
    let query_span = tracing::info_span!("Fetching pipe instance by ID");
    sqlx::query_as::<_, PipeInstance>(
        r#"
        SELECT id, template_id, deployment_hash, source_adapter, source_container,
               target_adapter, target_container, target_url, field_mapping_override,
               config_override, status, last_triggered_at, trigger_count, error_count,
               is_local, created_by, created_at, updated_at
        FROM pipe_instances
        WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .instrument(query_span)
    .await
    .map_err(|err| {
        tracing::error!("Failed to fetch pipe instance: {:?}", err);
        format!("Failed to fetch pipe instance: {}", err)
    })
}

/// List pipe instances for a specific deployment
#[tracing::instrument(name = "List pipe instances for deployment", skip(pool))]
pub async fn list_instances(
    pool: &PgPool,
    deployment_hash: &str,
) -> Result<Vec<PipeInstance>, String> {
    let query_span = tracing::info_span!("Listing pipe instances for deployment");
    sqlx::query_as::<_, PipeInstance>(
        r#"
        SELECT id, template_id, deployment_hash, source_adapter, source_container,
               target_adapter, target_container, target_url, field_mapping_override,
               config_override, status, last_triggered_at, trigger_count, error_count,
               is_local, created_by, created_at, updated_at
        FROM pipe_instances
        WHERE deployment_hash = $1
        ORDER BY created_at DESC
        "#,
    )
    .bind(deployment_hash)
    .fetch_all(pool)
    .instrument(query_span)
    .await
    .map_err(|err| {
        tracing::error!("Failed to list pipe instances: {:?}", err);
        format!("Failed to list pipe instances: {}", err)
    })
}

/// List local pipe instances for a specific user (is_local = true)
#[tracing::instrument(name = "List local pipe instances for user", skip(pool))]
pub async fn list_local_instances_by_user(
    pool: &PgPool,
    user_id: &str,
) -> Result<Vec<PipeInstance>, String> {
    let query_span = tracing::info_span!("Listing local pipe instances");
    sqlx::query_as::<_, PipeInstance>(
        r#"
        SELECT id, template_id, deployment_hash, source_adapter, source_container,
               target_adapter, target_container, target_url, field_mapping_override,
               config_override, status, last_triggered_at, trigger_count, error_count,
               is_local, created_by, created_at, updated_at
        FROM pipe_instances
        WHERE is_local = true AND created_by = $1
        ORDER BY created_at DESC
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .instrument(query_span)
    .await
    .map_err(|err| {
        tracing::error!("Failed to list local pipe instances: {:?}", err);
        format!("Failed to list local pipe instances: {}", err)
    })
}

/// Update the status of a pipe instance
#[tracing::instrument(name = "Update pipe instance status", skip(pool))]
pub async fn update_instance_status(
    pool: &PgPool,
    id: &Uuid,
    status: &str,
) -> Result<PipeInstance, String> {
    let query_span = tracing::info_span!("Updating pipe instance status");
    sqlx::query_as::<_, PipeInstance>(
        r#"
        UPDATE pipe_instances
        SET status = $2, updated_at = NOW()
        WHERE id = $1
        RETURNING id, template_id, deployment_hash, source_adapter, source_container,
                  target_adapter, target_container, target_url, field_mapping_override,
                  config_override, status, last_triggered_at, trigger_count, error_count,
                  is_local, created_by, created_at, updated_at
        "#,
    )
    .bind(id)
    .bind(status)
    .fetch_one(pool)
    .instrument(query_span)
    .await
    .map_err(|err| {
        tracing::error!("Failed to update pipe instance status: {:?}", err);
        format!("Failed to update pipe instance status: {}", err)
    })
}

/// Delete a pipe instance by ID
#[tracing::instrument(name = "Delete pipe instance", skip(pool))]
pub async fn delete_instance(pool: &PgPool, id: &Uuid) -> Result<bool, String> {
    let query_span = tracing::info_span!("Deleting pipe instance");
    let result = sqlx::query("DELETE FROM pipe_instances WHERE id = $1")
        .bind(id)
        .execute(pool)
        .instrument(query_span)
        .await
        .map_err(|err| {
            tracing::error!("Failed to delete pipe instance: {:?}", err);
            format!("Failed to delete pipe instance: {}", err)
        })?;

    Ok(result.rows_affected() > 0)
}

/// Increment trigger count (and optionally error count) for a pipe instance
#[tracing::instrument(name = "Increment pipe trigger count", skip(pool))]
pub async fn increment_trigger_count(
    pool: &PgPool,
    id: &Uuid,
    success: bool,
) -> Result<(), String> {
    let query_span = tracing::info_span!("Incrementing pipe trigger count");

    let sql = if success {
        r#"
        UPDATE pipe_instances
        SET trigger_count = trigger_count + 1,
            last_triggered_at = NOW(),
            updated_at = NOW()
        WHERE id = $1
        "#
    } else {
        r#"
        UPDATE pipe_instances
        SET trigger_count = trigger_count + 1,
            error_count = error_count + 1,
            last_triggered_at = NOW(),
            updated_at = NOW()
        WHERE id = $1
        "#
    };

    sqlx::query(sql)
        .bind(id)
        .execute(pool)
        .instrument(query_span)
        .await
        .map_err(|err| {
            tracing::error!("Failed to increment pipe trigger count: {:?}", err);
            format!("Failed to increment pipe trigger count: {}", err)
        })
        .map(|_| ())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// PipeExecution queries
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Insert a new pipe execution record
#[tracing::instrument(name = "Insert pipe execution", skip(pool))]
pub async fn insert_execution(
    pool: &PgPool,
    execution: &PipeExecution,
) -> Result<PipeExecution, String> {
    let query_span = tracing::info_span!("Saving pipe execution to database");
    sqlx::query_as::<_, PipeExecution>(
        r#"
        INSERT INTO pipe_executions (
            id, pipe_instance_id, deployment_hash, trigger_type, status,
            source_data, mapped_data, target_response, error, duration_ms,
            replay_of, is_local, created_by, started_at, completed_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
        RETURNING id, pipe_instance_id, deployment_hash, trigger_type, status,
                  source_data, mapped_data, target_response, error, duration_ms,
                  replay_of, is_local, created_by, started_at, completed_at
        "#,
    )
    .bind(execution.id)
    .bind(execution.pipe_instance_id)
    .bind(&execution.deployment_hash)
    .bind(&execution.trigger_type)
    .bind(&execution.status)
    .bind(&execution.source_data)
    .bind(&execution.mapped_data)
    .bind(&execution.target_response)
    .bind(&execution.error)
    .bind(execution.duration_ms)
    .bind(execution.replay_of)
    .bind(execution.is_local)
    .bind(&execution.created_by)
    .bind(execution.started_at)
    .bind(execution.completed_at)
    .fetch_one(pool)
    .instrument(query_span)
    .await
    .map_err(|err| {
        tracing::error!("Failed to insert pipe execution: {:?}", err);
        format!("Failed to insert pipe execution: {}", err)
    })
}

/// Fetch a pipe execution by ID
#[tracing::instrument(name = "Fetch pipe execution by ID", skip(pool))]
pub async fn get_execution(pool: &PgPool, id: &Uuid) -> Result<Option<PipeExecution>, String> {
    let query_span = tracing::info_span!("Fetching pipe execution by ID");
    sqlx::query_as::<_, PipeExecution>(
        r#"
        SELECT id, pipe_instance_id, deployment_hash, trigger_type, status,
               source_data, mapped_data, target_response, error, duration_ms,
               replay_of, is_local, created_by, started_at, completed_at
        FROM pipe_executions
        WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .instrument(query_span)
    .await
    .map_err(|err| {
        tracing::error!("Failed to fetch pipe execution: {:?}", err);
        format!("Failed to fetch pipe execution: {}", err)
    })
}

/// Find the latest pending replay execution for an instance/deployment pair.
#[tracing::instrument(name = "Find pending replay execution", skip(pool))]
pub async fn find_pending_replay_execution(
    pool: &PgPool,
    instance_id: &Uuid,
    deployment_hash: &str,
) -> Result<Option<PipeExecution>, String> {
    let query_span = tracing::info_span!("Finding pending replay execution");
    sqlx::query_as::<_, PipeExecution>(
        r#"
        SELECT id, pipe_instance_id, deployment_hash, trigger_type, status,
               source_data, mapped_data, target_response, error, duration_ms,
               replay_of, is_local, created_by, started_at, completed_at
        FROM pipe_executions
        WHERE pipe_instance_id = $1
          AND deployment_hash = $2
          AND trigger_type = 'replay'
          AND replay_of IS NOT NULL
          AND status = 'running'
        ORDER BY started_at DESC
        LIMIT 1
        "#,
    )
    .bind(instance_id)
    .bind(deployment_hash)
    .fetch_optional(pool)
    .instrument(query_span)
    .await
    .map_err(|err| {
        tracing::error!("Failed to find pending replay execution: {:?}", err);
        format!("Failed to find pending replay execution: {}", err)
    })
}

/// List pipe executions for a specific instance (paginated, newest first)
#[tracing::instrument(name = "List pipe executions for instance", skip(pool))]
pub async fn list_executions(
    pool: &PgPool,
    instance_id: &Uuid,
    limit: i64,
    offset: i64,
) -> Result<Vec<PipeExecution>, String> {
    let query_span = tracing::info_span!("Listing pipe executions for instance");
    sqlx::query_as::<_, PipeExecution>(
        r#"
        SELECT id, pipe_instance_id, deployment_hash, trigger_type, status,
               source_data, mapped_data, target_response, error, duration_ms,
               replay_of, is_local, created_by, started_at, completed_at
        FROM pipe_executions
        WHERE pipe_instance_id = $1
        ORDER BY started_at DESC
        LIMIT $2 OFFSET $3
        "#,
    )
    .bind(instance_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .instrument(query_span)
    .await
    .map_err(|err| {
        tracing::error!("Failed to list pipe executions: {:?}", err);
        format!("Failed to list pipe executions: {}", err)
    })
}

/// Update a pipe execution with its result
#[tracing::instrument(name = "Update pipe execution result", skip(pool))]
pub async fn update_execution_result(
    pool: &PgPool,
    id: &Uuid,
    status: &str,
    source_data: Option<&serde_json::Value>,
    mapped_data: Option<&serde_json::Value>,
    target_response: Option<&serde_json::Value>,
    error: Option<&str>,
    duration_ms: Option<i64>,
) -> Result<PipeExecution, String> {
    let query_span = tracing::info_span!("Updating pipe execution result");
    sqlx::query_as::<_, PipeExecution>(
        r#"
        UPDATE pipe_executions
        SET status = $2,
            source_data = COALESCE($3, source_data),
            mapped_data = COALESCE($4, mapped_data),
            target_response = COALESCE($5, target_response),
            error = COALESCE($6, error),
            duration_ms = COALESCE($7, duration_ms),
            completed_at = NOW()
        WHERE id = $1
        RETURNING id, pipe_instance_id, deployment_hash, trigger_type, status,
                  source_data, mapped_data, target_response, error, duration_ms,
                  replay_of, is_local, created_by, started_at, completed_at
        "#,
    )
    .bind(id)
    .bind(status)
    .bind(source_data)
    .bind(mapped_data)
    .bind(target_response)
    .bind(error)
    .bind(duration_ms)
    .fetch_one(pool)
    .instrument(query_span)
    .await
    .map_err(|err| {
        tracing::error!("Failed to update pipe execution result: {:?}", err);
        format!("Failed to update pipe execution result: {}", err)
    })
}
