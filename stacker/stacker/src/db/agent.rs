use crate::models;
use sqlx::PgPool;
use tracing::Instrument;
use uuid::Uuid;

pub async fn insert(pool: &PgPool, agent: models::Agent) -> Result<models::Agent, String> {
    let query_span = tracing::info_span!("Inserting agent into database");
    sqlx::query_as::<_, models::Agent>(
        r#"
        INSERT INTO agents (id, deployment_hash, capabilities, version, system_info, 
                           last_heartbeat, status, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING id, deployment_hash, capabilities, version, system_info, 
                  last_heartbeat, status, created_at, updated_at
        "#,
    )
    .bind(agent.id)
    .bind(agent.deployment_hash)
    .bind(agent.capabilities)
    .bind(agent.version)
    .bind(agent.system_info)
    .bind(agent.last_heartbeat)
    .bind(agent.status)
    .bind(agent.created_at)
    .bind(agent.updated_at)
    .fetch_one(pool)
    .instrument(query_span)
    .await
    .map_err(|err| {
        tracing::error!("Failed to insert agent: {:?}", err);
        "Failed to create agent".to_string()
    })
}

pub async fn fetch_by_id(pool: &PgPool, agent_id: Uuid) -> Result<Option<models::Agent>, String> {
    let query_span = tracing::info_span!("Fetching agent by ID");
    sqlx::query_as::<_, models::Agent>(
        r#"
        SELECT id, deployment_hash, capabilities, version, system_info, 
               last_heartbeat, status, created_at, updated_at
        FROM agents 
        WHERE id = $1
        "#,
    )
    .bind(agent_id)
    .fetch_optional(pool)
    .instrument(query_span)
    .await
    .map_err(|err| {
        tracing::error!("Failed to fetch agent: {:?}", err);
        "Database error".to_string()
    })
}

pub async fn fetch_by_deployment_hash(
    pool: &PgPool,
    deployment_hash: &str,
) -> Result<Option<models::Agent>, String> {
    let query_span = tracing::info_span!("Fetching agent by deployment_hash");
    sqlx::query_as::<_, models::Agent>(
        r#"
        SELECT id, deployment_hash, capabilities, version, system_info, 
               last_heartbeat, status, created_at, updated_at
        FROM agents 
        WHERE deployment_hash = $1
        "#,
    )
    .bind(deployment_hash)
    .fetch_optional(pool)
    .instrument(query_span)
    .await
    .map_err(|err| {
        tracing::error!("Failed to fetch agent by deployment_hash: {:?}", err);
        "Database error".to_string()
    })
}

/// Fetch the most recently heartbeated agent for a project (heartbeat within last 5 minutes).
pub async fn fetch_active_by_project(
    pool: &PgPool,
    project_id: i32,
) -> Result<Option<models::Agent>, String> {
    let query_span = tracing::info_span!("Fetching active agent by project");
    sqlx::query_as::<_, models::Agent>(
        r#"
        SELECT a.id, a.deployment_hash, a.capabilities, a.version, a.system_info,
               a.last_heartbeat, a.status, a.created_at, a.updated_at
        FROM agents a
        JOIN deployment d ON a.deployment_hash = d.deployment_hash
        WHERE d.project_id = $1
          AND a.last_heartbeat > NOW() - INTERVAL '5 minutes'
        ORDER BY a.last_heartbeat DESC
        LIMIT 1
        "#,
    )
    .bind(project_id)
    .fetch_optional(pool)
    .instrument(query_span)
    .await
    .map_err(|err| {
        tracing::error!("Failed to fetch active agent by project: {:?}", err);
        "Database error".to_string()
    })
}

pub async fn update_heartbeat(pool: &PgPool, agent_id: Uuid, status: &str) -> Result<(), String> {
    let query_span = tracing::info_span!("Updating agent heartbeat");
    sqlx::query!(
        r#"
        UPDATE agents 
        SET last_heartbeat = NOW(), status = $2, updated_at = NOW()
        WHERE id = $1
        "#,
        agent_id,
        status,
    )
    .execute(pool)
    .instrument(query_span)
    .await
    .map(|_| ())
    .map_err(|err| {
        tracing::error!("Failed to update agent heartbeat: {:?}", err);
        "Failed to update heartbeat".to_string()
    })
}

pub async fn update(pool: &PgPool, agent: models::Agent) -> Result<models::Agent, String> {
    let query_span = tracing::info_span!("Updating agent in database");
    sqlx::query_as::<_, models::Agent>(
        r#"
        UPDATE agents 
        SET capabilities = $2, version = $3, system_info = $4, 
            last_heartbeat = $5, status = $6, updated_at = NOW()
        WHERE id = $1
        RETURNING id, deployment_hash, capabilities, version, system_info, 
                  last_heartbeat, status, created_at, updated_at
        "#,
    )
    .bind(agent.id)
    .bind(agent.capabilities)
    .bind(agent.version)
    .bind(agent.system_info)
    .bind(agent.last_heartbeat)
    .bind(agent.status)
    .fetch_one(pool)
    .instrument(query_span)
    .await
    .map_err(|err| {
        tracing::error!("Failed to update agent: {:?}", err);
        "Failed to update agent".to_string()
    })
}

pub async fn delete(pool: &PgPool, agent_id: Uuid) -> Result<(), String> {
    let query_span = tracing::info_span!("Deleting agent from database");
    sqlx::query!(
        r#"
        DELETE FROM agents WHERE id = $1
        "#,
        agent_id,
    )
    .execute(pool)
    .instrument(query_span)
    .await
    .map(|_| ())
    .map_err(|err| {
        tracing::error!("Failed to delete agent: {:?}", err);
        "Failed to delete agent".to_string()
    })
}

pub async fn log_audit(
    pool: &PgPool,
    audit_log: models::AuditLog,
) -> Result<models::AuditLog, String> {
    let query_span = tracing::info_span!("Inserting audit log");
    sqlx::query_as::<_, models::AuditLog>(
        r#"
        INSERT INTO audit_log (id, agent_id, deployment_hash, action, status, details, 
                              ip_address, user_agent, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7::INET, $8, $9)
        RETURNING id, agent_id, deployment_hash, action, status, details, 
                  ip_address, user_agent, created_at
        "#,
    )
    .bind(audit_log.id)
    .bind(audit_log.agent_id)
    .bind(audit_log.deployment_hash)
    .bind(audit_log.action)
    .bind(audit_log.status)
    .bind(audit_log.details)
    .bind(audit_log.ip_address)
    .bind(audit_log.user_agent)
    .bind(audit_log.created_at)
    .fetch_one(pool)
    .instrument(query_span)
    .await
    .map_err(|err| {
        tracing::error!("Failed to insert audit log: {:?}", err);
        "Failed to log audit event".to_string()
    })
}
