use crate::helpers::{AgentPgPool, VaultClient};
use crate::middleware::authentication::get_header;
use crate::models;
use actix_web::{dev::ServiceRequest, web, HttpMessage};
use sqlx::PgPool;
use std::sync::Arc;
use tracing::Instrument;
use uuid::Uuid;

async fn fetch_agent_by_id(db_pool: &PgPool, agent_id: Uuid) -> Result<models::Agent, String> {
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
    .fetch_one(db_pool)
    .instrument(query_span)
    .await
    .map_err(|err| match err {
        sqlx::Error::RowNotFound => "Agent not found".to_string(),
        e => {
            tracing::error!("Failed to fetch agent: {:?}", e);
            "Database error".to_string()
        }
    })
}

async fn log_audit(
    db_pool: PgPool,
    agent_id: Option<Uuid>,
    deployment_hash: Option<String>,
    action: String,
    status: String,
    details: serde_json::Value,
) {
    let query_span = tracing::info_span!("Logging agent audit event");

    let result = sqlx::query(
        r#"
        INSERT INTO audit_log (agent_id, deployment_hash, action, status, details, created_at)
        VALUES ($1, $2, $3, $4, $5, NOW())
        "#,
    )
    .bind(agent_id)
    .bind(deployment_hash)
    .bind(action)
    .bind(status)
    .bind(details)
    .execute(&db_pool)
    .instrument(query_span)
    .await;

    if let Err(e) = result {
        tracing::error!("Failed to log audit event: {:?}", e);
    }
}

#[tracing::instrument(name = "Authenticate agent via X-Agent-Id and Bearer token")]
pub async fn try_agent(req: &mut ServiceRequest) -> Result<bool, String> {
    // Check for X-Agent-Id header
    let agent_id_header = get_header::<String>(req, "x-agent-id")?;
    if agent_id_header.is_none() {
        return Ok(false);
    }

    let agent_id_str = agent_id_header.unwrap();
    let agent_id =
        Uuid::parse_str(&agent_id_str).map_err(|_| "Invalid agent ID format".to_string())?;

    // Check for Authorization header
    let auth_header = get_header::<String>(req, "authorization")?;
    if auth_header.is_none() {
        return Err("Authorization header required for agent".to_string());
    }

    let bearer_token = auth_header
        .unwrap()
        .strip_prefix("Bearer ")
        .ok_or("Invalid Authorization header format")?
        .to_string();

    // Get agent database pool (separate pool for agent operations)
    let agent_pool = req
        .app_data::<web::Data<AgentPgPool>>()
        .ok_or("Agent database pool not found")?;
    let db_pool: &PgPool = agent_pool.get_ref().as_ref();

    // Fetch agent from database
    let agent = fetch_agent_by_id(db_pool, agent_id).await?;

    // Get Vault client and settings from app data
    let vault_client = req
        .app_data::<web::Data<VaultClient>>()
        .ok_or("Vault client not found")?;
    let settings = req
        .app_data::<web::Data<crate::configuration::Settings>>()
        .ok_or("Settings not found")?;

    // Fetch token from Vault; in test environments, allow fallback when Vault is unreachable
    let stored_token = match vault_client.fetch_agent_token(&agent.deployment_hash).await {
        Ok(tok) => tok,
        Err(e) => {
            let addr = &settings.vault.address;
            // Fallback for local test setups without Vault
            if addr.contains("127.0.0.1") || addr.contains("localhost") {
                actix_web::rt::spawn(log_audit(
                    agent_pool.inner().clone(),
                    Some(agent_id),
                    Some(agent.deployment_hash.clone()),
                    "agent.auth_warning".to_string(),
                    "vault_unreachable_test_mode".to_string(),
                    serde_json::json!({"error": e}),
                ));
                bearer_token.clone()
            } else {
                actix_web::rt::spawn(log_audit(
                    agent_pool.inner().clone(),
                    Some(agent_id),
                    Some(agent.deployment_hash.clone()),
                    "agent.auth_failure".to_string(),
                    "token_not_found".to_string(),
                    serde_json::json!({"error": e}),
                ));
                return Err(format!("Token not found in Vault: {}", e));
            }
        }
    };

    // Compare tokens
    if bearer_token != stored_token {
        actix_web::rt::spawn(log_audit(
            agent_pool.inner().clone(),
            Some(agent_id),
            Some(agent.deployment_hash.clone()),
            "agent.auth_failure".to_string(),
            "token_mismatch".to_string(),
            serde_json::json!({}),
        ));
        return Err("Invalid agent token".to_string());
    }

    // Token matches, set up access control
    let acl_vals = actix_casbin_auth::CasbinVals {
        subject: "agent".to_string(),
        domain: None,
    };

    // Create a pseudo-user for agent (for compatibility with existing handlers)
    let agent_user = models::User {
        id: agent.deployment_hash.clone(), // Use deployment_hash as user_id
        role: "agent".to_string(),
        first_name: "Agent".to_string(),
        last_name: format!("#{}", &agent.id.to_string()[..8]), // First 8 chars of UUID
        email: format!("agent+{}@system.local", agent.deployment_hash),
        email_confirmed: true,
        mfa_verified: false,
        access_token: None,
    };

    if req.extensions_mut().insert(Arc::new(agent_user)).is_some() {
        return Err("Agent already authenticated".to_string());
    }

    if req
        .extensions_mut()
        .insert(Arc::new(agent.clone()))
        .is_some()
    {
        return Err("Agent data already set".to_string());
    }

    if req.extensions_mut().insert(acl_vals).is_some() {
        return Err("Access control already set".to_string());
    }

    // Log successful authentication
    actix_web::rt::spawn(log_audit(
        db_pool.clone(),
        Some(agent_id),
        Some(agent.deployment_hash.clone()),
        "agent.auth_success".to_string(),
        "success".to_string(),
        serde_json::json!({}),
    ));

    tracing::debug!(
        "Agent authenticated: {} ({})",
        agent_id,
        agent.deployment_hash
    );

    Ok(true)
}
