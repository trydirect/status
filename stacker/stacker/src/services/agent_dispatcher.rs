use crate::{
    db, helpers,
    models::{Command, CommandPriority},
};
use helpers::VaultClient;
use serde_json::Value;
use sqlx::PgPool;

/// AgentDispatcher - queue commands for Status Panel agents
pub struct AgentDispatcher<'a> {
    pg: &'a PgPool,
}

impl<'a> AgentDispatcher<'a> {
    pub fn new(pg: &'a PgPool) -> Self {
        Self { pg }
    }

    /// Queue a command for the agent to execute
    pub async fn queue_command(
        &self,
        deployment_id: i32,
        command_type: &str,
        parameters: Value,
    ) -> Result<String, String> {
        // Get deployment hash
        let deployment = db::deployment::fetch(self.pg, deployment_id)
            .await
            .map_err(|e| format!("Failed to fetch deployment: {}", e))?
            .ok_or_else(|| "Deployment not found".to_string())?;

        let command_id = uuid::Uuid::new_v4().to_string();

        // Create command using the model's constructor and builder pattern
        let command = Command::new(
            command_id.clone(),
            deployment.deployment_hash.clone(),
            command_type.to_string(),
            "mcp_tool".to_string(),
        )
        .with_priority(CommandPriority::Normal)
        .with_parameters(parameters);

        db::command::insert(self.pg, &command)
            .await
            .map_err(|e| format!("Failed to insert command: {}", e))?;

        db::command::add_to_queue(
            self.pg,
            &command_id,
            &deployment.deployment_hash,
            &CommandPriority::Normal,
        )
        .await
        .map_err(|e| format!("Failed to queue command: {}", e))?;

        tracing::info!(
            deployment_id = deployment_id,
            command_id = %command_id,
            command_type = %command_type,
            "Queued command for agent"
        );

        Ok(command_id)
    }
}

/// Rotate token by writing the new value into Vault.
/// Agent is expected to pull the latest token from Vault.
#[tracing::instrument(name = "AgentDispatcher rotate_token", skip(pg, vault, new_token), fields(deployment_hash = %deployment_hash))]
pub async fn rotate_token(
    pg: &PgPool,
    vault: &VaultClient,
    deployment_hash: &str,
    new_token: &str,
) -> Result<(), String> {
    // Ensure agent exists for the deployment
    let _ = db::agent::fetch_by_deployment_hash(pg, deployment_hash)
        .await
        .map_err(|e| format!("DB error: {}", e))?
        .ok_or_else(|| "Agent not found for deployment_hash".to_string())?;

    tracing::info!(deployment_hash = %deployment_hash, "Storing rotated token in Vault");
    vault
        .store_agent_token(deployment_hash, new_token)
        .await
        .map_err(|e| format!("Vault store error: {}", e))?;

    Ok(())
}
