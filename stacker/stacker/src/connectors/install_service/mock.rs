use super::InstallServiceConnector;
use crate::forms::cloud_firewall;
use crate::forms::project::{RegistryForm, Stack};
use crate::forms::{CloudFirewallOperationMessage, ConfigureCloudFirewallResponse};
use crate::helpers::MqManager;
use crate::models;
use async_trait::async_trait;

pub struct MockInstallServiceConnector;

#[async_trait]
impl InstallServiceConnector for MockInstallServiceConnector {
    async fn deploy(
        &self,
        _user_id: String,
        _user_email: String,
        project_id: i32,
        _deployment_id: i32,
        _deployment_hash: String,
        _project: &models::Project,
        _cloud_creds: models::Cloud,
        _server: models::Server,
        _form_stack: &Stack,
        _registry: Option<RegistryForm>,
        _fc: String,
        _mq_manager: &MqManager,
        _server_public_key: Option<String>,
        _server_private_key: Option<String>,
    ) -> Result<i32, String> {
        Ok(project_id)
    }

    async fn configure_cloud_firewall(
        &self,
        message: CloudFirewallOperationMessage,
        _mq_manager: &MqManager,
    ) -> Result<ConfigureCloudFirewallResponse, String> {
        let routing_key = cloud_firewall::routing_key(&message.target.provider)
            .ok_or_else(|| format!("Unsupported cloud provider: {}", message.target.provider))?;

        Ok(ConfigureCloudFirewallResponse {
            operation_id: message.operation_id,
            accepted: true,
            protocol_version: message.protocol_version,
            provider: cloud_firewall::normalize_provider(&message.target.provider)
                .unwrap_or(message.target.provider.as_str())
                .to_string(),
            server_id: message.target.server_id,
            action: message.action,
            rules: message.rules,
            routing_key,
            message: "Cloud firewall operation accepted".to_string(),
            firewall_name: None,
            firewall: None,
        })
    }
}
