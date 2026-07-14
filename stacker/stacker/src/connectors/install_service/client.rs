use super::InstallServiceConnector;
use crate::forms::cloud_firewall;
use crate::forms::project::{RegistryForm, Stack};
use crate::forms::{CloudFirewallOperationMessage, ConfigureCloudFirewallResponse};
use crate::helpers::{compressor::compress, MqManager};
use crate::models;
use async_trait::async_trait;

/// Real implementation that publishes deployment requests through RabbitMQ
pub struct InstallServiceClient;

fn normalize_server_region_for_installer(provider: &str, server: &mut crate::forms::ServerForm) {
    if !matches!(provider, "htz" | "hetzner") {
        return;
    }

    let Some(region) = server.region.as_deref() else {
        return;
    };

    let location = match region {
        "nbg1-dc3" => "nbg1",
        "fsn1-dc14" => "fsn1",
        "hel1-dc2" => "hel1",
        "ash-dc1" => "ash",
        "hil-dc1" => "hil",
        _ => return,
    };

    server.region = Some(location.to_string());
}

#[cfg(test)]
mod tests {
    use super::normalize_server_region_for_installer;
    use crate::forms::ServerForm;

    #[test]
    fn preserves_hetzner_location_for_installer() {
        let mut server = ServerForm {
            region: Some("nbg1".to_string()),
            server: Some("cpx21".to_string()),
            os: Some("docker-ce".to_string()),
            ..Default::default()
        };

        normalize_server_region_for_installer("htz", &mut server);

        assert_eq!(server.region.as_deref(), Some("nbg1"));
        assert_eq!(server.server.as_deref(), Some("cpx21"));
        assert_eq!(server.os.as_deref(), Some("docker-ce"));
    }

    #[test]
    fn normalizes_hetzner_datacenter_to_location_for_installer() {
        let mut server = ServerForm {
            region: Some("fsn1-dc14".to_string()),
            ..Default::default()
        };

        normalize_server_region_for_installer("htz", &mut server);

        assert_eq!(server.region.as_deref(), Some("fsn1"));
    }

    #[test]
    fn leaves_non_hetzner_regions_unchanged() {
        let mut server = ServerForm {
            region: Some("fra1".to_string()),
            ..Default::default()
        };

        normalize_server_region_for_installer("do", &mut server);

        assert_eq!(server.region.as_deref(), Some("fra1"));
    }
}

#[async_trait]
impl InstallServiceConnector for InstallServiceClient {
    async fn deploy(
        &self,
        user_id: String,
        user_email: String,
        project_id: i32,
        deployment_id: i32,
        deployment_hash: String,
        project: &models::Project,
        cloud_creds: models::Cloud,
        server: models::Server,
        form_stack: &Stack,
        registry: Option<RegistryForm>,
        fc: String,
        mq_manager: &MqManager,
        server_public_key: Option<String>,
        server_private_key: Option<String>,
    ) -> Result<i32, String> {
        // Build payload for the install service
        let mut payload = crate::forms::project::Payload::try_from(project)
            .map_err(|err| format!("Failed to build payload: {}", err))?;

        payload.id = Some(deployment_id);
        // Force-set deployment_hash in case deserialization overwrote it
        payload.deployment_hash = Some(deployment_hash.clone());

        // Determine routing before server is moved into payload:
        // If server has an existing IP, deploy to it directly (own flow).
        // Otherwise, use the cloud provider to decide (own vs tfa).
        let has_existing_ip = server.srv_ip.as_ref().map_or(false, |ip| !ip.is_empty());

        payload.server = Some(server.into());
        // Inject newly-generated public key so Install Service can append it to authorized_keys
        if let Some(ref mut srv) = payload.server {
            normalize_server_region_for_installer(&cloud_creds.provider, srv);
            if srv.public_key.is_none() {
                srv.public_key = server_public_key;
            }
            // Include the SSH private key so the Install Service can SSH into
            // existing servers without relying on Redis-cached file paths.
            if srv.ssh_private_key.is_none() {
                srv.ssh_private_key = server_private_key;
            }
        }
        payload.cloud = Some(cloud_creds.into());
        payload.stack = form_stack.clone().into();
        payload.user_token = Some(user_id);
        payload.user_email = Some(user_email);
        payload.docker_compose = Some(compress(fc.as_str()));
        payload.registry = registry;

        tracing::debug!(
            "Send project data (deployment_hash = {:?}): {:?}",
            payload.deployment_hash,
            payload
        );

        let provider = if has_existing_ip {
            // Server already has an IP → deploy to existing server via SSH (own flow)
            tracing::info!("Server has existing IP, routing to 'own' flow");
            "own"
        } else {
            // No IP → provision new server via cloud provider (tfa or own)
            payload
                .cloud
                .as_ref()
                .map(|form| {
                    if form.provider.contains("own") {
                        "own"
                    } else {
                        "tfa"
                    }
                })
                .unwrap_or("tfa")
        }
        .to_string();

        let routing_key = format!("install.start.{}.all.all", provider);
        tracing::debug!("Route: {:?}", routing_key);

        mq_manager
            .publish("install".to_string(), routing_key, &payload)
            .await
            .map_err(|err| format!("Failed to publish to MQ: {}", err))?;

        Ok(project_id)
    }

    async fn configure_cloud_firewall(
        &self,
        message: CloudFirewallOperationMessage,
        mq_manager: &MqManager,
    ) -> Result<ConfigureCloudFirewallResponse, String> {
        let routing_key = cloud_firewall::routing_key(&message.target.provider)
            .ok_or_else(|| format!("Unsupported cloud provider: {}", message.target.provider))?;

        mq_manager
            .publish("install".to_string(), routing_key.clone(), &message)
            .await
            .map_err(|err| format!("Failed to publish cloud firewall operation to MQ: {}", err))?;

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
