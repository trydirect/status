use std::collections::BTreeMap;
use std::sync::Arc;

use actix_web::{post, web, Responder, Result};
use sqlx::PgPool;

use crate::connectors::install_service::InstallServiceConnector;
use crate::db;
use crate::forms::cloud_firewall::{
    default_firewall_name, idempotency_key, normalize_provider, routing_key, rules_from_request,
    validate_request, CloudFirewallAction, CloudFirewallCredentials, CloudFirewallDetails,
    CloudFirewallOperationMessage, CloudFirewallProviderRule, CloudFirewallRequestedBy,
    CloudFirewallTarget, ConfigureCloudFirewallRequest, ConfigureCloudFirewallResponse,
    CLOUD_FIREWALL_PROTOCOL_VERSION,
};
use crate::helpers::{JsonResponse, MqManager};
use crate::models;

#[tracing::instrument(name = "Configure cloud firewall for server.", skip_all)]
#[post("/{id}/cloud-firewall")]
pub async fn configure(
    path: web::Path<(i32,)>,
    user: web::ReqData<Arc<models::User>>,
    form: web::Json<ConfigureCloudFirewallRequest>,
    pg_pool: web::Data<PgPool>,
    mq_manager: web::Data<MqManager>,
    install_service: web::Data<Arc<dyn InstallServiceConnector>>,
) -> Result<impl Responder> {
    let server_id = path.0;
    let action = validate_request(&form)
        .map_err(|err| JsonResponse::<ConfigureCloudFirewallResponse>::build().bad_request(err))?;

    let server = db::server::fetch(pg_pool.get_ref(), server_id)
        .await
        .map_err(|err| {
            JsonResponse::<ConfigureCloudFirewallResponse>::build().internal_server_error(err)
        })
        .and_then(|server| match server {
            Some(server) if server.user_id == user.id => Ok(server),
            _ => Err(JsonResponse::<ConfigureCloudFirewallResponse>::build()
                .not_found("Server not found")),
        })?;

    let cloud_id = server.cloud_id.ok_or_else(|| {
        JsonResponse::<ConfigureCloudFirewallResponse>::build()
            .bad_request("Cloud firewall operations require a cloud-managed server")
    })?;
    let cloud = db::cloud::fetch(pg_pool.get_ref(), cloud_id)
        .await
        .map_err(|err| {
            JsonResponse::<ConfigureCloudFirewallResponse>::build().internal_server_error(err)
        })
        .and_then(|cloud| match cloud {
            Some(cloud) if cloud.user_id == user.id => Ok(cloud),
            _ => Err(JsonResponse::<ConfigureCloudFirewallResponse>::build()
                .not_found("Cloud credentials not found")),
        })?;

    let provider = normalize_provider(&cloud.provider).ok_or_else(|| {
        JsonResponse::<ConfigureCloudFirewallResponse>::build()
            .bad_request(format!("Unsupported cloud provider: {}", cloud.provider))
    })?;
    let credentials = prepare_cloud_firewall_credentials(provider, cloud)
        .map_err(|err| JsonResponse::<ConfigureCloudFirewallResponse>::build().bad_request(err))?;

    let server_public_ip = server
        .srv_ip
        .clone()
        .filter(|ip| !ip.trim().is_empty())
        .ok_or_else(|| {
            JsonResponse::<ConfigureCloudFirewallResponse>::build()
                .bad_request("Cloud firewall operations require a server public IP")
        })?;

    let managed_scope = format!("server:{}", server.id);
    let mut rules = rules_from_request(&form, managed_scope)
        .map_err(|err| JsonResponse::<ConfigureCloudFirewallResponse>::build().bad_request(err))?;
    for rule in &mut rules {
        rule.labels
            .insert("stacker.server_id".to_string(), server.id.to_string());
    }

    let mut target = CloudFirewallTarget {
        provider: provider.to_string(),
        cloud_id,
        server_id: server.id,
        project_id: server.project_id,
        deployment_hash: None,
        server_public_ip,
        provider_server_id: None,
        server_name: server.name.clone().or_else(|| server.server.clone()),
        region: server.region.clone(),
        zone: server.zone.clone(),
        firewall_id: None,
        firewall_name: None,
    };
    let default_firewall_name = default_firewall_name(&target);
    let resolved_firewall = list_cloud_firewall(&credentials, &default_firewall_name, &target)
        .await
        .map_err(|err| JsonResponse::<ConfigureCloudFirewallResponse>::build().bad_request(err))?;
    apply_resolved_firewall_to_target(&mut target, &resolved_firewall);

    let mut provider_context = BTreeMap::new();
    provider_context.insert(
        provider.to_string(),
        serde_json::json!({ "firewall_name": resolved_firewall.name.clone() }),
    );
    let firewall_name = resolved_firewall.name.clone();

    let operation_id = format!("cfw_{}", uuid::Uuid::new_v4());
    for rule in &mut rules {
        rule.labels
            .insert("stacker.operation_id".to_string(), operation_id.clone());
    }

    let message = CloudFirewallOperationMessage {
        protocol_version: CLOUD_FIREWALL_PROTOCOL_VERSION.to_string(),
        operation_id: operation_id.clone(),
        idempotency_key: idempotency_key(server.id, &action, &rules),
        action,
        dry_run: form.dry_run,
        target,
        rules,
        credentials,
        provider_context,
        requested_by: CloudFirewallRequestedBy {
            user_id: user.id.clone(),
            user_email: Some(user.email.clone()),
        },
    };

    if message.action == CloudFirewallAction::List {
        let routing_key = routing_key(&message.target.provider).unwrap_or_default();

        return Ok(JsonResponse::build()
            .set_item(ConfigureCloudFirewallResponse {
                operation_id,
                accepted: true,
                protocol_version: CLOUD_FIREWALL_PROTOCOL_VERSION.to_string(),
                provider: provider.to_string(),
                server_id: server.id,
                action: CloudFirewallAction::List,
                rules: Vec::new(),
                routing_key,
                message: "Cloud firewall list retrieved".to_string(),
                firewall_name: Some(firewall_name),
                firewall: Some(resolved_firewall),
            })
            .ok("Cloud firewall list retrieved"));
    }

    let response = install_service
        .configure_cloud_firewall(message, mq_manager.get_ref())
        .await
        .map_err(|err| {
            JsonResponse::<ConfigureCloudFirewallResponse>::build().internal_server_error(err)
        })?;

    let routing_key = routing_key(&response.provider).unwrap_or(response.routing_key.clone());
    Ok(JsonResponse::build()
        .set_item(ConfigureCloudFirewallResponse {
            routing_key,
            firewall_name: Some(firewall_name),
            ..response
        })
        .ok("Cloud firewall operation accepted"))
}

#[derive(Debug, serde::Deserialize)]
struct HetznerFirewallsResponse {
    #[serde(default)]
    firewalls: Vec<HetznerFirewall>,
}

#[derive(Debug, serde::Deserialize)]
struct HetznerFirewall {
    id: i64,
    name: String,
    #[serde(default)]
    rules: Vec<CloudFirewallProviderRule>,
    #[serde(default)]
    applied_to: Vec<HetznerFirewallAppliedTo>,
}

#[derive(Debug, serde::Deserialize)]
struct HetznerFirewallAppliedTo {
    #[serde(default)]
    server: Option<HetznerAppliedServer>,
}

#[derive(Debug, serde::Deserialize)]
struct HetznerAppliedServer {
    id: i64,
}

#[derive(Debug, serde::Deserialize)]
struct HetznerServersResponse {
    #[serde(default)]
    servers: Vec<HetznerServer>,
}

#[derive(Debug, serde::Deserialize)]
struct HetznerServer {
    id: i64,
    name: String,
    #[serde(default)]
    public_net: Option<HetznerServerPublicNet>,
}

#[derive(Debug, serde::Deserialize)]
struct HetznerServerPublicNet {
    #[serde(default)]
    ipv4: Option<HetznerServerIpv4>,
    #[serde(default)]
    firewalls: Vec<HetznerServerFirewall>,
}

#[derive(Debug, serde::Deserialize)]
struct HetznerServerIpv4 {
    ip: String,
}

#[derive(Debug, serde::Deserialize)]
struct HetznerServerFirewall {
    id: i64,
}

async fn list_cloud_firewall(
    credentials: &CloudFirewallCredentials,
    firewall_name: &str,
    target: &CloudFirewallTarget,
) -> Result<CloudFirewallDetails, String> {
    let token = credentials
        .token
        .as_deref()
        .ok_or_else(|| "Hetzner cloud firewall list requires a valid cloud token".to_string())?;
    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|err| format!("Failed to initialize Hetzner API client: {}", err))?;
    let response = client
        .get("https://api.hetzner.cloud/v1/firewalls")
        .bearer_auth(token)
        .query(&[("name", firewall_name)])
        .send()
        .await
        .map_err(|err| format!("Failed to query Hetzner firewalls: {}", err))?;

    let status = response.status();
    if !status.is_success() {
        return Err(match status.as_u16() {
            401 | 403 => {
                "Hetzner rejected the saved cloud token. Please delete and re-add your Hetzner cloud credentials.".to_string()
            }
            _ => format!("Hetzner firewall list failed with status {}", status.as_u16()),
        });
    }

    let body: HetznerFirewallsResponse = response
        .json()
        .await
        .map_err(|err| format!("Invalid Hetzner firewall response: {}", err))?;
    let firewall = match select_single_hetzner_firewall(body.firewalls, firewall_name) {
        Ok(firewall) => firewall,
        Err(err) if err.starts_with("Hetzner firewall not found:") => {
            list_hetzner_firewall_attached_to_server(&client, token, target)
                .await?
                .ok_or_else(|| {
                    format!(
                        "{}. No firewall attached to server {} was found either",
                        err, target.server_public_ip
                    )
                })?
        }
        Err(err) => return Err(err),
    };

    Ok(CloudFirewallDetails {
        id: Some(firewall.id),
        name: firewall.name,
        rules: firewall.rules,
    })
}

async fn list_hetzner_firewall_attached_to_server(
    client: &reqwest::Client,
    token: &str,
    target: &CloudFirewallTarget,
) -> Result<Option<HetznerFirewall>, String> {
    let response = client
        .get("https://api.hetzner.cloud/v1/servers")
        .bearer_auth(token)
        .send()
        .await
        .map_err(|err| format!("Failed to query Hetzner servers: {}", err))?;

    let status = response.status();
    if !status.is_success() {
        return Err(format!(
            "Hetzner server lookup failed with status {} while resolving firewall for {}",
            status.as_u16(),
            target.server_public_ip
        ));
    }

    let body: HetznerServersResponse = response
        .json()
        .await
        .map_err(|err| format!("Invalid Hetzner server response: {}", err))?;
    let server = select_hetzner_server_for_target(body.servers, target);
    let Some(server) = server else {
        return Ok(None);
    };

    if let Some(firewall_id) = server
        .public_net
        .as_ref()
        .and_then(|public_net| public_net.firewalls.first())
        .map(|firewall| firewall.id)
    {
        let response = client
            .get(format!(
                "https://api.hetzner.cloud/v1/firewalls/{}",
                firewall_id
            ))
            .bearer_auth(token)
            .send()
            .await
            .map_err(|err| format!("Failed to query Hetzner firewall {}: {}", firewall_id, err))?;
        let status = response.status();
        if !status.is_success() {
            return Err(format!(
                "Hetzner firewall {} lookup failed with status {}",
                firewall_id,
                status.as_u16()
            ));
        }
        return response
            .json::<serde_json::Value>()
            .await
            .map_err(|err| format!("Invalid Hetzner firewall response: {}", err))?
            .get("firewall")
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|err| format!("Invalid Hetzner firewall response: {}", err));
    }

    let response = client
        .get("https://api.hetzner.cloud/v1/firewalls")
        .bearer_auth(token)
        .send()
        .await
        .map_err(|err| format!("Failed to query Hetzner firewalls: {}", err))?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!(
            "Hetzner firewall lookup failed with status {} while resolving attached firewall",
            status.as_u16()
        ));
    }
    let body: HetznerFirewallsResponse = response
        .json()
        .await
        .map_err(|err| format!("Invalid Hetzner firewall response: {}", err))?;

    Ok(body
        .firewalls
        .into_iter()
        .find(|firewall| firewall_applies_to_server(firewall, server.id)))
}

fn select_single_hetzner_firewall(
    firewalls: Vec<HetznerFirewall>,
    firewall_name: &str,
) -> Result<HetznerFirewall, String> {
    let mut firewalls = firewalls.into_iter();
    match (firewalls.next(), firewalls.next()) {
        (None, _) => Err(format!("Hetzner firewall not found: {}", firewall_name)),
        (Some(firewall), None) => Ok(firewall),
        (Some(_), Some(_)) => Err(format!(
            "Multiple Hetzner firewalls found with name '{}'; expected exactly one",
            firewall_name
        )),
    }
}

fn select_hetzner_server_for_target(
    servers: Vec<HetznerServer>,
    target: &CloudFirewallTarget,
) -> Option<HetznerServer> {
    let target_ip = target.server_public_ip.trim();
    let target_name = target.server_name.as_deref().unwrap_or("").trim();

    servers.into_iter().find(|server| {
        let server_ip = server
            .public_net
            .as_ref()
            .and_then(|public_net| public_net.ipv4.as_ref())
            .map(|ipv4| ipv4.ip.as_str());
        (!target_ip.is_empty() && server_ip == Some(target_ip))
            || (!target_name.is_empty() && server.name == target_name)
    })
}

fn firewall_applies_to_server(firewall: &HetznerFirewall, server_id: i64) -> bool {
    firewall
        .applied_to
        .iter()
        .filter_map(|target| target.server.as_ref())
        .any(|server| server.id == server_id)
}

fn apply_resolved_firewall_to_target(
    target: &mut CloudFirewallTarget,
    firewall: &CloudFirewallDetails,
) {
    target.firewall_id = firewall.id.map(|id| id.to_string());
    target.firewall_name = Some(firewall.name.clone());
}

fn prepare_cloud_firewall_credentials(
    provider: &str,
    cloud: models::Cloud,
) -> Result<CloudFirewallCredentials, String> {
    let cloud = if cloud.save_token == Some(true) {
        crate::forms::CloudForm::decode_model(cloud, true)
    } else {
        cloud
    };
    let token = non_empty_secret(cloud.cloud_token);
    let key = non_empty_secret(cloud.cloud_key);
    let secret = non_empty_secret(cloud.cloud_secret);

    if provider == "htz" && token.is_none() {
        return Err(
            "Hetzner cloud firewall operations require a valid cloud token. Please delete and re-add your Hetzner cloud credentials."
                .to_string(),
        );
    }

    Ok(CloudFirewallCredentials {
        provider: provider.to_string(),
        token,
        key,
        secret,
    })
}

fn non_empty_secret(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forms::CloudForm;
    use std::sync::Mutex;

    static ENV_MUTEX: Mutex<()> = Mutex::new(());
    const TEST_SECURITY_KEY: &str = "01234567890123456789012345678901";

    fn encrypted_cloud(token: &str) -> models::Cloud {
        let form = CloudForm {
            user_id: Some("user-1".to_string()),
            project_id: None,
            name: Some("prod-hetzner".to_string()),
            provider: "htz".to_string(),
            cloud_token: Some(token.to_string()),
            cloud_key: None,
            cloud_secret: None,
            save_token: Some(true),
        };

        (&form).into()
    }

    fn plaintext_cloud(token: &str) -> models::Cloud {
        models::Cloud::new(
            "user-1".to_string(),
            "prod-hetzner".to_string(),
            "htz".to_string(),
            Some(token.to_string()),
            None,
            None,
            Some(false),
        )
    }

    #[test]
    fn prepare_cloud_firewall_credentials_decodes_saved_token() {
        let _lock = ENV_MUTEX.lock().unwrap();
        std::env::set_var("SECURITY_KEY", TEST_SECURITY_KEY);
        let cloud = encrypted_cloud("live-hcloud-token");
        let encrypted_token = cloud.cloud_token.clone();

        let credentials = prepare_cloud_firewall_credentials("htz", cloud).unwrap();

        assert_eq!(credentials.token.as_deref(), Some("live-hcloud-token"));
        assert_ne!(credentials.token, encrypted_token);
        std::env::remove_var("SECURITY_KEY");
    }

    #[test]
    fn prepare_cloud_firewall_credentials_accepts_plaintext_token() {
        let cloud = plaintext_cloud("plain-hcloud-token");

        let credentials = prepare_cloud_firewall_credentials("htz", cloud).unwrap();

        assert_eq!(credentials.token.as_deref(), Some("plain-hcloud-token"));
    }

    #[test]
    fn select_single_hetzner_firewall_rejects_ambiguous_matches() {
        let firewalls = vec![
            HetznerFirewall {
                id: 1,
                name: "frw-test".to_string(),
                rules: Vec::new(),
                applied_to: Vec::new(),
            },
            HetznerFirewall {
                id: 2,
                name: "frw-test".to_string(),
                rules: Vec::new(),
                applied_to: Vec::new(),
            },
        ];

        let error = select_single_hetzner_firewall(firewalls, "frw-test").unwrap_err();

        assert!(error.contains("Multiple Hetzner firewalls"));
    }

    #[test]
    fn apply_resolved_firewall_sets_target_identity() {
        let mut target = CloudFirewallTarget {
            provider: "htz".to_string(),
            cloud_id: 1,
            server_id: 10,
            project_id: 20,
            deployment_hash: None,
            server_public_ip: "203.0.113.10".to_string(),
            provider_server_id: None,
            server_name: Some("stale-name".to_string()),
            region: None,
            zone: None,
            firewall_id: None,
            firewall_name: None,
        };
        let firewall = CloudFirewallDetails {
            id: Some(10957668),
            name: "frw-coolify-zxiuehu1".to_string(),
            rules: Vec::new(),
        };

        apply_resolved_firewall_to_target(&mut target, &firewall);

        assert_eq!(target.firewall_id.as_deref(), Some("10957668"));
        assert_eq!(
            target.firewall_name.as_deref(),
            Some("frw-coolify-zxiuehu1")
        );
    }

    #[test]
    fn select_hetzner_server_for_target_prefers_public_ip() {
        let target = CloudFirewallTarget {
            provider: "htz".to_string(),
            cloud_id: 1,
            server_id: 10,
            project_id: 20,
            deployment_hash: None,
            server_public_ip: "203.0.113.10".to_string(),
            provider_server_id: None,
            server_name: Some("stale-name".to_string()),
            region: None,
            zone: None,
            firewall_id: None,
            firewall_name: None,
        };
        let servers = vec![HetznerServer {
            id: 123,
            name: "current-name".to_string(),
            public_net: Some(HetznerServerPublicNet {
                ipv4: Some(HetznerServerIpv4 {
                    ip: "203.0.113.10".to_string(),
                }),
                firewalls: vec![HetznerServerFirewall { id: 456 }],
            }),
        }];

        let server = select_hetzner_server_for_target(servers, &target).unwrap();

        assert_eq!(server.id, 123);
    }

    #[test]
    fn firewall_applies_to_server_matches_applied_server_id() {
        let firewall = HetznerFirewall {
            id: 456,
            name: "frw-current".to_string(),
            rules: Vec::new(),
            applied_to: vec![HetznerFirewallAppliedTo {
                server: Some(HetznerAppliedServer { id: 123 }),
            }],
        };

        assert!(firewall_applies_to_server(&firewall, 123));
        assert!(!firewall_applies_to_server(&firewall, 124));
    }
}
