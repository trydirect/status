use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::forms::firewall::{validate_rule, FirewallPortRule, FirewallRuleDirection};

pub const CLOUD_FIREWALL_PROTOCOL_VERSION: &str = "stacker.cloud_firewall.v1";

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CloudFirewallAction {
    Add,
    Remove,
    List,
}

impl CloudFirewallAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Remove => "remove",
            Self::List => "list",
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct ConfigureCloudFirewallRequest {
    #[serde(default)]
    pub action: Option<CloudFirewallAction>,
    #[serde(default)]
    pub public_ports: Vec<FirewallPortRule>,
    #[serde(default)]
    pub private_ports: Vec<FirewallPortRule>,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct ConfigureCloudFirewallResponse {
    pub operation_id: String,
    pub accepted: bool,
    pub protocol_version: String,
    pub provider: String,
    pub server_id: i32,
    pub action: CloudFirewallAction,
    pub rules: Vec<CloudFirewallRule>,
    pub routing_key: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub firewall_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub firewall: Option<CloudFirewallDetails>,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct CloudFirewallDetails {
    pub id: Option<i64>,
    pub name: String,
    #[serde(default)]
    pub rules: Vec<CloudFirewallProviderRule>,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct CloudFirewallProviderRule {
    pub direction: String,
    pub protocol: String,
    pub port: String,
    #[serde(default)]
    pub source_ips: Vec<String>,
    #[serde(default)]
    pub destination_ips: Vec<String>,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct CloudFirewallRule {
    pub direction: FirewallRuleDirection,
    pub port: u16,
    pub protocol: String,
    pub source: String,
    #[serde(default)]
    pub comment: Option<String>,
    pub managed_by: String,
    pub managed_scope: String,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

impl CloudFirewallRule {
    pub fn from_port_rule(
        rule: FirewallPortRule,
        direction: FirewallRuleDirection,
        managed_scope: impl Into<String>,
    ) -> Self {
        Self {
            direction,
            port: rule.port,
            protocol: rule.protocol,
            source: rule.source,
            comment: rule.comment,
            managed_by: "stacker".to_string(),
            managed_scope: managed_scope.into(),
            labels: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct CloudFirewallTarget {
    pub provider: String,
    pub cloud_id: i32,
    pub server_id: i32,
    pub project_id: i32,
    #[serde(default)]
    pub deployment_hash: Option<String>,
    pub server_public_ip: String,
    #[serde(default)]
    pub provider_server_id: Option<String>,
    #[serde(default)]
    pub server_name: Option<String>,
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default)]
    pub zone: Option<String>,
    #[serde(default)]
    pub firewall_id: Option<String>,
    #[serde(default)]
    pub firewall_name: Option<String>,
}

#[derive(Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct CloudFirewallCredentials {
    pub provider: String,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub secret: Option<String>,
}

impl fmt::Debug for CloudFirewallCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CloudFirewallCredentials")
            .field("provider", &self.provider)
            .field("token", &self.token.as_ref().map(|_| "[REDACTED]"))
            .field("key", &self.key.as_ref().map(|_| "[REDACTED]"))
            .field("secret", &self.secret.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct CloudFirewallOperationMessage {
    pub protocol_version: String,
    pub operation_id: String,
    pub idempotency_key: String,
    pub action: CloudFirewallAction,
    pub dry_run: bool,
    pub target: CloudFirewallTarget,
    pub rules: Vec<CloudFirewallRule>,
    pub credentials: CloudFirewallCredentials,
    #[serde(default)]
    pub provider_context: BTreeMap<String, serde_json::Value>,
    pub requested_by: CloudFirewallRequestedBy,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct CloudFirewallRequestedBy {
    pub user_id: String,
    #[serde(default)]
    pub user_email: Option<String>,
}

pub fn rules_from_request(
    request: &ConfigureCloudFirewallRequest,
    managed_scope: impl Into<String>,
) -> Result<Vec<CloudFirewallRule>, String> {
    let managed_scope = managed_scope.into();
    let mut rules = Vec::new();

    for rule in &request.public_ports {
        validate_rule(rule)?;
        rules.push(CloudFirewallRule::from_port_rule(
            rule.clone(),
            FirewallRuleDirection::Inbound,
            managed_scope.clone(),
        ));
    }

    for rule in &request.private_ports {
        validate_rule(rule)?;
        rules.push(CloudFirewallRule::from_port_rule(
            rule.clone(),
            FirewallRuleDirection::Inbound,
            managed_scope.clone(),
        ));
    }

    Ok(rules)
}

pub fn validate_request(
    request: &ConfigureCloudFirewallRequest,
) -> Result<CloudFirewallAction, String> {
    let action = request.action.clone().unwrap_or(CloudFirewallAction::Add);
    if matches!(
        action,
        CloudFirewallAction::Add | CloudFirewallAction::Remove
    ) && request.public_ports.is_empty()
        && request.private_ports.is_empty()
    {
        return Err("at least one public or private port is required".to_string());
    }

    for rule in request
        .public_ports
        .iter()
        .chain(request.private_ports.iter())
    {
        validate_rule(rule)?;
    }

    Ok(action)
}

pub fn normalize_provider(provider: &str) -> Option<&'static str> {
    match provider.trim().to_ascii_lowercase().as_str() {
        "htz" | "hetzner" | "hetzner_cloud" | "hcloud" => Some("htz"),
        _ => None,
    }
}

pub fn routing_key(provider: &str) -> Option<String> {
    normalize_provider(provider).map(|provider| format!("install.firewall.{}.v1", provider))
}

pub fn idempotency_key(
    server_id: i32,
    action: &CloudFirewallAction,
    rules: &[CloudFirewallRule],
) -> String {
    let mut parts: Vec<String> = rules
        .iter()
        .map(|rule| {
            format!(
                "{}:{}:{}:{}:{}",
                rule.direction.as_str(),
                rule.protocol,
                rule.port,
                rule.source,
                rule.managed_scope
            )
        })
        .collect();
    parts.sort();
    format!(
        "server:{}:{}:{}",
        server_id,
        action.as_str(),
        parts.join("|")
    )
}

pub fn default_firewall_name(target: &CloudFirewallTarget) -> String {
    target
        .firewall_name
        .clone()
        .or_else(|| {
            target
                .server_name
                .clone()
                .map(|name| format!("frw-{}", name))
        })
        .unwrap_or_else(|| format!("frw-server-{}", target.server_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloud_firewall_message_round_trips() {
        let rule = CloudFirewallRule::from_port_rule(
            FirewallPortRule {
                port: 8000,
                protocol: "tcp".to_string(),
                source: "0.0.0.0/0".to_string(),
                comment: Some("Stacker public port 8000/tcp".to_string()),
            },
            FirewallRuleDirection::Inbound,
            "server:42",
        );
        let message = CloudFirewallOperationMessage {
            protocol_version: CLOUD_FIREWALL_PROTOCOL_VERSION.to_string(),
            operation_id: "cfw_test".to_string(),
            idempotency_key: "server:42:add:inbound:tcp:8000:0.0.0.0/0".to_string(),
            action: CloudFirewallAction::Add,
            dry_run: false,
            target: CloudFirewallTarget {
                provider: "htz".to_string(),
                cloud_id: 7,
                server_id: 42,
                project_id: 9,
                deployment_hash: Some("deployment_test".to_string()),
                server_public_ip: "203.0.113.10".to_string(),
                provider_server_id: None,
                server_name: Some("coolify".to_string()),
                region: Some("fsn1".to_string()),
                zone: None,
                firewall_id: None,
                firewall_name: Some("frw-coolify".to_string()),
            },
            rules: vec![rule],
            credentials: CloudFirewallCredentials {
                provider: "htz".to_string(),
                token: Some("secret-token".to_string()),
                key: None,
                secret: None,
            },
            provider_context: BTreeMap::new(),
            requested_by: CloudFirewallRequestedBy {
                user_id: "user-1".to_string(),
                user_email: Some("user@example.com".to_string()),
            },
        };

        let json = serde_json::to_string(&message).expect("message should serialize");
        let decoded: CloudFirewallOperationMessage =
            serde_json::from_str(&json).expect("message should deserialize");

        assert_eq!(decoded.protocol_version, CLOUD_FIREWALL_PROTOCOL_VERSION);
        assert_eq!(decoded.target.provider, "htz");
        assert_eq!(decoded.rules[0].port, 8000);
        assert_eq!(decoded.rules[0].managed_by, "stacker");
    }

    #[test]
    fn cloud_firewall_credentials_debug_redacts_secrets() {
        let credentials = CloudFirewallCredentials {
            provider: "htz".to_string(),
            token: Some("secret-token".to_string()),
            key: Some("key".to_string()),
            secret: Some("secret".to_string()),
        };
        let debug = format!("{:?}", credentials);

        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("secret-token"));
    }

    #[test]
    fn cloud_firewall_routing_key_normalizes_hetzner() {
        assert_eq!(
            routing_key("hetzner"),
            Some("install.firewall.htz.v1".to_string())
        );
        assert_eq!(routing_key("unknown"), None);
    }
}
