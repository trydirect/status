//! MCP Tools for Firewall (iptables) Management
//!
//! These tools provide AI access to:
//! - Configure iptables firewall rules on remote servers
//! - List current firewall rules
//! - Add/remove port rules based on public/private port definitions
//!
//! Supports two execution methods:
//! - SSH Method: Direct SSH to target server for Ansible-based deployments
//! - Status Panel Method: Commands sent via agent command queue for execution on target
//!
//! Port rules are derived from:
//! - Ansible role definitions (public_ports, private_ports)
//! - stacker.yml service port configurations

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::connectors::user_service::UserServiceDeploymentResolver;
use crate::db;
use crate::forms::status_panel::{ConfigureFirewallCommandRequest, FirewallPortRule};
use crate::mcp::protocol::{Tool, ToolContent};
use crate::mcp::registry::{ToolContext, ToolHandler};
use crate::models::{Command, CommandPriority};
use crate::services::{DeploymentIdentifier, DeploymentResolver};

/// Execution method for firewall commands
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum FirewallExecutionMethod {
    /// Execute via Status Panel agent (preferred - runs directly on target)
    #[default]
    StatusPanel,
    /// Execute via SSH (fallback for servers without Status Panel)
    Ssh,
}

/// Tool: configure_firewall - Configure iptables rules on a deployment
pub struct ConfigureFirewallTool;

#[async_trait]
impl ToolHandler for ConfigureFirewallTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            #[serde(default)]
            deployment_id: Option<i64>,
            #[serde(default)]
            deployment_hash: Option<String>,
            #[serde(default)]
            app_code: Option<String>,
            #[serde(default)]
            public_ports: Vec<FirewallPortRule>,
            #[serde(default)]
            private_ports: Vec<FirewallPortRule>,
            #[serde(default = "default_action")]
            action: String,
            #[serde(default)]
            persist: Option<bool>,
            #[serde(default)]
            execution_method: Option<FirewallExecutionMethod>,
        }

        fn default_action() -> String {
            "add".to_string()
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        // Resolve deployment hash
        let identifier = DeploymentIdentifier::try_from_options(
            params.deployment_hash.clone(),
            params.deployment_id,
        )?;

        let resolver = UserServiceDeploymentResolver::from_context(
            &context.settings.user_service_url,
            context.user.access_token.as_deref(),
        );
        let deployment_hash = resolver.resolve(&identifier).await?;

        // Build firewall request
        let firewall_request = ConfigureFirewallCommandRequest {
            app_code: params.app_code.clone(),
            public_ports: params.public_ports.clone(),
            private_ports: params.private_ports.clone(),
            action: params.action.clone(),
            persist: params.persist.unwrap_or(true),
        };

        // Validate the request
        let validated_params = serde_json::to_value(&firewall_request)
            .map_err(|e| format!("Failed to serialize firewall request: {}", e))?;

        let execution_method = params.execution_method.unwrap_or_default();

        match execution_method {
            FirewallExecutionMethod::StatusPanel => {
                // Queue command for Status Panel agent execution
                let command_id = format!("cmd_{}", uuid::Uuid::new_v4());

                let command = Command::new(
                    command_id.clone(),
                    deployment_hash.clone(),
                    "configure_firewall".to_string(),
                    context.user.id.clone(),
                )
                .with_parameters(validated_params)
                .with_priority(CommandPriority::High);

                // Insert command
                let saved = db::command::insert(&context.pg_pool, &command)
                    .await
                    .map_err(|e| format!("Failed to create firewall command: {}", e))?;

                // Add to queue
                db::command::add_to_queue(
                    &context.pg_pool,
                    &saved.command_id,
                    &saved.deployment_hash,
                    &CommandPriority::High,
                )
                .await
                .map_err(|e| format!("Failed to queue firewall command: {}", e))?;

                tracing::info!(
                    command_id = %saved.command_id,
                    deployment_hash = %deployment_hash,
                    action = %params.action,
                    public_ports = params.public_ports.len(),
                    private_ports = params.private_ports.len(),
                    "Firewall configuration command queued for Status Panel execution"
                );

                let result = json!({
                    "status": "queued",
                    "execution_method": "status_panel",
                    "command_id": saved.command_id,
                    "deployment_hash": deployment_hash,
                    "action": params.action,
                    "public_ports_count": params.public_ports.len(),
                    "private_ports_count": params.private_ports.len(),
                    "message": "Firewall configuration command queued. Status Panel agent will execute on target server."
                });

                Ok(ToolContent::Text {
                    text: serde_json::to_string(&result).unwrap(),
                })
            }
            FirewallExecutionMethod::Ssh => {
                // For SSH method, we would need to execute via Ansible
                // This requires the deploy_role infrastructure
                // For now, return a placeholder indicating SSH method

                let result = json!({
                    "status": "pending",
                    "execution_method": "ssh",
                    "deployment_hash": deployment_hash,
                    "action": params.action,
                    "public_ports": params.public_ports,
                    "private_ports": params.private_ports,
                    "message": "SSH execution method selected. Use deploy_role tool with 'firewall' role for Ansible-based execution.",
                    "note": "Prefer 'status_panel' execution_method when Status Panel agent is available on target."
                });

                Ok(ToolContent::Text {
                    text: serde_json::to_string(&result).unwrap(),
                })
            }
        }
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "configure_firewall".to_string(),
            description: "Configure iptables firewall rules on a deployment target server. \
                Supports two execution methods: 'status_panel' (preferred, runs directly on target) \
                or 'ssh' (fallback for Ansible-based deployments). \
                Public ports are opened to all IPs (0.0.0.0/0). \
                Private ports are restricted to specified source IPs/networks."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "deployment_hash": {
                        "type": "string",
                        "description": "Deployment hash (preferred identifier)"
                    },
                    "deployment_id": {
                        "type": "number",
                        "description": "Deployment ID (legacy numeric ID)"
                    },
                    "app_code": {
                        "type": "string",
                        "description": "App code for context/logging (optional)"
                    },
                    "public_ports": {
                        "type": "array",
                        "description": "Ports to open publicly (accessible from any IP)",
                        "items": {
                            "type": "object",
                            "properties": {
                                "port": {"type": "number", "description": "Port number"},
                                "protocol": {"type": "string", "enum": ["tcp", "udp"], "default": "tcp"},
                                "source": {"type": "string", "default": "0.0.0.0/0"},
                                "comment": {"type": "string"}
                            },
                            "required": ["port"]
                        }
                    },
                    "private_ports": {
                        "type": "array",
                        "description": "Ports to open privately (restricted to specific IPs/networks)",
                        "items": {
                            "type": "object",
                            "properties": {
                                "port": {"type": "number", "description": "Port number"},
                                "protocol": {"type": "string", "enum": ["tcp", "udp"], "default": "tcp"},
                                "source": {"type": "string", "description": "Source IP/CIDR (e.g., '10.0.0.0/8')"},
                                "comment": {"type": "string"}
                            },
                            "required": ["port", "source"]
                        }
                    },
                    "action": {
                        "type": "string",
                        "enum": ["add", "remove", "list", "flush"],
                        "default": "add",
                        "description": "Action to perform on firewall rules"
                    },
                    "persist": {
                        "type": "boolean",
                        "default": true,
                        "description": "Whether to persist rules across reboots"
                    },
                    "execution_method": {
                        "type": "string",
                        "enum": ["status_panel", "ssh"],
                        "default": "status_panel",
                        "description": "Execution method: 'status_panel' (preferred) or 'ssh' (fallback)"
                    }
                },
                "required": []
            }),
        }
    }
}

/// Tool: list_firewall_rules - List current iptables rules on a deployment
pub struct ListFirewallRulesTool;

#[async_trait]
impl ToolHandler for ListFirewallRulesTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            #[serde(default)]
            deployment_id: Option<i64>,
            #[serde(default)]
            deployment_hash: Option<String>,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        // Resolve deployment hash
        let identifier = DeploymentIdentifier::try_from_options(
            params.deployment_hash.clone(),
            params.deployment_id,
        )?;

        let resolver = UserServiceDeploymentResolver::from_context(
            &context.settings.user_service_url,
            context.user.access_token.as_deref(),
        );
        let deployment_hash = resolver.resolve(&identifier).await?;

        // Queue a list command
        let command_id = format!("cmd_{}", uuid::Uuid::new_v4());

        let firewall_request = ConfigureFirewallCommandRequest {
            app_code: None,
            public_ports: vec![],
            private_ports: vec![],
            action: "list".to_string(),
            persist: false,
        };

        let command = Command::new(
            command_id.clone(),
            deployment_hash.clone(),
            "configure_firewall".to_string(),
            context.user.id.clone(),
        )
        .with_parameters(serde_json::to_value(&firewall_request).unwrap())
        .with_priority(CommandPriority::Normal);

        let saved = db::command::insert(&context.pg_pool, &command)
            .await
            .map_err(|e| format!("Failed to create list firewall command: {}", e))?;

        db::command::add_to_queue(
            &context.pg_pool,
            &saved.command_id,
            &saved.deployment_hash,
            &CommandPriority::Normal,
        )
        .await
        .map_err(|e| format!("Failed to queue list firewall command: {}", e))?;

        tracing::info!(
            command_id = %saved.command_id,
            deployment_hash = %deployment_hash,
            "Firewall list command queued"
        );

        let result = json!({
            "status": "queued",
            "command_id": saved.command_id,
            "deployment_hash": deployment_hash,
            "message": "List firewall rules command queued. Check command status for results."
        });

        Ok(ToolContent::Text {
            text: serde_json::to_string(&result).unwrap(),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "list_firewall_rules".to_string(),
            description: "List current iptables firewall rules on a deployment target server. \
                Queues a command for the Status Panel agent to retrieve the current ruleset."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "deployment_hash": {
                        "type": "string",
                        "description": "Deployment hash"
                    },
                    "deployment_id": {
                        "type": "number",
                        "description": "Deployment ID"
                    }
                },
                "required": []
            }),
        }
    }
}

/// Tool: configure_firewall_from_role - Configure firewall based on Ansible role ports
pub struct ConfigureFirewallFromRoleTool;

#[async_trait]
impl ToolHandler for ConfigureFirewallFromRoleTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            role_name: String,
            #[serde(default)]
            deployment_id: Option<i64>,
            #[serde(default)]
            deployment_hash: Option<String>,
            #[serde(default = "default_action")]
            action: String,
            #[serde(default)]
            private_network: Option<String>,
        }

        fn default_action() -> String {
            "add".to_string()
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        // Resolve deployment hash
        let identifier = DeploymentIdentifier::try_from_options(
            params.deployment_hash.clone(),
            params.deployment_id,
        )?;

        let resolver = UserServiceDeploymentResolver::from_context(
            &context.settings.user_service_url,
            context.user.access_token.as_deref(),
        );
        let deployment_hash = resolver.resolve(&identifier).await?;

        // Fetch role info from database to get ports
        let user_service_url = &context.settings.user_service_url;
        let endpoint = format!("{}/role?name=eq.{}", user_service_url, params.role_name);

        let client = reqwest::Client::new();
        let response = client
            .get(&endpoint)
            .header(
                "Authorization",
                format!(
                    "Bearer {}",
                    context.user.access_token.as_deref().unwrap_or("")
                ),
            )
            .send()
            .await
            .map_err(|e| format!("Failed to fetch role info: {}", e))?;

        if !response.status().is_success() {
            return Err(format!(
                "Failed to fetch role '{}': {}",
                params.role_name,
                response.status()
            ));
        }

        #[derive(Deserialize)]
        #[allow(dead_code)]
        struct DbRole {
            name: String,
            #[serde(default)]
            public_ports: Vec<String>,
            #[serde(default)]
            private_ports: Vec<String>,
        }

        let roles: Vec<DbRole> = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse role response: {}", e))?;

        let role = roles
            .into_iter()
            .next()
            .ok_or_else(|| format!("Role '{}' not found", params.role_name))?;

        // Convert port strings to FirewallPortRule
        let public_ports: Vec<FirewallPortRule> = role
            .public_ports
            .iter()
            .filter_map(|p| parse_port_string(p, "0.0.0.0/0"))
            .collect();

        let private_source = params.private_network.as_deref().unwrap_or("10.0.0.0/8");
        let private_ports: Vec<FirewallPortRule> = role
            .private_ports
            .iter()
            .filter_map(|p| parse_port_string(p, private_source))
            .collect();

        // Build firewall request
        let firewall_request = ConfigureFirewallCommandRequest {
            app_code: Some(params.role_name.clone()),
            public_ports: public_ports.clone(),
            private_ports: private_ports.clone(),
            action: params.action.clone(),
            persist: true,
        };

        // Queue command
        let command_id = format!("cmd_{}", uuid::Uuid::new_v4());

        let command = Command::new(
            command_id.clone(),
            deployment_hash.clone(),
            "configure_firewall".to_string(),
            context.user.id.clone(),
        )
        .with_parameters(serde_json::to_value(&firewall_request).unwrap())
        .with_priority(CommandPriority::High);

        let saved = db::command::insert(&context.pg_pool, &command)
            .await
            .map_err(|e| format!("Failed to create firewall command: {}", e))?;

        db::command::add_to_queue(
            &context.pg_pool,
            &saved.command_id,
            &saved.deployment_hash,
            &CommandPriority::High,
        )
        .await
        .map_err(|e| format!("Failed to queue firewall command: {}", e))?;

        tracing::info!(
            command_id = %saved.command_id,
            deployment_hash = %deployment_hash,
            role_name = %params.role_name,
            action = %params.action,
            "Firewall configuration from role queued"
        );

        let result = json!({
            "status": "queued",
            "command_id": saved.command_id,
            "deployment_hash": deployment_hash,
            "role_name": params.role_name,
            "action": params.action,
            "public_ports": public_ports,
            "private_ports": private_ports,
            "message": format!(
                "Firewall rules from role '{}' queued for configuration. {} public ports, {} private ports.",
                params.role_name,
                public_ports.len(),
                private_ports.len()
            )
        });

        Ok(ToolContent::Text {
            text: serde_json::to_string(&result).unwrap(),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "configure_firewall_from_role".to_string(),
            description: "Configure firewall rules based on an Ansible role's port definitions. \
                Automatically extracts public_ports and private_ports from the role configuration \
                and creates corresponding iptables rules. Public ports are opened to all IPs, \
                private ports are restricted to the specified network (default: 10.0.0.0/8)."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "role_name": {
                        "type": "string",
                        "description": "Name of the Ansible role (e.g., 'nginx', 'postgres', 'redis')"
                    },
                    "deployment_hash": {
                        "type": "string",
                        "description": "Deployment hash"
                    },
                    "deployment_id": {
                        "type": "number",
                        "description": "Deployment ID"
                    },
                    "action": {
                        "type": "string",
                        "enum": ["add", "remove"],
                        "default": "add",
                        "description": "Action to perform"
                    },
                    "private_network": {
                        "type": "string",
                        "default": "10.0.0.0/8",
                        "description": "CIDR for private port access restriction"
                    }
                },
                "required": ["role_name"]
            }),
        }
    }
}

/// Parse a port string like "80", "443/tcp", "53/udp" into a FirewallPortRule
fn parse_port_string(port_str: &str, source: &str) -> Option<FirewallPortRule> {
    let parts: Vec<&str> = port_str.split('/').collect();
    let port: u16 = parts.first()?.parse().ok()?;
    let protocol = parts.get(1).unwrap_or(&"tcp").to_string();

    Some(FirewallPortRule {
        port,
        protocol,
        source: source.to_string(),
        comment: None,
    })
}
