use crate::cli::deployment_lock::DeploymentLock;
use crate::cli::error::CliError;
use crate::cli::runtime::CliRuntime;
use crate::console::commands::CallableTrait;
use crate::forms::{
    parse_private_port, parse_public_port, CloudFirewallAction, ConfigureCloudFirewallRequest,
    ConfigureCloudFirewallResponse,
};

pub struct CloudFirewallCommand {
    pub action: CloudFirewallAction,
    pub server_id: Option<i32>,
    pub public_ports: Vec<String>,
    pub private_ports: Vec<String>,
    pub dry_run: bool,
    pub json: bool,
}

impl CloudFirewallCommand {
    pub fn new(
        action: CloudFirewallAction,
        server_id: Option<i32>,
        public_ports: Vec<String>,
        private_ports: Vec<String>,
        dry_run: bool,
        json: bool,
    ) -> Self {
        Self {
            action,
            server_id,
            public_ports,
            private_ports,
            dry_run,
            json,
        }
    }

    fn resolve_server_id(&self, ctx: &CliRuntime) -> Result<i32, CliError> {
        if let Some(server_id) = self.server_id {
            return Ok(server_id);
        }

        let project_dir = std::env::current_dir().map_err(CliError::Io)?;

        if let Ok(Some(lock)) = DeploymentLock::load_active(&project_dir) {
            if let Some(server_name) = lock.server_name {
                if let Ok(Some(server)) =
                    ctx.block_on(ctx.client.find_server_by_name(&server_name))
                {
                    return Ok(server.id);
                }
            }
        }
        let config_path = project_dir.join("stacker.yml");
        if !config_path.exists() {
            return Err(CliError::ConfigValidation(
                "Use --server-id <ID>, or run from a directory with stacker.yml".to_string(),
            ));
        }

        let config = crate::cli::config_parser::StackerConfig::from_file(&config_path)
            .and_then(|config| config.with_resolved_deploy_target(None))?;
        let project_name = config.project.identity.ok_or_else(|| {
            CliError::ConfigValidation(
                "Use --server-id <ID>, or set project.identity in stacker.yml".to_string(),
            )
        })?;
        let project = ctx
            .block_on(ctx.client.find_project_by_name(&project_name))?
            .ok_or_else(|| {
                CliError::ConfigValidation(format!(
                    "Project '{}' was not found on the Stacker server",
                    project_name
                ))
            })?;
        let servers = ctx.block_on(ctx.client.list_servers())?;
        let mut project_servers = servers
            .into_iter()
            .filter(|server| server.project_id == project.id)
            .collect::<Vec<_>>();
        project_servers.sort_by_key(|server| server.id);

        match project_servers.as_slice() {
            [server] => Ok(server.id),
            [] => Err(CliError::ConfigValidation(format!(
                "No server found for project '{}'. Use --server-id <ID>.",
                project_name
            ))),
            _ => Err(CliError::ConfigValidation(format!(
                "Multiple servers found for project '{}'. Use --server-id <ID>.",
                project_name
            ))),
        }
    }
}

impl CallableTrait for CloudFirewallCommand {
    fn call(&self) -> Result<(), Box<dyn std::error::Error>> {
        let ctx = CliRuntime::new("cloud firewall")?;
        let server_id = self.resolve_server_id(&ctx)?;
        let public_ports = self
            .public_ports
            .iter()
            .map(|port| parse_public_port(port))
            .collect::<Result<Vec<_>, _>>()
            .map_err(CliError::ConfigValidation)?;
        let private_ports = self
            .private_ports
            .iter()
            .map(|port| parse_private_port(port))
            .collect::<Result<Vec<_>, _>>()
            .map_err(CliError::ConfigValidation)?;

        let request = ConfigureCloudFirewallRequest {
            action: Some(self.action.clone()),
            public_ports,
            private_ports,
            dry_run: self.dry_run,
        };
        let response = ctx.block_on(ctx.client.configure_cloud_firewall(server_id, &request))?;

        if self.json {
            println!("{}", serde_json::to_string_pretty(&response)?);
            return Ok(());
        }

        for line in format_response_lines(&response, crate::cli::debug::cli_debug_enabled()) {
            println!("{}", line);
        }

        Ok(())
    }
}

fn format_response_lines(response: &ConfigureCloudFirewallResponse, debug: bool) -> Vec<String> {
    let mut lines = Vec::new();
    if response.action == CloudFirewallAction::List {
        lines.push(format!(
            "Cloud firewall list for server {} ({})",
            response.server_id, response.provider
        ));
    } else {
        lines.push(format!(
            "Cloud firewall {} accepted for server {} ({})",
            response.action.as_str(),
            response.server_id,
            response.provider
        ));
    }
    if debug {
        lines.push(format!("Operation: {}", response.operation_id));
        lines.push(format!("Route: {}", response.routing_key));
    }

    if let Some(firewall) = &response.firewall {
        let id = firewall
            .id
            .map(|id| format!(" (#{})", id))
            .unwrap_or_default();
        lines.push(format!("Firewall: {}{}", firewall.name, id));
        if firewall.rules.is_empty() {
            lines.push("Rules: none".to_string());
        } else {
            lines.push("Rules:".to_string());
            for rule in &firewall.rules {
                lines.push(format_provider_rule(rule));
            }
        }
        return lines;
    }

    if let Some(name) = &response.firewall_name {
        lines.push(format!("Firewall: {}", name));
    }

    for rule in &response.rules {
        lines.push(format!(
            "- {} {}/{} from {}",
            rule.direction.as_str(),
            rule.port,
            rule.protocol,
            rule.source
        ));
    }
    lines
}

fn format_provider_rule(rule: &crate::forms::CloudFirewallProviderRule) -> String {
    let peer_label = if rule.source_ips.is_empty() {
        "to"
    } else {
        "from"
    };
    let peers = if rule.source_ips.is_empty() {
        rule.destination_ips.join(", ")
    } else {
        rule.source_ips.join(", ")
    };
    let peers = if peers.is_empty() {
        "-"
    } else {
        peers.as_str()
    };
    let description = rule
        .description
        .as_deref()
        .filter(|description| !description.trim().is_empty())
        .map(|description| format!(" ({})", description))
        .unwrap_or_default();

    format!(
        "- {} {}/{} {} {}{}",
        rule.direction, rule.port, rule.protocol, peer_label, peers, description
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forms::{CloudFirewallDetails, CloudFirewallProviderRule};

    #[test]
    fn cloud_firewall_command_stores_action_and_ports() {
        let command = CloudFirewallCommand::new(
            CloudFirewallAction::Add,
            Some(42),
            vec!["8000/tcp".to_string()],
            vec![],
            false,
            true,
        );

        assert_eq!(command.server_id, Some(42));
        assert_eq!(command.public_ports, vec!["8000/tcp"]);
        assert_eq!(command.action, CloudFirewallAction::Add);
    }

    #[test]
    fn cloud_firewall_list_output_includes_firewall_name_and_rules() {
        let response = ConfigureCloudFirewallResponse {
            operation_id: "cfw_test".to_string(),
            accepted: true,
            protocol_version: "stacker.cloud_firewall.v1".to_string(),
            provider: "htz".to_string(),
            server_id: 80,
            action: CloudFirewallAction::List,
            rules: Vec::new(),
            routing_key: "install.firewall.htz.v1".to_string(),
            message: "Cloud firewall list retrieved".to_string(),
            firewall_name: Some("frw-coolify-86b8".to_string()),
            firewall: Some(CloudFirewallDetails {
                id: Some(123),
                name: "frw-coolify-86b8".to_string(),
                rules: vec![CloudFirewallProviderRule {
                    direction: "in".to_string(),
                    protocol: "tcp".to_string(),
                    port: "8000".to_string(),
                    source_ips: vec!["0.0.0.0/0".to_string()],
                    destination_ips: Vec::new(),
                    description: Some("Coolify".to_string()),
                }],
            }),
        };

        let lines = format_response_lines(&response, false);

        assert!(lines.contains(&"Firewall: frw-coolify-86b8 (#123)".to_string()));
        assert!(lines.contains(&"- in 8000/tcp from 0.0.0.0/0 (Coolify)".to_string()));
        assert!(!lines.iter().any(|line| line.starts_with("Operation:")));
        assert!(!lines.iter().any(|line| line.starts_with("Route:")));
    }

    #[test]
    fn cloud_firewall_list_output_includes_debug_metadata_when_debug_enabled() {
        let response = ConfigureCloudFirewallResponse {
            operation_id: "cfw_test".to_string(),
            accepted: true,
            protocol_version: "stacker.cloud_firewall.v1".to_string(),
            provider: "htz".to_string(),
            server_id: 80,
            action: CloudFirewallAction::List,
            rules: Vec::new(),
            routing_key: "install.firewall.htz.v1".to_string(),
            message: "Cloud firewall list retrieved".to_string(),
            firewall_name: Some("frw-coolify-86b8".to_string()),
            firewall: None,
        };

        let lines = format_response_lines(&response, true);

        assert!(lines.contains(&"Operation: cfw_test".to_string()));
        assert!(lines.contains(&"Route: install.firewall.htz.v1".to_string()));
    }
}
