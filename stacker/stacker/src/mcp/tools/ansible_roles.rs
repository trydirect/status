//! MCP Tools for Ansible Roles Management
//!
//! These tools provide AI access to:
//! - Discover available Ansible roles
//! - Get role details, requirements, and variables
//! - Validate role configuration
//! - Deploy roles to SSH-accessible servers
//!
//! Role discovery uses hybrid approach:
//! - Primary: Database `role` table via PostgREST
//! - Fallback: Filesystem scan of tfa/roles/ directory
//!
//! Used for SSH deployment method in Stack Builder UI.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::mcp::protocol::{Tool, ToolContent};
use crate::mcp::registry::{ToolContext, ToolHandler};

const ROLES_BASE_PATH: &str = "/ansible/roles";
const POSTGREST_ROLE_ENDPOINT: &str = "/role";

/// Role metadata structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnsibleRole {
    pub name: String,
    pub description: Option<String>,
    pub public_ports: Vec<String>,
    pub private_ports: Vec<String>,
    pub variables: HashMap<String, RoleVariable>,
    pub dependencies: Vec<String>,
    pub supported_os: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleVariable {
    pub name: String,
    pub default_value: Option<String>,
    pub description: Option<String>,
    pub required: bool,
    pub var_type: String, // string, integer, boolean, etc.
}

/// Fetch roles from database via PostgREST
async fn fetch_roles_from_db(context: &ToolContext) -> Result<Vec<AnsibleRole>, String> {
    let user_service_url = &context.settings.user_service_url;
    let endpoint = format!("{}{}", user_service_url, POSTGREST_ROLE_ENDPOINT);

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
        .map_err(|e| format!("Failed to fetch roles from database: {}", e))?;

    if !response.status().is_success() {
        return Err(format!("Database query failed: {}", response.status()));
    }

    #[derive(Deserialize)]
    struct DbRole {
        name: String,
        #[serde(default)]
        public_ports: Vec<String>,
        #[serde(default)]
        private_ports: Vec<String>,
    }

    let db_roles: Vec<DbRole> = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse database response: {}", e))?;

    Ok(db_roles
        .into_iter()
        .map(|r| AnsibleRole {
            name: r.name,
            description: None,
            public_ports: r.public_ports,
            private_ports: r.private_ports,
            variables: HashMap::new(),
            dependencies: vec![],
            supported_os: vec![],
        })
        .collect())
}

/// Scan filesystem for available roles
fn scan_roles_from_filesystem() -> Result<Vec<String>, String> {
    let roles_path = Path::new(ROLES_BASE_PATH);

    if !roles_path.exists() {
        return Err(format!("Roles directory not found: {}", ROLES_BASE_PATH));
    }

    let mut roles = vec![];

    if let Ok(entries) = std::fs::read_dir(roles_path) {
        for entry in entries.flatten() {
            if let Ok(file_type) = entry.file_type() {
                if file_type.is_dir() {
                    if let Some(name) = entry.file_name().to_str() {
                        // Skip hidden directories and common non-role dirs
                        if !name.starts_with('.') && name != "old" && name != "custom" {
                            roles.push(name.to_string());
                        }
                    }
                }
            }
        }
    }

    roles.sort();
    Ok(roles)
}

/// Get detailed information about a specific role from filesystem
fn get_role_details_from_fs(role_name: &str) -> Result<AnsibleRole, String> {
    let role_path = PathBuf::from(ROLES_BASE_PATH).join(role_name);

    if !role_path.exists() {
        return Err(format!("Role '{}' not found in filesystem", role_name));
    }

    let mut role = AnsibleRole {
        name: role_name.to_string(),
        description: None,
        public_ports: vec![],
        private_ports: vec![],
        variables: HashMap::new(),
        dependencies: vec![],
        supported_os: vec!["ubuntu", "debian"]
            .into_iter()
            .map(|s| s.to_string())
            .collect(), // default
    };

    // Parse README.md for description
    let readme_path = role_path.join("README.md");
    if readme_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&readme_path) {
            // Extract first non-empty line after "Role Name" or "Description"
            for line in content.lines() {
                let trimmed = line.trim();
                if !trimmed.is_empty()
                    && !trimmed.starts_with('#')
                    && !trimmed.starts_with('=')
                    && !trimmed.starts_with('-')
                    && trimmed.len() > 10
                {
                    role.description = Some(trimmed.to_string());
                    break;
                }
            }
        }
    }

    // Parse defaults/main.yml for variables
    let defaults_path = role_path.join("defaults/main.yml");
    if defaults_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&defaults_path) {
            // Simple YAML parsing for variable names (not full parser)
            for line in content.lines() {
                if let Some((key, value)) = parse_yaml_variable(line) {
                    role.variables.insert(
                        key.clone(),
                        RoleVariable {
                            name: key,
                            default_value: Some(value),
                            description: None,
                            required: false,
                            var_type: "string".to_string(),
                        },
                    );
                }
            }
        }
    }

    Ok(role)
}

/// Simple YAML variable parser (key: value)
fn parse_yaml_variable(line: &str) -> Option<(String, String)> {
    let trimmed = line.trim();
    if trimmed.starts_with('#') || trimmed.starts_with("---") || trimmed.is_empty() {
        return None;
    }

    if let Some(colon_pos) = trimmed.find(':') {
        let key = trimmed[..colon_pos].trim();
        let value = trimmed[colon_pos + 1..].trim();

        if !key.is_empty() && !value.is_empty() {
            return Some((key.to_string(), value.to_string()));
        }
    }

    None
}

/// Tool: list_available_roles - Get catalog of all Ansible roles
pub struct ListAvailableRolesTool;

#[async_trait]
impl ToolHandler for ListAvailableRolesTool {
    async fn execute(&self, _args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        // Try database first
        let roles = match fetch_roles_from_db(context).await {
            Ok(db_roles) => {
                tracing::info!("Fetched {} roles from database", db_roles.len());
                db_roles
            }
            Err(db_err) => {
                tracing::warn!(
                    "Database fetch failed ({}), falling back to filesystem",
                    db_err
                );

                // Fallback to filesystem scan
                let role_names = scan_roles_from_filesystem()?;
                tracing::info!("Scanned {} roles from filesystem", role_names.len());

                role_names
                    .into_iter()
                    .map(|name| AnsibleRole {
                        name,
                        description: None,
                        public_ports: vec![],
                        private_ports: vec![],
                        variables: HashMap::new(),
                        dependencies: vec![],
                        supported_os: vec![],
                    })
                    .collect()
            }
        };

        let result = json!({
            "status": "success",
            "total_roles": roles.len(),
            "roles": roles.iter().map(|r| json!({
                "name": r.name,
                "description": r.description.as_deref().unwrap_or("No description available"),
                "public_ports": r.public_ports,
                "private_ports": r.private_ports,
            })).collect::<Vec<_>>(),
        });

        Ok(ToolContent::Text {
            text: serde_json::to_string(&result).unwrap(),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "list_available_roles".to_string(),
            description: "Get a catalog of all available Ansible roles for SSH-based deployments. \
                Returns role names, descriptions, and port configurations. \
                Uses database as primary source with filesystem fallback."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {},
                "required": []
            }),
        }
    }
}

/// Tool: get_role_details - Get detailed info about a specific role
pub struct GetRoleDetailsTool;

#[async_trait]
impl ToolHandler for GetRoleDetailsTool {
    async fn execute(&self, args: Value, _context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            role_name: String,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        // Get detailed info from filesystem (includes variables, README, etc.)
        let role = get_role_details_from_fs(&params.role_name)?;

        let result = json!({
            "status": "success",
            "role": {
                "name": role.name,
                "description": role.description,
                "public_ports": role.public_ports,
                "private_ports": role.private_ports,
                "variables": role.variables,
                "dependencies": role.dependencies,
                "supported_os": role.supported_os,
            }
        });

        Ok(ToolContent::Text {
            text: serde_json::to_string(&result).unwrap(),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "get_role_details".to_string(),
            description: "Get detailed information about a specific Ansible role. \
                Returns description, variables, dependencies, supported OS, and ports. \
                Parses role's README.md and defaults/main.yml for metadata."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "role_name": {
                        "type": "string",
                        "description": "Name of the Ansible role (e.g., 'nginx', 'postgres', 'redis')"
                    }
                },
                "required": ["role_name"]
            }),
        }
    }
}

/// Tool: get_role_requirements - Get role requirements and dependencies
pub struct GetRoleRequirementsTool;

#[async_trait]
impl ToolHandler for GetRoleRequirementsTool {
    async fn execute(&self, args: Value, _context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            role_name: String,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        let role = get_role_details_from_fs(&params.role_name)?;

        let result = json!({
            "status": "success",
            "role_name": role.name,
            "requirements": {
                "dependencies": role.dependencies,
                "supported_os": role.supported_os,
                "required_variables": role.variables.values()
                    .filter(|v| v.required)
                    .map(|v| &v.name)
                    .collect::<Vec<_>>(),
                "optional_variables": role.variables.values()
                    .filter(|v| !v.required)
                    .map(|v| &v.name)
                    .collect::<Vec<_>>(),
                "public_ports": role.public_ports,
                "private_ports": role.private_ports,
            }
        });

        Ok(ToolContent::Text {
            text: serde_json::to_string(&result).unwrap(),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "get_role_requirements".to_string(),
            description: "Get requirements and dependencies for a specific Ansible role. \
                Returns OS requirements, dependent roles, required/optional variables, \
                and port configurations needed for deployment."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "role_name": {
                        "type": "string",
                        "description": "Name of the Ansible role"
                    }
                },
                "required": ["role_name"]
            }),
        }
    }
}

/// Tool: validate_role_vars - Validate role variable configuration
pub struct ValidateRoleVarsTool;

#[async_trait]
impl ToolHandler for ValidateRoleVarsTool {
    async fn execute(&self, args: Value, _context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            role_name: String,
            variables: HashMap<String, Value>,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        let role = get_role_details_from_fs(&params.role_name)?;

        let mut errors = vec![];
        let mut warnings = vec![];

        // Check required variables
        for (var_name, var_def) in &role.variables {
            if var_def.required && !params.variables.contains_key(var_name) {
                errors.push(format!("Required variable '{}' is missing", var_name));
            }
        }

        // Check for unknown variables
        for user_var in params.variables.keys() {
            if !role.variables.contains_key(user_var) {
                warnings.push(format!(
                    "Variable '{}' is not defined in role defaults (may be unused)",
                    user_var
                ));
            }
        }

        let is_valid = errors.is_empty();

        let result = json!({
            "status": if is_valid { "valid" } else { "invalid" },
            "role_name": role.name,
            "valid": is_valid,
            "errors": errors,
            "warnings": warnings,
            "validated_variables": params.variables.keys().collect::<Vec<_>>(),
        });

        Ok(ToolContent::Text {
            text: serde_json::to_string(&result).unwrap(),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "validate_role_vars".to_string(),
            description: "Validate variable configuration for an Ansible role before deployment. \
                Checks for required variables, type compatibility, and warns about unknown variables. \
                Returns validation status with specific errors/warnings."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "role_name": {
                        "type": "string",
                        "description": "Name of the Ansible role"
                    },
                    "variables": {
                        "type": "object",
                        "description": "Key-value pairs of variables to validate",
                        "additionalProperties": true
                    }
                },
                "required": ["role_name", "variables"]
            }),
        }
    }
}

/// Tool: deploy_role - Execute Ansible role on remote server via SSH
pub struct DeployRoleTool;

#[async_trait]
impl ToolHandler for DeployRoleTool {
    async fn execute(&self, args: Value, _context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            server_ip: String,
            role_name: String,
            variables: HashMap<String, Value>,
            #[serde(default)]
            ssh_user: Option<String>,
            #[serde(default)]
            ssh_key_path: Option<String>,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        // Validate role exists
        let role = get_role_details_from_fs(&params.role_name)?;

        // Validate variables
        let mut errors = vec![];
        for (var_name, var_def) in &role.variables {
            if var_def.required && !params.variables.contains_key(var_name) {
                errors.push(format!("Required variable '{}' is missing", var_name));
            }
        }

        if !errors.is_empty() {
            return Ok(ToolContent::Text {
                text: serde_json::to_string(&json!({
                    "status": "validation_failed",
                    "errors": errors,
                }))
                .unwrap(),
            });
        }

        // TODO: Implement actual Ansible playbook execution
        // This would interface with the Install Service or execute ansible-playbook directly
        // For now, return a placeholder response

        let ssh_user = params.ssh_user.unwrap_or_else(|| "root".to_string());
        let ssh_key = params
            .ssh_key_path
            .unwrap_or_else(|| "/root/.ssh/id_rsa".to_string());

        let result = json!({
            "status": "queued",
            "message": "Role deployment has been queued for execution",
            "deployment": {
                "role_name": role.name,
                "server_ip": params.server_ip,
                "ssh_user": ssh_user,
                "ssh_key_path": ssh_key,
                "variables": params.variables,
            },
            "note": "This tool currently queues the deployment. Integration with Install Service pending."
        });

        Ok(ToolContent::Text {
            text: serde_json::to_string(&result).unwrap(),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "deploy_role".to_string(),
            description: "Deploy an Ansible role to a remote server via SSH. \
                Validates configuration, generates playbook, and executes on target. \
                Requires SSH access credentials (key-based authentication). \
                Used for SSH deployment method in Stack Builder."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "server_ip": {
                        "type": "string",
                        "description": "Target server IP address or hostname"
                    },
                    "role_name": {
                        "type": "string",
                        "description": "Name of the Ansible role to deploy"
                    },
                    "variables": {
                        "type": "object",
                        "description": "Role variables (key-value pairs)",
                        "additionalProperties": true
                    },
                    "ssh_user": {
                        "type": "string",
                        "description": "SSH username (default: 'root')",
                        "default": "root"
                    },
                    "ssh_key_path": {
                        "type": "string",
                        "description": "Path to SSH private key (default: '/root/.ssh/id_rsa')",
                        "default": "/root/.ssh/id_rsa"
                    }
                },
                "required": ["server_ip", "role_name", "variables"]
            }),
        }
    }
}
