use crate::configuration::Settings;
use crate::models;
use actix_casbin_auth::{
    casbin::{CoreApi, Error as CasbinError},
    CasbinService,
};
use actix_web::web;
use async_trait::async_trait;
use serde_json::Value;
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;

use super::protocol::{Tool, ToolContent};
use crate::mcp::tools::{
    ActivatePipeTool,
    AddAppToDeploymentTool,
    AddCloudTool,
    AdminApproveTemplateTool,
    AdminGetTemplateDetailTool,
    AdminListSubmittedTemplatesTool,
    AdminListTemplateReviewsTool,
    AdminListTemplateVersionsTool,
    AdminRejectTemplateTool,
    AdminValidateTemplateSecurityTool,
    ApplyDeploymentPlanTool,
    ApplyVaultConfigTool,
    CancelDeploymentTool,
    CloneProjectTool,
    ConfigureFirewallFromRoleTool,
    // Firewall tools
    ConfigureFirewallTool,
    // Agent Control tools
    ConfigureProxyAgentTool,
    ConfigureProxyTool,
    CreatePipeInstanceTool,
    CreatePipeTemplateTool,
    CreateProjectAppTool,
    CreateProjectTool,
    DeactivatePipeTool,
    DeleteAppEnvVarTool,
    DeleteCloudTool,
    DeleteProjectTool,
    DeleteProxyTool,
    DeleteRemoteServiceSecretTool,
    // Ansible Roles tools
    DeployAppTool,
    DeployRoleTool,
    DiagnoseDeploymentTool,
    DiscoverStackServicesTool,
    EscalateToSupportTool,
    // Agent Control tools
    ExecuteAgentCommandTool,
    ExplainEnvTool,
    ExplainTopologyTool,
    GetAgentCommandHistoryTool,
    GetAgentStatusTool,
    GetAnsibleRoleDefaultsTool,
    GetAppConfigTool,
    // Phase 5: App Configuration tools
    GetAppEnvVarsTool,
    GetCloudTool,
    GetContainerExecTool,
    GetContainerHealthTool,
    GetContainerLogsTool,
    GetDeploymentEventsTool,
    GetDeploymentPlanTool,
    GetDeploymentResourcesTool,
    GetDeploymentStateTool,
    GetDeploymentStatusTool,
    GetDockerComposeYamlTool,
    GetErrorSummaryTool,
    GetInstallationDetailsTool,
    GetLiveChatInfoTool,
    GetNotificationsTool,
    GetPipeHistoryTool,
    GetPipeTool,
    GetProjectTool,
    GetRemoteServiceSecretTool,
    GetRoleDetailsTool,
    GetRoleRequirementsTool,
    GetServerResourcesTool,
    GetSubscriptionPlanTool,
    GetUserProfileTool,
    // Phase 5: Vault Configuration tools
    GetVaultConfigTool,
    InitiateDeploymentTool,
    ListAvailableRolesTool,
    ListCloudImagesTool,
    ListCloudRegionsTool,
    ListCloudServerSizesTool,
    ListCloudsTool,
    ListContainersTool,
    ListFirewallRulesTool,
    ListInstallationsTool,
    ListPipeTemplatesTool,
    ListPipesTool,
    ListProjectAppsTool,
    ListProjectsTool,
    ListProxiesTool,
    ListRemoteSecretTargetsTool,
    ListRemoteServiceSecretsTool,
    ListTemplatesTool,
    ListVaultConfigsTool,
    MarkAllNotificationsReadTool,
    MarkNotificationReadTool,
    PreviewInstallConfigTool,
    // Stack Recommendations
    RecommendStackServicesTool,
    RemoveAppTool,
    RenderAnsibleTemplateTool,
    ReplayPipeExecutionTool,
    RequestServerSnapshotTool,
    RestartContainerTool,
    SearchApplicationsTool,
    SearchMarketplaceTemplatesTool,
    SetAppEnvVarTool,
    SetRemoteServiceSecretTool,
    SetVaultConfigTool,
    StartContainerTool,
    StartDeploymentTool,
    // Phase 5: Container Operations tools
    StopContainerTool,
    SuggestResourcesTool,
    TriggerPipeTool,
    TriggerRedeployTool,
    UpdateAppDomainTool,
    UpdateAppPortsTool,
    ValidateDomainTool,
    ValidateRoleVarsTool,
    // Phase 5: Stack Validation tool
    ValidateStackConfigTool,
};

/// Context passed to tool handlers
pub struct ToolContext {
    pub user: Arc<models::User>,
    pub pg_pool: PgPool,
    pub settings: web::Data<Settings>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolAccessPolicy {
    pub object: String,
    pub action: &'static str,
    pub requires_mfa: bool,
}

const MCP_TOOL_ACTION: &str = "CALL";

const MFA_REQUIRED_TOOLS: &[&str] = &[
    "create_project",
    "create_project_app",
    "start_deployment",
    "cancel_deployment",
    "apply_deployment_plan",
    "add_cloud",
    "delete_cloud",
    "request_server_snapshot",
    "delete_project",
    "clone_project",
    "mark_notification_read",
    "mark_all_notifications_read",
    "initiate_deployment",
    "trigger_redeploy",
    "add_app_to_deployment",
    "restart_container",
    "escalate_to_support",
    "stop_container",
    "start_container",
    "set_app_env_var",
    "delete_app_env_var",
    "update_app_ports",
    "update_app_domain",
    "set_vault_config",
    "apply_vault_config",
    "configure_proxy",
    "delete_proxy",
    "set_remote_service_secret",
    "delete_remote_service_secret",
    "get_container_exec",
    "admin_approve_template",
    "admin_reject_template",
    "admin_validate_template_security",
    "deploy_role",
    "deploy_app",
    "remove_app",
    "configure_proxy_agent",
    "configure_firewall",
    "configure_firewall_from_role",
    "execute_agent_command",
    "create_pipe_template",
    "create_pipe_instance",
    "replay_pipe_execution",
    "activate_pipe",
    "deactivate_pipe",
    "trigger_pipe",
];

/// Trait for tool handlers
#[async_trait]
pub trait ToolHandler: Send + Sync {
    /// Execute the tool with given arguments
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String>;

    /// Return the tool schema definition
    fn schema(&self) -> Tool;
}

/// Tool registry managing all available MCP tools
pub struct ToolRegistry {
    handlers: HashMap<String, Box<dyn ToolHandler>>,
}

impl ToolRegistry {
    /// Create a new tool registry with all handlers registered
    pub fn new() -> Self {
        let mut registry = Self {
            handlers: HashMap::new(),
        };

        // Project management tools
        registry.register("list_projects", Box::new(ListProjectsTool));
        registry.register("get_project", Box::new(GetProjectTool));
        registry.register("create_project", Box::new(CreateProjectTool));
        registry.register("create_project_app", Box::new(CreateProjectAppTool));

        // Template & discovery tools
        registry.register("suggest_resources", Box::new(SuggestResourcesTool));
        registry.register("list_templates", Box::new(ListTemplatesTool));
        registry.register("validate_domain", Box::new(ValidateDomainTool));

        // Phase 3: Deployment tools
        registry.register("get_deployment_status", Box::new(GetDeploymentStatusTool));
        registry.register("get_deployment_state", Box::new(GetDeploymentStateTool));
        registry.register("get_deployment_plan", Box::new(GetDeploymentPlanTool));
        registry.register("get_deployment_events", Box::new(GetDeploymentEventsTool));
        registry.register("apply_deployment_plan", Box::new(ApplyDeploymentPlanTool));
        registry.register("explain_env", Box::new(ExplainEnvTool));
        registry.register("explain_topology", Box::new(ExplainTopologyTool));
        registry.register("start_deployment", Box::new(StartDeploymentTool));
        registry.register("cancel_deployment", Box::new(CancelDeploymentTool));

        // Phase 3: Cloud tools
        registry.register("list_clouds", Box::new(ListCloudsTool));
        registry.register("get_cloud", Box::new(GetCloudTool));
        registry.register("add_cloud", Box::new(AddCloudTool));
        registry.register("delete_cloud", Box::new(DeleteCloudTool));
        registry.register("list_cloud_regions", Box::new(ListCloudRegionsTool));
        registry.register(
            "list_cloud_server_sizes",
            Box::new(ListCloudServerSizesTool),
        );
        registry.register("list_cloud_images", Box::new(ListCloudImagesTool));
        registry.register(
            "request_server_snapshot",
            Box::new(RequestServerSnapshotTool),
        );

        // Phase 3: Project management
        registry.register("delete_project", Box::new(DeleteProjectTool));
        registry.register("clone_project", Box::new(CloneProjectTool));

        // Phase 4: User & Account tools (AI Integration)
        registry.register("get_user_profile", Box::new(GetUserProfileTool));
        registry.register("get_subscription_plan", Box::new(GetSubscriptionPlanTool));
        registry.register("list_installations", Box::new(ListInstallationsTool));
        registry.register(
            "get_installation_details",
            Box::new(GetInstallationDetailsTool),
        );
        registry.register("search_applications", Box::new(SearchApplicationsTool));
        registry.register(
            "search_marketplace_templates",
            Box::new(SearchMarketplaceTemplatesTool),
        );
        registry.register("get_notifications", Box::new(GetNotificationsTool));
        registry.register("mark_notification_read", Box::new(MarkNotificationReadTool));
        registry.register(
            "mark_all_notifications_read",
            Box::new(MarkAllNotificationsReadTool),
        );
        registry.register("initiate_deployment", Box::new(InitiateDeploymentTool));
        registry.register("trigger_redeploy", Box::new(TriggerRedeployTool));
        registry.register("add_app_to_deployment", Box::new(AddAppToDeploymentTool));

        // Phase 4: Monitoring & Logs tools (AI Integration)
        registry.register("get_container_logs", Box::new(GetContainerLogsTool));
        registry.register("get_container_health", Box::new(GetContainerHealthTool));
        registry.register("list_containers", Box::new(ListContainersTool));
        registry.register("restart_container", Box::new(RestartContainerTool));
        registry.register("diagnose_deployment", Box::new(DiagnoseDeploymentTool));

        // Phase 4: Support & Escalation tools (AI Integration)
        registry.register("escalate_to_support", Box::new(EscalateToSupportTool));
        registry.register("get_live_chat_info", Box::new(GetLiveChatInfoTool));

        // Phase 5: Container Operations tools (Agent-Based Deployment)
        registry.register("stop_container", Box::new(StopContainerTool));
        registry.register("start_container", Box::new(StartContainerTool));
        registry.register("get_error_summary", Box::new(GetErrorSummaryTool));

        // Phase 5: App Configuration Management tools
        registry.register("get_app_env_vars", Box::new(GetAppEnvVarsTool));
        registry.register("set_app_env_var", Box::new(SetAppEnvVarTool));
        registry.register("delete_app_env_var", Box::new(DeleteAppEnvVarTool));
        registry.register("get_app_config", Box::new(GetAppConfigTool));
        registry.register("update_app_ports", Box::new(UpdateAppPortsTool));
        registry.register("update_app_domain", Box::new(UpdateAppDomainTool));
        registry.register("preview_install_config", Box::new(PreviewInstallConfigTool));
        registry.register(
            "get_ansible_role_defaults",
            Box::new(GetAnsibleRoleDefaultsTool),
        );
        registry.register(
            "render_ansible_template",
            Box::new(RenderAnsibleTemplateTool),
        );

        // Phase 5: Stack Validation tool
        registry.register("validate_stack_config", Box::new(ValidateStackConfigTool));

        // Phase 6: Stack Service Discovery
        registry.register(
            "discover_stack_services",
            Box::new(DiscoverStackServicesTool),
        );

        // Phase 6: Vault Configuration tools
        registry.register("get_vault_config", Box::new(GetVaultConfigTool));
        registry.register("set_vault_config", Box::new(SetVaultConfigTool));
        registry.register("list_vault_configs", Box::new(ListVaultConfigsTool));
        registry.register("apply_vault_config", Box::new(ApplyVaultConfigTool));

        // Phase 6: Proxy Management tools (Nginx Proxy Manager)
        registry.register("configure_proxy", Box::new(ConfigureProxyTool));
        registry.register("delete_proxy", Box::new(DeleteProxyTool));
        registry.register("list_proxies", Box::new(ListProxiesTool));

        // Phase 6: Project Resource Discovery tools
        registry.register("list_project_apps", Box::new(ListProjectAppsTool));
        registry.register(
            "get_deployment_resources",
            Box::new(GetDeploymentResourcesTool),
        );

        // Vault-backed remote service secrets
        registry.register(
            "list_remote_secret_targets",
            Box::new(ListRemoteSecretTargetsTool),
        );
        registry.register(
            "list_remote_service_secrets",
            Box::new(ListRemoteServiceSecretsTool),
        );
        registry.register(
            "get_remote_service_secret",
            Box::new(GetRemoteServiceSecretTool),
        );
        registry.register(
            "set_remote_service_secret",
            Box::new(SetRemoteServiceSecretTool),
        );
        registry.register(
            "delete_remote_service_secret",
            Box::new(DeleteRemoteServiceSecretTool),
        );

        // Pipe tools
        registry.register("list_pipes", Box::new(ListPipesTool));
        registry.register("get_pipe", Box::new(GetPipeTool));
        registry.register("list_pipe_templates", Box::new(ListPipeTemplatesTool));
        registry.register("create_pipe_template", Box::new(CreatePipeTemplateTool));
        registry.register("create_pipe_instance", Box::new(CreatePipeInstanceTool));
        registry.register("get_pipe_history", Box::new(GetPipeHistoryTool));
        registry.register("replay_pipe_execution", Box::new(ReplayPipeExecutionTool));
        registry.register("activate_pipe", Box::new(ActivatePipeTool));
        registry.register("deactivate_pipe", Box::new(DeactivatePipeTool));
        registry.register("trigger_pipe", Box::new(TriggerPipeTool));

        // Phase 7: Advanced Monitoring & Troubleshooting tools
        registry.register(
            "get_docker_compose_yaml",
            Box::new(GetDockerComposeYamlTool),
        );
        registry.register("get_server_resources", Box::new(GetServerResourcesTool));
        registry.register("get_container_exec", Box::new(GetContainerExecTool));

        // Marketplace Admin tools (admin role required)
        registry.register(
            "admin_list_submitted_templates",
            Box::new(AdminListSubmittedTemplatesTool),
        );
        registry.register(
            "admin_get_template_detail",
            Box::new(AdminGetTemplateDetailTool),
        );
        registry.register("admin_approve_template", Box::new(AdminApproveTemplateTool));
        registry.register("admin_reject_template", Box::new(AdminRejectTemplateTool));
        registry.register(
            "admin_list_template_versions",
            Box::new(AdminListTemplateVersionsTool),
        );
        registry.register(
            "admin_list_template_reviews",
            Box::new(AdminListTemplateReviewsTool),
        );
        registry.register(
            "admin_validate_template_security",
            Box::new(AdminValidateTemplateSecurityTool),
        );

        // Ansible Roles tools (SSH deployment method)
        registry.register("list_available_roles", Box::new(ListAvailableRolesTool));
        registry.register("get_role_details", Box::new(GetRoleDetailsTool));
        registry.register("get_role_requirements", Box::new(GetRoleRequirementsTool));
        registry.register("validate_role_vars", Box::new(ValidateRoleVarsTool));
        registry.register("deploy_role", Box::new(DeployRoleTool));

        // Stack Recommendations
        registry.register(
            "recommend_stack_services",
            Box::new(RecommendStackServicesTool),
        );

        // Agent Control tools (deploy/remove apps, proxy config, agent status)
        registry.register("deploy_app", Box::new(DeployAppTool));
        registry.register("remove_app", Box::new(RemoveAppTool));
        registry.register("configure_proxy_agent", Box::new(ConfigureProxyAgentTool));
        registry.register("get_agent_status", Box::new(GetAgentStatusTool));
        registry.register(
            "get_agent_command_history",
            Box::new(GetAgentCommandHistoryTool),
        );
        registry.register("execute_agent_command", Box::new(ExecuteAgentCommandTool));

        // Firewall (iptables) management tools
        registry.register("configure_firewall", Box::new(ConfigureFirewallTool));
        registry.register("list_firewall_rules", Box::new(ListFirewallRulesTool));
        registry.register(
            "configure_firewall_from_role",
            Box::new(ConfigureFirewallFromRoleTool),
        );

        registry
    }

    /// Register a tool handler
    pub fn register(&mut self, name: &str, handler: Box<dyn ToolHandler>) {
        self.handlers.insert(name.to_string(), handler);
    }

    /// Get a tool handler by name
    pub fn get(&self, name: &str) -> Option<&dyn ToolHandler> {
        self.handlers.get(name).map(Box::as_ref)
    }

    pub fn access_policy(&self, name: &str) -> Option<ToolAccessPolicy> {
        self.has_tool(name).then(|| ToolAccessPolicy {
            object: format!("/mcp/tools/{name}"),
            action: MCP_TOOL_ACTION,
            requires_mfa: MFA_REQUIRED_TOOLS.contains(&name),
        })
    }

    pub async fn authorize_call(
        &self,
        name: &str,
        user: &models::User,
        casbin_service: CasbinService,
    ) -> Result<(), String> {
        let Some(policy) = self.access_policy(name) else {
            return Err("Forbidden: MCP tool call has no registered ACL policy".to_string());
        };

        let allowed = enforce_tool_policy(casbin_service, &user.role, &policy)
            .await
            .map_err(|err| format!("ACL check failed for MCP tool: {err}"))?;

        if !allowed {
            return Err("Forbidden: MCP tool call is not allowed by ACL".to_string());
        }

        if policy.requires_mfa && !user.has_verified_mfa() {
            return Err("Two-factor authentication is required for this MCP tool".to_string());
        }

        Ok(())
    }

    /// List all available tools
    pub fn list_tools(&self) -> Vec<Tool> {
        self.handlers.values().map(|h| h.schema()).collect()
    }

    /// Check if a tool exists
    pub fn has_tool(&self, name: &str) -> bool {
        self.handlers.contains_key(name)
    }

    /// Get count of registered tools
    pub fn count(&self) -> usize {
        self.handlers.len()
    }
}

async fn enforce_tool_policy(
    mut casbin_service: CasbinService,
    role: &str,
    policy: &ToolAccessPolicy,
) -> Result<bool, CasbinError> {
    let enforcer = casbin_service.get_enforcer();
    let mut lock = enforcer.write().await;
    lock.enforce_mut(vec![
        role.to_string(),
        policy.object.to_string(),
        policy.action.to_string(),
    ])
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::ToolRegistry;

    #[test]
    fn all_registered_tools_have_acl_policy() {
        let registry = ToolRegistry::new();

        for tool in registry.list_tools() {
            let policy = registry
                .access_policy(&tool.name)
                .unwrap_or_else(|| panic!("{} should require policy", tool.name));

            assert_eq!(policy.object, format!("/mcp/tools/{}", tool.name));
            assert_eq!(policy.action, "CALL");
        }
    }

    #[test]
    fn sensitive_write_tools_have_acl_and_mfa_policy() {
        let registry = ToolRegistry::new();

        let set_policy = registry
            .access_policy("set_remote_service_secret")
            .expect("set tool should require policy");
        assert_eq!(set_policy.object, "/mcp/tools/set_remote_service_secret");
        assert_eq!(set_policy.action, "CALL");
        assert!(set_policy.requires_mfa);

        let delete_policy = registry
            .access_policy("delete_remote_service_secret")
            .expect("delete tool should require policy");
        assert_eq!(
            delete_policy.object,
            "/mcp/tools/delete_remote_service_secret"
        );
        assert_eq!(delete_policy.action, "CALL");
        assert!(delete_policy.requires_mfa);

        let vault_policy = registry
            .access_policy("apply_vault_config")
            .expect("vault config apply should require policy");
        assert!(vault_policy.requires_mfa);

        let deploy_policy = registry
            .access_policy("deploy_app")
            .expect("deploy app should require policy");
        assert!(deploy_policy.requires_mfa);

        let apply_plan_policy = registry
            .access_policy("apply_deployment_plan")
            .expect("deployment plan apply should require policy");
        assert!(apply_plan_policy.requires_mfa);

        let admin_validate_policy = registry
            .access_policy("admin_validate_template_security")
            .expect("admin security validation should require policy");
        assert!(admin_validate_policy.requires_mfa);

        let exec_policy = registry
            .access_policy("execute_agent_command")
            .expect("raw agent exec should require policy");
        assert!(exec_policy.requires_mfa);

        let activate_policy = registry
            .access_policy("activate_pipe")
            .expect("pipe activation should require policy");
        assert!(activate_policy.requires_mfa);

        let replay_policy = registry
            .access_policy("replay_pipe_execution")
            .expect("pipe replay should require policy");
        assert!(replay_policy.requires_mfa);
    }

    #[test]
    fn read_tools_have_acl_without_step_up_policy() {
        let registry = ToolRegistry::new();

        let list_policy = registry
            .access_policy("list_remote_service_secrets")
            .expect("list tool should require policy");
        assert_eq!(list_policy.object, "/mcp/tools/list_remote_service_secrets");
        assert!(!list_policy.requires_mfa);

        let get_policy = registry
            .access_policy("get_remote_service_secret")
            .expect("get tool should require policy");
        assert_eq!(get_policy.object, "/mcp/tools/get_remote_service_secret");
        assert!(!get_policy.requires_mfa);

        let history_policy = registry
            .access_policy("get_agent_command_history")
            .expect("history tool should require policy");
        assert_eq!(
            history_policy.object,
            "/mcp/tools/get_agent_command_history"
        );
        assert!(!history_policy.requires_mfa);

        let list_pipes_policy = registry
            .access_policy("list_pipes")
            .expect("pipe list should require policy");
        assert_eq!(list_pipes_policy.object, "/mcp/tools/list_pipes");
        assert!(!list_pipes_policy.requires_mfa);
    }

    #[test]
    fn unknown_tools_have_no_policy() {
        let registry = ToolRegistry::new();

        assert!(registry.access_policy("unknown_tool").is_none());
    }
}
