//! MCP Tools for User Service integration.
//!
//! These tools provide AI access to:
//! - User profile information
//! - Subscription plans and limits
//! - Installations/deployments list
//! - Application catalog

use async_trait::async_trait;
use serde_json::{json, Value};

use crate::connectors::user_service::UserServiceClient;
use crate::mcp::protocol::{Tool, ToolContent};
use crate::mcp::registry::{ToolContext, ToolHandler};
use serde::Deserialize;

/// Get current user's profile information
pub struct GetUserProfileTool;

#[async_trait]
impl ToolHandler for GetUserProfileTool {
    async fn execute(&self, _args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        let client = UserServiceClient::new_public(&context.settings.user_service_url);

        // Use the user's token from context to call User Service
        let token = context.user.access_token.as_deref().unwrap_or("");

        let profile = client
            .get_user_profile(token)
            .await
            .map_err(|e| format!("Failed to fetch user profile: {}", e))?;

        let result =
            serde_json::to_string(&profile).map_err(|e| format!("Serialization error: {}", e))?;

        tracing::info!(user_id = %context.user.id, "Fetched user profile via MCP");

        Ok(ToolContent::Text { text: result })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "get_user_profile".to_string(),
            description:
                "Get the current user's profile information including email, name, and roles"
                    .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {},
                "required": []
            }),
        }
    }
}

/// Get user's subscription plan and limits
pub struct GetSubscriptionPlanTool;

#[async_trait]
impl ToolHandler for GetSubscriptionPlanTool {
    async fn execute(&self, _args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        let client = UserServiceClient::new_public(&context.settings.user_service_url);
        let token = context.user.access_token.as_deref().unwrap_or("");

        let plan = client
            .get_subscription_plan(token)
            .await
            .map_err(|e| format!("Failed to fetch subscription plan: {}", e))?;

        let result =
            serde_json::to_string(&plan).map_err(|e| format!("Serialization error: {}", e))?;

        tracing::info!(user_id = %context.user.id, "Fetched subscription plan via MCP");

        Ok(ToolContent::Text { text: result })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "get_subscription_plan".to_string(),
            description: "Get the user's current subscription plan including limits (max deployments, apps per deployment, storage, bandwidth) and features".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {},
                "required": []
            }),
        }
    }
}

/// List user's installations (deployments)
pub struct ListInstallationsTool;

#[async_trait]
impl ToolHandler for ListInstallationsTool {
    async fn execute(&self, _args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        let client = UserServiceClient::new_public(&context.settings.user_service_url);
        let token = context.user.access_token.as_deref().unwrap_or("");

        let installations = client
            .list_installations(token)
            .await
            .map_err(|e| format!("Failed to fetch installations: {}", e))?;

        let result = serde_json::to_string(&installations)
            .map_err(|e| format!("Serialization error: {}", e))?;

        tracing::info!(
            user_id = %context.user.id,
            count = installations.len(),
            "Listed installations via MCP"
        );

        Ok(ToolContent::Text { text: result })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "list_installations".to_string(),
            description: "List all user's deployments/installations with their status, cloud provider, and domain".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {},
                "required": []
            }),
        }
    }
}

/// Get specific installation details
pub struct GetInstallationDetailsTool;

#[async_trait]
impl ToolHandler for GetInstallationDetailsTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            installation_id: i64,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        let client = UserServiceClient::new_public(&context.settings.user_service_url);
        let token = context.user.access_token.as_deref().unwrap_or("");

        let installation = client
            .get_installation(token, params.installation_id)
            .await
            .map_err(|e| format!("Failed to fetch installation details: {}", e))?;

        let result = serde_json::to_string(&installation)
            .map_err(|e| format!("Serialization error: {}", e))?;

        tracing::info!(
            user_id = %context.user.id,
            installation_id = params.installation_id,
            "Fetched installation details via MCP"
        );

        Ok(ToolContent::Text { text: result })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "get_installation_details".to_string(),
            description: "Get detailed information about a specific deployment/installation including apps, server IP, and agent configuration".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "installation_id": {
                        "type": "number",
                        "description": "The installation/deployment ID to fetch details for"
                    }
                },
                "required": ["installation_id"]
            }),
        }
    }
}

/// Search available applications in the catalog
pub struct SearchApplicationsTool;

#[async_trait]
impl ToolHandler for SearchApplicationsTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            #[serde(default)]
            query: Option<String>,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        let client = UserServiceClient::new_public(&context.settings.user_service_url);
        let token = context.user.access_token.as_deref().unwrap_or("");

        let applications = client
            .search_applications(token, params.query.as_deref())
            .await
            .map_err(|e| format!("Failed to search applications: {}", e))?;

        let result = serde_json::to_string(&applications)
            .map_err(|e| format!("Serialization error: {}", e))?;

        tracing::info!(
            user_id = %context.user.id,
            query = ?params.query,
            count = applications.len(),
            "Searched applications via MCP"
        );

        Ok(ToolContent::Text { text: result })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "search_applications".to_string(),
            description: "Search available applications/services in the catalog that can be added to a stack. Returns app details including Docker image, default port, and description.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Optional search query to filter applications by name"
                    }
                },
                "required": []
            }),
        }
    }
}

/// List user notifications
pub struct GetNotificationsTool;

#[async_trait]
impl ToolHandler for GetNotificationsTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            #[serde(default)]
            page: Option<u32>,
            #[serde(default)]
            max_results: Option<u32>,
            #[serde(default)]
            unread_only: Option<bool>,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        let client = UserServiceClient::new_public(&context.settings.user_service_url);
        let token = context.user.access_token.as_deref().unwrap_or("");

        let mut notifications = client
            .list_notifications(token, params.page, params.max_results)
            .await
            .map_err(|e| format!("Failed to fetch notifications: {}", e))?;

        if params.unread_only.unwrap_or(false) {
            notifications.retain(|item| !item.is_read.unwrap_or(false));
        }

        let result = serde_json::to_string(&notifications)
            .map_err(|e| format!("Serialization error: {}", e))?;

        tracing::info!(
            user_id = %context.user.id,
            count = notifications.len(),
            unread_only = params.unread_only.unwrap_or(false),
            "Listed notifications via MCP"
        );

        Ok(ToolContent::Text { text: result })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "get_notifications".to_string(),
            description: "List user notifications with optional pagination and unread filter"
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "page": {
                        "type": "number",
                        "description": "Optional page number"
                    },
                    "max_results": {
                        "type": "number",
                        "description": "Optional number of records per page"
                    },
                    "unread_only": {
                        "type": "boolean",
                        "description": "When true, return only unread notifications"
                    }
                },
                "required": []
            }),
        }
    }
}

/// Mark a notification as read/unread
pub struct MarkNotificationReadTool;

#[async_trait]
impl ToolHandler for MarkNotificationReadTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            notification_id: i64,
            #[serde(default = "default_read_state")]
            is_read: bool,
        }

        fn default_read_state() -> bool {
            true
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        let client = UserServiceClient::new_public(&context.settings.user_service_url);
        let token = context.user.access_token.as_deref().unwrap_or("");

        let response = client
            .mark_notification_read(token, params.notification_id, params.is_read)
            .await
            .map_err(|e| format!("Failed to update notification state: {}", e))?;

        tracing::info!(
            user_id = %context.user.id,
            notification_id = params.notification_id,
            is_read = params.is_read,
            "Updated notification read state via MCP"
        );

        Ok(ToolContent::Text {
            text: response.to_string(),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "mark_notification_read".to_string(),
            description: "Mark a notification as read (default) or unread".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "notification_id": {
                        "type": "number",
                        "description": "Notification ID"
                    },
                    "is_read": {
                        "type": "boolean",
                        "description": "Read state to set (default: true)"
                    }
                },
                "required": ["notification_id"]
            }),
        }
    }
}

/// Mark all notifications as read
pub struct MarkAllNotificationsReadTool;

#[async_trait]
impl ToolHandler for MarkAllNotificationsReadTool {
    async fn execute(&self, _args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        let client = UserServiceClient::new_public(&context.settings.user_service_url);
        let token = context.user.access_token.as_deref().unwrap_or("");

        let response = client
            .mark_all_notifications_read(token)
            .await
            .map_err(|e| format!("Failed to mark all notifications read: {}", e))?;

        tracing::info!(
            user_id = %context.user.id,
            "Marked all notifications as read via MCP"
        );

        Ok(ToolContent::Text {
            text: response.to_string(),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "mark_all_notifications_read".to_string(),
            description: "Mark all notifications as read for the current user".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {},
                "required": []
            }),
        }
    }
}

/// Search templates from unified applications endpoint (official + marketplace)
pub struct SearchMarketplaceTemplatesTool;

#[async_trait]
impl ToolHandler for SearchMarketplaceTemplatesTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            #[serde(default)]
            query: Option<String>,
            #[serde(default)]
            category: Option<String>,
            #[serde(default)]
            is_marketplace: Option<bool>,
            #[serde(default)]
            page: Option<u32>,
            #[serde(default)]
            max_results: Option<u32>,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        let client = UserServiceClient::new_public(&context.settings.user_service_url);
        let token = context.user.access_token.as_deref().unwrap_or("");

        let applications = client
            .search_marketplace_templates(
                token,
                params.query.as_deref(),
                params.category.as_deref(),
                params.is_marketplace,
                params.page,
                params.max_results,
            )
            .await
            .map_err(|e| format!("Failed to search templates: {}", e))?;

        let response = json!({
            "count": applications.len(),
            "items": applications,
        });

        tracing::info!(
            user_id = %context.user.id,
            query = ?params.query,
            category = ?params.category,
            is_marketplace = ?params.is_marketplace,
            count = response.get("count").and_then(|v| v.as_u64()).unwrap_or(0),
            "Searched unified template catalog via MCP"
        );

        Ok(ToolContent::Text {
            text: response.to_string(),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "search_marketplace_templates".to_string(),
            description: "Search the unified applications catalog (official + marketplace templates) with optional text/category/source filters"
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Optional free-text search over name/code/description"
                    },
                    "category": {
                        "type": "string",
                        "description": "Optional category filter"
                    },
                    "is_marketplace": {
                        "type": "boolean",
                        "description": "Optional source filter: true for marketplace only, false for official only"
                    },
                    "page": {
                        "type": "number",
                        "description": "Optional page number"
                    },
                    "max_results": {
                        "type": "number",
                        "description": "Optional number of records per page"
                    }
                },
                "required": []
            }),
        }
    }
}

/// Initiate deployment using User Service native install flow
pub struct InitiateDeploymentTool;

#[async_trait]
impl ToolHandler for InitiateDeploymentTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            payload: Value,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        let client = UserServiceClient::new_public(&context.settings.user_service_url);
        let token = context.user.access_token.as_deref().unwrap_or("");

        let response = client
            .initiate_deployment(token, params.payload)
            .await
            .map_err(|e| format!("Failed to initiate deployment: {}", e))?;

        tracing::info!(
            user_id = %context.user.id,
            "Initiated deployment via User Service MCP tool"
        );

        Ok(ToolContent::Text {
            text: response.to_string(),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "initiate_deployment".to_string(),
            description: "Initiate deployment through User Service /install/init/ using native validation and orchestration flow"
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "payload": {
                        "type": "object",
                        "description": "Deployment request payload expected by User Service /install/init/"
                    }
                },
                "required": ["payload"]
            }),
        }
    }
}

/// Trigger redeploy for an existing installation
pub struct TriggerRedeployTool;

#[async_trait]
impl ToolHandler for TriggerRedeployTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            installation_id: i64,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        let client = UserServiceClient::new_public(&context.settings.user_service_url);
        let token = context.user.access_token.as_deref().unwrap_or("");

        let response = client
            .trigger_redeploy(token, params.installation_id)
            .await
            .map_err(|e| format!("Failed to trigger redeploy: {}", e))?;

        tracing::info!(
            user_id = %context.user.id,
            installation_id = params.installation_id,
            "Triggered installation redeploy via MCP"
        );

        Ok(ToolContent::Text {
            text: response.to_string(),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "trigger_redeploy".to_string(),
            description: "Trigger redeploy for an existing installation".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "installation_id": {
                        "type": "number",
                        "description": "Installation ID to redeploy"
                    }
                },
                "required": ["installation_id"]
            }),
        }
    }
}

/// Add a new app to an existing installation
pub struct AddAppToDeploymentTool;

#[async_trait]
impl ToolHandler for AddAppToDeploymentTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            installation_id: i64,
            app_code: String,
            #[serde(default)]
            app_config: Option<Value>,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        let client = UserServiceClient::new_public(&context.settings.user_service_url);
        let token = context.user.access_token.as_deref().unwrap_or("");

        let response = client
            .add_app_to_installation(
                token,
                params.installation_id,
                &params.app_code,
                params.app_config,
            )
            .await
            .map_err(|e| format!("Failed to add app to installation: {}", e))?;

        tracing::info!(
            user_id = %context.user.id,
            installation_id = params.installation_id,
            app_code = %params.app_code,
            "Added app to installation via MCP"
        );

        Ok(ToolContent::Text {
            text: response.to_string(),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "add_app_to_deployment".to_string(),
            description: "Add an app to an existing installation/deployment".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "installation_id": {
                        "type": "number",
                        "description": "Installation ID"
                    },
                    "app_code": {
                        "type": "string",
                        "description": "Application code to add"
                    },
                    "app_config": {
                        "type": "object",
                        "description": "Optional app-specific config payload"
                    }
                },
                "required": ["installation_id", "app_code"]
            }),
        }
    }
}
