use uuid::Uuid;

use crate::connectors::errors::ConnectorError;

use super::{
    CategoryInfo, PlanDefinition, ProductInfo, StackResponse, UserPlanInfo, UserProduct,
    UserProfile, UserServiceConnector,
};

/// Mock User Service for testing - always succeeds
pub struct MockUserServiceConnector;

#[async_trait::async_trait]
impl UserServiceConnector for MockUserServiceConnector {
    async fn create_stack_from_template(
        &self,
        marketplace_template_id: &Uuid,
        user_id: &str,
        template_version: &str,
        name: &str,
        _stack_definition: serde_json::Value,
    ) -> Result<StackResponse, ConnectorError> {
        Ok(StackResponse {
            id: 1,
            user_id: user_id.to_string(),
            name: name.to_string(),
            marketplace_template_id: Some(*marketplace_template_id),
            is_from_marketplace: true,
            template_version: Some(template_version.to_string()),
        })
    }

    async fn get_stack(
        &self,
        stack_id: i32,
        user_id: &str,
    ) -> Result<StackResponse, ConnectorError> {
        Ok(StackResponse {
            id: stack_id,
            user_id: user_id.to_string(),
            name: "Test Stack".to_string(),
            marketplace_template_id: None,
            is_from_marketplace: false,
            template_version: None,
        })
    }

    async fn list_stacks(&self, user_id: &str) -> Result<Vec<StackResponse>, ConnectorError> {
        Ok(vec![StackResponse {
            id: 1,
            user_id: user_id.to_string(),
            name: "Test Stack".to_string(),
            marketplace_template_id: None,
            is_from_marketplace: false,
            template_version: None,
        }])
    }

    async fn user_has_plan(
        &self,
        _user_id: &str,
        _required_plan_name: &str,
        _user_token: Option<&str>,
    ) -> Result<bool, ConnectorError> {
        // Mock always grants access for testing
        Ok(true)
    }

    async fn get_user_plan(&self, user_id: &str) -> Result<UserPlanInfo, ConnectorError> {
        Ok(UserPlanInfo {
            user_id: user_id.to_string(),
            plan_name: "professional".to_string(),
            plan_description: Some("Professional Plan".to_string()),
            tier: Some("pro".to_string()),
            active: true,
            started_at: Some("2025-01-01T00:00:00Z".to_string()),
            expires_at: None,
        })
    }

    async fn list_available_plans(&self) -> Result<Vec<PlanDefinition>, ConnectorError> {
        Ok(vec![
            PlanDefinition {
                name: "basic".to_string(),
                description: Some("Basic Plan".to_string()),
                tier: Some("basic".to_string()),
                features: None,
            },
            PlanDefinition {
                name: "professional".to_string(),
                description: Some("Professional Plan".to_string()),
                tier: Some("pro".to_string()),
                features: None,
            },
            PlanDefinition {
                name: "enterprise".to_string(),
                description: Some("Enterprise Plan".to_string()),
                tier: Some("enterprise".to_string()),
                features: None,
            },
        ])
    }

    async fn get_user_profile(&self, _user_token: &str) -> Result<UserProfile, ConnectorError> {
        Ok(UserProfile {
            email: "test@example.com".to_string(),
            plan: Some(serde_json::json!({
                "name": "professional",
                "date_end": "2026-12-31"
            })),
            products: vec![
                UserProduct {
                    id: Some("uuid-plan-pro".to_string()),
                    name: "Professional Plan".to_string(),
                    code: "professional".to_string(),
                    product_type: "plan".to_string(),
                    external_id: None,
                    owned_since: Some("2025-01-01T00:00:00Z".to_string()),
                },
                UserProduct {
                    id: Some("uuid-template-ai".to_string()),
                    name: "AI Agent Stack Pro".to_string(),
                    code: "ai-agent-stack-pro".to_string(),
                    product_type: "template".to_string(),
                    external_id: Some(100),
                    owned_since: Some("2025-01-15T00:00:00Z".to_string()),
                },
            ],
        })
    }

    async fn get_template_product(
        &self,
        stack_template_id: i32,
    ) -> Result<Option<ProductInfo>, ConnectorError> {
        if stack_template_id == 100 {
            Ok(Some(ProductInfo {
                id: "uuid-product-ai".to_string(),
                name: "AI Agent Stack Pro".to_string(),
                code: "ai-agent-stack-pro".to_string(),
                product_type: "template".to_string(),
                external_id: Some(100),
                price: Some(99.99),
                billing_cycle: Some("one_time".to_string()),
                currency: Some("USD".to_string()),
                vendor_id: Some(456),
                is_active: true,
            }))
        } else {
            Ok(None) // No product for other template IDs
        }
    }

    async fn user_owns_template(
        &self,
        _user_token: &str,
        stack_template_id: &str,
    ) -> Result<bool, ConnectorError> {
        // Mock user owns template if ID is "100" or contains "ai-agent"
        Ok(stack_template_id == "100" || stack_template_id.contains("ai-agent"))
    }

    async fn get_categories(&self) -> Result<Vec<CategoryInfo>, ConnectorError> {
        // Return mock categories
        Ok(vec![
            CategoryInfo {
                id: 1,
                name: "cms".to_string(),
                title: "CMS".to_string(),
                priority: Some(1),
            },
            CategoryInfo {
                id: 2,
                name: "ecommerce".to_string(),
                title: "E-commerce".to_string(),
                priority: Some(2),
            },
            CategoryInfo {
                id: 5,
                name: "ai".to_string(),
                title: "AI Agents".to_string(),
                priority: Some(5),
            },
        ])
    }
}
