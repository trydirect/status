/// Deployment validator for marketplace template ownership
///
/// Validates that users can deploy marketplace templates they own.
/// Implements plan gating (if template requires specific plan tier) and
/// product ownership checks (if template is a paid marketplace product).
use std::sync::Arc;
use tracing::Instrument;

use crate::connectors::UserServiceConnector;
use crate::models;

/// Custom error types for deployment validation
#[derive(Debug, Clone)]
pub enum DeploymentValidationError {
    /// User's plan is insufficient for this template
    InsufficientPlan {
        required_plan: String,
        user_plan: String,
    },

    /// User has not purchased this marketplace template
    TemplateNotPurchased {
        template_id: String,
        product_price: Option<f64>,
    },

    /// Template not found in User Service
    TemplateNotFound { template_id: String },

    /// Failed to validate with User Service (unavailable, auth error, etc.)
    ValidationFailed { reason: String },
}

impl std::fmt::Display for DeploymentValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InsufficientPlan {
                required_plan,
                user_plan,
            } => write!(
                f,
                "You require a '{}' subscription to deploy this template (you have '{}')",
                required_plan, user_plan
            ),
            Self::TemplateNotPurchased {
                template_id,
                product_price,
            } => {
                if let Some(price) = product_price {
                    write!(
                        f,
                        "This verified pro stack requires purchase (${:.2}). Please purchase from marketplace.",
                        price
                    )
                } else {
                    write!(
                        f,
                        "You must purchase this template to deploy it. Template ID: {}",
                        template_id
                    )
                }
            }
            Self::TemplateNotFound { template_id } => {
                write!(f, "Template {} not found in marketplace", template_id)
            }
            Self::ValidationFailed { reason } => {
                write!(f, "Failed to validate deployment: {}", reason)
            }
        }
    }
}

/// Validator for marketplace template deployments
pub struct DeploymentValidator {
    user_service_connector: Arc<dyn UserServiceConnector>,
}

impl DeploymentValidator {
    /// Create new deployment validator
    pub fn new(user_service_connector: Arc<dyn UserServiceConnector>) -> Self {
        Self {
            user_service_connector,
        }
    }

    /// Validate that user can deploy a marketplace template
    ///
    /// Checks:
    /// 1. If template requires a plan tier, verify user has it
    /// 2. If template is a paid marketplace product, verify user owns it
    ///
    /// # Arguments
    /// * `template` - The stack template being deployed
    /// * `user_token` - User's OAuth token for User Service queries
    ///
    /// # Returns
    /// Ok(()) if validation passes, Err(DeploymentValidationError) otherwise
    pub async fn validate_template_deployment(
        &self,
        template: &models::marketplace::StackTemplate,
        user_token: &str,
    ) -> Result<(), DeploymentValidationError> {
        let span = tracing::info_span!(
            "validate_template_deployment",
            template_id = %template.id
        );

        // Check plan requirement first (if specified)
        if let Some(required_plan) = &template.required_plan_name {
            self.validate_plan_access(user_token, required_plan)
                .instrument(span.clone())
                .await?;
        }

        // Check marketplace template purchase (if it's a marketplace template with a product)
        if template.product_id.is_some() {
            self.validate_template_ownership(user_token, &template.id.to_string())
                .instrument(span)
                .await?;
        }

        tracing::info!("Template deployment validation successful");
        Ok(())
    }

    /// Validate user has required plan tier
    async fn validate_plan_access(
        &self,
        user_token: &str,
        required_plan: &str,
    ) -> Result<(), DeploymentValidationError> {
        let span = tracing::info_span!("validate_plan_access", required_plan = required_plan);

        // Extract user ID from token (or use token directly for User Service query)
        // For now, we'll rely on User Service to validate the token
        let has_plan = self
            .user_service_connector
            .user_has_plan(user_token, required_plan, Some(user_token))
            .instrument(span.clone())
            .await
            .map_err(|e| DeploymentValidationError::ValidationFailed {
                reason: format!("Failed to check plan access: {}", e),
            })?;

        if !has_plan {
            // Get user's actual plan for error message
            let user_plan = self
                .user_service_connector
                .get_user_plan(user_token)
                .instrument(span)
                .await
                .map(|info| info.plan_name)
                .unwrap_or_else(|_| "unknown".to_string());

            return Err(DeploymentValidationError::InsufficientPlan {
                required_plan: required_plan.to_string(),
                user_plan,
            });
        }

        Ok(())
    }

    /// Validate user owns a marketplace template product
    async fn validate_template_ownership(
        &self,
        user_token: &str,
        stack_template_id: &str,
    ) -> Result<(), DeploymentValidationError> {
        let span = tracing::info_span!(
            "validate_template_ownership",
            template_id = stack_template_id
        );

        // First check if template even has a product
        // Note: We need template ID as i32 for User Service query
        // For now, we'll just check ownership directly
        let owns_template = self
            .user_service_connector
            .user_owns_template(user_token, stack_template_id)
            .instrument(span.clone())
            .await
            .map_err(|e| DeploymentValidationError::ValidationFailed {
                reason: format!("Failed to check template ownership: {}", e),
            })?;

        if !owns_template {
            // If user doesn't own, they may need to purchase
            // In a real scenario, we'd fetch price from User Service
            return Err(DeploymentValidationError::TemplateNotPurchased {
                template_id: stack_template_id.to_string(),
                product_price: None,
            });
        }

        tracing::info!("User owns template, allowing deployment");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn test_validation_error_display() {
        let err = DeploymentValidationError::InsufficientPlan {
            required_plan: "professional".to_string(),
            user_plan: "basic".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("professional"));
        assert!(msg.contains("basic"));
    }

    #[test]
    fn test_template_not_purchased_error() {
        let err = DeploymentValidationError::TemplateNotPurchased {
            template_id: "template-123".to_string(),
            product_price: Some(99.99),
        };
        let msg = err.to_string();
        assert!(msg.contains("99.99"));
        assert!(msg.contains("purchase"));
    }

    #[test]
    fn test_template_not_purchased_error_no_price() {
        let err = DeploymentValidationError::TemplateNotPurchased {
            template_id: "template-456".to_string(),
            product_price: None,
        };
        let msg = err.to_string();
        assert!(msg.contains("template-456"));
        assert!(msg.contains("purchase"));
    }

    #[test]
    fn test_template_not_found_error() {
        let err = DeploymentValidationError::TemplateNotFound {
            template_id: "missing-template".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("missing-template"));
        assert!(msg.contains("marketplace"));
    }

    #[test]
    fn test_validation_failed_error() {
        let err = DeploymentValidationError::ValidationFailed {
            reason: "User Service unavailable".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("unavailable"));
    }

    /// Test deployment validator creation
    #[test]
    fn test_deployment_validator_creation() {
        let connector = Arc::new(super::super::mock::MockUserServiceConnector);
        let _validator = DeploymentValidator::new(connector);
        // Validator created successfully - no need for additional assertions
    }

    /// Test that InsufficientPlan error message includes both plans
    #[test]
    fn test_error_message_includes_both_plans() {
        let error = DeploymentValidationError::InsufficientPlan {
            required_plan: "enterprise".to_string(),
            user_plan: "basic".to_string(),
        };
        let message = error.to_string();
        assert!(message.contains("enterprise"));
        assert!(message.contains("basic"));
        assert!(message.contains("subscription"));
    }

    /// Test that TemplateNotPurchased error shows price
    #[test]
    fn test_template_not_purchased_shows_price() {
        let error = DeploymentValidationError::TemplateNotPurchased {
            template_id: "ai-stack".to_string(),
            product_price: Some(49.99),
        };
        let message = error.to_string();
        assert!(message.contains("49.99"));
        assert!(message.contains("pro stack"));
    }

    /// Test Debug trait for errors
    #[test]
    fn test_error_debug_display() {
        let err = DeploymentValidationError::TemplateNotFound {
            template_id: "template-123".to_string(),
        };
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("TemplateNotFound"));
    }

    /// Test Clone trait for errors
    #[test]
    fn test_error_clone() {
        let err1 = DeploymentValidationError::InsufficientPlan {
            required_plan: "professional".to_string(),
            user_plan: "basic".to_string(),
        };
        let err2 = err1.clone();
        assert_eq!(err1.to_string(), err2.to_string());
    }

    /// Test that error messages are user-friendly and actionable
    #[test]
    fn test_error_messages_are_user_friendly() {
        // InsufficientPlan should guide users to upgrade
        let plan_err = DeploymentValidationError::InsufficientPlan {
            required_plan: "professional".to_string(),
            user_plan: "basic".to_string(),
        };
        assert!(plan_err.to_string().contains("subscription"));
        assert!(plan_err.to_string().contains("professional"));

        // TemplateNotPurchased should direct to marketplace
        let purchase_err = DeploymentValidationError::TemplateNotPurchased {
            template_id: "premium-stack".to_string(),
            product_price: Some(99.99),
        };
        assert!(purchase_err.to_string().contains("marketplace"));

        // ValidationFailed should explain the issue
        let validation_err = DeploymentValidationError::ValidationFailed {
            reason: "Cannot connect to marketplace service".to_string(),
        };
        assert!(validation_err.to_string().contains("Cannot connect"));
    }

    /// Test all error variants can be created
    #[test]
    fn test_all_error_variants_creation() {
        let _insufficient_plan = DeploymentValidationError::InsufficientPlan {
            required_plan: "pro".to_string(),
            user_plan: "basic".to_string(),
        };

        let _not_purchased = DeploymentValidationError::TemplateNotPurchased {
            template_id: "id".to_string(),
            product_price: Some(50.0),
        };

        let _not_found = DeploymentValidationError::TemplateNotFound {
            template_id: "id".to_string(),
        };

        let _failed = DeploymentValidationError::ValidationFailed {
            reason: "test".to_string(),
        };

        // If we get here, all variants can be constructed
    }
}
