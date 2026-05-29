/// Marketplace webhook sender for User Service integration
///
/// Sends webhooks to User Service when marketplace templates change status.
/// This implements Flow 3 from PAYMENT_MODEL.md: Creator publishes template → Product created in User Service
///
/// **Architecture**: One-way webhooks from Stacker to User Service.
/// - No bi-directional queries on approval
/// - Bearer token authentication using STACKER_SERVICE_TOKEN
/// - Template approval does not block if webhook send fails (async/retry pattern)
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::Instrument;

use crate::connectors::ConnectorError;
use crate::models;

/// Marketplace webhook payload sent to User Service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketplaceWebhookPayload {
    /// Action type for the marketplace sync webhook.
    pub action: String,

    /// Stacker template UUID (as string)
    pub stack_template_id: String,

    /// External ID for User Service product (UUID as string or i32, same as stack_template_id)
    pub external_id: String,

    /// Product code (slug-based identifier)
    pub code: Option<String>,

    /// Template name
    pub name: Option<String>,

    /// Template description
    pub description: Option<String>,

    /// Price in specified currency (set by creator during submission)
    pub price: Option<f64>,

    /// Billing cycle: "free", "one_time", or "subscription"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub billing_cycle: Option<String>,

    /// Currency code (USD, EUR, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,

    /// Creator/vendor user ID from Stacker
    pub vendor_user_id: Option<String>,

    /// Vendor display name (creator_name from template)
    pub vendor_name: Option<String>,

    /// Category of template
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,

    /// Tags/keywords
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<serde_json::Value>,

    /// Full description (long_description from template)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub long_description: Option<String>,

    /// Tech stack metadata (JSON object of services/apps)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tech_stack: Option<serde_json::Value>,

    /// Infrastructure compatibility metadata for deployment validation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub infrastructure_requirements: Option<serde_json::Value>,

    /// Creator display name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub creator_name: Option<String>,

    /// Total deployments count
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deploy_count: Option<i32>,

    /// Total views count
    #[serde(skip_serializing_if = "Option::is_none")]
    pub view_count: Option<i32>,

    /// When the template was approved
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approved_at: Option<String>,

    /// Minimum plan required to deploy
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_plan_name: Option<String>,

    /// Reviewer feedback for update-required notifications.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub review_reason: Option<String>,

    /// Suggested next step for the creator.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_action_hint: Option<String>,

    /// Creator email when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor_email: Option<String>,
}

/// Response from User Service webhook endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookResponse {
    pub success: bool,
    pub message: Option<String>,
    pub product_id: Option<String>,
}

/// Configuration for webhook sender
#[derive(Debug, Clone)]
pub struct WebhookSenderConfig {
    /// User Service base URL (e.g., "http://user:4100")
    pub base_url: String,

    /// Bearer token for service-to-service authentication
    pub bearer_token: String,

    /// HTTP client timeout in seconds
    pub timeout_secs: u64,

    /// Number of retry attempts on failure
    pub retry_attempts: usize,
}

impl WebhookSenderConfig {
    /// Create from environment variables
    pub fn from_env() -> Result<Self, String> {
        let base_url = std::env::var("URL_SERVER_USER")
            .or_else(|_| std::env::var("USER_SERVICE_URL"))
            .or_else(|_| std::env::var("USER_SERVICE_BASE_URL"))
            .map_err(|_| "USER_SERVICE_URL not configured".to_string())?;

        let bearer_token = std::env::var("STACKER_SERVICE_TOKEN")
            .map_err(|_| "STACKER_SERVICE_TOKEN not configured".to_string())?;

        Ok(Self {
            base_url,
            bearer_token,
            timeout_secs: 10,
            retry_attempts: 3,
        })
    }
}

/// Sends webhooks to User Service when marketplace templates change
pub struct MarketplaceWebhookSender {
    config: WebhookSenderConfig,
    http_client: reqwest::Client,
    // Track webhook deliveries in-memory (simple approach)
    #[allow(dead_code)]
    pending_webhooks: Arc<Mutex<Vec<String>>>,
}

impl MarketplaceWebhookSender {
    /// Create new webhook sender with configuration
    pub fn new(config: WebhookSenderConfig) -> Self {
        let timeout = std::time::Duration::from_secs(config.timeout_secs);
        let http_client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .expect("Failed to create HTTP client");

        Self {
            config,
            http_client,
            pending_webhooks: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Create from environment variables
    pub fn from_env() -> Result<Self, String> {
        let config = WebhookSenderConfig::from_env()?;
        Ok(Self::new(config))
    }

    /// Send template approved webhook to User Service
    /// Creates/updates product in User Service marketplace
    pub async fn send_template_approved(
        &self,
        template: &models::marketplace::StackTemplate,
        vendor_id: &str,
        category_code: Option<String>,
    ) -> Result<WebhookResponse, ConnectorError> {
        let span = tracing::info_span!(
            "send_template_approved_webhook",
            template_id = %template.id,
            vendor_id = vendor_id
        );

        let payload = MarketplaceWebhookPayload {
            action: "template_approved".to_string(),
            stack_template_id: template.id.to_string(),
            external_id: template.id.to_string(),
            code: Some(template.slug.clone()),
            name: Some(template.name.clone()),
            description: template
                .short_description
                .clone()
                .or_else(|| template.long_description.clone()),
            price: template.price,
            billing_cycle: template.billing_cycle.clone(),
            currency: template.currency.clone(),
            vendor_user_id: Some(vendor_id.to_string()),
            vendor_name: template.creator_name.clone(),
            category: category_code,
            tags: if let serde_json::Value::Array(_) = template.tags {
                Some(template.tags.clone())
            } else {
                None
            },
            long_description: template.long_description.clone(),
            tech_stack: if template.tech_stack != serde_json::json!({}) {
                Some(template.tech_stack.clone())
            } else {
                None
            },
            infrastructure_requirements: if template.infrastructure_requirements
                != serde_json::json!({})
            {
                Some(template.infrastructure_requirements.clone())
            } else {
                None
            },
            creator_name: template.creator_name.clone(),
            deploy_count: template.deploy_count,
            view_count: template.view_count,
            approved_at: template.approved_at.map(|dt| dt.to_rfc3339()),
            required_plan_name: template.required_plan_name.clone(),
            review_reason: None,
            next_action_hint: None,
            vendor_email: None,
        };

        self.send_webhook(&payload).instrument(span).await
    }

    /// Send template published webhook to User Service.
    /// Creates/updates the product and triggers the creator approval notification.
    pub async fn send_template_published(
        &self,
        template: &models::marketplace::StackTemplate,
        vendor_id: &str,
        category_code: Option<String>,
    ) -> Result<WebhookResponse, ConnectorError> {
        let span = tracing::info_span!(
            "send_template_published_webhook",
            template_id = %template.id,
            vendor_id = vendor_id
        );

        let payload = MarketplaceWebhookPayload {
            action: "template_published".to_string(),
            stack_template_id: template.id.to_string(),
            external_id: template.id.to_string(),
            code: Some(template.slug.clone()),
            name: Some(template.name.clone()),
            description: template
                .short_description
                .clone()
                .or_else(|| template.long_description.clone()),
            price: template.price,
            billing_cycle: template.billing_cycle.clone(),
            currency: template.currency.clone(),
            vendor_user_id: Some(vendor_id.to_string()),
            vendor_name: template.creator_name.clone(),
            category: category_code,
            tags: if let serde_json::Value::Array(_) = template.tags {
                Some(template.tags.clone())
            } else {
                None
            },
            long_description: template.long_description.clone(),
            tech_stack: if template.tech_stack != serde_json::json!({}) {
                Some(template.tech_stack.clone())
            } else {
                None
            },
            infrastructure_requirements: if template.infrastructure_requirements
                != serde_json::json!({})
            {
                Some(template.infrastructure_requirements.clone())
            } else {
                None
            },
            creator_name: template.creator_name.clone(),
            deploy_count: template.deploy_count,
            view_count: template.view_count,
            approved_at: template.approved_at.map(|dt| dt.to_rfc3339()),
            required_plan_name: template.required_plan_name.clone(),
            review_reason: None,
            next_action_hint: None,
            vendor_email: None,
        };

        self.send_webhook(&payload).instrument(span).await
    }

    /// Send template updated webhook to User Service
    /// Updates product metadata/details in User Service
    pub async fn send_template_updated(
        &self,
        template: &models::marketplace::StackTemplate,
        vendor_id: &str,
        category_code: Option<String>,
    ) -> Result<WebhookResponse, ConnectorError> {
        let span = tracing::info_span!(
            "send_template_updated_webhook",
            template_id = %template.id
        );

        let payload = MarketplaceWebhookPayload {
            action: "template_updated".to_string(),
            stack_template_id: template.id.to_string(),
            external_id: template.id.to_string(),
            code: Some(template.slug.clone()),
            name: Some(template.name.clone()),
            description: template
                .short_description
                .clone()
                .or_else(|| template.long_description.clone()),
            price: template.price,
            billing_cycle: template.billing_cycle.clone(),
            currency: template.currency.clone(),
            vendor_user_id: Some(vendor_id.to_string()),
            vendor_name: template.creator_name.clone(),
            category: category_code,
            tags: if let serde_json::Value::Array(_) = template.tags {
                Some(template.tags.clone())
            } else {
                None
            },
            long_description: template.long_description.clone(),
            tech_stack: if template.tech_stack != serde_json::json!({}) {
                Some(template.tech_stack.clone())
            } else {
                None
            },
            infrastructure_requirements: if template.infrastructure_requirements
                != serde_json::json!({})
            {
                Some(template.infrastructure_requirements.clone())
            } else {
                None
            },
            creator_name: template.creator_name.clone(),
            deploy_count: template.deploy_count,
            view_count: template.view_count,
            approved_at: template.approved_at.map(|dt| dt.to_rfc3339()),
            required_plan_name: template.required_plan_name.clone(),
            review_reason: None,
            next_action_hint: None,
            vendor_email: None,
        };

        self.send_webhook(&payload).instrument(span).await
    }

    /// Send template submitted webhook to User Service.
    /// Notifies the creator that their stack entered marketplace review.
    pub async fn send_template_submitted(
        &self,
        template: &models::marketplace::StackTemplate,
        vendor_id: &str,
        category_code: Option<String>,
    ) -> Result<WebhookResponse, ConnectorError> {
        let span = tracing::info_span!(
            "send_template_submitted_webhook",
            template_id = %template.id,
            vendor_id = vendor_id
        );

        let payload = MarketplaceWebhookPayload {
            action: "template_submitted".to_string(),
            stack_template_id: template.id.to_string(),
            external_id: template.id.to_string(),
            code: Some(template.slug.clone()),
            name: Some(template.name.clone()),
            description: template
                .short_description
                .clone()
                .or_else(|| template.long_description.clone()),
            price: template.price,
            billing_cycle: template.billing_cycle.clone(),
            currency: template.currency.clone(),
            vendor_user_id: Some(vendor_id.to_string()),
            vendor_name: template.creator_name.clone(),
            category: category_code,
            tags: if let serde_json::Value::Array(_) = template.tags {
                Some(template.tags.clone())
            } else {
                None
            },
            long_description: template.long_description.clone(),
            tech_stack: if template.tech_stack != serde_json::json!({}) {
                Some(template.tech_stack.clone())
            } else {
                None
            },
            infrastructure_requirements: if template.infrastructure_requirements
                != serde_json::json!({})
            {
                Some(template.infrastructure_requirements.clone())
            } else {
                None
            },
            creator_name: template.creator_name.clone(),
            deploy_count: template.deploy_count,
            view_count: template.view_count,
            approved_at: template.approved_at.map(|dt| dt.to_rfc3339()),
            required_plan_name: template.required_plan_name.clone(),
            review_reason: None,
            next_action_hint: None,
            vendor_email: None,
        };

        self.send_webhook(&payload).instrument(span).await
    }

    /// Send template update-required webhook to User Service.
    pub async fn send_template_needs_changes(
        &self,
        template: &models::marketplace::StackTemplate,
        vendor_id: &str,
        review_reason: Option<&str>,
        next_action_hint: &str,
    ) -> Result<WebhookResponse, ConnectorError> {
        let span = tracing::info_span!(
            "send_template_needs_changes_webhook",
            template_id = %template.id,
            vendor_id = vendor_id
        );

        let payload = MarketplaceWebhookPayload {
            action: "template_needs_changes".to_string(),
            stack_template_id: template.id.to_string(),
            external_id: template.id.to_string(),
            code: Some(template.slug.clone()),
            name: Some(template.name.clone()),
            description: template
                .short_description
                .clone()
                .or_else(|| template.long_description.clone()),
            price: template.price,
            billing_cycle: template.billing_cycle.clone(),
            currency: template.currency.clone(),
            vendor_user_id: Some(vendor_id.to_string()),
            vendor_name: template.creator_name.clone(),
            category: template.category_code.clone(),
            tags: if let serde_json::Value::Array(_) = template.tags {
                Some(template.tags.clone())
            } else {
                None
            },
            long_description: template.long_description.clone(),
            tech_stack: if template.tech_stack != serde_json::json!({}) {
                Some(template.tech_stack.clone())
            } else {
                None
            },
            infrastructure_requirements: if template.infrastructure_requirements
                != serde_json::json!({})
            {
                Some(template.infrastructure_requirements.clone())
            } else {
                None
            },
            creator_name: template.creator_name.clone(),
            deploy_count: template.deploy_count,
            view_count: template.view_count,
            approved_at: template.approved_at.map(|dt| dt.to_rfc3339()),
            required_plan_name: template.required_plan_name.clone(),
            review_reason: review_reason.map(str::to_string),
            next_action_hint: Some(next_action_hint.to_string()),
            vendor_email: None,
        };

        self.send_webhook(&payload).instrument(span).await
    }

    /// Send template review-rejected webhook to User Service.
    /// This notifies the creator without invoking marketplace removal behavior.
    pub async fn send_template_review_rejected(
        &self,
        template: &models::marketplace::StackTemplate,
        vendor_id: &str,
        review_reason: Option<&str>,
    ) -> Result<WebhookResponse, ConnectorError> {
        let span = tracing::info_span!(
            "send_template_review_rejected_webhook",
            template_id = %template.id,
            vendor_id = vendor_id
        );

        let payload = MarketplaceWebhookPayload {
            action: "template_review_rejected".to_string(),
            stack_template_id: template.id.to_string(),
            external_id: template.id.to_string(),
            code: Some(template.slug.clone()),
            name: Some(template.name.clone()),
            description: template
                .short_description
                .clone()
                .or_else(|| template.long_description.clone()),
            price: template.price,
            billing_cycle: template.billing_cycle.clone(),
            currency: template.currency.clone(),
            vendor_user_id: Some(vendor_id.to_string()),
            vendor_name: template.creator_name.clone(),
            category: template.category_code.clone(),
            tags: if let serde_json::Value::Array(_) = template.tags {
                Some(template.tags.clone())
            } else {
                None
            },
            long_description: template.long_description.clone(),
            tech_stack: if template.tech_stack != serde_json::json!({}) {
                Some(template.tech_stack.clone())
            } else {
                None
            },
            infrastructure_requirements: if template.infrastructure_requirements
                != serde_json::json!({})
            {
                Some(template.infrastructure_requirements.clone())
            } else {
                None
            },
            creator_name: template.creator_name.clone(),
            deploy_count: template.deploy_count,
            view_count: template.view_count,
            approved_at: template.approved_at.map(|dt| dt.to_rfc3339()),
            required_plan_name: template.required_plan_name.clone(),
            review_reason: review_reason.map(str::to_string),
            next_action_hint: Some(
                "Review the feedback, update the stack, and submit a new revision when it is ready."
                    .to_string(),
            ),
            vendor_email: None,
        };

        self.send_webhook(&payload).instrument(span).await
    }

    /// Send template rejected webhook to User Service
    /// Deactivates product in User Service
    pub async fn send_template_rejected(
        &self,
        stack_template_id: &str,
    ) -> Result<WebhookResponse, ConnectorError> {
        let span = tracing::info_span!(
            "send_template_rejected_webhook",
            template_id = stack_template_id
        );

        let payload = MarketplaceWebhookPayload {
            action: "template_rejected".to_string(),
            stack_template_id: stack_template_id.to_string(),
            external_id: stack_template_id.to_string(),
            code: None,
            name: None,
            description: None,
            price: None,
            billing_cycle: None,
            currency: None,
            vendor_user_id: None,
            vendor_name: None,
            category: None,
            tags: None,
            long_description: None,
            tech_stack: None,
            infrastructure_requirements: None,
            creator_name: None,
            deploy_count: None,
            view_count: None,
            approved_at: None,
            required_plan_name: None,
            review_reason: None,
            next_action_hint: None,
            vendor_email: None,
        };

        self.send_webhook(&payload).instrument(span).await
    }

    /// Send template unpublished webhook to User Service.
    /// This deactivates the marketplace listing but preserves the subscription record.
    pub async fn send_template_unpublished(
        &self,
        template: &models::marketplace::StackTemplate,
        vendor_id: &str,
    ) -> Result<WebhookResponse, ConnectorError> {
        let span = tracing::info_span!(
            "send_template_unpublished_webhook",
            template_id = %template.id,
            vendor_id = vendor_id
        );

        let payload = MarketplaceWebhookPayload {
            action: "template_unpublished".to_string(),
            stack_template_id: template.id.to_string(),
            external_id: template.id.to_string(),
            code: Some(template.slug.clone()),
            name: Some(template.name.clone()),
            description: template
                .short_description
                .clone()
                .or_else(|| template.long_description.clone()),
            price: template.price,
            billing_cycle: template.billing_cycle.clone(),
            currency: template.currency.clone(),
            vendor_user_id: Some(vendor_id.to_string()),
            vendor_name: template.creator_name.clone(),
            category: template.category_code.clone(),
            tags: if let serde_json::Value::Array(_) = template.tags {
                Some(template.tags.clone())
            } else {
                None
            },
            long_description: template.long_description.clone(),
            tech_stack: if template.tech_stack != serde_json::json!({}) {
                Some(template.tech_stack.clone())
            } else {
                None
            },
            infrastructure_requirements: if template.infrastructure_requirements
                != serde_json::json!({})
            {
                Some(template.infrastructure_requirements.clone())
            } else {
                None
            },
            creator_name: template.creator_name.clone(),
            deploy_count: template.deploy_count,
            view_count: template.view_count,
            approved_at: template.approved_at.map(|dt| dt.to_rfc3339()),
            required_plan_name: template.required_plan_name.clone(),
            review_reason: None,
            next_action_hint: None,
            vendor_email: None,
        };

        self.send_webhook(&payload).instrument(span).await
    }

    /// Internal method to send webhook with retries
    async fn send_webhook(
        &self,
        payload: &MarketplaceWebhookPayload,
    ) -> Result<WebhookResponse, ConnectorError> {
        let url = format!("{}/marketplace/sync", self.config.base_url);

        let mut attempt = 0;
        loop {
            attempt += 1;

            let req = self
                .http_client
                .post(&url)
                .json(payload)
                .header(
                    "Authorization",
                    format!("Bearer {}", self.config.bearer_token),
                )
                .header("Content-Type", "application/json");

            match req.send().await {
                Ok(resp) => match resp.status().as_u16() {
                    200 | 201 => {
                        let text = resp
                            .text()
                            .await
                            .map_err(|e| ConnectorError::HttpError(e.to_string()))?;
                        return serde_json::from_str::<WebhookResponse>(&text)
                            .map_err(|_| ConnectorError::InvalidResponse(text));
                    }
                    401 => {
                        return Err(ConnectorError::Unauthorized(
                            "Invalid service token for User Service webhook".to_string(),
                        ));
                    }
                    404 => {
                        return Err(ConnectorError::NotFound(
                            "/marketplace/sync endpoint not found".to_string(),
                        ));
                    }
                    500..=599 => {
                        // Retry on server errors
                        if attempt < self.config.retry_attempts {
                            let backoff = std::time::Duration::from_millis(
                                100 * 2_u64.pow((attempt - 1) as u32),
                            );
                            tracing::warn!(
                                "User Service webhook failed with {}, retrying after {:?}",
                                resp.status(),
                                backoff
                            );
                            tokio::time::sleep(backoff).await;
                            continue;
                        }
                        return Err(ConnectorError::ServiceUnavailable(format!(
                            "User Service returned {}: webhook send failed",
                            resp.status()
                        )));
                    }
                    status => {
                        return Err(ConnectorError::HttpError(format!(
                            "Unexpected status code: {}",
                            status
                        )));
                    }
                },
                Err(e) if e.is_timeout() => {
                    if attempt < self.config.retry_attempts {
                        let backoff =
                            std::time::Duration::from_millis(100 * 2_u64.pow((attempt - 1) as u32));
                        tracing::warn!(
                            "User Service webhook timeout, retrying after {:?}",
                            backoff
                        );
                        tokio::time::sleep(backoff).await;
                        continue;
                    }
                    return Err(ConnectorError::ServiceUnavailable(
                        "Webhook send timeout".to_string(),
                    ));
                }
                Err(e) => {
                    return Err(ConnectorError::HttpError(format!(
                        "Webhook send failed: {}",
                        e
                    )));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webhook_payload_serialization() {
        let payload = MarketplaceWebhookPayload {
            action: "template_approved".to_string(),
            stack_template_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            external_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            code: Some("ai-agent-stack-pro".to_string()),
            name: Some("AI Agent Stack Pro".to_string()),
            description: Some("Advanced AI agent template".to_string()),
            price: Some(99.99),
            billing_cycle: Some("one_time".to_string()),
            currency: Some("USD".to_string()),
            vendor_user_id: Some("user-456".to_string()),
            vendor_name: Some("alice@example.com".to_string()),
            category: Some("AI Agents".to_string()),
            tags: Some(serde_json::json!(["ai", "agents"])),
            long_description: None,
            tech_stack: None,
            creator_name: None,
            deploy_count: None,
            view_count: None,
            approved_at: None,
            required_plan_name: None,
            review_reason: None,
            next_action_hint: None,
            vendor_email: None,
            infrastructure_requirements: None,
        };

        let json = serde_json::to_string(&payload).expect("Failed to serialize");
        assert!(json.contains("template_approved"));
        assert!(json.contains("ai-agent-stack-pro"));

        // Verify all fields are present
        assert!(json.contains("550e8400-e29b-41d4-a716-446655440000"));
        assert!(json.contains("AI Agent Stack Pro"));
        assert!(json.contains("99.99"));
    }

    #[test]
    fn test_webhook_payload_with_rejection() {
        let payload = MarketplaceWebhookPayload {
            action: "template_rejected".to_string(),
            stack_template_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            external_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            code: None,
            name: None,
            description: None,
            price: None,
            billing_cycle: None,
            currency: None,
            vendor_user_id: None,
            vendor_name: None,
            category: None,
            tags: None,
            long_description: None,
            tech_stack: None,
            creator_name: None,
            deploy_count: None,
            view_count: None,
            approved_at: None,
            required_plan_name: None,
            review_reason: None,
            next_action_hint: None,
            vendor_email: None,
            infrastructure_requirements: None,
        };

        let json = serde_json::to_string(&payload).expect("Failed to serialize");
        assert!(json.contains("template_rejected"));
        assert!(!json.contains("ai-agent"));
    }

    /// Test webhook payload for approved template action
    #[test]
    fn test_webhook_payload_template_approved() {
        let payload = MarketplaceWebhookPayload {
            action: "template_approved".to_string(),
            stack_template_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            external_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            code: Some("cms-starter".to_string()),
            name: Some("CMS Starter Template".to_string()),
            description: Some("Complete CMS setup".to_string()),
            price: Some(49.99),
            billing_cycle: Some("one_time".to_string()),
            currency: Some("USD".to_string()),
            vendor_user_id: Some("vendor-123".to_string()),
            vendor_name: Some("vendor@example.com".to_string()),
            category: Some("CMS".to_string()),
            tags: Some(serde_json::json!(["cms", "wordpress"])),
            long_description: None,
            tech_stack: None,
            creator_name: None,
            deploy_count: None,
            view_count: None,
            approved_at: None,
            required_plan_name: None,
            review_reason: None,
            next_action_hint: None,
            vendor_email: None,
            infrastructure_requirements: None,
        };

        assert_eq!(payload.action, "template_approved");
        assert_eq!(payload.code, Some("cms-starter".to_string()));
        assert_eq!(payload.price, Some(49.99));
    }

    /// Test webhook payload for updated template action
    #[test]
    fn test_webhook_payload_template_updated() {
        let payload = MarketplaceWebhookPayload {
            action: "template_updated".to_string(),
            stack_template_id: "550e8400-e29b-41d4-a716-446655440001".to_string(),
            external_id: "550e8400-e29b-41d4-a716-446655440001".to_string(),
            code: Some("cms-starter".to_string()),
            name: Some("CMS Starter Template v2".to_string()),
            description: Some("Updated CMS setup with new features".to_string()),
            price: Some(59.99), // Price updated
            billing_cycle: Some("one_time".to_string()),
            currency: Some("USD".to_string()),
            vendor_user_id: Some("vendor-123".to_string()),
            vendor_name: Some("vendor@example.com".to_string()),
            category: Some("CMS".to_string()),
            tags: Some(serde_json::json!(["cms", "wordpress", "v2"])),
            long_description: None,
            tech_stack: None,
            creator_name: None,
            deploy_count: None,
            view_count: None,
            approved_at: None,
            required_plan_name: None,
            review_reason: None,
            next_action_hint: None,
            vendor_email: None,
            infrastructure_requirements: None,
        };

        assert_eq!(payload.action, "template_updated");
        assert_eq!(payload.name, Some("CMS Starter Template v2".to_string()));
        assert_eq!(payload.price, Some(59.99));
    }

    /// Test webhook payload for free template
    #[test]
    fn test_webhook_payload_free_template() {
        let payload = MarketplaceWebhookPayload {
            action: "template_approved".to_string(),
            stack_template_id: "550e8400-e29b-41d4-a716-446655440002".to_string(),
            external_id: "550e8400-e29b-41d4-a716-446655440002".to_string(),
            code: Some("basic-blog".to_string()),
            name: Some("Basic Blog Template".to_string()),
            description: Some("Free blog template".to_string()),
            price: None, // Free template
            billing_cycle: None,
            currency: None,
            vendor_user_id: None,
            vendor_name: None,
            category: Some("CMS".to_string()),
            tags: Some(serde_json::json!(["blog", "free"])),
            long_description: None,
            tech_stack: None,
            creator_name: None,
            deploy_count: None,
            view_count: None,
            approved_at: None,
            required_plan_name: None,
            review_reason: None,
            next_action_hint: None,
            vendor_email: None,
            infrastructure_requirements: None,
        };

        assert_eq!(payload.action, "template_approved");
        assert_eq!(payload.price, None);
        assert_eq!(payload.billing_cycle, None);
    }

    /// Test webhook sender config from environment
    #[test]
    fn test_webhook_sender_config_creation() {
        let config = WebhookSenderConfig {
            base_url: "http://user:4100".to_string(),
            bearer_token: "test-token-123".to_string(),
            timeout_secs: 10,
            retry_attempts: 3,
        };

        assert_eq!(config.base_url, "http://user:4100");
        assert_eq!(config.bearer_token, "test-token-123");
        assert_eq!(config.timeout_secs, 10);
        assert_eq!(config.retry_attempts, 3);
    }

    /// Test that MarketplaceWebhookSender creates successfully
    #[test]
    fn test_webhook_sender_creation() {
        let config = WebhookSenderConfig {
            base_url: "http://user:4100".to_string(),
            bearer_token: "test-token".to_string(),
            timeout_secs: 10,
            retry_attempts: 3,
        };

        let sender = MarketplaceWebhookSender::new(config);
        // Just verify sender was created without panicking
        assert!(sender.pending_webhooks.blocking_lock().is_empty());
    }

    /// Test webhook response deserialization
    #[test]
    fn test_webhook_response_deserialization() {
        let json = serde_json::json!({
            "success": true,
            "message": "Product created successfully",
            "product_id": "product-123"
        });

        let response: WebhookResponse = serde_json::from_value(json).unwrap();
        assert!(response.success);
        assert_eq!(
            response.message,
            Some("Product created successfully".to_string())
        );
        assert_eq!(response.product_id, Some("product-123".to_string()));
    }

    /// Test webhook response with failure
    #[test]
    fn test_webhook_response_failure() {
        let json = serde_json::json!({
            "success": false,
            "message": "Template not found",
            "product_id": null
        });

        let response: WebhookResponse = serde_json::from_value(json).unwrap();
        assert!(!response.success);
        assert_eq!(response.message, Some("Template not found".to_string()));
        assert_eq!(response.product_id, None);
    }

    /// Test payload with all optional fields populated
    #[test]
    fn test_webhook_payload_all_fields_populated() {
        let payload = MarketplaceWebhookPayload {
            action: "template_approved".to_string(),
            stack_template_id: "template-uuid".to_string(),
            external_id: "external-id".to_string(),
            code: Some("complex-template".to_string()),
            name: Some("Complex Template".to_string()),
            description: Some("A complex template with many features".to_string()),
            price: Some(199.99),
            billing_cycle: Some("monthly".to_string()),
            currency: Some("EUR".to_string()),
            vendor_user_id: Some("vendor-id".to_string()),
            vendor_name: Some("John Doe".to_string()),
            category: Some("Enterprise".to_string()),
            tags: Some(serde_json::json!(["enterprise", "complex", "saas"])),
            long_description: Some("Full enterprise description".to_string()),
            tech_stack: Some(serde_json::json!({"nginx": "1.25", "postgres": "16"})),
            creator_name: Some("John Doe".to_string()),
            deploy_count: Some(42),
            view_count: Some(1337),
            approved_at: Some("2026-02-11T10:00:00Z".to_string()),
            required_plan_name: Some("starter".to_string()),
            review_reason: None,
            next_action_hint: None,
            vendor_email: None,
            infrastructure_requirements: None,
        };

        // Verify all fields are accessible
        assert_eq!(payload.action, "template_approved");
        assert_eq!(payload.billing_cycle, Some("monthly".to_string()));
        assert_eq!(payload.currency, Some("EUR".to_string()));
        assert_eq!(payload.price, Some(199.99));
    }

    /// Test payload minimal fields (only required ones)
    #[test]
    fn test_webhook_payload_minimal_fields() {
        let payload = MarketplaceWebhookPayload {
            action: "template_rejected".to_string(),
            stack_template_id: "template-uuid".to_string(),
            external_id: "external-id".to_string(),
            code: None,
            name: None,
            description: None,
            price: None,
            billing_cycle: None,
            currency: None,
            vendor_user_id: None,
            vendor_name: None,
            category: None,
            tags: None,
            long_description: None,
            tech_stack: None,
            creator_name: None,
            deploy_count: None,
            view_count: None,
            approved_at: None,
            required_plan_name: None,
            review_reason: None,
            next_action_hint: None,
            vendor_email: None,
            infrastructure_requirements: None,
        };

        // Should serialize without errors even with all optional fields as None
        let json = serde_json::to_string(&payload).expect("Should serialize");
        assert!(json.contains("template_rejected"));
        assert!(json.contains("external_id"));
    }
}
