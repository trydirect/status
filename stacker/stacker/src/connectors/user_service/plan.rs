use serde::{Deserialize, Serialize};

use crate::connectors::errors::ConnectorError;

use super::UserServiceClient;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionPlan {
    /// Plan name (e.g., "Free", "Basic", "Plus")
    pub name: Option<String>,

    /// Plan code (e.g., "plan-free-periodically", "plan-basic-monthly")
    pub code: Option<String>,

    /// Plan features and limits. User Service may return strings or structured objects.
    pub includes: Option<serde_json::Value>,

    /// Expiration date (null for active subscriptions)
    pub date_end: Option<String>,

    /// Whether the plan is active (date_end is null)
    pub active: Option<bool>,

    /// Price of the plan
    pub price: Option<String>,

    /// Currency (e.g., "USD")
    pub currency: Option<String>,

    /// Billing period ("month" or "year")
    pub period: Option<String>,

    /// Date of purchase
    pub date_of_purchase: Option<String>,

    /// Billing agreement ID
    pub billing_id: Option<String>,
}

impl UserServiceClient {
    /// Get user's subscription plan and limits
    pub async fn get_subscription_plan(
        &self,
        bearer_token: &str,
    ) -> Result<SubscriptionPlan, ConnectorError> {
        // Use the /oauth_server/api/me endpoint which returns user profile including plan info
        let url = format!("{}/oauth_server/api/me", self.base_url);

        let response = self
            .http_client
            .get(&url)
            .header("Authorization", format!("Bearer {}", bearer_token))
            .send()
            .await
            .map_err(ConnectorError::from)?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let body = response.text().await.unwrap_or_default();
            return Err(ConnectorError::HttpError(format!(
                "User Service error ({}): {}",
                status, body
            )));
        }

        // The response includes the user profile with "plan" field
        let user_profile: serde_json::Value = response
            .json()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(e.to_string()))?;

        let plan_value = [
            user_profile.get("plan"),
            user_profile.pointer("/item/plan"),
            user_profile.pointer("/user/plan"),
            user_profile.pointer("/profile/plan"),
            user_profile.pointer("/data/plan"),
            user_profile.pointer("/result/plan"),
            user_profile.pointer("/_items/0/plan"),
        ]
        .into_iter()
        .flatten()
        .find(|value| !value.is_null())
        .ok_or_else(|| {
            ConnectorError::InvalidResponse("No plan field in user profile".to_string())
        })?;

        serde_json::from_value(plan_value.clone())
            .map_err(|e| ConnectorError::InvalidResponse(format!("Failed to parse plan: {}", e)))
    }
}
