use crate::connectors::config::UserServiceConfig;
use crate::connectors::errors::ConnectorError;

use serde::{Deserialize, Serialize};
use tracing::Instrument;
use uuid::Uuid;

use super::connector::UserServiceConnector;
use super::types::{
    CategoryInfo, PlanDefinition, ProductInfo, StackResponse, UserPlanInfo, UserProfile,
};
use super::utils::is_plan_higher_tier;

/// HTTP-based User Service client
pub struct UserServiceClient {
    pub(crate) base_url: String,
    pub(crate) http_client: reqwest::Client,
    pub(crate) auth_token: Option<String>,
    pub(crate) retry_attempts: usize,
}

impl UserServiceClient {
    /// Create new User Service client
    pub fn new(config: UserServiceConfig) -> Self {
        let timeout = std::time::Duration::from_secs(config.timeout_secs);
        let http_client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .expect("Failed to create HTTP client");

        Self {
            base_url: config.base_url,
            http_client,
            auth_token: config.auth_token,
            retry_attempts: config.retry_attempts,
        }
    }

    /// Create a client from a base URL with default config (used by MCP tools)
    pub fn new_public(base_url: &str) -> Self {
        let mut config = UserServiceConfig::default();
        config.base_url = base_url.trim_end_matches('/').to_string();
        config.auth_token = None;
        Self::new(config)
    }

    /// Build authorization header if token configured
    pub(crate) fn auth_header(&self) -> Option<String> {
        self.auth_token
            .as_ref()
            .map(|token| format!("Bearer {}", token))
    }

    /// Retry helper with exponential backoff
    #[allow(dead_code)]
    pub(crate) async fn retry_request<F, T>(&self, mut f: F) -> Result<T, ConnectorError>
    where
        F: FnMut() -> futures::future::BoxFuture<'static, Result<T, ConnectorError>>,
    {
        let mut attempt = 0;
        loop {
            match f().await {
                Ok(result) => return Ok(result),
                Err(err) => {
                    attempt += 1;
                    if attempt >= self.retry_attempts {
                        return Err(err);
                    }
                    // Exponential backoff: 100ms, 200ms, 400ms, etc.
                    let backoff = std::time::Duration::from_millis(100 * 2_u64.pow(attempt as u32));
                    tokio::time::sleep(backoff).await;
                }
            }
        }
    }
}

#[async_trait::async_trait]
impl UserServiceConnector for UserServiceClient {
    async fn create_stack_from_template(
        &self,
        marketplace_template_id: &Uuid,
        user_id: &str,
        template_version: &str,
        name: &str,
        stack_definition: serde_json::Value,
    ) -> Result<StackResponse, ConnectorError> {
        let span = tracing::info_span!(
            "user_service_create_stack",
            template_id = %marketplace_template_id,
            user_id = %user_id
        );

        let url = format!("{}/api/1.0/stacks", self.base_url);
        let payload = serde_json::json!({
            "name": name,
            "marketplace_template_id": marketplace_template_id.to_string(),
            "is_from_marketplace": true,
            "template_version": template_version,
            "stack_definition": stack_definition,
            "user_id": user_id,
        });

        let mut req = self.http_client.post(&url).json(&payload);

        if let Some(auth) = self.auth_header() {
            req = req.header("Authorization", auth);
        }

        let resp = req
            .send()
            .instrument(span)
            .await
            .and_then(|resp| resp.error_for_status())
            .map_err(|e| {
                tracing::error!("create_stack error: {:?}", e);
                ConnectorError::HttpError(format!("Failed to create stack: {}", e))
            })?;

        let text = resp
            .text()
            .await
            .map_err(|e| ConnectorError::HttpError(e.to_string()))?;
        serde_json::from_str::<StackResponse>(&text)
            .map_err(|_| ConnectorError::InvalidResponse(text))
    }

    async fn get_stack(
        &self,
        stack_id: i32,
        user_id: &str,
    ) -> Result<StackResponse, ConnectorError> {
        let span =
            tracing::info_span!("user_service_get_stack", stack_id = stack_id, user_id = %user_id);

        let url = format!("{}/api/1.0/stacks/{}", self.base_url, stack_id);
        let mut req = self.http_client.get(&url);

        if let Some(auth) = self.auth_header() {
            req = req.header("Authorization", auth);
        }

        let resp = req.send().instrument(span).await.map_err(|e| {
            if e.status().map_or(false, |s| s == 404) {
                ConnectorError::NotFound(format!("Stack {} not found", stack_id))
            } else {
                ConnectorError::HttpError(format!("Failed to get stack: {}", e))
            }
        })?;

        if resp.status() == 404 {
            return Err(ConnectorError::NotFound(format!(
                "Stack {} not found",
                stack_id
            )));
        }

        let text = resp
            .text()
            .await
            .map_err(|e| ConnectorError::HttpError(e.to_string()))?;
        serde_json::from_str::<StackResponse>(&text)
            .map_err(|_| ConnectorError::InvalidResponse(text))
    }

    async fn list_stacks(&self, user_id: &str) -> Result<Vec<StackResponse>, ConnectorError> {
        let span = tracing::info_span!("user_service_list_stacks", user_id = %user_id);

        let url = format!("{}/api/1.0/stacks", self.base_url);
        let mut req = self.http_client.post(&url);

        if let Some(auth) = self.auth_header() {
            req = req.header("Authorization", auth);
        }

        #[derive(Serialize)]
        struct WhereFilter<'a> {
            user_id: &'a str,
        }

        #[derive(Serialize)]
        struct ListRequest<'a> {
            r#where: WhereFilter<'a>,
        }

        let body = ListRequest {
            r#where: WhereFilter { user_id },
        };

        #[derive(Deserialize)]
        struct ListResponse {
            _items: Vec<StackResponse>,
        }

        let resp = req
            .json(&body)
            .send()
            .instrument(span)
            .await
            .and_then(|resp| resp.error_for_status())
            .map_err(|e| {
                tracing::error!("list_stacks error: {:?}", e);
                ConnectorError::HttpError(format!("Failed to list stacks: {}", e))
            })?;

        let text = resp
            .text()
            .await
            .map_err(|e| ConnectorError::HttpError(e.to_string()))?;
        serde_json::from_str::<ListResponse>(&text)
            .map(|r| r._items)
            .map_err(|_| ConnectorError::InvalidResponse(text))
    }

    async fn user_has_plan(
        &self,
        user_id: &str,
        required_plan_name: &str,
        user_token: Option<&str>,
    ) -> Result<bool, ConnectorError> {
        // "free" plan never requires a subscription check
        if required_plan_name.to_lowercase() == "free" {
            return Ok(true);
        }

        let span = tracing::info_span!(
            "user_service_check_plan",
            user_id = %user_id,
            required_plan = %required_plan_name
        );

        // Get user's current plan via /oauth_server/api/me endpoint
        let url = format!("{}/oauth_server/api/me", self.base_url);
        let mut req = self.http_client.get(&url);

        // Prefer the user's own token; fall back to service account
        let auth = user_token
            .map(|t| format!("Bearer {}", t))
            .or_else(|| self.auth_header());
        if let Some(auth) = auth {
            req = req.header("Authorization", auth);
        }

        #[derive(serde::Deserialize)]
        struct UserMeResponse {
            #[serde(default)]
            plan: Option<PlanInfo>,
        }

        #[derive(serde::Deserialize)]
        struct PlanInfo {
            name: Option<String>,
        }

        let resp = req.send().instrument(span.clone()).await.map_err(|e| {
            tracing::error!("user_has_plan error: {:?}", e);
            ConnectorError::HttpError(format!("Failed to check plan: {}", e))
        })?;

        match resp.status().as_u16() {
            200 => {
                let text = resp
                    .text()
                    .await
                    .map_err(|e| ConnectorError::HttpError(e.to_string()))?;
                serde_json::from_str::<UserMeResponse>(&text)
                    .map(|response| {
                        let user_plan = response.plan.and_then(|p| p.name).unwrap_or_default();
                        is_plan_higher_tier(&user_plan, required_plan_name)
                    })
                    .map_err(|_| ConnectorError::InvalidResponse(text))
            }
            401 | 403 => {
                tracing::debug!(parent: &span, "User not authenticated or authorized");
                Ok(false)
            }
            404 => {
                tracing::debug!(parent: &span, "User or plan not found");
                Ok(false)
            }
            _ => Err(ConnectorError::HttpError(format!(
                "Unexpected status code: {}",
                resp.status()
            ))),
        }
    }

    async fn get_user_plan(&self, user_id: &str) -> Result<UserPlanInfo, ConnectorError> {
        let span = tracing::info_span!("user_service_get_plan", user_id = %user_id);

        // Use /oauth_server/api/me endpoint to get user's current plan via OAuth
        let url = format!("{}/oauth_server/api/me", self.base_url);
        let mut req = self.http_client.get(&url);

        if let Some(auth) = self.auth_header() {
            req = req.header("Authorization", auth);
        }

        #[derive(serde::Deserialize)]
        struct PlanInfoResponse {
            #[serde(default)]
            plan: Option<String>,
            #[serde(default)]
            plan_name: Option<String>,
            #[serde(default)]
            user_id: Option<String>,
            #[serde(default)]
            description: Option<String>,
            #[serde(default)]
            active: Option<bool>,
        }

        let resp = req
            .send()
            .instrument(span)
            .await
            .and_then(|resp| resp.error_for_status())
            .map_err(|e| {
                tracing::error!("get_user_plan error: {:?}", e);
                ConnectorError::HttpError(format!("Failed to get user plan: {}", e))
            })?;

        let text = resp
            .text()
            .await
            .map_err(|e| ConnectorError::HttpError(e.to_string()))?;
        serde_json::from_str::<PlanInfoResponse>(&text)
            .map(|info| UserPlanInfo {
                user_id: info.user_id.unwrap_or_else(|| user_id.to_string()),
                plan_name: info.plan.or(info.plan_name).unwrap_or_default(),
                plan_description: info.description,
                tier: None,
                active: info.active.unwrap_or(true),
                started_at: None,
                expires_at: None,
            })
            .map_err(|_| ConnectorError::InvalidResponse(text))
    }

    async fn list_available_plans(&self) -> Result<Vec<PlanDefinition>, ConnectorError> {
        let span = tracing::info_span!("user_service_list_plans");

        // Query plan_description via Eve REST API (PostgREST endpoint)
        let url = format!("{}/api/1.0/plan_description", self.base_url);
        let mut req = self.http_client.get(&url);

        if let Some(auth) = self.auth_header() {
            req = req.header("Authorization", auth);
        }

        #[derive(serde::Deserialize)]
        struct EveResponse {
            #[serde(default)]
            _items: Vec<PlanDefinition>,
        }

        let resp = req
            .send()
            .instrument(span)
            .await
            .and_then(|resp| resp.error_for_status())
            .map_err(|e| {
                tracing::error!("list_available_plans error: {:?}", e);
                ConnectorError::HttpError(format!("Failed to list plans: {}", e))
            })?;

        let text = resp
            .text()
            .await
            .map_err(|e| ConnectorError::HttpError(e.to_string()))?;

        // Try Eve format first, fallback to direct array
        if let Ok(eve_resp) = serde_json::from_str::<EveResponse>(&text) {
            Ok(eve_resp._items)
        } else {
            serde_json::from_str::<Vec<PlanDefinition>>(&text)
                .map_err(|_| ConnectorError::InvalidResponse(text))
        }
    }

    async fn get_user_profile(&self, user_token: &str) -> Result<UserProfile, ConnectorError> {
        let span = tracing::info_span!("user_service_get_profile");

        // Query /oauth_server/api/me with user's token
        let url = format!("{}/oauth_server/api/me", self.base_url);
        let req = self
            .http_client
            .get(&url)
            .header("Authorization", format!("Bearer {}", user_token));

        let resp = req.send().instrument(span.clone()).await.map_err(|e| {
            tracing::error!("get_user_profile error: {:?}", e);
            ConnectorError::HttpError(format!("Failed to get user profile: {}", e))
        })?;

        if resp.status() == 401 {
            return Err(ConnectorError::Unauthorized(
                "Invalid or expired user token".to_string(),
            ));
        }

        let text = resp
            .text()
            .await
            .map_err(|e| ConnectorError::HttpError(e.to_string()))?;
        serde_json::from_str::<UserProfile>(&text).map_err(|e| {
            tracing::error!("Failed to parse user profile: {:?}", e);
            ConnectorError::InvalidResponse(text)
        })
    }

    async fn get_template_product(
        &self,
        stack_template_id: i32,
    ) -> Result<Option<ProductInfo>, ConnectorError> {
        let span = tracing::info_span!(
            "user_service_get_template_product",
            template_id = stack_template_id
        );

        // Query /api/1.0/products?external_id={template_id}&product_type=template
        let url = format!(
            "{}/api/1.0/products?where={{\"external_id\":{},\"product_type\":\"template\"}}",
            self.base_url, stack_template_id
        );

        let mut req = self.http_client.get(&url);

        if let Some(auth) = self.auth_header() {
            req = req.header("Authorization", auth);
        }

        #[derive(serde::Deserialize)]
        struct ProductsResponse {
            #[serde(default)]
            _items: Vec<ProductInfo>,
        }

        let resp = req.send().instrument(span).await.map_err(|e| {
            tracing::error!("get_template_product error: {:?}", e);
            ConnectorError::HttpError(format!("Failed to get template product: {}", e))
        })?;

        let text = resp
            .text()
            .await
            .map_err(|e| ConnectorError::HttpError(e.to_string()))?;

        // Try Eve format first (with _items wrapper)
        if let Ok(products_resp) = serde_json::from_str::<ProductsResponse>(&text) {
            Ok(products_resp._items.into_iter().next())
        } else {
            // Try direct array format
            serde_json::from_str::<Vec<ProductInfo>>(&text)
                .map(|mut items| items.pop())
                .map_err(|_| ConnectorError::InvalidResponse(text))
        }
    }

    async fn user_owns_template(
        &self,
        user_token: &str,
        stack_template_id: &str,
    ) -> Result<bool, ConnectorError> {
        let span = tracing::info_span!(
            "user_service_check_template_ownership",
            template_id = stack_template_id
        );

        // Get user profile (includes products list)
        let profile = self
            .get_user_profile(user_token)
            .instrument(span.clone())
            .await?;

        // Try to parse stack_template_id as i32 first (for backward compatibility with integer IDs)
        let owns_template = if let Ok(template_id_int) = stack_template_id.parse::<i32>() {
            profile
                .products
                .iter()
                .any(|p| p.product_type == "template" && p.external_id == Some(template_id_int))
        } else {
            // If not i32, try comparing as string (UUID or slug)
            profile.products.iter().any(|p| {
                if p.product_type != "template" {
                    return false;
                }
                // Compare with code (slug)
                if p.code == stack_template_id {
                    return true;
                }
                // Compare with id if available
                if let Some(id) = &p.id {
                    if id == stack_template_id {
                        return true;
                    }
                }
                false
            })
        };

        tracing::info!(
            owned = owns_template,
            "User template ownership check complete"
        );

        Ok(owns_template)
    }

    async fn get_categories(&self) -> Result<Vec<CategoryInfo>, ConnectorError> {
        let span = tracing::info_span!("user_service_get_categories");
        let url = format!("{}/api/1.0/category", self.base_url);

        let mut attempt = 0;
        loop {
            attempt += 1;

            let mut req = self.http_client.get(&url);

            if let Some(auth) = self.auth_header() {
                req = req.header("Authorization", auth);
            }

            match req.send().instrument(span.clone()).await {
                Ok(resp) => match resp.status().as_u16() {
                    200 => {
                        let text = resp
                            .text()
                            .await
                            .map_err(|e| ConnectorError::HttpError(e.to_string()))?;

                        // User Service returns {_items: [...]}
                        #[derive(Deserialize)]
                        struct CategoriesResponse {
                            #[serde(rename = "_items")]
                            items: Vec<CategoryInfo>,
                        }

                        return serde_json::from_str::<CategoriesResponse>(&text)
                            .map(|resp| resp.items)
                            .map_err(|e| {
                                tracing::error!("Failed to parse categories response: {:?}", e);
                                ConnectorError::InvalidResponse(text)
                            });
                    }
                    404 => {
                        return Err(ConnectorError::NotFound(
                            "Category endpoint not found".to_string(),
                        ));
                    }
                    500..=599 => {
                        if attempt < self.retry_attempts {
                            let backoff = std::time::Duration::from_millis(
                                100 * 2_u64.pow((attempt - 1) as u32),
                            );
                            tracing::warn!(
                                "User Service categories request failed with {}, retrying after {:?}",
                                resp.status(),
                                backoff
                            );
                            tokio::time::sleep(backoff).await;
                            continue;
                        }
                        return Err(ConnectorError::ServiceUnavailable(format!(
                            "User Service returned {}: get categories failed",
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
                    if attempt < self.retry_attempts {
                        let backoff =
                            std::time::Duration::from_millis(100 * 2_u64.pow((attempt - 1) as u32));
                        tracing::warn!(
                            "User Service get categories timeout, retrying after {:?}",
                            backoff
                        );
                        tokio::time::sleep(backoff).await;
                        continue;
                    }
                    return Err(ConnectorError::ServiceUnavailable(
                        "Get categories timeout".to_string(),
                    ));
                }
                Err(e) => {
                    return Err(ConnectorError::HttpError(format!(
                        "Get categories request failed: {}",
                        e
                    )));
                }
            }
        }
    }
}
