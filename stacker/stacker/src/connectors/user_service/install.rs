use serde::{Deserialize, Serialize};
use urlencoding::encode;

use crate::connectors::errors::ConnectorError;

use super::UserServiceClient;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Installation {
    #[serde(rename = "_id")]
    pub id: Option<i64>,
    pub stack_code: Option<String>,
    pub status: Option<String>,
    pub cloud: Option<String>,
    pub deployment_hash: Option<String>,
    pub domain: Option<String>,
    #[serde(rename = "_created")]
    pub created_at: Option<String>,
    #[serde(rename = "_updated")]
    pub updated_at: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallationDetails {
    #[serde(rename = "_id", alias = "id")]
    pub id: Option<i64>,
    pub stack_code: Option<String>,
    pub status: Option<String>,
    pub cloud: Option<String>,
    pub deployment_hash: Option<String>,
    pub domain: Option<String>,
    pub server_ip: Option<String>,
    pub apps: Option<Vec<InstallationApp>>,
    pub agent_config: Option<serde_json::Value>,
    #[serde(rename = "_created")]
    pub created_at: Option<String>,
    #[serde(rename = "_updated")]
    pub updated_at: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallationApp {
    pub app_code: Option<String>,
    pub name: Option<String>,
    pub version: Option<String>,
    pub port: Option<i32>,
}

// Wrapper types for Eve-style responses
#[derive(Debug, Deserialize)]
struct InstallationsResponse {
    _items: Vec<Installation>,
}

fn parse_installation_details_payload(
    mut payload: serde_json::Value,
) -> Result<InstallationDetails, ConnectorError> {
    if let Some(wrapper) = payload.as_object_mut() {
        if let Some(mut installation) = wrapper.remove("installation") {
            if let Some(agent_config) = wrapper.remove("agent_config") {
                if let Some(installation_obj) = installation.as_object_mut() {
                    installation_obj.insert("agent_config".to_string(), agent_config);
                }
            }
            payload = installation;
        }
    }

    if let Some(installation_obj) = payload.as_object_mut() {
        if !installation_obj.contains_key("_id") {
            if let Some(id) = installation_obj.remove("id") {
                installation_obj.insert("_id".to_string(), id);
            }
        }
        if !installation_obj.contains_key("_created") {
            if let Some(created_at) = installation_obj.get("date_created").cloned() {
                installation_obj.insert("_created".to_string(), created_at);
            }
        }

        if let Some(request_dump) = installation_obj
            .get("request_dump")
            .and_then(|value| value.as_object())
            .cloned()
        {
            let field_mappings = [
                ("stack_code", "stack_code"),
                ("provider", "cloud"),
                ("cloud", "cloud"),
                ("commonDomain", "domain"),
                ("domain", "domain"),
                ("server_ip", "server_ip"),
                ("deployment_hash", "deployment_hash"),
            ];

            for (source, target) in field_mappings {
                if installation_obj.contains_key(target) {
                    continue;
                }
                if let Some(value) = request_dump.get(source).cloned() {
                    installation_obj.insert(target.to_string(), value);
                }
            }
        }
    }

    serde_json::from_value::<InstallationDetails>(payload)
        .map_err(|e| ConnectorError::InvalidResponse(e.to_string()))
}

impl UserServiceClient {
    /// List user's installations (deployments)
    pub async fn list_installations(
        &self,
        bearer_token: &str,
    ) -> Result<Vec<Installation>, ConnectorError> {
        let url = format!("{}/api/1.0/installations", self.base_url);

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

        // User Service returns { "_items": [...], "_meta": {...} }
        let wrapper: InstallationsResponse = response
            .json()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(e.to_string()))?;

        Ok(wrapper._items)
    }

    /// Get specific installation details
    pub async fn get_installation(
        &self,
        bearer_token: &str,
        installation_id: i64,
    ) -> Result<InstallationDetails, ConnectorError> {
        let url = format!(
            "{}/api/1.0/installations/{}",
            self.base_url, installation_id
        );

        let mut response = self
            .http_client
            .get(&url)
            .header("Authorization", format!("Bearer {}", bearer_token))
            .send()
            .await
            .map_err(ConnectorError::from)?;

        if response.status().as_u16() == 404 {
            let fallback_url = format!("{}/install/{}", self.base_url, installation_id);
            response = self
                .http_client
                .get(&fallback_url)
                .header("Authorization", format!("Bearer {}", bearer_token))
                .send()
                .await
                .map_err(ConnectorError::from)?;
        }

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let body = response.text().await.unwrap_or_default();
            return Err(ConnectorError::HttpError(format!(
                "User Service error ({}): {}",
                status, body
            )));
        }

        let payload = response
            .json::<serde_json::Value>()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(e.to_string()))?;

        parse_installation_details_payload(payload)
    }

    /// Get installation details by deployment hash via the lightweight Flask route.
    pub async fn get_installation_by_hash(
        &self,
        bearer_token: &str,
        deployment_hash: &str,
    ) -> Result<InstallationDetails, ConnectorError> {
        let url = format!(
            "{}/install/by-deployment-hash/{}",
            self.base_url,
            encode(deployment_hash)
        );

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

        response
            .json::<InstallationDetails>()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(e.to_string()))
    }

    /// Initiate a deployment via User Service native flow
    pub async fn initiate_deployment(
        &self,
        bearer_token: &str,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, ConnectorError> {
        let url = format!("{}/install/init/", self.base_url);

        let response = self
            .http_client
            .post(&url)
            .header("Authorization", format!("Bearer {}", bearer_token))
            .json(&payload)
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

        response
            .json::<serde_json::Value>()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(e.to_string()))
    }

    /// Trigger redeploy for an installation
    pub async fn trigger_redeploy(
        &self,
        bearer_token: &str,
        installation_id: i64,
    ) -> Result<serde_json::Value, ConnectorError> {
        let url = format!("{}/install/{}/redeploy", self.base_url, installation_id);

        let response = self
            .http_client
            .post(&url)
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

        response
            .json::<serde_json::Value>()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(e.to_string()))
    }

    /// Add app to an existing installation
    pub async fn add_app_to_installation(
        &self,
        bearer_token: &str,
        installation_id: i64,
        app_code: &str,
        app_config: Option<serde_json::Value>,
    ) -> Result<serde_json::Value, ConnectorError> {
        let url = format!("{}/install/{}/add-app", self.base_url, installation_id);
        let payload = serde_json::json!({
            "app_code": app_code,
            "app_config": app_config.unwrap_or_else(|| serde_json::json!({}))
        });

        let response = self
            .http_client
            .post(&url)
            .header("Authorization", format!("Bearer {}", bearer_token))
            .json(&payload)
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

        response
            .json::<serde_json::Value>()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(e.to_string()))
    }
}
