use serde::{Deserialize, Serialize};

use crate::connectors::errors::ConnectorError;

use super::UserServiceClient;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationItem {
    #[serde(rename = "_id")]
    pub id: Option<i64>,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub r#type: Option<String>,
    #[serde(default)]
    pub is_read: Option<bool>,
    #[serde(rename = "_created")]
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(rename = "_updated")]
    #[serde(default)]
    pub updated_at: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct NotificationsResponse {
    _items: Vec<NotificationItem>,
}

impl UserServiceClient {
    pub async fn list_notifications(
        &self,
        bearer_token: &str,
        page: Option<u32>,
        max_results: Option<u32>,
    ) -> Result<Vec<NotificationItem>, ConnectorError> {
        let mut url = format!("{}/notifications/", self.base_url);
        let mut query = Vec::new();

        if let Some(page) = page {
            query.push(format!("page={}", page));
        }

        if let Some(max_results) = max_results {
            query.push(format!("max_results={}", max_results));
        }

        if !query.is_empty() {
            url.push('?');
            url.push_str(&query.join("&"));
        }

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

        let wrapper: NotificationsResponse = response
            .json()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(e.to_string()))?;

        Ok(wrapper._items)
    }

    pub async fn mark_notification_read(
        &self,
        bearer_token: &str,
        notification_id: i64,
        is_read: bool,
    ) -> Result<serde_json::Value, ConnectorError> {
        let url = format!("{}/notifications/{}", self.base_url, notification_id);

        let response = self
            .http_client
            .patch(&url)
            .header("Authorization", format!("Bearer {}", bearer_token))
            .json(&serde_json::json!({ "is_read": is_read }))
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

    pub async fn mark_all_notifications_read(
        &self,
        bearer_token: &str,
    ) -> Result<serde_json::Value, ConnectorError> {
        let url = format!("{}/notifications/mark-all-read", self.base_url);

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
}
