use serde::Deserialize;

use crate::connectors::errors::ConnectorError;

use super::app::Application;
use super::UserServiceClient;

#[derive(Debug, Deserialize)]
pub(crate) struct StackViewItem {
    pub(crate) code: String,
    pub(crate) value: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub(crate) struct StackViewResponse {
    pub(crate) _items: Vec<StackViewItem>,
}

impl UserServiceClient {
    pub(crate) async fn search_stack_view(
        &self,
        bearer_token: &str,
        query: Option<&str>,
    ) -> Result<Vec<Application>, ConnectorError> {
        let url = format!("{}/stack_view", self.base_url);

        tracing::info!("Fetching stack_view from {}", url);
        let start = std::time::Instant::now();

        // Create a dedicated client for stack_view with longer timeout (30s for large response)
        // and explicit connection settings to avoid connection reuse issues
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .connect_timeout(std::time::Duration::from_secs(10))
            .http1_only()
            .pool_max_idle_per_host(0) // Don't reuse connections
            .build()
            .map_err(|e| {
                ConnectorError::Internal(format!("Failed to create HTTP client: {}", e))
            })?;

        let response = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", bearer_token))
            .send()
            .await
            .map_err(|e| {
                tracing::error!("Failed to send request to stack_view: {:?}", e);
                ConnectorError::from(e)
            })?;

        let status = response.status();
        tracing::info!(
            "stack_view responded with status {} in {:?}",
            status,
            start.elapsed()
        );

        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ConnectorError::HttpError(format!(
                "User Service error ({}): {}",
                status.as_u16(),
                body
            )));
        }

        tracing::info!("Reading stack_view JSON body...");
        let json_start = std::time::Instant::now();

        let wrapper: StackViewResponse = response.json().await.map_err(|e| {
            tracing::error!(
                "Failed to parse stack_view JSON after {:?}: {:?}",
                json_start.elapsed(),
                e
            );
            ConnectorError::InvalidResponse(e.to_string())
        })?;

        tracing::info!(
            "Parsed stack_view with {} items in {:?}",
            wrapper._items.len(),
            json_start.elapsed()
        );

        let mut apps: Vec<Application> = wrapper
            ._items
            .into_iter()
            .map(application_from_stack_view)
            .collect();

        if let Some(q) = query {
            let q = q.to_lowercase();
            apps.retain(|app| {
                let name = app.name.as_deref().unwrap_or("").to_lowercase();
                let code = app.code.as_deref().unwrap_or("").to_lowercase();
                name.contains(&q) || code.contains(&q)
            });
        }

        Ok(apps)
    }
}

pub(crate) fn application_from_stack_view(item: StackViewItem) -> Application {
    let value = item.value;
    let id = value.get("_id").and_then(|v| v.as_i64());
    let name = value
        .get("name")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let code = value
        .get("code")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| Some(item.code));
    let description = value
        .get("description")
        .or_else(|| value.get("_description"))
        .or_else(|| value.get("full_description"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let category = value
        .get("module")
        .or_else(|| value.get("category"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let docker_image = value
        .get("image")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| {
            value
                .get("images")
                .and_then(|v| v.as_array())
                .and_then(|arr| arr.first())
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        });
    let default_port = value
        .get("ports")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|port| {
            port.get("container")
                .or_else(|| port.get("host"))
                .and_then(|v| v.as_i64())
        })
        .map(|v| v as i32);

    Application {
        id,
        name,
        code,
        description,
        category,
        docker_image,
        default_port,
        role: None,
        default_env: None,
        default_ports: None,
        default_config_files: None,
    }
}
