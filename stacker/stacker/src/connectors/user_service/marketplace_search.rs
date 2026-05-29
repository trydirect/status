use crate::connectors::errors::ConnectorError;

use super::UserServiceClient;

impl UserServiceClient {
    pub async fn search_marketplace_templates(
        &self,
        bearer_token: &str,
        query: Option<&str>,
        category: Option<&str>,
        is_marketplace: Option<bool>,
        page: Option<u32>,
        max_results: Option<u32>,
    ) -> Result<Vec<serde_json::Value>, ConnectorError> {
        let mut url = format!("{}/applications/", self.base_url);
        let mut query_parts: Vec<String> = Vec::new();

        if let Some(page) = page {
            query_parts.push(format!("page={}", page));
        }

        if let Some(max_results) = max_results {
            query_parts.push(format!("max_results={}", max_results));
        }

        if !query_parts.is_empty() {
            url.push('?');
            url.push_str(&query_parts.join("&"));
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

        let payload = response
            .json::<serde_json::Value>()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(e.to_string()))?;

        let raw_items = if let Some(items) = payload.get("_items").and_then(|v| v.as_array()) {
            items.clone()
        } else if let Some(items) = payload.as_array() {
            items.clone()
        } else {
            Vec::new()
        };

        let query_lc = query.map(|q| q.to_lowercase());
        let category_lc = category.map(|c| c.to_lowercase());

        let items = raw_items
            .into_iter()
            .filter(|item| {
                if let Some(expected) = is_marketplace {
                    let actual = item
                        .get("is_from_marketplace")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    if actual != expected {
                        return false;
                    }
                }

                if let Some(ref q) = query_lc {
                    let name = item
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_lowercase();
                    let code = item
                        .get("code")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_lowercase();
                    let description = item
                        .get("description")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_lowercase();

                    if !(name.contains(q) || code.contains(q) || description.contains(q)) {
                        return false;
                    }
                }

                if let Some(ref expected_category) = category_lc {
                    let category_match = item
                        .get("category")
                        .and_then(|v| v.as_str())
                        .map(|v| v.to_lowercase() == *expected_category)
                        .unwrap_or(false)
                        || item
                            .get("categories")
                            .and_then(|v| v.as_array())
                            .map(|arr| {
                                arr.iter().any(|entry| {
                                    entry
                                        .as_str()
                                        .map(|v| v.to_lowercase() == *expected_category)
                                        .unwrap_or(false)
                                })
                            })
                            .unwrap_or(false);

                    if !category_match {
                        return false;
                    }
                }

                true
            })
            .collect::<Vec<_>>();

        Ok(items)
    }
}
