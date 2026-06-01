//! Hetzner Cloud connector.
//!
//! Keep all Hetzner API calls behind this trait so MCP/routes can be tested
//! without touching real infrastructure.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::Duration;

use crate::connectors::ConnectorError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HetznerSnapshotTarget {
    pub provider_server_id: Option<i64>,
    pub server_name: Option<String>,
    pub public_ip: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HetznerSnapshot {
    pub action_id: i64,
    pub status: String,
    pub image_id: Option<i64>,
}

#[async_trait]
pub trait HetznerCloudConnector: Send + Sync {
    async fn create_server_snapshot(
        &self,
        token: &str,
        target: HetznerSnapshotTarget,
        description: &str,
    ) -> Result<HetznerSnapshot, ConnectorError>;
}

#[derive(Clone)]
pub struct HetznerCloudClient {
    http_client: reqwest::Client,
    base_url: String,
}

impl HetznerCloudClient {
    pub fn new(base_url: impl Into<String>) -> Result<Self, ConnectorError> {
        let http_client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(45))
            .build()
            .map_err(ConnectorError::from)?;
        Ok(Self {
            http_client,
            base_url: base_url.into().trim_end_matches("/").to_string(),
        })
    }

    pub fn from_env() -> Result<Self, ConnectorError> {
        let base_url = std::env::var("HETZNER_API_BASE_URL")
            .unwrap_or_else(|_| "https://api.hetzner.cloud/v1".to_string());
        Self::new(base_url)
    }

    async fn resolve_server_id(
        &self,
        token: &str,
        target: &HetznerSnapshotTarget,
    ) -> Result<i64, ConnectorError> {
        if let Some(id) = target.provider_server_id {
            return Ok(id);
        }

        let response = self
            .http_client
            .get(format!("{}/servers", self.base_url))
            .bearer_auth(token)
            .send()
            .await
            .map_err(ConnectorError::from)?;
        let status = response.status();
        if !status.is_success() {
            return Err(status_to_error(status, "Hetzner server lookup failed"));
        }

        let body: HetznerServersResponse = response
            .json()
            .await
            .map_err(|err| ConnectorError::InvalidResponse(err.to_string()))?;
        find_matching_hetzner_server(&body.servers, target)
            .map(|server| server.id)
            .ok_or_else(|| {
                ConnectorError::NotFound(
                    "No Hetzner server matched the saved Stacker server name or public IP"
                        .to_string(),
                )
            })
    }
}

#[async_trait]
impl HetznerCloudConnector for HetznerCloudClient {
    async fn create_server_snapshot(
        &self,
        token: &str,
        target: HetznerSnapshotTarget,
        description: &str,
    ) -> Result<HetznerSnapshot, ConnectorError> {
        let server_id = self.resolve_server_id(token, &target).await?;
        let response = self
            .http_client
            .post(format!(
                "{}/servers/{}/actions/create_image",
                self.base_url, server_id
            ))
            .bearer_auth(token)
            .json(&json!({
                "type": "snapshot",
                "description": description,
            }))
            .send()
            .await
            .map_err(ConnectorError::from)?;

        let status = response.status();
        if !status.is_success() {
            return Err(status_to_error(status, "Hetzner snapshot request failed"));
        }

        let body: HetznerCreateImageResponse = response
            .json()
            .await
            .map_err(|err| ConnectorError::InvalidResponse(err.to_string()))?;
        let image_id = body
            .action
            .resources
            .iter()
            .find(|resource| resource.resource_type == "image")
            .map(|resource| resource.id);

        Ok(HetznerSnapshot {
            action_id: body.action.id,
            status: body.action.status,
            image_id,
        })
    }
}

fn status_to_error(status: reqwest::StatusCode, message: &str) -> ConnectorError {
    match status.as_u16() {
        401 | 403 => {
            ConnectorError::Unauthorized("Hetzner rejected the saved cloud token".to_string())
        }
        404 => ConnectorError::NotFound(message.to_string()),
        429 => ConnectorError::RateLimited("Hetzner API rate limit exceeded".to_string()),
        _ => ConnectorError::HttpError(format!("{} with status {}", message, status.as_u16())),
    }
}

fn find_matching_hetzner_server<'a>(
    servers: &'a [HetznerServer],
    target: &HetznerSnapshotTarget,
) -> Option<&'a HetznerServer> {
    let expected_ip = target
        .public_ip
        .as_deref()
        .filter(|value| !value.trim().is_empty());
    let expected_name = target
        .server_name
        .as_deref()
        .filter(|value| !value.trim().is_empty());

    servers.iter().find(|server| {
        expected_ip.is_some_and(|ip| hetzner_server_ip(server) == Some(ip))
            || expected_name.is_some_and(|name| server.name == name)
    })
}

fn hetzner_server_ip(server: &HetznerServer) -> Option<&str> {
    server
        .public_net
        .as_ref()
        .and_then(|net| net.ipv4.as_ref())
        .map(|ipv4| ipv4.ip.as_str())
}

#[derive(Debug, Deserialize)]
struct HetznerServersResponse {
    servers: Vec<HetznerServer>,
}

#[derive(Debug, Deserialize)]
struct HetznerServer {
    id: i64,
    name: String,
    #[serde(default)]
    public_net: Option<HetznerServerPublicNet>,
}

#[derive(Debug, Deserialize)]
struct HetznerServerPublicNet {
    #[serde(default)]
    ipv4: Option<HetznerServerIpv4>,
}

#[derive(Debug, Deserialize)]
struct HetznerServerIpv4 {
    ip: String,
}

#[derive(Debug, Deserialize)]
struct HetznerCreateImageResponse {
    action: HetznerAction,
}

#[derive(Debug, Deserialize)]
struct HetznerAction {
    id: i64,
    status: String,
    #[serde(default)]
    resources: Vec<HetznerActionResource>,
}

#[derive(Debug, Deserialize)]
struct HetznerActionResource {
    id: i64,
    #[serde(rename = "type")]
    resource_type: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_partial_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn create_snapshot_resolves_server_by_public_ip_without_live_api() {
        let api = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/servers"))
            .and(header("authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "servers": [{
                    "id": 123,
                    "name": "prod-web-1",
                    "public_net": { "ipv4": { "ip": "203.0.113.10" } }
                }]
            })))
            .mount(&api)
            .await;
        Mock::given(method("POST"))
            .and(path("/servers/123/actions/create_image"))
            .and(header("authorization", "Bearer test-token"))
            .and(body_partial_json(json!({"type": "snapshot"})))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "action": {
                    "id": 777,
                    "status": "running",
                    "resources": [{"id": 888, "type": "image"}]
                }
            })))
            .mount(&api)
            .await;

        let client = HetznerCloudClient::new(api.uri()).unwrap();
        let snapshot = client
            .create_server_snapshot(
                "test-token",
                HetznerSnapshotTarget {
                    provider_server_id: None,
                    server_name: None,
                    public_ip: Some("203.0.113.10".to_string()),
                },
                "Stacker troubleshooting snapshot",
            )
            .await
            .unwrap();

        assert_eq!(snapshot.action_id, 777);
        assert_eq!(snapshot.image_id, Some(888));
        assert_eq!(snapshot.status, "running");
    }

    #[tokio::test]
    async fn create_snapshot_can_use_known_provider_server_id() {
        let api = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/servers/456/actions/create_image"))
            .and(header("authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "action": { "id": 778, "status": "running", "resources": [] }
            })))
            .mount(&api)
            .await;

        let client = HetznerCloudClient::new(api.uri()).unwrap();
        let snapshot = client
            .create_server_snapshot(
                "test-token",
                HetznerSnapshotTarget {
                    provider_server_id: Some(456),
                    server_name: None,
                    public_ip: None,
                },
                "Stacker troubleshooting snapshot",
            )
            .await
            .unwrap();

        assert_eq!(snapshot.action_id, 778);
        assert_eq!(snapshot.image_id, None);
    }
}
