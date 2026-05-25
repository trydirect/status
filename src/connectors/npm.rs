//! Nginx Proxy Manager API client
//!
//! This module provides a client for interacting with the Nginx Proxy Manager API
//! to create, update, and delete proxy hosts programmatically.

use anyhow::{Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::security::vault_client::NpmCredentials;

/// Configuration for connecting to Nginx Proxy Manager
#[derive(Debug, Clone)]
pub struct NpmConfig {
    /// NPM API host (e.g., "http://nginx-proxy-manager:81")
    pub host: String,
    /// Admin email for authentication
    pub email: String,
    /// Admin password for authentication
    pub password: String,
}

impl NpmConfig {
    pub fn new(host: String, email: String, password: String) -> Self {
        Self {
            host: normalize_npm_host(host),
            email,
            password,
        }
    }

    pub fn from_credentials(credentials: &NpmCredentials) -> Self {
        Self::new(
            credentials.host().to_string(),
            credentials.email().to_string(),
            credentials.password().to_string(),
        )
    }

    pub fn from_env() -> Option<Self> {
        let host = std::env::var("NPM_HOST").ok()?;
        let email = std::env::var("NPM_EMAIL").ok()?;
        let password = std::env::var("NPM_PASSWORD").ok()?;
        Some(Self::new(host, email, password))
    }
}

fn normalize_npm_host(host: String) -> String {
    let canonical = "nginx-proxy-manager";
    let legacy = "nginx_proxy_manager";

    if host == legacy {
        return canonical.to_string();
    }

    if let Some(rest) = host.strip_prefix(&format!("{legacy}:")) {
        return format!("{canonical}:{rest}");
    }

    host.replace(&format!("://{legacy}"), &format!("://{canonical}"))
}

/// Request to create or update a proxy host
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyHostRequest {
    pub domain_names: Vec<String>,
    pub forward_host: String,
    pub forward_port: u16,
    #[serde(default = "default_true")]
    pub ssl_enabled: bool,
    #[serde(default = "default_true")]
    pub ssl_forced: bool,
    #[serde(default = "default_true")]
    pub http2_support: bool,
}

fn default_true() -> bool {
    true
}

/// Result of a proxy host operation
#[derive(Debug, Clone, Serialize)]
pub struct ProxyHostResult {
    pub success: bool,
    pub proxy_host_id: Option<i64>,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub npm_response: Option<Value>,
    pub domain_names: Vec<String>,
    pub forward_host: String,
    pub forward_port: u16,
    pub adopted: bool,
    pub ssl_enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssl_status: Option<String>,
}

/// Nginx Proxy Manager API client
pub struct NpmClient {
    config: NpmConfig,
    client: Client,
    token: Option<String>,
}

impl NpmClient {
    /// Create a new NPM client with the given configuration
    pub fn new(config: NpmConfig) -> Self {
        Self {
            config,
            client: Client::new(),
            token: None,
        }
    }

    /// Create a new NPM client with default configuration from environment
    pub fn from_env() -> Option<Self> {
        NpmConfig::from_env().map(Self::new)
    }

    /// Create a new NPM client with custom host/credentials
    pub fn with_credentials(host: String, email: String, password: String) -> Self {
        Self::new(NpmConfig::new(host, email, password))
    }

    /// Authenticate with NPM and store the token
    pub async fn authenticate(&mut self) -> Result<()> {
        tracing::info!(
            npm_host = %self.config.host,
            "Authenticating with Nginx Proxy Manager"
        );

        let response = self
            .client
            .post(format!("{}/api/tokens", self.config.host))
            .json(&json!({
                "identity": self.config.email,
                "secret": self.config.password
            }))
            .send()
            .await
            .context("Failed to connect to Nginx Proxy Manager")?;

        if !response.status().is_success() {
            let status = response.status();
            let _ = response.text().await;
            anyhow::bail!("NPM authentication failed with status {}", status);
        }

        let token_data: Value = response
            .json()
            .await
            .context("Failed to parse NPM token response")?;

        self.token = Some(
            token_data["token"]
                .as_str()
                .context("No token in NPM response")?
                .to_string(),
        );

        tracing::debug!("NPM authentication successful");
        Ok(())
    }

    /// Ensure we have a valid token, authenticating if necessary
    async fn ensure_authenticated(&mut self) -> Result<&str> {
        if self.token.is_none() {
            self.authenticate().await?;
        }
        self.token
            .as_deref()
            .context("Failed to obtain NPM authentication token")
    }

    /// Create a new proxy host
    pub async fn create_proxy_host(
        &mut self,
        request: &ProxyHostRequest,
    ) -> Result<ProxyHostResult> {
        let token = self.ensure_authenticated().await?.to_string();

        let certificate_id: Value = if request.ssl_enabled {
            json!("new")
        } else {
            Value::Null
        };
        let meta = if request.ssl_enabled {
            json!({
                "letsencrypt_agree": true,
                "letsencrypt_email": self.config.email,
                "dns_challenge": false
            })
        } else {
            json!({})
        };

        let payload = json!({
            "domain_names": request.domain_names,
            "forward_scheme": "http",
            "forward_host": request.forward_host,
            "forward_port": request.forward_port,
            "certificate_id": certificate_id,
            "ssl_forced": request.ssl_forced,
            "http2_support": request.http2_support,
            "block_exploits": true,
            "allow_websocket_upgrade": true,
            "access_list_id": 0,
            "meta": meta,
            "locations": []
        });

        tracing::info!(
            forward_host = %request.forward_host,
            forward_port = %request.forward_port,
            domains = ?request.domain_names,
            ssl = %request.ssl_enabled,
            "Creating proxy host in NPM"
        );

        let response = self
            .client
            .post(format!("{}/api/nginx/proxy-hosts", self.config.host))
            .header("Authorization", format!("Bearer {}", token))
            .json(&payload)
            .send()
            .await
            .context("Failed to send request to NPM")?;

        let status = response.status();
        let body_text = response.text().await.unwrap_or_default();
        let body = npm_response_body(&body_text);

        if status.is_success() {
            let proxy_host_id = body["id"].as_i64();
            tracing::info!(proxy_host_id = ?proxy_host_id, "Proxy host created successfully");

            Ok(ProxyHostResult {
                success: true,
                proxy_host_id,
                message: "Proxy host created successfully".to_string(),
                details: None,
                npm_response: None,
                domain_names: request.domain_names.clone(),
                forward_host: request.forward_host.clone(),
                forward_port: request.forward_port,
                adopted: false,
                ssl_enabled: request.ssl_enabled,
                ssl_status: Some(if request.ssl_enabled {
                    "enabled".to_string()
                } else {
                    "disabled".to_string()
                }),
            })
        } else {
            let details = npm_error_details(&body);
            if let Some(primary_domain) = request.domain_names.first() {
                match self.find_proxy_host_by_domain(primary_domain).await {
                    Ok(Some(existing_host)) => {
                        return Ok(adopt_existing_proxy_host_after_create_failure(
                            request,
                            &existing_host,
                            details,
                            Some(body.clone()),
                        ));
                    }
                    Ok(None) => {}
                    Err(error) => {
                        tracing::warn!(
                            error = %error,
                            domain = %primary_domain,
                            "Failed to verify whether NPM created the proxy host after an error"
                        );
                    }
                }
            }

            let message = match details.as_deref() {
                Some(details) => format!("Failed to create proxy host: {} - {}", status, details),
                None => format!("Failed to create proxy host: {}", status),
            };
            tracing::error!(%message);

            Ok(ProxyHostResult {
                success: false,
                proxy_host_id: None,
                message,
                details,
                npm_response: Some(body),
                domain_names: request.domain_names.clone(),
                forward_host: request.forward_host.clone(),
                forward_port: request.forward_port,
                adopted: false,
                ssl_enabled: false,
                ssl_status: Some("unknown".to_string()),
            })
        }
    }

    /// Delete a proxy host by matching domain names
    pub async fn delete_proxy_host(&mut self, domain_names: &[String]) -> Result<ProxyHostResult> {
        let token = self.ensure_authenticated().await?.to_string();

        // First, list all proxy hosts to find the matching one
        let response = self
            .client
            .get(format!("{}/api/nginx/proxy-hosts", self.config.host))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .context("Failed to list proxy hosts from NPM")?;

        let hosts: Vec<Value> = response.json().await.unwrap_or_default();

        // Find the proxy host with matching domain
        let matching_host = hosts.iter().find(|host| {
            if let Some(domains) = host["domain_names"].as_array() {
                domains.iter().any(|d| {
                    domain_names
                        .iter()
                        .any(|target| d.as_str().map(|s| s == target).unwrap_or(false))
                })
            } else {
                false
            }
        });

        if let Some(host) = matching_host {
            let host_id = host["id"].as_i64().unwrap_or(0);
            let forward_host = host["forward_host"].as_str().unwrap_or("").to_string();
            let forward_port = host["forward_port"].as_u64().unwrap_or(0) as u16;

            tracing::info!(proxy_host_id = %host_id, "Deleting proxy host");

            let delete_response = self
                .client
                .delete(format!(
                    "{}/api/nginx/proxy-hosts/{}",
                    self.config.host, host_id
                ))
                .header("Authorization", format!("Bearer {}", token))
                .send()
                .await
                .context("Failed to send delete request to NPM")?;

            if delete_response.status().is_success() {
                tracing::info!(proxy_host_id = %host_id, "Proxy host deleted successfully");

                Ok(ProxyHostResult {
                    success: true,
                    proxy_host_id: Some(host_id),
                    message: "Proxy host deleted successfully".to_string(),
                    details: None,
                    npm_response: None,
                    domain_names: domain_names.to_vec(),
                    forward_host,
                    forward_port,
                    adopted: false,
                    ssl_enabled: false,
                    ssl_status: None,
                })
            } else {
                let status = delete_response.status();
                let _ = delete_response.text().await;
                let message = format!("Failed to delete proxy host (status {})", status);

                Ok(ProxyHostResult {
                    success: false,
                    proxy_host_id: Some(host_id),
                    message,
                    details: None,
                    npm_response: None,
                    domain_names: domain_names.to_vec(),
                    forward_host,
                    forward_port,
                    adopted: false,
                    ssl_enabled: false,
                    ssl_status: None,
                })
            }
        } else {
            // No matching proxy host found - consider it success (idempotent)
            tracing::warn!(domains = ?domain_names, "No matching proxy host found to delete");

            Ok(ProxyHostResult {
                success: true,
                proxy_host_id: None,
                message: "No matching proxy host found (already deleted?)".to_string(),
                details: None,
                npm_response: None,
                domain_names: domain_names.to_vec(),
                forward_host: String::new(),
                forward_port: 0,
                adopted: false,
                ssl_enabled: false,
                ssl_status: None,
            })
        }
    }

    /// List all proxy hosts
    pub async fn list_proxy_hosts(&mut self) -> Result<Vec<Value>> {
        let token = self.ensure_authenticated().await?.to_string();

        let response = self
            .client
            .get(format!("{}/api/nginx/proxy-hosts", self.config.host))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .context("Failed to list proxy hosts from NPM")?;

        let hosts: Vec<Value> = response.json().await.unwrap_or_default();
        Ok(hosts)
    }

    /// Find a proxy host by domain name
    pub async fn find_proxy_host_by_domain(&mut self, domain: &str) -> Result<Option<Value>> {
        let hosts = self.list_proxy_hosts().await?;

        Ok(hosts.into_iter().find(|host| {
            if let Some(domains) = host["domain_names"].as_array() {
                domains
                    .iter()
                    .any(|d| d.as_str().map(|s| s == domain).unwrap_or(false))
            } else {
                false
            }
        }))
    }
}

fn npm_response_body(body_text: &str) -> Value {
    let trimmed = body_text.trim();
    if trimmed.is_empty() {
        json!({})
    } else {
        serde_json::from_str(trimmed)
            .map(redact_json_value)
            .unwrap_or_else(|_| json!({ "body": redact_sensitive(trimmed) }))
    }
}

fn redact_json_value(mut value: Value) -> Value {
    match &mut value {
        Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                if matches!(
                    key.to_ascii_lowercase().as_str(),
                    "token" | "secret" | "password" | "credential" | "credentials"
                ) {
                    *child = Value::String("***".to_string());
                } else {
                    *child = redact_json_value(child.take());
                }
            }
            value
        }
        Value::Array(items) => {
            for item in items {
                *item = redact_json_value(item.take());
            }
            value
        }
        Value::String(message) => Value::String(redact_sensitive(message)),
        other => other.take(),
    }
}

fn redact_sensitive(message: &str) -> String {
    let mut redacted = message.to_string();
    for key in ["token", "secret", "password", "credential"] {
        redacted = redact_key_value(&redacted, key);
    }
    redacted
}

fn redact_key_value(message: &str, key: &str) -> String {
    let lower = message.to_lowercase();
    let Some(index) = lower.find(key) else {
        return message.to_string();
    };
    let value_start = message[index + key.len()..]
        .find(|ch: char| ch == ':' || ch == '=')
        .map(|offset| index + key.len() + offset + 1);
    let Some(value_start) = value_start else {
        return message.to_string();
    };
    let value_end = message[value_start..]
        .find(|ch: char| ch == ',' || ch == '&' || ch == '\n')
        .map(|offset| value_start + offset)
        .unwrap_or(message.len());
    format!("{}***{}", &message[..value_start], &message[value_end..])
}

fn proxy_host_ssl_enabled(host: &Value) -> bool {
    match host.get("certificate_id") {
        Some(Value::Number(value)) => value.as_i64().unwrap_or_default() > 0,
        Some(Value::String(value)) => {
            let value = value.trim();
            !value.is_empty() && value != "0" && value != "null"
        }
        Some(value) => !value.is_null(),
        None => false,
    }
}

fn adopt_existing_proxy_host_after_create_failure(
    request: &ProxyHostRequest,
    existing_host: &Value,
    create_error: Option<String>,
    npm_response: Option<Value>,
) -> ProxyHostResult {
    let ssl_enabled = proxy_host_ssl_enabled(existing_host);
    let ssl_status = if request.ssl_enabled && !ssl_enabled {
        "pending_or_failed_http_only"
    } else if ssl_enabled {
        "enabled"
    } else {
        "disabled"
    };
    let message = if request.ssl_enabled && !ssl_enabled {
        "Proxy host exists after NPM create returned an error; adopted existing HTTP route, SSL certificate is pending or failed"
    } else {
        "Proxy host exists after NPM create returned an error; adopted existing route"
    };

    ProxyHostResult {
        success: true,
        proxy_host_id: existing_host["id"].as_i64(),
        message: message.to_string(),
        details: create_error,
        npm_response,
        domain_names: existing_host
            .get("domain_names")
            .and_then(Value::as_array)
            .map(|domains| {
                domains
                    .iter()
                    .filter_map(|domain| domain.as_str().map(ToString::to_string))
                    .collect()
            })
            .unwrap_or_else(|| request.domain_names.clone()),
        forward_host: existing_host["forward_host"]
            .as_str()
            .unwrap_or(&request.forward_host)
            .to_string(),
        forward_port: existing_host["forward_port"]
            .as_u64()
            .map(|port| port as u16)
            .unwrap_or(request.forward_port),
        adopted: true,
        ssl_enabled,
        ssl_status: Some(ssl_status.to_string()),
    }
}

fn npm_error_details(body: &Value) -> Option<String> {
    body.get("error")
        .and_then(|error| {
            error
                .get("message")
                .and_then(Value::as_str)
                .or_else(|| error.get("error").and_then(Value::as_str))
                .or_else(|| error.get("detail").and_then(Value::as_str))
        })
        .or_else(|| body.get("message").and_then(Value::as_str))
        .filter(|message| !message.trim().is_empty())
        .map(ToString::to_string)
        .or_else(|| {
            if body.is_null() || body.as_object().map(|map| map.is_empty()).unwrap_or(false) {
                None
            } else {
                Some(body.to_string())
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::{Matcher, Server};

    #[test]
    fn test_npm_config_from_env_requires_all_values() {
        std::env::remove_var("NPM_HOST");
        std::env::remove_var("NPM_EMAIL");
        std::env::remove_var("NPM_PASSWORD");

        assert!(NpmConfig::from_env().is_none());

        std::env::set_var("NPM_HOST", "http://npm.local");
        std::env::set_var("NPM_EMAIL", "ops@example.com");
        std::env::set_var("NPM_PASSWORD", "secret");

        let config = NpmConfig::from_env().expect("env-backed config");
        assert_eq!(config.host, "http://npm.local");
        assert_eq!(config.email, "ops@example.com");
        assert_eq!(config.password, "secret");
    }

    #[test]
    fn npm_config_normalizes_legacy_underscore_internal_host() {
        let config = NpmConfig::new(
            "http://nginx_proxy_manager:81".to_string(),
            "ops@example.com".to_string(),
            "secret".to_string(),
        );

        assert_eq!(config.host, "http://nginx-proxy-manager:81");
    }

    #[test]
    fn test_proxy_host_request_serialization() {
        let request = ProxyHostRequest {
            domain_names: vec!["example.com".to_string()],
            forward_host: "app".to_string(),
            forward_port: 8080,
            ssl_enabled: true,
            ssl_forced: true,
            http2_support: true,
        };

        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(json["forward_port"], 8080);
        assert_eq!(json["domain_names"][0], "example.com");
    }

    #[tokio::test]
    async fn create_proxy_host_includes_letsencrypt_email() {
        let mut server = Server::new_async().await;
        let token_mock = server
            .mock("POST", "/api/tokens")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"token":"token-123"}"#)
            .create_async()
            .await;
        let create_mock = server
            .mock("POST", "/api/nginx/proxy-hosts")
            .match_header("authorization", "Bearer token-123")
            .match_body(Matcher::PartialJson(json!({
                "domain_names": ["app.example.com"],
                "certificate_id": "new",
                "meta": {
                    "letsencrypt_email": "ops@example.com",
                    "letsencrypt_agree": true,
                    "dns_challenge": false
                }
            })))
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":7}"#)
            .create_async()
            .await;

        let mut client = NpmClient::with_credentials(
            server.url(),
            "ops@example.com".to_string(),
            "secret".to_string(),
        );
        let result = client
            .create_proxy_host(&ProxyHostRequest {
                domain_names: vec!["app.example.com".to_string()],
                forward_host: "app".to_string(),
                forward_port: 8080,
                ssl_enabled: true,
                ssl_forced: true,
                http2_support: true,
            })
            .await
            .expect("proxy host should be created");

        assert!(result.success);
        assert_eq!(result.proxy_host_id, Some(7));
        token_mock.assert_async().await;
        create_mock.assert_async().await;
    }

    #[tokio::test]
    async fn create_proxy_host_without_ssl_does_not_request_letsencrypt() {
        let mut server = Server::new_async().await;
        let _token_mock = server
            .mock("POST", "/api/tokens")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"token":"token-123"}"#)
            .create_async()
            .await;
        let create_mock = server
            .mock("POST", "/api/nginx/proxy-hosts")
            .match_body(Matcher::PartialJson(json!({
                "domain_names": ["app.example.com"],
                "certificate_id": null,
                "ssl_forced": false,
                "http2_support": false,
                "meta": {}
            })))
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":8}"#)
            .create_async()
            .await;

        let mut client = NpmClient::with_credentials(
            server.url(),
            "ops@example.com".to_string(),
            "secret".to_string(),
        );
        let result = client
            .create_proxy_host(&ProxyHostRequest {
                domain_names: vec!["app.example.com".to_string()],
                forward_host: "app".to_string(),
                forward_port: 8080,
                ssl_enabled: false,
                ssl_forced: false,
                http2_support: false,
            })
            .await
            .expect("plain HTTP proxy host should be created");

        assert!(result.success);
        assert_eq!(result.proxy_host_id, Some(8));
        create_mock.assert_async().await;
    }

    #[tokio::test]
    async fn create_proxy_host_preserves_npm_error_detail() {
        let mut server = Server::new_async().await;
        let _token_mock = server
            .mock("POST", "/api/tokens")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"token":"token-123"}"#)
            .create_async()
            .await;
        let _create_mock = server
            .mock("POST", "/api/nginx/proxy-hosts")
            .with_status(500)
            .with_header("content-type", "application/json")
            .with_body(r#"{"error":{"message":"Internal Error"}}"#)
            .create_async()
            .await;

        let mut client = NpmClient::with_credentials(
            server.url(),
            "ops@example.com".to_string(),
            "secret".to_string(),
        );
        let result = client
            .create_proxy_host(&ProxyHostRequest {
                domain_names: vec!["app.example.com".to_string()],
                forward_host: "app".to_string(),
                forward_port: 8080,
                ssl_enabled: true,
                ssl_forced: true,
                http2_support: true,
            })
            .await
            .expect("NPM errors should be returned as operation results");

        assert!(!result.success);
        assert_eq!(result.details.as_deref(), Some("Internal Error"));
        assert_eq!(
            result.message,
            "Failed to create proxy host: 500 Internal Server Error - Internal Error"
        );
    }

    #[tokio::test]
    async fn create_proxy_host_adopts_existing_host_after_create_failure() {
        let mut server = Server::new_async().await;
        let _token_mock = server
            .mock("POST", "/api/tokens")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"token":"token-123"}"#)
            .create_async()
            .await;
        let _create_mock = server
            .mock("POST", "/api/nginx/proxy-hosts")
            .with_status(500)
            .with_header("content-type", "application/json")
            .with_body(r#"{"error":{"message":"Internal Error"}}"#)
            .create_async()
            .await;
        let list_mock = server
            .mock("GET", "/api/nginx/proxy-hosts")
            .match_header("authorization", "Bearer token-123")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"[{
                    "id": 9,
                    "domain_names": ["app.example.com"],
                    "forward_host": "app",
                    "forward_port": 8080,
                    "certificate_id": 4,
                    "ssl_forced": true,
                    "http2_support": true
                }]"#,
            )
            .create_async()
            .await;

        let mut client = NpmClient::with_credentials(
            server.url(),
            "ops@example.com".to_string(),
            "secret".to_string(),
        );
        let result = client
            .create_proxy_host(&ProxyHostRequest {
                domain_names: vec!["app.example.com".to_string()],
                forward_host: "app".to_string(),
                forward_port: 8080,
                ssl_enabled: true,
                ssl_forced: true,
                http2_support: true,
            })
            .await
            .expect("existing host should be adopted");

        assert!(result.success);
        assert!(result.adopted);
        assert_eq!(result.proxy_host_id, Some(9));
        assert_eq!(result.ssl_status.as_deref(), Some("enabled"));
        assert_eq!(result.details.as_deref(), Some("Internal Error"));
        list_mock.assert_async().await;
    }

    #[tokio::test]
    async fn create_proxy_host_reports_http_only_adoption_when_ssl_was_requested() {
        let mut server = Server::new_async().await;
        let _token_mock = server
            .mock("POST", "/api/tokens")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"token":"token-123"}"#)
            .create_async()
            .await;
        let _create_mock = server
            .mock("POST", "/api/nginx/proxy-hosts")
            .with_status(500)
            .with_header("content-type", "application/json")
            .with_body(r#"{"error":{"message":"certificate challenge failed"}}"#)
            .create_async()
            .await;
        let _list_mock = server
            .mock("GET", "/api/nginx/proxy-hosts")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"[{
                    "id": 10,
                    "domain_names": ["app.example.com"],
                    "forward_host": "app",
                    "forward_port": 8080,
                    "certificate_id": null,
                    "ssl_forced": false,
                    "http2_support": false
                }]"#,
            )
            .create_async()
            .await;

        let mut client = NpmClient::with_credentials(
            server.url(),
            "ops@example.com".to_string(),
            "secret".to_string(),
        );
        let result = client
            .create_proxy_host(&ProxyHostRequest {
                domain_names: vec!["app.example.com".to_string()],
                forward_host: "app".to_string(),
                forward_port: 8080,
                ssl_enabled: true,
                ssl_forced: true,
                http2_support: true,
            })
            .await
            .expect("HTTP-only existing host should be adopted");

        assert!(result.success);
        assert!(result.adopted);
        assert!(!result.ssl_enabled);
        assert_eq!(
            result.ssl_status.as_deref(),
            Some("pending_or_failed_http_only")
        );
        assert!(result.message.contains("adopted existing HTTP route"));
        assert_eq!(
            result.details.as_deref(),
            Some("certificate challenge failed")
        );
    }
}
