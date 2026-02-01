//! Nginx Proxy Manager API client
//!
//! This module provides a client for interacting with the Nginx Proxy Manager API
//! to create, update, and delete proxy hosts programmatically.

use anyhow::{Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

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

impl Default for NpmConfig {
    fn default() -> Self {
        Self {
            host: std::env::var("NPM_HOST")
                .unwrap_or_else(|_| "http://nginx-proxy-manager:81".to_string()),
            email: std::env::var("NPM_EMAIL").unwrap_or_else(|_| "admin@example.com".to_string()),
            password: std::env::var("NPM_PASSWORD").unwrap_or_else(|_| "changeme".to_string()),
        }
    }
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
    pub domain_names: Vec<String>,
    pub forward_host: String,
    pub forward_port: u16,
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
    pub fn from_env() -> Self {
        Self::new(NpmConfig::default())
    }

    /// Create a new NPM client with custom host/credentials
    pub fn with_credentials(host: String, email: String, password: String) -> Self {
        Self::new(NpmConfig {
            host,
            email,
            password,
        })
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
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("NPM authentication failed: {} - {}", status, body);
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
            "meta": {
                "letsencrypt_agree": true,
                "dns_challenge": false
            },
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
        let body: Value = response.json().await.unwrap_or(json!({}));

        if status.is_success() {
            let proxy_host_id = body["id"].as_i64();
            tracing::info!(proxy_host_id = ?proxy_host_id, "Proxy host created successfully");

            Ok(ProxyHostResult {
                success: true,
                proxy_host_id,
                message: "Proxy host created successfully".to_string(),
                domain_names: request.domain_names.clone(),
                forward_host: request.forward_host.clone(),
                forward_port: request.forward_port,
            })
        } else {
            let message = format!("Failed to create proxy host: {} - {:?}", status, body);
            tracing::error!(%message);

            Ok(ProxyHostResult {
                success: false,
                proxy_host_id: None,
                message,
                domain_names: request.domain_names.clone(),
                forward_host: request.forward_host.clone(),
                forward_port: request.forward_port,
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
                    domain_names: domain_names.to_vec(),
                    forward_host,
                    forward_port,
                })
            } else {
                let status = delete_response.status();
                let body = delete_response.text().await.unwrap_or_default();
                let message = format!("Failed to delete proxy host: {} - {}", status, body);

                Ok(ProxyHostResult {
                    success: false,
                    proxy_host_id: Some(host_id),
                    message,
                    domain_names: domain_names.to_vec(),
                    forward_host,
                    forward_port,
                })
            }
        } else {
            // No matching proxy host found - consider it success (idempotent)
            tracing::warn!(domains = ?domain_names, "No matching proxy host found to delete");

            Ok(ProxyHostResult {
                success: true,
                proxy_host_id: None,
                message: "No matching proxy host found (already deleted?)".to_string(),
                domain_names: domain_names.to_vec(),
                forward_host: String::new(),
                forward_port: 0,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_npm_config_default() {
        let config = NpmConfig::default();
        assert!(config.host.contains("nginx-proxy-manager"));
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
}
