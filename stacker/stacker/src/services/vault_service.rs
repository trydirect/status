//! Vault Service for managing app configurations
//!
//! This service provides access to HashiCorp Vault for:
//! - Storing and retrieving app configuration files
//! - Managing secrets per deployment/app
//!
//! Vault Path Template: {prefix}/{deployment_hash}/apps/{app_name}/config

use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

const REQUEST_TIMEOUT_SECS: u64 = 10;

/// App configuration stored in Vault
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    /// Configuration file content (JSON, YAML, or raw text)
    pub content: String,
    /// Content type: "json", "yaml", "env", "text"
    pub content_type: String,
    /// Target file path on the deployment server
    pub destination_path: String,
    /// File permissions (e.g., "0644")
    #[serde(default = "default_file_mode")]
    pub file_mode: String,
    /// Optional: owner user
    pub owner: Option<String>,
    /// Optional: owner group
    pub group: Option<String>,
}

fn default_file_mode() -> String {
    "0644".to_string()
}

/// Vault KV response envelope
#[derive(Debug, Deserialize)]
struct VaultKvResponse {
    #[serde(default)]
    data: VaultKvData,
}

#[derive(Debug, Deserialize, Default)]
struct VaultKvData {
    #[serde(default)]
    data: HashMap<String, serde_json::Value>,
    #[serde(default)]
    #[allow(dead_code)]
    metadata: Option<VaultMetadata>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct VaultMetadata {
    pub created_time: Option<String>,
    pub version: Option<u64>,
}

/// Vault client for app configuration management
#[derive(Clone)]
pub struct VaultService {
    base_url: String,
    token: String,
    prefix: String,
    http_client: Client,
}

#[derive(Debug)]
pub enum VaultError {
    NotConfigured,
    ConnectionFailed(String),
    NotFound(String),
    Forbidden(String),
    Other(String),
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultError::NotConfigured => write!(f, "Vault not configured"),
            VaultError::ConnectionFailed(msg) => write!(f, "Vault connection failed: {}", msg),
            VaultError::NotFound(path) => write!(f, "Config not found: {}", path),
            VaultError::Forbidden(msg) => write!(f, "Vault access denied: {}", msg),
            VaultError::Other(msg) => write!(f, "Vault error: {}", msg),
        }
    }
}

impl std::error::Error for VaultError {}

impl VaultService {
    /// Create a new Vault service from VaultSettings (configuration.yaml)
    pub fn from_settings(
        settings: &crate::configuration::VaultSettings,
    ) -> Result<Self, VaultError> {
        let http_client = Client::builder()
            .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
            .build()
            .map_err(|e| VaultError::Other(format!("Failed to create HTTP client: {}", e)))?;

        tracing::debug!(
            "Vault service initialized from settings: base_url={}, prefix={}",
            settings.address,
            settings.agent_path_prefix
        );

        Ok(VaultService {
            base_url: settings.address.clone(),
            token: settings.token.clone(),
            prefix: settings.agent_path_prefix.clone(),
            http_client,
        })
    }

    /// Create a new Vault service from environment variables
    ///
    /// Environment variables:
    /// - `VAULT_ADDRESS`: Base URL (e.g., https://vault.try.direct)
    /// - `VAULT_TOKEN`: Authentication token
    /// - `VAULT_CONFIG_PATH_PREFIX`: KV mount/prefix (e.g., secret/debug)
    pub fn from_env() -> Result<Option<Self>, VaultError> {
        let base_url = std::env::var("VAULT_ADDRESS").ok();
        let token = std::env::var("VAULT_TOKEN").ok();
        let prefix = std::env::var("VAULT_CONFIG_PATH_PREFIX")
            .or_else(|_| std::env::var("VAULT_AGENT_PATH_PREFIX"))
            .ok();

        match (base_url, token, prefix) {
            (Some(base), Some(tok), Some(pref)) => {
                let http_client = Client::builder()
                    .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
                    .build()
                    .map_err(|e| {
                        VaultError::Other(format!("Failed to create HTTP client: {}", e))
                    })?;

                tracing::debug!("Vault service initialized with base_url={}", base);

                Ok(Some(VaultService {
                    base_url: base,
                    token: tok,
                    prefix: pref,
                    http_client,
                }))
            }
            _ => {
                tracing::debug!("Vault not configured (missing VAULT_ADDRESS, VAULT_TOKEN, or VAULT_CONFIG_PATH_PREFIX)");
                Ok(None)
            }
        }
    }

    /// Build the Vault path for app configuration
    /// For KV v1 API: {base}/v1/{prefix}/{deployment_hash}/apps/{app_code}/{config_type}
    /// The prefix already includes the mount (e.g., "secret/debug/status_panel")
    /// app_name format:
    ///   "{app_code}" for compose
    ///   "{app_code}_config" for single app config file (legacy)
    ///   "{app_code}_configs" for bundled config files (JSON array)
    ///   "{app_code}_env" for .env files
    fn config_path(&self, deployment_hash: &str, app_name: &str) -> String {
        // Parse app_name to determine app_code and config_type
        // "telegraf" -> apps/telegraf/_compose
        // "telegraf_config" -> apps/telegraf/_config (legacy single config)
        // "telegraf_configs" -> apps/telegraf/_configs (bundled config files)
        // "telegraf_env" -> apps/telegraf/_env (for .env files)
        // "_compose" -> apps/_compose (legacy global compose)
        let (app_code, config_type) = if app_name == "_compose" {
            ("_compose".to_string(), "_compose".to_string())
        } else if let Some(app_code) = app_name.strip_suffix("_env") {
            (app_code.to_string(), "_env".to_string())
        } else if let Some(app_code) = app_name.strip_suffix("_configs") {
            (app_code.to_string(), "_configs".to_string())
        } else if let Some(app_code) = app_name.strip_suffix("_config") {
            (app_code.to_string(), "_config".to_string())
        } else {
            (app_name.to_string(), "_compose".to_string())
        };

        format!(
            "{}/v1/{}/{}/apps/{}/{}",
            self.base_url, self.prefix, deployment_hash, app_code, config_type
        )
    }

    fn secret_url(&self, logical_path: &str) -> String {
        format!(
            "{}/v1/{}",
            self.base_url.trim_end_matches('/'),
            logical_path.trim_matches('/')
        )
    }

    pub fn service_secret_path(
        &self,
        user_id: &str,
        project_id: i32,
        app_code: &str,
        name: &str,
    ) -> String {
        format!(
            "{}/users/{}/projects/{}/apps/{}/secrets/{}",
            self.prefix.trim_matches('/'),
            user_id,
            project_id,
            app_code,
            name
        )
    }

    pub fn server_secret_path(&self, user_id: &str, server_id: i32, name: &str) -> String {
        format!(
            "{}/users/{}/servers/{}/secrets/{}",
            self.prefix.trim_matches('/'),
            user_id,
            server_id,
            name
        )
    }

    pub fn status_panel_npm_credentials_path(&self, server_id: i32) -> String {
        format!(
            "{}/hosts/{}/npm_credentials",
            self.prefix.trim_matches('/'),
            server_id
        )
    }

    pub async fn fetch_secret_value(&self, logical_path: &str) -> Result<String, VaultError> {
        let response = self
            .http_client
            .get(self.secret_url(logical_path))
            .header("X-Vault-Token", &self.token)
            .send()
            .await
            .map_err(|e| VaultError::ConnectionFailed(e.to_string()))?;

        if response.status() == 404 {
            return Err(VaultError::NotFound(logical_path.to_string()));
        }

        if response.status() == 403 {
            return Err(VaultError::Forbidden(logical_path.to_string()));
        }

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(VaultError::Other(format!(
                "Vault returned {}: {}",
                status, body
            )));
        }

        let vault_resp: VaultKvResponse = response
            .json()
            .await
            .map_err(|e| VaultError::Other(format!("Failed to parse Vault response: {}", e)))?;

        vault_resp
            .data
            .data
            .get("value")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| VaultError::Other("value not found in Vault response".to_string()))
    }

    pub async fn store_secret_value(
        &self,
        logical_path: &str,
        value: &str,
    ) -> Result<(), VaultError> {
        let payload = serde_json::json!({
            "data": {
                "value": value
            }
        });

        let response = self
            .http_client
            .post(self.secret_url(logical_path))
            .header("X-Vault-Token", &self.token)
            .json(&payload)
            .send()
            .await
            .map_err(|e| VaultError::ConnectionFailed(e.to_string()))?;

        if response.status() == 403 {
            return Err(VaultError::Forbidden(logical_path.to_string()));
        }

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(VaultError::Other(format!(
                "Vault store failed with {}: {}",
                status, body
            )));
        }

        Ok(())
    }

    pub async fn store_structured_secret_value(
        &self,
        logical_path: &str,
        value: &serde_json::Value,
    ) -> Result<(), VaultError> {
        let payload = serde_json::json!({
            "data": value
        });

        let response = self
            .http_client
            .post(self.secret_url(logical_path))
            .header("X-Vault-Token", &self.token)
            .json(&payload)
            .send()
            .await
            .map_err(|e| VaultError::ConnectionFailed(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(VaultError::Other(format!(
                "Failed to store secret at {}: {} - {}",
                logical_path, status, body
            )));
        }

        Ok(())
    }

    pub async fn delete_secret_value(&self, logical_path: &str) -> Result<(), VaultError> {
        let response = self
            .http_client
            .delete(self.secret_url(logical_path))
            .header("X-Vault-Token", &self.token)
            .send()
            .await
            .map_err(|e| VaultError::ConnectionFailed(e.to_string()))?;

        if response.status() == 404 || response.status() == 204 {
            return Ok(());
        }

        if response.status() == 403 {
            return Err(VaultError::Forbidden(logical_path.to_string()));
        }

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(VaultError::Other(format!(
                "Vault delete failed with {}: {}",
                status, body
            )));
        }

        Ok(())
    }

    /// Fetch app configuration from Vault
    pub async fn fetch_app_config(
        &self,
        deployment_hash: &str,
        app_name: &str,
    ) -> Result<AppConfig, VaultError> {
        let url = self.config_path(deployment_hash, app_name);

        tracing::debug!("Fetching app config from Vault: {}", url);

        let response = self
            .http_client
            .get(&url)
            .header("X-Vault-Token", &self.token)
            .send()
            .await
            .map_err(|e| VaultError::ConnectionFailed(e.to_string()))?;

        if response.status() == 404 {
            return Err(VaultError::NotFound(format!(
                "{}/{}",
                deployment_hash, app_name
            )));
        }

        if response.status() == 403 {
            return Err(VaultError::Forbidden(format!(
                "{}/{}",
                deployment_hash, app_name
            )));
        }

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(VaultError::Other(format!(
                "Vault returned {}: {}",
                status, body
            )));
        }

        let vault_resp: VaultKvResponse = response
            .json()
            .await
            .map_err(|e| VaultError::Other(format!("Failed to parse Vault response: {}", e)))?;

        let data = &vault_resp.data.data;

        let content = data
            .get("content")
            .and_then(|v| v.as_str())
            .ok_or_else(|| VaultError::Other("content not found in Vault response".into()))?
            .to_string();

        let content_type = data
            .get("content_type")
            .and_then(|v| v.as_str())
            .unwrap_or("text")
            .to_string();

        let destination_path = data
            .get("destination_path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                VaultError::Other("destination_path not found in Vault response".into())
            })?
            .to_string();

        let file_mode = data
            .get("file_mode")
            .and_then(|v| v.as_str())
            .unwrap_or("0644")
            .to_string();

        let owner = data
            .get("owner")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let group = data
            .get("group")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        tracing::info!(
            "Fetched config for {}/{} from Vault (type: {}, dest: {})",
            deployment_hash,
            app_name,
            content_type,
            destination_path
        );

        Ok(AppConfig {
            content,
            content_type,
            destination_path,
            file_mode,
            owner,
            group,
        })
    }

    /// Store app configuration in Vault
    pub async fn store_app_config(
        &self,
        deployment_hash: &str,
        app_name: &str,
        config: &AppConfig,
    ) -> Result<(), VaultError> {
        let url = self.config_path(deployment_hash, app_name);

        tracing::debug!("Storing app config in Vault: {}", url);

        let payload = serde_json::json!({
            "data": {
                "content": config.content,
                "content_type": config.content_type,
                "destination_path": config.destination_path,
                "file_mode": config.file_mode,
                "owner": config.owner,
                "group": config.group,
            }
        });

        let response = self
            .http_client
            .post(&url)
            .header("X-Vault-Token", &self.token)
            .json(&payload)
            .send()
            .await
            .map_err(|e| VaultError::ConnectionFailed(e.to_string()))?;

        if response.status() == 403 {
            return Err(VaultError::Forbidden(format!(
                "{}/{}",
                deployment_hash, app_name
            )));
        }

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(VaultError::Other(format!(
                "Vault store failed with {}: {}",
                status, body
            )));
        }

        tracing::info!(
            "Config stored in Vault for {}/{} (dest: {})",
            deployment_hash,
            app_name,
            config.destination_path
        );

        Ok(())
    }

    /// List all app configs for a deployment
    pub async fn list_app_configs(&self, deployment_hash: &str) -> Result<Vec<String>, VaultError> {
        let url = format!(
            "{}/v1/{}/{}/apps",
            self.base_url, self.prefix, deployment_hash
        );

        tracing::debug!("Listing app configs from Vault: {}", url);

        // Vault uses LIST method for listing keys
        let response = self
            .http_client
            .request(
                reqwest::Method::from_bytes(b"LIST").unwrap_or(reqwest::Method::GET),
                &url,
            )
            .header("X-Vault-Token", &self.token)
            .send()
            .await
            .map_err(|e| VaultError::ConnectionFailed(e.to_string()))?;

        if response.status() == 404 {
            // No configs exist yet
            return Ok(vec![]);
        }

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(VaultError::Other(format!(
                "Vault list failed with {}: {}",
                status, body
            )));
        }

        #[derive(Deserialize)]
        struct ListResponse {
            data: ListData,
        }

        #[derive(Deserialize)]
        struct ListData {
            keys: Vec<String>,
        }

        let list_resp: ListResponse = response
            .json()
            .await
            .map_err(|e| VaultError::Other(format!("Failed to parse list response: {}", e)))?;

        // Filter to only include app names (not subdirectories)
        let apps: Vec<String> = list_resp
            .data
            .keys
            .into_iter()
            .filter(|k| !k.ends_with('/'))
            .collect();

        tracing::info!(
            "Found {} app configs for deployment {}",
            apps.len(),
            deployment_hash
        );
        Ok(apps)
    }

    /// Delete app configuration from Vault
    pub async fn delete_app_config(
        &self,
        deployment_hash: &str,
        app_name: &str,
    ) -> Result<(), VaultError> {
        let url = self.config_path(deployment_hash, app_name);

        tracing::debug!("Deleting app config from Vault: {}", url);

        let response = self
            .http_client
            .delete(&url)
            .header("X-Vault-Token", &self.token)
            .send()
            .await
            .map_err(|e| VaultError::ConnectionFailed(e.to_string()))?;

        if !response.status().is_success() && response.status() != 204 {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            tracing::warn!(
                "Vault delete returned status {}: {} (may still be deleted)",
                status,
                body
            );
        }

        tracing::info!(
            "Config deleted from Vault for {}/{}",
            deployment_hash,
            app_name
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Helper to extract config path components without creating a full VaultService
    fn parse_app_name(app_name: &str) -> (String, String) {
        if app_name == "_compose" {
            ("_compose".to_string(), "_compose".to_string())
        } else if let Some(app_code) = app_name.strip_suffix("_env") {
            (app_code.to_string(), "_env".to_string())
        } else if let Some(app_code) = app_name.strip_suffix("_configs") {
            (app_code.to_string(), "_configs".to_string())
        } else if let Some(app_code) = app_name.strip_suffix("_config") {
            (app_code.to_string(), "_config".to_string())
        } else {
            (app_name.to_string(), "_compose".to_string())
        }
    }

    #[test]
    fn test_config_path_parsing_compose() {
        // Plain app_code maps to _compose
        let (app_code, config_type) = parse_app_name("telegraf");
        assert_eq!(app_code, "telegraf");
        assert_eq!(config_type, "_compose");

        let (app_code, config_type) = parse_app_name("komodo");
        assert_eq!(app_code, "komodo");
        assert_eq!(config_type, "_compose");
    }

    #[test]
    fn test_config_path_parsing_env() {
        // _env suffix maps to _env config type
        let (app_code, config_type) = parse_app_name("telegraf_env");
        assert_eq!(app_code, "telegraf");
        assert_eq!(config_type, "_env");

        let (app_code, config_type) = parse_app_name("komodo_env");
        assert_eq!(app_code, "komodo");
        assert_eq!(config_type, "_env");
    }

    #[test]
    fn test_config_path_parsing_configs_bundle() {
        // _configs suffix maps to _configs config type (bundled config files)
        let (app_code, config_type) = parse_app_name("telegraf_configs");
        assert_eq!(app_code, "telegraf");
        assert_eq!(config_type, "_configs");

        let (app_code, config_type) = parse_app_name("komodo_configs");
        assert_eq!(app_code, "komodo");
        assert_eq!(config_type, "_configs");
    }

    #[test]
    fn test_config_path_parsing_single_config() {
        // _config suffix maps to _config config type (legacy single config)
        let (app_code, config_type) = parse_app_name("telegraf_config");
        assert_eq!(app_code, "telegraf");
        assert_eq!(config_type, "_config");

        let (app_code, config_type) = parse_app_name("nginx_config");
        assert_eq!(app_code, "nginx");
        assert_eq!(config_type, "_config");
    }

    #[test]
    fn test_config_path_parsing_global_compose() {
        // Special _compose key
        let (app_code, config_type) = parse_app_name("_compose");
        assert_eq!(app_code, "_compose");
        assert_eq!(config_type, "_compose");
    }

    #[test]
    fn test_config_path_suffix_priority() {
        // Ensure _env is checked before _config (since _env_config would be wrong)
        // This shouldn't happen in practice, but tests parsing priority
        let (app_code, config_type) = parse_app_name("test_env");
        assert_eq!(app_code, "test");
        assert_eq!(config_type, "_env");

        // _configs takes priority over _config for apps named like "my_configs"
        let (app_code, config_type) = parse_app_name("my_configs");
        assert_eq!(app_code, "my");
        assert_eq!(config_type, "_configs");
    }

    #[test]
    fn test_app_config_serialization() {
        let config = AppConfig {
            content: "FOO=bar\nBAZ=qux".to_string(),
            content_type: "env".to_string(),
            destination_path: "/home/trydirect/abc123/telegraf.env".to_string(),
            file_mode: "0640".to_string(),
            owner: Some("trydirect".to_string()),
            group: Some("docker".to_string()),
        };

        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("FOO=bar"));
        assert!(json.contains("telegraf.env"));
        assert!(json.contains("0640"));
    }

    #[test]
    fn test_config_bundle_json_format() {
        // Test that bundled configs can be serialized and deserialized
        let configs: Vec<serde_json::Value> = vec![
            serde_json::json!({
                "name": "telegraf.conf",
                "content": "[agent]\n  interval = \"10s\"",
                "content_type": "text/plain",
                "destination_path": "/home/trydirect/abc123/config/telegraf.conf",
                "file_mode": "0644",
                "owner": null,
                "group": null,
            }),
            serde_json::json!({
                "name": "nginx.conf",
                "content": "server { }",
                "content_type": "text/plain",
                "destination_path": "/home/trydirect/abc123/config/nginx.conf",
                "file_mode": "0644",
                "owner": null,
                "group": null,
            }),
        ];

        let bundle_json = serde_json::to_string(&configs).unwrap();

        // Parse back
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&bundle_json).unwrap();
        assert_eq!(parsed.len(), 2);

        let names: Vec<&str> = parsed
            .iter()
            .filter_map(|c| c.get("name").and_then(|n| n.as_str()))
            .collect();
        assert!(names.contains(&"telegraf.conf"));
        assert!(names.contains(&"nginx.conf"));
    }

    fn test_vault_service(server: &MockServer) -> VaultService {
        VaultService {
            base_url: server.uri(),
            token: "test-token".to_string(),
            prefix: "agent".to_string(),
            http_client: Client::builder()
                .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
                .build()
                .unwrap(),
        }
    }

    #[test]
    fn test_remote_secret_paths_use_kv_v1_layout() {
        let service = VaultService {
            base_url: "http://vault.example".to_string(),
            token: "test-token".to_string(),
            prefix: "agent".to_string(),
            http_client: Client::builder().build().unwrap(),
        };

        assert_eq!(
            service.service_secret_path("user-1", 42, "web", "S3_KEY"),
            "agent/users/user-1/projects/42/apps/web/secrets/S3_KEY"
        );
        assert_eq!(
            service.server_secret_path("user-1", 99, "HOST_TOKEN"),
            "agent/users/user-1/servers/99/secrets/HOST_TOKEN"
        );
        assert_eq!(
            service.status_panel_npm_credentials_path(99),
            "agent/hosts/99/npm_credentials"
        );
        assert_eq!(
            service.secret_url("agent/users/user-1/projects/42/apps/web/secrets/S3_KEY"),
            "http://vault.example/v1/agent/users/user-1/projects/42/apps/web/secrets/S3_KEY"
        );
    }

    #[tokio::test]
    async fn test_remote_secret_kv_v1_crud_uses_flat_v1_endpoints() {
        let server = MockServer::start().await;
        let service = test_vault_service(&server);
        let logical_path = "agent/users/user-1/projects/42/apps/web/secrets/S3_KEY";

        Mock::given(method("POST"))
            .and(path(
                "/v1/agent/users/user-1/projects/42/apps/web/secrets/S3_KEY",
            ))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path(
                "/v1/agent/users/user-1/projects/42/apps/web/secrets/S3_KEY",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "data": {
                        "value": "supersecret"
                    }
                }
            })))
            .mount(&server)
            .await;

        Mock::given(method("DELETE"))
            .and(path(
                "/v1/agent/users/user-1/projects/42/apps/web/secrets/S3_KEY",
            ))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;

        service
            .store_secret_value(logical_path, "supersecret")
            .await
            .unwrap();
        let fetched = service.fetch_secret_value(logical_path).await.unwrap();
        assert_eq!(fetched, "supersecret");
        service.delete_secret_value(logical_path).await.unwrap();

        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[0].method.to_string(), "POST");
        assert_eq!(requests[1].method.to_string(), "GET");
        assert_eq!(requests[2].method.to_string(), "DELETE");
        assert!(requests
            .iter()
            .all(|request| !request.url.path().contains("/data/")));
        assert!(requests
            .iter()
            .all(|request| !request.url.path().contains("/metadata/")));
    }
}
