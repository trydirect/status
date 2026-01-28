use anyhow::{Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info, warn};

/// Vault KV response envelope for token fetch.
#[derive(Debug, Deserialize)]
struct VaultKvResponse {
    #[serde(default)]
    data: VaultKvData,
}

#[derive(Debug, Deserialize, Default)]
struct VaultKvData {
    #[serde(default)]
    data: VaultTokenData,
}

#[derive(Debug, Deserialize, Default)]
struct VaultTokenData {
    token: Option<String>,
}

/// Vault KV response envelope for config fetch.
#[derive(Debug, Deserialize)]
struct VaultConfigResponse {
    #[serde(default)]
    data: VaultConfigData,
}

#[derive(Debug, Deserialize, Default)]
struct VaultConfigData {
    #[serde(default)]
    data: HashMap<String, serde_json::Value>,
    #[serde(default)]
    #[allow(dead_code)]
    metadata: Option<VaultConfigMetadata>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct VaultConfigMetadata {
    pub created_time: Option<String>,
    pub version: Option<u64>,
}

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

/// Vault client for fetching and managing agent tokens.
#[derive(Debug, Clone)]
pub struct VaultClient {
    base_url: String,
    token: String,
    prefix: String,
    http_client: reqwest::Client,
}

impl VaultClient {
    /// Create a new Vault client from environment variables.
    ///
    /// Environment variables:
    /// - `VAULT_ADDRESS`: Base URL (e.g., http://127.0.0.1:8200)
    /// - `VAULT_TOKEN`: Authentication token
    /// - `VAULT_AGENT_PATH_PREFIX`: KV mount/prefix (e.g., status_panel or kv/status_panel)
    pub fn from_env() -> Result<Option<Self>> {
        let base_url = std::env::var("VAULT_ADDRESS").ok();
        let token = std::env::var("VAULT_TOKEN").ok();
        let prefix = std::env::var("VAULT_AGENT_PATH_PREFIX").ok();

        match (base_url, token, prefix) {
            (Some(base), Some(tok), Some(pref)) => {
                let http_client = Client::builder()
                    .timeout(std::time::Duration::from_secs(10))
                    .build()
                    .context("creating HTTP client")?;

                debug!("Vault client initialized with base_url={}", base);

                Ok(Some(VaultClient {
                    base_url: base,
                    token: tok,
                    prefix: pref,
                    http_client,
                }))
            }
            _ => {
                debug!("Vault not configured (missing VAULT_ADDRESS, VAULT_TOKEN, or VAULT_AGENT_PATH_PREFIX)");
                Ok(None)
            }
        }
    }

    /// Fetch agent token from Vault KV store.
    ///
    /// Constructs path: GET {base_url}/v1/{prefix}/{deployment_hash}/{token_key}
    /// where token_key is "status_panel_token" or "compose_agent_token"
    /// Expects response: {"data":{"data":{"token":"..."}}}
    pub async fn fetch_agent_token(
        &self,
        deployment_hash: &str,
        token_key: Option<&str>,
    ) -> Result<String> {
        let key = token_key.unwrap_or("status_panel_token");
        let url = format!(
            "{}/v1/{}/{}/{}",
            self.base_url, self.prefix, deployment_hash, key
        );

        debug!("Fetching token from Vault: {}", url);

        let response = self
            .http_client
            .get(&url)
            .header("X-Vault-Token", &self.token)
            .send()
            .await
            .context("sending Vault request")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!(
                "Vault fetch failed with status {}: {}",
                status,
                body
            ));
        }

        let vault_resp: VaultKvResponse =
            response.json().await.context("parsing Vault response")?;

        vault_resp
            .data
            .data
            .token
            .context("token not found in Vault response")
    }

    /// Store agent token in Vault KV store (for registration or update).
    ///
    /// Constructs path: POST {base_url}/v1/{prefix}/{deployment_hash}/{token_key}
    /// where token_key is "status_panel_token" or "compose_agent_token"
    pub async fn store_agent_token(
        &self,
        deployment_hash: &str,
        token: &str,
        token_key: Option<&str>,
    ) -> Result<()> {
        let key = token_key.unwrap_or("status_panel_token");
        let url = format!(
            "{}/v1/{}/{}/{}",
            self.base_url, self.prefix, deployment_hash, key
        );

        debug!("Storing token in Vault: {}", url);

        let payload = serde_json::json!({
            "data": {
                "token": token
            }
        });

        let response = self
            .http_client
            .post(&url)
            .header("X-Vault-Token", &self.token)
            .json(&payload)
            .send()
            .await
            .context("sending Vault store request")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!(
                "Vault store failed with status {}: {}",
                status,
                body
            ));
        }

        info!(
            "Token successfully stored in Vault for {} ({})",
            deployment_hash, key
        );
        Ok(())
    }

    /// Delete agent token from Vault KV store (for revocation).
    ///
    /// Constructs path: DELETE {base_url}/v1/{prefix}/{deployment_hash}/{token_key}
    /// where token_key is "status_panel_token" or "compose_agent_token"
    pub async fn delete_agent_token(
        &self,
        deployment_hash: &str,
        token_key: Option<&str>,
    ) -> Result<()> {
        let key = token_key.unwrap_or("status_panel_token");
        let url = format!(
            "{}/v1/{}/{}/{}",
            self.base_url, self.prefix, deployment_hash, key
        );

        debug!("Deleting token from Vault: {}", url);

        let response = self
            .http_client
            .delete(&url)
            .header("X-Vault-Token", &self.token)
            .send()
            .await
            .context("sending Vault delete request")?;

        if !response.status().is_success() && response.status() != 204 {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            warn!(
                "Vault delete returned status {}: {} (may still be deleted)",
                status, body
            );
        }

        info!("Token deleted from Vault for {} ({})", deployment_hash, key);
        Ok(())
    }

    // =========================================================================
    // App Configuration Methods
    // =========================================================================

    /// Build the Vault path for app configuration.
    ///
    /// Path template: {prefix}/{deployment_hash}/apps/{app_name}/config
    fn config_path(&self, deployment_hash: &str, app_name: &str) -> String {
        format!(
            "{}/v1/{}/{}/apps/{}/config",
            self.base_url, self.prefix, deployment_hash, app_name
        )
    }

    /// Fetch app configuration from Vault.
    ///
    /// Returns the AppConfig struct with content, type, and destination path.
    /// Path: GET {base_url}/v1/{prefix}/{deployment_hash}/apps/{app_name}/config
    pub async fn fetch_app_config(
        &self,
        deployment_hash: &str,
        app_name: &str,
    ) -> Result<AppConfig> {
        let url = self.config_path(deployment_hash, app_name);

        debug!("Fetching app config from Vault: {}", url);

        let response = self
            .http_client
            .get(&url)
            .header("X-Vault-Token", &self.token)
            .send()
            .await
            .context("sending Vault config request")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!(
                "Vault config fetch failed with status {}: {}",
                status,
                body
            ));
        }

        let vault_resp: VaultConfigResponse = response
            .json()
            .await
            .context("parsing Vault config response")?;

        // Extract AppConfig from the data map
        let data = &vault_resp.data.data;

        let content = data
            .get("content")
            .and_then(|v| v.as_str())
            .context("config content not found in Vault response")?
            .to_string();

        let content_type = data
            .get("content_type")
            .and_then(|v| v.as_str())
            .unwrap_or("text")
            .to_string();

        let destination_path = data
            .get("destination_path")
            .and_then(|v| v.as_str())
            .context("destination_path not found in Vault response")?
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

        info!(
            "Fetched config for {}/{} from Vault (type: {}, dest: {})",
            deployment_hash, app_name, content_type, destination_path
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

    /// Store app configuration in Vault.
    ///
    /// Path: POST {base_url}/v1/{prefix}/{deployment_hash}/apps/{app_name}/config
    pub async fn store_app_config(
        &self,
        deployment_hash: &str,
        app_name: &str,
        config: &AppConfig,
    ) -> Result<()> {
        let url = self.config_path(deployment_hash, app_name);

        debug!("Storing app config in Vault: {}", url);

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
            .context("sending Vault config store request")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!(
                "Vault config store failed with status {}: {}",
                status,
                body
            ));
        }

        info!(
            "Config stored in Vault for {}/{} (dest: {})",
            deployment_hash, app_name, config.destination_path
        );
        Ok(())
    }

    /// List all app configs for a deployment.
    ///
    /// Path: LIST {base_url}/v1/{prefix}/{deployment_hash}/apps
    /// Returns list of app names that have configurations stored.
    pub async fn list_app_configs(&self, deployment_hash: &str) -> Result<Vec<String>> {
        let url = format!(
            "{}/v1/{}/{}/apps",
            self.base_url, self.prefix, deployment_hash
        );

        debug!("Listing app configs from Vault: {}", url);

        let response = self
            .http_client
            .request(
                reqwest::Method::from_bytes(b"LIST").unwrap_or(reqwest::Method::GET),
                &url,
            )
            .header("X-Vault-Token", &self.token)
            .send()
            .await
            .context("sending Vault list request")?;

        if response.status() == 404 {
            // No configs exist yet
            return Ok(vec![]);
        }

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!(
                "Vault list failed with status {}: {}",
                status,
                body
            ));
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
            .context("parsing Vault list response")?;

        // Filter to only include app names (not subdirectories)
        let apps: Vec<String> = list_resp
            .data
            .keys
            .into_iter()
            .filter(|k| !k.ends_with('/'))
            .collect();

        info!(
            "Found {} app configs for deployment {}",
            apps.len(),
            deployment_hash
        );
        Ok(apps)
    }

    /// Delete app configuration from Vault.
    ///
    /// Path: DELETE {base_url}/v1/{prefix}/{deployment_hash}/apps/{app_name}/config
    pub async fn delete_app_config(&self, deployment_hash: &str, app_name: &str) -> Result<()> {
        let url = self.config_path(deployment_hash, app_name);

        debug!("Deleting app config from Vault: {}", url);

        let response = self
            .http_client
            .delete(&url)
            .header("X-Vault-Token", &self.token)
            .send()
            .await
            .context("sending Vault config delete request")?;

        if !response.status().is_success() && response.status() != 204 {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            warn!(
                "Vault config delete returned status {}: {} (may still be deleted)",
                status, body
            );
        }

        info!(
            "Config deleted from Vault for {}/{}",
            deployment_hash, app_name
        );
        Ok(())
    }

    /// Fetch multiple app configs at once (for deployment).
    ///
    /// Returns a map of app_name -> AppConfig for all specified apps.
    pub async fn fetch_all_app_configs(
        &self,
        deployment_hash: &str,
        app_names: &[String],
    ) -> Result<HashMap<String, AppConfig>> {
        let mut configs = HashMap::new();

        for app_name in app_names {
            match self.fetch_app_config(deployment_hash, app_name).await {
                Ok(config) => {
                    configs.insert(app_name.clone(), config);
                }
                Err(e) => {
                    warn!(
                        "Failed to fetch config for {}/{}: {}",
                        deployment_hash, app_name, e
                    );
                    // Continue fetching other configs, don't fail the entire operation
                }
            }
        }

        Ok(configs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_client_from_env_missing() {
        // Clear env vars if set
        std::env::remove_var("VAULT_ADDRESS");
        std::env::remove_var("VAULT_TOKEN");
        std::env::remove_var("VAULT_AGENT_PATH_PREFIX");

        let result = VaultClient::from_env();
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }
}
