use anyhow::{Result, Context};
use reqwest::Client;
use serde::{Deserialize};
use tracing::{debug, warn, info};

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
    /// Constructs path: GET {base_url}/v1/{prefix}/{deployment_hash}/token
    /// Expects response: {"data":{"data":{"token":"..."}}}
    pub async fn fetch_agent_token(&self, deployment_hash: &str) -> Result<String> {
        let url = format!(
            "{}/v1/{}/{}/token",
            self.base_url, self.prefix, deployment_hash
        );

        debug!("Fetching token from Vault: {}", url);

        let response = self.http_client
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

        let vault_resp: VaultKvResponse = response
            .json()
            .await
            .context("parsing Vault response")?;

        vault_resp
            .data
            .data
            .token
            .context("token not found in Vault response")
    }

    /// Store agent token in Vault KV store (for registration or update).
    /// 
    /// Constructs path: POST {base_url}/v1/{prefix}/{deployment_hash}/token
    pub async fn store_agent_token(
        &self,
        deployment_hash: &str,
        token: &str,
    ) -> Result<()> {
        let url = format!(
            "{}/v1/{}/{}/token",
            self.base_url, self.prefix, deployment_hash
        );

        debug!("Storing token in Vault: {}", url);

        let payload = serde_json::json!({
            "data": {
                "token": token
            }
        });

        let response = self.http_client
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

        info!("Token successfully stored in Vault for {}", deployment_hash);
        Ok(())
    }

    /// Delete agent token from Vault KV store (for revocation).
    pub async fn delete_agent_token(&self, deployment_hash: &str) -> Result<()> {
        let url = format!(
            "{}/v1/{}/{}/token",
            self.base_url, self.prefix, deployment_hash
        );

        debug!("Deleting token from Vault: {}", url);

        let response = self.http_client
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

        info!("Token deleted from Vault for {}", deployment_hash);
        Ok(())
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
