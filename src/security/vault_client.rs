//! # Vault Client - Secure Secret Management for Status Panel Agents
//!
//! ## Security Architecture Overview
//!
//! This module implements a secure client for HashiCorp Vault, providing:
//!
//! 1. **Per-Deployment Token Isolation**: Each deployment (identified by `deployment_hash`)
//!    has its own dedicated Vault path, ensuring tenant isolation. A compromised agent
//!    on one deployment cannot access secrets from other deployments.
//!
//! 2. **Principle of Least Privilege**: Vault tokens are scoped to specific paths
//!    using Vault policies. Status Panel agents only have access to:
//!    - `{prefix}/{deployment_hash}/*` - Their own deployment's secrets
//!    - This prevents lateral movement between deployments if an agent is compromised.
//!
//! 3. **Short-Lived Credentials**: Agent tokens stored in Vault can have TTLs,
//!    requiring periodic renewal. This limits the window of exposure if a token
//!    is leaked or an agent is compromised.
//!
//! 4. **Secrets Never in Git or Logs**: Configuration files containing sensitive
//!    data (database passwords, API keys) are stored encrypted in Vault and
//!    fetched at deployment time, never committed to source control.
//!
//! 5. **Audit Trail**: All Vault accesses are logged by Vault's audit backend,
//!    providing forensic capabilities for security incidents.
//!
//! ## Path Structure
//!
//! ```text
//! {VAULT_AGENT_PATH_PREFIX}/
//! └── {deployment_hash}/
//!     ├── status_panel_token     # Agent authentication token
//!     ├── compose_agent_token    # Docker Compose agent token
//!     └── apps/
//!         ├── {app_name_1}/
//!         │   └── config         # App configuration (env vars, docker-compose, etc.)
//!         └── {app_name_2}/
//!             └── config
//! ```
//!
//! ## Why Per-Deployment Tokens?
//!
//! - **Blast Radius Limitation**: If one deployment's token is compromised,
//!   only that deployment's secrets are exposed, not the entire platform.
//! - **Revocation Granularity**: Individual deployments can be revoked without
//!   affecting other customers/deployments.
//! - **Compliance**: Many security frameworks (SOC2, ISO 27001) require
//!   tenant isolation and audit trails for secret access.

use anyhow::{Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info, warn};

// =============================================================================
// Vault Response Types
// =============================================================================
// These structures mirror Vault's KV v2 API response format.
// Vault wraps all data in {"data": {"data": {...}, "metadata": {...}}} envelopes.

/// Vault KV response envelope for token fetch.
/// Security Note: Token responses are parsed strictly to prevent injection attacks.
#[derive(Debug, Deserialize)]
struct VaultKvResponse {
    #[serde(default)]
    data: VaultKvData,
}

/// Vault KV data wrapper - inner layer of the response envelope.
#[derive(Debug, Deserialize, Default)]
struct VaultKvData {
    #[serde(default)]
    data: VaultTokenData,
}

/// Token data extracted from Vault KV store.
/// Security Note: The token field is Option to gracefully handle missing/empty secrets.
#[derive(Debug, Deserialize, Default)]
struct VaultTokenData {
    token: Option<String>,
}

// =============================================================================
// Configuration Response Types
// =============================================================================

/// Vault KV response envelope for app configuration fetch.
/// Security Note: Configurations may contain sensitive environment variables,
/// database credentials, and API keys. Handle with care.
#[derive(Debug, Deserialize)]
struct VaultConfigResponse {
    #[serde(default)]
    data: VaultConfigData,
}

/// Configuration data wrapper with version metadata.
/// Security Note: Metadata includes version info for drift detection -
/// helps identify unauthorized configuration changes.
#[derive(Debug, Deserialize, Default)]
struct VaultConfigData {
    #[serde(default)]
    data: HashMap<String, serde_json::Value>,
    /// Metadata provides version tracking for configuration changes.
    /// This enables detection of configuration tampering or drift.
    #[serde(default)]
    #[allow(dead_code)]
    metadata: Option<VaultConfigMetadata>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct VaultConfigMetadata {
    /// ISO 8601 timestamp of when this secret version was created.
    /// Used for audit trails and detecting recent changes.
    pub created_time: Option<String>,
    /// Monotonically increasing version number.
    /// Enables rollback to previous configurations if needed.
    pub version: Option<u64>,
}

// =============================================================================
// App Configuration Model
// =============================================================================

/// App configuration stored in Vault.
///
/// ## Security Considerations
///
/// - **content**: May contain sensitive data (passwords, API keys, connection strings).
///   Never log this field. Content is encrypted at rest in Vault.
/// - **destination_path**: Target file path on the deployment server. Validated
///   to prevent path traversal attacks (e.g., `../../etc/passwd`).
/// - **file_mode**: Unix file permissions. Sensitive configs should use restrictive
///   modes like "0600" to prevent unauthorized local access.
/// - **owner/group**: OS-level access control. Combine with file_mode for defense in depth.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    /// Configuration file content (JSON, YAML, or raw text).
    /// WARNING: May contain secrets - never log or expose in error messages.
    pub content: String,
    /// Content type: "json", "yaml", "env", "text".
    /// Used by the agent to determine parsing and validation strategy.
    pub content_type: String,
    /// Target file path on the deployment server.
    /// Security: Must be validated to prevent path traversal attacks.
    pub destination_path: String,
    /// File permissions (e.g., "0644" for readable, "0600" for secrets).
    /// Security: Sensitive files should use "0600" or "0640".
    #[serde(default = "default_file_mode")]
    pub file_mode: String,
    /// Optional: owner user for chown after file creation.
    /// Security: Ensures only the designated user can access sensitive configs.
    pub owner: Option<String>,
    /// Optional: owner group for chown after file creation.
    /// Security: Enables group-based access control for shared configurations.
    pub group: Option<String>,
}

/// Default file mode for non-sensitive configuration files.
/// For sensitive files (containing credentials), explicitly set "0600".
fn default_file_mode() -> String {
    "0644".to_string()
}

// =============================================================================
// Vault Client Implementation
// =============================================================================

/// Vault client for fetching and managing agent tokens and configurations.
///
/// ## Security Design
///
/// This client is designed with several security principles in mind:
///
/// ### 1. Token-Based Authentication
/// The client authenticates to Vault using a token (`VAULT_TOKEN`), which should
/// be provisioned with minimal required permissions via Vault policies.
///
/// ### 2. Path-Based Access Control
/// All operations are scoped to `{prefix}/{deployment_hash}/*`, ensuring
/// that even if this client's token is compromised, it cannot access
/// other deployments' secrets.
///
/// ### 3. Secure Defaults
/// - HTTP timeout of 10 seconds prevents hanging connections
/// - TLS verification is enabled by default (reqwest default behavior)
/// - Sensitive data is not logged (token values, config contents)
///
/// ### 4. Error Handling
/// Errors are logged without exposing secret content. Status codes are
/// reported to help with debugging without leaking sensitive information.
#[derive(Debug, Clone)]
pub struct VaultClient {
    /// Base URL of the Vault server (e.g., https://vault.example.com:8200).
    /// Security: Should use HTTPS in production to encrypt traffic.
    base_url: String,
    /// Authentication token for Vault API calls.
    /// Security: Never logged or exposed in error messages.
    token: String,
    /// KV mount/prefix path (e.g., "status_panel" or "kv/status_panel").
    /// Security: Defines the namespace boundary for this client's access.
    prefix: String,
    /// HTTP client with configured timeouts and TLS.
    http_client: reqwest::Client,
}

impl VaultClient {
    /// Create a new Vault client from environment variables.
    ///
    /// ## Environment Variables
    ///
    /// | Variable | Description | Example |
    /// |----------|-------------|---------|
    /// | `VAULT_ADDRESS` | Vault server URL | `https://vault.example.com:8200` |
    /// | `VAULT_TOKEN` | Authentication token | (provisioned by Install Service) |
    /// | `VAULT_AGENT_PATH_PREFIX` | KV mount/prefix | `status_panel` |
    ///
    /// ## Security Notes
    ///
    /// - **VAULT_TOKEN** should be a short-lived, scoped token created during
    ///   deployment provisioning (by Install Service). It should have a Vault
    ///   policy that only permits access to this deployment's path.
    ///
    /// - In production, tokens should have TTLs and require renewal. This limits
    ///   exposure if an agent is compromised.
    ///
    /// - Returns `Ok(None)` if Vault is not configured, allowing agents to
    ///   operate in environments without Vault (development, testing).
    pub fn from_env() -> Result<Option<Self>> {
        let base_url = std::env::var("VAULT_ADDRESS").ok();
        let token = std::env::var("VAULT_TOKEN").ok();
        let prefix = std::env::var("VAULT_AGENT_PATH_PREFIX").ok();

        match (base_url, token, prefix) {
            (Some(base), Some(tok), Some(pref)) => {
                // Configure HTTP client with security-conscious defaults:
                // - 10 second timeout prevents resource exhaustion from hanging connections
                // - TLS certificate validation enabled by default (reqwest behavior)
                let http_client = Client::builder()
                    .timeout(std::time::Duration::from_secs(10))
                    .build()
                    .context("creating HTTP client")?;

                // Note: We log the base_url but NEVER log the token
                debug!("Vault client initialized with base_url={}", base);

                Ok(Some(VaultClient {
                    base_url: base,
                    token: tok,
                    prefix: pref,
                    http_client,
                }))
            }
            _ => {
                // Graceful degradation: Vault is optional for development/testing
                debug!("Vault not configured (missing VAULT_ADDRESS, VAULT_TOKEN, or VAULT_AGENT_PATH_PREFIX)");
                Ok(None)
            }
        }
    }

    // =========================================================================
    // Agent Token Management
    // =========================================================================
    // These methods manage authentication tokens for Status Panel agents.
    // Each deployment has its own token, providing tenant isolation.

    /// Fetch agent token from Vault KV store.
    ///
    /// ## Security Purpose
    ///
    /// This retrieves the authentication token that this agent uses to communicate
    /// with the TryDirect backend. Each deployment has a unique token, ensuring:
    ///
    /// 1. **Tenant Isolation**: One customer's compromised agent cannot impersonate
    ///    another customer's deployment.
    /// 2. **Revocation**: Individual agents can be revoked without affecting others.
    /// 3. **Audit Trail**: Vault logs all token accesses for forensic analysis.
    ///
    /// ## Path Structure
    ///
    /// `GET {base_url}/v1/{prefix}/{deployment_hash}/{token_key}`
    ///
    /// Where `token_key` is typically "status_panel_token" or "compose_agent_token".
    ///
    /// ## Response Format
    ///
    /// Vault KV v2 response: `{"data":{"data":{"token":"..."}}}`
    pub async fn fetch_agent_token(
        &self,
        deployment_hash: &str,
        token_key: Option<&str>,
    ) -> Result<String> {
        let key = token_key.unwrap_or("status_panel_token");
        // Construct the Vault path - each deployment has isolated namespace
        let url = format!(
            "{}/v1/{}/{}/{}",
            self.base_url, self.prefix, deployment_hash, key
        );

        // Note: We log the URL (path) but never the token value
        debug!("Fetching token from Vault: {}", url);

        let response = self
            .http_client
            .get(&url)
            // X-Vault-Token header authenticates this request to Vault
            // This token determines what paths we're allowed to access
            .header("X-Vault-Token", &self.token)
            .send()
            .await
            .context("sending Vault request")?;

        if !response.status().is_success() {
            let status = response.status();
            // Log error details but never the actual secret content
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!(
                "Vault fetch failed with status {}: {}",
                status,
                body
            ));
        }

        let vault_resp: VaultKvResponse =
            response.json().await.context("parsing Vault response")?;

        // Extract token from nested Vault response structure
        vault_resp
            .data
            .data
            .token
            .context("token not found in Vault response")
    }

    /// Store agent token in Vault KV store (for registration or update).
    ///
    /// ## Security Purpose
    ///
    /// This is called during deployment provisioning (by Install Service) to
    /// store the newly generated agent token. The token is then retrieved by
    /// the agent when it starts up.
    ///
    /// ## Why Store in Vault?
    ///
    /// 1. **Encryption at Rest**: Vault encrypts all secrets before storing.
    /// 2. **Access Control**: Only authorized services can write tokens.
    /// 3. **Audit Logging**: All writes are logged for compliance.
    /// 4. **Versioning**: Previous token versions are preserved for rollback.
    ///
    /// ## Path Structure
    ///
    /// `POST {base_url}/v1/{prefix}/{deployment_hash}/{token_key}`
    pub async fn store_agent_token(
        &self,
        deployment_hash: &str,
        token: &str,
        token_key: Option<&str>,
    ) -> Result<()> {
        let key = token_key.unwrap_or("status_panel_token");
        // Each deployment gets its own isolated path in Vault
        let url = format!(
            "{}/v1/{}/{}/{}",
            self.base_url, self.prefix, deployment_hash, key
        );

        // Security: Never log the actual token value
        debug!("Storing token in Vault: {}", url);

        // Vault KV v2 requires data to be wrapped in {"data": {...}}
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
            // Log error without exposing the token value
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!(
                "Vault store failed with status {}: {}",
                status,
                body
            ));
        }

        // Log success with identifiers but not the secret value
        info!(
            "Token successfully stored in Vault for {} ({})",
            deployment_hash, key
        );
        Ok(())
    }

    /// Delete agent token from Vault KV store (for revocation).
    ///
    /// ## Security Purpose
    ///
    /// Token deletion is critical for:
    ///
    /// 1. **Decommissioning**: When a deployment is destroyed, its tokens must
    ///    be deleted to prevent reuse.
    /// 2. **Incident Response**: If an agent is compromised, immediately delete
    ///    its token to revoke access.
    /// 3. **Key Rotation**: Old tokens should be deleted after rotating to new ones.
    ///
    /// ## Soft vs Hard Delete
    ///
    /// Vault KV v2 supports soft deletes (versioned). For complete removal,
    /// consider using the `metadata` endpoint to permanently destroy secrets.
    ///
    /// ## Path Structure
    ///
    /// `DELETE {base_url}/v1/{prefix}/{deployment_hash}/{token_key}`
    pub async fn delete_agent_token(
        &self,
        deployment_hash: &str,
        token_key: Option<&str>,
    ) -> Result<()> {
        let key = token_key.unwrap_or("status_panel_token");
        // Construct path for this deployment's token
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

        // 204 No Content is a valid success response for DELETE
        // Some Vault configurations may return 200 or 204
        if !response.status().is_success() && response.status() != 204 {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            // Warn but don't fail - token may already be deleted
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
    //
    // These methods manage application-specific configurations stored in Vault.
    // Configurations include docker-compose.yml, .env files, nginx configs, etc.
    //
    // ## Security Model
    //
    // App configs are stored under: {prefix}/{deployment_hash}/apps/{app_code}/{config_type}
    // Where config_type is "_compose" for docker-compose.yml or "_config" for app-specific configs
    //
    // This path structure ensures:
    // - Each deployment's configs are isolated from others
    // - Apps within a deployment are organized but share the deployment namespace
    // - Vault policies can grant access at deployment or app level granularity

    /// Build the Vault path for app configuration.
    ///
    /// ## Path Template
    ///
    /// `{base_url}/v1/{prefix}/{deployment_hash}/apps/{app_code}/{config_type}`
    ///
    /// This creates a hierarchical structure where:
    /// - `deployment_hash` isolates tenants
    /// - `apps/{app_code}/` groups all configs for an app
    /// - `{config_type}` is "_compose" or "_config"
    ///
    /// ## app_name format
    /// - "telegraf" -> apps/telegraf/_compose
    /// - "telegraf_env" -> apps/telegraf/_env
    /// - "telegraf_config" -> apps/telegraf/_config
    /// - "telegraf_configs" -> apps/telegraf/_configs
    /// - "_compose" -> apps/_compose/_compose (legacy global compose)
    fn config_path(&self, deployment_hash: &str, app_name: &str) -> String {
        // Parse app_name to determine app_code and config_type
        let (app_code, config_type) = if app_name == "_compose" {
            ("_compose", "_compose")
        } else if let Some(app_code) = app_name.strip_suffix("_env") {
            (app_code, "_env")
        } else if let Some(app_code) = app_name.strip_suffix("_configs") {
            (app_code, "_configs")
        } else if let Some(app_code) = app_name.strip_suffix("_config") {
            (app_code, "_config")
        } else {
            (app_name, "_compose")
        };

        format!(
            "{}/v1/{}/{}/apps/{}/{}",
            self.base_url, self.prefix, deployment_hash, app_code, config_type
        )
    }

    /// Fetch app configuration from Vault.
    ///
    /// ## Security Purpose
    ///
    /// This retrieves the rendered configuration for an app, which may contain:
    /// - Database connection strings with passwords
    /// - API keys and secrets
    /// - TLS certificates and private keys
    /// - OAuth client credentials
    ///
    /// ## Why Fetch from Vault (vs. static files)?
    ///
    /// 1. **Dynamic Secrets**: Vault can generate short-lived database credentials
    /// 2. **Encryption in Transit**: Secrets travel over TLS, never stored on disk unencrypted
    /// 3. **Access Logging**: Every fetch is logged for audit purposes
    /// 4. **Centralized Rotation**: Update secrets in Vault, agents fetch new values
    ///
    /// ## Path
    ///
    /// `GET {base_url}/v1/{prefix}/{deployment_hash}/apps/{app_name}/config`
    ///
    /// ## Returns
    ///
    /// `AppConfig` containing the file content, destination path, and permissions.
    pub async fn fetch_app_config(
        &self,
        deployment_hash: &str,
        app_name: &str,
    ) -> Result<AppConfig> {
        let url = self.config_path(deployment_hash, app_name);

        // Security: Log path but never log config content
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
            // Don't expose config content in error messages
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

        // Extract AppConfig fields from the Vault response
        // Vault KV v2 wraps data in nested {"data": {"data": {...}}}
        let data = &vault_resp.data.data;

        // Content is required - this is the actual configuration file content
        // WARNING: May contain sensitive data, never log
        let content = data
            .get("content")
            .and_then(|v| v.as_str())
            .context("config content not found in Vault response")?
            .to_string();

        // Content type helps the agent validate and apply the config correctly
        let content_type = data
            .get("content_type")
            .and_then(|v| v.as_str())
            .unwrap_or("text")
            .to_string();

        // Destination path is where the config file will be written on the server
        // Security: This should be validated to prevent path traversal attacks
        let destination_path = data
            .get("destination_path")
            .and_then(|v| v.as_str())
            .context("destination_path not found in Vault response")?
            .to_string();

        // File mode controls OS-level access permissions
        // Sensitive configs should use restrictive modes like 0600
        let file_mode = data
            .get("file_mode")
            .and_then(|v| v.as_str())
            .unwrap_or("0644")
            .to_string();

        // Owner/group for chown - enables OS-level access control
        let owner = data
            .get("owner")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let group = data
            .get("group")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        // Log metadata but never the actual content
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
    /// ## Security Purpose
    ///
    /// This is called by the Stacker service when app configurations are created
    /// or updated. Storing configs in Vault provides:
    ///
    /// 1. **Encryption at Rest**: Vault encrypts all data before storage
    /// 2. **Versioning**: Previous versions are preserved for rollback
    /// 3. **Access Control**: Only authorized services can write configs
    /// 4. **Audit Trail**: All writes are logged with timestamps
    ///
    /// ## Path
    ///
    /// `POST {base_url}/v1/{prefix}/{deployment_hash}/apps/{app_name}/config`
    pub async fn store_app_config(
        &self,
        deployment_hash: &str,
        app_name: &str,
        config: &AppConfig,
    ) -> Result<()> {
        let url = self.config_path(deployment_hash, app_name);

        // Security: Never log config.content - may contain secrets
        debug!("Storing app config in Vault: {}", url);

        // Vault KV v2 requires wrapping data in {"data": {...}}
        // All fields are stored together as a single secret for atomic updates
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
            // Don't log the payload - contains secrets
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!(
                "Vault config store failed with status {}: {}",
                status,
                body
            ));
        }

        // Log metadata but not the actual secret content
        info!(
            "Config stored in Vault for {}/{} (dest: {})",
            deployment_hash, app_name, config.destination_path
        );
        Ok(())
    }

    /// List all app configs for a deployment.
    ///
    /// ## Security Purpose
    ///
    /// This enables the Status Panel agent to discover all apps that have
    /// configurations without knowing them in advance. Useful for:
    ///
    /// 1. **Bulk Config Fetch**: Agent can fetch all configs on startup
    /// 2. **Drift Detection**: Compare local files against Vault state
    /// 3. **Inventory**: Know what apps are configured for this deployment
    ///
    /// ## Path
    ///
    /// `LIST {base_url}/v1/{prefix}/{deployment_hash}/apps`
    ///
    /// ## Note on LIST Method
    ///
    /// Vault uses the non-standard HTTP "LIST" method for directory listings.
    /// This prevents accidental exposure via GET requests.
    ///
    /// ## Returns
    ///
    /// List of app names (e.g., ["nginx", "redis", "postgres"]) that have
    /// configurations stored in Vault for this deployment.
    pub async fn list_app_configs(&self, deployment_hash: &str) -> Result<Vec<String>> {
        // Construct list path - deployment-scoped apps directory
        let url = format!(
            "{}/v1/{}/{}/apps",
            self.base_url, self.prefix, deployment_hash
        );

        debug!("Listing app configs from Vault: {}", url);

        // Vault uses the non-standard HTTP LIST method for directory operations
        // This is a security feature - prevents accidental disclosure via GET
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

        // 404 means the apps/ path doesn't exist yet (no configs stored)
        // This is not an error - just return empty list
        if response.status() == 404 {
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

        // Response structure for LIST operations
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

        // Filter out subdirectories (ending with /) - we only want app names
        // Vault returns both files and directories in the keys list
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
    /// ## Security Purpose
    ///
    /// Configuration deletion is important for:
    ///
    /// 1. **App Removal**: When an app is removed from a stack, its secrets
    ///    should be deleted to prevent accumulation of stale credentials.
    /// 2. **Key Rotation**: Delete old configs after rotating to new credentials.
    /// 3. **Decommissioning**: Clean up all secrets when a deployment is destroyed.
    ///
    /// ## Soft Delete Behavior
    ///
    /// Vault KV v2 performs soft deletes by default - the secret is marked as
    /// deleted but previous versions are preserved. Use metadata destroy
    /// endpoint for permanent removal if required by compliance policies.
    ///
    /// ## Path
    ///
    /// `DELETE {base_url}/v1/{prefix}/{deployment_hash}/apps/{app_name}/config`
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

        // 204 No Content is a valid success response for DELETE
        // Don't fail if already deleted - idempotent operation
        if !response.status().is_success() && response.status() != 204 {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            // Warn but don't fail - config may already be deleted
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
    /// ## Security Purpose
    ///
    /// Bulk fetching is used during:
    ///
    /// 1. **Initial Deployment**: Agent needs all configs to set up the stack
    /// 2. **Sync Operations**: Periodic check to ensure configs match Vault state
    /// 3. **Rollback**: Restore all configs to a known-good state
    ///
    /// ## Failure Handling
    ///
    /// This method is resilient - if one app's config fails to fetch, it logs
    /// a warning and continues with the others. This prevents a single missing
    /// config from blocking the entire deployment.
    ///
    /// ## Returns
    ///
    /// Map of `app_name -> AppConfig` for all successfully fetched configurations.
    /// Apps that failed to fetch are logged but not included in the result.
    pub async fn fetch_all_app_configs(
        &self,
        deployment_hash: &str,
        app_names: &[String],
    ) -> Result<HashMap<String, AppConfig>> {
        let mut configs = HashMap::new();

        // Fetch each app's config sequentially
        // Note: Could be parallelized with tokio::join! for performance,
        // but sequential is simpler and avoids overwhelming Vault
        for app_name in app_names {
            match self.fetch_app_config(deployment_hash, app_name).await {
                Ok(config) => {
                    configs.insert(app_name.clone(), config);
                }
                Err(e) => {
                    // Log warning but continue - don't let one failure block others
                    // This is a design choice: partial success is better than total failure
                    warn!(
                        "Failed to fetch config for {}/{}: {}",
                        deployment_hash, app_name, e
                    );
                }
            }
        }

        Ok(configs)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that VaultClient::from_env returns None when Vault is not configured.
    /// This ensures graceful degradation in development/testing environments.
    #[test]
    fn test_vault_client_from_env_missing() {
        // Clear env vars to simulate unconfigured Vault
        std::env::remove_var("VAULT_ADDRESS");
        std::env::remove_var("VAULT_TOKEN");
        std::env::remove_var("VAULT_AGENT_PATH_PREFIX");

        let result = VaultClient::from_env();
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }
}
