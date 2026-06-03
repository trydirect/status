use std::sync::Arc;

use anyhow::Result;
use chrono::{DateTime, Utc};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use super::vault_client::VaultClient;

/// Minimum seconds between consecutive refresh attempts to prevent hammering.
const REFRESH_COOLDOWN_SECS: i64 = 10;

/// Provides shared, refreshable access to the agent token.
///
/// When a 401/403 is received from Stacker, callers invoke `refresh()` which:
/// 1. Checks a cooldown to avoid hammering Vault or env re-reads.
/// 2. Tries Vault (if configured) to get a new token.
/// 3. Falls back to re-reading `AGENT_TOKEN` from the environment.
/// 4. Returns whether the token actually changed.
#[derive(Debug, Clone)]
pub struct TokenProvider {
    token: Arc<RwLock<String>>,
    vault_client: Option<VaultClient>,
    deployment_hash: String,
    last_refresh: Arc<RwLock<Option<DateTime<Utc>>>>,
}

impl TokenProvider {
    pub fn new(
        initial_token: String,
        vault_client: Option<VaultClient>,
        deployment_hash: String,
    ) -> Self {
        Self {
            token: Arc::new(RwLock::new(initial_token)),
            vault_client,
            deployment_hash,
            last_refresh: Arc::new(RwLock::new(None)),
        }
    }

    /// Build a provider from environment variables, optionally attaching a Vault client.
    pub fn from_env(vault_client: Option<VaultClient>) -> Self {
        let token = std::env::var("AGENT_TOKEN").unwrap_or_default();
        let deployment_hash =
            std::env::var("DEPLOYMENT_HASH").unwrap_or_else(|_| "default".to_string());
        Self::new(token, vault_client, deployment_hash)
    }

    /// Get the current token value.
    pub async fn get(&self) -> String {
        self.token.read().await.clone()
    }

    /// Attempt to refresh the token after a 401/403.
    ///
    /// Returns `Ok(true)` if the token was actually changed, `Ok(false)` if
    /// it stayed the same (cooldown, Vault returned same token, no env change).
    pub async fn refresh(&self) -> Result<bool> {
        // Cooldown check
        {
            let last = self.last_refresh.read().await;
            if let Some(t) = *last {
                let elapsed = (Utc::now() - t).num_seconds();
                if elapsed < REFRESH_COOLDOWN_SECS {
                    debug!(
                        elapsed,
                        cooldown = REFRESH_COOLDOWN_SECS,
                        "token refresh skipped (cooldown)"
                    );
                    return Ok(false);
                }
            }
        }

        // Record this attempt
        {
            let mut last = self.last_refresh.write().await;
            *last = Some(Utc::now());
        }

        let old_token = self.token.read().await.clone();

        // Strategy 1: Vault
        if let Some(vault) = &self.vault_client {
            match vault.fetch_agent_token(&self.deployment_hash, None).await {
                Ok(new_token) if new_token != old_token => {
                    let mut token = self.token.write().await;
                    *token = new_token;
                    info!("Agent token refreshed from Vault after auth error");
                    return Ok(true);
                }
                Ok(_) => {
                    debug!("Vault returned same token; trying env fallback");
                }
                Err(e) => {
                    warn!(error = %e, "Vault token refresh failed; trying env fallback");
                }
            }
        }

        // Strategy 2: re-read AGENT_TOKEN from environment
        let env_token = std::env::var("AGENT_TOKEN").unwrap_or_default();
        if !env_token.is_empty() && env_token != old_token {
            let mut token = self.token.write().await;
            *token = env_token;
            info!("Agent token refreshed from environment after auth error");
            return Ok(true);
        }

        // Strategy 3: self-issue a new token and write it to Vault.
        // Stacker validates by reading from the same Vault KV path, so a token
        // the agent writes there is immediately accepted on the next poll.
        if let Some(vault) = &self.vault_client {
            let new_token = generate_secure_token();
            match vault
                .store_agent_token(&self.deployment_hash, &new_token, None)
                .await
            {
                Ok(()) => {
                    let mut token = self.token.write().await;
                    *token = new_token;
                    super::audit_log::AuditLogger::new()
                        .token_self_issued(&self.deployment_hash, "primary_strategies_failed");
                    return Ok(true);
                }
                Err(e) => {
                    warn!(error = %e, "Vault self-issue failed; token unchanged");
                }
            }
        }

        debug!("No new token available after refresh attempt");
        Ok(false)
    }

    /// Directly swap the token (used by background rotation tasks).
    pub async fn swap(&self, new_token: String) {
        let mut token = self.token.write().await;
        if *token != new_token {
            *token = new_token;
        }
    }
}

fn generate_secure_token() -> String {
    use ring::rand::{SecureRandom, SystemRandom};
    let rng = SystemRandom::new();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes).expect("CSPRNG failure");
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::EnvGuard;
    use std::sync::{Mutex, OnceLock};

    /// Serializes tests that mutate AGENT_TOKEN env var.
    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[tokio::test]
    async fn get_returns_initial_token() {
        let tp = TokenProvider::new("tok123".into(), None, "hash".into());
        assert_eq!(tp.get().await, "tok123");
    }

    #[tokio::test]
    async fn swap_updates_token() {
        let tp = TokenProvider::new("old".into(), None, "hash".into());
        tp.swap("new".into()).await;
        assert_eq!(tp.get().await, "new");
    }

    #[tokio::test]
    async fn refresh_without_vault_reads_env() {
        let _guard = env_lock().lock().unwrap();
        let _env = EnvGuard::set("AGENT_TOKEN", "env_refreshed_tp");
        let tp = TokenProvider::new("stale".into(), None, "hash".into());

        let changed = tp.refresh().await.unwrap();
        assert!(changed);
        assert_eq!(tp.get().await, "env_refreshed_tp");
    }

    #[tokio::test]
    async fn refresh_respects_cooldown() {
        let _guard = env_lock().lock().unwrap();
        let _env = EnvGuard::set("AGENT_TOKEN", "fresh_tp");
        let tp = TokenProvider::new("stale".into(), None, "hash".into());

        let first = tp.refresh().await.unwrap();
        assert!(first);

        // Second attempt within cooldown should be skipped
        std::env::set_var("AGENT_TOKEN", "even_fresher_tp");
        let second = tp.refresh().await.unwrap();
        assert!(!second);
        assert_eq!(tp.get().await, "fresh_tp");
    }

    #[tokio::test]
    async fn refresh_noop_when_env_same() {
        let _guard = env_lock().lock().unwrap();
        let _env = EnvGuard::set("AGENT_TOKEN", "same");
        let tp = TokenProvider::new("same".into(), None, "hash".into());

        let changed = tp.refresh().await.unwrap();
        assert!(!changed);
    }

    #[tokio::test]
    async fn clone_shares_state() {
        let tp = TokenProvider::new("a".into(), None, "h".into());
        let tp2 = tp.clone();
        tp2.swap("b".into()).await;
        assert_eq!(tp.get().await, "b");
    }

    #[tokio::test]
    async fn refresh_self_issues_token_when_vault_has_no_entry() {
        use crate::security::vault_client::VaultClient;
        use mockito::Server;

        let _guard = env_lock().lock().unwrap();

        let mut server = Server::new_async().await;

        // Strategy 1: Vault read returns 404 (KV entry was deleted)
        let read = server
            .mock("GET", "/v1/status_panel/dep-abc/status_panel_token")
            .with_status(404)
            .with_body(r#"{"errors":[]}"#)
            .expect(1)
            .create_async()
            .await;

        // Strategy 3: Vault write accepted (must be called exactly once)
        let write = server
            .mock("POST", "/v1/status_panel/dep-abc/status_panel_token")
            .with_status(200)
            .with_body("{}")
            .expect(1)
            .create_async()
            .await;

        let _addr = EnvGuard::set("VAULT_ADDRESS", &server.url());
        let _tok = EnvGuard::set("VAULT_TOKEN", "vault-root");
        let _prefix = EnvGuard::set("VAULT_AGENT_PATH_PREFIX", "status_panel");
        // Strategy 2 is a no-op: env token matches current
        let _agent = EnvGuard::set("AGENT_TOKEN", "stale-token");

        let vault = VaultClient::from_env().unwrap().unwrap();
        let tp = TokenProvider::new("stale-token".into(), Some(vault), "dep-abc".into());

        let changed = tp.refresh().await.unwrap();
        assert!(changed, "expected self-issued token to be applied");

        let new_token = tp.get().await;
        assert_ne!(new_token, "stale-token");
        assert_eq!(new_token.len(), 64, "expected 32-byte hex token");
        assert!(new_token.chars().all(|c| c.is_ascii_hexdigit()));

        read.assert_async().await;
        write.assert_async().await;
    }

    #[tokio::test]
    async fn refresh_keeps_token_when_vault_write_forbidden() {
        use crate::security::vault_client::VaultClient;
        use mockito::Server;

        let _guard = env_lock().lock().unwrap();

        let mut server = Server::new_async().await;

        // Strategy 1: Vault read returns 404
        let _read = server
            .mock("GET", "/v1/status_panel/dep-xyz/status_panel_token")
            .with_status(404)
            .with_body(r#"{"errors":[]}"#)
            .create_async()
            .await;

        // Strategy 3: Vault write rejected (agent lacks write capability)
        let write = server
            .mock("POST", "/v1/status_panel/dep-xyz/status_panel_token")
            .with_status(403)
            .with_body(r#"{"errors":["permission denied"]}"#)
            .expect(1)
            .create_async()
            .await;

        let _addr = EnvGuard::set("VAULT_ADDRESS", &server.url());
        let _tok = EnvGuard::set("VAULT_TOKEN", "vault-root");
        let _prefix = EnvGuard::set("VAULT_AGENT_PATH_PREFIX", "status_panel");
        let _agent = EnvGuard::set("AGENT_TOKEN", "stale-token");

        let vault = VaultClient::from_env().unwrap().unwrap();
        let tp = TokenProvider::new("stale-token".into(), Some(vault), "dep-xyz".into());

        let changed = tp.refresh().await.unwrap();
        assert!(!changed, "Strategy 3 must not claim success on write failure");
        assert_eq!(tp.get().await, "stale-token", "token must not change on failure");

        write.assert_async().await;
    }
}
