use tokio::time::{sleep, Duration};
use tracing::{debug, info, warn};

use crate::security::token_cache::TokenCache;
use crate::security::vault_client::VaultClient;

/// Background task that refreshes the agent token from Vault.
///
/// Runs every 60 seconds (+ 5-10s jitter) and:
/// 1. Fetches the current token from Vault
/// 2. If changed, atomically swaps it in the cache
/// 3. Handles Vault errors gracefully with warnings
pub async fn spawn_token_refresh(
    vault_client: VaultClient,
    deployment_hash: String,
    token_cache: TokenCache,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            // Generate jitter (5-10s) outside the loop context to satisfy Send
            let jitter = {
                use rand::Rng;
                rand::thread_rng().gen_range(5..10)
            };
            let interval = Duration::from_secs(60 + jitter as u64);

            sleep(interval).await;

            match vault_client.fetch_agent_token(&deployment_hash).await {
                Ok(new_token) => {
                    let current = token_cache.get().await;
                    if current != new_token {
                        token_cache.swap(new_token).await;
                        info!(
                            deployment_hash = %deployment_hash,
                            "Agent token rotated from Vault"
                        );
                    } else {
                        debug!(
                            deployment_hash = %deployment_hash,
                            "Token unchanged from Vault"
                        );
                    }
                }
                Err(err) => {
                    warn!(
                        deployment_hash = %deployment_hash,
                        error = %err,
                        "Failed to fetch token from Vault (will retry)"
                    );
                }
            }
        }
    })
}

/// Graceful token rotation handler for in-flight requests.
///
/// This helper can be called when a token rotation is detected
/// to ensure in-flight requests are not prematurely terminated.
pub fn allow_graceful_termination(_token_cache: &TokenCache) {
    // In-flight requests with the old token will complete successfully
    // because new requests will pick up the swapped token from the cache.
    // This is handled implicitly via Arc-based sharing of TokenCache.
    debug!("Token rotation allowed to proceed; in-flight requests will complete");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_allow_graceful_termination() {
        let cache = TokenCache::new("token".to_string());
        allow_graceful_termination(&cache);
        // Just ensure it doesn't panic
        assert_eq!(cache.get().await, "token");
    }
}
