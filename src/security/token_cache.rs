use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc};
use tracing::debug;

/// Token cache with atomic swap capability and rotation tracking.
#[derive(Debug, Clone)]
pub struct TokenCache {
    token: Arc<RwLock<String>>,
    last_rotated: Arc<RwLock<Option<DateTime<Utc>>>>,
}

impl TokenCache {
    /// Create a new token cache with initial token.
    pub fn new(initial_token: String) -> Self {
        Self {
            token: Arc::new(RwLock::new(initial_token)),
            last_rotated: Arc::new(RwLock::new(Some(Utc::now()))),
        }
    }

    /// Get the current token (read-only).
    pub async fn get(&self) -> String {
        self.token.read().await.clone()
    }

    /// Atomically swap the token and record rotation time.
    pub async fn swap(&self, new_token: String) {
        let mut token = self.token.write().await;
        if *token != new_token {
            *token = new_token;
            drop(token);

            let mut last_rotated = self.last_rotated.write().await;
            *last_rotated = Some(Utc::now());
            debug!("Token rotated at {:?}", last_rotated);
        }
    }

    /// Get the time of last rotation.
    pub async fn last_rotated(&self) -> Option<DateTime<Utc>> {
        *self.last_rotated.read().await
    }

    /// Get token age in seconds since last rotation.
    pub async fn age_seconds(&self) -> u64 {
        if let Some(rotated) = self.last_rotated().await {
            let age = Utc::now() - rotated;
            age.num_seconds().max(0) as u64
        } else {
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_token_cache_get_set() {
        let cache = TokenCache::new("initial_token".to_string());
        assert_eq!(cache.get().await, "initial_token");

        cache.swap("new_token".to_string()).await;
        assert_eq!(cache.get().await, "new_token");
    }

    #[tokio::test]
    async fn test_token_cache_no_rotation_on_same_token() {
        let cache = TokenCache::new("token".to_string());
        let first_rotated = cache.last_rotated().await;

        // Try to swap with the same token
        cache.swap("token".to_string()).await;
        let second_rotated = cache.last_rotated().await;

        assert_eq!(first_rotated, second_rotated);
    }

    #[tokio::test]
    async fn test_token_cache_age_seconds() {
        let cache = TokenCache::new("token".to_string());
        let age = cache.age_seconds().await;

        // Should be 0 or very small
        assert!(age <= 1);

        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let age = cache.age_seconds().await;

        // May be 0 or 1 depending on timing
        assert!(age <= 2);
    }

    #[tokio::test]
    async fn test_token_cache_clone() {
        let cache = TokenCache::new("token".to_string());
        let cloned = cache.clone();

        cloned.swap("new_token".to_string()).await;
        assert_eq!(cache.get().await, "new_token");
    }
}
