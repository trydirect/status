use std::sync::Arc;
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

/// A request id was seen before its TTL expired — the request is a replay.
///
/// A named type rather than `()`: `Result<_, ()>` tells a caller nothing about
/// why the call failed and cannot carry context if this ever grows a second
/// failure mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplayDetected;

impl std::fmt::Display for ReplayDetected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("request id was already used within the replay window")
    }
}

impl std::error::Error for ReplayDetected {}

#[derive(Debug, Clone)]
pub struct ReplayProtection {
    ttl: Duration,
    inner: Arc<Mutex<HashMap<String, Instant>>>,
}

impl ReplayProtection {
    pub fn new_ttl(ttl_secs: u64) -> Self {
        Self {
            ttl: Duration::from_secs(ttl_secs),
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// `Ok(())` if the id is fresh and now stored; [`ReplayDetected`] if it
    /// was already seen inside the TTL window.
    pub async fn check_and_store(&self, id: &str) -> Result<(), ReplayDetected> {
        let now = Instant::now();
        let mut map = self.inner.lock().await;
        // purge expired
        let ttl = self.ttl;
        map.retain(|_, &mut t| now.duration_since(t) < ttl);
        if map.contains_key(id) {
            return Err(ReplayDetected);
        }
        map.insert(id.to_string(), now);
        Ok(())
    }

    /// Remove all expired entries. Call periodically to bound memory.
    pub async fn cleanup_expired(&self) {
        let now = Instant::now();
        let ttl = self.ttl;
        let mut map = self.inner.lock().await;
        map.retain(|_, &mut t| now.duration_since(t) < ttl);
    }
}
