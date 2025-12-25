use std::sync::Arc;
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

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

    // Returns Ok(()) if id is fresh and stored; Err(()) if replay detected
    pub async fn check_and_store(&self, id: &str) -> Result<(), ()> {
        let now = Instant::now();
        let mut map = self.inner.lock().await;
        // purge expired
        let ttl = self.ttl;
        map.retain(|_, &mut t| now.duration_since(t) < ttl);
        if map.contains_key(id) {
            return Err(());
        }
        map.insert(id.to_string(), now);
        Ok(())
    }
}
