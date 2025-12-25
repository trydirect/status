use std::{collections::{HashMap, VecDeque}, time::{Duration, Instant}};
use tokio::sync::Mutex;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct RateLimiter {
    window: Duration,
    limit: usize,
    inner: Arc<Mutex<HashMap<String, VecDeque<Instant>>>>,
}

impl RateLimiter {
    pub fn new_per_minute(limit: usize) -> Self {
        Self { window: Duration::from_secs(60), limit, inner: Arc::new(Mutex::new(HashMap::new())) }
    }

    pub async fn allow(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut map = self.inner.lock().await;
        let deque = map.entry(key.to_string()).or_insert_with(VecDeque::new);
        // purge old
        while let Some(&front) = deque.front() {
            if now.duration_since(front) > self.window { deque.pop_front(); } else { break; }
        }
        if deque.len() < self.limit {
            deque.push_back(now);
            true
        } else {
            false
        }
    }
}
