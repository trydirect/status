use std::sync::Arc;
use std::{
    collections::{HashMap, VecDeque},
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
pub struct RateLimiter {
    window: Duration,
    limit: usize,
    inner: Arc<Mutex<HashMap<String, VecDeque<Instant>>>>,
}

impl RateLimiter {
    pub fn new_per_minute(limit: usize) -> Self {
        Self {
            window: Duration::from_secs(60),
            limit,
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn allow(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut map = self.inner.lock().await;
        let deque = map.entry(key.to_string()).or_insert_with(VecDeque::new);
        // purge old
        while let Some(&front) = deque.front() {
            if now.duration_since(front) > self.window {
                deque.pop_front();
            } else {
                break;
            }
        }
        if deque.len() < self.limit {
            deque.push_back(now);
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn allows_requests_within_limit() {
        let limiter = RateLimiter::new_per_minute(3);
        assert!(limiter.allow("client-1").await);
        assert!(limiter.allow("client-1").await);
        assert!(limiter.allow("client-1").await);
    }

    #[tokio::test]
    async fn blocks_requests_over_limit() {
        let limiter = RateLimiter::new_per_minute(2);
        assert!(limiter.allow("client-1").await);
        assert!(limiter.allow("client-1").await);
        assert!(!limiter.allow("client-1").await);
    }

    #[tokio::test]
    async fn independent_keys() {
        let limiter = RateLimiter::new_per_minute(1);
        assert!(limiter.allow("client-1").await);
        assert!(limiter.allow("client-2").await);
        // client-1 is now blocked, client-2 is also blocked
        assert!(!limiter.allow("client-1").await);
        assert!(!limiter.allow("client-2").await);
    }

    #[tokio::test]
    async fn window_expiry_allows_new_requests() {
        // Use a very short window to test expiry
        let limiter = RateLimiter {
            window: Duration::from_millis(50),
            limit: 1,
            inner: Arc::new(Mutex::new(HashMap::new())),
        };
        assert!(limiter.allow("client").await);
        assert!(!limiter.allow("client").await);

        // Wait for window to expire
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(limiter.allow("client").await);
    }

    #[tokio::test]
    async fn limit_of_zero_blocks_all() {
        let limiter = RateLimiter::new_per_minute(0);
        assert!(!limiter.allow("client").await);
    }

    #[tokio::test]
    async fn limiter_is_clone_safe() {
        let limiter = RateLimiter::new_per_minute(1);
        let limiter_clone = limiter.clone();

        assert!(limiter.allow("client").await);
        // Clone shares state, so this should be blocked
        assert!(!limiter_clone.allow("client").await);
    }
}
