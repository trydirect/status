use crate::models::agent_protocol::RetryPolicy;
use serde_json::Value as JsonValue;
use std::time::{Duration, Instant};

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// In-Memory Circuit Breaker
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

impl std::fmt::Display for CircuitState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed => write!(f, "closed"),
            Self::Open => write!(f, "open"),
            Self::HalfOpen => write!(f, "half_open"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    pub failure_threshold: u32,
    pub recovery_timeout: Duration,
    pub half_open_max_requests: u32,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            recovery_timeout: Duration::from_secs(60),
            half_open_max_requests: 3,
        }
    }
}

#[derive(Debug)]
pub struct InMemoryCircuitBreaker {
    state: CircuitState,
    failure_count: u32,
    success_count: u32,
    half_open_requests: u32,
    config: CircuitBreakerConfig,
    opened_at: Option<Instant>,
}

impl InMemoryCircuitBreaker {
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            state: CircuitState::Closed,
            failure_count: 0,
            success_count: 0,
            half_open_requests: 0,
            config,
            opened_at: None,
        }
    }

    pub fn state(&self) -> &CircuitState {
        &self.state
    }

    /// Check if the circuit allows a request. May transition Open → HalfOpen
    /// if recovery timeout has elapsed.
    pub fn allows_request(&mut self) -> bool {
        match self.state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                if let Some(opened) = self.opened_at {
                    if opened.elapsed() >= self.config.recovery_timeout {
                        self.state = CircuitState::HalfOpen;
                        self.half_open_requests = 0;
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            CircuitState::HalfOpen => self.half_open_requests < self.config.half_open_max_requests,
        }
    }

    pub fn record_success(&mut self) {
        match self.state {
            CircuitState::Closed => {
                self.failure_count = 0;
            }
            CircuitState::HalfOpen => {
                self.success_count += 1;
                if self.success_count >= self.config.half_open_max_requests {
                    self.state = CircuitState::Closed;
                    self.failure_count = 0;
                    self.success_count = 0;
                    self.half_open_requests = 0;
                    self.opened_at = None;
                }
            }
            CircuitState::Open => {} // shouldn't happen
        }
    }

    pub fn record_failure(&mut self) {
        match self.state {
            CircuitState::Closed => {
                self.failure_count += 1;
                if self.failure_count >= self.config.failure_threshold {
                    self.state = CircuitState::Open;
                    self.opened_at = Some(Instant::now());
                    self.success_count = 0;
                }
            }
            CircuitState::HalfOpen => {
                self.state = CircuitState::Open;
                self.opened_at = Some(Instant::now());
                self.failure_count = 0;
                self.success_count = 0;
                self.half_open_requests = 0;
            }
            CircuitState::Open => {} // shouldn't happen
        }
    }

    pub fn reset(&mut self) {
        self.state = CircuitState::Closed;
        self.failure_count = 0;
        self.success_count = 0;
        self.half_open_requests = 0;
        self.opened_at = None;
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Retry with Exponential Backoff
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Compute backoff duration for a given attempt (0-indexed).
pub fn compute_backoff(attempt: u32, policy: &RetryPolicy) -> Duration {
    let delay_ms = (policy.backoff_base_ms as u128)
        .saturating_mul(2u128.saturating_pow(attempt))
        .min(policy.backoff_max_ms as u128) as u64;
    Duration::from_millis(delay_ms)
}

/// Execute a step with retry and circuit breaker protection.
/// Returns the final result after all retries are exhausted.
pub async fn execute_with_resilience(
    step_type: &str,
    config: &JsonValue,
    input: &JsonValue,
    retry_policy: &RetryPolicy,
    circuit_breaker: &mut InMemoryCircuitBreaker,
) -> Result<JsonValue, String> {
    use super::step_executor;

    if !circuit_breaker.allows_request() {
        return Err("Circuit breaker is open".to_string());
    }

    let mut last_err = String::new();

    for attempt in 0..=retry_policy.max_retries {
        if attempt > 0 {
            if !circuit_breaker.allows_request() {
                return Err(format!(
                    "Circuit breaker opened after {} attempts: {}",
                    attempt, last_err
                ));
            }
            let backoff = compute_backoff(attempt - 1, retry_policy);
            tokio::time::sleep(backoff).await;
        }

        match step_executor::execute_step(step_type, config, input).await {
            Ok(output) => {
                circuit_breaker.record_success();
                return Ok(output);
            }
            Err(err) => {
                circuit_breaker.record_failure();
                last_err = err;
            }
        }
    }

    Err(format!(
        "Step failed after {} retries: {}",
        retry_policy.max_retries, last_err
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── Circuit Breaker Tests ──────────────────────────

    #[test]
    fn new_breaker_is_closed() {
        let cb = InMemoryCircuitBreaker::new(CircuitBreakerConfig::default());
        assert_eq!(*cb.state(), CircuitState::Closed);
    }

    #[test]
    fn closed_allows_requests() {
        let mut cb = InMemoryCircuitBreaker::new(CircuitBreakerConfig::default());
        assert!(cb.allows_request());
    }

    #[test]
    fn failures_below_threshold_stay_closed() {
        let mut cb = InMemoryCircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 3,
            ..Default::default()
        });
        cb.record_failure();
        cb.record_failure();
        assert_eq!(*cb.state(), CircuitState::Closed);
        assert!(cb.allows_request());
    }

    #[test]
    fn failures_at_threshold_opens_circuit() {
        let mut cb = InMemoryCircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 3,
            ..Default::default()
        });
        cb.record_failure();
        cb.record_failure();
        cb.record_failure();
        assert_eq!(*cb.state(), CircuitState::Open);
        assert!(!cb.allows_request());
    }

    #[test]
    fn success_resets_failure_count() {
        let mut cb = InMemoryCircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 3,
            ..Default::default()
        });
        cb.record_failure();
        cb.record_failure();
        cb.record_success();
        assert_eq!(cb.failure_count, 0);
        assert_eq!(*cb.state(), CircuitState::Closed);
    }

    #[test]
    fn open_transitions_to_half_open_after_timeout() {
        let mut cb = InMemoryCircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 1,
            recovery_timeout: Duration::from_millis(0), // instant recovery for test
            half_open_max_requests: 2,
        });
        cb.record_failure();
        assert_eq!(*cb.state(), CircuitState::Open);

        // With zero timeout, should transition on next allows_request
        assert!(cb.allows_request());
        assert_eq!(*cb.state(), CircuitState::HalfOpen);
    }

    #[test]
    fn half_open_limits_requests() {
        let mut cb = InMemoryCircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 1,
            recovery_timeout: Duration::from_millis(0),
            half_open_max_requests: 2,
        });
        cb.record_failure();
        cb.allows_request(); // transitions to HalfOpen

        assert!(cb.allows_request()); // request 0 < 2
        cb.half_open_requests = 1;
        assert!(cb.allows_request()); // request 1 < 2
        cb.half_open_requests = 2;
        assert!(!cb.allows_request()); // request 2 >= 2
    }

    #[test]
    fn half_open_success_closes_circuit() {
        let mut cb = InMemoryCircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 1,
            recovery_timeout: Duration::from_millis(0),
            half_open_max_requests: 2,
        });
        cb.record_failure();
        cb.allows_request(); // HalfOpen

        cb.record_success();
        cb.record_success();
        assert_eq!(*cb.state(), CircuitState::Closed);
    }

    #[test]
    fn half_open_failure_reopens_circuit() {
        let mut cb = InMemoryCircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 1,
            recovery_timeout: Duration::from_millis(0),
            half_open_max_requests: 2,
        });
        cb.record_failure();
        cb.allows_request(); // HalfOpen

        cb.record_failure();
        assert_eq!(*cb.state(), CircuitState::Open);
    }

    #[test]
    fn reset_returns_to_closed() {
        let mut cb = InMemoryCircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 1,
            ..Default::default()
        });
        cb.record_failure();
        assert_eq!(*cb.state(), CircuitState::Open);

        cb.reset();
        assert_eq!(*cb.state(), CircuitState::Closed);
        assert!(cb.allows_request());
    }

    #[test]
    fn circuit_state_display() {
        assert_eq!(CircuitState::Closed.to_string(), "closed");
        assert_eq!(CircuitState::Open.to_string(), "open");
        assert_eq!(CircuitState::HalfOpen.to_string(), "half_open");
    }

    // ── Backoff Tests ──────────────────────────────────

    #[test]
    fn backoff_exponential() {
        let policy = RetryPolicy {
            max_retries: 5,
            backoff_base_ms: 100,
            backoff_max_ms: 10_000,
        };
        assert_eq!(compute_backoff(0, &policy), Duration::from_millis(100));
        assert_eq!(compute_backoff(1, &policy), Duration::from_millis(200));
        assert_eq!(compute_backoff(2, &policy), Duration::from_millis(400));
        assert_eq!(compute_backoff(3, &policy), Duration::from_millis(800));
    }

    #[test]
    fn backoff_capped_at_max() {
        let policy = RetryPolicy {
            max_retries: 10,
            backoff_base_ms: 1000,
            backoff_max_ms: 5000,
        };
        assert_eq!(compute_backoff(0, &policy), Duration::from_millis(1000));
        assert_eq!(compute_backoff(1, &policy), Duration::from_millis(2000));
        assert_eq!(compute_backoff(2, &policy), Duration::from_millis(4000));
        assert_eq!(compute_backoff(3, &policy), Duration::from_millis(5000)); // capped
        assert_eq!(compute_backoff(10, &policy), Duration::from_millis(5000));
    }

    // ── execute_with_resilience Tests ──────────────────

    #[tokio::test]
    async fn resilience_succeeds_on_first_try() {
        let mut cb = InMemoryCircuitBreaker::new(CircuitBreakerConfig::default());
        let policy = RetryPolicy {
            max_retries: 3,
            backoff_base_ms: 1,
            backoff_max_ms: 10,
        };

        let result = execute_with_resilience(
            "source",
            &json!({"output": {"ok": true}}),
            &json!({}),
            &policy,
            &mut cb,
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), json!({"ok": true}));
    }

    #[tokio::test]
    async fn resilience_fails_after_retries() {
        let mut cb = InMemoryCircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 10, // high so CB doesn't open
            ..Default::default()
        });
        let policy = RetryPolicy {
            max_retries: 2,
            backoff_base_ms: 1,
            backoff_max_ms: 5,
        };

        let result = execute_with_resilience(
            "source",
            &json!({"error": "always fails"}),
            &json!({}),
            &policy,
            &mut cb,
        )
        .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("after 2 retries"));
        assert!(err.contains("always fails"));
    }

    #[tokio::test]
    async fn resilience_blocked_by_open_circuit() {
        let mut cb = InMemoryCircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 1,
            recovery_timeout: Duration::from_secs(60),
            ..Default::default()
        });
        cb.record_failure(); // Open the circuit

        let policy = RetryPolicy::default();
        let result = execute_with_resilience(
            "source",
            &json!({"output": {"ok": true}}),
            &json!({}),
            &policy,
            &mut cb,
        )
        .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Circuit breaker is open"));
    }
}
