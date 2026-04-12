use std::time::Duration;

use anyhow::{Context, Result};
use reqwest::header::CONTENT_TYPE;
use reqwest::{Client, Response};
use serde::Serialize;
use tracing::warn;

use crate::security::token_provider::TokenProvider;
use crate::transport::http_polling::build_signed_headers;

/// Configuration for retry behaviour on outbound Stacker requests.
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// How many times to retry after a 401/403 (each attempt refreshes the token first).
    pub max_auth_retries: u32,
    /// How many times to retry on 5xx / network errors with exponential backoff.
    pub max_server_retries: u32,
    /// Starting backoff duration for server/network retries.
    pub initial_backoff: Duration,
    /// Maximum backoff cap.
    pub max_backoff: Duration,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_auth_retries: 1,
            max_server_retries: 3,
            initial_backoff: Duration::from_secs(2),
            max_backoff: Duration::from_secs(60),
        }
    }
}

impl RetryConfig {
    /// Suitable for long-poll requests where server retries are handled by the outer loop.
    pub fn auth_only() -> Self {
        Self {
            max_auth_retries: 1,
            max_server_retries: 0,
            initial_backoff: Duration::from_secs(2),
            max_backoff: Duration::from_secs(60),
        }
    }
}

/// Returns `true` if the status code indicates an auth failure (401 or 403).
fn is_auth_error(status: u16) -> bool {
    status == 401 || status == 403
}

/// Send a signed GET request, automatically refreshing the token on 401/403.
pub async fn signed_get_with_retry(
    client: &Client,
    url: &str,
    agent_id: &str,
    token_provider: &TokenProvider,
    timeout: Duration,
    config: &RetryConfig,
) -> Result<Response> {
    let mut auth_retries = 0u32;
    let mut server_retries = 0u32;
    let mut backoff = config.initial_backoff;

    loop {
        let token = token_provider.get().await;
        let headers = build_signed_headers(agent_id, &token, &[])?;

        let result = client
            .get(url)
            .headers(headers)
            .timeout(timeout)
            .send()
            .await;

        match result {
            Ok(resp) => {
                let status = resp.status().as_u16();

                if is_auth_error(status) && auth_retries < config.max_auth_retries {
                    auth_retries += 1;
                    warn!(
                        status,
                        attempt = auth_retries,
                        url = %url,
                        "auth error from Stacker; refreshing token and retrying"
                    );
                    token_provider.refresh().await?;
                    continue;
                }

                if resp.status().is_server_error() && server_retries < config.max_server_retries {
                    server_retries += 1;
                    warn!(
                        status,
                        attempt = server_retries,
                        backoff_ms = backoff.as_millis() as u64,
                        "server error; retrying with backoff"
                    );
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(config.max_backoff);
                    continue;
                }

                return Ok(resp);
            }
            Err(e) => {
                if server_retries < config.max_server_retries {
                    server_retries += 1;
                    warn!(
                        error = %e,
                        attempt = server_retries,
                        "network error; retrying with backoff"
                    );
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(config.max_backoff);
                    continue;
                }
                return Err(e).context("signed GET failed after retries");
            }
        }
    }
}

/// Send a signed POST (JSON body) request with 401/403 retry.
pub async fn signed_post_with_retry<T: Serialize>(
    client: &Client,
    url: &str,
    agent_id: &str,
    token_provider: &TokenProvider,
    payload: &T,
    config: &RetryConfig,
) -> Result<Response> {
    let body_bytes = serde_json::to_vec(payload).context("serialize JSON body")?;
    let mut auth_retries = 0u32;
    let mut server_retries = 0u32;
    let mut backoff = config.initial_backoff;

    loop {
        let token = token_provider.get().await;
        let headers = build_signed_headers(agent_id, &token, &body_bytes)?;

        let result = client
            .post(url)
            .headers(headers)
            .header(CONTENT_TYPE, "application/json")
            .body(body_bytes.clone())
            .send()
            .await;

        match result {
            Ok(resp) => {
                let status = resp.status().as_u16();

                if is_auth_error(status) && auth_retries < config.max_auth_retries {
                    auth_retries += 1;
                    warn!(
                        status,
                        attempt = auth_retries,
                        url = %url,
                        "auth error on POST; refreshing token and retrying"
                    );
                    token_provider.refresh().await?;
                    continue;
                }

                if resp.status().is_server_error() && server_retries < config.max_server_retries {
                    server_retries += 1;
                    warn!(
                        status,
                        attempt = server_retries,
                        backoff_ms = backoff.as_millis() as u64,
                        "server error on POST; retrying with backoff"
                    );
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(config.max_backoff);
                    continue;
                }

                return Ok(resp);
            }
            Err(e) => {
                if server_retries < config.max_server_retries {
                    server_retries += 1;
                    warn!(
                        error = %e,
                        attempt = server_retries,
                        "network error on POST; retrying with backoff"
                    );
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(config.max_backoff);
                    continue;
                }
                return Err(e).context("signed POST failed after retries");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_values() {
        let cfg = RetryConfig::default();
        assert_eq!(cfg.max_auth_retries, 1);
        assert_eq!(cfg.max_server_retries, 3);
    }

    #[test]
    fn auth_only_config_no_server_retries() {
        let cfg = RetryConfig::auth_only();
        assert_eq!(cfg.max_server_retries, 0);
        assert_eq!(cfg.max_auth_retries, 1);
    }

    #[test]
    fn is_auth_error_detects_401_403() {
        assert!(is_auth_error(401));
        assert!(is_auth_error(403));
        assert!(!is_auth_error(200));
        assert!(!is_auth_error(500));
        assert!(!is_auth_error(404));
    }
}
