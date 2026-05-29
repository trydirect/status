//! Log Caching Service
//!
//! Provides Redis-based caching for container logs with TTL expiration.
//! Features:
//! - Cache container logs by deployment + container
//! - Automatic TTL expiration (configurable, default 30 min)
//! - Log streaming support with cursor-based pagination
//! - Log summary generation for AI context

use redis::{AsyncCommands, Client as RedisClient};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Default cache TTL for logs (30 minutes)
const DEFAULT_LOG_TTL_SECONDS: u64 = 1800;

/// Maximum number of log entries to store per key
const MAX_LOG_ENTRIES: i64 = 1000;

/// Log entry structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: String,
    pub level: String,
    pub message: String,
    pub container: String,
}

/// Log cache result with pagination
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogCacheResult {
    pub entries: Vec<LogEntry>,
    pub total_count: usize,
    pub cursor: Option<String>,
    pub has_more: bool,
}

/// Log summary for AI context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogSummary {
    pub deployment_id: i32,
    pub container: Option<String>,
    pub total_entries: usize,
    pub error_count: usize,
    pub warning_count: usize,
    pub time_range: Option<(String, String)>, // (oldest, newest)
    pub common_patterns: Vec<String>,
}

/// Log caching service
pub struct LogCacheService {
    client: RedisClient,
    ttl: Duration,
}

impl LogCacheService {
    /// Create a new log cache service
    pub fn new() -> Result<Self, String> {
        let redis_url =
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".to_string());
        let ttl_seconds = std::env::var("LOG_CACHE_TTL_SECONDS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_LOG_TTL_SECONDS);

        let client = RedisClient::open(redis_url)
            .map_err(|e| format!("Failed to connect to Redis: {}", e))?;

        Ok(Self {
            client,
            ttl: Duration::from_secs(ttl_seconds),
        })
    }

    /// Generate cache key for deployment logs
    fn cache_key(deployment_id: i32, container: Option<&str>) -> String {
        match container {
            Some(c) => format!("logs:{}:{}", deployment_id, c),
            None => format!("logs:{}:all", deployment_id),
        }
    }

    /// Store log entries in cache
    pub async fn store_logs(
        &self,
        deployment_id: i32,
        container: Option<&str>,
        entries: &[LogEntry],
    ) -> Result<(), String> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| format!("Redis connection error: {}", e))?;

        let key = Self::cache_key(deployment_id, container);

        // Serialize entries as JSON array
        for entry in entries {
            let entry_json =
                serde_json::to_string(entry).map_err(|e| format!("Serialization error: {}", e))?;

            // Push to list
            conn.rpush::<_, _, ()>(&key, entry_json)
                .await
                .map_err(|e| format!("Redis rpush error: {}", e))?;
        }

        // Trim to max entries
        conn.ltrim::<_, ()>(&key, -MAX_LOG_ENTRIES as isize, -1)
            .await
            .map_err(|e| format!("Redis ltrim error: {}", e))?;

        // Set TTL
        conn.expire::<_, ()>(&key, self.ttl.as_secs() as i64)
            .await
            .map_err(|e| format!("Redis expire error: {}", e))?;

        tracing::debug!(
            deployment_id = deployment_id,
            container = ?container,
            entry_count = entries.len(),
            "Stored logs in cache"
        );

        Ok(())
    }

    /// Retrieve logs from cache with pagination
    pub async fn get_logs(
        &self,
        deployment_id: i32,
        container: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<LogCacheResult, String> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| format!("Redis connection error: {}", e))?;

        let key = Self::cache_key(deployment_id, container);

        // Get total count
        let total_count: i64 = conn.llen(&key).await.unwrap_or(0);

        if total_count == 0 {
            return Ok(LogCacheResult {
                entries: vec![],
                total_count: 0,
                cursor: None,
                has_more: false,
            });
        }

        // Get range (newest first, so we reverse indices)
        let start = -(offset as isize) - (limit as isize);
        let stop = -(offset as isize) - 1;

        let raw_entries: Vec<String> = conn
            .lrange(&key, start.max(0), stop)
            .await
            .unwrap_or_default();

        let entries: Vec<LogEntry> = raw_entries
            .iter()
            .rev() // Reverse to get newest first
            .filter_map(|s| serde_json::from_str(s).ok())
            .collect();

        let has_more = offset + entries.len() < total_count as usize;
        let cursor = if has_more {
            Some((offset + limit).to_string())
        } else {
            None
        };

        Ok(LogCacheResult {
            entries,
            total_count: total_count as usize,
            cursor,
            has_more,
        })
    }

    /// Generate a summary of cached logs for AI context
    pub async fn get_log_summary(
        &self,
        deployment_id: i32,
        container: Option<&str>,
    ) -> Result<LogSummary, String> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| format!("Redis connection error: {}", e))?;

        let key = Self::cache_key(deployment_id, container);

        // Get all entries for analysis
        let raw_entries: Vec<String> = conn.lrange(&key, 0, -1).await.unwrap_or_default();

        let entries: Vec<LogEntry> = raw_entries
            .iter()
            .filter_map(|s| serde_json::from_str(s).ok())
            .collect();

        if entries.is_empty() {
            return Ok(LogSummary {
                deployment_id,
                container: container.map(|s| s.to_string()),
                total_entries: 0,
                error_count: 0,
                warning_count: 0,
                time_range: None,
                common_patterns: vec![],
            });
        }

        // Count by level
        let error_count = entries
            .iter()
            .filter(|e| e.level.to_lowercase() == "error")
            .count();
        let warning_count = entries
            .iter()
            .filter(|e| e.level.to_lowercase() == "warn" || e.level.to_lowercase() == "warning")
            .count();

        // Get time range
        let time_range = if !entries.is_empty() {
            let oldest = entries
                .first()
                .map(|e| e.timestamp.clone())
                .unwrap_or_default();
            let newest = entries
                .last()
                .map(|e| e.timestamp.clone())
                .unwrap_or_default();
            Some((oldest, newest))
        } else {
            None
        };

        // Extract common error patterns
        let common_patterns = self.extract_error_patterns(&entries);

        Ok(LogSummary {
            deployment_id,
            container: container.map(|s| s.to_string()),
            total_entries: entries.len(),
            error_count,
            warning_count,
            time_range,
            common_patterns,
        })
    }

    /// Extract common error patterns from log entries
    fn extract_error_patterns(&self, entries: &[LogEntry]) -> Vec<String> {
        use std::collections::HashMap;

        let mut patterns: HashMap<String, usize> = HashMap::new();

        for entry in entries.iter().filter(|e| e.level.to_lowercase() == "error") {
            // Extract key error indicators
            let msg = &entry.message;

            // Common error patterns to track
            if msg.contains("connection refused") || msg.contains("ECONNREFUSED") {
                *patterns
                    .entry("Connection refused".to_string())
                    .or_insert(0) += 1;
            }
            if msg.contains("timeout") || msg.contains("ETIMEDOUT") {
                *patterns.entry("Timeout".to_string()).or_insert(0) += 1;
            }
            if msg.contains("permission denied") || msg.contains("EACCES") {
                *patterns.entry("Permission denied".to_string()).or_insert(0) += 1;
            }
            if msg.contains("out of memory") || msg.contains("OOM") || msg.contains("ENOMEM") {
                *patterns.entry("Out of memory".to_string()).or_insert(0) += 1;
            }
            if msg.contains("disk full") || msg.contains("ENOSPC") {
                *patterns.entry("Disk full".to_string()).or_insert(0) += 1;
            }
            if msg.contains("not found") || msg.contains("ENOENT") {
                *patterns
                    .entry("Resource not found".to_string())
                    .or_insert(0) += 1;
            }
            if msg.contains("authentication") || msg.contains("unauthorized") || msg.contains("401")
            {
                *patterns
                    .entry("Authentication error".to_string())
                    .or_insert(0) += 1;
            }
            if msg.contains("certificate") || msg.contains("SSL") || msg.contains("TLS") {
                *patterns.entry("SSL/TLS error".to_string()).or_insert(0) += 1;
            }
        }

        // Sort by frequency and return top patterns
        let mut sorted: Vec<_> = patterns.into_iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));

        sorted
            .into_iter()
            .take(5)
            .map(|(pattern, count)| format!("{} ({}x)", pattern, count))
            .collect()
    }

    /// Clear cached logs for a deployment
    pub async fn clear_logs(
        &self,
        deployment_id: i32,
        container: Option<&str>,
    ) -> Result<(), String> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| format!("Redis connection error: {}", e))?;

        let key = Self::cache_key(deployment_id, container);
        conn.del::<_, ()>(&key)
            .await
            .map_err(|e| format!("Redis del error: {}", e))?;

        tracing::info!(
            deployment_id = deployment_id,
            container = ?container,
            "Cleared cached logs"
        );

        Ok(())
    }

    /// Extend TTL on cache hit (sliding expiration)
    pub async fn touch_logs(
        &self,
        deployment_id: i32,
        container: Option<&str>,
    ) -> Result<(), String> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| format!("Redis connection error: {}", e))?;

        let key = Self::cache_key(deployment_id, container);
        conn.expire::<_, ()>(&key, self.ttl.as_secs() as i64)
            .await
            .map_err(|e| format!("Redis expire error: {}", e))?;

        Ok(())
    }
}

impl Default for LogCacheService {
    fn default() -> Self {
        Self::new().expect("Failed to create LogCacheService")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_key_with_container() {
        let key = LogCacheService::cache_key(123, Some("nginx"));
        assert_eq!(key, "logs:123:nginx");
    }

    #[test]
    fn test_cache_key_without_container() {
        let key = LogCacheService::cache_key(123, None);
        assert_eq!(key, "logs:123:all");
    }
}
