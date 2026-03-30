use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct RemoteVersion {
    pub version: String,
    #[serde(default)]
    pub checksum: Option<String>,
}

/// Checks a remote update server for the latest version.
/// Falls back gracefully if `UPDATE_SERVER_URL` is not provided or unreachable.
pub async fn check_remote_version() -> Result<Option<RemoteVersion>> {
    let base = match std::env::var("UPDATE_SERVER_URL") {
        Ok(v) if !v.is_empty() => v,
        _ => return Ok(None),
    };
    // Conventional endpoint: `${UPDATE_SERVER_URL}/api/version`
    let url = format!("{}/api/version", base.trim_end_matches('/'));
    let resp = reqwest::Client::new()
        .get(&url)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .context("requesting remote version")?;

    if !resp.status().is_success() {
        return Ok(None);
    }

    let rv: RemoteVersion = resp
        .json()
        .await
        .context("parsing remote version response")?;
    Ok(Some(rv))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::EnvGuard;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn remote_version_deserialize_with_checksum() {
        let json = r#"{"version": "1.2.3", "checksum": "abc123"}"#;
        let rv: RemoteVersion = serde_json::from_str(json).unwrap();
        assert_eq!(rv.version, "1.2.3");
        assert_eq!(rv.checksum, Some("abc123".to_string()));
    }

    #[test]
    fn remote_version_deserialize_without_checksum() {
        let json = r#"{"version": "1.2.3"}"#;
        let rv: RemoteVersion = serde_json::from_str(json).unwrap();
        assert_eq!(rv.version, "1.2.3");
        assert_eq!(rv.checksum, None);
    }

    #[test]
    fn remote_version_deserialize_null_checksum() {
        let json = r#"{"version": "0.1.0", "checksum": null}"#;
        let rv: RemoteVersion = serde_json::from_str(json).unwrap();
        assert_eq!(rv.version, "0.1.0");
        assert_eq!(rv.checksum, None);
    }

    #[test]
    fn remote_version_deserialize_missing_version_fails() {
        let json = r#"{"checksum": "abc"}"#;
        let result: std::result::Result<RemoteVersion, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn check_remote_version_no_env_returns_none() {
        let _lock = env_lock().lock().expect("env lock poisoned");
        let _env = EnvGuard::remove("UPDATE_SERVER_URL");
        let result = check_remote_version().await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn check_remote_version_empty_env_returns_none() {
        let _lock = env_lock().lock().expect("env lock poisoned");
        let _env = EnvGuard::set("UPDATE_SERVER_URL", "");
        let result = check_remote_version().await.unwrap();
        assert!(result.is_none());
    }
}
