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
