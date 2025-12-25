use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub enum UpdatePhase {
    Pending,
    Downloading,
    Verifying,
    Completed,
    Failed(String),
}

#[derive(Debug, Clone)]
pub struct UpdateStatus {
    pub phase: UpdatePhase,
}

impl UpdateStatus {
    pub fn new() -> Self {
        Self {
            phase: UpdatePhase::Pending,
        }
    }
}

pub type UpdateJobs = Arc<RwLock<HashMap<String, UpdateStatus>>>;

/// Start a background update job that downloads a binary to a temp path
/// and verifies sha256 if `UPDATE_EXPECTED_SHA256` is provided.
/// This initial version does NOT deploy the binary; it prepares it.
pub async fn start_update_job(jobs: UpdateJobs, target_version: Option<String>) -> Result<String> {
    let id = Uuid::new_v4().to_string();
    {
        let mut m = jobs.write().await;
        m.insert(id.clone(), UpdateStatus::new());
    }

    let binary_url = std::env::var("UPDATE_BINARY_URL").ok();
    let server_url = std::env::var("UPDATE_SERVER_URL").ok();

    let expected_sha = std::env::var("UPDATE_EXPECTED_SHA256").ok();

    let id_clone = id.clone();
    let jobs_clone = jobs.clone();

    tokio::spawn(async move {
        // Resolve URL
        let url = if let Some(u) = binary_url {
            u
        } else if let (Some(srv), Some(ver)) = (server_url, target_version.clone()) {
            // Detect platform and construct binary name
            let binary_name = detect_binary_name();
            format!(
                "{}/releases/{}/{}",
                srv.trim_end_matches('/'),
                ver,
                binary_name
            )
        } else {
            let mut w = jobs_clone.write().await;
            if let Some(st) = w.get_mut(&id_clone) {
                st.phase = UpdatePhase::Failed("No update URL resolved".to_string());
            }
            return;
        };

        {
            let mut w = jobs_clone.write().await;
            if let Some(st) = w.get_mut(&id_clone) {
                st.phase = UpdatePhase::Downloading;
            }
        }

        let tmp_path = format!("/tmp/status-panel.{}.bin", id_clone);
        let dl = async {
            let resp = reqwest::Client::new()
                .get(&url)
                .timeout(std::time::Duration::from_secs(300))
                .send()
                .await
                .context("download request failed")?;
            if !resp.status().is_success() {
                anyhow::bail!("download returned status {}", resp.status());
            }
            let bytes = resp.bytes().await.context("reading download bytes")?;
            tokio::fs::write(&tmp_path, &bytes)
                .await
                .context("writing temp binary")?;
            Result::<()>::Ok(())
        };

        if let Err(e) = dl.await {
            let mut w = jobs_clone.write().await;
            if let Some(st) = w.get_mut(&id_clone) {
                st.phase = UpdatePhase::Failed(e.to_string());
            }
            return;
        }

        {
            let mut w = jobs_clone.write().await;
            if let Some(st) = w.get_mut(&id_clone) {
                st.phase = UpdatePhase::Verifying;
            }
        }

        // Optional SHA256 verification
        if let Some(expected) = expected_sha {
            let verify_res = async {
                let data = tokio::fs::read(&tmp_path)
                    .await
                    .context("reading temp binary for sha256")?;
                let mut hasher = Sha256::new();
                hasher.update(&data);
                let got = format!("{:x}", hasher.finalize());
                if got != expected.to_lowercase() {
                    anyhow::bail!("sha256 mismatch: got {} expected {}", got, expected);
                }
                Result::<()>::Ok(())
            }
            .await;

            if let Err(e) = verify_res {
                let mut w = jobs_clone.write().await;
                if let Some(st) = w.get_mut(&id_clone) {
                    st.phase = UpdatePhase::Failed(e.to_string());
                }
                return;
            }
        }

        // Completed preparation (download + verify). Deployment handled in a later phase.
        let mut w = jobs_clone.write().await;
        if let Some(st) = w.get_mut(&id_clone) {
            st.phase = UpdatePhase::Completed;
        }
    });

    Ok(id)
}

pub async fn get_update_status(jobs: UpdateJobs, id: &str) -> Option<UpdateStatus> {
    let m = jobs.read().await;
    m.get(id).cloned()
}

fn detect_binary_name() -> String {
    // Detect if we're running on musl by checking for /etc/alpine-release or ldd output
    #[cfg(target_os = "linux")]
    {
        // Check if musl by trying to detect Alpine or running ldd on ourselves
        if std::path::Path::new("/etc/alpine-release").exists() {
            return "status-linux-x86_64-musl".to_string();
        }
        // Default to glibc version for Linux
        return "status-linux-x86_64".to_string();
    }
    #[cfg(target_os = "macos")]
    {
        return "status-darwin-x86_64".to_string();
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        "status-linux-x86_64".to_string()
    }
}
