use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::Path;
use tokio::process::Command;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RollbackEntry {
    pub job_id: String,
    pub backup_path: String,
    pub install_path: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct RollbackManifest {
    pub entries: Vec<RollbackEntry>,
}

fn storage_path() -> String {
    std::env::var("UPDATE_STORAGE_PATH").unwrap_or_else(|_| "/var/lib/status-panel".to_string())
}

fn manifest_path() -> String {
    format!("{}/rollback.manifest", storage_path())
}

pub async fn load_manifest() -> Result<RollbackManifest> {
    let p = manifest_path();
    if !Path::new(&p).exists() {
        return Ok(RollbackManifest::default());
    }
    let data = tokio::fs::read(&p)
        .await
        .context("reading rollback manifest")?;
    Ok(serde_json::from_slice(&data).context("parsing rollback manifest")?)
}

pub async fn save_manifest(m: &RollbackManifest) -> Result<()> {
    let p = manifest_path();
    if let Some(dir) = Path::new(&p).parent() {
        tokio::fs::create_dir_all(dir).await.ok();
    }
    let data = serde_json::to_vec_pretty(m).context("serializing rollback manifest")?;
    tokio::fs::write(&p, data)
        .await
        .context("writing rollback manifest")
}

pub async fn backup_current_binary(install_path: &str, job_id: &str) -> Result<String> {
    let ts = Utc::now().format("%Y%m%d%H%M%S");
    let backup_dir = format!("{}/backups", storage_path());
    tokio::fs::create_dir_all(&backup_dir).await.ok();
    let backup_path = format!("{}/status.{}.{}.bak", backup_dir, ts, job_id);
    tokio::fs::copy(install_path, &backup_path)
        .await
        .context("copying current binary to backup")?;
    Ok(backup_path)
}

pub async fn deploy_temp_binary(job_id: &str, install_path: &str) -> Result<String> {
    let tmp_path = format!("/tmp/status-panel.{}.bin", job_id);
    // move temp to install path and chmod +x
    tokio::fs::copy(&tmp_path, install_path)
        .await
        .context("installing new binary")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = tokio::fs::metadata(install_path).await?;
        let mut perms = meta.permissions();
        perms.set_mode(0o755);
        tokio::fs::set_permissions(install_path, perms).await?;
    }
    Ok(tmp_path)
}

pub async fn restart_service(service_name: &str) -> Result<()> {
    // Best-effort systemd restart; if not present, return error.
    let status = Command::new("systemctl")
        .arg("restart")
        .arg(service_name)
        .status()
        .await
        .context("running systemctl restart")?;
    if !status.success() {
        anyhow::bail!("systemctl restart failed with status {:?}", status.code());
    }
    Ok(())
}

pub async fn record_rollback(job_id: &str, backup_path: &str, install_path: &str) -> Result<()> {
    let mut m = load_manifest().await?;
    m.entries.push(RollbackEntry {
        job_id: job_id.to_string(),
        backup_path: backup_path.to_string(),
        install_path: install_path.to_string(),
        timestamp: Utc::now(),
    });
    save_manifest(&m).await
}

pub async fn rollback_latest() -> Result<Option<RollbackEntry>> {
    let mut m = load_manifest().await?;
    let entry = match m.entries.pop() {
        Some(e) => e,
        None => return Ok(None),
    };
    // restore backup to install path
    tokio::fs::copy(&entry.backup_path, &entry.install_path)
        .await
        .context("restoring backup binary")?;
    save_manifest(&m).await?;
    Ok(Some(entry))
}
