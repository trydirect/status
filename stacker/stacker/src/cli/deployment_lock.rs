use std::path::{Path, PathBuf};

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::cli::config_parser::{ServerConfig, StackerConfig};
use crate::cli::error::CliError;
use crate::cli::install_runner::DeployResult;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// DeploymentLock — persisted deployment context
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Legacy filename for the deployment lockfile inside `.stacker/`.
pub const LOCKFILE_NAME: &str = "deployment.lock";

/// Returns the per-target lockfile name, e.g. `deployment-cloud.lock`.
pub fn lockfile_name_for_target(target: &str) -> String {
    format!("deployment-{}.lock", target)
}

/// Persisted deployment context written after a successful deploy.
///
/// Lives in `.stacker/deployment.lock` and allows subsequent deploys
/// to reuse the same server without requiring manual stacker.yml edits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentLock {
    /// Deploy target that was used (local / cloud / server).
    pub target: String,

    /// IP address of the provisioned/used server.
    pub server_ip: Option<String>,

    /// SSH user on the target server.
    pub ssh_user: Option<String>,

    /// SSH port on the target server.
    pub ssh_port: Option<u16>,

    /// Server name on the Stacker platform (for `--server` reuse).
    pub server_name: Option<String>,

    /// Stacker server deployment ID.
    pub deployment_id: Option<i64>,

    /// Stacker server project ID.
    pub project_id: Option<i64>,

    /// Cloud credential ID used for this deployment.
    pub cloud_id: Option<i32>,

    /// Project name as known by the Stacker server.
    pub project_name: Option<String>,

    /// Stacker account email used for the deployment.
    pub stacker_email: Option<String>,

    /// ISO 8601 timestamp of the deployment.
    pub deployed_at: String,
}

impl DeploymentLock {
    // ── Constructors ─────────────────────────────────

    /// Build a lock from a `DeployResult` (basic info available immediately after deploy).
    pub fn from_result(result: &DeployResult) -> Self {
        Self {
            target: format!("{:?}", result.target).to_lowercase(),
            server_ip: result.server_ip.clone(),
            ssh_user: None,
            ssh_port: None,
            server_name: None,
            deployment_id: result.deployment_id,
            project_id: result.project_id,
            cloud_id: None,
            project_name: None,
            stacker_email: None,
            deployed_at: Utc::now().to_rfc3339(),
        }
    }

    /// Build a lock for a local deploy.
    pub fn for_local() -> Self {
        Self {
            target: "local".to_string(),
            server_ip: Some("127.0.0.1".to_string()),
            ssh_user: None,
            ssh_port: None,
            server_name: None,
            deployment_id: None,
            project_id: None,
            cloud_id: None,
            project_name: None,
            stacker_email: None,
            deployed_at: Utc::now().to_rfc3339(),
        }
    }

    /// Build a lock for a server (SSH) deploy from the config.
    pub fn for_server(server_cfg: &ServerConfig) -> Self {
        Self {
            target: "server".to_string(),
            server_ip: Some(server_cfg.host.clone()),
            ssh_user: Some(server_cfg.user.clone()),
            ssh_port: Some(server_cfg.port),
            server_name: None,
            deployment_id: None,
            project_id: None,
            cloud_id: None,
            project_name: None,
            stacker_email: None,
            deployed_at: Utc::now().to_rfc3339(),
        }
    }

    // ── Enrichment (builder pattern) ─────────────────

    /// Enrich with server details fetched from the Stacker API.
    pub fn with_server_info(
        mut self,
        ip: Option<String>,
        user: Option<String>,
        port: Option<u16>,
        name: Option<String>,
        cloud_id: Option<i32>,
    ) -> Self {
        if ip.is_some() {
            self.server_ip = ip;
        }
        if user.is_some() {
            self.ssh_user = user;
        }
        if port.is_some() {
            self.ssh_port = port;
        }
        if name.is_some() {
            self.server_name = name;
        }
        if cloud_id.is_some() {
            self.cloud_id = cloud_id;
        }
        self
    }

    pub fn with_project_name(mut self, name: Option<String>) -> Self {
        if name.is_some() {
            self.project_name = name;
        }
        self
    }

    pub fn with_stacker_email(mut self, email: Option<String>) -> Self {
        if email.is_some() {
            self.stacker_email = email;
        }
        self
    }

    // ── Persistence ──────────────────────────────────

    /// Resolve the per-target lockfile path (e.g. `.stacker/deployment-cloud.lock`).
    pub fn lockfile_path_for_target(project_dir: &Path, target: &str) -> PathBuf {
        project_dir
            .join(".stacker")
            .join(lockfile_name_for_target(target))
    }

    /// Legacy lockfile path (`.stacker/deployment.lock`).
    pub fn lockfile_path(project_dir: &Path) -> PathBuf {
        project_dir.join(".stacker").join(LOCKFILE_NAME)
    }

    /// Save the lock to `.stacker/deployment-{target}.lock`.
    pub fn save(&self, project_dir: &Path) -> Result<PathBuf, CliError> {
        let path = Self::lockfile_path_for_target(project_dir, &self.target);

        // Ensure .stacker/ exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(CliError::Io)?;
        }

        let content = serde_yaml::to_string(self).map_err(|e| {
            CliError::ConfigValidation(format!("Failed to serialize deployment lock: {}", e))
        })?;

        std::fs::write(&path, &content).map_err(CliError::Io)?;

        Ok(path)
    }

    /// Load a deployment lock for a specific target.
    /// Falls back to the legacy `deployment.lock` if the per-target file doesn't exist.
    pub fn load_for_target(project_dir: &Path, target: &str) -> Result<Option<Self>, CliError> {
        let target_path = Self::lockfile_path_for_target(project_dir, target);
        if target_path.exists() {
            let content = std::fs::read_to_string(&target_path).map_err(CliError::Io)?;
            let lock: Self = serde_yaml::from_str(&content).map_err(|e| {
                CliError::ConfigValidation(format!(
                    "Failed to parse deployment lock ({}): {}. Delete the file and redeploy.",
                    target_path.display(),
                    e
                ))
            })?;
            return Ok(Some(lock));
        }

        // Fallback: try legacy deployment.lock (only if its target matches)
        Self::load_legacy(project_dir, Some(target))
    }

    /// Load the legacy `deployment.lock`, optionally filtering by target.
    fn load_legacy(
        project_dir: &Path,
        filter_target: Option<&str>,
    ) -> Result<Option<Self>, CliError> {
        let path = Self::lockfile_path(project_dir);
        if !path.exists() {
            return Ok(None);
        }

        let content = std::fs::read_to_string(&path).map_err(CliError::Io)?;
        let lock: Self = serde_yaml::from_str(&content).map_err(|e| {
            CliError::ConfigValidation(format!(
                "Failed to parse deployment lock ({}): {}. Delete the file and redeploy.",
                path.display(),
                e
            ))
        })?;

        if let Some(target) = filter_target {
            if lock.target != target {
                return Ok(None);
            }
        }

        Ok(Some(lock))
    }

    /// Load a deployment lock from `.stacker/deployment.lock` (legacy).
    /// Returns `None` if the file does not exist.
    pub fn load(project_dir: &Path) -> Result<Option<Self>, CliError> {
        // Try all per-target files first, then fall back to legacy
        for target in &["cloud", "server", "local"] {
            let target_path = Self::lockfile_path_for_target(project_dir, target);
            if target_path.exists() {
                let content = std::fs::read_to_string(&target_path).map_err(CliError::Io)?;
                let lock: Self = serde_yaml::from_str(&content).map_err(|e| {
                    CliError::ConfigValidation(format!(
                        "Failed to parse deployment lock ({}): {}. Delete the file and redeploy.",
                        target_path.display(),
                        e
                    ))
                })?;
                return Ok(Some(lock));
            }
        }

        Self::load_legacy(project_dir, None)
    }

    /// Load the lock for the active target if present, otherwise fall back to the
    /// first available lock.
    pub fn load_active(project_dir: &Path) -> Result<Option<Self>, CliError> {
        if let Some(target) = Self::read_active_target(project_dir)? {
            if let Some(lock) = Self::load_for_target(project_dir, &target)? {
                return Ok(Some(lock));
            }
        }

        Self::load(project_dir)
    }

    /// Check whether a lockfile exists for a given target.
    pub fn exists_for_target(project_dir: &Path, target: &str) -> bool {
        Self::lockfile_path_for_target(project_dir, target).exists()
    }

    /// Check whether any lockfile exists for this project (per-target or legacy).
    pub fn exists(project_dir: &Path) -> bool {
        for target in &["cloud", "server", "local"] {
            if Self::lockfile_path_for_target(project_dir, target).exists() {
                return true;
            }
        }
        Self::lockfile_path(project_dir).exists()
    }

    // ── Active Target ────────────────────────────────

    /// Path to the active-target file: `.stacker/active-target`
    pub fn active_target_path(project_dir: &Path) -> PathBuf {
        project_dir.join(".stacker").join("active-target")
    }

    /// Read the current active target (local, cloud, or server).
    /// Returns `None` if no active-target file exists.
    pub fn read_active_target(project_dir: &Path) -> Result<Option<String>, CliError> {
        let path = Self::active_target_path(project_dir);
        if !path.exists() {
            return Ok(None);
        }
        let content = std::fs::read_to_string(&path).map_err(CliError::Io)?;
        let target = content.trim().to_string();
        if target.is_empty() {
            Ok(None)
        } else {
            Ok(Some(target))
        }
    }

    /// Write the active target to `.stacker/active-target`.
    pub fn write_active_target(project_dir: &Path, target: &str) -> Result<(), CliError> {
        let path = Self::active_target_path(project_dir);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(CliError::Io)?;
        }
        std::fs::write(&path, target).map_err(CliError::Io)?;
        Ok(())
    }

    /// Switch active target. For `local`, also creates the lock if missing.
    pub fn switch_target(project_dir: &Path, target: &str) -> Result<(), CliError> {
        match target {
            "local" => {
                if !Self::exists_for_target(project_dir, "local") {
                    let lock = Self::for_local();
                    lock.save(project_dir)?;
                }
            }
            "cloud" | "server" => {
                if !Self::exists_for_target(project_dir, target) {
                    return Err(CliError::ConfigValidation(format!(
                        "No {} deployment lock found. Deploy to {} first before switching.",
                        target, target
                    )));
                }
            }
            _ => {
                return Err(CliError::ConfigValidation(format!(
                    "Unknown target '{}'. Use: local, cloud, or server.",
                    target
                )));
            }
        }
        Self::write_active_target(project_dir, target)
    }

    // ── Config update ────────────────────────────────

    /// Update a StackerConfig's `deploy.server` section from this lock.
    ///
    /// Used by `--lock` flag and `stacker config lock` to persist
    /// server details into stacker.yml for future SSH-based deploys.
    pub fn apply_to_config(&self, config: &mut StackerConfig) {
        if let Some(ref ip) = self.server_ip {
            if ip == "127.0.0.1" {
                // Local deploy — nothing to persist in server section
                return;
            }

            let ssh_key = config
                .deploy
                .server
                .as_ref()
                .and_then(|s| s.ssh_key.clone())
                .or_else(|| config.deploy.cloud.as_ref().and_then(|c| c.ssh_key.clone()));

            config.deploy.server = Some(ServerConfig {
                host: ip.clone(),
                user: self.ssh_user.clone().unwrap_or_else(|| "root".to_string()),
                ssh_key,
                port: self.ssh_port.unwrap_or(22),
            });
        }
    }

    /// Write a StackerConfig back to disk (used after `apply_to_config`).
    ///
    /// Creates a `.bak` backup before overwriting.
    pub fn write_config(config: &StackerConfig, config_path: &Path) -> Result<(), CliError> {
        // Backup existing file
        if config_path.exists() {
            let backup_path = config_path.with_extension("yml.bak");
            std::fs::copy(config_path, &backup_path).map_err(CliError::Io)?;
        }

        let yaml = serde_yaml::to_string(config).map_err(|e| {
            CliError::ConfigValidation(format!("Failed to serialize config: {}", e))
        })?;

        std::fs::write(config_path, &yaml).map_err(CliError::Io)?;

        Ok(())
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Tests
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::config_parser::DeployTarget;
    use tempfile::TempDir;

    fn sample_lock() -> DeploymentLock {
        DeploymentLock {
            target: "cloud".to_string(),
            server_ip: Some("203.0.113.42".to_string()),
            ssh_user: Some("root".to_string()),
            ssh_port: Some(22),
            server_name: Some("my-server".to_string()),
            deployment_id: Some(123),
            project_id: Some(456),
            cloud_id: Some(7),
            project_name: Some("my-project".to_string()),
            stacker_email: Some("owner@example.com".to_string()),
            deployed_at: "2026-03-06T12:00:00+00:00".to_string(),
        }
    }

    #[test]
    fn round_trip_save_load() {
        let tmp = TempDir::new().unwrap();
        let lock = sample_lock();

        let path = lock.save(tmp.path()).unwrap();
        assert!(path.exists());
        assert!(path.ends_with("deployment-cloud.lock"));

        let loaded = DeploymentLock::load_for_target(tmp.path(), "cloud")
            .unwrap()
            .unwrap();
        assert_eq!(loaded.server_ip, lock.server_ip);
        assert_eq!(loaded.deployment_id, lock.deployment_id);
        assert_eq!(loaded.project_id, lock.project_id);
        assert_eq!(loaded.server_name, lock.server_name);
        assert_eq!(loaded.stacker_email, lock.stacker_email);
        assert_eq!(loaded.target, "cloud");
    }

    #[test]
    fn load_returns_none_when_missing() {
        let tmp = TempDir::new().unwrap();
        let result = DeploymentLock::load(tmp.path()).unwrap();
        assert!(result.is_none());
        let result = DeploymentLock::load_for_target(tmp.path(), "cloud").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn exists_detection() {
        let tmp = TempDir::new().unwrap();
        assert!(!DeploymentLock::exists(tmp.path()));
        assert!(!DeploymentLock::exists_for_target(tmp.path(), "cloud"));

        sample_lock().save(tmp.path()).unwrap();
        assert!(DeploymentLock::exists(tmp.path()));
        assert!(DeploymentLock::exists_for_target(tmp.path(), "cloud"));
        assert!(!DeploymentLock::exists_for_target(tmp.path(), "local"));
    }

    #[test]
    fn local_and_cloud_locks_coexist() {
        let tmp = TempDir::new().unwrap();

        // Save cloud lock
        let cloud_lock = sample_lock();
        cloud_lock.save(tmp.path()).unwrap();

        // Save local lock
        let local_lock = DeploymentLock::for_local();
        local_lock.save(tmp.path()).unwrap();

        // Both exist
        assert!(DeploymentLock::exists_for_target(tmp.path(), "cloud"));
        assert!(DeploymentLock::exists_for_target(tmp.path(), "local"));

        // Load each independently
        let loaded_cloud = DeploymentLock::load_for_target(tmp.path(), "cloud")
            .unwrap()
            .unwrap();
        assert_eq!(loaded_cloud.server_ip, Some("203.0.113.42".to_string()));
        assert_eq!(loaded_cloud.deployment_id, Some(123));

        let loaded_local = DeploymentLock::load_for_target(tmp.path(), "local")
            .unwrap()
            .unwrap();
        assert_eq!(loaded_local.server_ip, Some("127.0.0.1".to_string()));
        assert_eq!(loaded_local.deployment_id, None);

        // Generic load() prefers cloud over local
        let generic = DeploymentLock::load(tmp.path()).unwrap().unwrap();
        assert_eq!(generic.target, "cloud");
    }

    #[test]
    fn legacy_lockfile_fallback() {
        let tmp = TempDir::new().unwrap();

        // Manually write a legacy deployment.lock
        let stacker_dir = tmp.path().join(".stacker");
        std::fs::create_dir_all(&stacker_dir).unwrap();
        let legacy_lock = sample_lock();
        let content = serde_yaml::to_string(&legacy_lock).unwrap();
        std::fs::write(stacker_dir.join("deployment.lock"), &content).unwrap();

        // load_for_target("cloud") should find it via legacy fallback
        let loaded = DeploymentLock::load_for_target(tmp.path(), "cloud")
            .unwrap()
            .unwrap();
        assert_eq!(loaded.target, "cloud");
        assert_eq!(loaded.deployment_id, Some(123));

        // load_for_target("local") should NOT find it (target mismatch)
        let loaded_local = DeploymentLock::load_for_target(tmp.path(), "local").unwrap();
        assert!(loaded_local.is_none());

        // Generic load() should find the legacy file
        let generic = DeploymentLock::load(tmp.path()).unwrap().unwrap();
        assert_eq!(generic.target, "cloud");
    }

    #[test]
    fn apply_to_config_sets_server_section() {
        let lock = sample_lock();
        let mut config = StackerConfig::default();

        lock.apply_to_config(&mut config);

        let server = config.deploy.server.unwrap();
        assert_eq!(server.host, "203.0.113.42");
        assert_eq!(server.user, "root");
        assert_eq!(server.port, 22);
    }

    #[test]
    fn apply_to_config_skips_local() {
        let lock = DeploymentLock::for_local();
        let mut config = StackerConfig::default();

        lock.apply_to_config(&mut config);

        assert!(config.deploy.server.is_none());
    }

    #[test]
    fn for_server_captures_config() {
        let server_cfg = ServerConfig {
            host: "10.0.0.1".to_string(),
            user: "deploy".to_string(),
            ssh_key: None,
            port: 2222,
        };

        let lock = DeploymentLock::for_server(&server_cfg);
        assert_eq!(lock.server_ip, Some("10.0.0.1".to_string()));
        assert_eq!(lock.ssh_user, Some("deploy".to_string()));
        assert_eq!(lock.ssh_port, Some(2222));
        assert_eq!(lock.target, "server");
    }

    #[test]
    fn with_server_info_enriches_lock() {
        let lock = DeploymentLock::from_result(&DeployResult {
            target: DeployTarget::Cloud,
            message: "deployed".to_string(),
            server_ip: None,
            deployment_id: Some(1),
            project_id: Some(2),
            server_name: None,
        });

        let enriched = lock.with_server_info(
            Some("1.2.3.4".to_string()),
            Some("ubuntu".to_string()),
            Some(22),
            Some("prod-01".to_string()),
            Some(99),
        );

        assert_eq!(enriched.server_ip, Some("1.2.3.4".to_string()));
        assert_eq!(enriched.ssh_user, Some("ubuntu".to_string()));
        assert_eq!(enriched.server_name, Some("prod-01".to_string()));
        assert_eq!(enriched.cloud_id, Some(99));
    }

    #[test]
    fn with_stacker_email_enriches_lock() {
        let lock = DeploymentLock::for_local().with_stacker_email(Some("user@example.com".into()));
        assert_eq!(lock.stacker_email.as_deref(), Some("user@example.com"));
    }

    #[test]
    fn active_target_read_write() {
        let tmp = TempDir::new().unwrap();

        // No active target initially
        assert_eq!(
            DeploymentLock::read_active_target(tmp.path()).unwrap(),
            None
        );

        // Write and read back
        DeploymentLock::write_active_target(tmp.path(), "local").unwrap();
        assert_eq!(
            DeploymentLock::read_active_target(tmp.path()).unwrap(),
            Some("local".to_string())
        );

        // Switch to cloud
        DeploymentLock::write_active_target(tmp.path(), "cloud").unwrap();
        assert_eq!(
            DeploymentLock::read_active_target(tmp.path()).unwrap(),
            Some("cloud".to_string())
        );
    }

    #[test]
    fn switch_target_creates_local_lock() {
        let tmp = TempDir::new().unwrap();

        // Switch to local — should create the lock automatically
        DeploymentLock::switch_target(tmp.path(), "local").unwrap();
        assert!(DeploymentLock::exists_for_target(tmp.path(), "local"));
        assert_eq!(
            DeploymentLock::read_active_target(tmp.path()).unwrap(),
            Some("local".to_string())
        );
    }

    #[test]
    fn switch_target_cloud_requires_existing_lock() {
        let tmp = TempDir::new().unwrap();

        // Switch to cloud without a lock should fail
        let result = DeploymentLock::switch_target(tmp.path(), "cloud");
        assert!(result.is_err());
    }

    #[test]
    fn switch_target_unknown_target_fails() {
        let tmp = TempDir::new().unwrap();
        let result = DeploymentLock::switch_target(tmp.path(), "mars");
        assert!(result.is_err());
    }

    #[test]
    fn load_active_prefers_active_target_lock() {
        let tmp = TempDir::new().unwrap();

        sample_lock().save(tmp.path()).unwrap();
        DeploymentLock::for_local().save(tmp.path()).unwrap();
        DeploymentLock::write_active_target(tmp.path(), "local").unwrap();

        let lock = DeploymentLock::load_active(tmp.path()).unwrap().unwrap();
        assert_eq!(lock.target, "local");
    }
}
