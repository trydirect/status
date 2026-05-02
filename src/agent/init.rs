use std::path::Path;

use anyhow::{Context, Result};
use tracing::info;

/// Default config.json content with sensible defaults.
const DEFAULT_CONFIG: &str = r#"{
    "ssl": "letsencrypt",
    "domain": "example.com",
    "reqdata": {
        "email": "admin@example.com"
    },
    "apps_info": null,
    "subdomains": {},
    "compose_agent_enabled": false,
    "control_plane": "status_panel"
}
"#;

/// Default .env content with documented variables.
const DEFAULT_ENV: &str = r#"# Status Panel Agent – Environment Configuration
# Docs: https://github.com/trydirect/status

# ── Agent Identity (set after running `status register`) ─────────────
AGENT_ID=
AGENT_TOKEN=

# ── Dashboard / Stacker Server ───────────────────────────────────────
DASHBOARD_URL=https://stacker.try.direct

# ── Polling (pull-based command loop) ────────────────────────────────
POLLING_TIMEOUT_SECS=30
POLLING_BACKOFF_SECS=5
COMMAND_TIMEOUT_SECS=300

# ── Metrics ──────────────────────────────────────────────────────────
METRICS_INTERVAL_SECS=15
# METRICS_WEBHOOK=https://example.com/metrics

# ── UI / API credentials (must be set explicitly before use) ─────────
STATUS_PANEL_USERNAME=
STATUS_PANEL_PASSWORD=

# ── Docker ───────────────────────────────────────────────────────────
# DOCKER_SOCK=unix:///var/run/docker.sock
# NGINX_CONTAINER=nginx

# ── Compose Agent ────────────────────────────────────────────────────
# COMPOSE_AGENT_ENABLED=false

# ── Backup / Security ───────────────────────────────────────────────
# DEPLOYMENT_HASH=
# BACKUP_PATH=/data/encrypted/backup.tar.gz.cpt
# TRYDIRECT_IP=

# ── Vault (optional) ────────────────────────────────────────────────
# VAULT_ADDRESS=http://127.0.0.1:8200
# VAULT_TOKEN=
# STACKER_SERVER_ID=
# STATUS_PANEL_PROXY_OWNER=true
# NPM_ALLOW_ENV_FALLBACK=false

# ── Self-update (optional) ──────────────────────────────────────────
# UPDATE_SERVER_URL=
# UPDATE_BINARY_URL=
# UPDATE_EXPECTED_SHA256=
# UPDATE_STORAGE_PATH=/var/lib/status-panel
"#;

/// Result of the init operation, indicating which files were created.
pub struct InitResult {
    pub config_created: bool,
    pub env_created: bool,
    pub config_path: String,
    pub env_path: String,
}

/// Generate default config.json and .env files in the given directory.
///
/// Existing files are never overwritten unless `force` is true.
/// The .env file is created with restricted permissions (0600) on Unix.
pub fn generate_default_config(dir: &Path, force: bool) -> Result<InitResult> {
    let config_path = dir.join("config.json");
    let env_path = dir.join(".env");

    let config_created =
        write_if_absent(&config_path, DEFAULT_CONFIG, force).context("writing config.json")?;
    let env_created =
        write_if_absent_secure(&env_path, DEFAULT_ENV, force).context("writing .env")?;

    if config_created {
        info!(path = %config_path.display(), "created default config.json");
    }
    if env_created {
        info!(path = %env_path.display(), "created default .env");
    }

    Ok(InitResult {
        config_created,
        env_created,
        config_path: config_path.display().to_string(),
        env_path: env_path.display().to_string(),
    })
}

/// Write `content` to `path` atomically if the file does not exist.
/// When `force` is true, truncates and overwrites.
/// Returns `true` when the file was actually written.
fn write_if_absent(path: &Path, content: &str, force: bool) -> Result<bool> {
    use std::fs::OpenOptions;
    use std::io::Write;

    if force {
        std::fs::write(path, content)?;
        return Ok(true);
    }

    // Atomic create: fails with AlreadyExists if file is present (no TOCTOU)
    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(mut f) => {
            f.write_all(content.as_bytes())?;
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// Like `write_if_absent` but sets 0600 permissions on Unix (for secret-bearing files).
fn write_if_absent_secure(path: &Path, content: &str, force: bool) -> Result<bool> {
    use std::fs::OpenOptions;
    use std::io::Write;

    if force {
        write_with_restricted_perms(path, content)?;
        return Ok(true);
    }

    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(mut f) => {
            f.write_all(content.as_bytes())?;
            drop(f);
            set_restricted_perms(path);
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(e) => Err(e.into()),
    }
}

fn write_with_restricted_perms(path: &Path, content: &str) -> Result<()> {
    std::fs::write(path, content)?;
    set_restricted_perms(path);
    Ok(())
}

#[cfg(unix)]
fn set_restricted_perms(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn set_restricted_perms(_path: &Path) {
    // No-op on non-Unix platforms
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_creates_both_files() {
        let dir = tempfile::tempdir().unwrap();
        let result = generate_default_config(dir.path(), false).unwrap();

        assert!(result.config_created);
        assert!(result.env_created);

        let config_content = std::fs::read_to_string(dir.path().join("config.json")).unwrap();
        assert!(config_content.contains("\"domain\""));
        assert!(config_content.contains("\"reqdata\""));

        let env_content = std::fs::read_to_string(dir.path().join(".env")).unwrap();
        assert!(env_content.contains("AGENT_ID="));
        assert!(env_content.contains("DASHBOARD_URL="));
    }

    #[test]
    fn test_generate_skips_existing_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("config.json"), "existing").unwrap();

        let result = generate_default_config(dir.path(), false).unwrap();

        assert!(!result.config_created);
        assert!(result.env_created);

        // Original file untouched
        let content = std::fs::read_to_string(dir.path().join("config.json")).unwrap();
        assert_eq!(content, "existing");
    }

    #[test]
    fn test_generate_force_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("config.json"), "old").unwrap();

        let result = generate_default_config(dir.path(), true).unwrap();

        assert!(result.config_created);
        let content = std::fs::read_to_string(dir.path().join("config.json")).unwrap();
        assert!(content.contains("\"domain\""));
    }

    #[test]
    fn test_default_config_is_valid_json() {
        let parsed: serde_json::Value = serde_json::from_str(DEFAULT_CONFIG).unwrap();
        assert_eq!(parsed["domain"], "example.com");
        assert_eq!(parsed["reqdata"]["email"], "admin@example.com");
    }

    #[test]
    fn test_default_config_deserializes_to_config() {
        let cfg: super::super::config::Config = serde_json::from_str(DEFAULT_CONFIG).unwrap();
        assert_eq!(cfg.domain.as_deref(), Some("example.com"));
        assert_eq!(cfg.reqdata.email, "admin@example.com");
        assert!(!cfg.compose_agent_enabled);
    }

    #[test]
    fn test_env_contains_all_documented_vars() {
        assert!(DEFAULT_ENV.contains("AGENT_ID="));
        assert!(DEFAULT_ENV.contains("AGENT_TOKEN="));
        assert!(DEFAULT_ENV.contains("DASHBOARD_URL="));
        assert!(DEFAULT_ENV.contains("STATUS_PANEL_USERNAME="));
        assert!(DEFAULT_ENV.contains("STATUS_PANEL_PASSWORD="));
        assert!(DEFAULT_ENV.contains("COMPOSE_AGENT_ENABLED"));
        assert!(DEFAULT_ENV.contains("VAULT_ADDRESS"));
        assert!(DEFAULT_ENV.contains("VAULT_TOKEN"));
        assert!(DEFAULT_ENV.contains("DEPLOYMENT_HASH"));
        assert!(DEFAULT_ENV.contains("UPDATE_SERVER_URL"));
        assert!(DEFAULT_ENV.contains("UPDATE_STORAGE_PATH"));
        // Credentials must not have default values baked in
        assert!(DEFAULT_ENV.contains("STATUS_PANEL_USERNAME=\n"));
        assert!(DEFAULT_ENV.contains("STATUS_PANEL_PASSWORD=\n"));
    }

    #[cfg(unix)]
    #[test]
    fn test_env_file_has_restricted_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        generate_default_config(dir.path(), false).unwrap();

        let meta = std::fs::metadata(dir.path().join(".env")).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0600, got {:o}", mode);
    }
}
