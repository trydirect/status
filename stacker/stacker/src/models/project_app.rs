//! ProjectApp model for storing app configurations within projects.
//!
//! Each project can have multiple apps, and each app has its own:
//! - Environment variables
//! - Port configurations
//! - Volume mounts
//! - Domain/SSL settings
//! - Resource limits
//! - Config versioning for Vault sync

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// App configuration stored in the database.
///
/// Apps belong to projects and contain all the configuration
/// needed to deploy a container (env vars, ports, volumes, etc.)
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ProjectApp {
    pub id: i32,
    pub project_id: i32,
    /// Unique code within the project (e.g., "nginx", "postgres", "redis")
    pub code: String,
    /// Human-readable name
    pub name: String,
    /// Docker image (e.g., "nginx:latest", "postgres:15")
    pub image: String,
    /// Environment variables as JSON object
    #[sqlx(default)]
    pub environment: Option<Value>,
    /// Port mappings as JSON array [{host: 80, container: 80, protocol: "tcp"}]
    #[sqlx(default)]
    pub ports: Option<Value>,
    /// Volume mounts as JSON array
    #[sqlx(default)]
    pub volumes: Option<Value>,
    /// Domain configuration (e.g., "app.example.com")
    #[sqlx(default)]
    pub domain: Option<String>,
    /// SSL enabled for this app
    #[sqlx(default)]
    pub ssl_enabled: Option<bool>,
    /// Resource limits as JSON {cpu_limit, memory_limit, etc.}
    #[sqlx(default)]
    pub resources: Option<Value>,
    /// Restart policy (always, no, unless-stopped, on-failure)
    #[sqlx(default)]
    pub restart_policy: Option<String>,
    /// Custom command override
    #[sqlx(default)]
    pub command: Option<String>,
    /// Custom entrypoint override
    #[sqlx(default)]
    pub entrypoint: Option<String>,
    /// Networks this app connects to
    #[sqlx(default)]
    pub networks: Option<Value>,
    /// Dependencies on other apps (starts after these)
    #[sqlx(default)]
    pub depends_on: Option<Value>,
    /// Health check configuration
    #[sqlx(default)]
    pub healthcheck: Option<Value>,
    /// Labels for the container
    #[sqlx(default)]
    pub labels: Option<Value>,
    /// Configuration file templates as JSON array
    #[sqlx(default)]
    pub config_files: Option<Value>,
    /// Source template for this app configuration (e.g., marketplace template URL)
    #[sqlx(default)]
    pub template_source: Option<String>,
    /// App is enabled (will be deployed)
    #[sqlx(default)]
    pub enabled: Option<bool>,
    /// Order in deployment (lower = first)
    #[sqlx(default)]
    pub deploy_order: Option<i32>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// Config version (incrementing on each change)
    #[sqlx(default)]
    pub config_version: Option<i32>,
    /// Last time config was synced to Vault
    #[sqlx(default)]
    pub vault_synced_at: Option<DateTime<Utc>>,
    /// Config version that was last synced to Vault
    #[sqlx(default)]
    pub vault_sync_version: Option<i32>,
    /// SHA256 hash of rendered config for drift detection
    #[sqlx(default)]
    pub config_hash: Option<String>,
    /// Parent app code for multi-service stacks (e.g., "komodo" for komodo-core, komodo-ferretdb)
    /// When set, this app is a child service discovered from parent's compose file
    #[sqlx(default)]
    pub parent_app_code: Option<String>,
    /// Deployment this app belongs to. NULL for legacy apps created before deployment scoping.
    #[sqlx(default)]
    pub deployment_id: Option<i32>,
}

impl ProjectApp {
    /// Create a new app with minimal required fields
    pub fn new(project_id: i32, code: String, name: String, image: String) -> Self {
        let now = Utc::now();
        Self {
            id: 0,
            project_id,
            code,
            name,
            image,
            environment: None,
            ports: None,
            volumes: None,
            domain: None,
            ssl_enabled: Some(false),
            resources: None,
            restart_policy: Some("unless-stopped".to_string()),
            command: None,
            entrypoint: None,
            networks: None,
            depends_on: None,
            healthcheck: None,
            labels: None,
            config_files: None,
            template_source: None,
            enabled: Some(true),
            deploy_order: None,
            created_at: now,
            updated_at: now,
            config_version: Some(1),
            vault_synced_at: None,
            vault_sync_version: None,
            config_hash: None,
            parent_app_code: None,
            deployment_id: None,
        }
    }

    /// Check if the app is enabled for deployment
    pub fn is_enabled(&self) -> bool {
        self.enabled.unwrap_or(true)
    }

    /// Get environment variables as a map, or empty map if none
    pub fn env_map(&self) -> serde_json::Map<String, Value> {
        self.environment
            .as_ref()
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default()
    }

    /// Check if config needs to be synced to Vault
    pub fn needs_vault_sync(&self) -> bool {
        match (self.config_version, self.vault_sync_version) {
            (Some(current), Some(synced)) => current > synced,
            (Some(_), None) => true, // Never synced
            _ => false,
        }
    }

    /// Increment config version (call before saving changes)
    pub fn increment_version(&mut self) {
        self.config_version = Some(self.config_version.unwrap_or(0) + 1);
    }

    /// Mark as synced to Vault
    pub fn mark_synced(&mut self) {
        self.vault_synced_at = Some(Utc::now());
        self.vault_sync_version = self.config_version;
    }
}

impl Default for ProjectApp {
    fn default() -> Self {
        Self {
            id: 0,
            project_id: 0,
            code: String::new(),
            name: String::new(),
            image: String::new(),
            environment: None,
            ports: None,
            volumes: None,
            domain: None,
            ssl_enabled: None,
            resources: None,
            restart_policy: None,
            command: None,
            entrypoint: None,
            networks: None,
            depends_on: None,
            healthcheck: None,
            labels: None,
            config_files: None,
            template_source: None,
            enabled: None,
            deploy_order: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            config_version: Some(1),
            vault_synced_at: None,
            vault_sync_version: None,
            config_hash: None,
            parent_app_code: None,
            deployment_id: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_defaults() {
        let app = ProjectApp::new(
            1,
            "nginx".to_string(),
            "Nginx".to_string(),
            "nginx:latest".to_string(),
        );
        assert_eq!(app.project_id, 1);
        assert_eq!(app.code, "nginx");
        assert_eq!(app.name, "Nginx");
        assert_eq!(app.image, "nginx:latest");
        assert_eq!(app.enabled, Some(true));
        assert_eq!(app.ssl_enabled, Some(false));
        assert_eq!(app.restart_policy, Some("unless-stopped".to_string()));
        assert_eq!(app.config_version, Some(1));
        assert!(app.vault_synced_at.is_none());
        assert!(app.vault_sync_version.is_none());
    }

    #[test]
    fn test_is_enabled_true() {
        let app = ProjectApp {
            enabled: Some(true),
            ..Default::default()
        };
        assert!(app.is_enabled());
    }

    #[test]
    fn test_is_enabled_false() {
        let app = ProjectApp {
            enabled: Some(false),
            ..Default::default()
        };
        assert!(!app.is_enabled());
    }

    #[test]
    fn test_is_enabled_none_defaults_true() {
        let app = ProjectApp {
            enabled: None,
            ..Default::default()
        };
        assert!(app.is_enabled());
    }

    #[test]
    fn test_env_map_with_data() {
        let app = ProjectApp {
            environment: Some(serde_json::json!({"DB_HOST": "localhost", "DB_PORT": "5432"})),
            ..Default::default()
        };
        let map = app.env_map();
        assert_eq!(map.len(), 2);
        assert_eq!(map.get("DB_HOST").unwrap(), "localhost");
    }

    #[test]
    fn test_env_map_empty() {
        let app = ProjectApp {
            environment: None,
            ..Default::default()
        };
        let map = app.env_map();
        assert!(map.is_empty());
    }

    #[test]
    fn test_env_map_non_object() {
        let app = ProjectApp {
            environment: Some(serde_json::json!("not an object")),
            ..Default::default()
        };
        let map = app.env_map();
        assert!(map.is_empty());
    }

    #[test]
    fn test_needs_vault_sync_never_synced() {
        let app = ProjectApp {
            config_version: Some(1),
            vault_sync_version: None,
            ..Default::default()
        };
        assert!(app.needs_vault_sync());
    }

    #[test]
    fn test_needs_vault_sync_outdated() {
        let app = ProjectApp {
            config_version: Some(3),
            vault_sync_version: Some(2),
            ..Default::default()
        };
        assert!(app.needs_vault_sync());
    }

    #[test]
    fn test_needs_vault_sync_up_to_date() {
        let app = ProjectApp {
            config_version: Some(2),
            vault_sync_version: Some(2),
            ..Default::default()
        };
        assert!(!app.needs_vault_sync());
    }

    #[test]
    fn test_needs_vault_sync_no_version() {
        let app = ProjectApp {
            config_version: None,
            vault_sync_version: None,
            ..Default::default()
        };
        assert!(!app.needs_vault_sync());
    }

    #[test]
    fn test_increment_version() {
        let mut app = ProjectApp {
            config_version: Some(1),
            ..Default::default()
        };
        app.increment_version();
        assert_eq!(app.config_version, Some(2));
    }

    #[test]
    fn test_increment_version_from_none() {
        let mut app = ProjectApp {
            config_version: None,
            ..Default::default()
        };
        app.increment_version();
        assert_eq!(app.config_version, Some(1));
    }

    #[test]
    fn test_mark_synced() {
        let mut app = ProjectApp {
            config_version: Some(3),
            vault_synced_at: None,
            vault_sync_version: None,
            ..Default::default()
        };
        app.mark_synced();
        assert!(app.vault_synced_at.is_some());
        assert_eq!(app.vault_sync_version, Some(3));
        assert!(!app.needs_vault_sync());
    }
}
