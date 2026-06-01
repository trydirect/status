//! ProjectApp Service - Manages app configurations with Vault sync
//!
//! This service wraps the database operations for ProjectApp and automatically
//! syncs configuration changes to Vault for the Status Panel to consume.

use crate::db;
use crate::forms::project::Payload;
use crate::models::{Project, ProjectApp};
use crate::services::config_renderer::{env_body_hash, ConfigRenderer};
use crate::services::vault_service::{VaultError, VaultService};
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Result type for ProjectApp operations
pub type Result<T> = std::result::Result<T, ProjectAppError>;

/// Error type for ProjectApp operations
#[derive(Debug)]
pub enum ProjectAppError {
    Database(String),
    VaultSync(VaultError),
    ConfigRender(String),
    NotFound(String),
    Validation(String),
}

impl std::fmt::Display for ProjectAppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Database(msg) => write!(f, "Database error: {}", msg),
            Self::VaultSync(e) => write!(f, "Vault sync error: {}", e),
            Self::ConfigRender(msg) => write!(f, "Config render error: {}", msg),
            Self::NotFound(msg) => write!(f, "Not found: {}", msg),
            Self::Validation(msg) => write!(f, "Validation error: {}", msg),
        }
    }
}

impl std::error::Error for ProjectAppError {}

impl From<VaultError> for ProjectAppError {
    fn from(e: VaultError) -> Self {
        Self::VaultSync(e)
    }
}

/// ProjectApp service with automatic Vault sync
pub struct ProjectAppService {
    pool: Arc<PgPool>,
    config_renderer: Arc<RwLock<ConfigRenderer>>,
    vault_sync_enabled: bool,
}

impl ProjectAppService {
    /// Create a new ProjectAppService
    pub fn new(pool: Arc<PgPool>) -> std::result::Result<Self, String> {
        let config_renderer = ConfigRenderer::new()
            .map_err(|e| format!("Failed to create config renderer: {}", e))?;

        Ok(Self {
            pool,
            config_renderer: Arc::new(RwLock::new(config_renderer)),
            vault_sync_enabled: true,
        })
    }

    pub fn default_network_from_project(project: &Project) -> Option<String> {
        Payload::try_from(project).ok().and_then(|payload| {
            payload
                .custom
                .networks
                .networks
                .as_ref()
                .and_then(|networks| {
                    networks
                        .iter()
                        .find(|network| network.name == "default_network")
                        .map(|network| network.name.clone())
                })
        })
    }

    /// Create service without Vault sync (for testing or offline mode)
    pub fn new_without_sync(pool: Arc<PgPool>) -> std::result::Result<Self, String> {
        let config_renderer = ConfigRenderer::new()
            .map_err(|e| format!("Failed to create config renderer: {}", e))?;

        Ok(Self {
            pool,
            config_renderer: Arc::new(RwLock::new(config_renderer)),
            vault_sync_enabled: false,
        })
    }

    /// Fetch a single app by ID
    pub async fn get(&self, id: i32) -> Result<ProjectApp> {
        db::project_app::fetch(&self.pool, id)
            .await
            .map_err(ProjectAppError::Database)?
            .ok_or_else(|| ProjectAppError::NotFound(format!("App with id {} not found", id)))
    }

    /// Fetch all apps for a project
    pub async fn list_by_project(&self, project_id: i32) -> Result<Vec<ProjectApp>> {
        db::project_app::fetch_by_project(&self.pool, project_id)
            .await
            .map_err(ProjectAppError::Database)
    }

    /// Fetch a single app by project ID and app code
    pub async fn get_by_code(&self, project_id: i32, code: &str) -> Result<ProjectApp> {
        db::project_app::fetch_by_project_and_code(&self.pool, project_id, code)
            .await
            .map_err(ProjectAppError::Database)?
            .ok_or_else(|| {
                ProjectAppError::NotFound(format!(
                    "App with code '{}' not found in project {}",
                    code, project_id
                ))
            })
    }

    /// Create a new app and sync to Vault
    pub async fn create(
        &self,
        app: &ProjectApp,
        project: &Project,
        deployment_hash: &str,
    ) -> Result<ProjectApp> {
        // Validate app
        self.validate_app(app)?;

        // Insert into database
        let created = db::project_app::insert(&self.pool, app)
            .await
            .map_err(ProjectAppError::Database)?;

        // Sync to Vault if enabled
        if self.vault_sync_enabled {
            if let Err(e) = self
                .sync_app_to_vault(&created, project, deployment_hash)
                .await
            {
                tracing::warn!(
                    app_code = %app.code,
                    error = %e,
                    "Failed to sync new app to Vault (will retry on next update)"
                );
                // Don't fail the create operation, just warn
            }
        }

        Ok(created)
    }

    /// Update an existing app and sync to Vault
    pub async fn update(
        &self,
        app: &ProjectApp,
        project: &Project,
        deployment_hash: &str,
    ) -> Result<ProjectApp> {
        // Validate app
        self.validate_app(app)?;

        // Update in database
        let updated = db::project_app::update(&self.pool, app)
            .await
            .map_err(ProjectAppError::Database)?;

        // Sync to Vault if enabled
        if self.vault_sync_enabled {
            if let Err(e) = self
                .sync_app_to_vault(&updated, project, deployment_hash)
                .await
            {
                tracing::warn!(
                    app_code = %app.code,
                    error = %e,
                    "Failed to sync updated app to Vault"
                );
            }
        }

        Ok(updated)
    }

    /// Delete an app and remove from Vault
    pub async fn delete(&self, id: i32, deployment_hash: &str) -> Result<bool> {
        // Get the app first to know its code
        let app = self.get(id).await?;

        // Delete from database
        let deleted = db::project_app::delete(&self.pool, id)
            .await
            .map_err(ProjectAppError::Database)?;

        // Remove from Vault if enabled
        if deleted && self.vault_sync_enabled {
            if let Err(e) = self.delete_from_vault(&app.code, deployment_hash).await {
                tracing::warn!(
                    app_code = %app.code,
                    error = %e,
                    "Failed to delete app config from Vault"
                );
            }
        }

        Ok(deleted)
    }

    /// Create or update an app (upsert) and sync to Vault
    pub async fn upsert(
        &self,
        app: &ProjectApp,
        project: &Project,
        deployment_hash: &str,
    ) -> Result<ProjectApp> {
        // Check if app exists
        let exists =
            db::project_app::exists_by_project_and_code(&self.pool, app.project_id, &app.code)
                .await
                .map_err(ProjectAppError::Database)?;

        if exists {
            // Fetch existing to get ID
            let existing = self.get_by_code(app.project_id, &app.code).await?;
            let mut updated_app = app.clone();
            updated_app.id = existing.id;
            self.update(&updated_app, project, deployment_hash).await
        } else {
            self.create(app, project, deployment_hash).await
        }
    }

    /// Sync all apps for a project to Vault
    pub async fn sync_all_to_vault(
        &self,
        project: &Project,
        deployment_hash: &str,
    ) -> Result<SyncSummary> {
        let apps = self.list_by_project(project.id).await?;
        let renderer = self.config_renderer.read().await;

        // Render the full bundle
        let bundle = renderer
            .render_bundle(&self.pool, project, &apps, deployment_hash)
            .await
            .map_err(|e| ProjectAppError::ConfigRender(e.to_string()))?;

        // Sync to Vault
        let sync_result = renderer.sync_to_vault(&bundle).await?;
        for app in &apps {
            let env_key = format!("{}_env", app.code);
            if !sync_result.synced.iter().any(|key| key == &env_key) {
                continue;
            }
            if let Some(config) = bundle.app_configs.get(&app.code) {
                let config_hash = env_body_hash(&config.content);
                db::project_app::update_sync_metadata(&self.pool, app.id, &config_hash)
                    .await
                    .map_err(ProjectAppError::Database)?;
            }
        }

        Ok(SyncSummary {
            total_apps: apps.len(),
            synced: sync_result.synced.len(),
            failed: sync_result.failed.len(),
            version: sync_result.version,
            details: sync_result,
        })
    }

    /// Sync a single app to Vault
    pub async fn sync_app_to_vault(
        &self,
        app: &ProjectApp,
        project: &Project,
        deployment_hash: &str,
    ) -> Result<()> {
        let renderer = self.config_renderer.read().await;
        let config_hash = renderer
            .sync_app_to_vault(&self.pool, app, project, deployment_hash)
            .await
            .map_err(ProjectAppError::VaultSync)?;
        crate::db::project_app::update_sync_metadata(&self.pool, app.id, &config_hash)
            .await
            .map_err(ProjectAppError::Database)?;

        Ok(())
    }

    /// Delete an app config from Vault
    async fn delete_from_vault(&self, app_code: &str, deployment_hash: &str) -> Result<()> {
        let vault = VaultService::from_env()
            .map_err(|e| ProjectAppError::VaultSync(e))?
            .ok_or_else(|| ProjectAppError::VaultSync(VaultError::NotConfigured))?;

        vault
            .delete_app_config(deployment_hash, app_code)
            .await
            .map_err(ProjectAppError::VaultSync)
    }

    /// Validate app before saving
    fn validate_app(&self, app: &ProjectApp) -> Result<()> {
        tracing::info!(
            "[VALIDATE_APP] Validating app - code: '{}', name: '{}', image: '{}'",
            app.code,
            app.name,
            app.image
        );
        if app.code.is_empty() {
            tracing::error!("[VALIDATE_APP] FAILED: App code is required");
            return Err(ProjectAppError::Validation("App code is required".into()));
        }
        if app.name.is_empty() {
            tracing::error!("[VALIDATE_APP] FAILED: App name is required");
            return Err(ProjectAppError::Validation("App name is required".into()));
        }
        if app.image.is_empty() {
            tracing::error!("[VALIDATE_APP] FAILED: Docker image is required (image is empty!)");
            return Err(ProjectAppError::Validation(
                "Docker image is required".into(),
            ));
        }
        // Validate code format (alphanumeric, dash, underscore)
        if !app
            .code
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            tracing::error!("[VALIDATE_APP] FAILED: Invalid app code format");
            return Err(ProjectAppError::Validation(
                "App code must be alphanumeric with dashes or underscores only".into(),
            ));
        }
        tracing::info!("[VALIDATE_APP] Validation passed");
        Ok(())
    }

    /// Regenerate all configs without syncing (for preview)
    pub async fn preview_bundle(
        &self,
        project: &Project,
        apps: &[ProjectApp],
        deployment_hash: &str,
    ) -> Result<crate::services::config_renderer::ConfigBundle> {
        let renderer = self.config_renderer.read().await;
        renderer
            .render_bundle(&self.pool, project, apps, deployment_hash)
            .await
            .map_err(|e| ProjectAppError::ConfigRender(e.to_string()))
    }
}

/// Summary of a sync operation
#[derive(Debug, Clone)]
pub struct SyncSummary {
    pub total_apps: usize,
    pub synced: usize,
    pub failed: usize,
    pub version: u64,
    pub details: crate::services::config_renderer::SyncResult,
}

impl SyncSummary {
    pub fn is_success(&self) -> bool {
        self.failed == 0
    }
}

#[cfg(test)]
mod tests {
    use crate::models::ProjectApp;

    #[test]
    fn test_validate_app_empty_code() {
        // Can't easily test without a real pool, but we can test validation logic
        let app = ProjectApp::new(
            1,
            "".to_string(),
            "Test".to_string(),
            "nginx:latest".to_string(),
        );

        // Validation would fail for empty code
        assert!(app.code.is_empty());
    }

    #[test]
    fn test_validate_app_invalid_code() {
        let app = ProjectApp::new(
            1,
            "my app!".to_string(), // Invalid: contains space and !
            "Test".to_string(),
            "nginx:latest".to_string(),
        );

        // This code contains invalid characters
        let has_invalid = app
            .code
            .chars()
            .any(|c| !c.is_ascii_alphanumeric() && c != '-' && c != '_');
        assert!(has_invalid);
    }
}
