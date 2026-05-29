use crate::cli::config_parser::{DeployTarget, StackerConfig};
use crate::cli::credentials::{CredentialsManager, StoredCredentials};
use crate::cli::error::CliError;
use crate::cli::install_runner::normalize_stacker_server_url;
use crate::cli::stacker_client::{self, StackerClient};
use crate::console::commands::CallableTrait;

const DEFAULT_CONFIG_FILE: &str = "stacker.yml";

/// `stacker rollback --version <VERSION> --confirm`
///
/// Requests a safe marketplace rollback to a known template version.
pub struct RollbackCommand {
    pub version: String,
    pub confirm: bool,
}

impl RollbackCommand {
    pub fn new(version: String, confirm: bool) -> Self {
        Self { version, confirm }
    }
}

fn resolve_project_name(config: &StackerConfig) -> String {
    config
        .project
        .identity
        .clone()
        .unwrap_or_else(|| config.name.clone())
}

fn resolve_stacker_base_url(creds: &StoredCredentials) -> String {
    creds
        .server_url
        .as_deref()
        .map(normalize_stacker_server_url)
        .unwrap_or_else(|| stacker_client::DEFAULT_STACKER_URL.to_string())
}

impl CallableTrait for RollbackCommand {
    fn call(&self) -> Result<(), Box<dyn std::error::Error>> {
        if !self.confirm {
            return Err(Box::new(CliError::ConfigValidation(
                "Rollback requires --confirm (-y) flag. This will redeploy the selected marketplace version."
                    .to_string(),
            )));
        }

        let project_dir = std::env::current_dir()?;
        let config_path = project_dir.join(DEFAULT_CONFIG_FILE);

        if !config_path.exists() {
            return Err(Box::new(CliError::ConfigValidation(
                "No stacker.yml found. Run 'stacker init' first.".to_string(),
            )));
        }

        let config = StackerConfig::from_file(&config_path)?
            .with_resolved_deploy_target(None)
            .map_err(|e| CliError::ConfigValidation(format!("Invalid stacker.yml: {}", e)))?;

        let project_name = resolve_project_name(&config);

        let cred_manager = CredentialsManager::with_default_store();
        let creds = cred_manager.require_valid_token("rollback")?;
        let base_url = resolve_stacker_base_url(&creds);
        let version = self.version.clone();

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| CliError::DeployFailed {
                target: DeployTarget::Cloud,
                reason: format!("Failed to initialize async runtime: {}", e),
            })?;

        rt.block_on(async move {
            let client = StackerClient::new(&base_url, &creds.access_token);
            let project = client.find_project_by_name(&project_name).await?;
            let project = project.ok_or_else(|| CliError::DeployFailed {
                target: DeployTarget::Cloud,
                reason: format!("Project '{}' not found on server.", project_name),
            })?;

            eprintln!(
                "Rolling back project '{}' to version '{}'...",
                project_name, version
            );
            let response = client.rollback_project(project.id, &version).await?;

            if let Some(meta) = response.meta {
                if let Some(deployment_id) =
                    meta.get("deployment_id").and_then(|value| value.as_i64())
                {
                    eprintln!(
                        "✓ Rollback requested for project '{}' to version '{}' (deployment #{})",
                        project_name, version, deployment_id
                    );
                    return Ok::<(), CliError>(());
                }
            }

            eprintln!(
                "✓ Rollback requested for project '{}' to version '{}'",
                project_name, version
            );
            Ok::<(), CliError>(())
        })?;

        Ok(())
    }
}
