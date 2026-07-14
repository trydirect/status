use crate::cli::config_parser::{DeployTarget, StackerConfig};
use crate::cli::error::CliError;
use crate::cli::runtime::CliRuntime;
use crate::console::commands::CallableTrait;

const DEFAULT_CONFIG_FILE: &str = "stacker.yml";

/// `stacker resolve [-y] [--force] [--deployment=<hash>]`
///
/// Force-complete a stuck deployment (paused or error → completed).
/// Use `--force` to also override `in_progress` deployments.
/// Use `--deployment=<hash>` to target a specific deployment; defaults to the latest.
pub struct ResolveCommand {
    pub confirm: bool,
    pub force: bool,
    pub deployment: Option<String>,
}

impl ResolveCommand {
    pub fn new(confirm: bool, force: bool, deployment: Option<String>) -> Self {
        Self {
            confirm,
            force,
            deployment,
        }
    }
}

impl CallableTrait for ResolveCommand {
    fn call(&self) -> Result<(), Box<dyn std::error::Error>> {
        if !self.confirm {
            return Err(Box::new(CliError::ConfigValidation(
                "Resolve requires --confirm (-y) flag. This will mark a paused/error \
                 deployment as completed."
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

        let project_name = config
            .project
            .identity
            .clone()
            .unwrap_or_else(|| config.name.clone());

        let ctx = CliRuntime::new("resolve").map_err(|e| CliError::DeployFailed {
            target: DeployTarget::Cloud,
            reason: e.to_string(),
        })?;

        let deployment = self.deployment.clone();
        let force = self.force;

        ctx.block_on(async {
            // Resolve the target deployment — by hash or by latest in project
            let info = if let Some(ref hash) = deployment {
                ctx.client
                    .get_deployment_by_hash(hash)
                    .await?
                    .ok_or_else(|| CliError::DeployFailed {
                        target: DeployTarget::Cloud,
                        reason: format!("Deployment '{}' not found.", hash),
                    })?
            } else {
                // Find project first, then get its latest deployment
                let project = ctx.client.find_project_by_name(&project_name).await?;
                let project = project.ok_or_else(|| CliError::DeployFailed {
                    target: DeployTarget::Cloud,
                    reason: format!("Project '{}' not found on server.", project_name),
                })?;

                ctx.client
                    .get_deployment_status_by_project(project.id)
                    .await?
                    .ok_or_else(|| CliError::DeployFailed {
                        target: DeployTarget::Cloud,
                        reason: format!("No deployments found for project '{}'.", project_name),
                    })?
            };

            let allowed = ["paused", "error"];
            if !force && !allowed.contains(&info.status.as_str()) {
                return Err(CliError::DeployFailed {
                    target: DeployTarget::Cloud,
                    reason: format!(
                        "Deployment #{} has status '{}'. Only paused or error deployments can be resolved. Use --force to override.",
                        info.id, info.status
                    ),
                });
            }

            eprintln!(
                "Resolving deployment #{} [{}] (status: '{}'){}...",
                info.id,
                info.deployment_hash,
                info.status,
                if force { " [forced]" } else { "" },
            );

            let updated = ctx
                .client
                .force_complete_deployment(info.id, force)
                .await?;

            eprintln!(
                "✓ Deployment #{} status changed to '{}'",
                updated.id, updated.status
            );

            Ok::<(), CliError>(())
        })?;

        Ok(())
    }
}
