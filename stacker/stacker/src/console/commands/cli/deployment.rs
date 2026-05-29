use crate::cli::config_parser::StackerConfig;
use crate::cli::credentials::CredentialsManager;
use crate::cli::error::CliError;
use crate::cli::stacker_client::StackerClient;
use crate::console::commands::cli::status::{
    is_remote_deployment, missing_remote_project_reason, resolve_project_name,
    resolve_stacker_base_url,
};
use crate::console::commands::CallableTrait;
use crate::services::{
    DeployPlan, DeployPlanOperation, DeploymentEventFeed, DeploymentState, TypedErrorEnvelope,
};

const DEFAULT_CONFIG_FILE: &str = "stacker.yml";

/// `stacker deployment state [--json] [--deployment <hash>]`
///
/// Queries the canonical deployment state payload from the Stacker API.
pub struct DeploymentStateCommand {
    pub json: bool,
    pub deployment: Option<String>,
}

/// `stacker deployment events [--json] [--deployment <hash>]`
///
/// Queries the structured deployment event feed from the Stacker API.
pub struct DeploymentEventsCommand {
    pub json: bool,
    pub deployment: Option<String>,
}

/// `stacker deployment rollback --to <target> [--plan] [--apply-plan <fingerprint>] --confirm`
pub struct DeploymentRollbackCommand {
    pub to: String,
    pub plan: bool,
    pub apply_plan: Option<String>,
    pub confirm: bool,
    pub deployment: Option<String>,
}

impl DeploymentRollbackCommand {
    pub fn new(
        to: String,
        plan: bool,
        apply_plan: Option<String>,
        confirm: bool,
        deployment: Option<String>,
    ) -> Self {
        Self {
            to,
            plan,
            apply_plan,
            confirm,
            deployment,
        }
    }
}

impl DeploymentEventsCommand {
    pub fn new(json: bool, deployment: Option<String>) -> Self {
        Self { json, deployment }
    }
}

impl DeploymentStateCommand {
    pub fn new(json: bool, deployment: Option<String>) -> Self {
        Self { json, deployment }
    }
}

fn print_state(state: &DeploymentState, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(state).expect("deployment state should serialize")
        );
        return;
    }

    println!("Deployment: {}", state.deployment.deployment_hash);
    println!("Status:     {}", state.deployment.status);
    println!("Runtime:    {}", state.deployment.runtime);
    println!("Project:    {}", state.project.name);
    println!("Agent:      {}", state.agent.status);
    println!("Compose:    {}", state.runtime.compose_path);
    println!("Env:        {}", state.runtime.env_path);

    if !state.apps.is_empty() {
        println!("\nApps:");
        for app in &state.apps {
            println!(
                "  - {} ({}) cfg={} vault_sync={}",
                app.name, app.code, app.config_version, app.vault_sync_version
            );
        }
    }

    if let Some(last_command) = &state.last_command {
        println!(
            "\nLast command: {} [{}] at {}",
            last_command.r#type, last_command.status, last_command.finished_at
        );
    }
}

fn print_plan(plan: &DeployPlan) -> Result<(), CliError> {
    println!(
        "{}",
        serde_json::to_string_pretty(plan).map_err(|err| CliError::ConfigValidation(format!(
            "Failed to serialize deployment plan: {err}"
        )))?,
    );
    Ok(())
}

fn print_events(feed: &DeploymentEventFeed, json: bool) -> Result<(), CliError> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(feed).map_err(|err| CliError::ConfigValidation(
                format!("Failed to serialize deployment events: {err}")
            ))?
        );
        return Ok(());
    }

    println!("Deployment: {}", feed.deployment_hash);
    if feed.events.is_empty() {
        println!("No deployment events recorded.");
        return Ok(());
    }

    for event in &feed.events {
        let status = event.status.as_deref().unwrap_or("-");
        println!(
            "{:>2}. {} [{} / {}] {}",
            event.sequence,
            event.occurred_at,
            serde_json::to_string(&event.kind)
                .unwrap_or_default()
                .trim_matches('"'),
            status,
            event.summary
        );
    }

    Ok(())
}

pub(crate) async fn fetch_remote_deployment_plan(
    config: &StackerConfig,
    base_url: &str,
    client: &StackerClient,
    requested_hash: Option<&str>,
    operation: DeployPlanOperation,
    app_code: Option<&str>,
    rollback_target: Option<&str>,
    expected_fingerprint: Option<&str>,
) -> Result<DeployPlan, CliError> {
    let deployment_hash = resolve_deployment_hash(config, base_url, client, requested_hash).await?;
    client
        .get_deployment_plan_by_hash(
            &deployment_hash,
            operation,
            &config.deploy.target.to_string(),
            app_code,
            rollback_target,
            expected_fingerprint,
        )
        .await?
        .ok_or_else(|| {
            CliError::from(
                TypedErrorEnvelope::deployment_not_found(format!(
                    "No deployment plan found for hash '{}'",
                    deployment_hash
                ))
                .with_context("deploymentHash", deployment_hash),
            )
        })
}

async fn resolve_deployment_hash(
    config: &StackerConfig,
    base_url: &str,
    client: &StackerClient,
    requested_hash: Option<&str>,
) -> Result<String, CliError> {
    if let Some(hash) = requested_hash
        .map(str::trim)
        .filter(|hash| !hash.is_empty())
        .map(ToOwned::to_owned)
    {
        return Ok(hash);
    }

    if let Some(hash) = config
        .deploy
        .deployment_hash
        .as_ref()
        .map(|hash| hash.trim())
        .filter(|hash| !hash.is_empty())
        .map(ToOwned::to_owned)
    {
        return Ok(hash);
    }

    let project_name = resolve_project_name(config);
    let deploy_target = config.deploy.target;
    let project = client.find_project_by_name(&project_name).await?;
    let project = project.ok_or_else(|| CliError::DeployFailed {
        target: deploy_target,
        reason: missing_remote_project_reason(&project_name, base_url, deploy_target),
    })?;

    let latest = client.get_deployment_status_by_project(project.id).await?;
    latest
        .map(|deployment| deployment.deployment_hash)
        .ok_or_else(|| CliError::DeployFailed {
            target: deploy_target,
            reason: format!(
                "No deployments found for project '{}' on {}",
                project_name, base_url
            ),
        })
}

fn run_remote_deployment_state(
    json: bool,
    requested_hash: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
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
    let deploy_target = config.deploy.target;

    let cred_manager = CredentialsManager::with_default_store();
    let creds = cred_manager.require_valid_token("deployment state")?;
    let base_url = resolve_stacker_base_url(&creds);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| CliError::DeployFailed {
            target: deploy_target,
            reason: format!("Failed to initialize async runtime: {}", e),
        })?;

    rt.block_on(async {
        let client = StackerClient::new(&base_url, &creds.access_token);
        let deployment_hash =
            resolve_deployment_hash(&config, &base_url, &client, requested_hash).await?;
        let state = client
            .get_deployment_state_by_hash(&deployment_hash)
            .await?
            .ok_or_else(|| {
                CliError::from(
                    TypedErrorEnvelope::deployment_not_found(format!(
                        "No deployment state found for hash '{}'",
                        deployment_hash
                    ))
                    .with_context("deploymentHash", deployment_hash.clone()),
                )
            })?;

        print_state(&state, json);
        Ok(())
    })
}

fn run_remote_deployment_events(
    json: bool,
    requested_hash: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
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
    let deploy_target = config.deploy.target;

    let cred_manager = CredentialsManager::with_default_store();
    let creds = cred_manager.require_valid_token("deployment events")?;
    let base_url = resolve_stacker_base_url(&creds);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| CliError::DeployFailed {
            target: deploy_target,
            reason: format!("Failed to initialize async runtime: {}", e),
        })?;

    rt.block_on(async {
        let client = StackerClient::new(&base_url, &creds.access_token);
        let deployment_hash =
            resolve_deployment_hash(&config, &base_url, &client, requested_hash).await?;
        let events = client
            .get_deployment_events_by_hash(&deployment_hash)
            .await?
            .ok_or_else(|| {
                CliError::from(
                    TypedErrorEnvelope::deployment_not_found(format!(
                        "No deployment events found for hash '{}'",
                        deployment_hash
                    ))
                    .with_context("deploymentHash", deployment_hash.clone()),
                )
            })?;

        print_events(&events, json)?;
        Ok(())
    })
}

pub(crate) fn run_remote_deployment_plan(
    requested_hash: Option<&str>,
    operation: DeployPlanOperation,
    app_code: Option<&str>,
    rollback_target: Option<&str>,
    expected_fingerprint: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
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
    let deploy_target = config.deploy.target;

    let cred_manager = CredentialsManager::with_default_store();
    let creds = cred_manager.require_valid_token("deployment plan")?;
    let base_url = resolve_stacker_base_url(&creds);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| CliError::DeployFailed {
            target: deploy_target,
            reason: format!("Failed to initialize async runtime: {}", e),
        })?;

    rt.block_on(async {
        let client = StackerClient::new(&base_url, &creds.access_token);
        let plan = fetch_remote_deployment_plan(
            &config,
            &base_url,
            &client,
            requested_hash,
            operation,
            app_code,
            rollback_target,
            expected_fingerprint,
        )
        .await?;
        print_plan(&plan)?;
        Ok(())
    })
}

impl CallableTrait for DeploymentStateCommand {
    fn call(&self) -> Result<(), Box<dyn std::error::Error>> {
        let project_dir = std::env::current_dir()?;
        if !is_remote_deployment(&project_dir) {
            return Err(Box::new(CliError::ConfigValidation(
                "Deployment state is only available for cloud or server targets.".to_string(),
            )));
        }

        run_remote_deployment_state(self.json, self.deployment.as_deref())
    }
}

impl CallableTrait for DeploymentEventsCommand {
    fn call(&self) -> Result<(), Box<dyn std::error::Error>> {
        let project_dir = std::env::current_dir()?;
        if !is_remote_deployment(&project_dir) {
            return Err(Box::new(CliError::ConfigValidation(
                "Deployment events are only available for cloud or server targets.".to_string(),
            )));
        }

        run_remote_deployment_events(self.json, self.deployment.as_deref())
    }
}

impl CallableTrait for DeploymentRollbackCommand {
    fn call(&self) -> Result<(), Box<dyn std::error::Error>> {
        let project_dir = std::env::current_dir()?;
        if !is_remote_deployment(&project_dir) {
            return Err(Box::new(CliError::ConfigValidation(
                "Deployment rollback is only available for cloud or server targets.".to_string(),
            )));
        }

        if self.plan {
            return run_remote_deployment_plan(
                self.deployment.as_deref(),
                DeployPlanOperation::RollbackDeploy,
                None,
                Some(&self.to),
                None,
            );
        }

        let fingerprint = self.apply_plan.as_deref().ok_or_else(|| {
            Box::new(CliError::ConfigValidation(
                "Use --plan to preview rollback or --apply-plan <fingerprint> to execute it."
                    .to_string(),
            )) as Box<dyn std::error::Error>
        })?;

        if !self.confirm {
            return Err(Box::new(CliError::ConfigValidation(
                "Rollback apply requires --confirm (-y).".to_string(),
            )));
        }

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
        let deploy_target = config.deploy.target;

        let cred_manager = CredentialsManager::with_default_store();
        let creds = cred_manager.require_valid_token("deployment rollback")?;
        let base_url = resolve_stacker_base_url(&creds);

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| CliError::DeployFailed {
                target: deploy_target,
                reason: format!("Failed to initialize async runtime: {}", e),
            })?;

        rt.block_on(async {
            let client = StackerClient::new(&base_url, &creds.access_token);
            let plan = fetch_remote_deployment_plan(
                &config,
                &base_url,
                &client,
                self.deployment.as_deref(),
                DeployPlanOperation::RollbackDeploy,
                None,
                Some(&self.to),
                Some(fingerprint),
            )
            .await?;

            if !plan.has_changes {
                println!(
                    "Rollback already satisfied for {}. Nothing to apply.",
                    plan.deployment_hash
                );
                return Ok::<(), CliError>(());
            }

            let resolved_version = plan
                .rollback
                .as_ref()
                .map(|rollback| rollback.resolved_version.clone())
                .ok_or_else(|| {
                    CliError::from(TypedErrorEnvelope::internal_error(
                        "Rollback plan did not include a resolved target version",
                    ))
                })?;

            let project = client.find_project_by_name(&project_name).await?;
            let project = project.ok_or_else(|| CliError::DeployFailed {
                target: deploy_target,
                reason: format!("Project '{}' not found on server.", project_name),
            })?;

            eprintln!(
                "Rolling back deployment '{}' to version '{}'...",
                plan.deployment_hash, resolved_version
            );
            client
                .rollback_project(project.id, &resolved_version)
                .await?;
            Ok::<(), CliError>(())
        })?;

        Ok(())
    }
}
