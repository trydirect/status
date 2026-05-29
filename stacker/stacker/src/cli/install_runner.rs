use std::path::{Path, PathBuf};

use crate::cli::cloud_env;
use crate::cli::compose_targets;
use crate::cli::config_parser::{CloudOrchestrator, DeployTarget, StackerConfig};
use crate::cli::credentials::{CredentialsManager, StoredCredentials};
use crate::cli::error::CliError;
use crate::cli::stacker_client::{self, StackerClient};

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Constants
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Default Docker image for the install container (Terraform + Ansible).
pub const DEFAULT_INSTALL_IMAGE: &str = "trydirect/install-service:latest";

/// Mount point for stacker.yml inside the install container.
pub const CONTAINER_CONFIG_PATH: &str = "/app/stacker.yml";

/// Mount point for the compose file inside the install container.
pub const CONTAINER_COMPOSE_PATH: &str = "/app/docker-compose.yml";

/// Mount point for SSH keys inside the install container.
pub const CONTAINER_SSH_KEY_PATH: &str = "/root/.ssh/id_rsa";

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// CommandExecutor — abstraction for running shell commands (DIP)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Result of executing a command.
#[derive(Debug, Clone)]
pub struct CommandOutput {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl CommandOutput {
    pub fn success(&self) -> bool {
        self.exit_code == 0
    }
}

/// Abstraction over shell command execution.
///
/// Production: `ShellExecutor` runs commands via `std::process::Command`.
/// Tests: `MockExecutor` records commands for assertion without side effects.
pub trait CommandExecutor: Send + Sync {
    fn execute(&self, program: &str, args: &[&str]) -> Result<CommandOutput, CliError>;
}

/// Production executor — actually runs docker commands.
pub struct ShellExecutor;

impl CommandExecutor for ShellExecutor {
    fn execute(&self, program: &str, args: &[&str]) -> Result<CommandOutput, CliError> {
        let output = std::process::Command::new(program)
            .args(args)
            .output()
            .map_err(|e| CliError::CommandFailed {
                command: format!("{} {} — {}", program, args.join(" "), e),
                exit_code: -1,
            })?;

        Ok(CommandOutput {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        })
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// DeployContext — everything needed for a deployment
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Aggregated deployment context passed to strategies.
#[derive(Debug, Clone)]
pub struct DeployContext {
    /// Path to the stacker.yml config file.
    pub config_path: PathBuf,

    /// Path to the generated docker-compose.yml.
    pub compose_path: PathBuf,

    /// Working directory of the project.
    pub project_dir: PathBuf,

    /// Whether this is a dry-run (plan) or real deployment (apply).
    pub dry_run: bool,

    /// Install container image override.
    pub image: Option<String>,

    /// Remote deploy overrides from CLI flags.
    pub project_name_override: Option<String>,
    pub key_name_override: Option<String>,
    pub key_id_override: Option<i32>,
    pub server_name_override: Option<String>,

    /// Container runtime preference ("runc" or "kata").
    pub runtime: String,

    /// Environment-specific config files collected from compose env_file and bind mounts.
    pub config_bundle: Option<crate::cli::config_bundle::ConfigBundleArtifacts>,

    /// Whether the Stacker-managed proxy role should be requested from Install Service.
    pub managed_proxy_feature_enabled: bool,

    /// Whether the user explicitly requested a fresh cloud server (`stacker deploy --force-new`).
    pub force_new: bool,
}

impl DeployContext {
    pub fn install_image(&self) -> &str {
        self.image.as_deref().unwrap_or(DEFAULT_INSTALL_IMAGE)
    }
}

fn should_run_managed_proxy_preflight(context: &DeployContext, target: DeployTarget) -> bool {
    context.managed_proxy_feature_enabled && !(target == DeployTarget::Cloud && context.force_new)
}

/// Outcome of a successful deployment.
#[derive(Debug, Clone)]
pub struct DeployResult {
    pub target: DeployTarget,
    pub message: String,
    pub server_ip: Option<String>,
    /// Cloud deployment ID (set for remote orchestrator deploys).
    pub deployment_id: Option<i64>,
    /// Stacker server project ID (set for remote orchestrator deploys).
    pub project_id: Option<i64>,
    /// Server name used/generated for this deploy (for lockfile persistence).
    pub server_name: Option<String>,
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// DeployStrategy — strategy pattern for deployment targets (OCP + DIP)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Each deployment target implements this trait.
/// New targets can be added without modifying existing code (OCP).
pub trait DeployStrategy {
    fn validate(&self, config: &StackerConfig) -> Result<(), CliError>;
    fn deploy(
        &self,
        config: &StackerConfig,
        context: &DeployContext,
        executor: &dyn CommandExecutor,
    ) -> Result<DeployResult, CliError>;
    fn destroy(
        &self,
        config: &StackerConfig,
        context: &DeployContext,
        executor: &dyn CommandExecutor,
    ) -> Result<(), CliError>;
}

/// Factory: map `DeployTarget` to its strategy implementation.
pub fn strategy_for(target: &DeployTarget) -> Box<dyn DeployStrategy> {
    match target {
        DeployTarget::Local => Box::new(LocalDeploy),
        DeployTarget::Cloud => Box::new(CloudDeploy),
        DeployTarget::Server => Box::new(ServerDeploy),
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// LocalDeploy — docker compose up/down
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Detect which compose invocation is available on this host.
///
/// Returns `("docker", vec!["compose"])` when the Docker Compose plugin is
/// installed (`docker compose version` exits 0), or `("docker-compose", vec![])`
/// when only the standalone tool is available.
fn resolve_compose_cmd(executor: &dyn CommandExecutor) -> (&'static str, Vec<&'static str>) {
    if let Ok(out) = executor.execute("docker", &["compose", "version"]) {
        if out.success() {
            return ("docker", vec!["compose"]);
        }
    }
    ("docker-compose", vec![])
}

pub struct LocalDeploy;

impl DeployStrategy for LocalDeploy {
    fn validate(&self, _config: &StackerConfig) -> Result<(), CliError> {
        // Local deploy only requires Docker to be available;
        // that check happens at command level before calling deploy().
        Ok(())
    }

    fn deploy(
        &self,
        config: &StackerConfig,
        context: &DeployContext,
        executor: &dyn CommandExecutor,
    ) -> Result<DeployResult, CliError> {
        // In dry-run mode, artifacts have already been generated.
        // Skip calling docker compose — it may not be available in all environments,
        // and "dry run" means "preview, don't execute".
        if context.dry_run {
            return Ok(DeployResult {
                target: DeployTarget::Local,
                message: "Local deployment previewed successfully (dry-run)".to_string(),
                server_ip: None,
                deployment_id: None,
                project_id: None,
                server_name: None,
            });
        }

        let compose_path = context.compose_path.to_string_lossy().to_string();

        let (cmd, base_args) = resolve_compose_cmd(executor);
        let mut args: Vec<String> = base_args.iter().map(|s| s.to_string()).collect();

        if let Some(ref env_file) = config.env_file {
            let env_file_path = if env_file.is_absolute() {
                env_file.clone()
            } else {
                context.project_dir.join(env_file)
            };
            args.push("--env-file".into());
            args.push(env_file_path.to_string_lossy().to_string());
        }
        args.push("--file".into());
        args.push(compose_path.clone());
        args.push("up".into());
        args.push("-d".into());
        args.push("--build".into());

        let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let output = executor.execute(cmd, &args_refs)?;

        if !output.stdout.trim().is_empty() {
            println!("{}", output.stdout);
        }
        if !output.stderr.trim().is_empty() {
            eprintln!("{}", output.stderr);
        }

        if !output.success() {
            return Err(CliError::DeployFailed {
                target: DeployTarget::Local,
                reason: format!("docker compose failed: {}", output.stderr.trim()),
            });
        }

        Ok(DeployResult {
            target: DeployTarget::Local,
            message: "Local deployment started successfully".to_string(),
            server_ip: None,
            deployment_id: None,
            project_id: None,
            server_name: None,
        })
    }

    fn destroy(
        &self,
        config: &StackerConfig,
        context: &DeployContext,
        executor: &dyn CommandExecutor,
    ) -> Result<(), CliError> {
        let compose_path = context.compose_path.to_string_lossy().to_string();

        let (cmd, base_args) = resolve_compose_cmd(executor);
        let mut args: Vec<String> = base_args.iter().map(|s| s.to_string()).collect();

        if let Some(ref env_file) = config.env_file {
            let env_file_path = if env_file.is_absolute() {
                env_file.clone()
            } else {
                context.project_dir.join(env_file)
            };
            args.push("--env-file".into());
            args.push(env_file_path.to_string_lossy().to_string());
        }
        args.push("--file".into());
        args.push(compose_path);
        args.push("down".into());
        args.push("--volumes".into());
        let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let output = executor.execute(cmd, &args_refs)?;

        if !output.success() {
            return Err(CliError::DeployFailed {
                target: DeployTarget::Local,
                reason: format!("docker compose down failed: {}", output.stderr.trim()),
            });
        }

        Ok(())
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// InstallContainerCommand — builds `docker run` for the install container
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Builder for `docker run` commands that launch the install container
/// with Terraform + Ansible for cloud/server deployments.
///
/// Modeled after the existing install service docker-compose mounts
/// and the `ConfigureProxyCommandRequest` pattern in `forms/status_panel.rs`.
#[derive(Debug, Clone)]
pub struct InstallContainerCommand {
    image: String,
    volume_mounts: Vec<(String, String)>,
    env_vars: Vec<(String, String)>,
    action: InstallAction,
    remove_after: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallAction {
    Plan,
    Apply,
    Destroy,
}

impl InstallAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Plan => "plan",
            Self::Apply => "apply",
            Self::Destroy => "destroy",
        }
    }
}

impl InstallContainerCommand {
    /// Create a new builder with the given image (or default).
    pub fn new(image: Option<&str>) -> Self {
        Self {
            image: image.unwrap_or(DEFAULT_INSTALL_IMAGE).to_string(),
            volume_mounts: Vec::new(),
            env_vars: Vec::new(),
            action: InstallAction::Apply,
            remove_after: true,
        }
    }

    /// Mount a host path into the container.
    pub fn mount(mut self, host_path: impl AsRef<Path>, container_path: &str) -> Self {
        self.volume_mounts.push((
            host_path.as_ref().to_string_lossy().to_string(),
            container_path.to_string(),
        ));
        self
    }

    /// Add an environment variable.
    pub fn env(mut self, key: &str, value: &str) -> Self {
        self.env_vars.push((key.to_string(), value.to_string()));
        self
    }

    /// Set the action to perform (plan, apply, destroy).
    pub fn action(mut self, action: InstallAction) -> Self {
        self.action = action;
        self
    }

    /// Whether to remove the container after exit (--rm). Default: true.
    pub fn remove_after(mut self, remove: bool) -> Self {
        self.remove_after = remove;
        self
    }

    /// Build the argument list for `docker run`.
    pub fn build_args(&self) -> Vec<String> {
        let mut args = vec!["run".to_string()];

        if self.remove_after {
            args.push("--rm".to_string());
        }

        for (host, container) in &self.volume_mounts {
            args.push("-v".to_string());
            args.push(format!("{}:{}", host, container));
        }

        for (key, value) in &self.env_vars {
            args.push("-e".to_string());
            args.push(format!("{}={}", key, value));
        }

        args.push(self.image.clone());
        args.push(self.action.as_str().to_string());

        args
    }

    /// Build from a `StackerConfig` and `DeployContext`, setting up
    /// standard mounts and environment variables.
    pub fn from_config(
        config: &StackerConfig,
        context: &DeployContext,
        action: InstallAction,
    ) -> Self {
        let mut cmd = Self::new(Some(context.install_image())).action(action);

        // Mount stacker.yml
        cmd = cmd.mount(&context.config_path, CONTAINER_CONFIG_PATH);

        // Mount compose file
        cmd = cmd.mount(&context.compose_path, CONTAINER_COMPOSE_PATH);

        // Set project name
        cmd = cmd.env("PROJECT_NAME", &config.name);

        // Cloud-specific configuration
        if let Some(ref cloud) = config.deploy.cloud {
            cmd = cmd.env("CLOUD_PROVIDER", &cloud.provider.to_string());

            if let Some(ref region) = cloud.region {
                cmd = cmd.env("CLOUD_REGION", region);
            }

            if let Some(ref size) = cloud.size {
                cmd = cmd.env("CLOUD_SIZE", size);
            }

            // Mount SSH key if specified
            if let Some(ref ssh_key) = cloud.ssh_key {
                let resolved_ssh_key = resolve_ssh_key_path(ssh_key);
                cmd = cmd.mount(&resolved_ssh_key, CONTAINER_SSH_KEY_PATH);
            }
        }

        // Server-specific configuration
        if let Some(ref server) = config.deploy.server {
            cmd = cmd.env("SERVER_HOST", &server.host);
            cmd = cmd.env("SERVER_USER", &server.user);
            cmd = cmd.env("SERVER_PORT", &server.port.to_string());

            if let Some(ref ssh_key) = server.ssh_key {
                let resolved_ssh_key = resolve_ssh_key_path(ssh_key);
                cmd = cmd.mount(&resolved_ssh_key, CONTAINER_SSH_KEY_PATH);
            }
        }

        cmd
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// CloudDeploy — install container with Terraform/Ansible
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

pub struct CloudDeploy;

impl DeployStrategy for CloudDeploy {
    fn validate(&self, config: &StackerConfig) -> Result<(), CliError> {
        if config.deploy.cloud.is_none() {
            return Err(CliError::CloudProviderMissing);
        }

        Ok(())
    }

    fn deploy(
        &self,
        config: &StackerConfig,
        context: &DeployContext,
        executor: &dyn CommandExecutor,
    ) -> Result<DeployResult, CliError> {
        if let Some(cloud_cfg) = &config.deploy.cloud {
            if cloud_cfg.orchestrator == CloudOrchestrator::Remote {
                let cred_manager = CredentialsManager::with_default_store();
                let creds =
                    cred_manager.require_valid_token("remote cloud orchestrator deployment")?;

                if context.dry_run {
                    return Ok(DeployResult {
                        target: DeployTarget::Cloud,
                        message: "Remote cloud deploy dry-run validated payload and credentials"
                            .to_string(),
                        server_ip: None,
                        deployment_id: None,
                        project_id: None,
                        server_name: None,
                    });
                }

                // Resolve project name: CLI flag > config project.identity > config name
                let project_name = context
                    .project_name_override
                    .clone()
                    .or_else(|| config.project.identity.clone())
                    .unwrap_or_else(|| config.name.clone());

                // Resolve cloud key name: CLI flag > config deploy.cloud.key
                let key_name = context
                    .key_name_override
                    .clone()
                    .or_else(|| cloud_cfg.key.clone());

                // Resolve server name: CLI flag > config deploy.cloud.server
                let server_name = context
                    .server_name_override
                    .clone()
                    .or_else(|| cloud_cfg.server.clone());

                let base_url = resolve_saved_stacker_base_url(&creds);

                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| CliError::DeployFailed {
                        target: DeployTarget::Cloud,
                        reason: format!("Failed to initialize async runtime: {}", e),
                    })?;

                let (response, effective_server_name) = rt.block_on(async {
                    let client = StackerClient::new_for_target(
                        &base_url,
                        &creds.access_token,
                        DeployTarget::Server,
                    );

                    // Step 1: Resolve or auto-create project
                    eprintln!("  Resolving project '{}'...", project_name);
                    let project_config =
                        compose_targets::config_with_compose_secret_target_services(
                            config,
                            &context.compose_path,
                        )?;
                    let mut project_body = stacker_client::build_project_body(&project_config);
                    if let Some(bundle) = &context.config_bundle {
                        stacker_client::attach_config_bundle_to_project_body(
                            &mut project_body,
                            bundle,
                        );
                    }
                    let project = match client.find_project_by_name(&project_name).await? {
                        Some(p) => {
                            eprintln!("  Found project '{}' (id={}), syncing metadata...", p.name, p.id);
                            let updated = client
                                .update_project(p.id, project_body)
                                .await?;
                            eprintln!("  Updated project '{}' (id={})", updated.name, updated.id);
                            updated
                        }
                        None => {
                            eprintln!("  Project '{}' not found, creating...", project_name);
                            let p = client
                                .create_project(&project_name, project_body)
                                .await?;
                            eprintln!("  Created project '{}' (id={})", p.name, p.id);
                            p
                        }
                    };

                    if should_run_managed_proxy_preflight(context, DeployTarget::Cloud) {
                        cleanup_stale_managed_proxy_container(
                            &client,
                            project.id,
                            DeployTarget::Cloud,
                        )
                        .await?;
                    }

                    // Step 2: Resolve cloud credentials
                    let provider_str = cloud_cfg.provider.to_string();
                    let provider_code = provider_code_for_remote(&provider_str);
                    let env_creds = resolve_remote_cloud_credentials(provider_code);

                    let cloud_id = if let Some(cid) = context.key_id_override {
                        // --key-id flag: look up by ID (server checks ownership)
                        eprintln!("  Looking up cloud credentials by id={}...", cid);
                        match client.get_cloud(cid).await? {
                            Some(c) => {
                                eprintln!(
                                    "  Found cloud credentials (id={}, name='{}', provider={})",
                                    c.id, c.name, c.provider
                                );
                                Some(c.id)
                            }
                            None => {
                                return Err(CliError::DeployFailed {
                                    target: DeployTarget::Cloud,
                                    reason: format!(
                                        "Cloud credential id={} not found (or not owned by you). Use `stacker list clouds` to see available credentials.",
                                        cid
                                    ),
                                });
                            }
                        }
                    } else if let Some(key_ref) = &key_name {
                        // --key flag: look up by name first, fall back to provider match
                        eprintln!("  Looking up saved cloud key '{}'...", key_ref);
                        match client.find_cloud_by_name(key_ref).await? {
                            Some(c) => {
                                eprintln!(
                                    "  Found cloud credentials (id={}, name='{}', provider={})",
                                    c.id, c.name, c.provider
                                );
                                Some(c.id)
                            }
                            None => match client.find_cloud_by_provider(key_ref).await? {
                                Some(c) => {
                                    eprintln!(
                                        "  Found cloud credentials by provider (id={}, name='{}', provider={})",
                                        c.id, c.name, c.provider
                                    );
                                    Some(c.id)
                                }
                                None => {
                                    // Try saving current env-var creds under this provider
                                    let cloud_token = env_creds
                                        .get("cloud_token")
                                        .and_then(|v| v.as_str());
                                    let cloud_key = env_creds
                                        .get("cloud_key")
                                        .and_then(|v| v.as_str());
                                    let cloud_secret = env_creds
                                        .get("cloud_secret")
                                        .and_then(|v| v.as_str());

                                    if cloud_token.is_some()
                                        || cloud_key.is_some()
                                        || cloud_secret.is_some()
                                    {
                                        eprintln!(
                                            "  No saved cloud '{}', saving from env vars...",
                                            key_ref
                                        );
                                        let saved = client
                                            .save_cloud(
                                                provider_code,
                                                cloud_token,
                                                cloud_key,
                                                cloud_secret,
                                            )
                                            .await?;
                                        eprintln!(
                                            "  Saved/updated cloud credentials (id={})",
                                            saved.id
                                        );
                                        Some(saved.id)
                                    } else {
                                        return Err(CliError::DeployFailed {
                                            target: DeployTarget::Cloud,
                                            reason: format!(
                                                "Cloud key '{}' not found on server and no cloud credentials were found in env vars ({}).",
                                                key_ref,
                                                cloud_env::provider_env_summary(provider_code)
                                            ),
                                        });
                                    }
                                }
                            }
                        }
                    } else {
                        // No key specified: try to find existing cloud creds for this provider,
                        // or pass creds directly in deploy form from env vars
                        match client.find_cloud_by_provider(provider_code).await? {
                            Some(c) => {
                                eprintln!(
                                    "  Using saved cloud credentials (id={}, provider={})",
                                    c.id, c.provider
                                );
                                Some(c.id)
                            }
                            None => None,
                        }
                    };

                    ensure_remote_cloud_credentials_available(
                        cloud_id,
                        provider_code,
                        &env_creds,
                    )?;

                    // Step 3: Resolve server by name
                    let server_id = if let Some(srv_name) = &server_name {
                        eprintln!("  Looking up server '{}'...", srv_name);
                        match client.find_server_by_name(srv_name).await? {
                            Some(s) => {
                                eprintln!(
                                    "  Found server '{}' (id={})",
                                    s.name.as_deref().unwrap_or("unnamed"),
                                    s.id
                                );
                                Some(s.id)
                            }
                            None => {
                                return Err(CliError::DeployFailed {
                                    target: DeployTarget::Cloud,
                                    reason: format!(
                                        "Server '{}' not found. Create it on the Stacker server first or remove --server flag.",
                                        srv_name
                                    ),
                                });
                            }
                        }
                    } else {
                        None
                    };

                    // Step 4: Build deploy form
                    let mut deploy_form = stacker_client::build_deploy_form_with_options(
                        config,
                        stacker_client::DeployFormOptions {
                            include_managed_proxy: context.managed_proxy_feature_enabled,
                        },
                    );
                    if let Some(bundle) = &context.config_bundle {
                        stacker_client::attach_config_bundle_to_deploy_form(
                            &mut deploy_form,
                            bundle,
                        );
                    }

                    // Capture the server name from the form (auto-generated or overridden)
                    // so we can persist it in the deployment lock even if the API fetch
                    // after deploy doesn't return server details yet.
                    let effective_server_name = server_name.clone().or_else(|| {
                        deploy_form
                            .get("server")
                            .and_then(|s| s.get("name"))
                            .and_then(|n| n.as_str())
                            .map(|s| s.to_string())
                    });
                    if let Some(sid) = server_id {
                        if let Some(server_obj) = deploy_form.get_mut("server") {
                            if let Some(obj) = server_obj.as_object_mut() {
                                obj.insert(
                                    "server_id".to_string(),
                                    serde_json::Value::Number(sid.into()),
                                );
                                // When reusing an existing server, preserve
                                // the user-chosen / looked-up name rather
                                // than the auto-generated one.
                                if let Some(srv_name) = &server_name {
                                    obj.insert(
                                        "name".to_string(),
                                        serde_json::Value::String(srv_name.clone()),
                                    );
                                }
                            }
                        }
                    }

                    // Include env-var cloud creds in form if no saved cloud
                    if cloud_id.is_none() {
                        if let Some(cloud_obj) = deploy_form.get_mut("cloud") {
                            if let Some(obj) = cloud_obj.as_object_mut() {
                                for (k, v) in &env_creds {
                                    obj.insert(k.clone(), v.clone());
                                }
                                obj.insert(
                                    "save_token".to_string(),
                                    serde_json::Value::Bool(true),
                                );
                            }
                        }
                    }

                    // Inject container runtime preference
                    if let Some(form_obj) = deploy_form.as_object_mut() {
                        form_obj.insert(
                            "runtime".to_string(),
                            serde_json::json!(context.runtime),
                        );
                    }

                    // Step 5: Deploy
                    eprintln!("  Deploying project '{}' (id={})...", project_name, project.id);
                    let resp = client.deploy(project.id, cloud_id, deploy_form).await?;

                    Ok((resp, effective_server_name))
                }).map_err(|e: CliError| e)?;

                let deploy_id = response
                    .meta
                    .as_ref()
                    .and_then(|m| m.get("deployment_id"))
                    .and_then(|v| v.as_i64());

                let project_id = response.id;

                let mut message = format!(
                    "Cloud deployment requested via Stacker server (project='{}'",
                    project_name
                );

                if let Some(pid) = project_id {
                    message.push_str(&format!(", project_id={}", pid));
                }
                if let Some(did) = deploy_id {
                    message.push_str(&format!(", deployment_id={}", did));
                }
                message.push(')');

                if let Some(srv) = &server_name {
                    message.push_str(&format!("; server='{}'", srv));
                }
                if let Some(key) = &key_name {
                    message.push_str(&format!("; cloud_key='{}'", key));
                }

                return Ok(DeployResult {
                    target: DeployTarget::Cloud,
                    message,
                    server_ip: None,
                    deployment_id: deploy_id,
                    project_id: project_id.map(|id| id as i64),
                    server_name: effective_server_name,
                });
            }
        }

        let action = if context.dry_run {
            InstallAction::Plan
        } else {
            InstallAction::Apply
        };

        let cmd = InstallContainerCommand::from_config(config, context, action);
        let args = cmd.build_args();
        let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

        let output = executor.execute("docker", &args_refs)?;

        if !output.success() {
            return Err(CliError::DeployFailed {
                target: DeployTarget::Cloud,
                reason: format!("Install container failed: {}", output.stderr.trim()),
            });
        }

        let action_str = if context.dry_run {
            "plan completed"
        } else {
            "deployed"
        };
        Ok(DeployResult {
            target: DeployTarget::Cloud,
            message: format!("Cloud deployment {}", action_str),
            server_ip: extract_server_ip(&output.stdout),
            deployment_id: None,
            project_id: None,
            server_name: None,
        })
    }

    fn destroy(
        &self,
        config: &StackerConfig,
        context: &DeployContext,
        executor: &dyn CommandExecutor,
    ) -> Result<(), CliError> {
        if let Some(cloud_cfg) = &config.deploy.cloud {
            if cloud_cfg.orchestrator == CloudOrchestrator::Remote {
                return Err(CliError::DeployFailed {
                    target: DeployTarget::Cloud,
                    reason: "Remote cloud orchestrator destroy is not implemented yet. Use platform API/UI or switch deploy.cloud.orchestrator=local.".to_string(),
                });
            }
        }

        let cmd = InstallContainerCommand::from_config(config, context, InstallAction::Destroy);
        let args = cmd.build_args();
        let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

        let output = executor.execute("docker", &args_refs)?;

        if !output.success() {
            return Err(CliError::DeployFailed {
                target: DeployTarget::Cloud,
                reason: format!("Cloud destroy failed: {}", output.stderr.trim()),
            });
        }

        Ok(())
    }
}

pub fn provider_code_for_remote(config_provider: &str) -> &str {
    match config_provider {
        "hetzner" => "htz",
        "digitalocean" => "do",
        "aws" => "aws",
        "linode" => "lo",
        "vultr" => "vu",
        "contabo" => "cnt",
        _ => config_provider,
    }
}

#[allow(dead_code)]
fn normalize_user_service_base_url(raw: &str) -> String {
    let mut url = raw.trim_end_matches('/').to_string();
    if url.ends_with("/server/user/auth/login") {
        let len = url.len() - "/auth/login".len();
        return url[..len].to_string();
    }

    for suffix in ["/oauth_server/token", "/auth/login", "/login"] {
        if url.ends_with(suffix) {
            let len = url.len() - suffix.len();
            url = url[..len].to_string();
            break;
        }
    }
    url
}

/// Normalize the Stacker server URL from stored credentials.
/// Strips trailing slashes and known auth path suffixes to get the base API URL.
pub fn normalize_stacker_server_url(raw: &str) -> String {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return stacker_client::DEFAULT_STACKER_URL.to_string();
    }

    if let Ok(mut url) = reqwest::Url::parse(trimmed) {
        let path = url.path().trim_end_matches('/').to_string();
        for suffix in [
            "/api/v1",
            "/oauth_server/token",
            "/auth/login",
            "/login",
            "/api",
        ] {
            if path.ends_with(suffix) {
                let normalized = path.trim_end_matches(suffix);
                url.set_path(if normalized.is_empty() {
                    "/"
                } else {
                    normalized
                });
                url.set_query(None);
                url.set_fragment(None);
                break;
            }
        }

        return url.to_string().trim_end_matches('/').to_string();
    }

    trimmed.to_string()
}

fn resolve_saved_stacker_base_url(creds: &StoredCredentials) -> String {
    normalize_stacker_server_url(
        creds
            .server_url
            .as_deref()
            .unwrap_or(stacker_client::DEFAULT_STACKER_URL),
    )
}

#[allow(dead_code)]
fn sanitize_stack_code(name: &str) -> String {
    let mut out = String::new();
    let mut prev_dash = false;
    for ch in name.chars() {
        let c = ch.to_ascii_lowercase();
        if c.is_ascii_alphanumeric() {
            out.push(c);
            prev_dash = false;
        } else if !prev_dash {
            out.push('-');
            prev_dash = true;
        }
    }
    let out = out.trim_matches('-').to_string();
    if out.is_empty() {
        "app-stack".to_string()
    } else {
        out
    }
}

#[allow(dead_code)]
fn default_common_domain(project_name: &str) -> String {
    format!("{}.example.com", sanitize_stack_code(project_name))
}

fn first_non_empty_env(keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        std::env::var(key)
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    })
}

fn resolve_remote_cloud_credentials(provider: &str) -> serde_json::Map<String, serde_json::Value> {
    let mut creds = serde_json::Map::new();

    match provider {
        "htz" => {
            if let Some(token) = first_non_empty_env(cloud_env::token_env_vars("htz")) {
                creds.insert("cloud_token".to_string(), serde_json::Value::String(token));
            }
        }
        "do" => {
            if let Some(token) = first_non_empty_env(cloud_env::token_env_vars("do")) {
                creds.insert("cloud_token".to_string(), serde_json::Value::String(token));
            }
        }
        "lo" => {
            if let Some(token) = first_non_empty_env(cloud_env::token_env_vars("lo")) {
                creds.insert("cloud_token".to_string(), serde_json::Value::String(token));
            }
        }
        "vu" => {
            if let Some(token) = first_non_empty_env(cloud_env::token_env_vars("vu")) {
                creds.insert("cloud_token".to_string(), serde_json::Value::String(token));
            }
        }
        "aws" => {
            if let Some(key) = first_non_empty_env(cloud_env::key_env_vars("aws")) {
                creds.insert("cloud_key".to_string(), serde_json::Value::String(key));
            }
            if let Some(secret) = first_non_empty_env(cloud_env::secret_env_vars("aws")) {
                creds.insert(
                    "cloud_secret".to_string(),
                    serde_json::Value::String(secret),
                );
            }
        }
        "cnt" => {
            // Contabo uses four credentials: OAuth2 client_id/secret + API user/password.
            if let Some(v) = first_non_empty_env(cloud_env::CONTABO_CLIENT_ID_ENV_VARS) {
                creds.insert("cloud_key".to_string(), serde_json::Value::String(v));
            }
            if let Some(v) = first_non_empty_env(cloud_env::CONTABO_CLIENT_SECRET_ENV_VARS) {
                creds.insert("cloud_token".to_string(), serde_json::Value::String(v));
            }
            if let Some(v) = first_non_empty_env(cloud_env::CONTABO_API_USER_ENV_VARS) {
                creds.insert("cloud_user".to_string(), serde_json::Value::String(v));
            }
            if let Some(v) = first_non_empty_env(cloud_env::CONTABO_API_PASSWORD_ENV_VARS) {
                creds.insert("cloud_password".to_string(), serde_json::Value::String(v));
            }
        }
        _ => {}
    }

    creds
}

fn ensure_remote_cloud_credentials_available(
    cloud_id: Option<i32>,
    provider: &str,
    env_creds: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), CliError> {
    if cloud_id.is_some() || !env_creds.is_empty() {
        return Ok(());
    }

    let hint = cloud_env::provider_missing_credentials_hint(provider);

    Err(CliError::DeployFailed {
        target: DeployTarget::Cloud,
        reason: format!(
            "No saved cloud credentials were found for provider '{}', and no provider credentials were found in the environment. {}",
            provider, hint
        ),
    })
}

fn stale_managed_proxy_container_names(
    containers: &[serde_json::Value],
    app_code: &str,
) -> Vec<String> {
    let normalized_code = crate::project_app::normalize_app_code(app_code);
    containers
        .iter()
        .filter_map(|container| {
            let name = container.get("name").and_then(|value| value.as_str())?;
            let normalized_name = crate::project_app::normalize_app_code(name);
            let image = container
                .get("image")
                .and_then(|value| value.as_str())
                .unwrap_or_default()
                .to_lowercase();

            let is_project_scoped = normalized_name.starts_with("project_")
                && normalized_name.contains(&normalized_code);
            let is_duplicate_npm_image =
                image.contains("nginx-proxy-manager") && normalized_name != normalized_code;

            if is_project_scoped || is_duplicate_npm_image {
                Some(name.to_string())
            } else {
                None
            }
        })
        .collect()
}

fn stale_managed_proxy_app_codes(
    project_apps: &[stacker_client::ProjectAppInfo],
    app_code: &str,
) -> Vec<String> {
    let normalized_code = crate::project_app::normalize_app_code(app_code);
    project_apps
        .iter()
        .filter(|app| {
            crate::project_app::normalize_app_code(&app.code) == normalized_code
                || crate::project_app::normalize_app_code(&app.name) == normalized_code
        })
        .map(|app| app.code.clone())
        .collect()
}

async fn wait_for_agent_command_completion(
    client: &StackerClient,
    deployment_hash: &str,
    command_id: &str,
    timeout_secs: u64,
    target: DeployTarget,
) -> Result<stacker_client::AgentCommandInfo, CliError> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    let interval = std::time::Duration::from_secs(2);
    let mut last_status = "pending".to_string();

    loop {
        tokio::time::sleep(interval).await;

        if tokio::time::Instant::now() >= deadline {
            return Err(CliError::DeployFailed {
                target,
                reason: format!(
                    "Timed out waiting for cleanup command '{}' on deployment '{}' (last status: {})",
                    command_id, deployment_hash, last_status
                ),
            });
        }

        let status = client
            .agent_command_status(deployment_hash, command_id)
            .await?;
        last_status = status.status.clone();

        match status.status.as_str() {
            "completed" | "failed" => return Ok(status),
            _ => continue,
        }
    }
}

async fn fetch_live_containers(
    client: &StackerClient,
    deployment_hash: &str,
    target: DeployTarget,
) -> Result<Vec<serde_json::Value>, CliError> {
    let params = crate::forms::status_panel::ListContainersCommandRequest {
        include_health: true,
        include_logs: false,
        log_lines: 10,
    };
    let request = stacker_client::AgentEnqueueRequest::new(deployment_hash, "list_containers")
        .with_parameters(&params)
        .map_err(|error| {
            CliError::ConfigValidation(format!("Invalid list_containers parameters: {}", error))
        })?;

    let completed = client.agent_poll_result(&request, 120, 2).await?;
    if completed.status != "completed" {
        let detail = completed
            .error
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown error".to_string());
        return Err(CliError::DeployFailed {
            target,
            reason: format!("Failed to fetch live containers before deploy: {}", detail),
        });
    }

    Ok(completed
        .result
        .and_then(|result| {
            result
                .get("containers")
                .and_then(|value| value.as_array())
                .cloned()
        })
        .unwrap_or_default())
}

async fn cleanup_stale_managed_proxy_container(
    client: &StackerClient,
    project_id: i32,
    target: DeployTarget,
) -> Result<bool, CliError> {
    let project_apps = client.list_project_apps(project_id).await?;
    let stale_project_app_codes =
        stale_managed_proxy_app_codes(&project_apps, "nginx_proxy_manager");
    let deployment = client.get_deployment_status_by_project(project_id).await?;
    let stale_container_names = if let Some(deployment) = deployment.as_ref() {
        match fetch_live_containers(client, &deployment.deployment_hash, target).await {
            Ok(containers) => {
                stale_managed_proxy_container_names(&containers, "nginx_proxy_manager")
            }
            Err(CliError::AgentNotFound { .. }) => Vec::new(),
            Err(error) => return Err(error),
        }
    } else {
        Vec::new()
    };

    if stale_project_app_codes.is_empty() && stale_container_names.is_empty() {
        return Ok(false);
    }

    if !stale_project_app_codes.is_empty() {
        eprintln!(
            "  Found stale managed proxy app registrations ({}); deleting them before deploy...",
            stale_project_app_codes.join(", ")
        );
        for app_code in &stale_project_app_codes {
            client
                .delete_project_app(
                    project_id,
                    app_code,
                    deployment
                        .as_ref()
                        .map(|value| value.deployment_hash.as_str()),
                )
                .await?;
        }
    }

    if stale_container_names.is_empty() {
        eprintln!("  Removed stale managed nginx_proxy_manager project state");
        return Ok(true);
    }

    let Some(deployment) = deployment else {
        eprintln!("  Removed stale managed nginx_proxy_manager project state");
        return Ok(true);
    };

    eprintln!(
        "  Found stale managed proxy containers on deployment '{}': {}; removing them before managed proxy restart...",
        deployment.deployment_hash,
        stale_container_names.join(", ")
    );

    for container_name in &stale_container_names {
        let params = crate::forms::status_panel::RemoveAppCommandRequest {
            app_code: container_name.clone(),
            delete_config: false,
            remove_volumes: false,
            remove_image: false,
        };
        let request =
            stacker_client::AgentEnqueueRequest::new(&deployment.deployment_hash, "remove_app")
                .with_parameters(&params)
                .map_err(|error| {
                    CliError::ConfigValidation(format!("Invalid cleanup parameters: {}", error))
                })?;

        let enqueued = client.agent_enqueue(&request).await?;
        let completed = wait_for_agent_command_completion(
            client,
            &deployment.deployment_hash,
            &enqueued.command_id,
            120,
            target,
        )
        .await?;

        if completed.status != "completed" {
            let detail = completed
                .error
                .map(|value| value.to_string())
                .unwrap_or_else(|| "unknown error".to_string());
            return Err(CliError::DeployFailed {
                target,
                reason: format!(
                    "Failed to remove stale managed proxy container '{}' before deploy: {}",
                    container_name, detail
                ),
            });
        }
    }

    if !stale_project_app_codes.is_empty() {
        eprintln!("  Removed stale managed nginx_proxy_manager project state and containers");
    } else {
        eprintln!("  Removed stale managed nginx_proxy_manager containers");
    }
    Ok(true)
}

/// Resolve Docker registry credentials from the stacker.yml `deploy.registry` section
/// and/or environment variables. Env vars override config values (same pattern as cloud_token).
///
/// Returns a map with optional keys: `docker_username`, `docker_password`, `docker_registry`.
pub(crate) fn resolve_docker_registry_credentials(
    config: &super::config_parser::StackerConfig,
) -> serde_json::Map<String, serde_json::Value> {
    let mut creds = serde_json::Map::new();
    let registry = config.deploy.registry.as_ref();

    // Username: env var > config
    let username = first_non_empty_env(&["STACKER_DOCKER_USERNAME", "DOCKER_USERNAME"])
        .or_else(|| registry.and_then(|r| r.username.clone()));

    // Password: env var > config
    let password = first_non_empty_env(&["STACKER_DOCKER_PASSWORD", "DOCKER_PASSWORD"])
        .or_else(|| registry.and_then(|r| r.password.clone()));

    // Registry server: env var > config > default "docker.io"
    let server = first_non_empty_env(&["STACKER_DOCKER_REGISTRY", "DOCKER_REGISTRY"])
        .or_else(|| registry.and_then(|r| r.server.clone()))
        .or_else(|| {
            if username.is_some() || password.is_some() {
                Some("docker.io".to_string())
            } else {
                None
            }
        })
        .map(canonicalize_registry_server);

    if let Some(u) = username {
        creds.insert("docker_username".to_string(), serde_json::Value::String(u));
    }
    if let Some(p) = password {
        creds.insert("docker_password".to_string(), serde_json::Value::String(p));
    }
    if let Some(s) = server {
        creds.insert("docker_registry".to_string(), serde_json::Value::String(s));
    }

    creds
}

fn canonicalize_registry_server(server: String) -> String {
    let trimmed = server.trim().trim_end_matches('/').to_string();
    let lower = trimmed.to_ascii_lowercase();

    if lower == "docker.io"
        || lower == "hub.docker.com"
        || lower == "index.docker.io"
        || lower == "registry-1.docker.io"
        || lower == "https://docker.io"
        || lower == "https://hub.docker.com"
        || lower == "https://index.docker.io"
        || lower == "https://index.docker.io/v1"
        || lower == "https://index.docker.io/v1/"
        || lower == "https://registry-1.docker.io"
    {
        "docker.io".to_string()
    } else {
        trimmed
    }
}

#[allow(dead_code)]
fn build_remote_deploy_payload(config: &StackerConfig) -> serde_json::Value {
    let cloud = config.deploy.cloud.as_ref();
    let provider = cloud
        .map(|c| provider_code_for_remote(&c.provider.to_string()).to_string())
        .unwrap_or_else(|| "htz".to_string());
    let region = cloud
        .and_then(|c| c.region.clone())
        .unwrap_or_else(|| "nbg1".to_string());
    let server = cloud
        .and_then(|c| c.size.clone())
        .unwrap_or_else(|| "cpx11".to_string());
    let stack_code = config
        .project
        .identity
        .clone()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "custom-stack".to_string());
    let os = match provider.as_str() {
        "do" => "docker-20-04", // DigitalOcean marketplace image with Docker pre-installed
        "htz" => "docker-ce",   // Hetzner snapshot with Docker CE pre-installed (Ubuntu 24.04)
        "cnt" => "ubuntu-22.04", // Contabo: standard Ubuntu image
        _ => "ubuntu-22.04",
    };

    let mut payload = serde_json::json!({
        "provider": provider,
        "region": region,
        "server": server,
        "os": os,
        "ssl": "letsencrypt",
        "commonDomain": default_common_domain(&config.name),
        "domainList": {},
        "stack_code": stack_code,
        "project_name": config.name,
        "selected_plan": "free",
        "payment_type": "subscription",
        "subscriptions": [],
        "vars": [],
        "integrated_features": [],
        "extended_features": [],
        "save_token": true,
        "custom": {
            "project_name": config.name,
            "custom_stack_code": sanitize_stack_code(&config.name),
            "project_overview": format!("Generated by stacker-cli for {}", config.name)
        }
    });

    if let Some(obj) = payload.as_object_mut() {
        for (key, value) in resolve_remote_cloud_credentials(&provider) {
            obj.insert(key, value);
        }
    }

    payload
}

#[allow(dead_code)]
fn validate_remote_deploy_payload(payload: &serde_json::Value) -> Result<(), CliError> {
    let required = [
        "provider",
        "region",
        "server",
        "os",
        "commonDomain",
        "stack_code",
        "selected_plan",
        "payment_type",
        "subscriptions",
    ];

    let mut missing = Vec::new();

    for key in required {
        match payload.get(key) {
            Some(v) if !v.is_null() => {
                if key == "subscriptions" && !v.is_array() {
                    missing.push("subscriptions(array)");
                }
                if key == "stack_code" && v.as_str().map(|s| s.trim().is_empty()).unwrap_or(true) {
                    missing.push("stack_code(non-empty)");
                }
            }
            _ => missing.push(key),
        }
    }

    if !missing.is_empty() {
        let identity_hint = if missing.iter().any(|item| item.contains("stack_code")) {
            " stack_code defaults to 'custom-stack'. Optionally set project.identity in stacker.yml to a registered catalog stack code."
        } else {
            ""
        };
        Err(CliError::DeployFailed {
            target: DeployTarget::Cloud,
            reason: format!(
                "Remote deploy payload is missing required fields: {}. Preferred flow: remove `deploy.cloud.remote_payload_file` and run `stacker deploy --target cloud` so payload is generated automatically. For advanced/debug use `stacker-cli config setup remote-payload`.{}",
                missing.join(", "),
                identity_hint
            ),
        })
    } else {
        let mut invalid = Vec::new();

        if let Some(domain) = payload.get("commonDomain").and_then(|v| v.as_str()) {
            let normalized = domain.trim().to_ascii_lowercase();
            if normalized == "localhost" || !normalized.contains('.') {
                invalid.push("commonDomain(valid domain required)");
            }
        }

        let provider = payload
            .get("provider")
            .and_then(|v| v.as_str())
            .unwrap_or_default();

        match provider {
            "htz" | "lo" | "vu" => {
                let has_token = payload
                    .get("cloud_token")
                    .and_then(|v| v.as_str())
                    .map(|v| !v.trim().is_empty())
                    .unwrap_or(false);
                if !has_token {
                    invalid.push("cloud_token");
                }
            }
            "aws" => {
                let has_key = payload
                    .get("cloud_key")
                    .and_then(|v| v.as_str())
                    .map(|v| !v.trim().is_empty())
                    .unwrap_or(false);
                let has_secret = payload
                    .get("cloud_secret")
                    .and_then(|v| v.as_str())
                    .map(|v| !v.trim().is_empty())
                    .unwrap_or(false);

                if !has_key {
                    invalid.push("cloud_key");
                }
                if !has_secret {
                    invalid.push("cloud_secret");
                }
            }
            _ => {}
        }

        if invalid.is_empty() {
            Ok(())
        } else {
            Err(CliError::DeployFailed {
                target: DeployTarget::Cloud,
                reason: format!(
                    "Remote deploy payload has invalid/missing provider credentials: {}. Set env vars before deploy (e.g. STACKER_CLOUD_TOKEN or provider-specific token vars; for AWS use AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY).",
                    invalid.join(", ")
                ),
            })
        }
    }
}

#[allow(dead_code)]
fn persist_remote_payload_snapshot(
    project_dir: &Path,
    payload: &serde_json::Value,
) -> Option<PathBuf> {
    let stacker_dir = project_dir.join(".stacker");
    let snapshot_path = stacker_dir.join("remote-payload.last.json");

    if let Err(err) = std::fs::create_dir_all(&stacker_dir) {
        eprintln!(
            "Warning: failed to create payload snapshot directory {}: {}",
            stacker_dir.display(),
            err
        );
        return None;
    }

    let payload_str = match serde_json::to_string_pretty(payload) {
        Ok(s) => s,
        Err(err) => {
            eprintln!(
                "Warning: failed to serialize remote payload snapshot: {}",
                err
            );
            return None;
        }
    };

    if let Err(err) = std::fs::write(&snapshot_path, payload_str) {
        eprintln!(
            "Warning: failed to write payload snapshot {}: {}",
            snapshot_path.display(),
            err
        );
        return None;
    }

    Some(snapshot_path)
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// ServerDeploy — SSH + install container
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

pub struct ServerDeploy;

impl DeployStrategy for ServerDeploy {
    fn validate(&self, config: &StackerConfig) -> Result<(), CliError> {
        if config.deploy.server.is_none() {
            return Err(CliError::ServerHostMissing);
        }

        Ok(())
    }

    fn deploy(
        &self,
        config: &StackerConfig,
        context: &DeployContext,
        executor: &dyn CommandExecutor,
    ) -> Result<DeployResult, CliError> {
        if context.dry_run {
            let action = InstallAction::Plan;
            let cmd = InstallContainerCommand::from_config(config, context, action);
            let args = cmd.build_args();
            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

            let output = executor.execute("docker", &args_refs)?;

            if !output.success() {
                return Err(CliError::DeployFailed {
                    target: DeployTarget::Server,
                    reason: format!("Server deployment failed: {}", output.stderr.trim()),
                });
            }

            let server_host = config.deploy.server.as_ref().map(|s| s.host.clone());

            return Ok(DeployResult {
                target: DeployTarget::Server,
                message: "Server deployment plan completed".to_string(),
                server_ip: server_host,
                deployment_id: None,
                project_id: None,
                server_name: None,
            });
        }

        let creds =
            CredentialsManager::with_default_store().require_valid_token("server deploy")?;
        let base_url = normalize_stacker_server_url(
            creds
                .server_url
                .as_deref()
                .unwrap_or(stacker_client::DEFAULT_STACKER_URL),
        );
        let server_cfg = config
            .deploy
            .server
            .as_ref()
            .ok_or(CliError::ServerHostMissing)?;
        let project_name = resolve_remote_project_name(config, context);
        let project_config = compose_targets::config_with_compose_secret_target_services(
            config,
            &context.compose_path,
        )?;
        let mut project_body = stacker_client::build_project_body(&project_config);
        if let Some(bundle) = &context.config_bundle {
            stacker_client::attach_config_bundle_to_project_body(&mut project_body, bundle);
        }
        let bootstrap_status_panel = true;

        let (response, effective_server_name) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| CliError::DeployFailed {
                target: DeployTarget::Server,
                reason: format!("Failed to initialize async runtime: {}", e),
            })?
            .block_on(async {
                let client = StackerClient::new_for_target(
                    &base_url,
                    &creds.access_token,
                    DeployTarget::Server,
                );

                let project = match client.find_project_by_name(&project_name).await? {
                    Some(existing) => {
                        let _ = client
                            .update_project(existing.id, project_body.clone())
                            .await;
                        existing
                    }
                    None => {
                        let created = client
                            .create_project(&project_name, project_body.clone())
                            .await?;
                        eprintln!("  Created project '{}' (id={})", created.name, created.id);
                        created
                    }
                };

                if should_run_managed_proxy_preflight(context, DeployTarget::Server) {
                    cleanup_stale_managed_proxy_container(
                        &client,
                        project.id,
                        DeployTarget::Server,
                    )
                    .await?;
                }

                let existing_server = client.list_servers().await?.into_iter().find(|server| {
                    server.project_id == project.id
                        && (server.srv_ip.as_deref() == Some(server_cfg.host.as_str())
                            || context
                                .server_name_override
                                .as_deref()
                                .is_some_and(|name| server.name.as_deref() == Some(name)))
                });

                let effective_server_name = context
                    .server_name_override
                    .clone()
                    .or_else(|| {
                        existing_server
                            .as_ref()
                            .and_then(|server| server.name.clone())
                    })
                    .unwrap_or_else(|| {
                        format!(
                            "{}-server",
                            sanitize_stack_code(
                                &config
                                    .project
                                    .identity
                                    .clone()
                                    .unwrap_or_else(|| config.name.clone())
                            )
                        )
                    });

                let mut deploy_form = stacker_client::build_server_deploy_form_with_options(
                    config,
                    server_cfg,
                    &effective_server_name,
                    bootstrap_status_panel,
                    stacker_client::DeployFormOptions {
                        include_managed_proxy: context.managed_proxy_feature_enabled,
                    },
                );
                if let Some(bundle) = &context.config_bundle {
                    stacker_client::attach_config_bundle_to_deploy_form(&mut deploy_form, bundle);
                }

                if let Some(server_obj) = deploy_form
                    .get_mut("server")
                    .and_then(|v| v.as_object_mut())
                {
                    if let Some(existing) = existing_server.as_ref() {
                        server_obj.insert("server_id".to_string(), serde_json::json!(existing.id));
                    }

                    if let Some((private_key, public_key)) =
                        load_existing_server_ssh_key(server_cfg)?
                    {
                        server_obj.insert(
                            "ssh_private_key".to_string(),
                            serde_json::Value::String(private_key),
                        );
                        if let Some(public_key) = public_key {
                            server_obj.insert(
                                "public_key".to_string(),
                                serde_json::Value::String(public_key),
                            );
                        }
                    }
                }

                if let Some(form_obj) = deploy_form.as_object_mut() {
                    form_obj.insert("runtime".to_string(), serde_json::json!(context.runtime));
                }

                eprintln!(
                    "  Deploying project '{}' to {} via Stacker server...",
                    project_name, server_cfg.host
                );
                let response = client.deploy(project.id, None, deploy_form).await?;
                Ok::<_, CliError>((response, effective_server_name))
            })?;

        let deploy_id = response
            .meta
            .as_ref()
            .and_then(|m| m.get("deployment_id"))
            .and_then(|v| v.as_i64());
        let project_id = response.id;

        let mut message = format!(
            "Server deployment requested via Stacker server (project='{}'",
            project_name
        );
        if let Some(pid) = project_id {
            message.push_str(&format!(", project_id={}", pid));
        }
        if let Some(did) = deploy_id {
            message.push_str(&format!(", deployment_id={}", did));
        }
        message.push(')');
        message.push_str(&format!("; server='{}'", effective_server_name));

        Ok(DeployResult {
            target: DeployTarget::Server,
            message,
            server_ip: Some(server_cfg.host.clone()),
            deployment_id: deploy_id,
            project_id: project_id.map(|id| id as i64),
            server_name: Some(effective_server_name),
        })
    }

    fn destroy(
        &self,
        config: &StackerConfig,
        context: &DeployContext,
        executor: &dyn CommandExecutor,
    ) -> Result<(), CliError> {
        let action = if context.dry_run {
            InstallAction::Plan
        } else {
            InstallAction::Destroy
        };
        let cmd = InstallContainerCommand::from_config(config, context, action);
        let args = cmd.build_args();
        let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

        let output = executor.execute("docker", &args_refs)?;

        if !output.success() {
            return Err(CliError::DeployFailed {
                target: DeployTarget::Server,
                reason: format!("Server destroy failed: {}", output.stderr.trim()),
            });
        }

        Ok(())
    }
}

fn resolve_remote_project_name(config: &StackerConfig, context: &DeployContext) -> String {
    context.project_name_override.clone().unwrap_or_else(|| {
        config
            .project
            .identity
            .clone()
            .filter(|name| !name.trim().is_empty())
            .unwrap_or_else(|| config.name.clone())
    })
}

pub(crate) fn load_existing_server_ssh_key(
    server_cfg: &crate::cli::config_parser::ServerConfig,
) -> Result<Option<(String, Option<String>)>, CliError> {
    let Some(path) = server_cfg.ssh_key.as_ref() else {
        return Ok(None);
    };

    let resolved_path = resolve_ssh_key_path(path);

    let private_key =
        std::fs::read_to_string(&resolved_path).map_err(|e| CliError::DeployFailed {
            target: DeployTarget::Server,
            reason: format!(
                "Failed to read SSH private key {}: {}",
                resolved_path.display(),
                e
            ),
        })?;

    let public_key_path = PathBuf::from(format!("{}.pub", resolved_path.display()));
    let public_key = match std::fs::read_to_string(&public_key_path) {
        Ok(key) => Some(key),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            return Err(CliError::DeployFailed {
                target: DeployTarget::Server,
                reason: format!(
                    "Failed to read SSH public key {}: {}",
                    public_key_path.display(),
                    e
                ),
            });
        }
    };

    Ok(Some((private_key, public_key)))
}

fn resolve_ssh_key_path_with_home(path: &Path, home_dir: Option<&Path>) -> PathBuf {
    let path_str = path.to_string_lossy();
    if let Some(relative_path) = path_str.strip_prefix("~/") {
        if let Some(home_dir) = home_dir {
            return home_dir.join(relative_path);
        }
    }

    path.to_path_buf()
}

fn resolve_ssh_key_path(path: &Path) -> PathBuf {
    let home_dir = std::env::var_os("HOME").map(PathBuf::from);
    resolve_ssh_key_path_with_home(path, home_dir.as_deref())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Helpers
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Try to extract a server IP from install container stdout.
/// Looks for lines like `server_ip = 1.2.3.4` (Terraform output format).
fn extract_server_ip(stdout: &str) -> Option<String> {
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("server_ip") || trimmed.starts_with("public_ip") {
            if let Some(value) = trimmed.split('=').nth(1) {
                let ip = value.trim().trim_matches('"');
                if !ip.is_empty() {
                    return Some(ip.to_string());
                }
            }
        }
    }
    None
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Tests
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::config_parser::{
        CloudConfig, CloudOrchestrator, CloudProvider, ConfigBuilder, RegistryConfig, ServerConfig,
    };
    use std::sync::Mutex;

    // ── Mock executor ───────────────────────────────

    struct MockExecutor {
        recorded_calls: Mutex<Vec<(String, Vec<String>)>>,
        exit_code: i32,
        stdout: String,
        stderr: String,
    }

    impl MockExecutor {
        fn success() -> Self {
            Self {
                recorded_calls: Mutex::new(Vec::new()),
                exit_code: 0,
                stdout: String::new(),
                stderr: String::new(),
            }
        }

        #[allow(dead_code)]
        fn success_with_stdout(stdout: &str) -> Self {
            Self {
                recorded_calls: Mutex::new(Vec::new()),
                exit_code: 0,
                stdout: stdout.to_string(),
                stderr: String::new(),
            }
        }

        fn failure(stderr: &str) -> Self {
            Self {
                recorded_calls: Mutex::new(Vec::new()),
                exit_code: 1,
                stdout: String::new(),
                stderr: stderr.to_string(),
            }
        }

        fn last_call(&self) -> (String, Vec<String>) {
            self.recorded_calls.lock().unwrap().last().cloned().unwrap()
        }

        fn last_args(&self) -> Vec<String> {
            self.last_call().1
        }
    }

    impl CommandExecutor for MockExecutor {
        fn execute(&self, program: &str, args: &[&str]) -> Result<CommandOutput, CliError> {
            self.recorded_calls.lock().unwrap().push((
                program.to_string(),
                args.iter().map(|s| s.to_string()).collect(),
            ));

            Ok(CommandOutput {
                exit_code: self.exit_code,
                stdout: self.stdout.clone(),
                stderr: self.stderr.clone(),
            })
        }
    }

    // Helper to join args as a single string for easier assertion.
    fn args_as_string(args: &[String]) -> String {
        args.join(" ")
    }

    fn sample_cloud_config() -> StackerConfig {
        ConfigBuilder::new()
            .name("test-cloud-app")
            .deploy_target(DeployTarget::Cloud)
            .cloud(CloudConfig {
                provider: CloudProvider::Hetzner,
                orchestrator: CloudOrchestrator::Local,
                region: Some("fsn1".to_string()),
                size: Some("cpx21".to_string()),
                install_image: None,
                remote_payload_file: None,
                ssh_key: Some(PathBuf::from("/home/user/.ssh/id_ed25519")),
                key: None,
                server: None,
            })
            .build()
            .unwrap()
    }

    #[test]
    fn test_stale_managed_proxy_container_names_detect_project_scoped_nginx_proxy_manager() {
        let containers = vec![
            serde_json::json!({
                "name": "nginx-proxy-manager",
                "state": "running",
                "image": "jc21/nginx-proxy-manager:latest"
            }),
            serde_json::json!({
                "name": "project-nginx_proxy_manager-1",
                "state": "exited",
                "image": "jc21/nginx-proxy-manager:latest"
            }),
        ];

        assert_eq!(
            stale_managed_proxy_container_names(&containers, "nginx_proxy_manager"),
            vec!["project-nginx_proxy_manager-1".to_string()]
        );
    }

    #[test]
    fn test_stale_managed_proxy_container_names_ignore_managed_container_only() {
        let containers = vec![serde_json::json!({
            "name": "nginx-proxy-manager",
            "state": "running",
            "image": "jc21/nginx-proxy-manager:latest"
        })];

        assert!(stale_managed_proxy_container_names(&containers, "nginx_proxy_manager").is_empty());
    }

    #[test]
    fn test_stale_managed_proxy_container_names_detect_duplicate_npm_container_alias() {
        let containers = vec![
            serde_json::json!({
                "name": "nginx-proxy-manager",
                "state": "running",
                "image": "jc21/nginx-proxy-manager:latest"
            }),
            serde_json::json!({
                "name": "nginx-proxy-manager-app-1",
                "state": "running",
                "image": "jc21/nginx-proxy-manager:latest"
            }),
        ];

        assert_eq!(
            stale_managed_proxy_container_names(&containers, "nginx_proxy_manager"),
            vec!["nginx-proxy-manager-app-1".to_string()]
        );
    }

    #[test]
    fn test_stale_managed_proxy_app_codes_detect_nginx_proxy_manager_registration() {
        let apps = vec![
            stacker_client::ProjectAppInfo {
                id: 1,
                project_id: 1,
                code: "nginx_proxy_manager".to_string(),
                name: "Nginx Proxy Manager".to_string(),
                image: "jc21/nginx-proxy-manager".to_string(),
                enabled: true,
                deploy_order: None,
                parent_app_code: None,
            },
            stacker_client::ProjectAppInfo {
                id: 2,
                project_id: 1,
                code: "status-panel-web".to_string(),
                name: "Status Panel".to_string(),
                image: "trydirect/status".to_string(),
                enabled: true,
                deploy_order: None,
                parent_app_code: None,
            },
        ];

        assert_eq!(
            stale_managed_proxy_app_codes(&apps, "nginx_proxy_manager"),
            vec!["nginx_proxy_manager".to_string()]
        );
    }

    #[test]
    fn test_stale_managed_proxy_app_codes_match_hyphenated_aliases() {
        let apps = vec![stacker_client::ProjectAppInfo {
            id: 1,
            project_id: 1,
            code: "nginx-proxy-manager".to_string(),
            name: "Nginx Proxy Manager".to_string(),
            image: "jc21/nginx-proxy-manager".to_string(),
            enabled: true,
            deploy_order: None,
            parent_app_code: None,
        }];

        assert_eq!(
            stale_managed_proxy_app_codes(&apps, "nginx_proxy_manager"),
            vec!["nginx-proxy-manager".to_string()]
        );
    }

    #[test]
    fn test_stale_managed_proxy_app_codes_ignore_unrelated_apps() {
        let apps = vec![stacker_client::ProjectAppInfo {
            id: 2,
            project_id: 1,
            code: "status-panel-web".to_string(),
            name: "Status Panel".to_string(),
            image: "trydirect/status".to_string(),
            enabled: true,
            deploy_order: None,
            parent_app_code: None,
        }];

        assert!(stale_managed_proxy_app_codes(&apps, "nginx_proxy_manager").is_empty());
    }

    #[test]
    fn test_normalize_user_service_base_url_from_token_endpoint() {
        let url = normalize_user_service_base_url("https://api.try.direct/oauth_server/token");
        assert_eq!(url, "https://api.try.direct");
    }

    #[test]
    fn test_normalize_user_service_base_url_from_direct_login_endpoint() {
        let url = normalize_user_service_base_url("https://dev.try.direct/server/user/auth/login");
        assert_eq!(url, "https://dev.try.direct/server/user");
    }

    #[test]
    fn test_provider_code_for_remote_hetzner() {
        assert_eq!(provider_code_for_remote("hetzner"), "htz");
        assert_eq!(provider_code_for_remote("aws"), "aws");
        assert_eq!(provider_code_for_remote("linode"), "lo");
        assert_eq!(provider_code_for_remote("vultr"), "vu");
    }

    #[test]
    fn test_build_remote_deploy_payload_contains_required_fields() {
        let cfg = sample_cloud_config();
        let payload = build_remote_deploy_payload(&cfg);
        assert!(payload.get("provider").is_some());
        assert!(payload.get("region").is_some());
        assert!(payload.get("server").is_some());
        assert!(payload.get("os").is_some());
        assert!(payload.get("commonDomain").is_some());
        assert!(payload.get("selected_plan").is_some());
        assert!(payload.get("payment_type").is_some());
        assert!(payload.get("subscriptions").is_some());
        assert!(payload.get("stack_code").is_some());
        assert_eq!(
            payload.get("stack_code").and_then(|v| v.as_str()),
            Some("custom-stack")
        );
    }

    #[test]
    fn test_build_remote_deploy_payload_uses_project_identity_when_set() {
        let cfg = ConfigBuilder::new()
            .name("test-cloud-app")
            .project_identity("registered-stack-code")
            .deploy_target(DeployTarget::Cloud)
            .cloud(CloudConfig {
                provider: CloudProvider::Hetzner,
                orchestrator: CloudOrchestrator::Local,
                region: Some("fsn1".to_string()),
                size: Some("cpx21".to_string()),
                install_image: None,
                remote_payload_file: None,
                ssh_key: Some(PathBuf::from("/home/user/.ssh/id_ed25519")),
                key: None,
                server: None,
            })
            .build()
            .unwrap();

        let payload = build_remote_deploy_payload(&cfg);
        assert_eq!(
            payload.get("stack_code").and_then(|v| v.as_str()),
            Some("registered-stack-code")
        );
    }

    #[test]
    fn test_validate_remote_deploy_payload_accepts_generated_payload() {
        std::env::set_var("STACKER_CLOUD_TOKEN", "test-token-value");
        let cfg = sample_cloud_config();
        let payload = build_remote_deploy_payload(&cfg);
        let result = validate_remote_deploy_payload(&payload);
        std::env::remove_var("STACKER_CLOUD_TOKEN");
        assert!(result.is_ok());
    }

    #[test]
    fn test_resolve_remote_cloud_credentials_accepts_digitalocean_token() {
        std::env::remove_var("STACKER_CLOUD_TOKEN");
        std::env::remove_var("STACKER_DIGITALOCEAN_TOKEN");
        std::env::set_var("DIGITALOCEAN_TOKEN", "do-token-value");

        let creds = resolve_remote_cloud_credentials("do");

        std::env::remove_var("DIGITALOCEAN_TOKEN");

        assert_eq!(
            creds.get("cloud_token").and_then(|v| v.as_str()),
            Some("do-token-value")
        );
    }

    #[test]
    fn test_validate_remote_deploy_payload_rejects_missing_common_domain() {
        let payload = serde_json::json!({
            "provider": "htz",
            "region": "nbg1",
            "server": "cpx11",
            "os": "ubuntu-22.04",
            "stack_code": "demo",
            "selected_plan": "free",
            "payment_type": "subscription",
            "subscriptions": []
        });

        let err = validate_remote_deploy_payload(&payload).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("commonDomain"));
    }

    #[test]
    fn test_validate_remote_deploy_payload_rejects_empty_stack_code() {
        let payload = serde_json::json!({
            "provider": "htz",
            "region": "nbg1",
            "server": "cpx11",
            "os": "ubuntu-22.04",
            "commonDomain": "example.com",
            "stack_code": "",
            "selected_plan": "free",
            "payment_type": "subscription",
            "subscriptions": [],
            "cloud_token": "token"
        });

        let err = validate_remote_deploy_payload(&payload).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("stack_code"));
    }

    #[test]
    fn test_persist_remote_payload_snapshot_writes_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let payload = serde_json::json!({
            "provider": "htz",
            "region": "nbg1",
            "server": "cpx11",
            "os": "ubuntu-22.04",
            "commonDomain": "localhost",
            "stack_code": "demo-stack",
            "selected_plan": "free",
            "payment_type": "subscription",
            "subscriptions": []
        });

        let path = persist_remote_payload_snapshot(dir.path(), &payload).unwrap();
        assert!(path.exists());

        let raw = std::fs::read_to_string(path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(parsed.get("provider").and_then(|v| v.as_str()), Some("htz"));
    }

    fn sample_server_config() -> StackerConfig {
        ConfigBuilder::new()
            .name("test-server-app")
            .deploy_target(DeployTarget::Server)
            .server(ServerConfig {
                host: "192.168.1.100".to_string(),
                user: "deploy".to_string(),
                ssh_key: Some(PathBuf::from("/home/user/.ssh/id_rsa")),
                port: 22,
            })
            .build()
            .unwrap()
    }

    fn sample_context(dry_run: bool) -> DeployContext {
        DeployContext {
            config_path: PathBuf::from("/project/stacker.yml"),
            compose_path: PathBuf::from("/project/docker-compose.yml"),
            project_dir: PathBuf::from("/project"),
            dry_run,
            image: None,
            project_name_override: None,
            key_name_override: None,
            key_id_override: None,
            server_name_override: None,
            runtime: "runc".to_string(),
            config_bundle: None,
            managed_proxy_feature_enabled: true,
            force_new: false,
        }
    }

    // ── Phase 6 tests ───────────────────────────────

    #[test]
    fn test_build_run_command_with_cloud_config() {
        let config = sample_cloud_config();
        let context = sample_context(false);
        let cmd = InstallContainerCommand::from_config(&config, &context, InstallAction::Apply);
        let args = args_as_string(&cmd.build_args());

        assert!(args.contains("-v /project/stacker.yml:/app/stacker.yml"));
        assert!(args.contains("-v /project/docker-compose.yml:/app/docker-compose.yml"));
        assert!(args.contains("-e CLOUD_PROVIDER=hetzner"));
        assert!(args.contains("-e CLOUD_REGION=fsn1"));
        assert!(args.contains("-e PROJECT_NAME=test-cloud-app"));
    }

    #[test]
    fn test_run_command_mounts_stacker_yml() {
        let config = sample_cloud_config();
        let context = sample_context(false);
        let cmd = InstallContainerCommand::from_config(&config, &context, InstallAction::Apply);
        let args = cmd.build_args();

        let mount_idx = args.iter().position(|a| a == "-v").unwrap();
        let mount_val = &args[mount_idx + 1];
        assert!(mount_val.contains("stacker.yml:/app/stacker.yml"));
    }

    #[test]
    fn test_run_command_mounts_ssh_key() {
        let config = sample_cloud_config();
        let context = sample_context(false);
        let cmd = InstallContainerCommand::from_config(&config, &context, InstallAction::Apply);
        let args = args_as_string(&cmd.build_args());

        assert!(args.contains("-v /home/user/.ssh/id_ed25519:/root/.ssh/id_rsa"));
    }

    #[test]
    fn test_resolve_ssh_key_path_expands_tilde_with_explicit_home() {
        let resolved = resolve_ssh_key_path_with_home(
            Path::new("~/.ssh/website-deploy-key"),
            Some(Path::new("/tmp/test-home")),
        );

        assert_eq!(
            resolved,
            PathBuf::from("/tmp/test-home/.ssh/website-deploy-key")
        );
    }

    #[test]
    fn test_resolve_ssh_key_path_keeps_absolute_path() {
        let resolved = resolve_ssh_key_path_with_home(
            Path::new("/var/keys/website-deploy-key"),
            Some(Path::new("/tmp/test-home")),
        );

        assert_eq!(resolved, PathBuf::from("/var/keys/website-deploy-key"));
    }

    #[test]
    fn test_run_command_plan_mode() {
        let config = sample_cloud_config();
        let context = sample_context(true);
        let cmd = InstallContainerCommand::from_config(&config, &context, InstallAction::Plan);
        let args = cmd.build_args();

        let last = args.last().unwrap();
        assert_eq!(last, "plan");
        assert!(!args.contains(&"apply".to_string()));
    }

    #[test]
    fn test_run_command_apply_mode() {
        let config = sample_cloud_config();
        let context = sample_context(false);
        let cmd = InstallContainerCommand::from_config(&config, &context, InstallAction::Apply);
        let args = cmd.build_args();

        let last = args.last().unwrap();
        assert_eq!(last, "apply");
        assert!(!args.contains(&"plan".to_string()));
    }

    #[test]
    fn test_install_container_image_tag() {
        let cmd = InstallContainerCommand::new(None);
        let args = cmd.build_args();

        assert!(args.contains(&DEFAULT_INSTALL_IMAGE.to_string()));
    }

    // ── Additional tests ────────────────────────────

    #[test]
    fn test_install_container_custom_image() {
        let cmd = InstallContainerCommand::new(Some("custom/installer:v2"));
        let args = cmd.build_args();

        assert!(args.contains(&"custom/installer:v2".to_string()));
        assert!(!args.contains(&DEFAULT_INSTALL_IMAGE.to_string()));
    }

    #[test]
    fn test_deploy_context_default_image() {
        let ctx = sample_context(false);
        assert_eq!(ctx.install_image(), DEFAULT_INSTALL_IMAGE);
    }

    #[test]
    fn test_deploy_context_custom_image() {
        let ctx = DeployContext {
            config_path: PathBuf::from("/p/stacker.yml"),
            compose_path: PathBuf::from("/p/docker-compose.yml"),
            project_dir: PathBuf::from("/p"),
            dry_run: false,
            image: Some("mycompany/install:v3".to_string()),
            project_name_override: None,
            key_name_override: None,
            key_id_override: None,
            server_name_override: None,
            runtime: "runc".to_string(),
            config_bundle: None,
            managed_proxy_feature_enabled: true,
            force_new: false,
        };
        assert_eq!(ctx.install_image(), "mycompany/install:v3");
    }

    #[test]
    fn test_should_run_managed_proxy_preflight_skips_force_new_cloud() {
        let mut ctx = sample_context(false);
        ctx.force_new = true;

        assert!(!should_run_managed_proxy_preflight(
            &ctx,
            DeployTarget::Cloud
        ));
        assert!(should_run_managed_proxy_preflight(
            &ctx,
            DeployTarget::Server
        ));
    }

    #[test]
    fn test_local_deploy_dry_run() {
        let config = ConfigBuilder::new().name("local-app").build().unwrap();
        let context = sample_context(true);
        let executor = MockExecutor::success();
        let strategy = LocalDeploy;

        let result = strategy.deploy(&config, &context, &executor).unwrap();
        assert_eq!(result.target, DeployTarget::Local);
        assert!(
            result.message.contains("dry-run") || result.message.contains("previewed"),
            "dry-run message should indicate preview, got: {}",
            result.message
        );

        // Dry-run should NOT invoke docker at all (no compose call)
        let recorded = executor.recorded_calls.lock().unwrap();
        // Only the compose-version probe may have been called (from resolve_compose_cmd),
        // but the actual compose up/config should NOT be called.
        assert!(
            !recorded
                .iter()
                .any(|(_, args)| args.contains(&"up".to_string())),
            "dry-run must not call docker compose up"
        );
        assert!(
            !recorded
                .iter()
                .any(|(_, args)| args.contains(&"config".to_string())),
            "dry-run must not call docker compose config"
        );
    }

    #[test]
    fn test_local_deploy_apply() {
        let config = ConfigBuilder::new().name("local-app").build().unwrap();
        let context = sample_context(false);
        let executor = MockExecutor::success();
        let strategy = LocalDeploy;

        let result = strategy.deploy(&config, &context, &executor).unwrap();
        assert_eq!(result.target, DeployTarget::Local);
        assert!(result.message.contains("started"));

        let args = executor.last_args();
        assert!(args.contains(&"up".to_string()));
        assert!(args.contains(&"-d".to_string()));
        assert!(args.contains(&"--build".to_string()));
    }

    #[test]
    fn test_local_deploy_failure() {
        let config = ConfigBuilder::new().name("local-app").build().unwrap();
        let context = sample_context(false);
        let executor = MockExecutor::failure("service failed to start");
        let strategy = LocalDeploy;

        let result = strategy.deploy(&config, &context, &executor);
        assert!(result.is_err());
    }

    #[test]
    fn test_local_destroy() {
        let config = ConfigBuilder::new().name("local-app").build().unwrap();
        let context = sample_context(false);
        let executor = MockExecutor::success();
        let strategy = LocalDeploy;

        strategy.destroy(&config, &context, &executor).unwrap();

        let args = executor.last_args();
        assert!(args.contains(&"down".to_string()));
        assert!(args.contains(&"--volumes".to_string()));
    }

    #[test]
    fn test_local_deploy_uses_env_file_when_configured() {
        let config = ConfigBuilder::new()
            .name("local-app")
            .env_file(".env")
            .build()
            .unwrap();
        let context = sample_context(false); // real deploy, not dry-run
        let executor = MockExecutor::success();
        let strategy = LocalDeploy;

        strategy.deploy(&config, &context, &executor).unwrap();

        let args = executor.last_args();
        assert!(args.contains(&"--env-file".to_string()));
        assert!(args.contains(&"/project/.env".to_string()));
    }

    #[test]
    fn test_cloud_deploy_validates_provider() {
        let config = ConfigBuilder::new().name("no-cloud").build().unwrap();
        let strategy = CloudDeploy;
        let result = strategy.validate(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_cloud_deploy_has_provider_passes() {
        let config = sample_cloud_config();
        let strategy = CloudDeploy;
        assert!(strategy.validate(&config).is_ok());
    }

    #[test]
    fn test_normalize_stacker_server_url_strips_api_v1_suffix() {
        assert_eq!(
            normalize_stacker_server_url("https://stacker.example.com/api/v1"),
            "https://stacker.example.com"
        );
        assert_eq!(
            normalize_stacker_server_url("https://stacker.example.com/api/v1/"),
            "https://stacker.example.com"
        );
    }

    #[test]
    fn test_normalize_stacker_server_url_strips_direct_login_suffix() {
        assert_eq!(
            normalize_stacker_server_url("https://dev.try.direct/server/user/auth/login"),
            "https://dev.try.direct/server/user"
        );
    }

    #[test]
    fn test_normalize_stacker_server_url_preserves_legacy_stacker_route() {
        assert_eq!(
            normalize_stacker_server_url("https://dev.try.direct/stacker"),
            "https://dev.try.direct/stacker"
        );
    }

    #[test]
    fn test_normalize_stacker_server_url_preserves_api_gateway_host() {
        assert_eq!(
            normalize_stacker_server_url("https://api.try.direct"),
            "https://api.try.direct"
        );
    }

    #[test]
    fn test_resolve_saved_stacker_base_url_prefers_saved_server_url() {
        let creds = StoredCredentials {
            access_token: "token".to_string(),
            refresh_token: None,
            token_type: "Bearer".to_string(),
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(10),
            email: Some("user@example.com".to_string()),
            server_url: Some("https://dev.try.direct/stacker".to_string()),
            org: None,
            domain: None,
        };

        assert_eq!(
            resolve_saved_stacker_base_url(&creds),
            "https://dev.try.direct/stacker"
        );
    }

    #[test]
    fn test_resolve_saved_stacker_base_url_falls_back_to_default() {
        let creds = StoredCredentials {
            access_token: "token".to_string(),
            refresh_token: None,
            token_type: "Bearer".to_string(),
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(10),
            email: Some("user@example.com".to_string()),
            server_url: None,
            org: None,
            domain: None,
        };

        assert_eq!(
            resolve_saved_stacker_base_url(&creds),
            stacker_client::DEFAULT_STACKER_URL
        );
    }

    #[test]
    fn test_ensure_remote_cloud_credentials_available_accepts_saved_cloud_id() {
        let env_creds = serde_json::Map::new();
        assert!(ensure_remote_cloud_credentials_available(Some(12), "htz", &env_creds).is_ok());
    }

    #[test]
    fn test_ensure_remote_cloud_credentials_available_accepts_env_token() {
        let mut env_creds = serde_json::Map::new();
        env_creds.insert(
            "cloud_token".to_string(),
            serde_json::Value::String("token".to_string()),
        );
        assert!(ensure_remote_cloud_credentials_available(None, "htz", &env_creds).is_ok());
    }

    #[test]
    fn test_ensure_remote_cloud_credentials_available_fails_without_saved_or_env_creds() {
        let env_creds = serde_json::Map::new();
        let err = ensure_remote_cloud_credentials_available(None, "htz", &env_creds).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("No saved cloud credentials were found"));
        assert!(msg.contains("HCLOUD_TOKEN"));
    }

    #[test]
    fn test_canonicalize_registry_server_maps_docker_hub_urls_to_docker_io() {
        assert_eq!(
            canonicalize_registry_server("https://index.docker.io/v1/".to_string()),
            "docker.io"
        );
        assert_eq!(
            canonicalize_registry_server("https://registry-1.docker.io".to_string()),
            "docker.io"
        );
        assert_eq!(
            canonicalize_registry_server("hub.docker.com".to_string()),
            "docker.io"
        );
    }

    #[test]
    fn test_resolve_docker_registry_credentials_defaults_to_docker_io_when_auth_present() {
        let config = ConfigBuilder::new()
            .name("private-app")
            .registry(RegistryConfig {
                username: Some("syncopia-user".to_string()),
                password: Some("secret".to_string()),
                server: None,
            })
            .build()
            .unwrap();

        let creds = resolve_docker_registry_credentials(&config);
        assert_eq!(
            creds.get("docker_username").and_then(|v| v.as_str()),
            Some("syncopia-user")
        );
        assert_eq!(
            creds.get("docker_password").and_then(|v| v.as_str()),
            Some("secret")
        );
        assert_eq!(
            creds.get("docker_registry").and_then(|v| v.as_str()),
            Some("docker.io")
        );
    }

    #[test]
    fn test_cloud_deploy_runs_install_container() {
        let config = sample_cloud_config();
        let context = sample_context(false);
        let executor = MockExecutor::success();
        let strategy = CloudDeploy;

        let result = strategy.deploy(&config, &context, &executor).unwrap();
        assert_eq!(result.target, DeployTarget::Cloud);

        let (program, args) = executor.last_call();
        assert_eq!(program, "docker");
        assert!(args.contains(&"run".to_string()));
        assert!(args.contains(&DEFAULT_INSTALL_IMAGE.to_string()));
        assert!(args.contains(&"apply".to_string()));
    }

    #[test]
    fn test_cloud_deploy_dry_run_uses_plan() {
        let config = sample_cloud_config();
        let context = sample_context(true);
        let executor = MockExecutor::success();
        let strategy = CloudDeploy;

        strategy.deploy(&config, &context, &executor).unwrap();

        let args = executor.last_args();
        assert!(args.contains(&"plan".to_string()));
        assert!(!args.contains(&"apply".to_string()));
    }

    #[test]
    fn test_server_deploy_validates_host() {
        let config = ConfigBuilder::new().name("no-server").build().unwrap();
        let strategy = ServerDeploy;
        let result = strategy.validate(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_server_deploy_has_host_passes() {
        let config = sample_server_config();
        let strategy = ServerDeploy;
        assert!(strategy.validate(&config).is_ok());
    }

    #[test]
    fn test_server_deploy_sets_env_vars() {
        let config = sample_server_config();
        let context = sample_context(false);
        let cmd = InstallContainerCommand::from_config(&config, &context, InstallAction::Apply);
        let args = args_as_string(&cmd.build_args());

        assert!(args.contains("-e SERVER_HOST=192.168.1.100"));
        assert!(args.contains("-e SERVER_USER=deploy"));
        assert!(args.contains("-e SERVER_PORT=22"));
    }

    #[test]
    fn test_extract_server_ip_from_terraform_output() {
        let stdout = "Apply complete!\n\nOutputs:\n\nserver_ip = \"203.0.113.42\"\n";
        assert_eq!(extract_server_ip(stdout), Some("203.0.113.42".to_string()));
    }

    #[test]
    fn test_extract_server_ip_public_ip() {
        let stdout = "public_ip = 10.0.0.5\n";
        assert_eq!(extract_server_ip(stdout), Some("10.0.0.5".to_string()));
    }

    #[test]
    fn test_extract_server_ip_none() {
        assert_eq!(extract_server_ip("no ip here"), None);
    }

    #[test]
    fn test_strategy_for_factory() {
        // Verify the factory returns something for each variant (no panic).
        let _ = strategy_for(&DeployTarget::Local);
        let _ = strategy_for(&DeployTarget::Cloud);
        let _ = strategy_for(&DeployTarget::Server);
    }

    #[test]
    fn test_install_action_as_str() {
        assert_eq!(InstallAction::Plan.as_str(), "plan");
        assert_eq!(InstallAction::Apply.as_str(), "apply");
        assert_eq!(InstallAction::Destroy.as_str(), "destroy");
    }

    #[test]
    fn test_command_output_success() {
        let output = CommandOutput {
            exit_code: 0,
            stdout: "ok".to_string(),
            stderr: String::new(),
        };
        assert!(output.success());

        let output = CommandOutput {
            exit_code: 1,
            stdout: String::new(),
            stderr: "fail".to_string(),
        };
        assert!(!output.success());
    }

    #[test]
    fn test_install_command_remove_after_default() {
        let cmd = InstallContainerCommand::new(None);
        let args = cmd.build_args();
        assert!(args.contains(&"--rm".to_string()));
    }

    #[test]
    fn test_install_command_no_remove() {
        let cmd = InstallContainerCommand::new(None).remove_after(false);
        let args = cmd.build_args();
        assert!(!args.contains(&"--rm".to_string()));
    }
}
