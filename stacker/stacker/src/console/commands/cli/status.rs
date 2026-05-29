use std::path::Path;

use crate::cli::config_parser::{CloudOrchestrator, DeployTarget, ProxyType, StackerConfig};
use crate::cli::credentials::{CredentialsManager, StoredCredentials};
use crate::cli::error::CliError;
use crate::cli::install_runner::{CommandExecutor, CommandOutput, ShellExecutor};
use crate::cli::local_compose::resolve_local_compose_path;
use crate::cli::stacker_client::{self, DeploymentStatusInfo, ServerInfo, StackerClient};
use crate::console::commands::CallableTrait;

const DEFAULT_CONFIG_FILE: &str = "stacker.yml";

/// `stacker status [--json] [--watch]`
///
/// Shows the current deployment status.
///
/// - **Local deployments**: runs `docker compose ps` for container status.
/// - **Cloud deployments**: queries the Stacker server API for deployment
///   progress (pending → in_progress → completed / failed).
///   When `--watch` is used, polls every 5 seconds until a terminal status.
pub struct StatusCommand {
    pub json: bool,
    pub watch: bool,
}

impl StatusCommand {
    pub fn new(json: bool, watch: bool) -> Self {
        Self { json, watch }
    }
}

/// Build `docker compose ps` arguments.
pub fn build_status_args(compose_path: &str, json: bool) -> Vec<String> {
    let mut args = vec![
        "compose".to_string(),
        "-f".to_string(),
        compose_path.to_string(),
        "ps".to_string(),
    ];

    if json {
        args.push("--format".to_string());
        args.push("json".to_string());
    }

    args
}

/// Core status logic for **local** deployments, extracted for testability.
pub fn run_status(
    project_dir: &Path,
    json: bool,
    executor: &dyn CommandExecutor,
) -> Result<CommandOutput, CliError> {
    let compose_path = resolve_local_compose_path(project_dir)?;

    let compose_str = compose_path.to_string_lossy().to_string();
    let args = build_status_args(&compose_str, json);
    let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

    let output = executor.execute("docker", &args_refs)?;
    Ok(output)
}

// ── Cloud deployment status ─────────────────────────

/// Terminal statuses — once reached, `--watch` stops polling.
const TERMINAL_STATUSES: &[&str] = &["completed", "failed", "cancelled", "error", "paused"];

/// Check if a status is terminal (deployment finished or failed).
fn is_terminal(status: &str) -> bool {
    TERMINAL_STATUSES.iter().any(|s| *s == status)
}

/// Context for rendering a rich deployment report.
struct StatusContext<'a> {
    server: Option<&'a ServerInfo>,
    config: Option<&'a StackerConfig>,
    live_containers: Option<&'a [serde_json::Value]>,
}

/// Pretty-print a deployment status with optional server/config context.
fn print_deployment_status_rich(info: &DeploymentStatusInfo, json: bool, ctx: &StatusContext<'_>) {
    if json {
        if let Ok(j) = serde_json::to_string_pretty(info) {
            println!("{}", j);
        }
        return;
    }

    let status_icon = match info.status.as_str() {
        "completed" => "✓",
        "failed" | "error" | "cancelled" => "✗",
        "in_progress" => "⟳",
        "pending" | "wait_start" => "◷",
        "paused" | "wait_resume" => "⏸",
        "confirmed" => "✓",
        _ => "?",
    };

    // ── Header ──────────────────────────────────
    println!(
        "\n{} Deployment #{} — status: {}",
        status_icon, info.id, info.status
    );
    if let Some(ref msg) = info.status_message {
        println!("  Message:         {}", msg);
    }
    println!("  Project ID:      {}", info.project_id);
    println!("  Deployment hash: {}", info.deployment_hash);
    println!("  Created:         {}", info.created_at);
    println!("  Updated:         {}", info.updated_at);

    // Only show the rich details for terminal (completed/failed) statuses
    if !is_terminal(&info.status) {
        return;
    }

    // ── Server info ─────────────────────────────
    if let Some(srv) = ctx.server {
        println!("\n── Server ─────────────────────────────────");
        if let Some(ref name) = srv.name {
            println!("  Name:            {}", name);
        }
        if let Some(ref ip) = srv.srv_ip {
            println!("  IP:              {}", ip);
            let ssh_user = srv.ssh_user.as_deref().unwrap_or("root");
            let ssh_port = srv.ssh_port.unwrap_or(22);
            if ssh_port == 22 {
                println!("  SSH:             ssh {}@{}", ssh_user, ip);
            } else {
                println!("  SSH:             ssh -p {} {}@{}", ssh_port, ssh_user, ip);
            }
        }
        if let Some(ref cloud) = srv.cloud {
            println!("  Cloud:           {}", cloud);
        }
        if let Some(ref region) = srv.region {
            println!("  Region:          {}", region);
        }
    }

    if let Some(containers) = ctx.live_containers {
        if !containers.is_empty() {
            println!("\n── Live Containers ────────────────────────");
            println!("  {:<24} {:<12} {:<30}", "CONTAINER", "STATE", "IMAGE");
            for c in containers {
                let name = c.get("name").and_then(|v| v.as_str()).unwrap_or("-");
                let state = c
                    .get("state")
                    .or_else(|| c.get("status"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("-");
                let image = c.get("image").and_then(|v| v.as_str()).unwrap_or("-");
                println!("  {:<24} {:<12} {:<30}", name, state, image);
            }
        }
    }

    // ── Deployed apps / domains ─────────────────
    if let Some(config) = ctx.config {
        let srv_ip = ctx.server.and_then(|s| s.srv_ip.as_deref());

        // Services
        if !config.services.is_empty() {
            println!("\n── Services ───────────────────────────────");
            for svc in &config.services {
                let ports_str = if svc.ports.is_empty() {
                    String::new()
                } else {
                    format!(" (ports: {})", svc.ports.join(", "))
                };
                println!("  • {}{}", svc.name, ports_str);
            }
        }

        // Proxy / domains
        if config.proxy.proxy_type != ProxyType::None {
            println!("\n── Proxy ──────────────────────────────────");
            println!("  Type:            {}", config.proxy.proxy_type);

            if !config.proxy.domains.is_empty() {
                println!("\n── App URLs ───────────────────────────────");
                for d in &config.proxy.domains {
                    let scheme = match d.ssl {
                        crate::cli::config_parser::SslMode::Off => "http",
                        _ => "https",
                    };
                    println!("  • {}://{} → {}", scheme, d.domain, d.upstream);
                }
            }

            // Nginx Proxy Manager admin panel
            if matches!(
                config.proxy.proxy_type,
                ProxyType::Nginx | ProxyType::NginxProxyManager
            ) {
                if let Some(ip) = srv_ip {
                    println!("\n── Nginx Proxy Manager ────────────────────");
                    println!("  Admin panel:     http://{}:81", ip);
                    println!("  Default login:   admin@example.com / changeme");
                }
            }
        }

        // ── Next steps ──────────────────────────────
        if info.status == "completed" {
            println!("\n── Next Steps ─────────────────────────────");
            println!("  • Check service health:   stacker status --watch");
            println!("  • View logs:              stacker logs");
            if config.proxy.proxy_type != ProxyType::None && !config.proxy.domains.is_empty() {
                println!("  • Manage proxy:           stacker proxy");
            }
            println!(
                "  • Redeploy:               stacker deploy --target {}",
                config.deploy.target
            );
            println!("\n── Documentation ──────────────────────────");
            println!("  https://try.direct/docs");
        }
    }

    println!();
}

/// Resolve the project name from stacker.yml (same logic as deploy).
pub(crate) fn resolve_project_name(config: &StackerConfig) -> String {
    config
        .project
        .identity
        .clone()
        .unwrap_or_else(|| config.name.clone())
}

pub(crate) fn resolve_stacker_base_url(creds: &StoredCredentials) -> String {
    creds
        .server_url
        .as_deref()
        .map(crate::cli::install_runner::normalize_stacker_server_url)
        .unwrap_or_else(|| stacker_client::DEFAULT_STACKER_URL.to_string())
}

pub(crate) fn missing_remote_project_reason(
    project_name: &str,
    base_url: &str,
    deploy_target: DeployTarget,
) -> String {
    format!(
        "Project '{}' was not found on Stacker API {}. If this stack exists in another \
environment, run `stacker whoami` to verify the active Stacker API or re-login with \
`stacker login --auth-url <user-service-url> --api-url <stacker-api-url>`. If it has \
not been deployed there yet, run `stacker deploy --target {}`.",
        project_name, base_url, deploy_target
    )
}

fn snapshot_containers(snapshot: &serde_json::Value) -> Vec<serde_json::Value> {
    snapshot
        .get("containers")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
}

fn containers_signature(containers: &[serde_json::Value]) -> String {
    serde_json::to_string(containers).unwrap_or_default()
}

/// Query remote deployment status from the Stacker server, optionally watching.
fn run_remote_status(json: bool, watch: bool) -> Result<(), Box<dyn std::error::Error>> {
    // Load stacker.yml to find project name
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
    let deploy_target = config.deploy.target;

    // Load credentials
    let cred_manager = CredentialsManager::with_default_store();
    let creds = cred_manager.require_valid_token("deployment status")?;

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

        if let Some(deployment_hash) = config.deploy.deployment_hash.as_ref() {
            if !deployment_hash.trim().is_empty() {
                let ctx = StatusContext {
                    server: None,
                    config: Some(&config),
                    live_containers: None,
                };
                if !watch {
                    let status = client.get_deployment_by_hash(deployment_hash).await?;
                    match status {
                        Some(info) => {
                            print_deployment_status_rich(&info, json, &ctx);
                            return Ok(());
                        }
                        None => {
                            eprintln!("No deployment found for hash '{}'", deployment_hash);
                            return Ok(());
                        }
                    }
                }

                eprintln!(
                    "Watching deployment status for hash '{}'...\n",
                    deployment_hash
                );
                let poll_interval = std::time::Duration::from_secs(5);
                let mut last_status = String::new();
                let mut last_message: Option<String> = None;
                let mut last_containers = String::new();

                loop {
                    let status = client.get_deployment_by_hash(deployment_hash).await?;

                    match status {
                        Some(info) => {
                            let live_containers = if info.status == "completed" {
                                client
                                    .agent_snapshot_by_project(info.project_id)
                                    .await
                                    .ok()
                                    .map(|(snapshot, _)| snapshot_containers(&snapshot))
                                    .unwrap_or_default()
                            } else {
                                Vec::new()
                            };
                            let container_sig = containers_signature(&live_containers);
                            let status_changed = info.status != last_status;
                            let message_changed = info.status_message != last_message;
                            let containers_changed = container_sig != last_containers;
                            if status_changed || message_changed || containers_changed {
                                let ctx = StatusContext {
                                    server: None,
                                    config: Some(&config),
                                    live_containers: (!live_containers.is_empty())
                                        .then_some(live_containers.as_slice()),
                                };
                                print_deployment_status_rich(&info, json, &ctx);
                                last_status = info.status.clone();
                                last_message = info.status_message.clone();
                                last_containers = container_sig;
                            }

                            if is_terminal(&info.status) {
                                if !json {
                                    eprintln!(
                                        "\nDeployment reached terminal status: {}",
                                        info.status
                                    );
                                }
                                return Ok(());
                            }
                        }
                        None => {
                            if last_status.is_empty() {
                                eprintln!("No deployment found yet. Waiting...");
                                last_status = "<none>".to_string();
                            }
                        }
                    }

                    tokio::time::sleep(poll_interval).await;
                }
            }
        }

        // Resolve project ID by name
        let project = client.find_project_by_name(&project_name).await?;
        let project = project.ok_or_else(|| CliError::DeployFailed {
            target: deploy_target,
            reason: missing_remote_project_reason(&project_name, &base_url, deploy_target),
        })?;

        // Fetch server info for this project (best-effort)
        let server: Option<ServerInfo> = client
            .list_servers()
            .await
            .ok()
            .and_then(|servers| servers.into_iter().find(|s| s.project_id == project.id));

        if !watch {
            // Single query
            let status = client.get_deployment_status_by_project(project.id).await?;
            match status {
                Some(info) => {
                    let live_containers = client
                        .agent_snapshot_by_project(project.id)
                        .await
                        .ok()
                        .map(|(snapshot, _)| snapshot_containers(&snapshot))
                        .unwrap_or_default();
                    let ctx = StatusContext {
                        server: server.as_ref(),
                        config: Some(&config),
                        live_containers: (!live_containers.is_empty())
                            .then_some(live_containers.as_slice()),
                    };
                    print_deployment_status_rich(&info, json, &ctx);
                    Ok(())
                }
                None => {
                    eprintln!(
                        "No deployments found for project '{}' (id={})",
                        project_name, project.id
                    );
                    Ok(())
                }
            }
        } else {
            // Watch mode — poll every 5 seconds
            eprintln!(
                "Watching deployment status for project '{}' (id={})...\n",
                project_name, project.id
            );

            let poll_interval = std::time::Duration::from_secs(5);
            let mut last_status = String::new();
            let mut last_message: Option<String> = None;
            let mut last_containers = String::new();

            loop {
                let status = client.get_deployment_status_by_project(project.id).await?;

                match status {
                    Some(info) => {
                        let live_containers = client
                            .agent_snapshot_by_project(project.id)
                            .await
                            .ok()
                            .map(|(snapshot, _)| snapshot_containers(&snapshot))
                            .unwrap_or_default();
                        let container_sig = containers_signature(&live_containers);
                        let status_changed = info.status != last_status;
                        let message_changed = info.status_message != last_message;
                        let containers_changed = container_sig != last_containers;
                        if status_changed || message_changed || containers_changed {
                            let ctx = StatusContext {
                                server: server.as_ref(),
                                config: Some(&config),
                                live_containers: (!live_containers.is_empty())
                                    .then_some(live_containers.as_slice()),
                            };
                            print_deployment_status_rich(&info, json, &ctx);
                            last_status = info.status.clone();
                            last_message = info.status_message.clone();
                            last_containers = container_sig;
                        }

                        if is_terminal(&info.status) {
                            if !json {
                                eprintln!("\nDeployment reached terminal status: {}", info.status);
                            }
                            return Ok(());
                        }
                    }
                    None => {
                        if last_status.is_empty() {
                            eprintln!("No deployments found yet. Waiting...");
                            last_status = "<none>".to_string();
                        }
                    }
                }

                tokio::time::sleep(poll_interval).await;
            }
        }
    })
}

/// Detect whether the project is configured for a remote (cloud/server) deployment.
pub(crate) fn is_remote_deployment(project_dir: &Path) -> bool {
    if let Ok(Some(lock)) = crate::cli::deployment_lock::DeploymentLock::load(project_dir) {
        if lock.deployment_id.is_some() || lock.target != "local" {
            return true;
        }
    }

    let config_path = project_dir.join(DEFAULT_CONFIG_FILE);
    if !config_path.exists() {
        return false;
    }

    let config = match StackerConfig::from_file(&config_path)
        .and_then(|config| config.with_resolved_deploy_target(None))
    {
        Ok(config) => config,
        Err(_) => return false,
    };

    // Remote if target is Cloud/Server, or if remote orchestrator is configured
    if matches!(
        config.deploy.target,
        DeployTarget::Cloud | DeployTarget::Server
    ) {
        return true;
    }

    if let Some(cloud_cfg) = &config.deploy.cloud {
        if cloud_cfg.orchestrator == CloudOrchestrator::Remote {
            return true;
        }
    }

    false
}

impl CallableTrait for StatusCommand {
    fn call(&self) -> Result<(), Box<dyn std::error::Error>> {
        let project_dir = std::env::current_dir()?;

        if is_remote_deployment(&project_dir) {
            // Remote deployment — query Stacker server
            run_remote_status(self.json, self.watch)?;
        } else {
            // Local deployment — docker compose ps
            let executor = ShellExecutor;
            let output = run_status(&project_dir, self.json, &executor)?;
            print!("{}", output.stdout);

            if self.watch {
                eprintln!("Note: --watch is only supported for cloud deployments.");
            }
        }

        Ok(())
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::deployment_lock::DeploymentLock;
    use chrono::{Duration, Utc};

    #[test]
    fn test_status_local_constructs_query() {
        let args = build_status_args("/path/compose.yml", false);
        assert_eq!(args, vec!["compose", "-f", "/path/compose.yml", "ps"]);
    }

    #[test]
    fn test_status_json_flag() {
        let args = build_status_args("/path/compose.yml", true);
        assert!(args.contains(&"--format".to_string()));
        assert!(args.contains(&"json".to_string()));
    }

    #[test]
    fn test_status_no_deployment_returns_error() {
        struct MockExec;
        impl CommandExecutor for MockExec {
            fn execute(&self, _p: &str, _a: &[&str]) -> Result<CommandOutput, CliError> {
                Ok(CommandOutput {
                    exit_code: 0,
                    stdout: String::new(),
                    stderr: String::new(),
                })
            }
        }

        let dir = tempfile::TempDir::new().unwrap();
        let result = run_status(dir.path(), false, &MockExec);
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("No deployment found"));
    }

    #[test]
    fn test_status_uses_configured_compose_file_for_local_target() {
        struct MockExec {
            calls: std::sync::Mutex<Vec<Vec<String>>>,
        }

        impl CommandExecutor for MockExec {
            fn execute(&self, _p: &str, args: &[&str]) -> Result<CommandOutput, CliError> {
                self.calls
                    .lock()
                    .unwrap()
                    .push(args.iter().map(|arg| arg.to_string()).collect());
                Ok(CommandOutput {
                    exit_code: 0,
                    stdout: String::new(),
                    stderr: String::new(),
                })
            }
        }

        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("docker/local")).unwrap();
        std::fs::write(
            dir.path().join("docker/local/compose.yml"),
            "services: {}\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join(DEFAULT_CONFIG_FILE),
            "name: demo\ndeploy:\n  target: local\n  compose_file: docker/local/compose.yml\n",
        )
        .unwrap();

        let executor = MockExec {
            calls: std::sync::Mutex::new(Vec::new()),
        };

        run_status(dir.path(), false, &executor).unwrap();

        let calls = executor.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0][2],
            dir.path()
                .join("docker/local/compose.yml")
                .to_string_lossy()
        );
    }

    #[test]
    fn test_is_terminal_status() {
        assert!(is_terminal("completed"));
        assert!(is_terminal("failed"));
        assert!(is_terminal("cancelled"));
        assert!(is_terminal("error"));
        assert!(is_terminal("paused"));
        assert!(!is_terminal("pending"));
        assert!(!is_terminal("in_progress"));
        assert!(!is_terminal("wait_start"));
    }

    #[test]
    fn test_is_remote_deployment_no_config() {
        let dir = tempfile::TempDir::new().unwrap();
        assert!(!is_remote_deployment(dir.path()));
    }

    #[test]
    fn test_is_remote_deployment_for_server_target_config() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join(DEFAULT_CONFIG_FILE),
            "name: demo\ndeploy:\n  target: server\n  server:\n    host: 203.0.113.10\n    user: root\n    port: 22\n",
        )
        .unwrap();

        assert!(is_remote_deployment(dir.path()));
    }

    #[test]
    fn test_is_remote_deployment_for_named_server_target_config() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join(DEFAULT_CONFIG_FILE),
            r#"name: demo
app:
  type: static
deploy:
  default_target: prod
  targets:
    local:
      compose_file: docker/local/compose.yml
    prod:
      server:
        host: 10.0.0.8
        user: deploy
        ssh_key: ~/.ssh/id_ed25519
"#,
        )
        .unwrap();

        assert!(is_remote_deployment(dir.path()));
    }

    #[test]
    fn test_is_remote_deployment_for_hydrated_lock() {
        let dir = tempfile::TempDir::new().unwrap();
        DeploymentLock {
            target: "cloud".to_string(),
            server_ip: Some("203.0.113.10".to_string()),
            ssh_user: Some("root".to_string()),
            ssh_port: Some(22),
            server_name: Some("demo".to_string()),
            deployment_id: Some(42),
            project_id: Some(7),
            cloud_id: Some(9),
            project_name: Some("demo".to_string()),
            stacker_email: Some("owner@example.com".to_string()),
            deployed_at: Utc::now().to_rfc3339(),
        }
        .save(dir.path())
        .unwrap();

        assert!(is_remote_deployment(dir.path()));
    }

    #[test]
    fn test_resolve_stacker_base_url_prefers_hydrated_server_url() {
        let creds = StoredCredentials {
            access_token: "token".to_string(),
            refresh_token: None,
            token_type: "Bearer".to_string(),
            expires_at: Utc::now() + Duration::minutes(10),
            email: None,
            server_url: Some("https://custom.stacker.example".to_string()),
            org: None,
            domain: None,
        };

        assert_eq!(
            resolve_stacker_base_url(&creds),
            "https://custom.stacker.example"
        );
    }

    #[test]
    fn test_resolve_stacker_base_url_normalizes_api_v1_suffix() {
        let creds = StoredCredentials {
            access_token: "token".to_string(),
            refresh_token: None,
            token_type: "Bearer".to_string(),
            expires_at: Utc::now() + Duration::minutes(10),
            email: None,
            server_url: Some("https://custom.stacker.example/api/v1".to_string()),
            org: None,
            domain: None,
        };

        assert_eq!(
            resolve_stacker_base_url(&creds),
            "https://custom.stacker.example"
        );
    }

    #[test]
    fn test_resolve_stacker_base_url_preserves_legacy_stacker_route() {
        let creds = StoredCredentials {
            access_token: "token".to_string(),
            refresh_token: None,
            token_type: "Bearer".to_string(),
            expires_at: Utc::now() + Duration::minutes(10),
            email: None,
            server_url: Some("https://dev.try.direct/stacker".to_string()),
            org: None,
            domain: None,
        };

        assert_eq!(
            resolve_stacker_base_url(&creds),
            "https://dev.try.direct/stacker"
        );
    }

    #[test]
    fn test_resolve_stacker_base_url_preserves_api_gateway_host() {
        let creds = StoredCredentials {
            access_token: "token".to_string(),
            refresh_token: None,
            token_type: "Bearer".to_string(),
            expires_at: Utc::now() + Duration::minutes(10),
            email: None,
            server_url: Some("https://api.try.direct".to_string()),
            org: None,
            domain: None,
        };

        assert_eq!(resolve_stacker_base_url(&creds), "https://api.try.direct");
    }

    #[test]
    fn test_missing_remote_project_reason_mentions_active_stacker_api() {
        let reason = missing_remote_project_reason(
            "coolify",
            "https://stacker.try.direct",
            DeployTarget::Cloud,
        );

        assert!(reason.contains("Project 'coolify' was not found"));
        assert!(reason.contains("https://stacker.try.direct"));
        assert!(reason.contains("stacker whoami"));
        assert!(reason.contains("stacker login"));
        assert!(reason.contains("stacker deploy --target cloud"));
    }

    #[test]
    fn test_missing_remote_project_reason_uses_server_target_when_requested() {
        let reason = missing_remote_project_reason(
            "coolify",
            "https://dev.try.direct/stacker",
            DeployTarget::Server,
        );

        assert!(reason.contains("https://dev.try.direct/stacker"));
        assert!(reason.contains("stacker deploy --target server"));
    }
}
