use std::fmt::Write as _;
use std::path::Path;

use crate::cli::error::CliError;
use crate::cli::install_runner::{CommandExecutor, CommandOutput, ShellExecutor};
use crate::cli::local_compose::resolve_local_compose_path;
use crate::console::commands::CallableTrait;

const DEFAULT_CONFIG_FILE: &str = "stacker.yml";

/// `stacker logs [--service <name>] [--follow] [--tail <n>] [--since <duration>]`
///
/// Shows container logs for the deployed stack.
///
/// - **Local deployments**: delegates to `docker compose logs`.
/// - **Remote deployments**: fetches logs from the Status Panel agent via the
///   Stacker server API (same as `stacker agent logs`).
pub struct LogsCommand {
    pub service: Option<String>,
    pub follow: bool,
    pub tail: Option<u32>,
    pub since: Option<String>,
}

impl LogsCommand {
    pub fn new(
        service: Option<String>,
        follow: bool,
        tail: Option<u32>,
        since: Option<String>,
    ) -> Self {
        Self {
            service,
            follow,
            tail,
            since,
        }
    }
}

/// Build the `docker compose logs` argument list.
pub fn build_logs_args(
    compose_path: &str,
    service: Option<&str>,
    follow: bool,
    tail: Option<u32>,
    since: Option<&str>,
) -> Vec<String> {
    let mut args = vec![
        "compose".to_string(),
        "-f".to_string(),
        compose_path.to_string(),
        "logs".to_string(),
    ];

    if follow {
        args.push("-f".to_string());
    }

    if let Some(n) = tail {
        args.push("--tail".to_string());
        args.push(n.to_string());
    }

    if let Some(s) = since {
        args.push("--since".to_string());
        args.push(s.to_string());
    }

    if let Some(svc) = service {
        args.push(svc.to_string());
    }

    args
}

/// Core logic, extracted for testability.
pub fn run_logs(
    project_dir: &Path,
    service: Option<&str>,
    follow: bool,
    tail: Option<u32>,
    since: Option<&str>,
    executor: &dyn CommandExecutor,
) -> Result<CommandOutput, CliError> {
    let compose_path = resolve_local_compose_path(project_dir)?;

    let compose_str = compose_path.to_string_lossy().to_string();
    let args = build_logs_args(&compose_str, service, follow, tail, since);
    let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

    let output = executor.execute("docker", &args_refs)?;
    Ok(output)
}

impl CallableTrait for LogsCommand {
    fn call(&self) -> Result<(), Box<dyn std::error::Error>> {
        let project_dir = std::env::current_dir()?;

        // Try local first — use the same compose resolution logic as local deploy/status.
        if resolve_local_compose_path(&project_dir).is_ok() {
            let executor = ShellExecutor;
            let output = run_logs(
                &project_dir,
                self.service.as_deref(),
                self.follow,
                self.tail,
                self.since.as_deref(),
                &executor,
            )?;

            print!("{}", output.stdout);
            if !output.stderr.is_empty() {
                eprint!("{}", output.stderr);
            }
            return Ok(());
        }

        // No local compose — try remote agent logs
        if is_remote_deployment(&project_dir) {
            return run_remote_logs(self.service.as_deref(), self.tail);
        }

        // Neither local nor remote
        Err(Box::new(CliError::ConfigValidation(
            "No deployment found. Run 'stacker deploy' first.".to_string(),
        )))
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Remote (agent) logs
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

use crate::cli::config_parser::{CloudOrchestrator, DeployTarget, StackerConfig};
use crate::cli::fmt;
use crate::cli::progress;
use crate::cli::runtime::CliRuntime;
use crate::cli::stacker_client::{AgentCommandInfo, AgentEnqueueRequest};

/// Default poll timeout for agent commands (seconds).
const REMOTE_TIMEOUT_SECS: u64 = 60;

/// Default poll interval (seconds).
const REMOTE_POLL_INTERVAL_SECS: u64 = 2;

/// Detect whether the project has a remote (cloud/server) deployment.
fn is_remote_deployment(project_dir: &Path) -> bool {
    // 1. Deployment lock with a deployment_id → remote
    if let Ok(Some(lock)) = crate::cli::deployment_lock::DeploymentLock::load(project_dir) {
        if lock.deployment_id.is_some() {
            return true;
        }
        // Lock exists but with target != "local" → server deploy
        if lock.target != "local" {
            return true;
        }
    }

    // 2. stacker.yml declares cloud/server target
    let config_path = project_dir.join(DEFAULT_CONFIG_FILE);
    if let Ok(config) = StackerConfig::from_file(&config_path)
        .and_then(|config| config.with_resolved_deploy_target(None))
    {
        if config.deploy.target == DeployTarget::Cloud {
            return true;
        }
        if let Some(cloud_cfg) = &config.deploy.cloud {
            if cloud_cfg.orchestrator == CloudOrchestrator::Remote {
                return true;
            }
        }
    }

    false
}

/// Resolve the deployment hash for remote logs, same logic as agent commands.
fn resolve_deployment_hash(ctx: &CliRuntime) -> Result<String, CliError> {
    let project_dir = std::env::current_dir().map_err(CliError::Io)?;

    // 1. Deployment lock
    if let Some(lock) = crate::cli::deployment_lock::DeploymentLock::load(&project_dir)? {
        if let Some(dep_id) = lock.deployment_id {
            let info = ctx.block_on(ctx.client.get_deployment_status(dep_id as i32))?;
            if let Some(info) = info {
                return Ok(info.deployment_hash);
            }
        }
    }

    // 2. stacker.yml explicit deployment hash
    let config_path = project_dir.join(DEFAULT_CONFIG_FILE);
    if config_path.exists() {
        if let Ok(config) = crate::cli::config_parser::StackerConfig::from_file(&config_path)
            .and_then(|config| config.with_resolved_deploy_target(None))
        {
            if let Some(hash) = config.deploy.deployment_hash.as_ref() {
                if !hash.trim().is_empty() {
                    return Ok(hash.clone());
                }
            }

            // 3. stacker.yml project → active agent (most recent heartbeat)
            if let Some(ref project_name) = config.project.identity {
                let project = ctx.block_on(ctx.client.find_project_by_name(project_name))?;
                if let Some(proj) = project {
                    match ctx.block_on(ctx.client.agent_snapshot_by_project(proj.id)) {
                        Ok((_, hash)) => {
                            eprintln!(
                                "\x1b[2mℹ No --deployment specified — using active agent for project '{}': {}\x1b[0m",
                                project_name, hash
                            );
                            return Ok(hash);
                        }
                        Err(_) => {}
                    }
                }
            }
        }
    }

    Err(CliError::ConfigValidation(
        "Cannot determine deployment hash.\n\
         Use 'stacker agent logs <app>' with --deployment <HASH>, \
         or run from a directory with a deployment lock or stacker.yml."
            .to_string(),
    ))
}

/// Fetch logs from the remote agent, optionally for a single service.
///
/// If no `--service` is specified, fetches a snapshot to discover running
/// containers and fetches logs for all of them.
fn run_remote_logs(
    service: Option<&str>,
    tail: Option<u32>,
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = CliRuntime::new("remote logs")?;
    let hash = resolve_deployment_hash(&ctx)?;

    let limit = tail.map(|n| n as i32).unwrap_or(200);

    // Determine which app codes to fetch logs for.
    let app_codes: Vec<String> = if let Some(svc) = service {
        vec![svc.to_string()]
    } else {
        // Fetch snapshot to discover all running containers
        let pb = progress::spinner("Discovering containers");
        match ctx.block_on(ctx.client.agent_snapshot(&hash)) {
            Ok(snap) => {
                progress::finish_success(&pb, "Containers discovered");
                snap.get("containers")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|c| c.get("name").and_then(|n| n.as_str()))
                            .map(|s| s.to_string())
                            .collect()
                    })
                    .unwrap_or_default()
            }
            Err(e) => {
                progress::finish_error(&pb, &format!("Could not discover containers: {}", e));
                return Err(Box::new(e));
            }
        }
    };

    if app_codes.is_empty() {
        let (summary, tip) = no_containers_messages(&hash);
        eprintln!("{}", summary);
        eprintln!("{}", tip);
        return Ok(());
    }

    // Fetch logs for each container
    for app_code in &app_codes {
        let params = crate::forms::status_panel::LogsCommandRequest {
            app_code: app_code.clone(),
            container: None,
            cursor: None,
            limit,
            streams: vec!["stdout".to_string(), "stderr".to_string()],
            redact: true,
        };

        let request = AgentEnqueueRequest::new(&hash, "logs")
            .with_parameters(&params)
            .map_err(|e| CliError::ConfigValidation(format!("Invalid parameters: {}", e)))?;

        let spinner_msg = format!("Fetching logs for {}", app_code);
        let info = run_remote_agent_command(&ctx, &request, &spinner_msg, REMOTE_TIMEOUT_SECS)?;

        print_logs_result(app_code, &info, app_codes.len() > 1);
    }

    Ok(())
}

fn no_containers_messages(hash: &str) -> (String, String) {
    let mut summary = String::new();
    let mut tip = String::new();
    let _ = write!(&mut summary, "No containers found for deployment {}.", hash);
    let _ = write!(
        &mut tip,
        "Tip: use 'stacker agent status --deployment {}' to check the deployment.",
        hash
    );
    (summary, tip)
}

/// Execute an agent command with spinner and polling.
fn run_remote_agent_command(
    ctx: &CliRuntime,
    request: &AgentEnqueueRequest,
    spinner_msg: &str,
    timeout: u64,
) -> Result<AgentCommandInfo, CliError> {
    let pb = progress::spinner(spinner_msg);

    let result = ctx.block_on(async {
        let info = ctx.client.agent_enqueue(request).await?;
        let command_id = info.command_id.clone();
        let deployment_hash = request.deployment_hash.clone();

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(timeout);
        let interval = std::time::Duration::from_secs(REMOTE_POLL_INTERVAL_SECS);

        let mut last_status = "pending".to_string();

        loop {
            tokio::time::sleep(interval).await;

            if tokio::time::Instant::now() >= deadline {
                return Err(CliError::AgentCommandTimeout {
                    command_id: command_id.clone(),
                    command_type: spinner_msg.to_string(),
                    last_status,
                    deployment_hash,
                });
            }

            let status = ctx
                .client
                .agent_command_status(&deployment_hash, &command_id)
                .await?;

            last_status = status.status.clone();
            progress::update_message(&pb, &format!("{} [{}]", spinner_msg, status.status));

            match status.status.as_str() {
                "completed" | "failed" => return Ok(status),
                _ => continue,
            }
        }
    });

    match &result {
        Ok(info) if info.status == "completed" => {
            progress::finish_success(&pb, &format!("{} ✓", spinner_msg));
        }
        Ok(info) => {
            progress::finish_error(&pb, &format!("{} — {}", spinner_msg, info.status));
        }
        Err(e) => {
            let short_msg = if matches!(e, CliError::AgentCommandTimeout { .. }) {
                format!("{} — timed out", spinner_msg)
            } else {
                format!("{} — {}", spinner_msg, e)
            };
            progress::finish_error(&pb, &short_msg);
        }
    }

    result
}

/// Pretty-print agent log results.
fn print_logs_result(app_code: &str, info: &AgentCommandInfo, multi: bool) {
    if multi {
        println!("\n{}", fmt::separator(60));
        println!("── {} ──", app_code);
    }

    if info.status == "failed" {
        if let Some(ref error) = info.error {
            eprintln!(
                "Error fetching logs for {}: {}",
                app_code,
                fmt::pretty_json(error)
            );
        }
        return;
    }

    if let Some(ref result) = info.result {
        // Try to extract log lines from the result JSON
        if let Some(logs) = result.get("logs").and_then(|v| v.as_str()) {
            print!("{}", logs);
        } else if let Some(lines) = result.get("lines").and_then(|v| v.as_array()) {
            for line in lines {
                if let Some(s) = line.as_str() {
                    println!("{}", s);
                }
            }
        } else if let Some(output) = result.get("output").and_then(|v| v.as_str()) {
            print!("{}", output);
        } else {
            // Fallback: pretty-print the whole result
            println!("{}", fmt::pretty_json(result));
        }
    } else {
        println!("(no log output)");
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Tests
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::deployment_lock::DeploymentLock;
    use chrono::Utc;

    #[test]
    fn test_logs_constructs_compose_command() {
        let args = build_logs_args("/path/compose.yml", None, false, None, None);
        assert_eq!(args, vec!["compose", "-f", "/path/compose.yml", "logs"]);
    }

    #[test]
    fn test_logs_with_service_filter() {
        let args = build_logs_args("/path/compose.yml", Some("postgres"), false, None, None);
        assert!(args.contains(&"postgres".to_string()));
    }

    #[test]
    fn test_logs_with_follow() {
        let args = build_logs_args("/path/compose.yml", None, true, None, None);
        assert!(args.contains(&"-f".to_string()));
    }

    #[test]
    fn test_logs_with_tail() {
        let args = build_logs_args("/path/compose.yml", None, false, Some(100), None);
        assert!(args.contains(&"--tail".to_string()));
        assert!(args.contains(&"100".to_string()));
    }

    #[test]
    fn test_logs_with_since() {
        let args = build_logs_args("/path/compose.yml", None, false, None, Some("1h"));
        assert!(args.contains(&"--since".to_string()));
        assert!(args.contains(&"1h".to_string()));
    }

    #[test]
    fn test_logs_no_deployment_returns_error() {
        use crate::cli::install_runner::CommandOutput;

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
        let result = run_logs(dir.path(), None, false, None, None, &MockExec);
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("No deployment found") || err.contains("deploy"));
    }

    #[test]
    fn test_logs_uses_configured_compose_file_for_local_target() {
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

        run_logs(dir.path(), None, false, None, None, &executor).unwrap();

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
    fn test_no_containers_messages_use_full_hash() {
        let hash = "deployment_5cc15f7d-8c87-464a-a7c5-ee6116201f22";
        let (summary, tip) = no_containers_messages(hash);

        assert!(summary.contains(hash));
        assert!(tip.contains(hash));
        assert!(!summary.contains("deployme."));
    }

    #[test]
    fn test_is_remote_deployment_for_hydrated_handoff_lock() {
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
    fn test_is_remote_deployment_for_named_cloud_target_config() {
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
      cloud:
        provider: aws
"#,
        )
        .unwrap();

        assert!(is_remote_deployment(dir.path()));
    }
}
