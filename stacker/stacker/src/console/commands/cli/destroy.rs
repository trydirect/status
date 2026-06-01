use std::path::Path;

use crate::cli::config_parser::DeployTarget;
use crate::cli::error::CliError;
use crate::cli::install_runner::{CommandExecutor, ShellExecutor};
use crate::cli::local_compose::resolve_local_compose_path;
use crate::console::commands::CallableTrait;

#[allow(dead_code)]
const DEFAULT_CONFIG_FILE: &str = "stacker.yml";

/// `stacker destroy [--volumes] [--confirm]`
///
/// Tears down the deployed stack and optionally removes volumes.
pub struct DestroyCommand {
    pub volumes: bool,
    pub confirm: bool,
}

impl DestroyCommand {
    pub fn new(volumes: bool, confirm: bool) -> Self {
        Self { volumes, confirm }
    }
}

/// Build `docker compose down` arguments.
pub fn build_destroy_args(compose_path: &str, volumes: bool) -> Vec<String> {
    let mut args = vec![
        "compose".to_string(),
        "-f".to_string(),
        compose_path.to_string(),
        "down".to_string(),
    ];

    if volumes {
        args.push("--volumes".to_string());
    }

    args
}

/// Core destroy logic, extracted for testability.
pub fn run_destroy(
    project_dir: &Path,
    volumes: bool,
    confirm: bool,
    executor: &dyn CommandExecutor,
) -> Result<(), CliError> {
    if !confirm {
        return Err(CliError::ConfigValidation(
            "Destroy requires --confirm (-y) flag. This will remove all containers and data."
                .to_string(),
        ));
    }

    let compose_path = resolve_local_compose_path(project_dir).map_err(|err| match err {
        CliError::ConfigValidation(_) => {
            CliError::ConfigValidation("No deployment found. Nothing to destroy.".to_string())
        }
        other => other,
    })?;

    let compose_str = compose_path.to_string_lossy().to_string();
    let args = build_destroy_args(&compose_str, volumes);
    let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

    let output = executor.execute("docker", &args_refs)?;

    if !output.success() {
        return Err(CliError::DeployFailed {
            target: DeployTarget::Local,
            reason: format!("docker compose down failed: {}", output.stderr.trim()),
        });
    }

    Ok(())
}

impl CallableTrait for DestroyCommand {
    fn call(&self) -> Result<(), Box<dyn std::error::Error>> {
        let project_dir = std::env::current_dir()?;
        let executor = ShellExecutor;

        run_destroy(&project_dir, self.volumes, self.confirm, &executor)?;
        eprintln!("✓ Stack destroyed successfully");

        Ok(())
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::install_runner::CommandOutput;
    use std::sync::Mutex;

    struct MockExecutor {
        calls: Mutex<Vec<(String, Vec<String>)>>,
    }

    impl MockExecutor {
        fn new() -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
            }
        }

        fn recorded_calls(&self) -> Vec<(String, Vec<String>)> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl CommandExecutor for MockExecutor {
        fn execute(&self, program: &str, args: &[&str]) -> Result<CommandOutput, CliError> {
            self.calls.lock().unwrap().push((
                program.to_string(),
                args.iter().map(|s| s.to_string()).collect(),
            ));
            Ok(CommandOutput {
                exit_code: 0,
                stdout: String::new(),
                stderr: String::new(),
            })
        }
    }

    fn setup_with_compose() -> tempfile::TempDir {
        let dir = tempfile::TempDir::new().unwrap();
        let stacker_dir = dir.path().join(".stacker");
        std::fs::create_dir_all(&stacker_dir).unwrap();
        std::fs::write(stacker_dir.join("docker-compose.yml"), "version: '3.8'\n").unwrap();
        dir
    }

    #[test]
    fn test_destroy_constructs_down_command() {
        let dir = setup_with_compose();
        let executor = MockExecutor::new();

        run_destroy(dir.path(), false, true, &executor).unwrap();

        let calls = executor.recorded_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "docker");
        assert!(calls[0].1.contains(&"down".to_string()));
    }

    #[test]
    fn test_destroy_with_volumes_flag() {
        let args = build_destroy_args("/path/compose.yml", true);
        assert!(args.contains(&"--volumes".to_string()));
    }

    #[test]
    fn test_destroy_requires_confirmation() {
        let dir = setup_with_compose();
        let executor = MockExecutor::new();

        let result = run_destroy(dir.path(), false, false, &executor);
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("confirm") || err.contains("Destroy"));
    }

    #[test]
    fn test_destroy_no_deployment_returns_error() {
        let dir = tempfile::TempDir::new().unwrap();
        let executor = MockExecutor::new();

        let result = run_destroy(dir.path(), false, true, &executor);
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("No deployment found") || err.contains("Nothing to destroy"));
    }

    #[test]
    fn test_destroy_uses_configured_compose_file_for_local_target() {
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

        let executor = MockExecutor::new();
        run_destroy(dir.path(), false, true, &executor).unwrap();

        let calls = executor.recorded_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0].1[2],
            dir.path()
                .join("docker/local/compose.yml")
                .to_string_lossy()
        );
    }
}
