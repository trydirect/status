use std::path::{Path, PathBuf};

use crate::cli::config_parser::{DeployTarget, StackerConfig};
use crate::cli::error::CliError;

const OUTPUT_DIR: &str = ".stacker";
const DEFAULT_CONFIG_FILE: &str = "stacker.yml";

pub fn resolve_local_compose_path(project_dir: &Path) -> Result<PathBuf, CliError> {
    let generated = project_dir.join(OUTPUT_DIR).join("docker-compose.yml");
    let config_path = project_dir.join(DEFAULT_CONFIG_FILE);
    let mut selected_non_local_target = false;

    if config_path.exists() {
        if let Ok(config) = StackerConfig::from_file(&config_path) {
            if let Ok(config) = config.with_resolved_deploy_target(None) {
                selected_non_local_target = config.deploy.target != DeployTarget::Local;

                if config.deploy.target == DeployTarget::Local {
                    if let Some(compose_file) = config.deploy.compose_file {
                        let resolved = if compose_file.is_absolute() {
                            compose_file
                        } else {
                            project_dir.join(compose_file)
                        };
                        if resolved.exists() {
                            return Ok(resolved);
                        }
                    }
                }
            }
        }
    }

    if selected_non_local_target {
        return Err(CliError::ConfigValidation(
            "The selected deploy target is not local, so no local docker-compose file is available."
                .to_string(),
        ));
    }

    if generated.exists() {
        return Ok(generated);
    }

    Err(CliError::ConfigValidation(
        "No deployment found. Run 'stacker deploy' first.".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_local_compose_path_prefers_configured_compose_file() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("docker/local")).unwrap();
        std::fs::create_dir_all(dir.path().join(".stacker")).unwrap();
        std::fs::write(
            dir.path().join("docker/local/compose.yml"),
            "services: {}\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join(".stacker/docker-compose.yml"),
            "services: {}\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("stacker.yml"),
            "name: demo\ndeploy:\n  target: local\n  compose_file: docker/local/compose.yml\n",
        )
        .unwrap();

        let resolved = resolve_local_compose_path(dir.path()).unwrap();
        assert_eq!(resolved, dir.path().join("docker/local/compose.yml"));
    }

    #[test]
    fn test_resolve_local_compose_path_falls_back_to_generated_compose() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join(".stacker")).unwrap();
        std::fs::write(
            dir.path().join(".stacker/docker-compose.yml"),
            "services: {}\n",
        )
        .unwrap();

        let resolved = resolve_local_compose_path(dir.path()).unwrap();
        assert_eq!(resolved, dir.path().join(".stacker/docker-compose.yml"));
    }

    #[test]
    fn test_resolve_local_compose_path_rejects_remote_default_target() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join(".stacker")).unwrap();
        std::fs::write(
            dir.path().join(".stacker/docker-compose.yml"),
            "services: {}\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("stacker.yml"),
            "name: demo\ndeploy:\n  default_target: prod\n  targets:\n    local:\n      compose_file: docker/local/compose.yml\n    prod:\n      server:\n        host: 10.0.0.8\n        user: deploy\n        ssh_key: ~/.ssh/id_ed25519\n",
        )
        .unwrap();

        assert!(resolve_local_compose_path(dir.path()).is_err());
    }
}
