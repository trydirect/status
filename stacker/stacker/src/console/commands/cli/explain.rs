use std::path::{Path, PathBuf};

use crate::cli::config_parser::{ServiceDefinition, StackerConfig};
use crate::cli::error::CliError;
use crate::console::commands::CallableTrait;
use crate::helpers::{remote_runtime_compose_path, remote_runtime_env_path};
use crate::services::config_renderer::EnvRenderInput;
use crate::services::{
    build_explain_env, build_explain_topology, ExplainTopologyService, TypedErrorEnvelope,
};

const DEFAULT_CONFIG_FILE: &str = "stacker.yml";

pub struct ExplainEnvCommand {
    pub app: String,
    pub json: bool,
}

impl ExplainEnvCommand {
    pub fn new(app: String, json: bool) -> Self {
        Self { app, json }
    }
}

pub struct ExplainTopologyCommand {
    pub json: bool,
}

impl ExplainTopologyCommand {
    pub fn new(json: bool) -> Self {
        Self { json }
    }
}

fn load_config(project_dir: &Path) -> Result<StackerConfig, CliError> {
    StackerConfig::from_file(&project_dir.join(DEFAULT_CONFIG_FILE))?
        .with_resolved_deploy_target(None)
}

fn resolve_local_env_path(project_dir: &Path, config: &StackerConfig) -> Result<PathBuf, CliError> {
    let env_file = config
        .resolve_environment_config(None)?
        .and_then(|(_, env)| env.env_file)
        .or_else(|| config.env_file.clone())
        .unwrap_or_else(|| PathBuf::from(".env"));
    Ok(if env_file.is_absolute() {
        env_file
    } else {
        project_dir.join(env_file)
    })
}

fn resolve_local_compose_path(
    project_dir: &Path,
    config: &StackerConfig,
) -> Result<PathBuf, CliError> {
    let compose_file = config
        .resolve_environment_config(None)?
        .and_then(|(_, env)| env.compose_file)
        .or_else(|| config.deploy.compose_file.clone())
        .unwrap_or_else(|| PathBuf::from(".stacker/docker-compose.yml"));
    Ok(if compose_file.is_absolute() {
        compose_file
    } else {
        project_dir.join(compose_file)
    })
}

fn main_app_code(config: &StackerConfig) -> String {
    config
        .project
        .identity
        .clone()
        .unwrap_or_else(|| "app".to_string())
}

fn resolve_service<'a>(
    config: &'a StackerConfig,
    app_code: &str,
) -> Result<Option<&'a ServiceDefinition>, CliError> {
    if app_code == "app" || app_code == main_app_code(config) {
        return Ok(None);
    }

    config
        .services
        .iter()
        .find(|service| service.name == app_code)
        .map(Some)
        .ok_or_else(|| {
            TypedErrorEnvelope::invalid_request(format!(
                "App or service '{app_code}' was not found in stacker.yml"
            ))
            .with_context("appCode", app_code)
            .into()
        })
}

fn build_env_input(config: &StackerConfig, app_code: &str) -> Result<EnvRenderInput, CliError> {
    let service = resolve_service(config, app_code)?;
    let mut input = EnvRenderInput {
        base: config.env.clone(),
        ..EnvRenderInput::default()
    };
    if let Some(service) = service {
        input.service = service.environment.clone();
    } else {
        input.service = config.app.environment.clone();
    }
    Ok(input)
}

fn print_json<T: serde::Serialize>(value: &T) -> Result<(), CliError> {
    let rendered = serde_json::to_string_pretty(value).map_err(|err| {
        CliError::ConfigValidation(format!("Failed to serialize explain output: {err}"))
    })?;
    println!("{rendered}");
    Ok(())
}

impl CallableTrait for ExplainEnvCommand {
    fn call(&self) -> Result<(), Box<dyn std::error::Error>> {
        let project_dir = std::env::current_dir()?;
        let config = load_config(&project_dir)?;
        let deployment_hash = config
            .deploy
            .deployment_hash
            .clone()
            .unwrap_or_else(|| "unbound".to_string());
        let local_env_path = resolve_local_env_path(&project_dir, &config)?;
        let explain = build_explain_env(
            &deployment_hash,
            &self.app,
            &local_env_path.to_string_lossy(),
            remote_runtime_env_path(),
            remote_runtime_compose_path(),
            build_env_input(&config, &self.app)?,
        )
        .map_err(|err| CliError::ConfigValidation(err.to_string()))?;

        if self.json {
            print_json(&explain)?;
        } else {
            println!("Explain env for {}", explain.app_code);
            println!(
                "  local authoring env: {}",
                explain.local_authoring_env_path
            );
            println!("  runtime env:         {}", explain.runtime_env_path);
            println!("  runtime compose:     {}", explain.runtime_compose_path);
        }

        Ok(())
    }
}

impl CallableTrait for ExplainTopologyCommand {
    fn call(&self) -> Result<(), Box<dyn std::error::Error>> {
        let project_dir = std::env::current_dir()?;
        let config = load_config(&project_dir)?;
        let deployment_hash = config
            .deploy
            .deployment_hash
            .clone()
            .unwrap_or_else(|| "unbound".to_string());
        let local_env_path = resolve_local_env_path(&project_dir, &config)?;
        let local_compose_path = resolve_local_compose_path(&project_dir, &config)?;

        let mut services = vec![ExplainTopologyService {
            code: main_app_code(&config),
            name: config.name.clone(),
            enabled: true,
        }];
        services.extend(
            config
                .services
                .iter()
                .map(|service| ExplainTopologyService {
                    code: service.name.clone(),
                    name: service.name.clone(),
                    enabled: true,
                }),
        );

        let topology = build_explain_topology(
            &deployment_hash,
            &config.deploy.target.to_string(),
            &local_compose_path.to_string_lossy(),
            remote_runtime_compose_path(),
            &local_env_path.to_string_lossy(),
            remote_runtime_env_path(),
            services,
        );

        if self.json {
            print_json(&topology)?;
        } else {
            println!("Explain topology for {}", topology.deployment_hash);
            println!("  local compose:  {}", topology.local_compose_path);
            println!("  runtime compose: {}", topology.runtime_compose_path);
            println!("  local env:      {}", topology.local_authoring_env_path);
            println!("  runtime env:    {}", topology.runtime_env_path);
        }

        Ok(())
    }
}
