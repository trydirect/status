use std::collections::BTreeSet;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::cli::cloud_env;
use crate::cli::config_check::{check_inventory, load_check, ConfigCheckItem, ConfigCheckResult};
use crate::cli::config_contract::{suggest_contract_yaml, ContractSuggestOptions};
use crate::cli::config_diff::{diff_inventories, load_diff, ConfigDiff, DiffItem};
use crate::cli::config_inventory::{
    load_inventory, merge_remote_secret_names, ConfigInventory, InventoryOptions,
};
use crate::cli::config_parser::{
    AiProviderType, CloudConfig, CloudOrchestrator, CloudProvider, DeployTarget, ServerConfig,
    StackerConfig,
};
use crate::cli::config_promote::{
    load_promotion_plan, promotion_plan_from_diff, ConfigPromotionPlan,
};
use crate::cli::debug::cli_debug_enabled;
use crate::cli::deployment_lock::DeploymentLock;
use crate::cli::error::CliError;
use crate::cli::runtime::CliRuntime;
use crate::cli::stacker_client::ProjectAppInfo;
use crate::console::commands::cli::init::full_config_reference_example;
use crate::console::commands::CallableTrait;
use crate::helpers::env_path::{compose_env_file_reference, remote_runtime_env_path};
use crate::services::runtime_env_contract_response;

const DEFAULT_CONFIG_FILE: &str = "stacker.yml";

#[derive(Debug, Clone, PartialEq, Eq)]
enum RawPathIssueKind {
    Empty,
    NonString(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RawPathIssue {
    field: String,
    kind: RawPathIssueKind,
}

/// Resolve config path from optional override.
fn resolve_config_path(file: &Option<String>) -> String {
    file.as_deref().unwrap_or(DEFAULT_CONFIG_FILE).to_string()
}

fn is_path_like_field(field: &str) -> bool {
    matches!(
        field,
        "path"
            | "dockerfile"
            | "config"
            | "compose_file"
            | "remote_payload_file"
            | "ssh_key"
            | "pre_build"
            | "post_deploy"
            | "on_failure"
            | "env_file"
    )
}

fn yaml_value_kind(value: &serde_yaml::Value) -> &'static str {
    match value {
        serde_yaml::Value::Null => "empty",
        serde_yaml::Value::Bool(_) => "boolean",
        serde_yaml::Value::Number(_) => "number",
        serde_yaml::Value::String(_) => "string",
        serde_yaml::Value::Sequence(_) => "sequence",
        serde_yaml::Value::Mapping(_) => "map",
        serde_yaml::Value::Tagged(_) => "tagged value",
    }
}

fn collect_raw_path_issues(
    value: &serde_yaml::Value,
    prefix: Option<&str>,
    issues: &mut Vec<RawPathIssue>,
) {
    if let serde_yaml::Value::Mapping(map) = value {
        for (key, child) in map {
            let Some(key_str) = key.as_str() else {
                continue;
            };

            let field = match prefix {
                Some(parent) if !parent.is_empty() => format!("{parent}.{key_str}"),
                _ => key_str.to_string(),
            };

            if is_path_like_field(key_str) {
                match child {
                    serde_yaml::Value::Null => issues.push(RawPathIssue {
                        field: field.clone(),
                        kind: RawPathIssueKind::Empty,
                    }),
                    serde_yaml::Value::String(_) => {}
                    other => issues.push(RawPathIssue {
                        field: field.clone(),
                        kind: RawPathIssueKind::NonString(yaml_value_kind(other)),
                    }),
                }
            }

            collect_raw_path_issues(child, Some(&field), issues);
        }
    }
}

fn load_raw_path_issues(path: &Path) -> Result<Vec<RawPathIssue>, CliError> {
    let raw = std::fs::read_to_string(path)?;
    let parsed: serde_yaml::Value = serde_yaml::from_str(&raw)?;
    let mut issues = Vec::new();
    collect_raw_path_issues(&parsed, None, &mut issues);
    Ok(issues)
}

fn remove_empty_path_fields(
    value: &mut serde_yaml::Value,
    prefix: Option<&str>,
    applied: &mut Vec<String>,
) {
    if let serde_yaml::Value::Mapping(map) = value {
        let keys_to_remove: Vec<serde_yaml::Value> = map
            .iter()
            .filter_map(|(key, child)| {
                let key_str = key.as_str()?;
                if !is_path_like_field(key_str) || !matches!(child, serde_yaml::Value::Null) {
                    return None;
                }

                let field = match prefix {
                    Some(parent) if !parent.is_empty() => format!("{parent}.{key_str}"),
                    _ => key_str.to_string(),
                };
                applied.push(format!("Removed empty path field `{field}`"));
                Some(key.clone())
            })
            .collect();

        for key in keys_to_remove {
            map.remove(&key);
        }

        for (key, child) in map.iter_mut() {
            if let Some(key_str) = key.as_str() {
                let field = match prefix {
                    Some(parent) if !parent.is_empty() => format!("{parent}.{key_str}"),
                    _ => key_str.to_string(),
                };
                remove_empty_path_fields(child, Some(&field), applied);
            }
        }
    }
}

fn try_fix_raw_path_issues(config_path: &str) -> Result<Vec<String>, CliError> {
    let raw = std::fs::read_to_string(config_path)?;
    let mut parsed: serde_yaml::Value = serde_yaml::from_str(&raw)?;
    let mut applied = Vec::new();
    remove_empty_path_fields(&mut parsed, None, &mut applied);

    if applied.is_empty() {
        return Ok(applied);
    }

    let backup_path = format!("{}.bak", config_path);
    std::fs::copy(config_path, &backup_path)?;
    let yaml = serde_yaml::to_string(&parsed)
        .map_err(|e| CliError::ConfigValidation(format!("Failed to serialize config: {}", e)))?;
    std::fs::write(config_path, yaml)?;
    applied.push(format!("Backup written to {}", backup_path));
    Ok(applied)
}

fn render_raw_path_issue(issue: &RawPathIssue) -> String {
    match issue.kind {
        RawPathIssueKind::Empty => format!(
            "`{}` is empty. Remove the key or set it to a quoted path string",
            issue.field
        ),
        RawPathIssueKind::NonString(kind) => format!(
            "`{}` must be a quoted path string, but found {}",
            issue.field, kind
        ),
    }
}

fn prompt_line(prompt: &str) -> Result<String, CliError> {
    print!("{}", prompt);
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

fn prompt_with_default(prompt: &str, default: &str) -> Result<String, CliError> {
    let line = prompt_line(&format!("{} [{}]: ", prompt, default))?;
    if line.is_empty() {
        Ok(default.to_string())
    } else {
        Ok(line)
    }
}

fn parse_cloud_provider(s: &str) -> Result<CloudProvider, CliError> {
    let json = format!("\"{}\"", s.trim().to_lowercase());
    serde_json::from_str::<CloudProvider>(&json).map_err(|_| {
        CliError::ConfigValidation(
            "Invalid cloud provider. Use: hetzner, digitalocean, aws, linode, vultr, contabo"
                .to_string(),
        )
    })
}

fn parse_ai_provider(s: &str) -> Result<AiProviderType, CliError> {
    let json = format!("\"{}\"", s.trim().to_lowercase());
    serde_json::from_str::<AiProviderType>(&json).map_err(|_| {
        CliError::ConfigValidation(
            "Invalid AI provider. Use: openai, anthropic, ollama, custom".to_string(),
        )
    })
}

fn default_region_for_provider(provider: CloudProvider) -> &'static str {
    match provider {
        CloudProvider::Hetzner => "nbg1",
        CloudProvider::Digitalocean => "fra1",
        CloudProvider::Aws => "us-east-1",
        CloudProvider::Linode => "us-east",
        CloudProvider::Vultr => "ewr",
        CloudProvider::Contabo => "EU",
    }
}

fn default_size_for_provider(provider: CloudProvider) -> &'static str {
    match provider {
        CloudProvider::Hetzner => "cx23",
        CloudProvider::Digitalocean => "s-1vcpu-2gb",
        CloudProvider::Aws => "t3.small",
        CloudProvider::Linode => "g6-standard-2",
        CloudProvider::Vultr => "vc2-2c-4gb",
        CloudProvider::Contabo => "V45",
    }
}

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

fn provider_code_for_remote(provider: CloudProvider) -> &'static str {
    match provider {
        CloudProvider::Hetzner => "htz",
        CloudProvider::Digitalocean => "do",
        CloudProvider::Aws => "aws",
        CloudProvider::Linode => "lo",
        CloudProvider::Vultr => "vu",
        CloudProvider::Contabo => "cnt",
    }
}

fn first_non_empty_env(keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        std::env::var(key)
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    })
}

fn resolve_remote_cloud_credentials(
    provider_code: &str,
) -> serde_json::Map<String, serde_json::Value> {
    let mut creds = serde_json::Map::new();

    match provider_code {
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
        _ => {}
    }

    creds
}

pub fn run_generate_remote_payload(
    config_path: &str,
    output: Option<&str>,
) -> Result<Vec<String>, CliError> {
    let path = Path::new(config_path);
    if !path.exists() {
        return Err(CliError::ConfigNotFound {
            path: PathBuf::from(config_path),
        });
    }

    let mut config = StackerConfig::from_file_raw(path)?;
    let config_dir = path.parent().unwrap_or_else(|| Path::new("."));

    let output_path = match output {
        Some(out) => {
            let p = PathBuf::from(out);
            if p.is_absolute() {
                p
            } else {
                config_dir.join(p)
            }
        }
        None => config_dir.join("stacker.remote.deploy.json"),
    };

    let cloud = config.deploy.cloud.clone();
    let provider = cloud
        .as_ref()
        .map(|c| c.provider)
        .unwrap_or(CloudProvider::Hetzner);
    let region = cloud
        .as_ref()
        .and_then(|c| c.region.clone())
        .unwrap_or_else(|| default_region_for_provider(provider).to_string());
    let size = cloud
        .as_ref()
        .and_then(|c| c.size.clone())
        .unwrap_or_else(|| default_size_for_provider(provider).to_string());
    let stack_code = config
        .project
        .identity
        .clone()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "custom-stack".to_string());
    let provider_code = provider_code_for_remote(provider);
    let os = match provider_code {
        "do" => "docker-20-04", // DigitalOcean marketplace image with Docker pre-installed
        "htz" => "docker-ce",   // Hetzner snapshot with Docker CE pre-installed (Ubuntu 24.04)
        _ => "ubuntu-22.04",
    };

    let mut payload = serde_json::json!({
        "provider": provider_code,
        "region": region,
        "server": size,
        "os": os,
        "ssl": "letsencrypt",
        "commonDomain": format!("{}.example.com", sanitize_stack_code(&config.name)),
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
        for (key, value) in resolve_remote_cloud_credentials(provider_code) {
            obj.insert(key, value);
        }
    }

    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let payload_str = serde_json::to_string_pretty(&payload)
        .map_err(|e| CliError::ConfigValidation(format!("Failed to serialize payload: {}", e)))?;
    std::fs::write(&output_path, payload_str)?;

    let remote_payload_file = output_path
        .strip_prefix(config_dir)
        .map(PathBuf::from)
        .unwrap_or_else(|_| output_path.clone());

    let existing_cloud = config.deploy.cloud.clone().unwrap_or(CloudConfig {
        provider,
        orchestrator: CloudOrchestrator::Remote,
        region: Some(default_region_for_provider(provider).to_string()),
        size: Some(default_size_for_provider(provider).to_string()),
        install_image: None,
        remote_payload_file: None,
        ssh_key: None,
        key: None,
        server: None,
    });

    config.deploy.target = DeployTarget::Cloud;
    config.deploy.cloud = Some(CloudConfig {
        provider: existing_cloud.provider,
        orchestrator: CloudOrchestrator::Remote,
        region: existing_cloud.region,
        size: existing_cloud.size,
        install_image: existing_cloud.install_image,
        remote_payload_file: Some(remote_payload_file),
        ssh_key: existing_cloud.ssh_key,
        key: existing_cloud.key,
        server: existing_cloud.server,
    });

    let backup_path = format!("{}.bak", config_path);
    std::fs::copy(config_path, &backup_path)?;
    let yaml = serde_yaml::to_string(&config)
        .map_err(|e| CliError::ConfigValidation(format!("Failed to serialize config: {}", e)))?;
    std::fs::write(config_path, yaml)?;

    Ok(vec![
        format!(
            "Generated remote payload (advanced/debug): {}",
            output_path.display()
        ),
        "Set deploy.target=cloud and deploy.cloud.orchestrator=remote (advanced mode)".to_string(),
        "Tip: regular users can skip this and run `stacker deploy --target cloud` directly"
            .to_string(),
        format!("Backup written to {}", backup_path),
    ])
}

fn apply_cloud_settings(
    config: &mut StackerConfig,
    provider: CloudProvider,
    region: Option<String>,
    size: Option<String>,
    ssh_key: Option<PathBuf>,
) {
    let existing_orchestrator = config
        .deploy
        .cloud
        .as_ref()
        .map(|c| c.orchestrator)
        .unwrap_or(CloudOrchestrator::Remote);
    let existing_install_image = config
        .deploy
        .cloud
        .as_ref()
        .and_then(|c| c.install_image.clone());

    let existing_remote_payload_file = config
        .deploy
        .cloud
        .as_ref()
        .and_then(|c| c.remote_payload_file.clone());

    config.deploy.target = DeployTarget::Cloud;
    config.deploy.cloud = Some(CloudConfig {
        provider,
        orchestrator: existing_orchestrator,
        region,
        size,
        install_image: existing_install_image,
        remote_payload_file: existing_remote_payload_file,
        ssh_key,
        key: None,
        server: None,
    });
}

pub struct AiSetupOptions<'a> {
    pub provider: Option<&'a str>,
    pub endpoint: Option<&'a str>,
    pub model: Option<&'a str>,
    pub timeout: Option<u64>,
    pub tasks: &'a [String],
}

pub fn run_setup_ai(
    config_path: &str,
    options: AiSetupOptions<'_>,
) -> Result<Vec<String>, CliError> {
    let path = Path::new(config_path);
    if !path.exists() {
        return Err(CliError::ConfigNotFound {
            path: PathBuf::from(config_path),
        });
    }

    let mut config = StackerConfig::from_file_raw(path)?;
    let interactive = options.provider.is_none()
        && options.endpoint.is_none()
        && options.model.is_none()
        && options.timeout.is_none()
        && options.tasks.is_empty();

    let provider = if let Some(provider) = options.provider {
        parse_ai_provider(provider)?
    } else if interactive {
        parse_ai_provider(&prompt_with_default(
            "AI provider (openai|anthropic|ollama|custom)",
            &config.ai.provider.to_string(),
        )?)?
    } else {
        AiProviderType::Ollama
    };

    let endpoint = if let Some(endpoint) = options.endpoint {
        Some(endpoint.trim().to_string()).filter(|value| !value.is_empty())
    } else if interactive {
        let default = config
            .ai
            .endpoint
            .clone()
            .unwrap_or_else(|| "http://localhost:11434".to_string());
        Some(prompt_with_default("AI endpoint", &default)?).filter(|value| !value.trim().is_empty())
    } else {
        config.ai.endpoint.clone()
    };

    let model = if let Some(model) = options.model {
        Some(model.trim().to_string()).filter(|value| !value.is_empty())
    } else if interactive {
        let default = config
            .ai
            .model
            .clone()
            .unwrap_or_else(|| "llama3.1".to_string());
        Some(prompt_with_default("AI model", &default)?).filter(|value| !value.trim().is_empty())
    } else {
        config.ai.model.clone()
    };

    let timeout = if let Some(timeout) = options.timeout {
        timeout
    } else if interactive {
        prompt_with_default("AI timeout seconds", &config.ai.timeout.to_string())?
            .parse::<u64>()
            .unwrap_or(config.ai.timeout)
    } else if config.ai.timeout == 0 {
        300
    } else {
        config.ai.timeout
    };

    let tasks = if !options.tasks.is_empty() {
        options
            .tasks
            .iter()
            .flat_map(|task| task.split(','))
            .map(str::trim)
            .filter(|task| !task.is_empty())
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>()
    } else if interactive {
        let default = if config.ai.tasks.is_empty() {
            "dockerfile,compose,troubleshoot".to_string()
        } else {
            config.ai.tasks.join(",")
        };
        prompt_with_default("AI tasks (comma-separated)", &default)?
            .split(',')
            .map(str::trim)
            .filter(|task| !task.is_empty())
            .map(ToOwned::to_owned)
            .collect()
    } else if config.ai.tasks.is_empty() {
        vec![
            "dockerfile".to_string(),
            "compose".to_string(),
            "troubleshoot".to_string(),
        ]
    } else {
        config.ai.tasks.clone()
    };

    config.ai.enabled = true;
    config.ai.provider = provider;
    config.ai.endpoint = endpoint;
    config.ai.model = model;
    config.ai.timeout = timeout;
    config.ai.tasks = tasks;

    let backup_path = format!("{}.bak", config_path);
    std::fs::copy(config_path, &backup_path)?;
    let yaml = serde_yaml::to_string(&config)
        .map_err(|e| CliError::ConfigValidation(format!("Failed to serialize config: {}", e)))?;
    std::fs::write(config_path, yaml)?;

    Ok(vec![
        "Enabled ai configuration".to_string(),
        format!("Set ai.provider={}", config.ai.provider),
        format!("Backup written to {}", backup_path),
    ])
}

pub fn run_setup_cloud_interactive(config_path: &str) -> Result<Vec<String>, CliError> {
    let path = Path::new(config_path);
    if !path.exists() {
        return Err(CliError::ConfigNotFound {
            path: PathBuf::from(config_path),
        });
    }

    let mut config = StackerConfig::from_file_raw(path)?;
    let mut applied = Vec::new();

    eprintln!("Cloud setup wizard:");

    let provider_default = config
        .deploy
        .cloud
        .as_ref()
        .map(|c| c.provider)
        .unwrap_or(CloudProvider::Hetzner);

    let provider_input = prompt_with_default(
        "Cloud provider (hetzner|digitalocean|aws|linode|vultr)",
        &provider_default.to_string(),
    )?;
    let provider = parse_cloud_provider(&provider_input)?;

    let region_default = config
        .deploy
        .cloud
        .as_ref()
        .and_then(|c| c.region.clone())
        .unwrap_or_else(|| default_region_for_provider(provider).to_string());
    let region = prompt_with_default("Cloud region", &region_default)?;

    let size_default = config
        .deploy
        .cloud
        .as_ref()
        .and_then(|c| c.size.clone())
        .unwrap_or_else(|| default_size_for_provider(provider).to_string());
    let size = prompt_with_default("Cloud size", &size_default)?;

    let ssh_key_default = config
        .deploy
        .cloud
        .as_ref()
        .and_then(|c| c.ssh_key.clone())
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|| "~/.ssh/id_rsa".to_string());
    let ssh_key_input =
        prompt_with_default("SSH key path (leave empty to skip)", &ssh_key_default)?;

    let region_opt = if region.trim().is_empty() {
        None
    } else {
        Some(region)
    };
    let size_opt = if size.trim().is_empty() {
        None
    } else {
        Some(size)
    };
    let ssh_key_opt = if ssh_key_input.trim().is_empty() {
        None
    } else {
        Some(PathBuf::from(ssh_key_input))
    };

    apply_cloud_settings(&mut config, provider, region_opt, size_opt, ssh_key_opt);

    let backup_path = format!("{}.bak", config_path);
    std::fs::copy(config_path, &backup_path)?;

    let yaml = serde_yaml::to_string(&config)
        .map_err(|e| CliError::ConfigValidation(format!("Failed to serialize config: {}", e)))?;
    std::fs::write(config_path, yaml)?;

    applied.push("Set deploy.target=cloud and deploy.cloud.*".to_string());
    applied.push(format!("Backup written to {}", backup_path));
    Ok(applied)
}

/// Interactive fixer for common missing required fields.
///
/// Current MVP handles:
/// - E001: missing deploy.cloud.provider
/// - E002: missing deploy.server.host
pub fn run_fix_interactive(config_path: &str) -> Result<Vec<String>, CliError> {
    let path = Path::new(config_path);
    if !path.exists() {
        return Err(CliError::ConfigNotFound {
            path: PathBuf::from(config_path),
        });
    }

    let raw_applied = try_fix_raw_path_issues(config_path)?;
    if !raw_applied.is_empty() {
        return Ok(raw_applied);
    }

    let mut config = match StackerConfig::from_file_raw(path) {
        Ok(config) => config,
        Err(CliError::ConfigParseFailed { .. }) => {
            let issues = load_raw_path_issues(path)?;
            if !issues.is_empty() {
                let details = issues
                    .iter()
                    .map(render_raw_path_issue)
                    .collect::<Vec<_>>()
                    .join("; ");
                return Err(CliError::ConfigValidation(format!(
                    "Cannot auto-fix stacker.yml yet: {details}"
                )));
            }

            return Err(CliError::ConfigValidation(
                "Cannot auto-fix stacker.yml because it contains parse errors outside the supported path-field recovery".to_string(),
            ));
        }
        Err(err) => return Err(err),
    };
    let issues = config.validate_semantics();
    let mut applied = Vec::new();

    if issues.is_empty() {
        return Ok(applied);
    }

    for issue in &issues {
        match issue.code.as_str() {
            "E001" => {
                eprintln!("Detected missing cloud provider settings (E001).");

                let provider_default = config
                    .deploy
                    .cloud
                    .as_ref()
                    .map(|c| c.provider.to_string())
                    .unwrap_or_else(|| "hetzner".to_string());

                let provider_input = prompt_with_default(
                    "Cloud provider (hetzner|digitalocean|aws|linode|vultr)",
                    &provider_default,
                )?;
                let provider = parse_cloud_provider(&provider_input)?;

                let region_default = config
                    .deploy
                    .cloud
                    .as_ref()
                    .and_then(|c| c.region.clone())
                    .unwrap_or_else(|| "nbg1".to_string());
                let region = prompt_with_default("Cloud region", &region_default)?;

                let size_default = config
                    .deploy
                    .cloud
                    .as_ref()
                    .and_then(|c| c.size.clone())
                    .unwrap_or_else(|| default_size_for_provider(provider).to_string());
                let size = prompt_with_default("Cloud size", &size_default)?;

                let ssh_key = config.deploy.cloud.as_ref().and_then(|c| c.ssh_key.clone());

                let orchestrator = config
                    .deploy
                    .cloud
                    .as_ref()
                    .map(|c| c.orchestrator)
                    .unwrap_or(CloudOrchestrator::Remote);

                let install_image = config
                    .deploy
                    .cloud
                    .as_ref()
                    .and_then(|c| c.install_image.clone());

                let remote_payload_file = config
                    .deploy
                    .cloud
                    .as_ref()
                    .and_then(|c| c.remote_payload_file.clone());

                config.deploy.target = DeployTarget::Cloud;
                config.deploy.cloud = Some(CloudConfig {
                    provider,
                    orchestrator,
                    region: if region.trim().is_empty() {
                        None
                    } else {
                        Some(region)
                    },
                    size: if size.trim().is_empty() {
                        None
                    } else {
                        Some(size)
                    },
                    install_image,
                    remote_payload_file,
                    ssh_key,
                    key: None,
                    server: None,
                });

                applied.push("Set deploy.target=cloud and deploy.cloud.*".to_string());
            }
            "E002" => {
                eprintln!("Detected missing server host settings (E002).");

                let mut host = config
                    .deploy
                    .server
                    .as_ref()
                    .map(|s| s.host.clone())
                    .unwrap_or_default();

                while host.trim().is_empty() {
                    host = prompt_line("Server host (required, e.g. 203.0.113.10): ")?;
                }

                let user_default = config
                    .deploy
                    .server
                    .as_ref()
                    .map(|s| s.user.clone())
                    .unwrap_or_else(|| "root".to_string());
                let user = prompt_with_default("SSH user", &user_default)?;

                let port_default = config
                    .deploy
                    .server
                    .as_ref()
                    .map(|s| s.port.to_string())
                    .unwrap_or_else(|| "22".to_string());
                let port_input = prompt_with_default("SSH port", &port_default)?;
                let port = port_input.parse::<u16>().unwrap_or(22);

                let ssh_key = config
                    .deploy
                    .server
                    .as_ref()
                    .and_then(|s| s.ssh_key.clone());

                config.deploy.target = DeployTarget::Server;
                config.deploy.server = Some(ServerConfig {
                    host,
                    user,
                    ssh_key,
                    port,
                });

                applied.push("Set deploy.target=server and deploy.server.*".to_string());
            }
            _ => {}
        }
    }

    if applied.is_empty() {
        return Ok(applied);
    }

    let backup_path = format!("{}.bak", config_path);
    std::fs::copy(config_path, &backup_path)?;

    let yaml = serde_yaml::to_string(&config)
        .map_err(|e| CliError::ConfigValidation(format!("Failed to serialize config: {}", e)))?;
    std::fs::write(config_path, yaml)?;

    applied.push(format!("Backup written to {}", backup_path));
    Ok(applied)
}

/// Core validate logic — loads config, runs semantic checks, returns issues.
pub fn run_validate(config_path: &str) -> Result<Vec<String>, CliError> {
    let path = Path::new(config_path);
    if !path.exists() {
        return Err(CliError::ConfigNotFound {
            path: PathBuf::from(config_path),
        });
    }

    let mut messages = match load_raw_path_issues(path) {
        Ok(issues) => {
            let mut rendered = issues.iter().map(render_raw_path_issue).collect::<Vec<_>>();
            if issues
                .iter()
                .any(|issue| matches!(issue.kind, RawPathIssueKind::Empty))
            {
                rendered.push(
                    "Run `stacker config fix` to remove empty structural path fields safely."
                        .to_string(),
                );
            }
            rendered
        }
        Err(_) => Vec::new(),
    };

    let config = StackerConfig::from_file(path)?;
    let issues = config.validate_semantics();
    messages.extend(issues.iter().map(|i| format!("{:?}", i)));
    Ok(messages)
}

/// Core show logic — loads config, serialises to YAML string.
pub fn run_show(config_path: &str) -> Result<String, CliError> {
    let path = Path::new(config_path);
    if !path.exists() {
        return Err(CliError::ConfigNotFound {
            path: PathBuf::from(config_path),
        });
    }

    let config = StackerConfig::from_file(path)?;
    let yaml = serde_yaml::to_string(&config)
        .map_err(|e| CliError::ConfigValidation(format!("Failed to serialize config: {}", e)))?;
    Ok(yaml)
}

pub fn run_show_resolved(config_path: &str) -> Result<String, CliError> {
    let path = Path::new(config_path);
    if !path.exists() {
        return Err(CliError::ConfigNotFound {
            path: PathBuf::from(config_path),
        });
    }

    let config = StackerConfig::from_file(path)?;
    let config_dir = path.parent().unwrap_or_else(|| Path::new("."));
    let local_env_file = config
        .resolve_environment_config(None)?
        .and_then(|(_, environment_config)| environment_config.env_file)
        .or_else(|| config.env_file.clone())
        .map(|env_file| resolve_display_path(config_dir, &env_file))
        .unwrap_or_else(|| "<none>".to_string());
    let runtime_env_contract = runtime_env_contract_response();
    let layers = runtime_env_contract
        .layers
        .iter()
        .map(|layer| {
            format!(
                "    - name: {}\n      precedence: {}\n      applies_when: {}\n      description: {}",
                layer.name, layer.precedence, layer.applies_when, layer.description
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    Ok(format!(
        "resolved_config:\n  local_env_file: {}\n  remote_runtime_env_file: {}\n  compose_env_file: {}\n  config_version: local\n  config_hash: unavailable_until_deploy\n  runtime_env_contract_version: {}\n  runtime_env_contract_order: {}\n  layers:\n{}\n",
        local_env_file,
        remote_runtime_env_path(),
        compose_env_file_reference(),
        runtime_env_contract.version,
        runtime_env_contract.order,
        layers
    ))
}

fn resolve_display_path(config_dir: &Path, env_file: &Path) -> String {
    if env_file.is_absolute() {
        env_file.display().to_string()
    } else {
        config_dir.join(env_file).display().to_string()
    }
}

/// `stacker config validate [--file stacker.yml]`
///
/// Validates a stacker.yml configuration file.
pub struct ConfigValidateCommand {
    pub file: Option<String>,
}

impl ConfigValidateCommand {
    pub fn new(file: Option<String>) -> Self {
        Self { file }
    }
}

impl CallableTrait for ConfigValidateCommand {
    fn call(&self) -> Result<(), Box<dyn std::error::Error>> {
        let path = resolve_config_path(&self.file);
        let issues = run_validate(&path)?;

        if issues.is_empty() {
            eprintln!("✓ Configuration is valid");
        } else {
            eprintln!("Configuration issues:");
            for issue in &issues {
                eprintln!("  - {}", issue);
            }
        }

        Ok(())
    }
}

/// `stacker config show [--file stacker.yml]`
///
/// Displays the resolved configuration (with env vars substituted).
pub struct ConfigShowCommand {
    pub file: Option<String>,
    pub resolved: bool,
}

/// `stacker config inventory --env <name> [--service <target>] [--json]`
///
/// Displays a redacted, comparable configuration key inventory.
pub struct ConfigInventoryCommand {
    pub file: Option<String>,
    pub environment: String,
    pub service: Option<String>,
    pub json: bool,
    pub show_values: bool,
    pub remote: bool,
    pub project: Option<String>,
}

/// `stacker config diff --from <env> --to <env> [--service <target>] [--json]`
///
/// Compares redacted local configuration inventories across environments.
pub struct ConfigDiffCommand {
    pub file: Option<String>,
    pub from: String,
    pub to: String,
    pub service: Option<String>,
    pub json: bool,
    pub strict: bool,
    pub remote: bool,
    pub project: Option<String>,
}

/// `stacker config check --env <name> [--service <target>] [--json] [--strict]`
///
/// Checks an environment against optional `config_contract` requirements.
pub struct ConfigCheckCommand {
    pub file: Option<String>,
    pub environment: String,
    pub service: Option<String>,
    pub json: bool,
    pub strict: bool,
    pub remote: bool,
    pub project: Option<String>,
}

/// `stacker config promote --from <env> --to <env> [--service <target>]`
///
/// Generates safe target placeholders for keys missing from the target environment.
pub struct ConfigPromoteCommand {
    pub file: Option<String>,
    pub from: String,
    pub to: String,
    pub service: Option<String>,
    pub keys: Vec<String>,
    pub json: bool,
    pub remote: bool,
    pub project: Option<String>,
}

/// `stacker config contract suggest --env <name> [--service <target>]`
///
/// Generates a reviewable `config_contract` YAML snippet from inventory.
pub struct ConfigContractSuggestCommand {
    pub file: Option<String>,
    pub environment: String,
    pub service: Option<String>,
}

/// `stacker config fix [--file stacker.yml] [--interactive]`
///
/// Interactively repairs common missing required fields in stacker.yml.
pub struct ConfigFixCommand {
    pub file: Option<String>,
    pub interactive: bool,
}

/// `stacker config setup cloud [--file stacker.yml]`
///
/// Interactive cloud setup wizard that writes deploy.target/deploy.cloud.
pub struct ConfigSetupCloudCommand {
    pub file: Option<String>,
}

/// `stacker config setup ai [--file stacker.yml]`
///
/// Guided AI setup wizard that writes ai.* without replacing unrelated config.
pub struct ConfigSetupAiCommand {
    pub file: Option<String>,
    pub provider: Option<String>,
    pub endpoint: Option<String>,
    pub model: Option<String>,
    pub timeout: Option<u64>,
    pub tasks: Vec<String>,
}

impl ConfigSetupAiCommand {
    pub fn new(
        file: Option<String>,
        provider: Option<String>,
        endpoint: Option<String>,
        model: Option<String>,
        timeout: Option<u64>,
        tasks: Vec<String>,
    ) -> Self {
        Self {
            file,
            provider,
            endpoint,
            model,
            timeout,
            tasks,
        }
    }
}

impl CallableTrait for ConfigSetupAiCommand {
    fn call(&self) -> Result<(), Box<dyn std::error::Error>> {
        let path = resolve_config_path(&self.file);
        let applied = run_setup_ai(
            &path,
            AiSetupOptions {
                provider: self.provider.as_deref(),
                endpoint: self.endpoint.as_deref(),
                model: self.model.as_deref(),
                timeout: self.timeout,
                tasks: &self.tasks,
            },
        )?;

        eprintln!("✓ Updated {}", path);
        for item in applied {
            eprintln!("  - {}", item);
        }
        eprintln!("Run: stacker config validate");
        Ok(())
    }
}

impl ConfigSetupCloudCommand {
    pub fn new(file: Option<String>) -> Self {
        Self { file }
    }
}

impl CallableTrait for ConfigSetupCloudCommand {
    fn call(&self) -> Result<(), Box<dyn std::error::Error>> {
        let path = resolve_config_path(&self.file);
        let applied = run_setup_cloud_interactive(&path)?;

        eprintln!("✓ Updated {}", path);
        for item in applied {
            eprintln!("  - {}", item);
        }
        eprintln!("Run: stacker config validate");
        Ok(())
    }
}

/// `stacker config setup remote-payload [--file stacker.yml] [--out stacker.remote.deploy.json]`
///
/// Advanced/debug helper: generate a User Service `/install/init/` payload file and wire config for remote orchestrator.
pub struct ConfigSetupRemotePayloadCommand {
    pub file: Option<String>,
    pub out: Option<String>,
}

impl ConfigSetupRemotePayloadCommand {
    pub fn new(file: Option<String>, out: Option<String>) -> Self {
        Self { file, out }
    }
}

impl CallableTrait for ConfigSetupRemotePayloadCommand {
    fn call(&self) -> Result<(), Box<dyn std::error::Error>> {
        let path = resolve_config_path(&self.file);
        let applied = run_generate_remote_payload(&path, self.out.as_deref())?;

        eprintln!("✓ Updated {}", path);
        for item in applied {
            eprintln!("  - {}", item);
        }
        eprintln!("Run: stacker deploy --target cloud");
        eprintln!("Note: this command is mainly for troubleshooting and integrations.");
        Ok(())
    }
}

impl ConfigFixCommand {
    pub fn new(file: Option<String>, interactive: bool) -> Self {
        Self { file, interactive }
    }
}

impl CallableTrait for ConfigFixCommand {
    fn call(&self) -> Result<(), Box<dyn std::error::Error>> {
        if !self.interactive {
            return Err(Box::new(CliError::ConfigValidation(
                "Only interactive mode is supported for now. Use: stacker config fix --interactive"
                    .to_string(),
            )));
        }

        let path = resolve_config_path(&self.file);
        let applied = run_fix_interactive(&path)?;

        if applied.is_empty() {
            eprintln!("No interactive fixes were applied.");
        } else {
            eprintln!("✓ Updated {}", path);
            for item in applied {
                eprintln!("  - {}", item);
            }
            eprintln!("Run: stacker config validate");
        }

        Ok(())
    }
}

impl ConfigShowCommand {
    pub fn new(file: Option<String>, resolved: bool) -> Self {
        Self { file, resolved }
    }
}

impl CallableTrait for ConfigShowCommand {
    fn call(&self) -> Result<(), Box<dyn std::error::Error>> {
        let path = resolve_config_path(&self.file);
        let output = if self.resolved {
            run_show_resolved(&path)?
        } else {
            run_show(&path)?
        };
        println!("{}", output);
        Ok(())
    }
}

impl ConfigInventoryCommand {
    pub fn new(
        file: Option<String>,
        environment: String,
        service: Option<String>,
        json: bool,
        show_values: bool,
        remote: bool,
        project: Option<String>,
    ) -> Self {
        Self {
            file,
            environment,
            service,
            json,
            show_values,
            remote,
            project,
        }
    }
}

impl CallableTrait for ConfigInventoryCommand {
    fn call(&self) -> Result<(), Box<dyn std::error::Error>> {
        let path = resolve_config_path(&self.file);
        let mut inventory = load_inventory(
            Path::new(&path),
            &InventoryOptions {
                environment: self.environment.clone(),
                service: self.service.clone(),
                show_values: self.show_values,
            },
        )?;
        if self.remote {
            enrich_remote_service_secret_metadata(
                Path::new(&path),
                self.project.as_deref(),
                &mut inventory,
            )?;
        }

        if self.json {
            println!("{}", serde_json::to_string_pretty(&inventory)?);
            return Ok(());
        }

        for warning in &inventory.warnings {
            eprintln!("⚠ {warning}");
        }
        print!("{}", format_inventory_table(&inventory));

        Ok(())
    }
}

fn format_inventory_table(inventory: &ConfigInventory) -> String {
    let mut rows = vec![[
        "Target".to_string(),
        "Key".to_string(),
        "Source".to_string(),
        "Present".to_string(),
        "Secret".to_string(),
        "Value".to_string(),
    ]];

    for target in &inventory.targets {
        for key in &target.keys {
            let value = if key.secret {
                "[REDACTED]".to_string()
            } else if key.present {
                key.value_preview
                    .clone()
                    .unwrap_or_else(|| "[HIDDEN]".to_string())
            } else {
                "[MISSING]".to_string()
            };

            rows.push([
                target.target_code.clone(),
                key.key.clone(),
                key.source.clone(),
                key.present.to_string(),
                key.secret.to_string(),
                value,
            ]);
        }
    }

    let mut widths = [0usize; 5];
    for row in &rows {
        for index in 0..widths.len() {
            widths[index] = widths[index].max(row[index].len());
        }
    }

    let mut output = String::new();
    for row in rows {
        output.push_str(&format!(
            "{:<target_width$}  {:<key_width$}  {:<source_width$}  {:<present_width$}  {:<secret_width$}  {}\n",
            row[0],
            row[1],
            row[2],
            row[3],
            row[4],
            row[5],
            target_width = widths[0],
            key_width = widths[1],
            source_width = widths[2],
            present_width = widths[3],
            secret_width = widths[4],
        ));
    }

    output
}

impl ConfigDiffCommand {
    pub fn new(
        file: Option<String>,
        from: String,
        to: String,
        service: Option<String>,
        json: bool,
        strict: bool,
        remote: bool,
        project: Option<String>,
    ) -> Self {
        Self {
            file,
            from,
            to,
            service,
            json,
            strict,
            remote,
            project,
        }
    }
}

impl CallableTrait for ConfigDiffCommand {
    fn call(&self) -> Result<(), Box<dyn std::error::Error>> {
        let path = resolve_config_path(&self.file);
        let diff = if self.remote {
            let from_inventory = load_inventory(
                Path::new(&path),
                &InventoryOptions {
                    environment: self.from.clone(),
                    service: self.service.clone(),
                    show_values: false,
                },
            )?;
            let mut to_inventory = load_inventory(
                Path::new(&path),
                &InventoryOptions {
                    environment: self.to.clone(),
                    service: self.service.clone(),
                    show_values: false,
                },
            )?;
            enrich_remote_service_secret_metadata(
                Path::new(&path),
                self.project.as_deref(),
                &mut to_inventory,
            )?;
            diff_inventories(from_inventory, to_inventory, self.service.clone())
        } else {
            load_diff(Path::new(&path), &self.from, &self.to, self.service.clone())?
        };

        if self.json {
            println!("{}", serde_json::to_string_pretty(&diff)?);
        } else {
            print_config_diff(&diff);
        }

        if self.strict && diff.has_differences() {
            return Err(Box::new(CliError::ConfigValidation(format!(
                "configuration differs between {} and {}",
                self.from, self.to
            ))));
        }

        Ok(())
    }
}

impl ConfigCheckCommand {
    pub fn new(
        file: Option<String>,
        environment: String,
        service: Option<String>,
        json: bool,
        strict: bool,
        remote: bool,
        project: Option<String>,
    ) -> Self {
        Self {
            file,
            environment,
            service,
            json,
            strict,
            remote,
            project,
        }
    }
}

impl CallableTrait for ConfigCheckCommand {
    fn call(&self) -> Result<(), Box<dyn std::error::Error>> {
        let path = resolve_config_path(&self.file);
        let result = if self.remote {
            let config = StackerConfig::from_file(Path::new(&path))?;
            let mut inventory = load_inventory(
                Path::new(&path),
                &InventoryOptions {
                    environment: self.environment.clone(),
                    service: self.service.clone(),
                    show_values: false,
                },
            )?;
            enrich_remote_service_secret_metadata(
                Path::new(&path),
                self.project.as_deref(),
                &mut inventory,
            )?;
            check_inventory(config, inventory, self.service.clone())
        } else {
            load_check(Path::new(&path), &self.environment, self.service.clone())?
        };

        if self.json {
            println!("{}", serde_json::to_string_pretty(&result)?);
        } else {
            print_config_check(&result);
        }

        if self.strict && result.has_required_failures() {
            return Err(Box::new(CliError::ConfigValidation(format!(
                "required configuration missing for {}",
                self.environment
            ))));
        }

        Ok(())
    }
}

impl ConfigPromoteCommand {
    pub fn new(
        file: Option<String>,
        from: String,
        to: String,
        service: Option<String>,
        keys: Vec<String>,
        json: bool,
        remote: bool,
        project: Option<String>,
    ) -> Self {
        Self {
            file,
            from,
            to,
            service,
            keys,
            json,
            remote,
            project,
        }
    }
}

impl CallableTrait for ConfigPromoteCommand {
    fn call(&self) -> Result<(), Box<dyn std::error::Error>> {
        let path = resolve_config_path(&self.file);
        let plan = if self.remote {
            let from_inventory = load_inventory(
                Path::new(&path),
                &InventoryOptions {
                    environment: self.from.clone(),
                    service: self.service.clone(),
                    show_values: false,
                },
            )?;
            let mut to_inventory = load_inventory(
                Path::new(&path),
                &InventoryOptions {
                    environment: self.to.clone(),
                    service: self.service.clone(),
                    show_values: false,
                },
            )?;
            enrich_remote_service_secret_metadata(
                Path::new(&path),
                self.project.as_deref(),
                &mut to_inventory,
            )?;
            let diff = diff_inventories(from_inventory, to_inventory, self.service.clone());
            promotion_plan_from_diff(diff, self.keys.clone())
        } else {
            load_promotion_plan(
                Path::new(&path),
                &self.from,
                &self.to,
                self.service.clone(),
                self.keys.clone(),
            )?
        };

        if self.json {
            println!("{}", serde_json::to_string_pretty(&plan)?);
        } else {
            print_promotion_plan(&plan);
        }

        Ok(())
    }
}

fn print_promotion_plan(plan: &ConfigPromotionPlan) {
    for warning in &plan.warnings {
        eprintln!("⚠ {warning}");
    }

    if plan.is_empty() {
        println!(
            "No missing keys to promote from {} to {}.",
            plan.from_environment, plan.to_environment
        );
        return;
    }

    println!(
        "Promotion placeholders from {} to {}:",
        plan.from_environment, plan.to_environment
    );
    let mut current_target = "";
    for item in &plan.items {
        if current_target != item.target {
            current_target = &item.target;
            println!();
            println!("# {}", item.target);
        }
        let secret_marker = if item.secret { " # secret" } else { "" };
        println!("{}{}", item.placeholder, secret_marker);
    }
    println!();
    println!("Review these placeholders and fill target values manually; plaintext is not copied.");
}

fn enrich_remote_service_secret_metadata(
    config_path: &Path,
    explicit_project: Option<&str>,
    inventory: &mut ConfigInventory,
) -> Result<(), CliError> {
    let project_ref = resolve_remote_project_reference(config_path, explicit_project)?;
    let ctx = CliRuntime::new("config remote metadata")?;
    let project = ctx
        .block_on(ctx.client.find_project(&project_ref))?
        .ok_or_else(|| {
            CliError::ConfigValidation(format!("Project '{}' was not found", project_ref))
        })?;
    let registered_apps = ctx.block_on(ctx.client.list_project_apps(project.id))?;
    let target_codes = registered_remote_target_codes(inventory, &registered_apps);

    for target_code in target_codes {
        match ctx.block_on(ctx.client.list_service_secrets(project.id, &target_code)) {
            Ok(secrets) => {
                merge_remote_secret_names(
                    inventory,
                    &target_code,
                    secrets.into_iter().map(|secret| secret.name),
                );
            }
            Err(error) => inventory.warnings.push(remote_metadata_warning(
                &target_code,
                &error,
                cli_debug_enabled(),
            )),
        }
    }

    Ok(())
}

fn remote_metadata_warning(target_code: &str, error: &CliError, debug: bool) -> String {
    if debug {
        return format!("Remote secret metadata unavailable for {target_code}: {error}");
    }

    format!(
        "Remote secret metadata unavailable for {target_code}; rerun with DEBUG=true for details."
    )
}

fn registered_remote_target_codes(
    inventory: &ConfigInventory,
    registered_apps: &[ProjectAppInfo],
) -> Vec<String> {
    let registered_codes = registered_apps
        .iter()
        .map(|app| app.code.as_str())
        .collect::<BTreeSet<_>>();

    inventory
        .targets
        .iter()
        .filter_map(|target| {
            registered_codes
                .contains(target.target_code.as_str())
                .then(|| target.target_code.clone())
        })
        .collect()
}

fn resolve_remote_project_reference(
    config_path: &Path,
    explicit_project: Option<&str>,
) -> Result<String, CliError> {
    if let Some(project) = explicit_project
        .map(str::trim)
        .filter(|project| !project.is_empty())
    {
        return Ok(project.to_string());
    }

    let config = StackerConfig::from_file_raw(config_path)?;
    config
        .project
        .identity
        .map(|project| project.trim().to_string())
        .filter(|project| !project.is_empty())
        .ok_or_else(|| {
            CliError::ConfigValidation(
                "Remote config metadata requires --project, or set project.identity in stacker.yml."
                    .to_string(),
            )
        })
}

impl ConfigContractSuggestCommand {
    pub fn new(file: Option<String>, environment: String, service: Option<String>) -> Self {
        Self {
            file,
            environment,
            service,
        }
    }
}

impl CallableTrait for ConfigContractSuggestCommand {
    fn call(&self) -> Result<(), Box<dyn std::error::Error>> {
        let path = resolve_config_path(&self.file);
        let output = suggest_contract_yaml(
            Path::new(&path),
            &ContractSuggestOptions {
                environment: self.environment.clone(),
                service: self.service.clone(),
            },
        )?;
        println!("{}", output.trim_end());
        Ok(())
    }
}

fn print_config_check(result: &ConfigCheckResult) {
    for warning in &result.warnings {
        eprintln!("⚠ {warning}");
    }

    print_check_items("Missing required:", &result.missing_required);
    print_check_items("Missing optional:", &result.missing_optional);

    if !result.has_required_failures() && result.missing_optional.is_empty() {
        println!(
            "Configuration contract satisfied for {}.",
            result.environment
        );
    }
}

fn print_check_items(title: &str, items: &[ConfigCheckItem]) {
    if items.is_empty() {
        return;
    }

    println!("{title}");
    for item in items {
        let secret_marker = if item.secret { " [secret]" } else { "" };
        println!("  {}:{}{}", item.target, item.key, secret_marker);
    }
}

fn print_config_diff(diff: &ConfigDiff) {
    for warning in &diff.warnings {
        eprintln!("⚠ {warning}");
    }

    print_diff_items(
        &format!("Missing in {}:", diff.to_environment),
        &diff.missing_in_to,
    );
    print_diff_items(
        &format!("Only in {}:", diff.to_environment),
        &diff.only_in_to,
    );
    print_diff_items("Different values:", &diff.different);

    if !diff.has_differences() {
        println!(
            "No configuration differences found between {} and {}.",
            diff.from_environment, diff.to_environment
        );
    }
}

fn print_diff_items(title: &str, items: &[DiffItem]) {
    if items.is_empty() {
        return;
    }

    println!("{title}");
    for item in items {
        let secret_marker = if item.secret { " [secret]" } else { "" };
        println!("  {}:{}{}", item.target, item.key, secret_marker);
    }
}

/// `stacker config example`
///
/// Prints a full commented `stacker.yml` reference example.
pub struct ConfigExampleCommand;

impl ConfigExampleCommand {
    pub fn new() -> Self {
        Self
    }
}

impl CallableTrait for ConfigExampleCommand {
    fn call(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("{}", full_config_reference_example());
        Ok(())
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// `stacker config lock` / `stacker config unlock`
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// `stacker config lock [--file stacker.yml]`
///
/// Reads `.stacker/deployment.lock` and writes the server details
/// (host, user, port, ssh_key) into stacker.yml's `deploy.server` section.
/// Next deploy will auto-detect the server and redeploy via SSH.
pub struct ConfigLockCommand {
    pub file: Option<String>,
}

impl ConfigLockCommand {
    pub fn new(file: Option<String>) -> Self {
        Self { file }
    }
}

impl CallableTrait for ConfigLockCommand {
    fn call(&self) -> Result<(), Box<dyn std::error::Error>> {
        let project_dir = std::env::current_dir()?;
        let config_path_str = resolve_config_path(&self.file);
        let config_path = project_dir.join(&config_path_str);

        // 1. Load lockfile (prefer cloud/server)
        let lock = match DeploymentLock::load(&project_dir)? {
            Some(l) => l,
            None => {
                eprintln!("No deployment lock found in .stacker/.");
                eprintln!("Deploy first with `stacker deploy`, then run this command.");
                return Ok(());
            }
        };

        // 2. Check it has usable server details
        match lock.server_ip.as_deref() {
            Some("127.0.0.1") | None => {
                eprintln!("Deployment lock exists but has no remote server details.");
                if lock.target == "cloud" {
                    eprintln!("The cloud deployment may still be provisioning.");
                    eprintln!(
                        "Wait for it to complete, then run `stacker deploy --lock` to retry."
                    );
                }
                return Ok(());
            }
            _ => {}
        }

        // 3. Load stacker.yml, apply lock, write back
        if !config_path.exists() {
            return Err(Box::new(CliError::ConfigNotFound { path: config_path }));
        }

        let mut config = StackerConfig::from_file_raw(&config_path)?;
        lock.apply_to_config(&mut config);

        DeploymentLock::write_config(&config, &config_path)?;

        let ip = lock.server_ip.as_deref().unwrap_or("?");
        let user = lock.ssh_user.as_deref().unwrap_or("root");
        let port = lock.ssh_port.unwrap_or(22);

        eprintln!("✓ stacker.yml updated with server details:");
        eprintln!("  deploy.server.host: {}", ip);
        eprintln!("  deploy.server.user: {}", user);
        eprintln!("  deploy.server.port: {}", port);
        eprintln!("  Backup: {}.bak", config_path_str);
        eprintln!();
        eprintln!("Next `stacker deploy` will target this server directly.");

        Ok(())
    }
}

/// `stacker config unlock [--file stacker.yml]`
///
/// Removes the `deploy.server` section from stacker.yml, allowing a fresh
/// cloud provision on the next deploy.
pub struct ConfigUnlockCommand {
    pub file: Option<String>,
}

impl ConfigUnlockCommand {
    pub fn new(file: Option<String>) -> Self {
        Self { file }
    }
}

impl CallableTrait for ConfigUnlockCommand {
    fn call(&self) -> Result<(), Box<dyn std::error::Error>> {
        let project_dir = std::env::current_dir()?;
        let config_path_str = resolve_config_path(&self.file);
        let config_path = project_dir.join(&config_path_str);

        if !config_path.exists() {
            return Err(Box::new(CliError::ConfigNotFound { path: config_path }));
        }

        let mut config = StackerConfig::from_file_raw(&config_path)?;

        if config.deploy.server.is_none() {
            eprintln!("No deploy.server section found in stacker.yml — nothing to unlock.");
            return Ok(());
        }

        let old_host = config
            .deploy
            .server
            .as_ref()
            .map(|s| s.host.clone())
            .unwrap_or_default();

        config.deploy.server = None;

        DeploymentLock::write_config(&config, &config_path)?;

        eprintln!("✓ Removed deploy.server section (was: host={})", old_host);
        eprintln!("  Backup: {}.bak", config_path_str);
        eprintln!("  Next `stacker deploy --target cloud` will provision a new server.");

        Ok(())
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn minimal_config_yaml() -> &'static str {
        "name: test-app\nversion: \"1.0\"\nproject:\n  identity: \"registered-stack-code\"\napp:\n  type: static\n  source: \"./dist\"\ndeploy:\n  target: local\n"
    }

    fn write_config(dir: &Path, content: &str) -> String {
        let path = dir.join("stacker.yml");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        path.to_string_lossy().to_string()
    }

    #[test]
    fn test_validate_returns_ok_for_valid_config() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = write_config(dir.path(), minimal_config_yaml());
        let result = run_validate(&path).unwrap();
        // Minimal valid config should have zero or few issues
        assert!(result.len() < 5);
    }

    #[test]
    fn test_validate_missing_file_returns_error() {
        let result = run_validate("/nonexistent/stacker.yml");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_reports_empty_path_fields() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = write_config(
            dir.path(),
            r#"
name: empty-paths
app:
  type: static
  path:
"#,
        );

        let issues = run_validate(&path).unwrap();
        assert!(issues.iter().any(|issue| issue.contains("app.path")));
        assert!(issues
            .iter()
            .any(|issue| issue.contains("quoted path string")));
        assert!(issues
            .iter()
            .any(|issue| issue.contains("stacker config fix")));
    }

    #[test]
    fn test_show_returns_yaml_string() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = write_config(dir.path(), minimal_config_yaml());
        let yaml = run_show(&path).unwrap();
        assert!(yaml.contains("test-app"));
    }

    #[test]
    fn test_show_missing_file_returns_error() {
        let result = run_show("/nonexistent/stacker.yml");
        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_config_path_default() {
        let resolved = resolve_config_path(&None);
        assert_eq!(resolved, "stacker.yml");
    }

    #[test]
    fn test_resolve_config_path_override() {
        let resolved = resolve_config_path(&Some("custom.yml".to_string()));
        assert_eq!(resolved, "custom.yml");
    }

    #[test]
    fn test_inventory_table_aligns_columns() {
        let inventory = ConfigInventory {
            environment: "local".to_string(),
            warnings: Vec::new(),
            targets: vec![crate::cli::config_inventory::TargetConfigInventory {
                target_code: "coolify".to_string(),
                keys: vec![
                    crate::cli::config_inventory::ConfigKeyInventory {
                        key: "APP_ENV".to_string(),
                        source: "compose environment".to_string(),
                        present: true,
                        secret: false,
                        value_hash: None,
                        value_preview: Some("${APP_ENV:-production}".to_string()),
                    },
                    crate::cli::config_inventory::ConfigKeyInventory {
                        key: "PHP_FPM_PM_MAX_SPARE_SERVERS".to_string(),
                        source: "compose environment".to_string(),
                        present: true,
                        secret: false,
                        value_hash: None,
                        value_preview: Some("${PHP_FPM_PM_MAX_SPARE_SERVERS:-10}".to_string()),
                    },
                    crate::cli::config_inventory::ConfigKeyInventory {
                        key: "DB_PASSWORD".to_string(),
                        source: "compose env_file".to_string(),
                        present: true,
                        secret: true,
                        value_hash: None,
                        value_preview: None,
                    },
                ],
            }],
        };

        let table = format_inventory_table(&inventory);

        assert!(table.starts_with("Target   Key                           Source"));
        assert!(table.contains("coolify  APP_ENV                       compose environment"));
        assert!(table.contains("coolify  DB_PASSWORD                   compose env_file"));
        assert!(table.contains("[REDACTED]"));
        assert!(!table.contains('\t'));
    }

    #[test]
    fn test_registered_remote_target_codes_skip_local_only_services() {
        let inventory = ConfigInventory {
            environment: "production".to_string(),
            warnings: Vec::new(),
            targets: vec![
                crate::cli::config_inventory::TargetConfigInventory {
                    target_code: "coolify".to_string(),
                    keys: Vec::new(),
                },
                crate::cli::config_inventory::TargetConfigInventory {
                    target_code: "postgres".to_string(),
                    keys: Vec::new(),
                },
                crate::cli::config_inventory::TargetConfigInventory {
                    target_code: "redis".to_string(),
                    keys: Vec::new(),
                },
            ],
        };
        let registered_apps = vec![ProjectAppInfo {
            id: 1,
            project_id: 229,
            code: "coolify".to_string(),
            name: "Coolify".to_string(),
            image: "coollabsio/coolify:latest".to_string(),
            enabled: true,
            deploy_order: None,
            parent_app_code: None,
        }];

        let codes = registered_remote_target_codes(&inventory, &registered_apps);

        assert_eq!(codes, vec!["coolify"]);
    }

    #[test]
    fn test_remote_metadata_warning_hides_api_details_without_debug() {
        let error = CliError::DeployFailed {
            target: DeployTarget::Cloud,
            reason: "Stacker server GET /project/229/apps/postgres/secrets failed (404): {\"message\":\"App not found\"}".to_string(),
        };

        let warning = remote_metadata_warning("postgres", &error, false);

        assert!(warning.contains("postgres"));
        assert!(warning.contains("DEBUG=true"));
        assert!(!warning.contains("GET /project"));
        assert!(!warning.contains("App not found"));
    }

    #[test]
    fn test_remote_metadata_warning_shows_api_details_with_debug() {
        let error = CliError::DeployFailed {
            target: DeployTarget::Cloud,
            reason: "Stacker server GET /project/229/apps/postgres/secrets failed (404): {\"message\":\"App not found\"}".to_string(),
        };

        let warning = remote_metadata_warning("postgres", &error, true);

        assert!(warning.contains("GET /project/229/apps/postgres/secrets"));
        assert!(warning.contains("App not found"));
    }

    #[test]
    fn test_parse_cloud_provider_valid() {
        assert_eq!(
            parse_cloud_provider("hetzner").unwrap(),
            CloudProvider::Hetzner
        );
        assert_eq!(parse_cloud_provider("AWS").unwrap(), CloudProvider::Aws);
    }

    #[test]
    fn test_parse_cloud_provider_invalid() {
        let result = parse_cloud_provider("gcp");
        assert!(result.is_err());
    }

    #[test]
    fn test_default_region_for_provider() {
        assert_eq!(default_region_for_provider(CloudProvider::Hetzner), "nbg1");
        assert_eq!(default_region_for_provider(CloudProvider::Aws), "us-east-1");
    }

    #[test]
    fn test_apply_cloud_settings_sets_target_and_cloud() {
        let mut cfg = StackerConfig::from_str(minimal_config_yaml()).unwrap();
        apply_cloud_settings(
            &mut cfg,
            CloudProvider::Hetzner,
            Some("nbg1".to_string()),
            Some("cpx11".to_string()),
            None,
        );

        assert_eq!(cfg.deploy.target, DeployTarget::Cloud);
        let cloud = cfg.deploy.cloud.unwrap();
        assert_eq!(cloud.provider, CloudProvider::Hetzner);
        assert_eq!(cloud.region.as_deref(), Some("nbg1"));
        assert_eq!(cloud.size.as_deref(), Some("cpx11"));
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
    fn test_run_generate_remote_payload_writes_file_and_updates_config() {
        let dir = tempfile::TempDir::new().unwrap();
        let config_path = write_config(dir.path(), minimal_config_yaml());

        let applied =
            run_generate_remote_payload(&config_path, Some("stacker.remote.deploy.json")).unwrap();
        assert!(!applied.is_empty());

        let payload_path = dir.path().join("stacker.remote.deploy.json");
        assert!(payload_path.exists());

        let payload_raw = std::fs::read_to_string(&payload_path).unwrap();
        let payload_json: serde_json::Value = serde_json::from_str(&payload_raw).unwrap();
        assert!(payload_json.get("provider").is_some());
        assert!(payload_json.get("commonDomain").is_some());
        assert!(payload_json.get("os").is_some());
        assert!(payload_json.get("selected_plan").is_some());
        assert!(payload_json.get("payment_type").is_some());
        assert!(payload_json.get("subscriptions").is_some());
        assert!(payload_json.get("stack_code").is_some());
        assert_eq!(
            payload_json.get("stack_code").and_then(|v| v.as_str()),
            Some("registered-stack-code")
        );

        let updated = StackerConfig::from_file(Path::new(&config_path)).unwrap();
        assert_eq!(updated.deploy.target, DeployTarget::Cloud);
        let cloud = updated.deploy.cloud.unwrap();
        assert_eq!(cloud.orchestrator, CloudOrchestrator::Remote);
        assert_eq!(
            cloud.remote_payload_file.as_deref(),
            Some(Path::new("stacker.remote.deploy.json"))
        );
    }

    #[test]
    fn test_try_fix_raw_path_issues_removes_empty_path_fields() {
        let dir = tempfile::TempDir::new().unwrap();
        let config_path = write_config(
            dir.path(),
            r#"
name: broken-paths
app:
  type: static
  path:
deploy:
  target: server
  server:
    host: example.com
    ssh_key:
"#,
        );

        let applied = try_fix_raw_path_issues(&config_path).unwrap();
        assert!(applied.iter().any(|item| item.contains("app.path")));
        assert!(applied
            .iter()
            .any(|item| item.contains("deploy.server.ssh_key")));

        let fixed = std::fs::read_to_string(&config_path).unwrap();
        assert!(!fixed.contains("path: null"));
        assert!(!fixed.contains("ssh_key: null"));
    }

    #[test]
    fn test_run_fix_interactive_reports_non_string_path_fields() {
        let dir = tempfile::TempDir::new().unwrap();
        let config_path = write_config(
            dir.path(),
            r#"
name: broken-paths
app:
  type: static
  path: {}
"#,
        );

        let err = run_fix_interactive(&config_path).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("app.path"), "unexpected message: {msg}");
        assert!(
            msg.contains("quoted path string"),
            "unexpected message: {msg}"
        );
    }

    #[test]
    fn test_run_setup_ai_configures_ollama_without_removing_existing_config() {
        let dir = tempfile::TempDir::new().unwrap();
        let config_path = write_config(
            dir.path(),
            r#"
name: ai-app
app:
  type: static
deploy:
  target: local
env:
  KEEP_ME: "true"
"#,
        );

        let applied = run_setup_ai(
            &config_path,
            AiSetupOptions {
                provider: Some("ollama"),
                endpoint: Some("http://localhost:11434"),
                model: Some("llama3.1"),
                timeout: Some(120),
                tasks: &["dockerfile,compose".to_string()],
            },
        )
        .unwrap();

        assert!(applied.iter().any(|item| item.contains("ai.provider")));
        let updated = StackerConfig::from_file(Path::new(&config_path)).unwrap();
        assert!(updated.ai.enabled);
        assert_eq!(updated.ai.provider, AiProviderType::Ollama);
        assert_eq!(
            updated.ai.endpoint.as_deref(),
            Some("http://localhost:11434")
        );
        assert_eq!(updated.ai.model.as_deref(), Some("llama3.1"));
        assert_eq!(updated.ai.timeout, 120);
        assert_eq!(updated.ai.tasks, vec!["dockerfile", "compose"]);
        assert_eq!(updated.env.get("KEEP_ME").map(String::as_str), Some("true"));
    }
}
