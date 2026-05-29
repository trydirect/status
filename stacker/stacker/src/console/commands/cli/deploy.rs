use std::convert::TryFrom;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::cli::ai_client::{
    build_prompt, create_provider, ollama_complete_streaming, AiTask, PromptContext,
};
use crate::cli::cloud_env;
#[cfg(test)]
use crate::cli::compose_targets::extract_compose_secret_target_services;
use crate::cli::config_bundle::build_config_bundle;
use crate::cli::config_parser::{
    AiProviderType, CloudConfig, CloudOrchestrator, CloudProvider, DeployTarget, RegistryConfig,
    ServerConfig, StackerConfig,
};
use crate::cli::credentials::{CredentialStore, CredentialsManager, StoredCredentials};
use crate::cli::deployment_lock::DeploymentLock;
use crate::cli::error::CliError;
use crate::cli::generator::compose::ComposeDefinition;
use crate::cli::generator::dockerfile::DockerfileBuilder;
use crate::cli::install_runner::{
    resolve_docker_registry_credentials, strategy_for, CommandExecutor, DeployContext,
    DeployResult, ShellExecutor,
};
use crate::cli::progress;
use crate::cli::stacker_client::{self, StackerClient};
use crate::console::commands::CallableTrait;
use crate::helpers::ip::extract_ipv4_from_text;
use crate::helpers::ssh_client;

/// Default config filename.
const DEFAULT_CONFIG_FILE: &str = "stacker.yml";

/// Output directory for generated artifacts.
const OUTPUT_DIR: &str = ".stacker";

fn parse_ai_provider(s: &str) -> Result<AiProviderType, CliError> {
    let json = format!("\"{}\"", s.trim().to_lowercase());
    serde_json::from_str::<AiProviderType>(&json).map_err(|_| {
        CliError::ConfigValidation(
            "Unknown AI provider. Use: openai, anthropic, ollama, custom".to_string(),
        )
    })
}

fn resolve_ai_from_env_or_config(
    project_dir: &Path,
    config_file: Option<&str>,
) -> Result<crate::cli::config_parser::AiConfig, CliError> {
    let config_path = match config_file {
        Some(f) => project_dir.join(f),
        None => project_dir.join(DEFAULT_CONFIG_FILE),
    };

    let mut ai = if config_path.exists() {
        StackerConfig::from_file(&config_path)?.ai
    } else {
        Default::default()
    };

    if let Ok(provider) = std::env::var("STACKER_AI_PROVIDER") {
        ai.provider = parse_ai_provider(&provider)?;
        ai.enabled = true;
    }

    if let Ok(model) = std::env::var("STACKER_AI_MODEL") {
        if !model.trim().is_empty() {
            ai.model = Some(model);
            ai.enabled = true;
        }
    }

    if let Ok(endpoint) = std::env::var("STACKER_AI_ENDPOINT") {
        if !endpoint.trim().is_empty() {
            ai.endpoint = Some(endpoint);
            ai.enabled = true;
        }
    }

    if let Ok(timeout) = std::env::var("STACKER_AI_TIMEOUT") {
        if let Ok(value) = timeout.parse::<u64>() {
            ai.timeout = value;
            ai.enabled = true;
        }
    }

    if let Ok(generic_key) = std::env::var("STACKER_AI_API_KEY") {
        if !generic_key.trim().is_empty() {
            ai.api_key = Some(generic_key);
            ai.enabled = true;
        }
    }

    if ai.api_key.is_none() {
        match ai.provider {
            AiProviderType::Openai => {
                if let Ok(key) = std::env::var("OPENAI_API_KEY") {
                    if !key.trim().is_empty() {
                        ai.api_key = Some(key);
                        ai.enabled = true;
                    }
                }
            }
            AiProviderType::Anthropic => {
                if let Ok(key) = std::env::var("ANTHROPIC_API_KEY") {
                    if !key.trim().is_empty() {
                        ai.api_key = Some(key);
                        ai.enabled = true;
                    }
                }
            }
            _ => {}
        }
    }

    Ok(ai)
}

fn fallback_troubleshooting_hints(reason: &str) -> Vec<String> {
    let lower = reason.to_lowercase();
    let mut hints = Vec::new();

    if lower.contains("npm ci") {
        hints.push(
            "npm ci failed: ensure package-lock.json exists and is in sync with package.json"
                .to_string(),
        );
        hints.push(
            "Try locally: npm ci --production (or npm ci) to see the full dependency error"
                .to_string(),
        );
    }
    if lower.contains("the attribute `version` is obsolete")
        || lower.contains("attribute `version` is obsolete")
    {
        hints.push("docker-compose version warning: remove top-level 'version:' from .stacker/docker-compose.yml".to_string());
    }
    if lower.contains("failed to solve") {
        hints.push("Docker build step failed: inspect the failing Dockerfile line and run docker build manually for verbose output".to_string());
    }
    if lower.contains("permission denied") || lower.contains("eacces") {
        hints.push("Permission issue detected: verify file ownership and executable bits for scripts copied into the image".to_string());
    }
    if lower.contains("no such file") || lower.contains("not found") {
        hints.push(
            "Missing file in build context: confirm COPY paths and .dockerignore rules".to_string(),
        );
    }
    if lower.contains("network") || lower.contains("timed out") {
        hints.push(
            "Network/timeout issue: retry build and verify registry connectivity".to_string(),
        );
    }
    if lower.contains("port is already allocated")
        || lower.contains("bind for 0.0.0.0")
        || lower.contains("failed programming external connectivity")
    {
        hints.push("Port conflict: another process/container already uses this host port (for example 3000).".to_string());
        hints.push("Find the owner with: lsof -nP -iTCP:3000 -sTCP:LISTEN".to_string());
        hints.push("Then stop it (docker compose down / docker rm -f <container>) or change ports in stacker.yml".to_string());
    }
    if lower.contains("remote orchestrator request failed")
        && lower.contains("http error")
        && lower.contains("404")
        && (lower.contains("<!doctype html") || lower.contains("<html"))
    {
        hints.push("Remote orchestrator URL looks incorrect (received frontend 404 HTML instead of User Service JSON).".to_string());
        hints.push("If you logged in with /server/user/auth/login, deploy expects User Service base URL ending with /server/user.".to_string());
        hints.push("Try re-login with: stacker-cli login --auth-url https://dev.try.direct/server/user/auth/login".to_string());
    }
    if lower.contains("orphan containers") {
        hints.push("Orphan containers detected: run docker compose -f .stacker/docker-compose.yml down --remove-orphans".to_string());
    }
    if lower.contains("manifest unknown") || lower.contains("pull access denied") {
        hints.push(
            "Image pull failed: the configured image tag is not available in the registry"
                .to_string(),
        );
        if let Some(image) = extract_missing_image(reason) {
            hints.push(format!("Missing image detected: {}", image));
            hints.push(format!(
                "Build and tag locally: docker build -t {} .",
                image
            ));
            hints.push(format!(
                "If using a remote registry, push it first: docker push {}",
                image
            ));
        } else {
            hints.push("Build locally first (docker build -t <image:tag> .) or use an existing published tag".to_string());
        }
        hints.push("Alternative: remove app.image in stacker.yml so Stacker generates/uses a local build context".to_string());
    }

    if hints.is_empty() {
        hints.push("Run docker compose -f .stacker/docker-compose.yml build --no-cache for detailed build logs".to_string());
        hints.push("Inspect .stacker/Dockerfile and .stacker/docker-compose.yml for invalid paths and commands".to_string());
        hints.push(
            "If the issue is dependency-related, run the failing install command locally first"
                .to_string(),
        );
    }

    hints
}

fn extract_missing_image(reason: &str) -> Option<String> {
    for marker in ["manifest for ", "pull access denied for "] {
        if let Some(start) = reason.find(marker) {
            let image_start = start + marker.len();
            let tail = &reason[image_start..];
            let image = tail
                .split(|c: char| c.is_whitespace() || c == ',' || c == '\n')
                .next()
                .unwrap_or("")
                .trim_matches('"')
                .to_string();
            if !image.is_empty() {
                return Some(image);
            }
        }
    }
    None
}

fn ensure_env_file_if_needed(config: &StackerConfig, project_dir: &Path) -> Result<(), CliError> {
    let Some(env_file) = &config.env_file else {
        return Ok(());
    };

    let env_path = resolve_project_relative_path(project_dir, env_file);
    ensure_env_file_from_example(&env_path, "stacker.yml env_file")
}

fn resolve_project_relative_path(project_dir: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        project_dir.join(path)
    }
}

fn ensure_env_file_from_example(env_path: &Path, source: &str) -> Result<(), CliError> {
    if env_path.exists() {
        return Ok(());
    }

    let file_name = env_path.file_name().and_then(|name| name.to_str());
    let example_path = match file_name {
        Some(".env") => env_path.with_file_name(".env.example"),
        Some(name) => env_path.with_file_name(format!("{name}.example")),
        None => env_path.with_extension("example"),
    };

    if example_path.exists() && file_name == Some(".env") {
        if let Some(parent) = env_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(&example_path, env_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(env_path, std::fs::Permissions::from_mode(0o600))?;
        }
        eprintln!(
            "  Created {} from {} for {} (mode 0600 where supported)",
            env_path.display(),
            example_path.display(),
            source
        );
        return Ok(());
    }

    Err(CliError::ConfigValidation(format!(
        "Missing env file referenced by {source}: {}. Create it or, for the common .env case, add {} and rerun `stacker deploy`.",
        env_path.display(),
        example_path.display()
    )))
}

fn collect_compose_env_file_paths(compose_path: &Path) -> Result<Vec<PathBuf>, CliError> {
    let raw = std::fs::read_to_string(compose_path)?;
    let doc: serde_yaml::Value = serde_yaml::from_str(&raw)
        .map_err(|e| CliError::ConfigValidation(format!("Failed to parse compose file: {e}")))?;
    let compose_dir = compose_path.parent().unwrap_or_else(|| Path::new("."));
    let mut paths = Vec::new();
    collect_compose_env_file_paths_from_doc(&doc, compose_dir, &mut paths);
    Ok(paths)
}

fn collect_compose_env_file_paths_from_doc(
    doc: &serde_yaml::Value,
    compose_dir: &Path,
    paths: &mut Vec<PathBuf>,
) {
    let Some(services) = doc
        .as_mapping()
        .and_then(|root| root.get(serde_yaml::Value::String("services".to_string())))
        .and_then(serde_yaml::Value::as_mapping)
    else {
        return;
    };

    for service in services.values() {
        let Some(service_map) = service.as_mapping() else {
            continue;
        };
        let Some(env_file) = service_map.get(serde_yaml::Value::String("env_file".to_string()))
        else {
            continue;
        };
        append_env_file_value_paths(env_file, compose_dir, paths);
    }
}

fn append_env_file_value_paths(
    value: &serde_yaml::Value,
    compose_dir: &Path,
    paths: &mut Vec<PathBuf>,
) {
    match value {
        serde_yaml::Value::String(path) => {
            let path = PathBuf::from(path);
            paths.push(if path.is_absolute() {
                path
            } else {
                compose_dir.join(path)
            });
        }
        serde_yaml::Value::Sequence(values) => {
            for value in values {
                append_env_file_value_paths(value, compose_dir, paths);
            }
        }
        serde_yaml::Value::Mapping(map) => {
            if let Some(path) = map
                .get(serde_yaml::Value::String("path".to_string()))
                .and_then(serde_yaml::Value::as_str)
            {
                let path = PathBuf::from(path);
                paths.push(if path.is_absolute() {
                    path
                } else {
                    compose_dir.join(path)
                });
            }
        }
        _ => {}
    }
}

fn ensure_compose_env_files_if_needed(compose_path: &Path) -> Result<(), CliError> {
    for env_path in collect_compose_env_file_paths(compose_path)? {
        ensure_env_file_from_example(&env_path, "compose env_file")?;
    }
    Ok(())
}

/// SSH connection timeout for server pre-check (seconds).
const SSH_CHECK_TIMEOUT_SECS: u64 = 4;

/// Resolve the path to an SSH key, expanding `~` to the user's home directory.
fn resolve_ssh_key_path(key_path: &Path) -> PathBuf {
    let path_str = key_path.to_string_lossy();
    if path_str.starts_with("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(&path_str[2..]);
        }
    }
    key_path.to_path_buf()
}

/// Try SSH connection to the server defined in `deploy.server` and return
/// the system check result. Returns `None` if no server section is configured
/// or if the SSH key cannot be read.
fn try_ssh_server_check(server: &ServerConfig) -> Option<ssh_client::SystemCheckResult> {
    let ssh_key_path = match &server.ssh_key {
        Some(key) => resolve_ssh_key_path(key),
        None => {
            // Try default SSH key locations
            let home = match std::env::var("HOME") {
                Ok(h) => PathBuf::from(h),
                Err(_) => {
                    eprintln!("  Cannot determine home directory for SSH key lookup");
                    return None;
                }
            };
            let candidates = [home.join(".ssh/id_ed25519"), home.join(".ssh/id_rsa")];
            match candidates.iter().find(|p| p.exists()) {
                Some(p) => p.clone(),
                None => {
                    eprintln!("  No SSH key specified and no default key found (~/.ssh/id_ed25519 or ~/.ssh/id_rsa)");
                    return None;
                }
            }
        }
    };

    let key_content = match std::fs::read_to_string(&ssh_key_path) {
        Ok(content) => content,
        Err(e) => {
            eprintln!("  Cannot read SSH key {}: {}", ssh_key_path.display(), e);
            return None;
        }
    };

    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("  Failed to initialize async runtime for SSH check: {}", e);
            return None;
        }
    };

    let result = rt.block_on(ssh_client::check_server(
        &server.host,
        server.port,
        &server.user,
        &key_content,
        Duration::from_secs(SSH_CHECK_TIMEOUT_SECS),
    ));

    Some(result)
}

/// Print a helpful message when the existing server is not reachable,
/// suggesting how to fix or proceed with a new cloud server.
fn print_server_unreachable_hint(server: &ServerConfig, check: &ssh_client::SystemCheckResult) {
    eprintln!();
    eprintln!("  ╭─ Existing server check failed ──────────────────────────────────╮");
    eprintln!("  │ Host: {}:{}", server.host, server.port);
    eprintln!("  │ User: {}", server.user);
    if let Some(ref err) = check.error {
        eprintln!("  │ Error: {}", err);
    }
    eprintln!("  ├─────────────────────────────────────────────────────────────────┤");
    eprintln!("  │ To deploy to this server, fix the connection issue and retry:   │");
    eprintln!("  │                                                                 │");
    if let Some(ref key) = server.ssh_key {
        eprintln!(
            "  │   ssh -i {} -p {} {}@{}",
            key.display(),
            server.port,
            server.user,
            server.host
        );
    } else {
        eprintln!(
            "  │   ssh -p {} {}@{}",
            server.port, server.user, server.host
        );
    }
    eprintln!("  │                                                                 │");
    eprintln!("  │ Or, to provision a new cloud server instead, remove the         │");
    eprintln!("  │ 'server' section from stacker.yml and re-run:                   │");
    eprintln!("  │                                                                 │");
    eprintln!("  │   stacker deploy --target cloud                                 │");
    eprintln!("  ╰─────────────────────────────────────────────────────────────────╯");
    eprintln!();
}

fn normalize_generated_compose_paths(compose_path: &Path) -> Result<(), CliError> {
    let is_stacker_compose = compose_path
        .components()
        .any(|c| c.as_os_str() == OUTPUT_DIR);

    if !is_stacker_compose || !compose_path.exists() {
        return Ok(());
    }

    let raw = std::fs::read_to_string(compose_path)?;
    let mut doc: serde_yaml::Value = serde_yaml::from_str(&raw)
        .map_err(|e| CliError::ConfigValidation(format!("Failed to parse compose file: {e}")))?;

    let mut changed = false;

    if let serde_yaml::Value::Mapping(ref mut root) = doc {
        // Remove obsolete compose version key.
        if root
            .remove(serde_yaml::Value::String("version".to_string()))
            .is_some()
        {
            changed = true;
        }

        let services_key = serde_yaml::Value::String("services".to_string());
        if let Some(serde_yaml::Value::Mapping(services)) = root.get_mut(&services_key) {
            for (service_key, service_value) in services.iter_mut() {
                let service_name = service_key.as_str().unwrap_or("");
                let service_map = match service_value {
                    serde_yaml::Value::Mapping(m) => m,
                    _ => continue,
                };

                let build_key = serde_yaml::Value::String("build".to_string());
                let build_val = match service_map.get_mut(&build_key) {
                    Some(v) => v,
                    None => continue,
                };

                let build_map = match build_val {
                    serde_yaml::Value::Mapping(m) => m,
                    _ => continue,
                };

                let context_key = serde_yaml::Value::String("context".to_string());
                let dockerfile_key = serde_yaml::Value::String("dockerfile".to_string());

                let current_context = build_map
                    .get(&context_key)
                    .and_then(|v| v.as_str())
                    .unwrap_or(".")
                    .to_string();

                let dockerfile = build_map
                    .get(&dockerfile_key)
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                let dockerfile_points_to_stacker = dockerfile
                    .as_deref()
                    .map(|d| d.starts_with(".stacker/"))
                    .unwrap_or(false);

                if dockerfile_points_to_stacker
                    && (current_context == "." || current_context == "./")
                {
                    build_map.insert(
                        context_key.clone(),
                        serde_yaml::Value::String("..".to_string()),
                    );
                    changed = true;
                }

                if service_name == "app" && (current_context == "." || current_context == "./") {
                    build_map.insert(context_key, serde_yaml::Value::String("..".to_string()));

                    let dockerfile_needs_rewrite = match dockerfile.as_deref() {
                        None => true,
                        Some("Dockerfile") | Some("./Dockerfile") => true,
                        _ => false,
                    };

                    if dockerfile_needs_rewrite {
                        build_map.insert(
                            dockerfile_key,
                            serde_yaml::Value::String(".stacker/Dockerfile".to_string()),
                        );
                    }

                    changed = true;
                }
            }
        }
    }

    if changed {
        let updated = serde_yaml::to_string(&doc).map_err(|e| {
            CliError::ConfigValidation(format!("Failed to serialize compose file: {e}"))
        })?;
        std::fs::write(compose_path, updated)?;
        eprintln!("  Normalized {}/docker-compose.yml paths", OUTPUT_DIR);
    }

    Ok(())
}

fn validate_compose_for_deploy(compose_path: &Path) -> Result<(), CliError> {
    let raw = std::fs::read_to_string(compose_path)?;
    let doc: serde_yaml::Value = serde_yaml::from_str(&raw)
        .map_err(|e| CliError::ConfigValidation(format!("Failed to parse compose file: {e}")))?;

    let root = match doc {
        serde_yaml::Value::Mapping(m) => m,
        _ => {
            return Err(CliError::ConfigValidation(
                "Compose file must be a YAML mapping at the top level".to_string(),
            ))
        }
    };

    let services_key = serde_yaml::Value::String("services".to_string());
    let include_key = serde_yaml::Value::String("include".to_string());
    let services = match root.get(&services_key) {
        Some(serde_yaml::Value::Mapping(m)) => Some(m),
        _ => None,
    };

    if services.is_none() {
        match root.get(&include_key) {
            Some(serde_yaml::Value::Sequence(_)) | Some(serde_yaml::Value::String(_)) => {
                return Ok(());
            }
            _ => {
                return Err(CliError::ConfigValidation(
                    "Compose file must define a top-level services mapping".to_string(),
                ))
            }
        }
    }

    let services = services.expect("services checked above");

    let mut published_ports: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();

    for (service_key, service_value) in services {
        let service_name = service_key.as_str().unwrap_or("<unknown>").to_string();
        let service_map = match service_value {
            serde_yaml::Value::Mapping(m) => m,
            _ => continue,
        };

        let ports_key = serde_yaml::Value::String("ports".to_string());
        let Some(serde_yaml::Value::Sequence(ports)) = service_map.get(&ports_key) else {
            continue;
        };

        for port in ports {
            if let Some(host_port) = extract_published_host_port(port) {
                published_ports
                    .entry(host_port)
                    .or_default()
                    .push(service_name.clone());
            }
        }
    }

    let collisions: Vec<String> = published_ports
        .into_iter()
        .filter_map(|(port, services)| {
            if services.len() > 1 {
                Some(format!(
                    "port {} is published by {}",
                    port,
                    services.join(", ")
                ))
            } else {
                None
            }
        })
        .collect();

    if collisions.is_empty() {
        Ok(())
    } else {
        Err(CliError::ConfigValidation(format!(
            "Compose file has conflicting published host ports: {}",
            collisions.join("; ")
        )))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ComposeImageRef {
    image: String,
    service_name: String,
    source_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DockerHubImageTarget {
    original: String,
    namespace: Option<String>,
    repository: String,
    tag: String,
}

impl DockerHubImageTarget {
    fn display_name(&self) -> String {
        match &self.namespace {
            Some(namespace) => format!("docker.io/{}/{}:{}", namespace, self.repository, self.tag),
            None => format!("docker.io/library/{}:{}", self.repository, self.tag),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RequiredImagePlatform {
    os: String,
    architecture: String,
}

impl RequiredImagePlatform {
    fn linux_amd64() -> Self {
        Self {
            os: "linux".to_string(),
            architecture: "amd64".to_string(),
        }
    }

    fn display_name(&self) -> String {
        format!("{}/{}", self.os, self.architecture)
    }

    fn matches(&self, image: &DockerHubTagImage) -> bool {
        image
            .os
            .as_deref()
            .map(|os| os.eq_ignore_ascii_case(&self.os))
            .unwrap_or(false)
            && image
                .architecture
                .as_deref()
                .map(|architecture| architecture.eq_ignore_ascii_case(&self.architecture))
                .unwrap_or(false)
    }
}

fn required_image_platform_for_deploy_target(
    deploy_target: &DeployTarget,
) -> Option<RequiredImagePlatform> {
    match deploy_target {
        DeployTarget::Cloud | DeployTarget::Server => Some(RequiredImagePlatform::linux_amd64()),
        DeployTarget::Local => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DockerHubImageCheckResult {
    Available,
    Missing,
    MissingPlatform {
        required: RequiredImagePlatform,
        available: Vec<String>,
    },
}

#[derive(Debug, serde::Deserialize)]
struct DockerHubTagDetails {
    #[serde(default)]
    images: Vec<DockerHubTagImage>,
}

#[derive(Debug, serde::Deserialize)]
struct DockerHubTagImage {
    architecture: Option<String>,
    os: Option<String>,
}

fn available_docker_hub_platforms(images: &[DockerHubTagImage]) -> Vec<String> {
    let mut platforms = std::collections::BTreeSet::new();

    for image in images {
        let Some(os) = image.os.as_deref() else {
            continue;
        };
        let Some(architecture) = image.architecture.as_deref() else {
            continue;
        };
        let os = os.trim();
        let architecture = architecture.trim();
        if os.is_empty() || architecture.is_empty() {
            continue;
        }
        platforms.insert(format!("{}/{}", os, architecture));
    }

    platforms.into_iter().collect()
}
fn validate_compose_images_for_deploy(
    compose_path: &Path,
    registry: Option<&RegistryConfig>,
    image_env: &std::collections::BTreeMap<String, String>,
    required_platform: Option<&RequiredImagePlatform>,
) -> Result<(), CliError> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| {
            CliError::ConfigValidation(format!("Failed to create async runtime: {}", e))
        })?;

    validate_compose_images_for_deploy_with_checker(
        compose_path,
        image_env,
        required_platform,
        |target| {
            rt.block_on(check_docker_hub_image_exists(
                target,
                registry,
                required_platform,
            ))
        },
    )
}

fn validate_compose_images_for_deploy_with_checker<F>(
    compose_path: &Path,
    image_env: &std::collections::BTreeMap<String, String>,
    required_platform: Option<&RequiredImagePlatform>,
    mut checker: F,
) -> Result<(), CliError>
where
    F: FnMut(&DockerHubImageTarget) -> Result<DockerHubImageCheckResult, String>,
{
    let images = collect_compose_image_refs(compose_path)?;
    let mut problems = Vec::new();

    for image_ref in images {
        let resolved_image =
            resolve_compose_image_reference(&image_ref.image, image_env).map_err(|err| {
                CliError::ConfigValidation(format!(
                    "Failed to resolve image for service '{}' in {}: {}",
                    image_ref.service_name,
                    image_ref.source_path.display(),
                    err
                ))
            })?;

        let Some(target) = parse_docker_hub_image_target(&resolved_image) else {
            continue;
        };

        match checker(&target) {
            Ok(DockerHubImageCheckResult::Available) => {}
            Ok(DockerHubImageCheckResult::Missing) => problems.push(format!(
                "{} (service '{}' in {})",
                target.display_name(),
                image_ref.service_name,
                image_ref.source_path.display()
            )),
            Ok(DockerHubImageCheckResult::MissingPlatform {
                required,
                available,
            }) => {
                let available_suffix = if available.is_empty() {
                    String::new()
                } else {
                    format!("; available platforms: {}", available.join(", "))
                };
                problems.push(format!(
                    "{} (service '{}' in {}) does not publish required platform {}{}",
                    target.display_name(),
                    image_ref.service_name,
                    image_ref.source_path.display(),
                    required.display_name(),
                    available_suffix
                ));
            }
            Err(err) => eprintln!(
                "  Warning: could not verify image {} before deploy: {}",
                target.display_name(),
                err
            ),
        }
    }

    if problems.is_empty() {
        Ok(())
    } else if let Some(required_platform) = required_platform {
        Err(CliError::ConfigValidation(format!(
            "Compose image preflight failed. These images are missing, inaccessible, or incompatible with required platform {}: {}",
            required_platform.display_name(),
            problems.join("; ")
        )))
    } else {
        Err(CliError::ConfigValidation(format!(
            "Compose image preflight failed. These images are missing or inaccessible: {}",
            problems.join("; ")
        )))
    }
}

fn print_registry_auth_guidance_if_needed(
    compose_path: &Path,
    config: &StackerConfig,
    image_env: &std::collections::BTreeMap<String, String>,
) -> Result<(), CliError> {
    let registry_creds = resolve_docker_registry_credentials(config);
    if registry_creds.contains_key("docker_username")
        && registry_creds.contains_key("docker_password")
    {
        return Ok(());
    }

    let images = collect_registry_auth_candidate_images(compose_path, image_env)?;
    if images.is_empty() {
        return Ok(());
    }

    eprintln!("  Registry auth: no deploy registry credentials were resolved.");
    eprintln!(
        "    If these images are private, set STACKER_DOCKER_USERNAME, STACKER_DOCKER_PASSWORD, and STACKER_DOCKER_REGISTRY, or configure deploy.registry."
    );
    eprintln!("    Candidate image(s): {}", images.join(", "));
    Ok(())
}

fn collect_registry_auth_candidate_images(
    compose_path: &Path,
    image_env: &std::collections::BTreeMap<String, String>,
) -> Result<Vec<String>, CliError> {
    let mut candidates = Vec::new();
    let mut seen = std::collections::BTreeSet::new();

    for image_ref in collect_compose_image_refs(compose_path)? {
        let resolved_image =
            resolve_compose_image_reference(&image_ref.image, image_env).map_err(|err| {
                CliError::ConfigValidation(format!(
                    "Failed to resolve image for service '{}' in {}: {}",
                    image_ref.service_name,
                    image_ref.source_path.display(),
                    err
                ))
            })?;
        if image_may_require_registry_auth(&resolved_image) && seen.insert(resolved_image.clone()) {
            candidates.push(resolved_image);
        }
    }

    Ok(candidates)
}

fn image_may_require_registry_auth(image: &str) -> bool {
    let image = image.trim();
    if image.is_empty() {
        return false;
    }

    let without_digest = image.split('@').next().unwrap_or(image);
    let (without_tag, _) = split_image_tag(without_digest);
    let parts: Vec<&str> = without_tag.split('/').collect();
    if parts.len() > 1 && is_registry_host(parts[0]) {
        return !is_docker_hub_host(parts[0]) || parts.len() > 2;
    }

    parts.len() == 2 && parts[0] != "library"
}

fn collect_compose_image_refs(compose_path: &Path) -> Result<Vec<ComposeImageRef>, CliError> {
    let mut visited = std::collections::BTreeSet::new();
    let mut images = Vec::new();
    collect_compose_image_refs_from_file(compose_path, &mut visited, &mut images)?;
    Ok(images)
}

fn collect_compose_image_refs_from_file(
    compose_path: &Path,
    visited: &mut std::collections::BTreeSet<PathBuf>,
    images: &mut Vec<ComposeImageRef>,
) -> Result<(), CliError> {
    let visited_key =
        std::fs::canonicalize(compose_path).unwrap_or_else(|_| compose_path.to_path_buf());
    if !visited.insert(visited_key) {
        return Ok(());
    }

    let raw = std::fs::read_to_string(compose_path)?;
    let doc: serde_yaml::Value = serde_yaml::from_str(&raw)
        .map_err(|e| CliError::ConfigValidation(format!("Failed to parse compose file: {e}")))?;

    let root = match doc {
        serde_yaml::Value::Mapping(m) => m,
        _ => {
            return Err(CliError::ConfigValidation(
                "Compose file must be a YAML mapping at the top level".to_string(),
            ))
        }
    };

    let services_key = serde_yaml::Value::String("services".to_string());
    let build_key = serde_yaml::Value::String("build".to_string());
    let image_key = serde_yaml::Value::String("image".to_string());

    if let Some(serde_yaml::Value::Mapping(services)) = root.get(&services_key) {
        for (service_key, service_value) in services {
            let service_name = service_key.as_str().unwrap_or("<unknown>").to_string();
            let service_map = match service_value {
                serde_yaml::Value::Mapping(m) => m,
                _ => continue,
            };

            if service_map.contains_key(&build_key) {
                continue;
            }

            let Some(image) = service_map.get(&image_key).and_then(|value| value.as_str()) else {
                continue;
            };

            images.push(ComposeImageRef {
                image: image.to_string(),
                service_name,
                source_path: compose_path.to_path_buf(),
            });
        }
    }

    for include_path in collect_compose_include_paths(&root, compose_path)? {
        if !include_path.exists() {
            return Err(CliError::ConfigValidation(format!(
                "Included compose file not found: {}",
                include_path.display()
            )));
        }
        collect_compose_image_refs_from_file(&include_path, visited, images)?;
    }

    Ok(())
}

fn collect_compose_include_paths(
    root: &serde_yaml::Mapping,
    compose_path: &Path,
) -> Result<Vec<PathBuf>, CliError> {
    let include_key = serde_yaml::Value::String("include".to_string());
    let Some(include_value) = root.get(&include_key) else {
        return Ok(Vec::new());
    };

    let compose_dir = compose_path.parent().unwrap_or_else(|| Path::new("."));
    let mut paths = Vec::new();
    append_compose_include_paths(include_value, compose_dir, &mut paths)?;
    Ok(paths)
}

fn append_compose_include_paths(
    value: &serde_yaml::Value,
    compose_dir: &Path,
    output: &mut Vec<PathBuf>,
) -> Result<(), CliError> {
    match value {
        serde_yaml::Value::String(path) => {
            let path = PathBuf::from(path);
            output.push(if path.is_absolute() {
                path
            } else {
                compose_dir.join(path)
            });
        }
        serde_yaml::Value::Sequence(entries) => {
            for entry in entries {
                append_compose_include_paths(entry, compose_dir, output)?;
            }
        }
        serde_yaml::Value::Mapping(map) => {
            let path_key = serde_yaml::Value::String("path".to_string());
            if let Some(path_value) = map.get(&path_key) {
                append_compose_include_paths(path_value, compose_dir, output)?;
            }
        }
        _ => {}
    }

    Ok(())
}

fn parse_docker_hub_image_target(image: &str) -> Option<DockerHubImageTarget> {
    let image = image.trim();
    if image.is_empty() {
        return None;
    }

    let without_digest = image.split('@').next().unwrap_or(image);
    let (without_tag, tag) = split_image_tag(without_digest);
    let parts: Vec<&str> = without_tag.split('/').collect();

    let remainder = if parts.len() > 1 && is_registry_host(parts[0]) {
        if !is_docker_hub_host(parts[0]) {
            return None;
        }
        &parts[1..]
    } else {
        &parts[..]
    };

    match remainder {
        [repo] => Some(DockerHubImageTarget {
            original: image.to_string(),
            namespace: None,
            repository: (*repo).to_string(),
            tag,
        }),
        [namespace, repo] if *namespace == "library" => Some(DockerHubImageTarget {
            original: image.to_string(),
            namespace: None,
            repository: (*repo).to_string(),
            tag,
        }),
        [namespace, repo] => Some(DockerHubImageTarget {
            original: image.to_string(),
            namespace: Some((*namespace).to_string()),
            repository: (*repo).to_string(),
            tag,
        }),
        _ => None,
    }
}

fn split_image_tag(image: &str) -> (&str, String) {
    if let Some(pos) = image.rfind(':') {
        let after_colon = &image[pos + 1..];
        if !after_colon.contains('/') {
            return (&image[..pos], after_colon.to_string());
        }
    }
    (image, "latest".to_string())
}

fn is_registry_host(segment: &str) -> bool {
    segment.contains('.') || segment.contains(':') || segment.eq_ignore_ascii_case("localhost")
}

fn is_docker_hub_host(segment: &str) -> bool {
    let lower = segment
        .trim()
        .trim_end_matches('/')
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .to_ascii_lowercase();
    lower == "docker.io"
        || lower == "hub.docker.com"
        || lower == "index.docker.io"
        || lower == "index.docker.io/v1"
        || lower == "registry-1.docker.io"
}

fn docker_hub_auth(registry: Option<&RegistryConfig>) -> Option<(&str, &str)> {
    let registry = registry?;
    let username = registry.username.as_deref()?.trim();
    let password = registry.password.as_deref()?.trim();

    if username.is_empty() || password.is_empty() {
        return None;
    }

    let uses_docker_hub = registry
        .server
        .as_deref()
        .map(is_docker_hub_host)
        .unwrap_or(true);
    if uses_docker_hub {
        Some((username, password))
    } else {
        None
    }
}

async fn check_docker_hub_image_exists(
    target: &DockerHubImageTarget,
    registry: Option<&RegistryConfig>,
    required_platform: Option<&RequiredImagePlatform>,
) -> Result<DockerHubImageCheckResult, String> {
    let client = reqwest::Client::new();
    let auth_token = if let Some((username, password)) = docker_hub_auth(registry) {
        Some(login_to_docker_hub(&client, username, password).await?)
    } else {
        None
    };

    let url = match &target.namespace {
        Some(namespace) => format!(
            "https://hub.docker.com/v2/namespaces/{}/repositories/{}/tags/{}",
            namespace, target.repository, target.tag
        ),
        None => format!(
            "https://hub.docker.com/v2/repositories/library/{}/tags/{}",
            target.repository, target.tag
        ),
    };

    let mut request = client.get(url).header("Accept", "application/json");
    if let Some(token) = auth_token {
        request = request.bearer_auth(token);
    }

    let response = request.send().await.map_err(|e| e.to_string())?;
    let status = response.status();
    if status.is_success() {
        if let Some(required_platform) = required_platform {
            let body: DockerHubTagDetails = response.json().await.map_err(|e| e.to_string())?;
            if !body.images.is_empty()
                && !body
                    .images
                    .iter()
                    .any(|image| required_platform.matches(image))
            {
                return Ok(DockerHubImageCheckResult::MissingPlatform {
                    required: required_platform.clone(),
                    available: available_docker_hub_platforms(&body.images),
                });
            }
        }

        Ok(DockerHubImageCheckResult::Available)
    } else if status == reqwest::StatusCode::NOT_FOUND
        || status == reqwest::StatusCode::UNAUTHORIZED
        || status == reqwest::StatusCode::FORBIDDEN
    {
        Ok(DockerHubImageCheckResult::Missing)
    } else {
        Err(format!("Docker Hub API returned {}", status))
    }
}

async fn login_to_docker_hub(
    client: &reqwest::Client,
    username: &str,
    password: &str,
) -> Result<String, String> {
    let response = client
        .post("https://hub.docker.com/v2/users/login")
        .json(&serde_json::json!({
            "username": username,
            "password": password,
        }))
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if !response.status().is_success() {
        return Err(format!(
            "Docker Hub login failed with status {}",
            response.status()
        ));
    }

    let body: serde_json::Value = response.json().await.map_err(|e| e.to_string())?;
    body.get("token")
        .and_then(|value| value.as_str())
        .map(|token| token.to_string())
        .ok_or_else(|| "Docker Hub login response did not include a token".to_string())
}

fn build_image_env_lookup(
    project_dir: &Path,
    config: &StackerConfig,
) -> Result<std::collections::BTreeMap<String, String>, CliError> {
    let mut env_map = std::collections::BTreeMap::new();

    if let Some(env_file) = &config.env_file {
        let env_path = if env_file.is_absolute() {
            env_file.clone()
        } else {
            project_dir.join(env_file)
        };

        if env_path.exists() {
            let iter = dotenvy::from_path_iter(&env_path).map_err(|e| {
                CliError::ConfigValidation(format!(
                    "Failed to read env file {}: {}",
                    env_path.display(),
                    e
                ))
            })?;

            for item in iter {
                let (key, value) = item.map_err(|e| {
                    CliError::ConfigValidation(format!(
                        "Failed to parse env file {}: {}",
                        env_path.display(),
                        e
                    ))
                })?;
                env_map.insert(key, value);
            }
        }
    }

    for (key, value) in &config.env {
        env_map.insert(key.clone(), value.clone());
    }

    for (key, value) in std::env::vars() {
        env_map.insert(key, value);
    }

    Ok(env_map)
}

fn merge_compose_public_ports_into_app_config(
    config: &mut StackerConfig,
    compose_path: &Path,
    env_lookup: &std::collections::BTreeMap<String, String>,
) -> Result<(), CliError> {
    let compose_ports = extract_compose_public_port_specs(compose_path, env_lookup)?;
    if compose_ports.is_empty() {
        return Ok(());
    }

    let mut seen = std::collections::BTreeSet::new();
    let mut merged = Vec::new();

    for port in &config.app.ports {
        if seen.insert(port.clone()) {
            merged.push(port.clone());
        }
    }

    for port in compose_ports {
        if seen.insert(port.clone()) {
            merged.push(port);
        }
    }

    config.app.ports = merged;
    Ok(())
}

fn extract_compose_public_port_specs(
    compose_path: &Path,
    env_lookup: &std::collections::BTreeMap<String, String>,
) -> Result<Vec<String>, CliError> {
    let raw = std::fs::read_to_string(compose_path).map_err(|err| {
        CliError::ConfigValidation(format!(
            "Failed to read compose file {}: {}",
            compose_path.display(),
            err
        ))
    })?;
    let doc: serde_yaml::Value = serde_yaml::from_str(&raw).map_err(|err| {
        CliError::ConfigValidation(format!(
            "Failed to parse compose file {}: {}",
            compose_path.display(),
            err
        ))
    })?;

    let services = doc
        .as_mapping()
        .and_then(|root| root.get(serde_yaml::Value::String("services".to_string())))
        .and_then(serde_yaml::Value::as_mapping);

    let Some(services) = services else {
        return Ok(Vec::new());
    };

    let mut seen = std::collections::BTreeSet::new();
    let mut ports = Vec::new();

    for service_value in services.values() {
        let Some(service_map) = service_value.as_mapping() else {
            continue;
        };
        let Some(port_values) = service_map
            .get(serde_yaml::Value::String("ports".to_string()))
            .and_then(serde_yaml::Value::as_sequence)
        else {
            continue;
        };

        for port_value in port_values {
            if let Some(spec) = compose_public_port_spec(port_value, env_lookup) {
                if seen.insert(spec.clone()) {
                    ports.push(spec);
                }
            }
        }
    }

    Ok(ports)
}

fn compose_public_port_spec(
    port_value: &serde_yaml::Value,
    env_lookup: &std::collections::BTreeMap<String, String>,
) -> Option<String> {
    match port_value {
        serde_yaml::Value::String(spec) => short_compose_public_port_spec(spec, env_lookup),
        serde_yaml::Value::Mapping(mapping) => long_compose_public_port_spec(mapping, env_lookup),
        _ => None,
    }
}

fn long_compose_public_port_spec(
    mapping: &serde_yaml::Mapping,
    env_lookup: &std::collections::BTreeMap<String, String>,
) -> Option<String> {
    let host_ip = yaml_scalar_as_string(mapping, "host_ip")
        .map(|value| resolve_compose_port_env(&value, env_lookup));
    if host_ip
        .as_deref()
        .is_some_and(|value| !is_public_compose_host_ip(value))
    {
        return None;
    }

    let protocol = yaml_scalar_as_string(mapping, "protocol")
        .unwrap_or_else(|| "tcp".to_string())
        .to_ascii_lowercase();
    if protocol != "tcp" {
        return None;
    }

    let published = yaml_scalar_as_string(mapping, "published")
        .map(|value| resolve_compose_port_env(&value, env_lookup))?;
    let target = yaml_scalar_as_string(mapping, "target")
        .map(|value| resolve_compose_port_env(&value, env_lookup))?;

    format_compose_public_port_spec(&published, &target)
}

fn short_compose_public_port_spec(
    spec: &str,
    env_lookup: &std::collections::BTreeMap<String, String>,
) -> Option<String> {
    let resolved = resolve_compose_port_env(spec.trim(), env_lookup);
    let without_protocol = match resolved.rsplit_once('/') {
        Some((port_spec, protocol)) if protocol.eq_ignore_ascii_case("tcp") => port_spec,
        Some(_) => return None,
        None => resolved.as_str(),
    };

    let (host_ip, host_port, container_port) = split_short_compose_port_spec(without_protocol)?;
    if host_ip.is_some_and(|value| !is_public_compose_host_ip(&value)) {
        return None;
    }

    format_compose_public_port_spec(&host_port, &container_port)
}

fn split_short_compose_port_spec(spec: &str) -> Option<(Option<String>, String, String)> {
    let trimmed = spec.trim();
    if trimmed.is_empty() {
        return None;
    }

    let parts = split_compose_port_parts(trimmed);
    match parts.len() {
        0 | 1 => None,
        2 => Some((None, parts[0].clone(), parts[1].clone())),
        _ => {
            let host_ip = parts[..parts.len() - 2].join(":");
            Some((
                Some(host_ip),
                parts[parts.len() - 2].clone(),
                parts[parts.len() - 1].clone(),
            ))
        }
    }
}

fn split_compose_port_parts(spec: &str) -> Vec<String> {
    let trimmed = spec.trim();
    if let Some(rest) = trimmed.strip_prefix('[') {
        if let Some(closing) = rest.find(']') {
            let host_ip = &rest[..closing];
            let after_bracket = rest[closing + 1..].trim_start_matches(':');
            let mut parts = vec![host_ip.to_string()];
            parts.extend(after_bracket.split(':').map(ToOwned::to_owned));
            return parts;
        }
    }

    trimmed.split(':').map(ToOwned::to_owned).collect()
}

fn yaml_scalar_as_string(mapping: &serde_yaml::Mapping, key: &str) -> Option<String> {
    mapping
        .get(serde_yaml::Value::String(key.to_string()))
        .and_then(|value| match value {
            serde_yaml::Value::String(value) => Some(value.clone()),
            serde_yaml::Value::Number(value) => Some(value.to_string()),
            _ => None,
        })
}

fn format_compose_public_port_spec(host_port: &str, container_port: &str) -> Option<String> {
    let host_port = host_port.trim();
    let container_port = container_port.trim();

    if !is_valid_tcp_port(host_port) || !is_valid_tcp_port(container_port) {
        return None;
    }

    Some(format!("{}:{}", host_port, container_port))
}

fn is_valid_tcp_port(value: &str) -> bool {
    value
        .parse::<u16>()
        .is_ok_and(|port| (1..=65535).contains(&port))
}

fn is_public_compose_host_ip(value: &str) -> bool {
    let normalized = value
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .trim_start_matches('[')
        .trim_end_matches(']');

    matches!(normalized, "" | "0.0.0.0" | "::" | "*")
}

fn resolve_compose_port_env(
    value: &str,
    env_lookup: &std::collections::BTreeMap<String, String>,
) -> String {
    let mut result = String::with_capacity(value.len());
    let mut rest = value;

    while let Some(start) = rest.find("${") {
        result.push_str(&rest[..start]);
        let after_start = &rest[start + 2..];
        let Some(end) = after_start.find('}') else {
            result.push_str(&rest[start..]);
            return result;
        };

        let expression = &after_start[..end];
        result.push_str(&resolve_compose_port_env_expression(expression, env_lookup));
        rest = &after_start[end + 1..];
    }

    result.push_str(rest);
    result
}

fn resolve_compose_port_env_expression(
    expression: &str,
    env_lookup: &std::collections::BTreeMap<String, String>,
) -> String {
    for separator in [":-", "-"] {
        if let Some((name, fallback)) = expression.split_once(separator) {
            return env_lookup
                .get(name)
                .filter(|value| !value.is_empty() || separator == "-")
                .cloned()
                .unwrap_or_else(|| fallback.to_string());
        }
    }

    env_lookup.get(expression).cloned().unwrap_or_default()
}

fn resolve_compose_image_reference(
    value: &str,
    vars: &std::collections::BTreeMap<String, String>,
) -> Result<String, String> {
    let mut output = String::new();
    let mut cursor = 0usize;

    while let Some(relative_start) = value[cursor..].find("${") {
        let start = cursor + relative_start;
        output.push_str(&value[cursor..start]);

        let expr_start = start + 2;
        let Some(relative_end) = value[expr_start..].find('}') else {
            return Err(format!("unterminated variable expression in '{}'", value));
        };
        let end = expr_start + relative_end;
        let expr = &value[expr_start..end];
        output.push_str(&resolve_compose_variable_expression(expr, vars)?);
        cursor = end + 1;
    }

    output.push_str(&value[cursor..]);
    let trimmed = output.trim();
    if trimmed.is_empty() {
        Err(format!(
            "image reference '{}' resolved to an empty value",
            value
        ))
    } else {
        Ok(trimmed.to_string())
    }
}

fn resolve_compose_variable_expression(
    expr: &str,
    vars: &std::collections::BTreeMap<String, String>,
) -> Result<String, String> {
    if let Some((name, fallback)) = expr.split_once(":-") {
        return match vars.get(name) {
            Some(value) if !value.is_empty() => Ok(value.clone()),
            _ => Ok(fallback.to_string()),
        };
    }

    if let Some((name, fallback)) = expr.split_once('-') {
        return match vars.get(name) {
            Some(value) => Ok(value.clone()),
            None => Ok(fallback.to_string()),
        };
    }

    if let Some((name, message)) = expr.split_once(":?") {
        return match vars.get(name) {
            Some(value) if !value.is_empty() => Ok(value.clone()),
            _ => Err(if message.is_empty() {
                format!("required variable {} is not set", name)
            } else {
                message.to_string()
            }),
        };
    }

    if let Some((name, message)) = expr.split_once('?') {
        return match vars.get(name) {
            Some(value) => Ok(value.clone()),
            None => Err(if message.is_empty() {
                format!("required variable {} is not set", name)
            } else {
                message.to_string()
            }),
        };
    }

    vars.get(expr)
        .cloned()
        .ok_or_else(|| format!("variable {} is not set", expr))
}

fn extract_published_host_port(port: &serde_yaml::Value) -> Option<String> {
    match port {
        serde_yaml::Value::String(spec) => extract_host_port_from_string(spec),
        serde_yaml::Value::Mapping(m) => {
            let published_key = serde_yaml::Value::String("published".to_string());
            m.get(&published_key).and_then(|value| match value {
                serde_yaml::Value::String(s) => Some(s.clone()),
                serde_yaml::Value::Number(n) => Some(n.to_string()),
                _ => None,
            })
        }
        _ => None,
    }
}

fn extract_host_port_from_string(spec: &str) -> Option<String> {
    let trimmed = spec.trim();
    if trimmed.is_empty() {
        return None;
    }

    let without_protocol = trimmed.split('/').next().unwrap_or(trimmed);
    let parts: Vec<&str> = without_protocol.split(':').collect();

    if parts.len() < 2 {
        return None;
    }

    parts
        .get(parts.len().saturating_sub(2))
        .map(|part| part.trim().to_string())
        .filter(|part| !part.is_empty())
}

/// Detect host-port collisions between stacker.yml `services:` and a user-supplied compose file.
///
/// `config_with_compose_secret_target_services` merges compose services into the config by name,
/// so two services with different names but the same host port will both survive the merge and
/// cause Docker to fail at runtime.  This check catches that case locally before any remote
/// operation is attempted.
fn validate_cross_source_port_collisions(
    config: &crate::cli::config_parser::StackerConfig,
    compose_path: &Path,
) -> Result<(), CliError> {
    // Collect host-port → service-name mapping from stacker.yml services (and app).
    let mut stacker_port_owners: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    for svc in &config.services {
        for spec in &svc.ports {
            if let Some(port) = extract_host_port_from_string(spec) {
                stacker_port_owners
                    .entry(port)
                    .or_insert_with(|| svc.name.clone());
            }
        }
    }
    for spec in &config.app.ports {
        if let Some(port) = extract_host_port_from_string(spec) {
            stacker_port_owners.entry(port).or_insert_with(|| "app".to_string());
        }
    }

    if stacker_port_owners.is_empty() {
        return Ok(());
    }

    // Parse the compose file and look for the same host ports.
    let raw = std::fs::read_to_string(compose_path)?;
    let doc: serde_yaml::Value = serde_yaml::from_str(&raw)
        .map_err(|e| CliError::ConfigValidation(format!("Failed to parse compose file: {e}")))?;

    let root = match doc {
        serde_yaml::Value::Mapping(m) => m,
        _ => return Ok(()),
    };

    let services_key = serde_yaml::Value::String("services".to_string());
    let services = match root.get(&services_key) {
        Some(serde_yaml::Value::Mapping(m)) => m,
        _ => return Ok(()),
    };

    let mut collisions: Vec<String> = Vec::new();
    for (svc_key, svc_val) in services {
        let compose_svc = svc_key.as_str().unwrap_or("<unknown>");
        let svc_map = match svc_val {
            serde_yaml::Value::Mapping(m) => m,
            _ => continue,
        };
        let ports_key = serde_yaml::Value::String("ports".to_string());
        let Some(serde_yaml::Value::Sequence(ports)) = svc_map.get(&ports_key) else {
            continue;
        };
        for port in ports {
            if let Some(host_port) = extract_published_host_port(port) {
                if let Some(stacker_svc) = stacker_port_owners.get(&host_port) {
                    collisions.push(format!(
                        "port {} is used by '{}' in stacker.yml and '{}' in {}",
                        host_port,
                        stacker_svc,
                        compose_svc,
                        compose_path.display(),
                    ));
                }
            }
        }
    }

    if collisions.is_empty() {
        Ok(())
    } else {
        Err(CliError::ConfigValidation(format!(
            "Host-port collision between stacker.yml services and compose file — \
             both sources will be deployed together but share the same host port(s): {}. \
             Remove the duplicate service from one of the two files.",
            collisions.join("; ")
        )))
    }
}

fn compose_app_build_source(compose_path: &Path) -> Option<String> {
    let raw = std::fs::read_to_string(compose_path).ok()?;
    let doc: serde_yaml::Value = serde_yaml::from_str(&raw).ok()?;

    let root = match doc {
        serde_yaml::Value::Mapping(m) => m,
        _ => return None,
    };

    let services_key = serde_yaml::Value::String("services".to_string());
    let app_key = serde_yaml::Value::String("app".to_string());
    let build_key = serde_yaml::Value::String("build".to_string());
    let context_key = serde_yaml::Value::String("context".to_string());
    let dockerfile_key = serde_yaml::Value::String("dockerfile".to_string());

    let services = match root.get(&services_key) {
        Some(serde_yaml::Value::Mapping(m)) => m,
        _ => return None,
    };
    let app = match services.get(&app_key) {
        Some(serde_yaml::Value::Mapping(m)) => m,
        _ => return None,
    };
    let build = app.get(&build_key)?;

    let compose_dir = compose_path.parent().unwrap_or_else(|| Path::new("."));

    match build {
        serde_yaml::Value::String(context_str) => {
            let context_path = PathBuf::from(context_str);
            let context_abs = if context_path.is_absolute() {
                context_path
            } else {
                compose_dir.join(context_path)
            };
            let dockerfile_abs = context_abs.join("Dockerfile");
            Some(format!(
                "context={}, dockerfile={}",
                context_abs.display(),
                dockerfile_abs.display()
            ))
        }
        serde_yaml::Value::Mapping(build_map) => {
            let context_raw = build_map
                .get(&context_key)
                .and_then(|v| v.as_str())
                .unwrap_or(".");
            let dockerfile_raw = build_map
                .get(&dockerfile_key)
                .and_then(|v| v.as_str())
                .unwrap_or("Dockerfile");

            let context_path = PathBuf::from(context_raw);
            let context_abs = if context_path.is_absolute() {
                context_path
            } else {
                compose_dir.join(context_path)
            };

            let dockerfile_path = PathBuf::from(dockerfile_raw);
            let dockerfile_abs = if dockerfile_path.is_absolute() {
                dockerfile_path
            } else {
                context_abs.join(dockerfile_path)
            };

            Some(format!(
                "context={}, dockerfile={}",
                context_abs.display(),
                dockerfile_abs.display()
            ))
        }
        _ => None,
    }
}

fn build_troubleshoot_error_log(project_dir: &Path, reason: &str) -> String {
    let dockerfile_path = project_dir.join(OUTPUT_DIR).join("Dockerfile");
    let compose_path = project_dir.join(OUTPUT_DIR).join("docker-compose.yml");

    let dockerfile = std::fs::read_to_string(&dockerfile_path).unwrap_or_default();
    let compose = std::fs::read_to_string(&compose_path).unwrap_or_default();

    let dockerfile_snippet = if dockerfile.is_empty() {
        "(not found)".to_string()
    } else {
        dockerfile.chars().take(4000).collect()
    };

    let compose_snippet = if compose.is_empty() {
        "(not found)".to_string()
    } else {
        compose.chars().take(4000).collect()
    };

    format!(
        "Deploy error:\n{}\n\nGenerated Dockerfile (.stacker/Dockerfile):\n{}\n\nGenerated Compose (.stacker/docker-compose.yml):\n{}",
        reason, dockerfile_snippet, compose_snippet
    )
}

fn print_ai_deploy_help(project_dir: &Path, config_file: Option<&str>, err: &CliError) {
    let reason = match err {
        CliError::DeployFailed { reason, .. } => reason,
        _ => return,
    };

    eprintln!("\nTroubleshooting help:");

    let ai_config = match resolve_ai_from_env_or_config(project_dir, config_file) {
        Ok(cfg) => cfg,
        Err(load_err) => {
            eprintln!(
                "  Could not load AI config for troubleshooting: {}",
                load_err
            );
            for hint in fallback_troubleshooting_hints(reason) {
                eprintln!("  - {}", hint);
            }
            eprintln!(
                "  Tip: enable AI with stacker init --with-ai or set STACKER_AI_PROVIDER=ollama"
            );
            return;
        }
    };

    if !ai_config.enabled {
        eprintln!("  AI troubleshooting disabled (ai.enabled=false).");
        for hint in fallback_troubleshooting_hints(reason) {
            eprintln!("  - {}", hint);
        }
        eprintln!("  Tip: enable AI in stacker.yml if you want AI troubleshooting suggestions");
        return;
    }

    let error_log = build_troubleshoot_error_log(project_dir, reason);
    let ctx = PromptContext {
        project_type: None,
        files: vec![
            ".stacker/Dockerfile".to_string(),
            ".stacker/docker-compose.yml".to_string(),
        ],
        error_log: Some(error_log),
        current_config: None,
    };
    let (system, prompt) = build_prompt(AiTask::Troubleshoot, &ctx);

    if ai_config.provider == AiProviderType::Ollama {
        eprintln!("  AI suggestion (streaming from Ollama):");
        match ollama_complete_streaming(&ai_config, &prompt, &system) {
            Ok(answer) => {
                if answer.trim().is_empty() {
                    eprintln!("    (empty AI response)");
                }
                eprintln!();
            }
            Err(ai_err) => {
                eprintln!("  AI troubleshooting unavailable: {}", ai_err);
                for hint in fallback_troubleshooting_hints(reason) {
                    eprintln!("  - {}", hint);
                }
                eprintln!("  Tip: set STACKER_AI_PROVIDER=ollama and ensure Ollama is running");
            }
        }
        return;
    }

    eprintln!("  AI request in progress...");
    match create_provider(&ai_config).and_then(|provider| provider.complete(&prompt, &system)) {
        Ok(answer) => {
            eprintln!("  AI suggestion:");
            for line in answer.lines().take(20) {
                eprintln!("    {}", line);
            }
        }
        Err(ai_err) => {
            eprintln!("  AI troubleshooting unavailable: {}", ai_err);
            for hint in fallback_troubleshooting_hints(reason) {
                eprintln!("  - {}", hint);
            }
            eprintln!("  Tip: set STACKER_AI_PROVIDER=ollama and ensure Ollama is running");
        }
    }
}

/// Map a provider code string (as stored in CloudInfo.provider) to a `CloudProvider` enum.
///
/// Accepts both short codes ("htz", "do", "aws", "lo", "vu") and full names
/// ("hetzner", "digitalocean", "aws", "linode", "vultr").
fn cloud_provider_from_code(code: &str) -> Option<CloudProvider> {
    match code.to_lowercase().as_str() {
        "htz" | "hetzner" => Some(CloudProvider::Hetzner),
        "do" | "digitalocean" => Some(CloudProvider::Digitalocean),
        "aws" => Some(CloudProvider::Aws),
        "lo" | "linode" => Some(CloudProvider::Linode),
        "vu" | "vultr" => Some(CloudProvider::Vultr),
        _ => None,
    }
}

/// Interactively prompt the user to select a saved cloud credential when
/// no `deploy.cloud` section is present in stacker.yml.
///
/// - Fetches the list of saved clouds from the Stacker server.
/// - Presents an interactive `Select` menu with each cloud plus a
///   "Connect a new cloud provider" option at the end.
/// - Returns:
///   - `Ok(Some(cloud_info))` when the user picks an existing credential.
///   - `Ok(None)` when the user picks "Connect a new cloud provider".
///   - `Err(...)` on I/O or network errors.
fn prompt_select_cloud(
    base_url: &str,
    access_token: &str,
) -> Result<Option<stacker_client::CloudInfo>, CliError> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| {
            CliError::ConfigValidation(format!("Failed to create async runtime: {}", e))
        })?;

    let clouds = rt.block_on(async {
        let client = StackerClient::new(&base_url, access_token);
        client.list_clouds().await
    })?;

    const CONNECT_NEW: &str = "→  Connect a new cloud provider";

    if clouds.is_empty() {
        eprintln!();
        eprintln!("  No saved cloud credentials found.");
        eprintln!("  To add cloud credentials, export your provider token and redeploy:");
        eprintln!("    {}   # Hetzner", cloud_env::provider_cli_example("htz"));
        eprintln!(
            "    {}   # DigitalOcean",
            cloud_env::provider_cli_example("do")
        );
        eprintln!("    {}  # AWS", cloud_env::provider_cli_example("aws"));
        eprintln!();
        return Err(CliError::CloudProviderMissing);
    }

    // Column widths for the interactive cloud selection menu.
    const CLOUD_ID_WIDTH: usize = 6;
    const CLOUD_NAME_WIDTH: usize = 24;

    let mut items: Vec<String> = clouds
        .iter()
        .map(|c| {
            format!(
                "{:<width_id$} {:<width_name$} ({})",
                c.id,
                c.name,
                c.provider,
                width_id = CLOUD_ID_WIDTH,
                width_name = CLOUD_NAME_WIDTH
            )
        })
        .collect();
    items.push(CONNECT_NEW.to_string());

    eprintln!();
    eprintln!("  No cloud provider configured in stacker.yml.");
    if cfg!(test) || !std::io::stdin().is_terminal() {
        eprintln!("  Non-interactive shell detected; skipping cloud credential prompt.");
        eprintln!("  Re-run with --key <name> or --key-id <id>, or configure deploy.cloud with `stacker config setup cloud`.");
        return Err(CliError::CloudProviderMissing);
    }
    eprintln!("  Select a saved cloud credential to use for this deployment:");
    eprintln!();

    let selection = dialoguer::Select::new()
        .with_prompt("Cloud credential")
        .items(&items)
        .default(0)
        .interact()
        .map_err(|e| CliError::ConfigValidation(format!("Selection error: {}", e)))?;

    if selection == clouds.len() {
        // User chose "Connect a new cloud provider"
        return Ok(None);
    }

    Ok(Some(clouds.into_iter().nth(selection).expect(
        "selection index should be within bounds of clouds vector",
    )))
}

fn active_stacker_base_url(creds: &StoredCredentials) -> String {
    if let Some(server_url) = creds.server_url.as_deref() {
        return crate::cli::install_runner::normalize_stacker_server_url(server_url);
    }
    if let Ok(server_url) = std::env::var("STACKER_URL") {
        if !server_url.trim().is_empty() {
            return crate::cli::install_runner::normalize_stacker_server_url(&server_url);
        }
    }
    stacker_client::DEFAULT_STACKER_URL.to_string()
}

fn cloud_config_from_info(cloud_info: &stacker_client::CloudInfo) -> Result<CloudConfig, CliError> {
    merge_cloud_config_from_info(None, cloud_info)
}

fn merge_cloud_config_from_info(
    existing: Option<&CloudConfig>,
    cloud_info: &stacker_client::CloudInfo,
) -> Result<CloudConfig, CliError> {
    let provider = cloud_provider_from_code(&cloud_info.provider).ok_or_else(|| {
        CliError::ConfigValidation(format!(
            "Unrecognised cloud provider '{}' for credential '{}'. Supported providers: hetzner (htz), digitalocean (do), aws, linode (lo), vultr (vu).",
            cloud_info.provider, cloud_info.name
        ))
    })?;

    Ok(CloudConfig {
        provider,
        orchestrator: existing
            .map(|cloud| cloud.orchestrator)
            .unwrap_or(CloudOrchestrator::Remote),
        region: existing.and_then(|cloud| cloud.region.clone()),
        size: existing.and_then(|cloud| cloud.size.clone()),
        install_image: existing.and_then(|cloud| cloud.install_image.clone()),
        remote_payload_file: existing.and_then(|cloud| cloud.remote_payload_file.clone()),
        ssh_key: existing.and_then(|cloud| cloud.ssh_key.clone()),
        key: Some(cloud_info.name.clone()),
        server: existing.and_then(|cloud| cloud.server.clone()),
    })
}

fn apply_cloud_cli_override(
    config: &mut StackerConfig,
    remote_overrides: &RemoteDeployOverrides,
    creds: &StoredCredentials,
) -> Result<(), CliError> {
    if remote_overrides.key_id.is_none() && remote_overrides.key_name.is_none() {
        return Ok(());
    }

    let base_url = active_stacker_base_url(creds);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| {
            CliError::ConfigValidation(format!("Failed to create async runtime: {}", e))
        })?;
    let client = StackerClient::new(&base_url, &creds.access_token);

    let cloud_info = if let Some(key_id) = remote_overrides.key_id {
        rt.block_on(client.get_cloud(key_id))?.ok_or_else(|| {
            CliError::ConfigValidation(format!("No saved cloud credential found with id {key_id}"))
        })?
    } else {
        let key_name = remote_overrides
            .key_name
            .as_deref()
            .expect("key_name checked above");
        rt.block_on(client.find_cloud_by_name(key_name))?
            .ok_or_else(|| {
                CliError::ConfigValidation(format!(
                    "No saved cloud credential found with name '{key_name}'"
                ))
            })?
    };

    eprintln!(
        "  Using cloud credential override: {} (id={}, provider={})",
        cloud_info.name, cloud_info.id, cloud_info.provider
    );
    config.deploy.target = DeployTarget::Cloud;
    config.deploy.cloud = Some(merge_cloud_config_from_info(
        config.deploy.cloud.as_ref(),
        &cloud_info,
    )?);
    Ok(())
}

/// `stacker deploy [--target local|cloud|server] [--file stacker.yml] [--dry-run] [--force-rebuild]`
/// `stacker deploy --project=myapp --target cloud --key devops --server bastion`
///
/// Generates Dockerfile + docker-compose from stacker.yml, then
/// deploys using the appropriate strategy (local, cloud, or server).
///
/// For remote cloud deploys, the CLI now goes through the Stacker server API
/// instead of calling User Service directly:
///   1. Resolves (or auto-creates) the project on the Stacker server
///   2. Looks up saved cloud credentials by provider (or passes env-var creds)
///   3. Looks up saved server by name (optional)
///   4. Calls `POST /project/{id}/deploy[/{cloud_id}]`
pub struct DeployCommand {
    pub target: Option<String>,
    pub environment: Option<String>,
    pub file: Option<String>,
    pub dry_run: bool,
    pub force_rebuild: bool,
    /// Override project name (--project flag)
    pub project_name: Option<String>,
    /// Override cloud key name (--key flag)
    pub key_name: Option<String>,
    /// Override cloud key by ID (--key-id flag)
    pub key_id: Option<i32>,
    /// Override server name (--server flag)
    pub server_name: Option<String>,
    /// Watch deployment progress until complete (--watch / --no-watch).
    /// `None` means "auto" (watch for cloud, health-check for local).
    pub watch: Option<bool>,
    /// Persist server details into stacker.yml after deploy (--lock).
    pub lock: bool,
    /// Skip smart server pre-check and lockfile hints; force fresh cloud provision (--force-new).
    pub force_new: bool,
    /// Container runtime: "runc" (default) or "kata" (--runtime).
    pub runtime: String,
    /// Generate a read-only deployment plan instead of applying changes.
    pub plan: bool,
    /// Revalidate and apply a previously generated plan fingerprint.
    pub apply_plan: Option<String>,
}

impl DeployCommand {
    pub fn new(
        target: Option<String>,
        file: Option<String>,
        dry_run: bool,
        force_rebuild: bool,
    ) -> Self {
        Self {
            target,
            environment: None,
            file,
            dry_run,
            force_rebuild,
            project_name: None,
            key_name: None,
            key_id: None,
            server_name: None,
            watch: None,
            lock: false,
            force_new: false,
            runtime: "runc".to_string(),
            plan: false,
            apply_plan: None,
        }
    }

    pub fn with_environment(mut self, environment: Option<String>) -> Self {
        self.environment = environment;
        self
    }

    /// Builder method to set remote override flags from CLI args.
    pub fn with_remote_overrides(
        mut self,
        project: Option<String>,
        key: Option<String>,
        server: Option<String>,
    ) -> Self {
        self.project_name = project;
        self.key_name = key;
        self.server_name = server;
        self
    }

    /// Builder method to set cloud key ID from CLI `--key-id` flag.
    pub fn with_key_id(mut self, key_id: Option<i32>) -> Self {
        self.key_id = key_id;
        self
    }

    /// Builder method to set watch behaviour.
    /// `--watch` forces watch on; `--no-watch` forces it off.
    /// Neither flag → auto (cloud=watch, local=health-check).
    pub fn with_watch(mut self, watch: bool, no_watch: bool) -> Self {
        if no_watch {
            self.watch = Some(false);
        } else if watch {
            self.watch = Some(true);
        }
        // else remains None → auto
        self
    }

    /// Builder method to set lock behaviour (--lock flag).
    pub fn with_lock(mut self, lock: bool) -> Self {
        self.lock = lock;
        self
    }

    /// Builder method to set force-new behaviour (--force-new flag).
    pub fn with_force_new(mut self, force_new: bool) -> Self {
        self.force_new = force_new;
        self
    }

    /// Builder method to set container runtime (--runtime flag).
    pub fn with_runtime(mut self, runtime: String) -> Self {
        let rt = runtime.to_lowercase();
        if rt != "runc" && rt != "kata" {
            eprintln!(
                "Warning: unknown runtime '{}', defaulting to 'runc'",
                runtime
            );
            self.runtime = "runc".to_string();
        } else {
            self.runtime = rt;
        }
        self
    }

    pub fn with_plan(mut self, plan: bool) -> Self {
        self.plan = plan;
        self
    }

    pub fn with_apply_plan(mut self, apply_plan: Option<String>) -> Self {
        self.apply_plan = apply_plan;
        self
    }
}

/// Parse a deploy target string into `DeployTarget`.
#[cfg(test)]
fn parse_deploy_target(s: &str) -> Result<DeployTarget, CliError> {
    let json = format!("\"{}\"", s.to_lowercase());
    serde_json::from_str::<DeployTarget>(&json).map_err(|_| {
        CliError::ConfigValidation(format!(
            "Unknown deploy target '{}'. Valid targets: local, cloud, server",
            s
        ))
    })
}

/// Override values from CLI flags for remote cloud deploys.
#[derive(Debug, Clone, Default)]
pub struct RemoteDeployOverrides {
    pub project_name: Option<String>,
    pub key_name: Option<String>,
    pub key_id: Option<i32>,
    pub server_name: Option<String>,
}

/// Core deploy logic, extracted for testability.
///
/// Takes injectable `CommandExecutor` so tests can mock shell calls.
#[allow(clippy::too_many_arguments)]
pub fn run_deploy(
    project_dir: &Path,
    config_file: Option<&str>,
    target_override: Option<&str>,
    dry_run: bool,
    force_rebuild: bool,
    force_new: bool,
    executor: &dyn CommandExecutor,
    remote_overrides: &RemoteDeployOverrides,
    runtime: &str,
) -> Result<DeployResult, CliError> {
    run_deploy_for_environment(
        project_dir,
        config_file,
        target_override,
        None,
        dry_run,
        force_rebuild,
        force_new,
        executor,
        remote_overrides,
        runtime,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn run_deploy_for_environment(
    project_dir: &Path,
    config_file: Option<&str>,
    target_override: Option<&str>,
    environment_override: Option<&str>,
    dry_run: bool,
    force_rebuild: bool,
    force_new: bool,
    executor: &dyn CommandExecutor,
    remote_overrides: &RemoteDeployOverrides,
    runtime: &str,
) -> Result<DeployResult, CliError> {
    let cred_manager = CredentialsManager::with_default_store();
    run_deploy_with_credentials_manager(
        project_dir,
        config_file,
        target_override,
        environment_override,
        dry_run,
        force_rebuild,
        force_new,
        executor,
        remote_overrides,
        runtime,
        &cred_manager,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_deploy_with_credentials_manager<S: CredentialStore>(
    project_dir: &Path,
    config_file: Option<&str>,
    target_override: Option<&str>,
    environment_override: Option<&str>,
    dry_run: bool,
    force_rebuild: bool,
    force_new: bool,
    executor: &dyn CommandExecutor,
    remote_overrides: &RemoteDeployOverrides,
    runtime: &str,
    cred_manager: &CredentialsManager<S>,
) -> Result<DeployResult, CliError> {
    // 1. Load config
    let config_path = match config_file {
        Some(f) => project_dir.join(f),
        None => project_dir.join(DEFAULT_CONFIG_FILE),
    };

    let mut config =
        StackerConfig::from_file(&config_path)?.with_resolved_deploy_target(target_override)?;
    let selected_environment = if let Some((environment, environment_config)) =
        config.resolve_environment_config(environment_override)?
    {
        config.deploy.environment = Some(environment.clone());
        if let Some(compose_file) = environment_config.compose_file {
            config.deploy.compose_file = Some(compose_file);
        }
        if let Some(env_file) = environment_config.env_file {
            config.env_file = Some(env_file);
        }
        Some(environment)
    } else {
        None
    };
    ensure_env_file_if_needed(&config, project_dir)?;

    // 2. Resolve deploy target/profile (flag > config default)
    let mut deploy_target = config.deploy.target;

    // 2b. Server pre-check: when target is Cloud but deploy.server section
    //     is defined with a host, try SSH connectivity first.
    //     If the server is reachable, automatically switch to Server target.
    //     If not, show diagnostics and abort so the user can fix or remove the section.
    //     Skipped when --force-new is set (user explicitly wants a fresh cloud provision).
    //     When a lockfile exists, auto-inject the server name so the API reuses the server.
    let mut lock_server_name: Option<String> = None;
    if deploy_target == DeployTarget::Cloud && !force_new {
        if let Some(ref server_cfg) = config.deploy.server {
            eprintln!(
                "  Found deploy.server section (host={}). Checking SSH connectivity...",
                server_cfg.host
            );

            match try_ssh_server_check(server_cfg) {
                Some(check) if check.connected && check.authenticated => {
                    eprintln!(
                        "  ✓ Server {} is reachable ({})",
                        server_cfg.host,
                        check.summary()
                    );

                    if !check.docker_installed {
                        eprintln!("  ⚠ Docker is NOT installed on the server.");
                        eprintln!("    Install Docker first:  ssh {}@{} 'curl -fsSL https://get.docker.com | sh'",
                            server_cfg.user, server_cfg.host);
                        return Err(CliError::DeployFailed {
                            target: DeployTarget::Server,
                            reason: format!(
                                "Server {} is reachable but Docker is not installed. \
                                 Install Docker and retry, or remove the 'server' section from stacker.yml \
                                 to provision a new cloud server.",
                                server_cfg.host
                            ),
                        });
                    }

                    eprintln!(
                        "  Switching deploy target from 'cloud' → 'server' (using existing server)"
                    );
                    deploy_target = DeployTarget::Server;
                }
                Some(check) => {
                    // Server defined but not reachable — abort with helpful hints
                    print_server_unreachable_hint(server_cfg, &check);
                    return Err(CliError::DeployFailed {
                        target: DeployTarget::Cloud,
                        reason: format!(
                            "deploy.server section defines host {} but the server is not reachable: {}. \
                             Fix the connection or remove the 'server' section to provision a new cloud server.",
                            server_cfg.host,
                            check.error.as_deref().unwrap_or("unknown error")
                        ),
                    });
                }
                None => {
                    // Could not perform SSH check (missing key, etc.) — warn and abort
                    eprintln!("  ⚠ Could not verify server connectivity (see above).");
                    eprintln!("    Remove the 'server' section from stacker.yml to provision a new cloud server,");
                    eprintln!("    or fix the SSH key configuration and retry.");
                    return Err(CliError::DeployFailed {
                        target: DeployTarget::Cloud,
                        reason: format!(
                            "deploy.server section defines host {} but SSH connectivity check could not be performed. \
                             Fix the SSH key or remove the 'server' section to provision a new cloud server.",
                            server_cfg.host
                        ),
                    });
                }
            }
        } else if DeploymentLock::exists_for_target(project_dir, "cloud")
            || DeploymentLock::exists(project_dir)
        {
            // No deploy.server in config, but a lockfile exists from a prior deploy.
            // Auto-inject the server name so the cloud deploy API reuses the same server.
            if let Ok(Some(lock)) = DeploymentLock::load_for_target(project_dir, "cloud") {
                if let Some(ref name) = lock.server_name {
                    eprintln!(
                        "  ℹ Found previous cloud deployment (server='{}') — reusing server",
                        name
                    );
                    eprintln!("    To provision a new server instead: stacker deploy --force-new");
                    lock_server_name = Some(name.clone());
                } else if let Some(ref ip) = lock.server_ip {
                    if ip != "127.0.0.1" {
                        eprintln!(
                            "  ℹ Found previous deployment to {} (from deployment lock)",
                            ip
                        );
                        eprintln!(
                            "    Server name unknown — cannot auto-reuse. Run: stacker config lock"
                        );
                        eprintln!(
                            "    To provision a new server instead:   stacker deploy --force-new"
                        );
                    }
                }
            }
        }
    }

    // 3. Cloud/server prerequisites — verify login and keep credentials for later use.
    let cloud_creds: Option<StoredCredentials> =
        if matches!(deploy_target, DeployTarget::Cloud | DeployTarget::Server) {
            let purpose = if deploy_target == DeployTarget::Cloud {
                "cloud deploy"
            } else {
                "server deploy"
            };
            Some(cred_manager.require_valid_token(purpose)?)
        } else {
            None
        };

    if deploy_target == DeployTarget::Cloud {
        if let Some(creds) = cloud_creds.as_ref() {
            apply_cloud_cli_override(&mut config, remote_overrides, creds)?;
        }
    }

    if deploy_target == DeployTarget::Server {
        if let Some(ref server_cfg) = config.deploy.server {
            eprintln!(
                "  Validating SSH connectivity to {} before bootstrap deploy...",
                server_cfg.host
            );

            match try_ssh_server_check(server_cfg) {
                Some(check) if check.connected && check.authenticated => {
                    eprintln!(
                        "  ✓ Server {} is reachable ({})",
                        server_cfg.host,
                        check.summary()
                    );

                    if !check.docker_installed {
                        return Err(CliError::DeployFailed {
                            target: DeployTarget::Server,
                            reason: format!(
                                "Server {} is reachable but Docker is not installed. Install Docker and Docker Compose, then retry.",
                                server_cfg.host
                            ),
                        });
                    }
                }
                Some(check) => {
                    print_server_unreachable_hint(server_cfg, &check);
                    return Err(CliError::DeployFailed {
                        target: DeployTarget::Server,
                        reason: format!(
                            "Failed to connect to {} over SSH: {}",
                            server_cfg.host,
                            check.error.as_deref().unwrap_or("unknown error")
                        ),
                    });
                }
                None => {
                    return Err(CliError::DeployFailed {
                        target: DeployTarget::Server,
                        reason: format!(
                            "Could not verify SSH connectivity to {}. Check deploy.server.ssh_key and retry.",
                            server_cfg.host
                        ),
                    });
                }
            }
        }
    }

    // 3b. If cloud target but no cloud section in stacker.yml, prompt to select a saved credential.
    if deploy_target == DeployTarget::Cloud && config.deploy.cloud.is_none() {
        let creds = cloud_creds
            .as_ref()
            .expect("cloud_creds should be set when deploy_target is Cloud (verified in step 3)");
        let access_token = &creds.access_token;
        let base_url = active_stacker_base_url(creds);

        match prompt_select_cloud(&base_url, access_token)? {
            Some(cloud_info) => {
                eprintln!(
                    "  Selected cloud credential: {} (id={}, provider={})",
                    cloud_info.name, cloud_info.id, cloud_info.provider
                );

                // Apply the selected cloud to the in-memory config.
                config.deploy.target = DeployTarget::Cloud;
                config.deploy.cloud = Some(cloud_config_from_info(&cloud_info)?);

                // Persist the selection to stacker.yml so subsequent deploys
                // do not prompt again.
                if config_path.exists() {
                    let yaml = serde_yaml::to_string(&config).map_err(|e| {
                        CliError::ConfigValidation(format!(
                            "Failed to serialize updated config: {}",
                            e
                        ))
                    })?;
                    std::fs::write(&config_path, yaml)?;
                    eprintln!(
                        "  ✓ Updated {} with deploy.cloud.key={}",
                        config_path.display(),
                        cloud_info.name
                    );
                }
            }
            None => {
                // User chose "Connect a new cloud provider"
                eprintln!();
                eprintln!("  To connect a new cloud provider, export your API token and redeploy:");
                eprintln!(
                    "    Hetzner:      {}",
                    cloud_env::provider_cli_example("htz")
                );
                eprintln!(
                    "    DigitalOcean: {}",
                    cloud_env::provider_cli_example("do")
                );
                eprintln!(
                    "    Linode:       {}",
                    cloud_env::provider_cli_example("lo")
                );
                eprintln!(
                    "    Vultr:        {}",
                    cloud_env::provider_cli_example("vu")
                );
                eprintln!(
                    "    AWS:          {}",
                    cloud_env::provider_cli_example("aws")
                );
                eprintln!();
                eprintln!("  Or configure manually with: stacker config setup cloud");
                eprintln!();
                return Err(CliError::CloudProviderMissing);
            }
        }
    }

    // 4. Validate via strategy
    let strategy = strategy_for(&deploy_target);
    strategy.validate(&config)?;

    // 5. Generate artifacts into .stacker/
    let output_dir = project_dir.join(OUTPUT_DIR);
    std::fs::create_dir_all(&output_dir)?;

    // 5a. Dockerfile
    let needs_dockerfile = config.app.image.is_none() && config.app.dockerfile.is_none();
    let dockerfile_path = output_dir.join("Dockerfile");

    if needs_dockerfile {
        if force_rebuild || !dockerfile_path.exists() {
            let builder = DockerfileBuilder::for_project(&project_dir, config.app.app_type);
            builder.write_to(&dockerfile_path, force_rebuild)?;
        } else {
            eprintln!(
                "  Using existing {}/Dockerfile (use --force-rebuild to regenerate)",
                OUTPUT_DIR
            );
        }
    }

    // 5b. docker-compose.yml
    let (compose_path, compose_is_user_supplied) =
        if let Some(ref existing) = config.deploy.compose_file {
            let configured_path = project_dir.join(existing);
            if configured_path.exists() {
                (configured_path, true)
            } else {
                let generated_fallback = output_dir.join("docker-compose.yml");
                if generated_fallback.exists() {
                    eprintln!(
                        "  Configured compose file not found: {}. Falling back to {}",
                        configured_path.display(),
                        generated_fallback.display()
                    );
                    (generated_fallback, false)
                } else {
                    return Err(CliError::ConfigValidation(format!(
                        "Compose file not found: {}",
                        configured_path.display()
                    )));
                }
            }
        } else {
            let compose_out = output_dir.join("docker-compose.yml");
            if force_rebuild || !compose_out.exists() {
                let compose = ComposeDefinition::try_from(&config)?;
                compose.write_to(&compose_out, force_rebuild)?;
            } else {
                eprintln!(
                    "  Using existing {}/docker-compose.yml (use --force-rebuild to regenerate)",
                    OUTPUT_DIR
                );
            }
            (compose_out, false)
        };

    normalize_generated_compose_paths(&compose_path)?;
    validate_compose_for_deploy(&compose_path)?;
    if compose_is_user_supplied {
        validate_cross_source_port_collisions(&config, &compose_path)?;
    }
    ensure_compose_env_files_if_needed(&compose_path)?;
    let image_env = build_image_env_lookup(project_dir, &config)?;
    merge_compose_public_ports_into_app_config(&mut config, &compose_path, &image_env)?;
    if matches!(deploy_target, DeployTarget::Cloud | DeployTarget::Server) {
        print_registry_auth_guidance_if_needed(&compose_path, &config, &image_env)?;
    }
    let required_image_platform = required_image_platform_for_deploy_target(&deploy_target);
    if !dry_run {
        validate_compose_images_for_deploy(
            &compose_path,
            config.deploy.registry.as_ref(),
            &image_env,
            required_image_platform.as_ref(),
        )?;
    }

    // 5b.1 Surface build source paths to avoid confusion.
    if let Some(image) = &config.app.image {
        eprintln!(
            "  App image source: image={} (no local Dockerfile build)",
            image
        );
    } else if let Some(build_src) = compose_app_build_source(&compose_path) {
        eprintln!("  App build source: {}", build_src);
    } else if let Some(dockerfile) = &config.app.dockerfile {
        let dockerfile_display = if dockerfile.is_absolute() {
            dockerfile.display().to_string()
        } else {
            project_dir.join(dockerfile).display().to_string()
        };
        eprintln!("  App build source: Dockerfile={}", dockerfile_display);
    } else {
        eprintln!(
            "  App build source: Dockerfile={}",
            dockerfile_path.display()
        );
    }
    eprintln!("  Compose file: {}", compose_path.display());
    if let Some(environment) = &selected_environment {
        eprintln!(
            "  Environment: {} -> Target: {}",
            environment, deploy_target
        );
    }

    let config_bundle = if matches!(deploy_target, DeployTarget::Cloud | DeployTarget::Server) {
        if let Some(environment) = selected_environment.as_deref() {
            let bundle = build_config_bundle(
                project_dir,
                environment,
                &compose_path,
                config.env_file.as_deref(),
            )?;
            eprintln!("  Config bundle: {}", bundle.archive_path.display());
            for file in &bundle.manifest.files {
                eprintln!(
                    "    Config file: {} -> {}",
                    file.source_path, file.destination_path
                );
            }
            Some(bundle)
        } else {
            None
        }
    } else {
        None
    };

    // 5c. Report hooks (dry-run)
    if dry_run {
        if let Some(ref pre_build) = config.hooks.pre_build {
            eprintln!("  Hook (pre_build): {}", pre_build.display());
        }
    }

    // 6. Deploy
    let context = DeployContext {
        config_path: config_path.clone(),
        compose_path: compose_path.clone(),
        project_dir: project_dir.to_path_buf(),
        dry_run,
        image: config
            .deploy
            .cloud
            .as_ref()
            .and_then(|cloud| cloud.install_image.clone()),
        project_name_override: remote_overrides.project_name.clone(),
        key_name_override: remote_overrides.key_name.clone(),
        key_id_override: remote_overrides.key_id,
        server_name_override: remote_overrides.server_name.clone().or(lock_server_name),
        runtime: runtime.to_string(),
        config_bundle,
        managed_proxy_feature_enabled: true,
        force_new,
    };

    let result = strategy.deploy(&config, &context, executor)?;

    Ok(result)
}

impl CallableTrait for DeployCommand {
    fn call(&self) -> Result<(), Box<dyn std::error::Error>> {
        if self.plan {
            return crate::console::commands::cli::deployment::run_remote_deployment_plan(
                None,
                crate::services::DeployPlanOperation::Deploy,
                None,
                None,
                None,
            );
        }

        if let Some(fingerprint) = self.apply_plan.as_deref() {
            let project_dir = std::env::current_dir()?;
            let config_path = project_dir.join("stacker.yml");
            let config = StackerConfig::from_file(&config_path)?
                .with_resolved_deploy_target(None)
                .map_err(|e| CliError::ConfigValidation(format!("Invalid stacker.yml: {}", e)))?;
            let ctx = crate::cli::runtime::CliRuntime::new("deploy apply-plan")?;
            let validated_plan = ctx.block_on(async {
                let base_url =
                    crate::console::commands::cli::status::resolve_stacker_base_url(&ctx.creds);
                crate::console::commands::cli::deployment::fetch_remote_deployment_plan(
                    &config,
                    &base_url,
                    &ctx.client,
                    None,
                    crate::services::DeployPlanOperation::Deploy,
                    None,
                    None,
                    Some(fingerprint),
                )
                .await
            })?;
            if !validated_plan.has_changes {
                println!(
                    "Plan already satisfied for {}. Nothing to apply.",
                    validated_plan.deployment_hash
                );
                return Ok(());
            }
        }

        let project_dir = std::env::current_dir()?;
        let executor = ShellExecutor;

        // Build remote overrides from CLI flags
        let remote_overrides = RemoteDeployOverrides {
            project_name: self.project_name.clone(),
            key_name: self.key_name.clone(),
            key_id: self.key_id,
            server_name: self.server_name.clone(),
        };

        // ── Spinner while deploying ──────────────────
        let spin = progress::deploy_spinner("starting...");

        let result = run_deploy_for_environment(
            &project_dir,
            self.file.as_deref(),
            self.target.as_deref(),
            self.environment.as_deref(),
            self.dry_run,
            self.force_rebuild,
            self.force_new,
            &executor,
            &remote_overrides,
            &self.runtime,
        );

        let result = match result {
            Ok(result) => {
                progress::finish_success(&spin, &result.message);
                result
            }
            Err(err) => {
                progress::finish_error(&spin, &format!("{}", err));
                if let CliError::LoginRequired { .. } = &err {
                    eprintln!("\nHint: run `stacker login` and retry deploy.");
                }
                print_ai_deploy_help(&project_dir, self.file.as_deref(), &err);
                return Err(Box::new(err));
            }
        };

        if let Some(ip) = &result.server_ip {
            eprintln!("  Server IP: {}", ip);
        }

        // ── Post-deploy progress tracking ────────────
        if self.dry_run {
            return Ok(());
        }

        // Resolve whether to watch: explicit flag > auto-detect
        let should_watch = self.watch.unwrap_or_else(|| {
            // Auto: watch for cloud remote deploys, health-check for local
            matches!(result.target, DeployTarget::Cloud | DeployTarget::Server)
                && (result.deployment_id.is_some() || result.project_id.is_some())
        });

        let mut watch_outcome = DeploymentWatchOutcome::Unknown;

        match result.target {
            DeployTarget::Local => {
                // Always do a quick health check for local deploy unless --no-watch
                if self.watch != Some(false) {
                    watch_local_containers(
                        &project_dir,
                        self.file.as_deref(),
                        self.target.as_deref(),
                    )?;
                }
            }
            DeployTarget::Cloud | DeployTarget::Server if should_watch => {
                watch_outcome = watch_cloud_deployment(&result)?;
            }
            _ => {}
        }

        let should_fetch_remote_details = !matches!(watch_outcome, DeploymentWatchOutcome::Failed);

        // ── Deployment lock: persist deployment context ──
        self.save_deployment_lock(&project_dir, &result, should_fetch_remote_details)?;
        if should_fetch_remote_details && should_install_cloud_backup_key(&result, self.dry_run) {
            self.install_cloud_backup_key(&result);
        }

        Ok(())
    }
}

fn should_install_cloud_backup_key(result: &DeployResult, dry_run: bool) -> bool {
    !dry_run && result.target == DeployTarget::Cloud && result.project_id.is_some()
}

impl DeployCommand {
    fn install_cloud_backup_key(&self, result: &DeployResult) {
        if result.target != DeployTarget::Cloud {
            return;
        }

        let Some(project_id) = result.project_id else {
            eprintln!(
                "  ⚠ Local SSH backup key was not installed: deployment returned no project ID."
            );
            return;
        };

        let server = match fetch_server_for_project(
            project_id as i32,
            DeployTarget::Cloud,
            result.server_name.as_deref(),
        ) {
            Ok(Some(server)) => server,
            Ok(None) => {
                eprintln!(
                    "  ⚠ Local SSH backup key was not installed: server details are not available yet."
                );
                return;
            }
            Err(err) => {
                eprintln!(
                    "  ⚠ Local SSH backup key was not installed: could not fetch server details: {}",
                    err
                );
                return;
            }
        };

        if server
            .srv_ip
            .as_deref()
            .is_none_or(|ip| ip.trim().is_empty())
        {
            eprintln!(
                "  ⚠ Local SSH backup key was not installed: server IP is not available yet."
            );
            return;
        }

        let (base_url, creds) = match resolve_saved_stacker_base_url("SSH backup key authorization")
        {
            Ok(values) => values,
            Err(err) => {
                eprintln!(
                    "  ⚠ Local SSH backup key was not installed: could not load credentials: {}",
                    err
                );
                return;
            }
        };

        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(err) => {
                eprintln!(
                    "  ⚠ Local SSH backup key was not installed: failed to initialize runtime: {}",
                    err
                );
                return;
            }
        };

        let client =
            StackerClient::new_for_target(&base_url, &creds.access_token, DeployTarget::Cloud);
        match rt.block_on(
            crate::console::commands::cli::ssh_key::ensure_local_backup_key_authorized(
                &client, &server,
            ),
        ) {
            Ok(auth) => {
                eprintln!("  ✓ Local SSH backup key authorized");
                eprintln!("    Key: {}", auth.private_key_path.display());
                eprintln!("    Public key: {}", auth.public_key_path.display());
                eprintln!("    Connect: {}", auth.ssh_command);
            }
            Err(err) => {
                eprintln!(
                    "  ⚠ App deploy succeeded, but local SSH backup access was not installed."
                );
                eprintln!("    Reason: {}", err);
                eprintln!(
                    "    Repair: stacker ssh-key inject --server-id {} --with-key <existing-private-key>",
                    server.id
                );
            }
        }
    }

    /// Save deployment context to `.stacker/deployment.lock` after a successful deploy.
    ///
    /// For cloud deploys, tries to fetch the provisioned server's details from the
    /// Stacker API (IP, SSH user/port, server name) so that subsequent deploys can
    /// target the same server via the smart pre-check.
    ///
    /// When `--lock` is set, also writes the server details into `stacker.yml`.
    fn save_deployment_lock(
        &self,
        project_dir: &Path,
        result: &DeployResult,
        fetch_remote_details: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Build the initial lock from the deploy result
        let mut lock = match result.target {
            DeployTarget::Local => DeploymentLock::for_local(),
            DeployTarget::Server => {
                let mut l = DeploymentLock::from_result(result)
                    .with_project_name(self.project_name.clone());

                let config_path = match &self.file {
                    Some(f) => project_dir.join(f),
                    None => project_dir.join(DEFAULT_CONFIG_FILE),
                };
                if let Ok(config) = StackerConfig::from_file(&config_path) {
                    if l.project_name.is_none() {
                        let name = config
                            .project
                            .identity
                            .filter(|s| !s.is_empty())
                            .unwrap_or(config.name);
                        l = l.with_project_name(Some(name));
                    }

                    if let Some(ref server_cfg) = config.deploy.server {
                        if l.server_ip.is_none() {
                            l.server_ip = Some(server_cfg.host.clone());
                        }
                        if l.ssh_user.is_none() {
                            l.ssh_user = Some(server_cfg.user.clone());
                        }
                        if l.ssh_port.is_none() {
                            l.ssh_port = Some(server_cfg.port);
                        }
                    }
                }

                if fetch_remote_details {
                    if let Some(project_id) = result.project_id {
                        match fetch_server_for_project(
                            project_id as i32,
                            DeployTarget::Server,
                            result.server_name.as_deref(),
                        ) {
                            Ok(Some(info)) => {
                                l = l.with_server_info(
                                    info.srv_ip.clone(),
                                    info.ssh_user.clone(),
                                    info.ssh_port.map(|p| p as u16),
                                    info.name.clone(),
                                    info.cloud_id,
                                );
                            }
                            Ok(None) => {}
                            Err(e) => {
                                eprintln!("  ⚠ Could not fetch server details: {}", e);
                            }
                        }
                    }
                }

                if l.server_name.is_none() {
                    if let Some(ref name) = result.server_name {
                        l.server_name = Some(name.clone());
                    }
                }

                l
            }
            DeployTarget::Cloud => {
                let mut l = DeploymentLock::from_result(result)
                    .with_project_name(self.project_name.clone());

                // If no --project flag, try to get the project name from config
                if l.project_name.is_none() {
                    let config_path = match &self.file {
                        Some(f) => project_dir.join(f),
                        None => project_dir.join(DEFAULT_CONFIG_FILE),
                    };
                    if let Ok(config) = StackerConfig::from_file(&config_path) {
                        // Prefer project.identity as the registered name, fall back to config name
                        let name = config
                            .project
                            .identity
                            .filter(|s| !s.is_empty())
                            .unwrap_or(config.name);
                        l = l.with_project_name(Some(name));
                    }
                }

                // Try to fetch provisioned server details from the Stacker API
                if fetch_remote_details {
                    if let Some(project_id) = result.project_id {
                        match fetch_server_for_project(
                            project_id as i32,
                            DeployTarget::Cloud,
                            result.server_name.as_deref(),
                        ) {
                            Ok(Some(info)) => {
                                l = l.with_server_info(
                                    info.srv_ip.clone(),
                                    info.ssh_user.clone(),
                                    info.ssh_port.map(|p| p as u16),
                                    info.name.clone(),
                                    info.cloud_id,
                                );
                                if let Some(ref ip) = info.srv_ip {
                                    eprintln!(
                                        "  Server details: {} ({}@{}:{})",
                                        info.name.as_deref().unwrap_or("unnamed"),
                                        info.ssh_user.as_deref().unwrap_or("root"),
                                        ip,
                                        info.ssh_port.unwrap_or(22),
                                    );
                                }
                            }
                            Ok(None) => {
                                eprintln!(
                                    "  ℹ Server details not yet available (may still be provisioning)."
                                );
                            }
                            Err(e) => {
                                eprintln!("  ⚠ Could not fetch server details: {}", e);
                            }
                        }
                    }
                }

                // Fallback: if the API fetch didn't populate server_name,
                // use the name from the deploy form so subsequent deploys
                // can still find and reuse the server.
                if l.server_name.is_none() {
                    if let Some(ref name) = result.server_name {
                        l.server_name = Some(name.clone());
                    }
                }

                l
            }
        };

        // Always set project_name if available from CLI flag
        if self.project_name.is_some() {
            lock = lock.with_project_name(self.project_name.clone());
        }

        if matches!(result.target, DeployTarget::Cloud | DeployTarget::Server) {
            if let Ok(Some(creds)) = CredentialsManager::with_default_store().load() {
                lock = lock.with_stacker_email(creds.email.clone());
            }
        }

        // Save lockfile
        match lock.save(project_dir) {
            Ok(path) => {
                eprintln!("  Deployment context saved to {}", path.display());
            }
            Err(e) => {
                eprintln!("  ⚠ Failed to save deployment lock: {}", e);
            }
        }

        // If --lock flag is set, also update stacker.yml with server details
        if self.lock {
            let config_path = match &self.file {
                Some(f) => project_dir.join(f),
                None => project_dir.join(DEFAULT_CONFIG_FILE),
            };

            if lock.server_ip.is_some() && lock.server_ip.as_deref() != Some("127.0.0.1") {
                match StackerConfig::from_file(&config_path) {
                    Ok(mut config) => {
                        lock.apply_to_config(&mut config);
                        match DeploymentLock::write_config(&config, &config_path) {
                            Ok(()) => {
                                eprintln!("  ✓ stacker.yml updated with server details (backup: stacker.yml.bak)");
                                eprintln!("    Next deploy will target this server directly.");
                            }
                            Err(e) => {
                                eprintln!("  ⚠ Failed to update stacker.yml: {}", e);
                                eprintln!("    Run `stacker config lock` to retry.");
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("  ⚠ Failed to read stacker.yml for update: {}", e);
                    }
                }
            } else {
                eprintln!("  ℹ --lock: No remote server details to persist (local deploy or server IP not yet available).");
                eprintln!("    Run `stacker config lock` after the server is provisioned.");
            }
        }

        Ok(())
    }
}

// ── Fetch server details from Stacker API by project ID ──

/// After a cloud deploy completes, look up the provisioned server's details
/// (IP, SSH user, port, name) from the Stacker server API.
///
/// First polls the deployment status until it reaches a terminal state (or a
/// timeout is reached), then retries fetching the server IP — because the IP
/// may be assigned a few seconds after the deployment status flips to
/// "completed".
fn resolve_saved_stacker_base_url(context: &str) -> Result<(String, StoredCredentials), CliError> {
    let cred_manager = CredentialsManager::with_default_store();
    let creds = cred_manager.require_valid_token(context)?;
    let raw_base_url = creds
        .server_url
        .as_deref()
        .unwrap_or(stacker_client::DEFAULT_STACKER_URL);
    let base_url = crate::cli::install_runner::normalize_stacker_server_url(raw_base_url);
    Ok((base_url, creds))
}

fn fetch_server_for_project(
    project_id: i32,
    target: DeployTarget,
    preferred_server_name: Option<&str>,
) -> Result<Option<stacker_client::ServerInfo>, Box<dyn std::error::Error>> {
    use std::time::Duration;

    let (base_url, creds) = resolve_saved_stacker_base_url("server lookup")?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    rt.block_on(async {
        let client = StackerClient::new_for_target(&base_url, &creds.access_token, target.clone());

        // Phase 1: wait for the deployment to reach a terminal state.
        // The watch_cloud_deployment may have timed out, so the deployment
        // could still be running.  We give it another 10 minutes here.
        let deploy_poll = Duration::from_secs(10);
        let deploy_timeout = Duration::from_secs(600);
        let deploy_start = std::time::Instant::now();
        let mut fallback_server_ip: Option<String> = None;

        loop {
            match client.get_deployment_status_by_project(project_id).await {
                Ok(Some(info)) if is_terminal(&info.status) => {
                    fallback_server_ip = fallback_server_ip.or_else(|| {
                        info.status_message
                            .as_deref()
                            .and_then(extract_ipv4_from_text)
                    });
                    if info.status != "completed" {
                        eprintln!(
                            "  Deployment #{} finished with status '{}' — server IP may not be available.",
                            info.id, info.status
                        );
                    }
                    break;
                }
                Ok(Some(info)) => {
                    fallback_server_ip = fallback_server_ip.or_else(|| {
                        info.status_message
                            .as_deref()
                            .and_then(extract_ipv4_from_text)
                    });
                    if deploy_start.elapsed() > deploy_timeout {
                        eprintln!(
                            "  Deployment #{} still '{}' after extended wait — saving what we have.",
                            info.id, info.status
                        );
                        break;
                    }
                    eprintln!(
                        "  Deployment still in progress ({}), waiting for IP...",
                        info.status_message
                            .as_deref()
                            .unwrap_or(&info.status),
                    );
                    tokio::time::sleep(deploy_poll).await;
                }
                _ => break, // no deployment info available
            }
        }

        // Phase 2: deployment is terminal (or timed out) — poll for the server IP.
        let ip_retries = 6;
        let ip_delay = Duration::from_secs(10);

        for attempt in 0..ip_retries {
            let servers = client.list_servers().await?;

            let server = choose_server_for_project(servers, project_id, preferred_server_name);

            match server {
                Some(ref s) if s.srv_ip.is_some() => {
                    return Ok(server);
                }
                Some(mut s) if fallback_server_ip.is_some() => {
                    s.srv_ip = fallback_server_ip.clone();
                    return Ok(Some(s));
                }
                Some(_) if attempt < ip_retries - 1 => {
                    eprintln!(
                        "  Server found but IP not yet assigned (attempt {}/{}), retrying in {}s...",
                        attempt + 1,
                        ip_retries,
                        ip_delay.as_secs(),
                    );
                    tokio::time::sleep(ip_delay).await;
                }
                Some(s) => {
                    return Ok(Some(s));
                }
                None if attempt < ip_retries - 1 => {
                    eprintln!(
                        "  No server found for project {} (attempt {}/{}), retrying in {}s...",
                        project_id,
                        attempt + 1,
                        ip_retries,
                        ip_delay.as_secs(),
                    );
                    tokio::time::sleep(ip_delay).await;
                }
                None => {
                    return Ok(None);
                }
            }
        }

        Ok(None)
    })
}

fn server_has_ip(server: &stacker_client::ServerInfo) -> bool {
    server
        .srv_ip
        .as_deref()
        .map(str::trim)
        .is_some_and(|ip| !ip.is_empty())
}

fn choose_server_for_project(
    servers: Vec<stacker_client::ServerInfo>,
    project_id: i32,
    preferred_server_name: Option<&str>,
) -> Option<stacker_client::ServerInfo> {
    let mut matching: Vec<stacker_client::ServerInfo> = servers
        .into_iter()
        .filter(|server| server.project_id == project_id)
        .collect();

    if let Some(preferred_name) = preferred_server_name
        .map(str::trim)
        .filter(|name| !name.is_empty())
    {
        if let Some(position) = matching.iter().position(|server| {
            server.name.as_deref() == Some(preferred_name) && server_has_ip(server)
        }) {
            return Some(matching.remove(position));
        }

        if let Some(position) = matching
            .iter()
            .position(|server| server.name.as_deref() == Some(preferred_name))
        {
            return Some(matching.remove(position));
        }
    }

    if let Some(position) = matching.iter().position(server_has_ip) {
        return Some(matching.remove(position));
    }

    matching.into_iter().next()
}

// ── Local container health-check after `docker compose up` ───

/// Poll `docker compose ps` until all containers are running/healthy
/// or a timeout is reached.
fn watch_local_containers(
    project_dir: &Path,
    config_file: Option<&str>,
    target_override: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::time::{Duration, Instant};

    let compose_path = {
        let output_dir = project_dir.join(OUTPUT_DIR);
        let config_path = match config_file {
            Some(f) => project_dir.join(f),
            None => project_dir.join(DEFAULT_CONFIG_FILE),
        };
        // Try to read compose_file from the resolved local target; fall back to
        // .stacker/docker-compose.yml.
        if let Ok(config) = StackerConfig::from_file(&config_path)
            .and_then(|config| config.with_resolved_deploy_target(target_override))
        {
            if let Some(ref existing) = config.deploy.compose_file {
                let p = project_dir.join(existing);
                if p.exists() {
                    p
                } else {
                    output_dir.join("docker-compose.yml")
                }
            } else {
                output_dir.join("docker-compose.yml")
            }
        } else {
            output_dir.join("docker-compose.yml")
        }
    };

    if !compose_path.exists() {
        return Ok(());
    }

    let compose_str = compose_path.to_string_lossy().to_string();
    let executor = ShellExecutor;
    let timeout = Duration::from_secs(120);
    let poll = Duration::from_secs(3);
    let start = Instant::now();

    let spin = progress::spinner("Checking container health...");

    loop {
        let args = vec!["compose", "-f", &compose_str, "ps", "--format", "json"];
        if let Ok(output) = executor.execute("docker", &args) {
            if output.success() {
                let stdout = output.stdout.trim();
                if !stdout.is_empty() {
                    match parse_container_statuses(stdout) {
                        Some((running, total)) if total > 0 => {
                            progress::update_health(&spin, running, total);
                            if running == total {
                                progress::finish_success(
                                    &spin,
                                    &format!("All {}/{} containers running", running, total),
                                );
                                // Show container summary
                                print_container_summary(&compose_str, &executor);
                                return Ok(());
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        if start.elapsed() > timeout {
            progress::finish_error(
                &spin,
                "Timeout waiting for containers — check `stacker status`",
            );
            return Ok(());
        }

        std::thread::sleep(poll);
    }
}

/// Parse `docker compose ps --format json` output and count running containers.
/// Returns `(running_count, total_count)`.
fn parse_container_statuses(json_str: &str) -> Option<(usize, usize)> {
    // docker compose ps --format json outputs one JSON object per line,
    // or a JSON array depending on the version.
    let containers: Vec<serde_json::Value> = if json_str.trim_start().starts_with('[') {
        serde_json::from_str(json_str).ok()?
    } else {
        // One JSON object per line
        json_str
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .collect()
    };

    let total = containers.len();
    let running = containers
        .iter()
        .filter(|c| {
            let state = c.get("State").and_then(|v| v.as_str()).unwrap_or("");
            state == "running"
        })
        .count();

    Some((running, total))
}

/// Print a brief container summary table.
fn print_container_summary(compose_str: &str, executor: &dyn CommandExecutor) {
    let args = vec!["compose", "-f", compose_str, "ps", "--format", "table"];
    if let Ok(output) = executor.execute("docker", &args) {
        if output.success() && !output.stdout.trim().is_empty() {
            eprintln!();
            eprint!("{}", output.stdout);
        }
    }
}

// ── Cloud deployment status polling after remote deploy ──────

/// Terminal statuses — once reached, watching stops.
const TERMINAL_STATUSES: &[&str] = &["completed", "failed", "cancelled", "error", "paused"];

fn is_terminal(status: &str) -> bool {
    TERMINAL_STATUSES.iter().any(|s| *s == status)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeploymentWatchOutcome {
    Completed,
    Failed,
    Unknown,
}

/// Watch remote deployment status until it reaches a terminal state.
fn watch_cloud_deployment(
    result: &DeployResult,
) -> Result<DeploymentWatchOutcome, Box<dyn std::error::Error>> {
    use std::time::Duration;

    let (base_url, creds) = match resolve_saved_stacker_base_url("deployment status") {
        Ok(values) => values,
        Err(e) => {
            eprintln!("  Cannot watch deployment status: {}", e);
            eprintln!("  Run `stacker status --watch` later to check progress.");
            return Ok(DeploymentWatchOutcome::Unknown);
        }
    };

    let project_id = match result.project_id {
        Some(id) => id as i32,
        None => {
            eprintln!("  No project ID — run `stacker status --watch` to check progress.");
            return Ok(DeploymentWatchOutcome::Unknown);
        }
    };

    eprintln!();
    let spin = progress::spinner("Watching deployment progress...");

    let poll_interval = Duration::from_secs(5);
    let timeout = Duration::from_secs(600); // 10 min max watch

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    rt.block_on(async {
        let client =
            StackerClient::new_for_target(&base_url, &creds.access_token, result.target.clone());
        let start = std::time::Instant::now();
        let mut last_status = String::new();
        let mut last_message: Option<String> = None;

        loop {
            match client.get_deployment_status_by_project(project_id).await {
                Ok(Some(info)) => {
                    let status_changed = info.status != last_status;
                    let message_changed = info.status_message != last_message;
                    if status_changed || message_changed {
                        let icon = progress::status_icon(&info.status);
                        progress::update_message(
                            &spin,
                            &format!(
                                "{} Deployment #{} — {}{}",
                                icon,
                                info.id,
                                info.status,
                                info.status_message
                                    .as_ref()
                                    .map(|m| format!(": {}", m))
                                    .unwrap_or_default(),
                            ),
                        );
                        last_status = info.status.clone();
                        last_message = info.status_message.clone();
                    }

                    if is_terminal(&info.status) {
                        if info.status == "completed" {
                            progress::finish_success(
                                &spin,
                                &format!("Deployment #{} completed", info.id),
                            );
                            return Ok(DeploymentWatchOutcome::Completed);
                        } else {
                            let msg = info.status_message.as_deref().unwrap_or(&info.status);
                            progress::finish_error(
                                &spin,
                                &format!("Deployment #{} — {}", info.id, msg),
                            );
                            return Ok(DeploymentWatchOutcome::Failed);
                        }
                    }
                }
                Ok(None) => {
                    if last_status.is_empty() {
                        progress::update_message(&spin, "Waiting for deployment to appear...");
                        last_status = "<none>".to_string();
                    }
                }
                Err(e) => {
                    progress::finish_success(
                        &spin,
                        "Deployment request accepted; live status polling unavailable",
                    );
                    eprintln!("  ⚠ Could not poll live deployment status: {}", e);
                    eprintln!("  Installation may still be in progress.");
                    eprintln!("  Run `stacker status --watch` to retry.");
                    return Ok(DeploymentWatchOutcome::Unknown);
                }
            }

            if start.elapsed() > timeout {
                progress::finish_error(&spin, "Watch timeout (10m) — deployment still in progress");
                eprintln!("  Run `stacker status --watch` to continue watching.");
                return Ok(DeploymentWatchOutcome::Unknown);
            }

            tokio::time::sleep(poll_interval).await;
        }
    })
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Tests
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::credentials::FileCredentialStore;
    use crate::cli::install_runner::CommandOutput;
    use std::sync::Mutex;
    use tempfile::TempDir;

    /// Mock executor that records commands and returns configurable output.
    struct MockExecutor {
        calls: Mutex<Vec<(String, Vec<String>)>>,
        output: CommandOutput,
    }

    impl MockExecutor {
        fn success() -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                output: CommandOutput {
                    exit_code: 0,
                    stdout: "ok".to_string(),
                    stderr: String::new(),
                },
            }
        }
    }

    impl CommandExecutor for MockExecutor {
        fn execute(&self, program: &str, args: &[&str]) -> Result<CommandOutput, CliError> {
            self.calls.lock().unwrap().push((
                program.to_string(),
                args.iter().map(|s| s.to_string()).collect(),
            ));
            Ok(self.output.clone())
        }
    }

    /// Create a tempdir with a minimal stacker.yml for local deploy.
    fn setup_local_project(files: &[(&str, &str)]) -> TempDir {
        let dir = TempDir::new().unwrap();
        for (name, content) in files {
            let path = dir.path().join(name);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(&path, content).unwrap();
        }
        dir
    }

    #[test]
    fn test_scn_004_compose_image_services_register_as_remote_secret_targets() {
        let dir = setup_local_project(&[(
            "docker-compose.yml",
            r#"
services:
  app:
    image: ghcr.io/example/device-api:1.0
  upload:
    image: ghcr.io/example/upload:1.0
    ports:
      - "8081:8080"
    environment:
      S3_BUCKET: "${S3_BUCKET}"
  worker:
    build: .
  nginx_proxy_manager:
    image: jc21/nginx-proxy-manager:latest
"#,
        )]);
        let config = StackerConfig {
            name: "device-api".to_string(),
            ..StackerConfig::default()
        };

        let services = extract_compose_secret_target_services(
            dir.path().join("docker-compose.yml").as_path(),
            &config,
        )
        .unwrap();
        let service_names = services
            .iter()
            .map(|service| service.name.as_str())
            .collect::<Vec<_>>();

        assert_eq!(service_names, vec!["upload"]);
        assert_eq!(services[0].image, "ghcr.io/example/upload:1.0");
        assert_eq!(services[0].ports, vec!["8081:8080"]);
    }

    fn minimal_config_yaml() -> String {
        "name: test-app\napp:\n  type: static\n  path: .\n".to_string()
    }

    fn cloud_config_yaml() -> String {
        "name: test-app\napp:\n  type: static\n  path: .\ndeploy:\n  target: cloud\n  cloud:\n    provider: hetzner\n    region: eu-central\n    size: cpx11\n".to_string()
    }

    fn server_config_yaml() -> String {
        "name: test-app\napp:\n  type: static\n  path: .\ndeploy:\n  target: server\n  server:\n    host: 1.2.3.4\n    user: root\n    port: 22\n".to_string()
    }

    // ── Tests ────────────────────────────────────────

    fn deploy_result_for_target(target: DeployTarget, project_id: Option<i64>) -> DeployResult {
        DeployResult {
            target,
            message: "ok".to_string(),
            server_ip: None,
            deployment_id: None,
            project_id,
            server_name: None,
        }
    }

    fn server_info(
        id: i32,
        project_id: i32,
        name: Option<&str>,
        srv_ip: Option<&str>,
    ) -> stacker_client::ServerInfo {
        stacker_client::ServerInfo {
            id,
            user_id: "user".to_string(),
            project_id,
            cloud_id: Some(7),
            cloud: Some("htz".to_string()),
            region: Some("fsn1".to_string()),
            zone: None,
            server: Some("cpx22".to_string()),
            os: Some("docker-ce".to_string()),
            disk_type: None,
            srv_ip: srv_ip.map(ToOwned::to_owned),
            ssh_port: Some(22),
            ssh_user: Some("root".to_string()),
            name: name.map(ToOwned::to_owned),
            vault_key_path: None,
            connection_mode: "status_panel".to_string(),
            key_status: "active".to_string(),
        }
    }

    #[test]
    fn backup_key_authorization_runs_only_after_real_cloud_deploy_with_project_id() {
        assert!(should_install_cloud_backup_key(
            &deploy_result_for_target(DeployTarget::Cloud, Some(42)),
            false
        ));
        assert!(!should_install_cloud_backup_key(
            &deploy_result_for_target(DeployTarget::Cloud, Some(42)),
            true
        ));
        assert!(!should_install_cloud_backup_key(
            &deploy_result_for_target(DeployTarget::Local, Some(42)),
            false
        ));
        assert!(!should_install_cloud_backup_key(
            &deploy_result_for_target(DeployTarget::Server, Some(42)),
            false
        ));
        assert!(!should_install_cloud_backup_key(
            &deploy_result_for_target(DeployTarget::Cloud, None),
            false
        ));
    }

    #[test]
    fn choose_server_for_project_prefers_requested_server_name_with_ip() {
        let servers = vec![
            server_info(1, 75, Some("old"), Some("203.0.113.10")),
            server_info(2, 75, Some("coolify-current"), Some("203.0.113.42")),
            server_info(3, 75, Some("coolify-current"), None),
        ];

        let selected = choose_server_for_project(servers, 75, Some("coolify-current"))
            .expect("matching server should be selected");

        assert_eq!(selected.id, 2);
        assert_eq!(selected.srv_ip.as_deref(), Some("203.0.113.42"));
    }

    #[test]
    fn choose_server_for_project_ignores_other_projects_and_prefers_ip() {
        let servers = vec![
            server_info(1, 10, Some("wrong-project"), Some("203.0.113.1")),
            server_info(2, 75, Some("pending"), None),
            server_info(3, 75, Some("ready"), Some("203.0.113.42")),
        ];

        let selected = choose_server_for_project(servers, 75, None)
            .expect("server with IP should be selected");

        assert_eq!(selected.id, 3);
    }

    #[test]
    fn extracts_server_ip_from_deployment_status_message() {
        assert_eq!(
            extract_ipv4_from_text("178.104.222.170: Copy files is done"),
            Some("178.104.222.170".to_string())
        );
        assert_eq!(extract_ipv4_from_text("Deployment still in progress"), None);
        assert_eq!(
            extract_ipv4_from_text("invalid 999.104.222.170: message"),
            None
        );
    }

    #[test]
    fn test_deploy_local_dry_run_generates_files() {
        let dir = setup_local_project(&[
            ("index.html", "<h1>hello</h1>"),
            ("stacker.yml", &minimal_config_yaml()),
        ]);
        let executor = MockExecutor::success();

        let result = run_deploy(
            dir.path(),
            None,
            Some("local"),
            true,
            false,
            false,
            &executor,
            &RemoteDeployOverrides::default(),
            "runc",
        );
        assert!(result.is_ok());

        // Generated files should exist
        assert!(dir.path().join(".stacker/Dockerfile").exists());
        assert!(dir.path().join(".stacker/docker-compose.yml").exists());
    }

    #[test]
    fn test_deploy_local_preserves_existing_dockerfile() {
        let config = "name: test-app\napp:\n  type: static\n  path: .\n  dockerfile: Dockerfile\n";
        let dir = setup_local_project(&[
            ("index.html", "<h1>hello</h1>"),
            ("Dockerfile", "FROM custom:latest\nCOPY . /custom"),
            ("stacker.yml", config),
        ]);
        let executor = MockExecutor::success();

        let result = run_deploy(
            dir.path(),
            None,
            Some("local"),
            true,
            false,
            false,
            &executor,
            &RemoteDeployOverrides::default(),
            "runc",
        );
        assert!(result.is_ok());

        // Custom Dockerfile should not be overwritten
        let df = std::fs::read_to_string(dir.path().join("Dockerfile")).unwrap();
        assert!(df.contains("custom:latest"));

        // .stacker/Dockerfile should NOT be generated (app.dockerfile is set)
        assert!(!dir.path().join(".stacker/Dockerfile").exists());
    }

    #[test]
    fn test_deploy_local_uses_existing_compose() {
        let config = "name: test-app\napp:\n  type: static\n  path: .\ndeploy:\n  compose_file: docker-compose.yml\n";
        let dir = setup_local_project(&[
            ("index.html", "<h1>hello</h1>"),
            (
                "docker-compose.yml",
                "version: '3.8'\nservices:\n  web:\n    image: nginx\n",
            ),
            ("stacker.yml", config),
        ]);
        let executor = MockExecutor::success();

        let result = run_deploy(
            dir.path(),
            None,
            Some("local"),
            true,
            false,
            false,
            &executor,
            &RemoteDeployOverrides::default(),
            "runc",
        );
        assert!(result.is_ok());

        // .stacker/docker-compose.yml should NOT be generated
        assert!(!dir.path().join(".stacker/docker-compose.yml").exists());
    }

    #[test]
    fn test_deploy_creates_missing_dotenv_from_example_for_compose_env_file() {
        let config = "name: test-app\napp:\n  type: static\n  path: .\ndeploy:\n  compose_file: docker-compose.yml\n";
        let dir = setup_local_project(&[
            ("index.html", "<h1>hello</h1>"),
            (
                "docker-compose.yml",
                "services:\n  web:\n    image: nginx\n    env_file: .env\n",
            ),
            (".env.example", "APP_ENV=production\n"),
            ("stacker.yml", config),
        ]);
        let executor = MockExecutor::success();

        let result = run_deploy(
            dir.path(),
            None,
            Some("local"),
            true,
            false,
            false,
            &executor,
            &RemoteDeployOverrides::default(),
            "runc",
        );

        assert!(result.is_ok());
        let env_path = dir.path().join(".env");
        assert_eq!(
            std::fs::read_to_string(&env_path).unwrap(),
            "APP_ENV=production\n"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&env_path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn test_deploy_reports_missing_env_file_without_raw_bundle_error() {
        let config = "name: test-app\napp:\n  type: static\n  path: .\ndeploy:\n  compose_file: docker-compose.yml\n";
        let dir = setup_local_project(&[
            (
                "docker-compose.yml",
                "services:\n  web:\n    image: nginx\n    env_file: .env\n",
            ),
            ("stacker.yml", config),
        ]);
        let executor = MockExecutor::success();

        let err = run_deploy(
            dir.path(),
            None,
            Some("local"),
            true,
            false,
            false,
            &executor,
            &RemoteDeployOverrides::default(),
            "runc",
        )
        .unwrap_err();

        let msg = err.to_string();
        assert!(msg.contains("Missing env file referenced by compose env_file"));
        assert!(msg.contains(".env.example"));
    }

    #[test]
    fn test_deploy_falls_back_when_configured_compose_missing() {
        let config = "name: test-app\napp:\n  type: static\n  path: .\ndeploy:\n  compose_file: stacker/docker-compose.yml\n";
        let dir = setup_local_project(&[
            ("index.html", "<h1>hello</h1>"),
            ("stacker.yml", config),
            (
                ".stacker/docker-compose.yml",
                "services:\n  app:\n    image: nginx\n",
            ),
        ]);
        let executor = MockExecutor::success();

        let result = run_deploy(
            dir.path(),
            None,
            Some("local"),
            true,
            false,
            false,
            &executor,
            &RemoteDeployOverrides::default(),
            "runc",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_deploy_environment_override_uses_environment_compose() {
        let config = r#"
name: device-api
app:
  type: static
  path: .
deploy:
  target: local
"#;
        let compose = r#"
services:
  api:
    image: device-api:latest
    environment:
      RUST_LOG: warning
"#;
        let dir = setup_local_project(&[
            ("index.html", "<h1>hello</h1>"),
            ("stacker.yml", config),
            ("docker/production/compose.yml", compose),
        ]);
        let executor = MockExecutor::success();

        let result = run_deploy_for_environment(
            dir.path(),
            None,
            Some("local"),
            Some("production"),
            true,
            false,
            false,
            &executor,
            &RemoteDeployOverrides::default(),
            "runc",
        );

        assert!(result.is_ok());
        assert!(
            !dir.path().join(".stacker/docker-compose.yml").exists(),
            "environment compose should be used instead of generating .stacker/docker-compose.yml"
        );
    }

    #[test]
    fn test_deploy_local_with_image_skips_build() {
        let config = "name: test-app\napp:\n  type: static\n  path: .\n  image: nginx:latest\n";
        let dir = setup_local_project(&[("stacker.yml", config)]);
        let executor = MockExecutor::success();

        let result = run_deploy(
            dir.path(),
            None,
            Some("local"),
            true,
            false,
            false,
            &executor,
            &RemoteDeployOverrides::default(),
            "runc",
        );
        assert!(result.is_ok());

        // No Dockerfile should be generated (using image)
        assert!(!dir.path().join(".stacker/Dockerfile").exists());
    }

    #[test]
    fn test_deploy_cloud_requires_login() {
        let dir = setup_local_project(&[("stacker.yml", &cloud_config_yaml())]);
        let executor = MockExecutor::success();
        let store = FileCredentialStore::new(dir.path().join("credentials.json"));
        let cred_manager = CredentialsManager::new(store);

        let result = run_deploy_with_credentials_manager(
            dir.path(),
            None,
            None,
            None,
            true,
            false,
            false,
            &executor,
            &RemoteDeployOverrides::default(),
            "runc",
            &cred_manager,
        );
        assert!(result.is_err());

        let err = format!("{}", result.unwrap_err());
        assert!(
            err.contains("Login required") || err.contains("login"),
            "Expected login error, got: {}",
            err
        );
    }

    #[test]
    fn test_deploy_cloud_requires_provider() {
        // Cloud target but no cloud config
        let config = "name: test-app\napp:\n  type: static\n  path: .\ndeploy:\n  target: cloud\n";
        let dir = setup_local_project(&[("stacker.yml", config)]);
        let executor = MockExecutor::success();

        // This should fail at validation since no credentials exist
        let result = run_deploy(
            dir.path(),
            None,
            None,
            true,
            false,
            false,
            &executor,
            &RemoteDeployOverrides::default(),
            "runc",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_deploy_server_requires_host() {
        let config = "name: test-app\napp:\n  type: static\n  path: .\ndeploy:\n  target: server\n";
        let dir = setup_local_project(&[("stacker.yml", config)]);
        let executor = MockExecutor::success();
        let store = FileCredentialStore::new(dir.path().join("credentials.json"));
        let cred_manager = CredentialsManager::new(store);
        cred_manager
            .save(&StoredCredentials {
                access_token: "test-token".to_string(),
                refresh_token: None,
                token_type: "Bearer".to_string(),
                expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
                email: Some("test@example.com".to_string()),
                server_url: Some("https://example.test".to_string()),
                org: None,
                domain: None,
            })
            .unwrap();

        let result = run_deploy_with_credentials_manager(
            dir.path(),
            None,
            None,
            None,
            true,
            false,
            false,
            &executor,
            &RemoteDeployOverrides::default(),
            "runc",
            &cred_manager,
        );
        assert!(result.is_err());

        let err = format!("{}", result.unwrap_err());
        assert!(
            err.contains("host") || err.contains("Host") || err.contains("server"),
            "Expected server host error, got: {}",
            err
        );
    }

    #[test]
    fn test_deploy_missing_config_file() {
        let dir = TempDir::new().unwrap();
        let executor = MockExecutor::success();

        let result = run_deploy(
            dir.path(),
            None,
            None,
            true,
            false,
            false,
            &executor,
            &RemoteDeployOverrides::default(),
            "runc",
        );
        assert!(result.is_err());

        let err = format!("{}", result.unwrap_err());
        assert!(
            err.contains("not found") || err.contains("Configuration"),
            "Expected config not found error, got: {}",
            err
        );
    }

    #[test]
    fn test_deploy_custom_file_flag() {
        let dir = setup_local_project(&[
            ("index.html", "<h1>hello</h1>"),
            ("custom.yml", &minimal_config_yaml()),
        ]);
        let executor = MockExecutor::success();

        let result = run_deploy(
            dir.path(),
            Some("custom.yml"),
            Some("local"),
            true,
            false,
            false,
            &executor,
            &RemoteDeployOverrides::default(),
            "runc",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_deploy_force_rebuild() {
        let dir = setup_local_project(&[
            ("index.html", "<h1>hello</h1>"),
            ("stacker.yml", &minimal_config_yaml()),
        ]);
        let executor = MockExecutor::success();

        // First deploy creates files
        let result = run_deploy(
            dir.path(),
            None,
            Some("local"),
            true,
            false,
            false,
            &executor,
            &RemoteDeployOverrides::default(),
            "runc",
        );
        assert!(result.is_ok());

        // Second deploy without force_rebuild should succeed (reuses existing files)
        let result2 = run_deploy(
            dir.path(),
            None,
            Some("local"),
            true,
            false,
            false,
            &executor,
            &RemoteDeployOverrides::default(),
            "runc",
        );
        assert!(result2.is_ok());

        // With force_rebuild should also succeed (regenerates files)
        let result3 = run_deploy(
            dir.path(),
            None,
            Some("local"),
            true,
            true,
            false,
            &executor,
            &RemoteDeployOverrides::default(),
            "runc",
        );
        assert!(result3.is_ok());
    }

    #[test]
    fn test_deploy_target_strategy_dispatch() {
        // Validate that strategy_for returns the right type
        let local = strategy_for(&DeployTarget::Local);
        let cloud = strategy_for(&DeployTarget::Cloud);
        let server = strategy_for(&DeployTarget::Server);

        // We can't check concrete types directly, but we can ensure
        // validation behavior matches expectations:
        let minimal_config = StackerConfig::from_str("name: test\napp:\n  type: static\n").unwrap();

        // Local always passes validation
        assert!(local.validate(&minimal_config).is_ok());
        // Cloud fails without cloud config
        assert!(cloud.validate(&minimal_config).is_err());
        // Server fails without server config
        assert!(server.validate(&minimal_config).is_err());
    }

    #[test]
    fn test_deploy_runs_pre_build_hook_noted() {
        let config =
            "name: test-app\napp:\n  type: static\n  path: .\nhooks:\n  pre_build: ./build.sh\n";
        let dir = setup_local_project(&[("index.html", "<h1>hello</h1>"), ("stacker.yml", config)]);
        let executor = MockExecutor::success();

        // Dry-run should succeed (hooks are just noted, not executed in dry-run)
        let result = run_deploy(
            dir.path(),
            None,
            Some("local"),
            true,
            false,
            false,
            &executor,
            &RemoteDeployOverrides::default(),
            "runc",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_fallback_hints_for_npm_ci_error() {
        let hints =
            fallback_troubleshooting_hints("failed to solve: /bin/sh -c npm ci --production");
        assert!(hints.iter().any(|h| h.contains("npm ci failed")));
    }

    #[test]
    fn test_compose_app_build_source_reads_context_and_dockerfile() {
        let dir = TempDir::new().unwrap();
        let compose_path = dir.path().join(".stacker").join("docker-compose.yml");
        std::fs::create_dir_all(compose_path.parent().unwrap()).unwrap();
        std::fs::write(
            &compose_path,
            "services:\n  app:\n    build:\n      context: ..\n      dockerfile: .stacker/Dockerfile\n",
        )
        .unwrap();

        let source = compose_app_build_source(&compose_path).unwrap();
        assert!(source.contains("context="));
        assert!(source.contains("dockerfile="));
        assert!(source.contains(".stacker/Dockerfile"));
    }

    #[test]
    fn test_build_troubleshoot_error_log_handles_missing_files() {
        let dir = TempDir::new().unwrap();
        let log = build_troubleshoot_error_log(dir.path(), "docker compose failed");
        assert!(log.contains("docker compose failed"));
        assert!(log.contains("(not found)"));
    }

    #[test]
    fn test_normalize_generated_compose_paths_fixes_stacker_context_and_version() {
        let dir = TempDir::new().unwrap();
        let stacker_dir = dir.path().join(".stacker");
        std::fs::create_dir_all(&stacker_dir).unwrap();

        let compose_path = stacker_dir.join("docker-compose.yml");
        let compose = r#"
version: "3.9"
services:
    app:
        build:
            context: .
            dockerfile: .stacker/Dockerfile
"#;
        std::fs::write(&compose_path, compose).unwrap();

        normalize_generated_compose_paths(&compose_path).unwrap();

        let normalized = std::fs::read_to_string(&compose_path).unwrap();
        assert!(!normalized.contains("version:"));
        assert!(normalized.contains("context: .."));
        assert!(normalized.contains("dockerfile: .stacker/Dockerfile"));
    }

    #[test]
    fn test_normalize_generated_compose_paths_adds_stacker_dockerfile_for_app_when_missing() {
        let dir = TempDir::new().unwrap();
        let stacker_dir = dir.path().join(".stacker");
        std::fs::create_dir_all(&stacker_dir).unwrap();

        let compose_path = stacker_dir.join("docker-compose.yml");
        let compose = r#"
services:
    app:
        build:
            context: .
"#;
        std::fs::write(&compose_path, compose).unwrap();

        normalize_generated_compose_paths(&compose_path).unwrap();

        let normalized = std::fs::read_to_string(&compose_path).unwrap();
        assert!(normalized.contains("context: .."));
        assert!(normalized.contains("dockerfile: .stacker/Dockerfile"));
    }

    #[test]
    fn test_validate_compose_for_deploy_allows_unique_published_ports() {
        let dir = TempDir::new().unwrap();
        let compose_path = dir.path().join("docker-compose.yml");
        let compose = r#"
services:
  web:
    image: nginx:latest
    ports:
      - "80:80"
  api:
    image: ghcr.io/example/api:latest
    ports:
      - published: 8080
        target: 8080
"#;
        std::fs::write(&compose_path, compose).unwrap();

        validate_compose_for_deploy(&compose_path).unwrap();
    }

    #[test]
    fn test_validate_compose_for_deploy_rejects_duplicate_published_ports() {
        let dir = TempDir::new().unwrap();
        let compose_path = dir.path().join("docker-compose.yml");
        let compose = r#"
services:
  nginx-proxy-manager:
    image: jc21/nginx-proxy-manager:latest
    ports:
      - "80:80"
      - "81:81"
      - "443:443"
  nginx_proxy_manager:
    image: jc21/nginx-proxy-manager:latest
    ports:
      - published: 80
        target: 80
      - published: 81
        target: 81
      - published: 443
        target: 443
"#;
        std::fs::write(&compose_path, compose).unwrap();

        let err = validate_compose_for_deploy(&compose_path).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("conflicting published host ports"));
        assert!(msg.contains("port 80"));
        assert!(msg.contains("nginx-proxy-manager"));
        assert!(msg.contains("nginx_proxy_manager"));
    }

    #[test]
    fn test_validate_compose_for_deploy_allows_include_only_compose() {
        let dir = TempDir::new().unwrap();
        let compose_path = dir.path().join("docker-compose.yml");
        let compose = r#"
include:
  - ../../postgres/docker/local/compose.yml
  - ../../website/docker/local/compose.yml
"#;
        std::fs::write(&compose_path, compose).unwrap();

        validate_compose_for_deploy(&compose_path).unwrap();
    }

    #[test]
    fn test_collect_compose_image_refs_follows_includes_and_skips_build_services() {
        let dir = TempDir::new().unwrap();
        let root_compose = dir.path().join("docker-compose.yml");
        let services_dir = dir.path().join("services");
        std::fs::create_dir_all(&services_dir).unwrap();
        let api_compose = services_dir.join("api.yml");
        let web_compose = services_dir.join("web.yml");

        std::fs::write(
            &root_compose,
            "include:\n  - services/api.yml\n  - services/web.yml\n",
        )
        .unwrap();
        std::fs::write(
            &api_compose,
            "services:\n  api:\n    image: optimum/syncopia-device-api:latest\n  worker:\n    image: ghcr.io/example/worker:latest\n",
        )
        .unwrap();
        std::fs::write(
            &web_compose,
            "services:\n  web:\n    build: .\n    image: optimum/syncopia-website:latest\n  proxy:\n    image: jc21/nginx-proxy-manager:latest\n",
        )
        .unwrap();

        let images = collect_compose_image_refs(&root_compose).unwrap();
        let collected: Vec<String> = images.into_iter().map(|image| image.image).collect();

        assert_eq!(
            collected,
            vec![
                "optimum/syncopia-device-api:latest".to_string(),
                "ghcr.io/example/worker:latest".to_string(),
                "jc21/nginx-proxy-manager:latest".to_string(),
            ]
        );
    }

    #[test]
    fn test_parse_docker_hub_image_target_supports_official_namespaced_and_prefixed_images() {
        let official = parse_docker_hub_image_target("postgres:17-alpine").unwrap();
        assert_eq!(official.namespace, None);
        assert_eq!(official.repository, "postgres");
        assert_eq!(official.tag, "17-alpine");

        let namespaced = parse_docker_hub_image_target("optimum/syncopia-device-api").unwrap();
        assert_eq!(namespaced.namespace.as_deref(), Some("optimum"));
        assert_eq!(namespaced.repository, "syncopia-device-api");
        assert_eq!(namespaced.tag, "latest");

        let prefixed =
            parse_docker_hub_image_target("docker.io/optimum/syncopia-website:main").unwrap();
        assert_eq!(prefixed.namespace.as_deref(), Some("optimum"));
        assert_eq!(prefixed.repository, "syncopia-website");
        assert_eq!(prefixed.tag, "main");

        assert!(
            parse_docker_hub_image_target("ghcr.io/optimum/syncopia-device-api:latest").is_none()
        );
    }

    #[test]
    fn test_registry_auth_candidates_ignore_official_public_images() {
        let dir = TempDir::new().unwrap();
        let compose_path = dir.path().join("docker-compose.yml");
        let image_env = std::collections::BTreeMap::new();
        std::fs::write(
            &compose_path,
            "services:\n  db:\n    image: postgres:17\n  api:\n    image: optimum/syncopia-api:latest\n  sidecar:\n    image: ghcr.io/acme/sidecar:latest\n",
        )
        .unwrap();

        let candidates = collect_registry_auth_candidate_images(&compose_path, &image_env).unwrap();

        assert_eq!(
            candidates,
            vec![
                "optimum/syncopia-api:latest".to_string(),
                "ghcr.io/acme/sidecar:latest".to_string()
            ]
        );
    }

    #[test]
    fn test_active_stacker_base_url_prefers_logged_in_server_url() {
        let creds = StoredCredentials {
            access_token: "token".to_string(),
            refresh_token: None,
            token_type: "Bearer".to_string(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            email: Some("test@example.com".to_string()),
            server_url: Some("https://dev.try.direct/server/stacker/api/v1".to_string()),
            org: None,
            domain: None,
        };

        assert_eq!(
            active_stacker_base_url(&creds),
            "https://dev.try.direct/server/stacker"
        );
    }

    #[test]
    fn test_cloud_config_from_cli_override_info_sets_in_memory_key() {
        let cloud = stacker_client::CloudInfo {
            id: 5,
            user_id: "u1".to_string(),
            name: "htz-5".to_string(),
            provider: "htz".to_string(),
            cloud_token: None,
            cloud_key: None,
            cloud_secret: None,
            save_token: None,
        };

        let config = cloud_config_from_info(&cloud).unwrap();

        assert_eq!(config.provider, CloudProvider::Hetzner);
        assert_eq!(config.key.as_deref(), Some("htz-5"));
        assert_eq!(config.orchestrator, CloudOrchestrator::Remote);
    }

    #[test]
    fn test_cloud_config_from_cli_override_preserves_existing_region_and_size() {
        let existing = CloudConfig {
            provider: CloudProvider::Hetzner,
            orchestrator: CloudOrchestrator::Remote,
            region: Some("nbg1".to_string()),
            size: Some("cpx21".to_string()),
            install_image: None,
            remote_payload_file: None,
            ssh_key: None,
            key: None,
            server: None,
        };
        let cloud = stacker_client::CloudInfo {
            id: 5,
            user_id: "u1".to_string(),
            name: "htz-5".to_string(),
            provider: "htz".to_string(),
            cloud_token: None,
            cloud_key: None,
            cloud_secret: None,
            save_token: None,
        };

        let config = merge_cloud_config_from_info(Some(&existing), &cloud).unwrap();

        assert_eq!(config.key.as_deref(), Some("htz-5"));
        assert_eq!(config.region.as_deref(), Some("nbg1"));
        assert_eq!(config.size.as_deref(), Some("cpx21"));
    }

    #[test]
    fn test_validate_compose_images_for_deploy_reports_missing_docker_hub_image_before_deploy() {
        let dir = TempDir::new().unwrap();
        let compose_path = dir.path().join("docker-compose.yml");
        let image_env = std::collections::BTreeMap::new();
        std::fs::write(
            &compose_path,
            "services:\n  api:\n    image: optimum/syncopia-device-api:latest\n  worker:\n    image: ghcr.io/example/worker:latest\n  proxy:\n    image: jc21/nginx-proxy-manager:latest\n",
        )
        .unwrap();

        let err = validate_compose_images_for_deploy_with_checker(
            &compose_path,
            &image_env,
            None,
            |target| {
                Ok(if target.repository == "syncopia-device-api" {
                    DockerHubImageCheckResult::Missing
                } else {
                    DockerHubImageCheckResult::Available
                })
            },
        )
        .unwrap_err();

        let message = err.to_string();
        assert!(message.contains("Compose image preflight failed"));
        assert!(message.contains("docker.io/optimum/syncopia-device-api:latest"));
        assert!(message.contains("service 'api'"));
        assert!(!message.contains("ghcr.io/example/worker:latest"));
    }

    #[test]
    fn test_required_image_platform_for_deploy_target_only_enforces_remote_linux_amd64() {
        assert_eq!(
            required_image_platform_for_deploy_target(&DeployTarget::Local),
            None
        );
        assert_eq!(
            required_image_platform_for_deploy_target(&DeployTarget::Cloud),
            Some(RequiredImagePlatform::linux_amd64())
        );
        assert_eq!(
            required_image_platform_for_deploy_target(&DeployTarget::Server),
            Some(RequiredImagePlatform::linux_amd64())
        );
    }

    #[test]
    fn test_validate_compose_images_for_deploy_reports_missing_required_platform_before_remote_deploy(
    ) {
        let dir = TempDir::new().unwrap();
        let compose_path = dir.path().join("docker-compose.yml");
        let image_env = std::collections::BTreeMap::new();
        let required_platform = RequiredImagePlatform::linux_amd64();
        std::fs::write(
            &compose_path,
            "services:
  api:
    image: optimum/syncopia-device-api:latest
  proxy:
    image: jc21/nginx-proxy-manager:latest
",
        )
        .unwrap();

        let err = validate_compose_images_for_deploy_with_checker(
            &compose_path,
            &image_env,
            Some(&required_platform),
            |target| {
                Ok(if target.repository == "syncopia-device-api" {
                    DockerHubImageCheckResult::MissingPlatform {
                        required: required_platform.clone(),
                        available: vec!["linux/arm64".to_string()],
                    }
                } else {
                    DockerHubImageCheckResult::Available
                })
            },
        )
        .unwrap_err();

        let message = err.to_string();
        assert!(message.contains("required platform linux/amd64"));
        assert!(message.contains("available platforms: linux/arm64"));
        assert!(message.contains("docker.io/optimum/syncopia-device-api:latest"));
        assert!(message.contains("service 'api'"));
    }

    #[test]
    fn test_resolve_compose_image_reference_supports_plain_default_and_required_forms() {
        let mut image_env = std::collections::BTreeMap::new();
        image_env.insert(
            "WEBSITE_IMAGE".to_string(),
            "optimum/syncopia-website".to_string(),
        );

        assert_eq!(
            resolve_compose_image_reference("${WEBSITE_IMAGE}:latest", &image_env).unwrap(),
            "optimum/syncopia-website:latest"
        );
        assert_eq!(
            resolve_compose_image_reference(
                "${DEVICE_API_IMAGE:-syncopia/device-api:dev}",
                &image_env
            )
            .unwrap(),
            "syncopia/device-api:dev"
        );
        assert_eq!(
            resolve_compose_image_reference(
                "${WEBSITE_IMAGE:?Set WEBSITE_IMAGE to a published website image}:latest",
                &image_env
            )
            .unwrap(),
            "optimum/syncopia-website:latest"
        );
    }

    #[test]
    fn test_resolve_compose_image_reference_errors_for_missing_required_variable() {
        let image_env = std::collections::BTreeMap::new();
        let err = resolve_compose_image_reference(
            "${WEBSITE_IMAGE:?Set WEBSITE_IMAGE to a published website image}:latest",
            &image_env,
        )
        .unwrap_err();
        assert!(err.contains("Set WEBSITE_IMAGE to a published website image"));
    }

    #[test]
    fn test_validate_compose_images_for_deploy_resolves_environment_images_before_checking() {
        let dir = TempDir::new().unwrap();
        let compose_path = dir.path().join("docker-compose.yml");
        let mut image_env = std::collections::BTreeMap::new();
        image_env.insert(
            "WEBSITE_IMAGE".to_string(),
            "optimum/syncopia-website".to_string(),
        );
        std::fs::write(
            &compose_path,
            "services:\n  website:\n    image: ${WEBSITE_IMAGE}:latest\n  proxy:\n    image: jc21/nginx-proxy-manager:latest\n",
        )
        .unwrap();

        let err = validate_compose_images_for_deploy_with_checker(
            &compose_path,
            &image_env,
            None,
            |target| {
                Ok(if target.repository == "syncopia-website" {
                    DockerHubImageCheckResult::Missing
                } else {
                    DockerHubImageCheckResult::Available
                })
            },
        )
        .unwrap_err();

        let message = err.to_string();
        assert!(message.contains("docker.io/optimum/syncopia-website:latest"));
        assert!(message.contains("service 'website'"));
    }

    #[test]
    fn test_extract_compose_public_port_specs_resolves_env_defaults() {
        let dir = TempDir::new().unwrap();
        let compose_path = dir.path().join("compose.yml");
        std::fs::write(
            &compose_path,
            r#"
services:
  coolify:
    image: coollabsio/coolify:latest
    ports:
      - "${APP_PORT:-8000}:8080"
      - "127.0.0.1:5432:5432"
      - "53:53/udp"
  soketi:
    image: coollabsio/coolify-realtime:1.0.13
    ports:
      - "${SOKETI_PORT:-6001}:6001"
      - "6002:6002"
  api:
    image: example/api:latest
    ports:
      - target: 9000
        published: "${API_PORT:-19000}"
        protocol: tcp
"#,
        )
        .unwrap();

        let env = std::collections::BTreeMap::new();
        let ports = extract_compose_public_port_specs(&compose_path, &env).unwrap();

        assert_eq!(
            ports,
            vec!["8000:8080", "6001:6001", "6002:6002", "19000:9000"]
        );
    }

    #[test]
    fn test_merge_compose_public_ports_into_app_config_prevents_default_custom_port() {
        let dir = TempDir::new().unwrap();
        let compose_path = dir.path().join("compose.yml");
        std::fs::write(
            &compose_path,
            r#"
services:
  coolify:
    image: coollabsio/coolify:latest
    ports:
      - "${APP_PORT:-8000}:8080"
"#,
        )
        .unwrap();
        let mut config = StackerConfig::from_str(
            "name: coolify\napp:\n  type: custom\n  image: coollabsio/coolify:latest\n",
        )
        .unwrap();
        let env = std::collections::BTreeMap::new();

        merge_compose_public_ports_into_app_config(&mut config, &compose_path, &env).unwrap();

        assert_eq!(config.app.ports, vec!["8000:8080"]);
    }

    #[test]
    fn test_compose_public_ports_flow_into_project_body_shared_ports() {
        let dir = TempDir::new().unwrap();
        let compose_path = dir.path().join("compose.yml");
        std::fs::write(
            &compose_path,
            r#"
services:
  coolify:
    image: coollabsio/coolify:latest
    ports:
      - "${APP_PORT:-8000}:8080"
"#,
        )
        .unwrap();
        let mut config = StackerConfig::from_str(
            "name: coolify\napp:\n  type: custom\n  image: coollabsio/coolify:latest\n",
        )
        .unwrap();
        let env = std::collections::BTreeMap::new();

        merge_compose_public_ports_into_app_config(&mut config, &compose_path, &env).unwrap();
        let project_body = crate::cli::stacker_client::build_project_body(&config);

        assert_eq!(
            project_body["custom"]["web"][0]["shared_ports"],
            serde_json::json!([{"host_port": "8000", "container_port": "8080"}])
        );
    }

    #[test]
    fn test_coolify_project_compose_ports_define_cloud_firewall_ports() {
        let dir = TempDir::new().unwrap();
        let compose_dir = dir.path().join("docker/production");
        std::fs::create_dir_all(&compose_dir).unwrap();
        let compose_path = compose_dir.join("compose.yml");
        std::fs::write(
            &compose_path,
            r#"
services:
  coolify:
    image: "${REGISTRY_URL:-ghcr.io}/coollabsio/coolify:${LATEST_IMAGE:-latest}"
    container_name: coolify
    ports:
      - "${APP_PORT:-8000}:8080"
    expose:
      - "8080"
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
      soketi:
        condition: service_healthy
  postgres:
    image: postgres:15-alpine
    container_name: coolify-db
  redis:
    image: redis:7-alpine
    container_name: coolify-redis
  soketi:
    image: "${REGISTRY_URL:-ghcr.io}/coollabsio/coolify-realtime:1.0.13"
    container_name: coolify-realtime
    ports:
      - "${SOKETI_PORT:-6001}:6001"
      - "6002:6002"
"#,
        )
        .unwrap();

        let mut config = StackerConfig::from_str(
            r#"
name: coolify
project:
  identity: coolify
app:
  type: custom
  image: "coollabsio/coolify:latest"
proxy:
  type: nginx-proxy-manager
  auto_detect: false
deploy:
  target: cloud
  cloud:
    provider: hetzner
    region: fsn1
    size: cpx22
environments:
  production:
    compose_file: docker/production/compose.yml
monitoring:
  status_panel: true
"#,
        )
        .unwrap()
        .with_resolved_deploy_target(None)
        .unwrap();

        let (_, environment_config) = config
            .resolve_environment_config(Some("production"))
            .unwrap()
            .unwrap();
        if let Some(compose_file) = environment_config.compose_file {
            config.deploy.compose_file = Some(compose_file);
        }

        let env = build_image_env_lookup(dir.path(), &config).unwrap();
        merge_compose_public_ports_into_app_config(&mut config, &compose_path, &env).unwrap();
        let project_body = crate::cli::stacker_client::build_project_body(&config);
        let shared_ports = project_body["custom"]["web"][0]["shared_ports"]
            .as_array()
            .unwrap();

        assert_eq!(
            shared_ports,
            &vec![
                serde_json::json!({"host_port": "8000", "container_port": "8080"}),
                serde_json::json!({"host_port": "6001", "container_port": "6001"}),
                serde_json::json!({"host_port": "6002", "container_port": "6002"}),
            ]
        );
        assert!(shared_ports
            .iter()
            .all(|port| port["host_port"].as_str() != Some("8080")));
        assert!(project_body["custom"]["feature"]
            .as_array()
            .unwrap()
            .is_empty());

        let deploy_form = crate::cli::stacker_client::build_deploy_form(&config);
        assert!(deploy_form["stack"]["extended_features"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("nginx_proxy_manager")));
        assert!(deploy_form["stack"]["integrated_features"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("statuspanel")));
    }

    #[test]
    fn test_parse_deploy_target_valid() {
        assert_eq!(parse_deploy_target("local").unwrap(), DeployTarget::Local);
        assert_eq!(parse_deploy_target("cloud").unwrap(), DeployTarget::Cloud);
        assert_eq!(parse_deploy_target("server").unwrap(), DeployTarget::Server);
        assert_eq!(parse_deploy_target("LOCAL").unwrap(), DeployTarget::Local);
    }

    #[test]
    fn test_parse_deploy_target_invalid() {
        let result = parse_deploy_target("kubernetes");
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("Unknown deploy target"));
    }

    #[test]
    fn test_extract_missing_image_from_manifest_error() {
        let reason = "manifest for optimum/optimumcode:latest not found: manifest unknown";
        let image = extract_missing_image(reason);
        assert_eq!(image.as_deref(), Some("optimum/optimumcode:latest"));
    }

    #[test]
    fn test_fallback_hints_for_manifest_unknown() {
        let hints = fallback_troubleshooting_hints(
            "docker compose failed: manifest for optimum/optimumcode:latest not found: manifest unknown"
        );
        assert!(hints.iter().any(|h| h.contains("Image pull failed")));
        assert!(hints
            .iter()
            .any(|h| h.contains("docker build -t optimum/optimumcode:latest .")));
    }

    #[test]
    fn test_fallback_hints_for_port_conflict() {
        let hints = fallback_troubleshooting_hints(
            "failed to set up container networking: driver failed programming external connectivity on endpoint app: Bind for 0.0.0.0:3000 failed: port is already allocated"
        );
        assert!(hints.iter().any(|h| h.contains("Port conflict")));
        assert!(hints.iter().any(|h| h.contains("lsof -nP -iTCP:3000")));
    }

    #[test]
    fn test_fallback_hints_for_orphan_containers() {
        let hints = fallback_troubleshooting_hints(
            "Found orphan containers ([stackerdb]) for this project",
        );
        assert!(hints.iter().any(|h| h.contains("--remove-orphans")));
    }

    #[test]
    fn test_fallback_hints_for_remote_orchestrator_html_404() {
        let hints = fallback_troubleshooting_hints(
            "Remote orchestrator request failed: HTTP error: User Service error (404): <!DOCTYPE html><html><head><title>Page not found</title></head>"
        );
        assert!(hints.iter().any(|h| h.contains("URL looks incorrect")));
        assert!(hints.iter().any(|h| h.contains("/server/user/auth/login")));
    }

    #[test]
    fn test_ensure_env_file_is_created_when_missing() {
        let dir = TempDir::new().unwrap();
        let config =
            StackerConfig::from_str("name: env-app\napp:\n  type: static\nenv_file: .env\n")
                .unwrap();
        std::fs::write(dir.path().join(".env.example"), "APP_ENV=production\n").unwrap();

        ensure_env_file_if_needed(&config, dir.path()).unwrap();

        let env_path = dir.path().join(".env");
        assert!(env_path.exists());
        let content = std::fs::read_to_string(&env_path).unwrap();
        assert!(content.contains("APP_ENV=production"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(env_path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    // ── Progress / health-check helpers ──────────────

    #[test]
    fn test_parse_container_statuses_json_array() {
        let json = r#"[
            {"State": "running", "Name": "app"},
            {"State": "running", "Name": "db"},
            {"State": "exited", "Name": "worker"}
        ]"#;
        let (running, total) = parse_container_statuses(json).unwrap();
        assert_eq!(running, 2);
        assert_eq!(total, 3);
    }

    #[test]
    fn test_parse_container_statuses_ndjson() {
        let json = "{\"State\": \"running\", \"Name\": \"app\"}\n{\"State\": \"running\", \"Name\": \"db\"}";
        let (running, total) = parse_container_statuses(json).unwrap();
        assert_eq!(running, 2);
        assert_eq!(total, 2);
    }

    #[test]
    fn test_parse_container_statuses_empty() {
        let (running, total) = parse_container_statuses("[]").unwrap();
        assert_eq!(running, 0);
        assert_eq!(total, 0);
    }

    #[test]
    fn test_is_terminal_statuses() {
        assert!(is_terminal("completed"));
        assert!(is_terminal("failed"));
        assert!(is_terminal("cancelled"));
        assert!(is_terminal("error"));
        assert!(is_terminal("paused"));
        assert!(!is_terminal("in_progress"));
        assert!(!is_terminal("pending"));
        assert!(!is_terminal("wait_start"));
    }

    #[test]
    fn test_deploy_result_has_watch_fields() {
        let result = DeployResult {
            target: DeployTarget::Cloud,
            message: "test".to_string(),
            server_ip: None,
            deployment_id: Some(42),
            project_id: Some(7),
            server_name: None,
        };
        assert_eq!(result.deployment_id, Some(42));
        assert_eq!(result.project_id, Some(7));
    }

    #[test]
    fn test_cloud_provider_from_code() {
        // Short codes
        assert_eq!(
            cloud_provider_from_code("htz"),
            Some(CloudProvider::Hetzner)
        );
        assert_eq!(
            cloud_provider_from_code("do"),
            Some(CloudProvider::Digitalocean)
        );
        assert_eq!(cloud_provider_from_code("aws"), Some(CloudProvider::Aws));
        assert_eq!(cloud_provider_from_code("lo"), Some(CloudProvider::Linode));
        assert_eq!(cloud_provider_from_code("vu"), Some(CloudProvider::Vultr));
        // Full names
        assert_eq!(
            cloud_provider_from_code("hetzner"),
            Some(CloudProvider::Hetzner)
        );
        assert_eq!(
            cloud_provider_from_code("digitalocean"),
            Some(CloudProvider::Digitalocean)
        );
        assert_eq!(
            cloud_provider_from_code("linode"),
            Some(CloudProvider::Linode)
        );
        assert_eq!(
            cloud_provider_from_code("vultr"),
            Some(CloudProvider::Vultr)
        );
        // Case insensitive
        assert_eq!(
            cloud_provider_from_code("HTZ"),
            Some(CloudProvider::Hetzner)
        );
        assert_eq!(cloud_provider_from_code("AWS"), Some(CloudProvider::Aws));
        // Unknown
        assert_eq!(cloud_provider_from_code("unknown"), None);
        assert_eq!(cloud_provider_from_code(""), None);
    }

    #[test]
    fn test_with_watch_flags() {
        let cmd = DeployCommand::new(None, None, false, false).with_watch(false, false);
        assert_eq!(cmd.watch, None); // auto

        let cmd = DeployCommand::new(None, None, false, false).with_watch(true, false);
        assert_eq!(cmd.watch, Some(true));

        let cmd = DeployCommand::new(None, None, false, false).with_watch(false, true);
        assert_eq!(cmd.watch, Some(false));

        // --no-watch wins over --watch
        let cmd = DeployCommand::new(None, None, false, false).with_watch(true, true);
        assert_eq!(cmd.watch, Some(false));
    }
}
