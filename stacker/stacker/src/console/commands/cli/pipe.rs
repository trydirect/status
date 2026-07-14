//! `stacker pipe` — CLI subcommands for connecting containerized apps.
//!
//! Pipe commands discover endpoints on running containers and create
//! data connections between them.
//!
//! ```text
//! CLI  ->  Stacker API (enqueue probe_endpoints)  ->  DB queue  ->  Agent probes  ->  Agent reports
//! ```

use crate::cli::error::CliError;
use crate::cli::field_matcher::{DeterministicFieldMatcher, FieldMatcher};
use crate::cli::fmt;
use crate::cli::local_pipe_store::{
    LocalPipeBinding, LocalPipeDiagnostics, LocalPipeDocument, LocalPipeInstance, LocalPipeStore,
    LocalPipeTemplate, NewLocalPipeDocument,
};
use crate::cli::progress;
use crate::cli::runtime::CliRuntime;
use crate::cli::service_catalog::ServiceCatalog;
use crate::cli::stacker_client::{
    AgentCommandInfo, AgentEnqueueRequest, CreatePipeInstanceApiRequest,
    CreatePipeTemplateApiRequest, DeploymentCapabilitiesInfo, PipeTemplateInfo,
};
use crate::console::commands::CallableTrait;
use crate::forms::status_panel::{
    ProbeAttempt, ProbeContainer, ProbeEndpoint, ProbeEndpointsCommandReport, ProbeForm,
    ProbeOperation, ProbeResource, ProbeResourceItem,
};
use chrono::Utc;
use dialoguer::Password;
use pipe_adapter_mail::SmtpTargetAdapter;
use pipe_adapter_sdk::{
    builtin_registry, selector_matches_builtin_kind, PipeAdapterCatalog, PipeAdapterKind,
    PipeAdapterMetadata, PipeAdapterPayload, PipeAdapterReference, PipeAdapterRole,
    PipeTargetAdapter,
};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, IsTerminal};
use std::path::{Path, PathBuf};

/// Default poll timeout for pipe probe commands (seconds).
const PROBE_TIMEOUT_SECS: u64 = 90;

/// Default poll interval (seconds).
const DEFAULT_POLL_INTERVAL_SECS: u64 = 2;

/// Current on-disk schema version for cached pipe discovery results.
const PIPE_SCAN_CACHE_VERSION: u32 = 1;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Deployment hash resolution (mirrors agent module)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Resolve a deployment hash from explicit flag, deployment lock, or stacker.yml project name.
///
/// Resolution order:
/// 1. Explicit `--deployment` flag value
/// 2. `.stacker/deployment.lock` -> `deployment_id` -> API lookup for hash
/// 3. `stacker.yml` project name -> API project lookup -> latest deployment hash
fn resolve_deployment_hash(
    explicit: &Option<String>,
    ctx: &CliRuntime,
) -> Result<String, CliError> {
    match resolve_deployment_context(explicit, ctx)? {
        DeploymentContext::Remote(hash) => Ok(hash),
        DeploymentContext::Local => Err(CliError::ConfigValidation(
            "This command requires a remote deployment, but the active target is 'local'.\n\
             Switch with: stacker target cloud"
                .to_string(),
        )),
    }
}

/// Deployment context resolved from CLI flags, active target, or lockfiles.
#[derive(Debug, Clone, PartialEq)]
pub enum DeploymentContext {
    /// Remote deployment identified by hash.
    Remote(String),
    /// Local mode — no deployment hash, pipes run against local Docker.
    Local,
}

impl DeploymentContext {
    /// Returns `true` when in local mode.
    pub fn is_local(&self) -> bool {
        matches!(self, DeploymentContext::Local)
    }

    /// Returns the deployment hash if remote.
    pub fn hash(&self) -> Option<&str> {
        match self {
            DeploymentContext::Remote(h) => Some(h),
            DeploymentContext::Local => None,
        }
    }
}

/// Helper that prepends `[local] ` when in local mode.
pub fn mode_prefix(ctx_mode: &DeploymentContext) -> &'static str {
    match ctx_mode {
        DeploymentContext::Local => "\x1b[36m[local]\x1b[0m ",
        DeploymentContext::Remote(_) => "",
    }
}

/// Resolve the deployment context from explicit flag, active target, deployment lock,
/// or stacker.yml project name.
///
/// Resolution order:
/// 1. Explicit `--deployment` flag value → `Remote(hash)`
/// 2. `.stacker/active-target` == "local" → `Local`
/// 3. Deployment lock → `deployment_id` → API lookup → `Remote(hash)`
/// 4. `stacker.yml` project name → API project lookup → `Remote(hash)`
fn resolve_deployment_context(
    explicit: &Option<String>,
    ctx: &CliRuntime,
) -> Result<DeploymentContext, CliError> {
    // 1. Explicit flag always wins
    if let Some(hash) = explicit {
        if !hash.is_empty() {
            return Ok(DeploymentContext::Remote(hash.clone()));
        }
    }

    let project_dir = std::env::current_dir().map_err(CliError::Io)?;

    // 2. Check active target — if "local", return Local immediately
    if let Some(target) =
        crate::cli::deployment_lock::DeploymentLock::read_active_target(&project_dir)?
    {
        if target == "local" {
            return Ok(DeploymentContext::Local);
        }
    }

    // 3. Deployment lock
    if let Some(lock) = crate::cli::deployment_lock::DeploymentLock::load(&project_dir)? {
        if let Some(dep_id) = lock.deployment_id {
            let info = ctx.block_on(ctx.client.get_deployment_status(dep_id as i32))?;
            if let Some(info) = info {
                return Ok(DeploymentContext::Remote(info.deployment_hash));
            }
        }
    }

    // 4. stacker.yml project → active agent (most recent heartbeat)
    let config_path = project_dir.join("stacker.yml");
    if config_path.exists() {
        if let Ok(config) = crate::cli::config_parser::StackerConfig::from_file(&config_path)
            .and_then(|config| config.with_resolved_deploy_target(None))
        {
            if config.deploy.target == crate::cli::config_parser::DeployTarget::Local {
                return Ok(DeploymentContext::Local);
            }

            if let Some(ref project_name) = config.project.identity {
                let project = ctx.block_on(ctx.client.find_project_by_name(project_name))?;
                if let Some(proj) = project {
                    match ctx.block_on(ctx.client.agent_snapshot_by_project(proj.id)) {
                        Ok((_, hash)) => {
                            eprintln!(
                                "\x1b[2mℹ No --deployment specified — using active agent for project '{}': {}\x1b[0m",
                                project_name, hash
                            );
                            return Ok(DeploymentContext::Remote(hash));
                        }
                        Err(_) => {}
                    }
                }
            }
        }
    }

    Err(CliError::ConfigValidation(
        "Cannot determine deployment context.\n\
         Use --deployment <HASH>, run `stacker target local` for local mode,\n\
         or run from a directory with a deployment lock or stacker.yml."
            .to_string(),
    ))
}

fn resolve_local_deployment_context(
    explicit: &Option<String>,
    project_dir: &Path,
) -> Result<Option<DeploymentContext>, CliError> {
    if explicit
        .as_ref()
        .map(|hash| !hash.trim().is_empty())
        .unwrap_or(false)
    {
        return Ok(None);
    }

    if let Some(target) =
        crate::cli::deployment_lock::DeploymentLock::read_active_target(project_dir)?
    {
        if target == "local" {
            return Ok(Some(DeploymentContext::Local));
        }
    }

    let config_path = project_dir.join("stacker.yml");
    if config_path.exists() {
        if let Ok(config) = crate::cli::config_parser::StackerConfig::from_file(&config_path)
            .and_then(|config| config.with_resolved_deploy_target(None))
        {
            if config.deploy.target == crate::cli::config_parser::DeployTarget::Local {
                return Ok(Some(DeploymentContext::Local));
            }
        }
    }

    Ok(None)
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Shared agent command execution
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

fn run_agent_command(
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
        let interval = std::time::Duration::from_secs(DEFAULT_POLL_INTERVAL_SECS);
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
            progress::finish_success(&pb, &format!("{} done", spinner_msg));
        }
        Ok(info) => {
            progress::finish_error(&pb, &format!("{} -- {}", spinner_msg, info.status));
        }
        Err(e) => {
            progress::finish_error(&pb, &format!("{} -- {}", spinner_msg, e));
        }
    }

    result
}

fn validate_pipe_command_capabilities(
    capabilities: &DeploymentCapabilitiesInfo,
) -> Result<(), CliError> {
    if capabilities.features.pipes {
        return Ok(());
    }

    let capabilities_list = if capabilities.capabilities.is_empty() {
        "(none)".to_string()
    } else {
        capabilities.capabilities.join(", ")
    };

    Err(CliError::ConfigValidation(format!(
        "The active agent for deployment '{}' does not support pipe commands.\n\
         Agent status: {}\n\
         Capabilities: {}\n\
         Update or relink the Status Panel agent so it advertises 'pipes', then retry.",
        capabilities.deployment_hash,
        if capabilities.status.is_empty() {
            "unknown"
        } else {
            &capabilities.status
        },
        capabilities_list
    )))
}

fn ensure_remote_pipe_command_capability(
    ctx: &CliRuntime,
    deployment_hash: &str,
) -> Result<(), CliError> {
    let capabilities = ctx.block_on(ctx.client.deployment_capabilities(deployment_hash))?;
    validate_pipe_command_capabilities(&capabilities)
}

fn print_command_result(info: &AgentCommandInfo, json_output: bool) {
    if json_output {
        if let Ok(j) = serde_json::to_string_pretty(info) {
            println!("{}", j);
        }
        return;
    }

    println!("Command:  {}", info.command_id);
    println!("Type:     {}", info.command_type);
    println!(
        "Status:   {} {}",
        progress::status_icon(&info.status),
        info.status
    );

    if let Some(ref result) = info.result {
        println!("\n{}", fmt::pretty_json(result));
    }

    if let Some(ref error) = info.error {
        eprintln!("\nError: {}", fmt::pretty_json(error));
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// stacker pipe scan
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone, PartialEq, Eq)]
struct LocalPortBinding {
    container_port: u16,
    host_port: Option<u16>,
    host_ip: Option<String>,
    protocol: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LocalContainerInfo {
    id: String,
    name: String,
    image: String,
    network: String,
    addresses: Vec<String>,
    ports: Vec<LocalPortBinding>,
    status: String,
    env: BTreeMap<String, String>,
    labels: BTreeMap<String, String>,
}

fn default_local_probe_protocols() -> Vec<String> {
    vec![
        "openapi".to_string(),
        "rest".to_string(),
        "html_forms".to_string(),
        "graphql".to_string(),
        "postgres".to_string(),
        "mysql".to_string(),
        "redis".to_string(),
        "rabbitmq".to_string(),
        "kafka".to_string(),
        "mcp".to_string(),
        "websocket".to_string(),
        "grpc".to_string(),
    ]
}

fn default_pipe_create_protocols() -> Vec<String> {
    vec![
        "openapi".to_string(),
        "html_forms".to_string(),
        "rest".to_string(),
    ]
}

fn normalize_protocols(protocols: &[String]) -> Vec<String> {
    protocols
        .iter()
        .map(|protocol| protocol.trim().to_ascii_lowercase())
        .filter(|protocol| !protocol.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PipeDiscoverySelector {
    mode: String,
    selector_kind: String,
    selector: String,
    deployment_hash: Option<String>,
    container: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PipeDiscoveryRequest {
    selector: PipeDiscoverySelector,
    protocols_requested: Vec<String>,
    capture_samples: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedPipeDiscovery {
    version: u32,
    selector: PipeDiscoverySelector,
    protocols_requested: Vec<String>,
    capture_samples: bool,
    cached_at: String,
    report: ProbeEndpointsCommandReport,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DiscoverySource {
    Cached,
    Fresh,
    Synthetic,
}

#[derive(Debug, Clone)]
struct DiscoveryRun {
    info: AgentCommandInfo,
    source: DiscoverySource,
}

impl PipeDiscoveryRequest {
    fn local(selector: &str, protocols: &[String], capture_samples: bool) -> Self {
        Self {
            selector: PipeDiscoverySelector {
                mode: "local".to_string(),
                selector_kind: "containers".to_string(),
                selector: selector.to_string(),
                deployment_hash: None,
                container: None,
            },
            protocols_requested: normalize_protocols(protocols),
            capture_samples,
        }
    }

    fn remote(
        deployment_hash: &str,
        app: &str,
        container: Option<&str>,
        protocols: &[String],
        capture_samples: bool,
    ) -> Self {
        Self {
            selector: PipeDiscoverySelector {
                mode: "remote".to_string(),
                selector_kind: "app".to_string(),
                selector: app.to_string(),
                deployment_hash: Some(deployment_hash.to_string()),
                container: container.map(str::to_string),
            },
            protocols_requested: normalize_protocols(protocols),
            capture_samples,
        }
    }
}

fn pipe_scan_cache_dir(project_dir: &Path) -> PathBuf {
    project_dir.join(".stacker").join("pipe-scan-cache")
}

fn encode_cache_key<T: Serialize>(value: &T) -> Result<String, CliError> {
    let payload = serde_json::to_vec(value).map_err(|err| {
        CliError::ConfigValidation(format!(
            "Failed to serialize pipe discovery cache key: {err}"
        ))
    })?;
    let digest = Sha256::digest(payload);
    Ok(digest.iter().map(|byte| format!("{:02x}", byte)).collect())
}

fn exact_pipe_scan_cache_path(
    project_dir: &Path,
    request: &PipeDiscoveryRequest,
) -> Result<PathBuf, CliError> {
    Ok(pipe_scan_cache_dir(project_dir).join(format!("{}.json", encode_cache_key(request)?)))
}

fn latest_pipe_scan_cache_path(
    project_dir: &Path,
    selector: &PipeDiscoverySelector,
) -> Result<PathBuf, CliError> {
    Ok(pipe_scan_cache_dir(project_dir)
        .join(format!("latest-{}.json", encode_cache_key(selector)?)))
}

fn read_cached_pipe_discovery(path: &Path) -> Result<Option<CachedPipeDiscovery>, CliError> {
    if !path.exists() {
        return Ok(None);
    }

    let bytes = std::fs::read(path).map_err(CliError::Io)?;
    let cached: CachedPipeDiscovery = serde_json::from_slice(&bytes).map_err(|err| {
        CliError::ConfigValidation(format!(
            "Failed to parse pipe discovery cache ({}): {}",
            path.display(),
            err
        ))
    })?;

    Ok((cached.version == PIPE_SCAN_CACHE_VERSION).then_some(cached))
}

fn cache_entry_to_agent_info(entry: &CachedPipeDiscovery) -> Result<AgentCommandInfo, CliError> {
    Ok(AgentCommandInfo {
        command_id: format!("cached-{}", encode_cache_key(&entry.selector)?),
        deployment_hash: entry.report.deployment_hash.clone(),
        command_type: "probe_endpoints".to_string(),
        status: "completed".to_string(),
        priority: "normal".to_string(),
        parameters: Some(serde_json::json!({
            "app_code": entry.selector.selector.clone(),
            "container": entry.selector.container.clone(),
            "protocols": entry.protocols_requested.clone(),
            "capture_samples": entry.capture_samples,
        })),
        result: Some(serde_json::to_value(&entry.report).map_err(|err| {
            CliError::ConfigValidation(format!(
                "Failed to serialize cached pipe discovery report: {}",
                err
            ))
        })?),
        error: None,
        created_at: entry.cached_at.clone(),
        updated_at: entry.cached_at.clone(),
    })
}

fn write_pipe_scan_cache(
    project_dir: &Path,
    request: &PipeDiscoveryRequest,
    report: &ProbeEndpointsCommandReport,
) -> Result<(), CliError> {
    let cache_dir = pipe_scan_cache_dir(project_dir);
    std::fs::create_dir_all(&cache_dir).map_err(CliError::Io)?;

    let entry = CachedPipeDiscovery {
        version: PIPE_SCAN_CACHE_VERSION,
        selector: request.selector.clone(),
        protocols_requested: request.protocols_requested.clone(),
        capture_samples: request.capture_samples,
        cached_at: Utc::now().to_rfc3339(),
        report: report.clone(),
    };
    let payload = serde_json::to_vec_pretty(&entry).map_err(|err| {
        CliError::ConfigValidation(format!("Failed to serialize pipe discovery cache: {}", err))
    })?;

    let exact_path = exact_pipe_scan_cache_path(project_dir, request)?;
    std::fs::write(&exact_path, &payload).map_err(CliError::Io)?;

    let latest_path = latest_pipe_scan_cache_path(project_dir, &request.selector)?;
    std::fs::write(&latest_path, &payload).map_err(CliError::Io)?;
    Ok(())
}

fn load_latest_pipe_scan_cache(
    project_dir: &Path,
    selector: &PipeDiscoverySelector,
) -> Result<Option<AgentCommandInfo>, CliError> {
    let path = latest_pipe_scan_cache_path(project_dir, selector)?;
    let Some(entry) = read_cached_pipe_discovery(&path)? else {
        return Ok(None);
    };
    cache_entry_to_agent_info(&entry).map(Some)
}

fn load_exact_pipe_scan_cache(
    project_dir: &Path,
    request: &PipeDiscoveryRequest,
) -> Result<Option<AgentCommandInfo>, CliError> {
    let path = exact_pipe_scan_cache_path(project_dir, request)?;
    let Some(entry) = read_cached_pipe_discovery(&path)? else {
        return Ok(None);
    };
    cache_entry_to_agent_info(&entry).map(Some)
}

fn detection_outcome(
    endpoints: &[ProbeEndpoint],
    forms: &[ProbeForm],
    resources: &[ProbeResource],
) -> String {
    if !endpoints.is_empty() || !forms.is_empty() || !resources.is_empty() {
        "detected".to_string()
    } else {
        "empty".to_string()
    }
}

fn selector_is_smtpish(selector: &str) -> bool {
    let canonical = ServiceCatalog::resolve_alias(selector);
    selector_matches_builtin_kind(&canonical, PipeAdapterKind::SmtpTarget)
        || selector_matches_builtin_kind(selector, PipeAdapterKind::SmtpTarget)
}

fn classify_probe_target_kind(selector: &str, report: &ProbeEndpointsCommandReport) -> String {
    if !report.endpoints.is_empty() {
        return "http_endpoint".to_string();
    }
    if !report.forms.is_empty() {
        return "html_form".to_string();
    }

    let resource_protocols = report
        .resources
        .iter()
        .map(|resource| resource.protocol.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    if resource_protocols.contains("smtp") || selector_is_smtpish(selector) {
        return "smtp".to_string();
    }
    if resource_protocols.len() == 1 {
        return resource_protocols
            .iter()
            .next()
            .cloned()
            .unwrap_or_else(|| "resource".to_string());
    }
    if resource_protocols.len() > 1 {
        return "resource".to_string();
    }
    if selector_is_smtpish(selector) {
        return "smtp".to_string();
    }

    "unknown".to_string()
}

fn enrich_probe_report_metadata(
    report: &mut ProbeEndpointsCommandReport,
    selector: &str,
    container: Option<&str>,
    request: &PipeDiscoveryRequest,
) {
    if report.protocols_requested.is_empty() {
        report.protocols_requested = request.protocols_requested.clone();
    }

    if report.probe_attempts.is_empty() {
        report.probe_attempts.push(ProbeAttempt {
            scope: if request.selector.mode == "local" {
                "local_selector".to_string()
            } else {
                "remote_app".to_string()
            },
            selector: Some(selector.to_string()),
            container: container.map(str::to_string),
            protocols: report.protocols_requested.clone(),
            outcome: detection_outcome(&report.endpoints, &report.forms, &report.resources),
        });
    }

    if report.target_kind.is_none() {
        report.target_kind = Some(classify_probe_target_kind(selector, report));
    }
}

fn decode_probe_report(info: &AgentCommandInfo) -> Result<ProbeEndpointsCommandReport, CliError> {
    let result = info.result.clone().ok_or_else(|| {
        CliError::ConfigValidation("probe_endpoints result payload is missing".to_string())
    })?;
    serde_json::from_value(result).map_err(|err| {
        CliError::ConfigValidation(format!("Invalid probe_endpoints result payload: {}", err))
    })
}

fn with_probe_report(
    mut info: AgentCommandInfo,
    report: &ProbeEndpointsCommandReport,
) -> Result<AgentCommandInfo, CliError> {
    info.result = Some(serde_json::to_value(report).map_err(|err| {
        CliError::ConfigValidation(format!(
            "Failed to encode probe_endpoints result payload: {}",
            err
        ))
    })?);
    Ok(info)
}

fn parse_port_key(key: &str) -> Option<(u16, String)> {
    let mut parts = key.split('/');
    let port = parts.next()?.parse::<u16>().ok()?;
    let protocol = parts.next().unwrap_or("tcp").to_string();
    Some((port, protocol))
}

fn parse_env_map(values: &[serde_json::Value]) -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    for value in values {
        if let Some(entry) = value.as_str() {
            if let Some((key, val)) = entry.split_once('=') {
                env.insert(key.to_string(), val.to_string());
            }
        }
    }
    env
}

fn parse_string_map(value: Option<&serde_json::Value>) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    if let Some(obj) = value.and_then(|v| v.as_object()) {
        for (key, val) in obj {
            if let Some(str_val) = val.as_str() {
                map.insert(key.clone(), str_val.to_string());
            }
        }
    }
    map
}

fn parse_local_container_inspect(
    value: &serde_json::Value,
) -> Result<LocalContainerInfo, CliError> {
    let id = value["Id"]
        .as_str()
        .ok_or_else(|| CliError::ConfigValidation("docker inspect missing Id".to_string()))?
        .to_string();
    let name = value["Name"]
        .as_str()
        .unwrap_or("")
        .trim_start_matches('/')
        .to_string();
    let image = value["Config"]["Image"].as_str().unwrap_or("").to_string();
    let status = value["State"]["Status"].as_str().unwrap_or("").to_string();
    let env = parse_env_map(
        value["Config"]["Env"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or(&[]),
    );
    let labels = parse_string_map(value["Config"].get("Labels"));

    let mut addresses = Vec::new();
    let mut network = String::new();
    if let Some(networks) = value["NetworkSettings"]["Networks"].as_object() {
        for (network_name, network_info) in networks {
            if network.is_empty() {
                network = network_name.clone();
            }
            if let Some(ip) = network_info["IPAddress"].as_str() {
                if !ip.is_empty() {
                    addresses.push(ip.to_string());
                }
            }
        }
    }

    let mut ports = Vec::new();
    let mut seen = BTreeSet::new();
    if let Some(port_map) = value["NetworkSettings"]["Ports"].as_object() {
        for (key, host_bindings) in port_map {
            if let Some((container_port, protocol)) = parse_port_key(key) {
                let binding_targets: Vec<(Option<u16>, Option<String>)> =
                    if let Some(bindings) = host_bindings.as_array() {
                        bindings
                            .iter()
                            .map(|binding| {
                                (
                                    binding["HostPort"]
                                        .as_str()
                                        .and_then(|v| v.parse::<u16>().ok()),
                                    binding["HostIp"].as_str().map(str::to_string),
                                )
                            })
                            .collect()
                    } else {
                        vec![(None, None)]
                    };
                for (host_port, host_ip) in binding_targets {
                    if seen.insert((container_port, host_port, protocol.clone())) {
                        ports.push(LocalPortBinding {
                            container_port,
                            host_port,
                            host_ip,
                            protocol: protocol.clone(),
                        });
                    }
                }
            }
        }
    }

    if let Some(exposed) = value["Config"]["ExposedPorts"].as_object() {
        for key in exposed.keys() {
            if let Some((container_port, protocol)) = parse_port_key(key) {
                if seen.insert((container_port, None, protocol.clone())) {
                    ports.push(LocalPortBinding {
                        container_port,
                        host_port: None,
                        host_ip: None,
                        protocol,
                    });
                }
            }
        }
    }

    if ports.is_empty() {
        for env_key in ["PORT", "APP_PORT", "SERVICE_PORT", "HTTP_PORT"] {
            if let Some(value) = env.get(env_key).and_then(|v| v.parse::<u16>().ok()) {
                ports.push(LocalPortBinding {
                    container_port: value,
                    host_port: None,
                    host_ip: None,
                    protocol: "tcp".to_string(),
                });
            }
        }
    }

    Ok(LocalContainerInfo {
        id,
        name,
        image,
        network,
        addresses,
        ports,
        status,
        env,
        labels,
    })
}

fn docker_host_http_target(host_ip: Option<&str>, host_port: u16) -> String {
    match host_ip.unwrap_or_default() {
        "::" => format!("http://[::1]:{}", host_port),
        "" | "0.0.0.0" => format!("http://localhost:{}", host_port),
        ip if ip.contains(':') => format!("http://[{}]:{}", ip, host_port),
        ip => format!("http://{}:{}", ip, host_port),
    }
}

fn docker_host_target(host_ip: Option<&str>) -> String {
    match host_ip.unwrap_or_default() {
        "::" | "" | "0.0.0.0" => "127.0.0.1".to_string(),
        ip => ip.to_string(),
    }
}

fn local_http_candidate_urls(container: &LocalContainerInfo) -> Vec<String> {
    let mut urls = Vec::new();
    let mut seen = BTreeSet::new();
    for port in &container.ports {
        if port.protocol != "tcp" {
            continue;
        }
        if let Some(host_port) = port.host_port {
            let url = docker_host_http_target(port.host_ip.as_deref(), host_port);
            if seen.insert(url.clone()) {
                urls.push(url);
            }
        }
        for address in &container.addresses {
            let url = format!("http://{}:{}", address, port.container_port);
            if seen.insert(url.clone()) {
                urls.push(url);
            }
        }
    }
    urls
}

fn docker_exec(container: &str, args: &[String]) -> Option<String> {
    let output = std::process::Command::new("docker")
        .arg("exec")
        .arg(container)
        .args(args)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8(output.stdout).ok()?;
    let trimmed = stdout.trim().to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

fn local_resource_probe_plan(container: &LocalContainerInfo) -> Vec<String> {
    let identity = format!(
        "{} {}",
        container.name.to_lowercase(),
        container.image.to_lowercase()
    );
    let mut plan = Vec::new();
    for (needle, protocol) in [
        ("postgres", "postgres"),
        ("timescaledb", "postgres"),
        ("mysql", "mysql"),
        ("mariadb", "mysql"),
        ("redis", "redis"),
        ("rabbitmq", "rabbitmq"),
        ("kafka", "kafka"),
        ("mcp", "mcp"),
        ("grpc", "grpc"),
        ("ws", "websocket"),
        ("socket", "websocket"),
    ] {
        if identity.contains(needle) && !plan.iter().any(|item| item == protocol) {
            plan.push(protocol.to_string());
        }
    }
    for port in &container.ports {
        match port.container_port {
            5432 => plan.push("postgres".to_string()),
            3306 => plan.push("mysql".to_string()),
            6379 => plan.push("redis".to_string()),
            5672 | 15672 => plan.push("rabbitmq".to_string()),
            9092 => plan.push("kafka".to_string()),
            50051 | 50052 => plan.push("grpc".to_string()),
            _ => {}
        }
    }
    plan.sort();
    plan.dedup();
    plan
}

fn parse_openapi_fields(operation: &serde_json::Value) -> Vec<String> {
    let mut fields = Vec::new();
    if let Some(parameters) = operation["parameters"].as_array() {
        for param in parameters {
            if let Some(name) = param["name"].as_str() {
                fields.push(name.to_string());
            }
        }
    }
    if let Some(content) = operation["requestBody"]["content"].as_object() {
        for schema in content.values() {
            if let Some(properties) = schema["schema"]["properties"].as_object() {
                for key in properties.keys() {
                    if !fields.contains(key) {
                        fields.push(key.clone());
                    }
                }
            }
        }
    }
    fields
}

fn parse_openapi_endpoint(
    container_name: &str,
    base_url: &str,
    spec_url: &str,
    doc: &serde_json::Value,
) -> Option<ProbeEndpoint> {
    let paths = doc["paths"].as_object()?;
    let mut operations = Vec::new();
    for (path, path_item) in paths {
        for method in ["get", "post", "put", "patch", "delete"] {
            if let Some(operation) = path_item.get(method) {
                operations.push(ProbeOperation {
                    path: path.clone(),
                    method: method.to_uppercase(),
                    summary: operation["summary"].as_str().unwrap_or("").to_string(),
                    fields: parse_openapi_fields(operation),
                    sample_response: None,
                });
            }
        }
    }
    if operations.is_empty() {
        return None;
    }
    Some(ProbeEndpoint {
        container: Some(container_name.to_string()),
        protocol: "openapi".to_string(),
        base_url: base_url.to_string(),
        spec_url: spec_url.to_string(),
        operations,
    })
}

fn try_parse_json(value: &str) -> Option<serde_json::Value> {
    serde_json::from_str(value).ok()
}

fn local_http_probe(
    container: &LocalContainerInfo,
    protocols: &[String],
    capture_samples: bool,
    timeout_secs: u64,
) -> (Vec<ProbeEndpoint>, Vec<ProbeForm>, Vec<String>) {
    let mut endpoints = Vec::new();
    let mut forms = Vec::new();
    let mut detected = Vec::new();
    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .danger_accept_invalid_certs(true)
        .build()
    {
        Ok(client) => client,
        Err(_) => return (endpoints, forms, detected),
    };

    let urls = local_http_candidate_urls(container);
    let mut seen_endpoint = BTreeSet::new();
    let protocol_set: BTreeSet<String> = protocols.iter().map(|p| p.to_lowercase()).collect();

    if protocol_set.contains("openapi") {
        for base_url in &urls {
            for spec_url in [
                "/openapi.json",
                "/swagger.json",
                "/api/openapi.json",
                "/v3/api-docs",
                "/swagger/v1/swagger.json",
            ] {
                let full_url = format!("{}{}", base_url, spec_url);
                let Ok(response) = client.get(&full_url).send() else {
                    continue;
                };
                if !response.status().is_success() {
                    continue;
                }
                let Ok(body) = response.text() else {
                    continue;
                };
                let Some(json) = try_parse_json(&body) else {
                    continue;
                };
                if json.get("paths").is_none() {
                    continue;
                }
                if let Some(endpoint) =
                    parse_openapi_endpoint(&container.name, base_url, spec_url, &json)
                {
                    let key = format!("openapi:{}{}", base_url, spec_url);
                    if seen_endpoint.insert(key) {
                        endpoints.push(endpoint);
                        detected.push("openapi".to_string());
                    }
                }
            }
        }
    }

    if protocol_set.contains("rest") {
        for base_url in &urls {
            for path in ["/health", "/healthz", "/ready", "/api", "/"] {
                let full_url = format!("{}{}", base_url, path);
                let Ok(response) = client.get(&full_url).send() else {
                    continue;
                };
                if !response.status().is_success() {
                    continue;
                }
                let content_type = response
                    .headers()
                    .get(reqwest::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                let Ok(body) = response.text() else {
                    continue;
                };
                if content_type.contains("html") {
                    continue;
                }
                let sample = if capture_samples {
                    try_parse_json(&body)
                } else {
                    None
                };
                let key = format!("rest:{}{}", base_url, path);
                if seen_endpoint.insert(key) {
                    endpoints.push(ProbeEndpoint {
                        container: Some(container.name.clone()),
                        protocol: "rest".to_string(),
                        base_url: base_url.to_string(),
                        spec_url: String::new(),
                        operations: vec![ProbeOperation {
                            path: path.to_string(),
                            method: "GET".to_string(),
                            summary: "Discovered local HTTP endpoint".to_string(),
                            fields: Vec::new(),
                            sample_response: sample,
                        }],
                    });
                    detected.push("rest".to_string());
                }
            }
        }
    }

    if protocol_set.contains("html_forms") {
        let form_re =
            Regex::new(r#"(?si)<form([^>]*)>(.*?)</form>"#).expect("form regex must compile");
        let action_re =
            Regex::new(r#"action=["']?([^"'\s>]+)"#).expect("action regex must compile");
        let method_re =
            Regex::new(r#"method=["']?([^"'\s>]+)"#).expect("method regex must compile");
        let id_re = Regex::new(r#"id=["']?([^"'\s>]+)"#).expect("id regex must compile");
        let field_re = Regex::new(r#"(?:input|select|textarea)[^>]*name=["']?([^"'\s>]+)"#)
            .expect("field regex must compile");

        for base_url in &urls {
            for path in ["/", "/login", "/signup", "/contact"] {
                let full_url = format!("{}{}", base_url, path);
                let Ok(response) = client.get(&full_url).send() else {
                    continue;
                };
                if !response.status().is_success() {
                    continue;
                }
                let content_type = response
                    .headers()
                    .get(reqwest::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                if !content_type.contains("html") {
                    continue;
                }
                let Ok(body) = response.text() else {
                    continue;
                };
                for capture in form_re.captures_iter(&body) {
                    let attrs = capture.get(1).map(|m| m.as_str()).unwrap_or("");
                    let inner = capture.get(2).map(|m| m.as_str()).unwrap_or("");
                    let action = action_re
                        .captures(attrs)
                        .and_then(|c| c.get(1))
                        .map(|m| m.as_str().to_string())
                        .unwrap_or_else(|| path.to_string());
                    let method = method_re
                        .captures(attrs)
                        .and_then(|c| c.get(1))
                        .map(|m| m.as_str().to_uppercase())
                        .unwrap_or_else(|| "GET".to_string());
                    let id = id_re
                        .captures(attrs)
                        .and_then(|c| c.get(1))
                        .map(|m| m.as_str().to_string())
                        .unwrap_or_else(|| format!("{}{}", container.name, path));
                    let fields = field_re
                        .captures_iter(inner)
                        .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
                        .collect::<Vec<_>>();
                    forms.push(ProbeForm {
                        container: Some(container.name.clone()),
                        id,
                        action,
                        method,
                        fields,
                    });
                    detected.push("html_forms".to_string());
                }
            }
        }
    }

    if protocol_set.contains("graphql") {
        let introspection = serde_json::json!({
            "query": "query IntrospectionQuery { __schema { queryType { name } mutationType { name } } }"
        });
        for base_url in &urls {
            for path in ["/graphql", "/api/graphql"] {
                let full_url = format!("{}{}", base_url, path);
                let Ok(response) = client.post(&full_url).json(&introspection).send() else {
                    continue;
                };
                if !response.status().is_success() {
                    continue;
                }
                let Ok(body) = response.text() else {
                    continue;
                };
                let Some(json) = try_parse_json(&body) else {
                    continue;
                };
                if json.get("data").is_none() {
                    continue;
                }
                let key = format!("graphql:{}{}", base_url, path);
                if seen_endpoint.insert(key) {
                    endpoints.push(ProbeEndpoint {
                        container: Some(container.name.clone()),
                        protocol: "graphql".to_string(),
                        base_url: base_url.to_string(),
                        spec_url: path.to_string(),
                        operations: vec![ProbeOperation {
                            path: path.to_string(),
                            method: "POST".to_string(),
                            summary: "GraphQL endpoint".to_string(),
                            fields: vec!["query".to_string(), "variables".to_string()],
                            sample_response: if capture_samples { Some(json) } else { None },
                        }],
                    });
                    detected.push("graphql".to_string());
                }
            }
        }
    }

    (endpoints, forms, detected)
}

fn first_container_address(container: &LocalContainerInfo, default_port: u16) -> String {
    if let Some(port) = container
        .ports
        .iter()
        .find(|port| port.container_port == default_port)
    {
        if let Some(host_port) = port.host_port {
            return docker_host_http_target(port.host_ip.as_deref(), host_port)
                .trim_start_matches("http://")
                .to_string();
        }
    }
    container
        .addresses
        .first()
        .map(|ip| format!("{}:{}", ip, default_port))
        .unwrap_or_else(|| format!("{}:{}", container.name, default_port))
}

fn local_resource_probe(
    container: &LocalContainerInfo,
    protocols: &[String],
) -> (Vec<ProbeResource>, Vec<String>) {
    let mut resources = Vec::new();
    let mut detected = Vec::new();
    let requested: BTreeSet<String> = protocols.iter().map(|p| p.to_lowercase()).collect();

    if requested.contains("postgres")
        && local_resource_probe_plan(container)
            .iter()
            .any(|p| p == "postgres")
    {
        let user = container
            .env
            .get("POSTGRES_USER")
            .cloned()
            .unwrap_or_else(|| "postgres".to_string());
        let db = container
            .env
            .get("POSTGRES_DB")
            .cloned()
            .unwrap_or_else(|| user.clone());
        let command = vec![
            "psql".to_string(),
            "-U".to_string(),
            user.clone(),
            "-d".to_string(),
            db.clone(),
            "-Atqc".to_string(),
            "SELECT table_schema||'.'||table_name FROM information_schema.tables WHERE table_schema NOT IN ('pg_catalog','information_schema') ORDER BY 1 LIMIT 50".to_string(),
        ];
        if let Some(output) = docker_exec(&container.name, &command) {
            let items = output
                .lines()
                .filter(|line| !line.trim().is_empty())
                .map(|line| ProbeResourceItem {
                    resource_type: "table".to_string(),
                    name: line.trim().to_string(),
                    summary: "CDC candidate".to_string(),
                    fields: Vec::new(),
                })
                .collect::<Vec<_>>();
            if !items.is_empty() {
                resources.push(ProbeResource {
                    container: container.name.clone(),
                    protocol: "postgres".to_string(),
                    address: format!(
                        "postgres://{}/{}",
                        first_container_address(container, 5432),
                        db
                    ),
                    items,
                });
                detected.push("postgres".to_string());
            }
        }
    }

    if requested.contains("mysql")
        && local_resource_probe_plan(container)
            .iter()
            .any(|p| p == "mysql")
    {
        let user = container
            .env
            .get("MYSQL_USER")
            .cloned()
            .unwrap_or_else(|| "root".to_string());
        let db = container
            .env
            .get("MYSQL_DATABASE")
            .cloned()
            .unwrap_or_else(|| "mysql".to_string());
        let password_arg = container
            .env
            .get("MYSQL_PASSWORD")
            .or_else(|| container.env.get("MYSQL_ROOT_PASSWORD"))
            .map(|v| format!("-p{}", v))
            .unwrap_or_default();
        let mut args = vec!["mysql".to_string(), "-u".to_string(), user.clone()];
        if !password_arg.is_empty() {
            args.push(password_arg);
        }
        args.extend([
            "-Nse".to_string(),
            "SELECT CONCAT(TABLE_SCHEMA,'.',TABLE_NAME) FROM information_schema.TABLES WHERE TABLE_SCHEMA NOT IN ('information_schema','mysql','performance_schema','sys') LIMIT 50".to_string(),
            db.clone(),
        ]);
        if let Some(output) = docker_exec(&container.name, &args) {
            let items = output
                .lines()
                .filter(|line| !line.trim().is_empty())
                .map(|line| ProbeResourceItem {
                    resource_type: "table".to_string(),
                    name: line.trim().to_string(),
                    summary: "SQL resource".to_string(),
                    fields: Vec::new(),
                })
                .collect::<Vec<_>>();
            if !items.is_empty() {
                resources.push(ProbeResource {
                    container: container.name.clone(),
                    protocol: "mysql".to_string(),
                    address: format!(
                        "mysql://{}/{}",
                        first_container_address(container, 3306),
                        db
                    ),
                    items,
                });
                detected.push("mysql".to_string());
            }
        }
    }

    if requested.contains("redis")
        && local_resource_probe_plan(container)
            .iter()
            .any(|p| p == "redis")
    {
        if let Some(output) = docker_exec(
            &container.name,
            &[
                "redis-cli".to_string(),
                "--raw".to_string(),
                "INFO".to_string(),
                "keyspace".to_string(),
            ],
        ) {
            let items = output
                .lines()
                .filter(|line| line.starts_with("db"))
                .map(|line| ProbeResourceItem {
                    resource_type: "keyspace".to_string(),
                    name: line.split(':').next().unwrap_or(line).to_string(),
                    summary: line.to_string(),
                    fields: Vec::new(),
                })
                .collect::<Vec<_>>();
            if !items.is_empty() {
                resources.push(ProbeResource {
                    container: container.name.clone(),
                    protocol: "redis".to_string(),
                    address: format!("redis://{}", first_container_address(container, 6379)),
                    items,
                });
                detected.push("redis".to_string());
            }
        }
    }

    if requested.contains("rabbitmq")
        && local_resource_probe_plan(container)
            .iter()
            .any(|p| p == "rabbitmq")
    {
        let queues = docker_exec(
            &container.name,
            &[
                "rabbitmqctl".to_string(),
                "list_queues".to_string(),
                "name".to_string(),
                "messages".to_string(),
            ],
        )
        .unwrap_or_default();
        let exchanges = docker_exec(
            &container.name,
            &[
                "rabbitmqctl".to_string(),
                "list_exchanges".to_string(),
                "name".to_string(),
                "type".to_string(),
            ],
        )
        .unwrap_or_default();
        let mut items = Vec::new();
        for line in queues.lines().skip(1) {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                let name = trimmed
                    .split_whitespace()
                    .next()
                    .unwrap_or(trimmed)
                    .to_string();
                items.push(ProbeResourceItem {
                    resource_type: "queue".to_string(),
                    name,
                    summary: trimmed.to_string(),
                    fields: Vec::new(),
                });
            }
        }
        for line in exchanges.lines().skip(1) {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                let name = trimmed
                    .split_whitespace()
                    .next()
                    .unwrap_or(trimmed)
                    .to_string();
                items.push(ProbeResourceItem {
                    resource_type: "exchange".to_string(),
                    name,
                    summary: trimmed.to_string(),
                    fields: Vec::new(),
                });
            }
        }
        if !items.is_empty() {
            resources.push(ProbeResource {
                container: container.name.clone(),
                protocol: "rabbitmq".to_string(),
                address: format!("amqp://{}", first_container_address(container, 5672)),
                items,
            });
            detected.push("rabbitmq".to_string());
        }
    }

    if requested.contains("kafka")
        && local_resource_probe_plan(container)
            .iter()
            .any(|p| p == "kafka")
    {
        let script = "if command -v kafka-topics.sh >/dev/null 2>&1; then kafka-topics.sh --bootstrap-server localhost:9092 --list; elif [ -x /opt/bitnami/kafka/bin/kafka-topics.sh ]; then /opt/bitnami/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --list; fi";
        if let Some(output) = docker_exec(
            &container.name,
            &["sh".to_string(), "-lc".to_string(), script.to_string()],
        ) {
            let items = output
                .lines()
                .filter(|line| !line.trim().is_empty())
                .map(|line| ProbeResourceItem {
                    resource_type: "topic".to_string(),
                    name: line.trim().to_string(),
                    summary: "Kafka topic".to_string(),
                    fields: Vec::new(),
                })
                .collect::<Vec<_>>();
            if !items.is_empty() {
                resources.push(ProbeResource {
                    container: container.name.clone(),
                    protocol: "kafka".to_string(),
                    address: first_container_address(container, 9092),
                    items,
                });
                detected.push("kafka".to_string());
            }
        }
    }

    if requested.contains("grpc")
        && local_resource_probe_plan(container)
            .iter()
            .any(|p| p == "grpc")
    {
        resources.push(ProbeResource {
            container: container.name.clone(),
            protocol: "grpc".to_string(),
            address: first_container_address(container, 50051),
            items: vec![ProbeResourceItem {
                resource_type: "service".to_string(),
                name: container.name.clone(),
                summary: "gRPC port detected; reflection probing not yet available locally"
                    .to_string(),
                fields: Vec::new(),
            }],
        });
        detected.push("grpc".to_string());
    }

    (resources, detected)
}

fn discover_local_containers(
    filter: Option<&str>,
) -> Result<Vec<LocalContainerInfo>, Box<dyn std::error::Error>> {
    let output = std::process::Command::new("docker")
        .args([
            "ps",
            "--format",
            "{{.ID}}\t{{.Names}}\t{{.Ports}}\t{{.Networks}}\t{{.Status}}\t{{.Image}}",
        ])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Box::new(CliError::ConfigValidation(format!(
            "docker ps failed: {}",
            stderr.trim()
        ))));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<_> = stdout.lines().filter(|l| !l.trim().is_empty()).collect();
    let filter = filter.filter(|value| !value.is_empty() && *value != "*" && *value != "all");

    let matched: Vec<_> = if let Some(filter) = filter {
        lines
            .into_iter()
            .filter(|line| {
                line.split('\t')
                    .nth(1)
                    .map(|name| name.contains(filter))
                    .unwrap_or(false)
            })
            .collect()
    } else {
        lines
    };

    let mut containers = Vec::new();
    for line in matched {
        let parts: Vec<&str> = line.split('\t').collect();
        let container_id = parts.first().copied().unwrap_or("");
        let inspect_output = std::process::Command::new("docker")
            .args(["inspect", container_id])
            .output()?;
        if !inspect_output.status.success() {
            continue;
        }
        let inspect_json: serde_json::Value = serde_json::from_slice(&inspect_output.stdout)?;
        let inspect_entry = inspect_json
            .as_array()
            .and_then(|items| items.first())
            .cloned()
            .unwrap_or(inspect_json);
        if let Ok(container) = parse_local_container_inspect(&inspect_entry) {
            containers.push(container);
        }
    }

    Ok(containers)
}

fn build_local_probe_report(
    app_code: &str,
    containers: &[LocalContainerInfo],
    protocols: &[String],
    capture_samples: bool,
) -> ProbeEndpointsCommandReport {
    build_local_probe_report_with_progress(
        app_code,
        containers,
        protocols,
        capture_samples,
        |_, _, _| {},
    )
}

fn build_local_probe_report_with_progress<F>(
    app_code: &str,
    containers: &[LocalContainerInfo],
    protocols: &[String],
    capture_samples: bool,
    mut on_progress: F,
) -> ProbeEndpointsCommandReport
where
    F: FnMut(usize, usize, &str),
{
    let mut endpoints = Vec::new();
    let mut forms = Vec::new();
    let mut resources = Vec::new();
    let mut containers_out = Vec::new();
    let mut probe_attempts = Vec::new();
    let mut protocols_detected = BTreeSet::new();
    let protocols_requested = normalize_protocols(protocols);
    let total = containers.len();

    for (index, container) in containers.iter().enumerate() {
        on_progress(index + 1, total, &container.name);
        let (http_endpoints, http_forms, http_detected) =
            local_http_probe(container, protocols, capture_samples, 3);
        let (resource_items, resource_detected) = local_resource_probe(container, protocols);
        let attempt_outcome = detection_outcome(&http_endpoints, &http_forms, &resource_items);

        for protocol in http_detected
            .into_iter()
            .chain(resource_detected.into_iter())
        {
            protocols_detected.insert(protocol);
        }
        probe_attempts.push(ProbeAttempt {
            scope: "local_container".to_string(),
            selector: Some(app_code.to_string()),
            container: Some(container.name.clone()),
            protocols: protocols_requested.clone(),
            outcome: attempt_outcome,
        });
        endpoints.extend(http_endpoints);
        forms.extend(http_forms);
        resources.extend(resource_items);
        containers_out.push(ProbeContainer {
            name: container.name.clone(),
            image: container.image.clone(),
            network: container.network.clone(),
            ports: container
                .ports
                .iter()
                .map(|binding| match binding.host_port {
                    Some(host_port) => format!(
                        "{}->{}{}",
                        host_port,
                        binding.container_port,
                        format!("/{}", binding.protocol)
                    ),
                    None => format!("{}/{}", binding.container_port, binding.protocol),
                })
                .collect(),
            addresses: container
                .addresses
                .iter()
                .flat_map(|address| {
                    if container.ports.is_empty() {
                        vec![address.clone()]
                    } else {
                        container
                            .ports
                            .iter()
                            .map(|binding| format!("{}:{}", address, binding.container_port))
                            .collect::<Vec<_>>()
                    }
                })
                .collect(),
        });
    }

    let mut report = ProbeEndpointsCommandReport {
        command_type: "probe_endpoints".to_string(),
        deployment_hash: "local".to_string(),
        app_code: app_code.to_string(),
        protocols_detected: protocols_detected.into_iter().collect(),
        protocols_requested,
        containers: containers_out,
        endpoints,
        resources,
        forms,
        probe_attempts,
        target_kind: None,
        probed_at: Utc::now().to_rfc3339(),
    };
    report.target_kind = Some(classify_probe_target_kind(app_code, &report));
    report
}

fn local_report_to_agent_info(
    report: &ProbeEndpointsCommandReport,
    capture_samples: bool,
) -> Result<AgentCommandInfo, Box<dyn std::error::Error>> {
    probe_report_to_agent_info(report, capture_samples)
}

fn probe_report_to_agent_info(
    report: &ProbeEndpointsCommandReport,
    capture_samples: bool,
) -> Result<AgentCommandInfo, Box<dyn std::error::Error>> {
    Ok(AgentCommandInfo {
        command_id: format!("synthetic-{}", report.app_code),
        deployment_hash: report.deployment_hash.clone(),
        command_type: "probe_endpoints".to_string(),
        status: "completed".to_string(),
        priority: "normal".to_string(),
        parameters: Some(serde_json::json!({
            "app_code": report.app_code,
            "protocols": report.protocols_requested,
            "capture_samples": capture_samples,
        })),
        result: Some(serde_json::to_value(report)?),
        error: None,
        created_at: report.probed_at.clone(),
        updated_at: report.probed_at.clone(),
    })
}

#[derive(Debug, Clone, PartialEq)]
pub enum PipeScanRequest {
    /// Backward-compatible form: local = container filter, remote = app code.
    Legacy { selector: Option<String> },
    /// Explicit local container discovery.
    Containers { filter: Option<String> },
    /// Explicit remote app probe.
    App {
        app: String,
        container: Option<String>,
    },
}

impl PipeScanRequest {
    fn local_filter(&self) -> Result<Option<&str>, CliError> {
        match self {
            PipeScanRequest::Legacy { selector } => Ok(selector.as_deref()),
            PipeScanRequest::Containers { filter } => Ok(filter.as_deref()),
            PipeScanRequest::App { .. } => Err(CliError::ConfigValidation(
                "Local scan works with containers, not app codes.\n\
                 Use `stacker pipe scan` or `stacker pipe scan --containers [FILTER]`."
                    .to_string(),
            )),
        }
    }

    fn remote_selector(&self) -> Result<(&str, Option<&str>), CliError> {
        match self {
            PipeScanRequest::Legacy {
                selector: Some(selector),
            } => Ok((selector.as_str(), None)),
            PipeScanRequest::Legacy { selector: None } => Err(CliError::ConfigValidation(
                "Remote scan requires an app selector.\n\
                 Use `stacker pipe scan --app <APP>`."
                    .to_string(),
            )),
            PipeScanRequest::Containers { .. } => Err(CliError::ConfigValidation(
                "Container inventory is local-only.\n\
                 For remote scans use `stacker pipe scan --app <APP> [--container <NAME>]`."
                    .to_string(),
            )),
            PipeScanRequest::App { app, container } => Ok((app.as_str(), container.as_deref())),
        }
    }

    fn maybe_print_legacy_hint(&self, is_local: bool) {
        if let PipeScanRequest::Legacy {
            selector: Some(selector),
        } = self
        {
            if is_local {
                eprintln!(
                    "Hint: `stacker pipe scan {}` is legacy syntax. Prefer `stacker pipe scan --containers {}`.",
                    selector, selector
                );
            } else {
                eprintln!(
                    "Hint: `stacker pipe scan {}` is legacy syntax. Prefer `stacker pipe scan --app {}`.",
                    selector, selector
                );
            }
        }
    }
}

pub struct PipeScanCommand {
    pub request: PipeScanRequest,
    pub protocols: Vec<String>,
    pub capture_samples: bool,
    pub json: bool,
    pub deployment: Option<String>,
}

impl PipeScanCommand {
    pub fn new(
        request: PipeScanRequest,
        protocols: Vec<String>,
        capture_samples: bool,
        json: bool,
        deployment: Option<String>,
    ) -> Self {
        Self {
            request,
            protocols,
            capture_samples,
            json,
            deployment,
        }
    }

    /// Local scan: discover containers via `docker ps`.
    fn scan_local(
        &self,
        project_dir: &Path,
        prefix: &str,
        filter: Option<&str>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let pb = progress::spinner(&format!("{}Scanning local Docker containers...", prefix));
        let containers = match discover_local_containers(filter) {
            Ok(containers) => containers,
            Err(error) => {
                progress::finish_error(&pb, "Docker discovery failed");
                eprintln!("{}", error);
                return Ok(());
            }
        };
        if containers.is_empty() {
            progress::finish_error(&pb, "No containers running");
            println!("No Docker containers found. Start your services first.");
            return Ok(());
        }
        progress::finish_success(
            &pb,
            &format!("{}{} container(s) discovered", prefix, containers.len()),
        );

        let protocols = if self.protocols.is_empty() {
            default_local_probe_protocols()
        } else {
            self.protocols.clone()
        };
        let probe_pb = progress::spinner(&format!(
            "{}Probing local containers (0/{})...",
            prefix,
            containers.len()
        ));
        let report = build_local_probe_report_with_progress(
            filter.unwrap_or("local"),
            &containers,
            &protocols,
            self.capture_samples,
            |current, total, container| {
                progress::update_message(
                    &probe_pb,
                    &format!(
                        "{}Probing container {}/{}: {}",
                        prefix, current, total, container
                    ),
                );
            },
        );
        progress::finish_success(&probe_pb, &format!("{}Probe stage complete", prefix));

        let request = PipeDiscoveryRequest::local(
            filter.unwrap_or("local"),
            &protocols,
            self.capture_samples,
        );
        write_pipe_scan_cache(project_dir, &request, &report)?;

        if self.json {
            println!("{}", serde_json::to_string_pretty(&report)?);
        } else {
            let info = local_report_to_agent_info(&report, self.capture_samples)?;
            print_scan_result(&info);
            println!("  Use these container names with 'stacker pipe create <source> <target>'");
        }

        Ok(())
    }

    fn scan_remote(
        &self,
        project_dir: &Path,
        ctx: &CliRuntime,
        hash: &str,
        app: &str,
        container: Option<&str>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let protocols = if self.protocols.is_empty() {
            vec![
                "openapi".to_string(),
                "html_forms".to_string(),
                "rest".to_string(),
            ]
        } else {
            self.protocols.clone()
        };
        let request =
            PipeDiscoveryRequest::remote(hash, app, container, &protocols, self.capture_samples);
        let description = match container {
            Some(container_name) => {
                format!(
                    "Scanning app {} (container {}) for endpoints",
                    app, container_name
                )
            }
            None => format!("Scanning app {} for endpoints", app),
        };

        let info = run_remote_probe(ctx, &request, &description)?;
        cache_probe_if_completed(project_dir, &request, &info)?;

        if self.json {
            print_command_result(&info, true);
        } else {
            print_scan_result(&info);
        }

        Ok(())
    }
}

impl CallableTrait for PipeScanCommand {
    fn call(&self) -> Result<(), Box<dyn std::error::Error>> {
        let ctx = CliRuntime::new("pipe scan")?;
        let deploy_ctx = resolve_deployment_context(&self.deployment, &ctx)?;
        let project_dir = std::env::current_dir().map_err(CliError::Io)?;
        let prefix = mode_prefix(&deploy_ctx);

        if deploy_ctx.is_local() {
            self.request.maybe_print_legacy_hint(true);
            let filter = self.request.local_filter()?;
            return self.scan_local(&project_dir, prefix, filter);
        }

        let hash = match &deploy_ctx {
            DeploymentContext::Remote(h) => h.clone(),
            _ => unreachable!(),
        };
        self.request.maybe_print_legacy_hint(false);
        let (app, container) = self.request.remote_selector()?;
        self.scan_remote(&project_dir, &ctx, &hash, app, container)
    }
}

fn print_scan_result(info: &AgentCommandInfo) {
    if info.status != "completed" {
        if let Some(ref error) = info.error {
            eprintln!("Scan failed: {}", fmt::pretty_json(error));
        } else {
            eprintln!("Scan failed: unknown error");
        }
        return;
    }

    let result = match &info.result {
        Some(r) => r,
        None => {
            eprintln!("No scan results returned");
            return;
        }
    };

    let app_code = result["app_code"].as_str().unwrap_or("unknown");
    let protocols = result["protocols_detected"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default();

    if let Some(containers) = result["containers"].as_array() {
        if !containers.is_empty() {
            println!("\n  Containers matched: {}", containers.len());
            for container in containers {
                let name = container["name"].as_str().unwrap_or("?");
                let network = container["network"].as_str().unwrap_or("");
                let image = container["image"].as_str().unwrap_or("");
                let addresses = container["addresses"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    })
                    .unwrap_or_default();
                println!("    {}  [{}] {}", name, network, image);
                if !addresses.is_empty() {
                    println!("      addresses: {}", addresses);
                }
            }
        }
    }

    println!("\n  App: {}", app_code);
    println!(
        "  Protocols detected: {}",
        if protocols.is_empty() {
            "none"
        } else {
            &protocols
        }
    );

    if let Some(endpoints) = result["endpoints"].as_array() {
        for ep in endpoints {
            let protocol = ep["protocol"].as_str().unwrap_or("unknown");
            let base_url = ep["base_url"].as_str().unwrap_or("");
            let spec_url = ep["spec_url"].as_str().unwrap_or("");
            println!("\n  [{protocol}] {base_url}{spec_url}");

            if let Some(operations) = ep["operations"].as_array() {
                for op in operations {
                    let method = op["method"].as_str().unwrap_or("?");
                    let path = op["path"].as_str().unwrap_or("?");
                    let summary = op["summary"].as_str().unwrap_or("");
                    let fields = op["fields"]
                        .as_array()
                        .map(|a| {
                            a.iter()
                                .filter_map(|v| v.as_str())
                                .collect::<Vec<_>>()
                                .join(", ")
                        })
                        .unwrap_or_default();

                    print!("    {:>6} {}", method, path);
                    if !summary.is_empty() {
                        print!("  -- {}", summary);
                    }
                    println!();
                    if !fields.is_empty() {
                        println!("           fields: [{}]", fields);
                    }
                    if let Some(sample) = op.get("sample_response") {
                        if !sample.is_null() {
                            let sample_str = serde_json::to_string(sample).unwrap_or_default();
                            if sample_str.len() > 120 {
                                println!("           sample: {}...", &sample_str[..117]);
                            } else {
                                println!("           sample: {}", sample_str);
                            }
                        }
                    }
                }
            }
        }
    }

    if let Some(resources) = result["resources"].as_array() {
        if !resources.is_empty() {
            println!("\n  Resources:");
            for resource in resources {
                let protocol = resource["protocol"].as_str().unwrap_or("unknown");
                let address = resource["address"].as_str().unwrap_or("");
                let container = resource["container"].as_str().unwrap_or("");
                if container.is_empty() {
                    println!("    [{}] {}", protocol, address);
                } else {
                    println!("    [{}] {} ({})", protocol, address, container);
                }
                if let Some(items) = resource["items"].as_array() {
                    for item in items {
                        let resource_type = item["resource_type"].as_str().unwrap_or("resource");
                        let name = item["name"].as_str().unwrap_or("?");
                        let summary = item["summary"].as_str().unwrap_or("");
                        let fields = item["fields"]
                            .as_array()
                            .map(|a| {
                                a.iter()
                                    .filter_map(|v| v.as_str())
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            })
                            .unwrap_or_default();
                        if summary.is_empty() {
                            println!("      {} {}", resource_type, name);
                        } else {
                            println!("      {} {}  -- {}", resource_type, name, summary);
                        }
                        if !fields.is_empty() {
                            println!("        fields: [{}]", fields);
                        }
                    }
                }
            }
        }
    }

    if let Some(forms) = result["forms"].as_array() {
        if !forms.is_empty() {
            println!("\n  HTML Forms:");
            for form in forms {
                let id = form["id"].as_str().unwrap_or("?");
                let action = form["action"].as_str().unwrap_or("?");
                let method = form["method"].as_str().unwrap_or("?");
                let fields = form["fields"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    })
                    .unwrap_or_default();

                println!("    #{}  {} {}", id, method, action);
                if !fields.is_empty() {
                    println!("      fields: [{}]", fields);
                }
            }
        }
    }

    let no_endpoints = result["endpoints"]
        .as_array()
        .map(|a| a.is_empty())
        .unwrap_or(true);
    let no_resources = result["resources"]
        .as_array()
        .map(|a| a.is_empty())
        .unwrap_or(true);
    let no_forms = result["forms"]
        .as_array()
        .map(|a| a.is_empty())
        .unwrap_or(true);
    if no_endpoints && no_resources && no_forms {
        println!("\n  No endpoints or resources were discovered for the matched containers.");
    }

    println!();
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// stacker pipe create — interactive pipe creation
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

pub struct PipeCreateCommand {
    pub source: String,
    pub target: String,
    pub manual: bool,
    pub ai: bool,
    pub no_ai: bool,
    pub ml: bool,
    pub json: bool,
    pub deployment: Option<String>,
}

impl PipeCreateCommand {
    pub fn new(
        source: String,
        target: String,
        manual: bool,
        ai: bool,
        no_ai: bool,
        ml: bool,
        json: bool,
        deployment: Option<String>,
    ) -> Self {
        Self {
            source,
            target,
            manual,
            ai,
            no_ai,
            ml,
            json,
            deployment,
        }
    }
}

#[derive(Debug, Clone)]
struct SelectableOperation {
    container: Option<String>,
    adapter: Option<PipeAdapterMetadata>,
    method: String,
    path: String,
    summary: String,
    fields: Vec<String>,
    sample: Option<serde_json::Value>,
}

/// Extract selectable HTTP/form operations from a probe result.
fn extract_operations(info: &AgentCommandInfo) -> Vec<SelectableOperation> {
    let mut ops = Vec::new();
    if let Some(ref result) = info.result {
        if let Some(endpoints) = result["endpoints"].as_array() {
            for ep in endpoints {
                let base = ep["base_url"].as_str().unwrap_or("");
                let container = ep["container"].as_str().map(String::from);
                if let Some(operations) = ep["operations"].as_array() {
                    for op in operations {
                        let method = op["method"].as_str().unwrap_or("GET").to_string();
                        let path = format!("{}{}", base, op["path"].as_str().unwrap_or(""));
                        let summary = op["summary"].as_str().unwrap_or("").to_string();
                        let fields = op["fields"]
                            .as_array()
                            .map(|a| {
                                a.iter()
                                    .filter_map(|v| v.as_str().map(String::from))
                                    .collect()
                            })
                            .unwrap_or_default();
                        let sample = op.get("sample_response").filter(|v| !v.is_null()).cloned();
                        ops.push(SelectableOperation {
                            container: container.clone(),
                            adapter: None,
                            method,
                            path,
                            summary,
                            fields,
                            sample,
                        });
                    }
                }
            }
        }
        if let Some(forms) = result["forms"].as_array() {
            for form in forms {
                let method = form["method"].as_str().unwrap_or("GET").to_string();
                let path = form["action"].as_str().unwrap_or("/").to_string();
                let fields = form["fields"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default();
                ops.push(SelectableOperation {
                    container: form["container"].as_str().map(String::from),
                    adapter: None,
                    method,
                    path,
                    summary: format!("HTML form {}", form["id"].as_str().unwrap_or("?")),
                    fields,
                    sample: None,
                });
            }
        }
    }
    ops
}

fn result_has_resources(info: &AgentCommandInfo) -> bool {
    info.result
        .as_ref()
        .and_then(|result| result["resources"].as_array())
        .map(|resources| !resources.is_empty())
        .unwrap_or(false)
}

fn builtin_adapter_for_selector(
    selector: &str,
    role: PipeAdapterRole,
) -> Option<PipeAdapterMetadata> {
    let registry = builtin_registry();
    let canonical = ServiceCatalog::resolve_alias(selector);
    let candidates = [canonical, selector.to_string()];
    candidates
        .iter()
        .find_map(|candidate| {
            registry.find(candidate).or_else(|| {
                registry
                    .adapters()
                    .into_iter()
                    .find(|metadata| selector_matches_builtin_kind(candidate, metadata.kind))
            })
        })
        .filter(|metadata| metadata.supports_role(role))
}

fn adapter_fields(kind: PipeAdapterKind) -> Vec<String> {
    match kind {
        PipeAdapterKind::SmtpTarget => vec![
            "from_email".to_string(),
            "reply_to_email".to_string(),
            "subject".to_string(),
            "body_text".to_string(),
            "body_html".to_string(),
        ],
        PipeAdapterKind::WebhookBridge
        | PipeAdapterKind::HttpEndpoint
        | PipeAdapterKind::HtmlForm => {
            vec![]
        }
        PipeAdapterKind::Pop3Source | PipeAdapterKind::ImapSource => vec![
            "subject".to_string(),
            "from_email".to_string(),
            "to_email".to_string(),
            "body_text".to_string(),
            "body_html".to_string(),
        ],
    }
}

fn adapter_sample(kind: PipeAdapterKind) -> Option<serde_json::Value> {
    match kind {
        PipeAdapterKind::Pop3Source | PipeAdapterKind::ImapSource => Some(serde_json::json!({
            "subject": "Incident opened",
            "from_email": "alerts@example.com",
            "to_email": "ops@example.com",
            "body_text": "CPU usage exceeded threshold"
        })),
        _ => None,
    }
}

fn synthetic_adapter_operation(metadata: &PipeAdapterMetadata) -> SelectableOperation {
    let method = match metadata.kind {
        PipeAdapterKind::SmtpTarget => "SEND",
        PipeAdapterKind::Pop3Source | PipeAdapterKind::ImapSource => "POLL",
        PipeAdapterKind::WebhookBridge => "POST",
        PipeAdapterKind::HttpEndpoint => "HTTP",
        PipeAdapterKind::HtmlForm => "FORM",
    };
    SelectableOperation {
        container: None,
        adapter: Some(metadata.clone()),
        method: method.to_string(),
        path: format!("adapter:{}", metadata.code),
        summary: format!("{} adapter", metadata.display_name),
        fields: adapter_fields(metadata.kind),
        sample: adapter_sample(metadata.kind),
    }
}

fn template_endpoint_for_operation(operation: &SelectableOperation) -> serde_json::Value {
    if let Some(adapter) = &operation.adapter {
        serde_json::json!({
            "mode": "adapter",
            "adapter": adapter.code,
            "display_name": adapter.display_name,
        })
    } else {
        serde_json::json!({
            "path": operation.path,
            "method": operation.method,
        })
    }
}

fn prompt_text(
    prompt: &str,
    default: Option<&str>,
    allow_empty: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut input = dialoguer::Input::<String>::new().with_prompt(prompt.to_string());
    if let Some(default) = default {
        input = input.default(default.to_string());
    }
    if allow_empty {
        input = input.allow_empty(true);
    }
    Ok(input.interact_text()?.trim().to_string())
}

fn prompt_optional_text(
    prompt: &str,
    default: Option<&str>,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let value = prompt_text(prompt, default, true)?;
    if value.is_empty() {
        Ok(None)
    } else {
        Ok(Some(value))
    }
}

fn prompt_secret(prompt: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let value = if io::stdin().is_terminal() {
        Password::new()
            .with_prompt(prompt)
            .allow_empty_password(true)
            .interact()?
    } else {
        prompt_text(prompt, None, true)?
    };
    let trimmed = value.trim().to_string();
    if trimmed.is_empty() {
        Ok(None)
    } else {
        Ok(Some(trimmed))
    }
}

fn prompt_port(prompt: &str, default: u16) -> Result<u16, Box<dyn std::error::Error>> {
    let value = prompt_text(prompt, Some(&default.to_string()), false)?;
    value
        .parse::<u16>()
        .map_err(|err| format!("Invalid port '{}': {}", value, err).into())
}

fn prompt_adapter_reference(
    metadata: &PipeAdapterMetadata,
) -> Result<(PipeAdapterReference, Option<String>), Box<dyn std::error::Error>> {
    let mut reference = PipeAdapterReference::new(metadata.code.clone());
    let role = metadata.roles.first().copied();
    if let Some(role) = role {
        reference = reference.with_role(role);
    }

    let mut config = serde_json::Map::new();
    let mut target_url = None;
    match metadata.kind {
        PipeAdapterKind::SmtpTarget => {
            let host = prompt_text("SMTP host", None, false)?;
            let port = prompt_port("SMTP port", 587)?;
            let username = prompt_optional_text("SMTP username", None)?;
            let password = prompt_secret("SMTP password")?;
            let from = prompt_optional_text("SMTP from address", None)?;
            let to = prompt_text("SMTP recipient address", None, false)?;
            let tls = dialoguer::Confirm::new()
                .with_prompt("Use TLS for SMTP")
                .default(true)
                .interact()?;
            config.insert("host".to_string(), serde_json::json!(host));
            config.insert("port".to_string(), serde_json::json!(port));
            config.insert("to".to_string(), serde_json::json!([to]));
            config.insert("tls".to_string(), serde_json::json!(tls));
            if let Some(username) = username {
                config.insert("username".to_string(), serde_json::json!(username));
            }
            if let Some(password) = password {
                config.insert("password".to_string(), serde_json::json!(password));
            }
            if let Some(from) = from {
                config.insert("from".to_string(), serde_json::json!(from));
            }
        }
        PipeAdapterKind::ImapSource => {
            let host = prompt_text("IMAP host", None, false)?;
            let port = prompt_port("IMAP port", 993)?;
            let username = prompt_text("IMAP username", None, false)?;
            let password = prompt_secret("IMAP password")?;
            let mailbox = prompt_text("IMAP mailbox", Some("INBOX"), false)?;
            let tls = dialoguer::Confirm::new()
                .with_prompt("Use TLS for IMAP")
                .default(true)
                .interact()?;
            config.insert("host".to_string(), serde_json::json!(host));
            config.insert("port".to_string(), serde_json::json!(port));
            config.insert("username".to_string(), serde_json::json!(username));
            config.insert("mailbox".to_string(), serde_json::json!(mailbox));
            config.insert("tls".to_string(), serde_json::json!(tls));
            if let Some(password) = password {
                config.insert("password".to_string(), serde_json::json!(password));
            }
        }
        PipeAdapterKind::Pop3Source => {
            let host = prompt_text("POP3 host", None, false)?;
            let port = prompt_port("POP3 port", 995)?;
            let username = prompt_text("POP3 username", None, false)?;
            let password = prompt_secret("POP3 password")?;
            let tls = dialoguer::Confirm::new()
                .with_prompt("Use TLS for POP3")
                .default(true)
                .interact()?;
            config.insert("host".to_string(), serde_json::json!(host));
            config.insert("port".to_string(), serde_json::json!(port));
            config.insert("username".to_string(), serde_json::json!(username));
            config.insert("tls".to_string(), serde_json::json!(tls));
            if let Some(password) = password {
                config.insert("password".to_string(), serde_json::json!(password));
            }
        }
        PipeAdapterKind::WebhookBridge => {
            let url = prompt_text("Webhook URL", None, false)?;
            target_url = Some(url.clone());
            config.insert("url".to_string(), serde_json::json!(url));
        }
        PipeAdapterKind::HttpEndpoint | PipeAdapterKind::HtmlForm => {}
    }

    if !config.is_empty() {
        reference = reference.with_config(serde_json::Value::Object(config));
    }

    Ok((reference, target_url))
}

fn is_sensitive_adapter_key(key: &str) -> bool {
    let lowered = key.trim().to_ascii_lowercase();
    lowered.contains("password")
        || lowered.contains("secret")
        || lowered.contains("token")
        || lowered.contains("credential")
        || lowered == "auth"
        || lowered.ends_with("_auth")
        || lowered.contains("api_key")
        || lowered.ends_with("_key")
}

fn redact_sensitive_json(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Array(values) => {
            for item in values {
                redact_sensitive_json(item);
            }
        }
        serde_json::Value::Object(map) => {
            for (key, value) in map.iter_mut() {
                if is_sensitive_adapter_key(key) {
                    *value = serde_json::Value::String("[REDACTED]".to_string());
                } else {
                    redact_sensitive_json(value);
                }
            }
        }
        _ => {}
    }
}

fn scan_inspection_hint(name: &str, deploy_ctx: &DeploymentContext) -> String {
    match deploy_ctx {
        DeploymentContext::Local => {
            format!(
                "Run `stacker pipe scan --containers {}` to inspect discovery results.",
                name
            )
        }
        DeploymentContext::Remote(_) => {
            format!(
                "Run `stacker pipe scan --app {}` to inspect discovery results.",
                name
            )
        }
    }
}

fn local_container_for_operation(operation: &SelectableOperation, fallback: &str) -> String {
    operation
        .container
        .clone()
        .unwrap_or_else(|| fallback.to_string())
}

fn operation_label(operation: &SelectableOperation) -> String {
    let prefix = operation
        .container
        .as_ref()
        .map(|container| format!("[{}] ", container))
        .unwrap_or_default();
    if operation.summary.is_empty() {
        format!("{}{:>6} {}", prefix, operation.method, operation.path)
    } else {
        format!(
            "{}{:>6} {} — {}",
            prefix, operation.method, operation.path, operation.summary
        )
    }
}

fn operation_labels(operations: &[SelectableOperation]) -> Vec<String> {
    operations.iter().map(operation_label).collect()
}

fn explain_no_selectable_operations(
    name: &str,
    info: &AgentCommandInfo,
    deploy_ctx: &DeploymentContext,
    role: &str,
) -> String {
    let target_kind = decode_probe_report(info)
        .ok()
        .and_then(|report| report.target_kind)
        .unwrap_or_else(|| {
            if selector_is_smtpish(name) {
                "smtp".to_string()
            } else if result_has_resources(info) {
                "resource".to_string()
            } else {
                "unknown".to_string()
            }
        });

    if target_kind == "smtp" {
        return format!(
            "'{}' looks like an SMTP {}. `stacker pipe create` currently supports HTTP endpoints and HTML forms only.\nUse an HTTP-capable bridge/webhook target first, validate locally, then export remotely.\n{}",
            name,
            role,
            scan_inspection_hint(name, deploy_ctx)
        );
    }

    if result_has_resources(info) {
        format!(
            "Resources were discovered for '{}', but `pipe create` currently supports HTTP endpoints and HTML forms only.\n{}",
            name,
            scan_inspection_hint(name, deploy_ctx)
        )
    } else {
        format!(
            "No selectable HTTP endpoints or HTML forms were discovered for '{}'.\n{}",
            name,
            scan_inspection_hint(name, deploy_ctx)
        )
    }
}

fn describe_discovery_run(run: &DiscoveryRun) -> String {
    let report = decode_probe_report(&run.info).ok();
    let requested = report
        .as_ref()
        .map(|report| {
            if report.protocols_requested.is_empty() {
                "default".to_string()
            } else {
                report.protocols_requested.join(",")
            }
        })
        .unwrap_or_else(|| "default".to_string());
    let capture_samples = run
        .info
        .parameters
        .as_ref()
        .and_then(|parameters| parameters.get("capture_samples"))
        .and_then(|value| value.as_bool())
        .unwrap_or(false);

    let source = match run.source {
        DiscoverySource::Cached => "cached",
        DiscoverySource::Fresh => "fresh",
        DiscoverySource::Synthetic => "synthetic",
    };

    format!(
        "{} result (protocols: {}, capture_samples: {})",
        source, requested, capture_samples
    )
}

fn prepare_local_discovery(
    _project_dir: &Path,
    request: &PipeDiscoveryRequest,
) -> Result<AgentCommandInfo, Box<dyn std::error::Error>> {
    let selector = request.selector.selector.as_str();
    let mut report = build_local_probe_report(
        selector,
        &discover_local_containers(Some(selector))?,
        &request.protocols_requested,
        request.capture_samples,
    );
    enrich_probe_report_metadata(&mut report, selector, None, request);
    local_report_to_agent_info(&report, request.capture_samples)
}

fn run_remote_probe(
    ctx: &CliRuntime,
    request: &PipeDiscoveryRequest,
    description: &str,
) -> Result<AgentCommandInfo, Box<dyn std::error::Error>> {
    let deployment_hash = request.selector.deployment_hash.as_deref().ok_or_else(|| {
        CliError::ConfigValidation("Remote discovery requires a deployment hash".to_string())
    })?;
    let params = crate::forms::status_panel::ProbeEndpointsCommandRequest {
        app_code: request.selector.selector.clone(),
        container: request.selector.container.clone(),
        protocols: request.protocols_requested.clone(),
        probe_timeout: 5,
        capture_samples: request.capture_samples,
    };

    let agent_request = AgentEnqueueRequest::new(deployment_hash, "probe_endpoints")
        .with_parameters(&params)
        .map_err(|e| CliError::ConfigValidation(format!("Invalid parameters: {}", e)))?;
    let info = run_agent_command(ctx, &agent_request, description, PROBE_TIMEOUT_SECS)?;
    if info.status != "completed" {
        return Ok(info);
    }

    let mut report = decode_probe_report(&info)?;
    enrich_probe_report_metadata(
        &mut report,
        &request.selector.selector,
        request.selector.container.as_deref(),
        request,
    );
    with_probe_report(info, &report).map_err(Into::into)
}

fn synthetic_transport_target_report(
    request: &PipeDiscoveryRequest,
) -> ProbeEndpointsCommandReport {
    let deployment_hash = request
        .selector
        .deployment_hash
        .clone()
        .unwrap_or_else(|| "local".to_string());

    ProbeEndpointsCommandReport {
        command_type: "probe_endpoints".to_string(),
        deployment_hash,
        app_code: request.selector.selector.clone(),
        protocols_detected: Vec::new(),
        protocols_requested: request.protocols_requested.clone(),
        containers: Vec::new(),
        endpoints: Vec::new(),
        resources: Vec::new(),
        forms: Vec::new(),
        probe_attempts: vec![ProbeAttempt {
            scope: if request.selector.mode == "local" {
                "local_selector".to_string()
            } else {
                "remote_app".to_string()
            },
            selector: Some(request.selector.selector.clone()),
            container: request.selector.container.clone(),
            protocols: request.protocols_requested.clone(),
            outcome: "skipped_transport_target".to_string(),
        }],
        target_kind: Some("smtp".to_string()),
        probed_at: Utc::now().to_rfc3339(),
    }
}

fn synthetic_transport_target_discovery(
    request: &PipeDiscoveryRequest,
) -> Result<DiscoveryRun, Box<dyn std::error::Error>> {
    let report = synthetic_transport_target_report(request);
    let info = probe_report_to_agent_info(&report, request.capture_samples)?;
    Ok(DiscoveryRun {
        info,
        source: DiscoverySource::Synthetic,
    })
}

fn cache_probe_if_completed(
    project_dir: &Path,
    request: &PipeDiscoveryRequest,
    info: &AgentCommandInfo,
) -> Result<(), Box<dyn std::error::Error>> {
    if info.status != "completed" {
        return Ok(());
    }
    let report = decode_probe_report(info)?;
    write_pipe_scan_cache(project_dir, request, &report)?;
    Ok(())
}

fn load_or_run_discovery<F>(
    project_dir: &Path,
    request: &PipeDiscoveryRequest,
    fresh_scan: F,
) -> Result<DiscoveryRun, Box<dyn std::error::Error>>
where
    F: FnOnce() -> Result<AgentCommandInfo, Box<dyn std::error::Error>>,
{
    if let Some(info) = load_exact_pipe_scan_cache(project_dir, request)? {
        return Ok(DiscoveryRun {
            info,
            source: DiscoverySource::Cached,
        });
    }
    if let Some(info) = load_latest_pipe_scan_cache(project_dir, &request.selector)? {
        return Ok(DiscoveryRun {
            info,
            source: DiscoverySource::Cached,
        });
    }

    let info = fresh_scan()?;
    cache_probe_if_completed(project_dir, request, &info)?;
    Ok(DiscoveryRun {
        info,
        source: DiscoverySource::Fresh,
    })
}

#[cfg(test)]
mod selectable_operation_tests {
    use super::*;
    use serde_json::json;
    use tempfile::tempdir;

    #[test]
    fn extract_operations_includes_html_forms_and_container() {
        let info = AgentCommandInfo {
            command_id: "local".to_string(),
            deployment_hash: "local".to_string(),
            command_type: "probe_endpoints".to_string(),
            status: "completed".to_string(),
            priority: "normal".to_string(),
            parameters: None,
            result: Some(json!({
                "app_code": "website",
                "protocols_detected": ["html_forms"],
                "endpoints": [],
                "resources": [],
                "forms": [{
                    "container": "local-website-1",
                    "id": "contact-form",
                    "action": "/contact",
                    "method": "POST",
                    "fields": ["name", "email"]
                }]
            })),
            error: None,
            created_at: String::new(),
            updated_at: String::new(),
        };
        let ops = extract_operations(&info);
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].container.as_deref(), Some("local-website-1"));
        assert_eq!(ops[0].method, "POST");
        assert_eq!(ops[0].path, "/contact");
        assert_eq!(ops[0].fields, vec!["name".to_string(), "email".to_string()]);
    }

    fn sample_report(protocols_requested: Vec<String>) -> ProbeEndpointsCommandReport {
        ProbeEndpointsCommandReport {
            command_type: "probe_endpoints".to_string(),
            deployment_hash: "local".to_string(),
            app_code: "status-panel-web".to_string(),
            protocols_detected: protocols_requested.clone(),
            protocols_requested,
            containers: vec![],
            endpoints: vec![],
            resources: vec![],
            forms: vec![ProbeForm {
                container: Some("status-panel-web".to_string()),
                id: "contact".to_string(),
                action: "/contact".to_string(),
                method: "POST".to_string(),
                fields: vec!["name".to_string(), "email".to_string()],
            }],
            probe_attempts: vec![ProbeAttempt {
                scope: "local_selector".to_string(),
                selector: Some("status-panel-web".to_string()),
                container: Some("status-panel-web".to_string()),
                protocols: vec!["html_forms".to_string()],
                outcome: "detected".to_string(),
            }],
            target_kind: Some("html_form".to_string()),
            probed_at: "2026-05-01T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn exact_cache_round_trip_reuses_discovery_result() {
        let dir = tempdir().expect("temp dir");
        let request =
            PipeDiscoveryRequest::local("status-panel-web", &["html_forms".to_string()], true);
        let report = sample_report(vec!["html_forms".to_string()]);

        write_pipe_scan_cache(dir.path(), &request, &report).expect("cache write should succeed");
        let cached = load_exact_pipe_scan_cache(dir.path(), &request)
            .expect("cache read should succeed")
            .expect("exact cache entry should exist");

        assert_eq!(cached.status, "completed");
        let cached_report = decode_probe_report(&cached).expect("cached report should decode");
        assert_eq!(cached_report.protocols_requested, vec!["html_forms"]);
        assert_eq!(cached_report.forms.len(), 1);
    }

    #[test]
    fn selector_cache_preserves_narrow_protocol_scope_for_create() {
        let dir = tempdir().expect("temp dir");
        let narrow_request =
            PipeDiscoveryRequest::local("status-panel-web", &["html_forms".to_string()], true);
        let report = sample_report(vec!["html_forms".to_string()]);
        write_pipe_scan_cache(dir.path(), &narrow_request, &report)
            .expect("cache write should succeed");

        let default_request =
            PipeDiscoveryRequest::local("status-panel-web", &default_pipe_create_protocols(), true);
        let cached_run = load_or_run_discovery(dir.path(), &default_request, || {
            panic!("fresh scan should not run when selector cache exists")
        })
        .expect("selector cache should be reused");

        assert_eq!(cached_run.source, DiscoverySource::Cached);
        let cached_report =
            decode_probe_report(&cached_run.info).expect("cached selector report should decode");
        assert_eq!(cached_report.protocols_requested, vec!["html_forms"]);
        assert_eq!(cached_report.forms[0].action, "/contact");
    }

    #[test]
    fn unsupported_smtp_target_returns_actionable_guidance() {
        let info = AgentCommandInfo {
            command_id: "cached-smtp".to_string(),
            deployment_hash: "local".to_string(),
            command_type: "probe_endpoints".to_string(),
            status: "completed".to_string(),
            priority: "normal".to_string(),
            parameters: Some(json!({
                "app_code": "smtp",
                "protocols": ["html_forms"],
                "capture_samples": true
            })),
            result: Some(json!({
                "type": "probe_endpoints",
                "deployment_hash": "local",
                "app_code": "smtp",
                "protocols_detected": [],
                "protocols_requested": ["html_forms"],
                "containers": [],
                "endpoints": [],
                "resources": [],
                "forms": [],
                "probe_attempts": [{
                    "scope": "local_selector",
                    "selector": "smtp",
                    "protocols": ["html_forms"],
                    "outcome": "empty"
                }],
                "target_kind": "smtp",
                "probed_at": "2026-05-01T00:00:00Z"
            })),
            error: None,
            created_at: String::new(),
            updated_at: String::new(),
        };

        let message =
            explain_no_selectable_operations("smtp", &info, &DeploymentContext::Local, "target");

        assert!(message.contains("SMTP target"));
        assert!(message.contains("HTTP-capable bridge/webhook target"));
        assert!(message.contains("stacker pipe scan --containers smtp"));
    }

    #[test]
    fn smtp_target_discovery_is_synthetic_for_remote_targets() {
        let request = PipeDiscoveryRequest::remote(
            "deployment-123",
            "smtp",
            None,
            &default_pipe_create_protocols(),
            true,
        );

        let run = synthetic_transport_target_discovery(&request)
            .expect("smtp transport target should synthesize discovery");
        let report = decode_probe_report(&run.info).expect("synthetic report should decode");

        assert_eq!(run.source, DiscoverySource::Synthetic);
        assert_eq!(run.info.status, "completed");
        assert_eq!(report.app_code, "smtp");
        assert_eq!(report.target_kind.as_deref(), Some("smtp"));
        assert!(report.endpoints.is_empty());
        assert!(report.forms.is_empty());
        assert_eq!(report.probe_attempts[0].outcome, "skipped_transport_target");
    }

    #[test]
    fn describe_discovery_run_labels_synthetic_results() {
        let request = PipeDiscoveryRequest::local("smtp", &default_pipe_create_protocols(), true);
        let run = synthetic_transport_target_discovery(&request)
            .expect("smtp transport target should synthesize discovery");

        let description = describe_discovery_run(&run);

        assert!(description.contains("synthetic"));
        assert!(description.contains("protocols:"));
    }

    #[test]
    fn builtin_adapter_detection_resolves_source_and_target_roles() {
        let source = builtin_adapter_for_selector("imap", PipeAdapterRole::Source)
            .expect("imap source adapter should resolve");
        let target = builtin_adapter_for_selector("mailhog", PipeAdapterRole::Target)
            .expect("mailhog smtp target adapter should resolve");

        assert_eq!(source.code, "imap");
        assert_eq!(source.kind, PipeAdapterKind::ImapSource);
        assert_eq!(target.code, "mailhog");
        assert_eq!(target.kind, PipeAdapterKind::SmtpTarget);
    }

    #[test]
    fn synthetic_adapter_operation_exposes_expected_mail_fields() {
        let metadata = builtin_adapter_for_selector("smtp", PipeAdapterRole::Target)
            .expect("smtp target adapter should resolve");
        let operation = synthetic_adapter_operation(&metadata);

        assert!(operation.adapter.is_some());
        assert_eq!(operation.method, "SEND");
        assert_eq!(operation.path, "adapter:smtp");
        assert!(operation.fields.contains(&"subject".to_string()));
        assert!(operation.fields.contains(&"body_text".to_string()));
    }

    #[test]
    fn redact_sensitive_json_masks_adapter_secrets() {
        let mut value = serde_json::json!({
            "instance": {
                "target_adapter": {
                    "code": "smtp",
                    "config": {
                        "host": "smtp.example.com",
                        "password": "supersecret",
                        "api_key": "key-123"
                    }
                }
            }
        });

        redact_sensitive_json(&mut value);

        assert_eq!(
            value["instance"]["target_adapter"]["config"]["password"],
            "[REDACTED]"
        );
        assert_eq!(
            value["instance"]["target_adapter"]["config"]["api_key"],
            "[REDACTED]"
        );
        assert_eq!(
            value["instance"]["target_adapter"]["config"]["host"],
            "smtp.example.com"
        );
    }
}

impl CallableTrait for PipeCreateCommand {
    fn call(&self) -> Result<(), Box<dyn std::error::Error>> {
        let project_dir = std::env::current_dir().map_err(CliError::Io)?;
        let (ctx, deploy_ctx) =
            match resolve_local_deployment_context(&self.deployment, &project_dir)? {
                Some(local_ctx) => (None, local_ctx),
                None => {
                    let ctx = CliRuntime::new("pipe create")?;
                    let deploy_ctx = resolve_deployment_context(&self.deployment, &ctx)?;
                    (Some(ctx), deploy_ctx)
                }
            };
        let prefix = mode_prefix(&deploy_ctx);
        let local_mode = deploy_ctx.is_local();
        let hash = match &deploy_ctx {
            DeploymentContext::Remote(h) => Some(h.clone()),
            DeploymentContext::Local => None,
        };
        let create_protocols = default_pipe_create_protocols();

        let source_adapter_meta =
            builtin_adapter_for_selector(&self.source, PipeAdapterRole::Source);
        let target_adapter_meta =
            builtin_adapter_for_selector(&self.target, PipeAdapterRole::Target);

        let source_run = if source_adapter_meta.is_none() {
            Some(if local_mode {
                println!(
                    "{}Preparing local discovery for source '{}'...",
                    prefix, self.source
                );
                let source_request =
                    PipeDiscoveryRequest::local(&self.source, &create_protocols, true);
                load_or_run_discovery(&project_dir, &source_request, || {
                    prepare_local_discovery(&project_dir, &source_request)
                })?
            } else {
                let ctx = ctx.as_ref().expect("remote runtime");
                let remote_hash = hash.clone().expect("remote hash");
                println!("Preparing discovery for source app '{}'...", self.source);
                let source_request = PipeDiscoveryRequest::remote(
                    &remote_hash,
                    &self.source,
                    None,
                    &create_protocols,
                    true,
                );
                load_or_run_discovery(&project_dir, &source_request, || {
                    run_remote_probe(
                        &ctx,
                        &source_request,
                        &format!("Scanning source: {}", self.source),
                    )
                })?
            })
        } else {
            None
        };
        let target_run = if target_adapter_meta.is_none() {
            Some(if local_mode {
                println!(
                    "{}Preparing local discovery for target '{}'...",
                    prefix, self.target
                );
                let target_request =
                    PipeDiscoveryRequest::local(&self.target, &create_protocols, true);
                load_or_run_discovery(&project_dir, &target_request, || {
                    prepare_local_discovery(&project_dir, &target_request)
                })?
            } else {
                let ctx = ctx.as_ref().expect("remote runtime");
                let remote_hash = hash.clone().expect("remote hash");
                println!("Preparing discovery for target app '{}'...", self.target);
                let target_request = PipeDiscoveryRequest::remote(
                    &remote_hash,
                    &self.target,
                    None,
                    &create_protocols,
                    true,
                );
                load_or_run_discovery(&project_dir, &target_request, || {
                    run_remote_probe(
                        &ctx,
                        &target_request,
                        &format!("Scanning target: {}", self.target),
                    )
                })?
            })
        } else {
            None
        };

        if let Some(run) = &source_run {
            println!("  Source discovery: {}", describe_discovery_run(run));
        } else if let Some(metadata) = &source_adapter_meta {
            println!(
                "  Source adapter: {} ({})",
                metadata.display_name, metadata.code
            );
        }
        if let Some(run) = &target_run {
            println!("  Target discovery: {}", describe_discovery_run(run));
        } else if let Some(metadata) = &target_adapter_meta {
            println!(
                "  Target adapter: {} ({})",
                metadata.display_name, metadata.code
            );
        }

        if source_run
            .as_ref()
            .is_some_and(|run| run.info.status != "completed")
            || target_run
                .as_ref()
                .is_some_and(|run| run.info.status != "completed")
        {
            eprintln!("Scan failed for one or both apps. Cannot create pipe.");
            if let Some(run) = &source_run {
                if run.info.status != "completed" {
                    eprintln!("  Source '{}': {}", self.source, run.info.status);
                }
            }
            if let Some(run) = &target_run {
                if run.info.status != "completed" {
                    eprintln!("  Target '{}': {}", self.target, run.info.status);
                }
            }
            return Ok(());
        }

        // Step 2: Extract discovered endpoints
        let source_ops = if let Some(metadata) = &source_adapter_meta {
            vec![synthetic_adapter_operation(metadata)]
        } else {
            extract_operations(&source_run.as_ref().expect("source discovery").info)
        };
        let target_ops = if let Some(metadata) = &target_adapter_meta {
            vec![synthetic_adapter_operation(metadata)]
        } else {
            extract_operations(&target_run.as_ref().expect("target discovery").info)
        };

        if source_ops.is_empty() {
            eprintln!(
                "{}",
                explain_no_selectable_operations(
                    &self.source,
                    &source_run.as_ref().expect("source discovery").info,
                    &deploy_ctx,
                    "source",
                )
            );
            return Ok(());
        }
        if target_ops.is_empty() {
            eprintln!(
                "{}",
                explain_no_selectable_operations(
                    &self.target,
                    &target_run.as_ref().expect("target discovery").info,
                    &deploy_ctx,
                    "target",
                )
            );
            return Ok(());
        }

        // Step 3: Let user select source endpoint
        let source_idx = if source_ops.len() == 1 {
            println!(
                "\n  Using source {}",
                operation_label(source_ops.first().expect("single source op"))
            );
            0
        } else {
            let source_labels = operation_labels(&source_ops);
            println!("\n  Select source endpoint (data comes FROM here):");
            dialoguer::Select::new()
                .items(&source_labels)
                .default(0)
                .interact()?
        };
        let src_op = &source_ops[source_idx];
        let src_method = &src_op.method;
        let src_path = &src_op.path;
        let src_fields = &src_op.fields;
        let src_sample = &src_op.sample;

        // Step 4: Let user select target endpoint
        let target_idx = if target_ops.len() == 1 {
            println!(
                "\n  Using target {}",
                operation_label(target_ops.first().expect("single target op"))
            );
            0
        } else {
            let target_labels = operation_labels(&target_ops);
            println!("\n  Select target endpoint (data goes TO here):");
            dialoguer::Select::new()
                .items(&target_labels)
                .default(0)
                .interact()?
        };
        let tgt_op = &target_ops[target_idx];
        let tgt_method = &tgt_op.method;
        let tgt_path = &tgt_op.path;
        let tgt_fields = &tgt_op.fields;

        // Step 5: Build field mapping (smart matching with sample data)
        let (field_mapping, match_result) = if !self.manual
            && !src_fields.is_empty()
            && !tgt_fields.is_empty()
        {
            let matcher = select_field_matcher(self.ai, self.no_ai, self.ml);
            let result = matcher.match_fields(src_fields, tgt_fields, src_sample.as_ref());
            let mode_label = match result.mode {
                crate::cli::field_matcher::MatchingMode::Ai => "AI",
                crate::cli::field_matcher::MatchingMode::Deterministic => "deterministic",
                crate::cli::field_matcher::MatchingMode::Ml => "ML",
            };
            println!(
                "\n  Auto-matching fields ({} mode, source → target):",
                mode_label
            );

            let matched: Vec<String> = result
                .mapping
                .as_object()
                .map(|m| {
                    m.iter()
                        .map(|(k, v)| {
                            let src = v.as_str().unwrap_or("?");
                            let conf = result.confidence.get(k).copied().unwrap_or(1.0);
                            if conf < 1.0 {
                                format!("    {} ← {} (confidence: {:.0}%) ✓", k, src, conf * 100.0)
                            } else {
                                format!("    {} ← {} ✓", k, src)
                            }
                        })
                        .collect()
                })
                .unwrap_or_default();

            for line in &matched {
                println!("{}", line);
            }

            // Show transformation suggestions from AI
            for suggestion in &result.suggestions {
                println!(
                    "    💡 {}: {} — {}",
                    suggestion.target_field, suggestion.expression, suggestion.description
                );
            }

            // Show unmatched target fields
            let matched_keys: Vec<&str> = result
                .mapping
                .as_object()
                .map(|m| m.keys().map(|k| k.as_str()).collect())
                .unwrap_or_default();
            let unmatched: Vec<&String> = tgt_fields
                .iter()
                .filter(|f| !matched_keys.contains(&f.as_str()))
                .collect();
            if !unmatched.is_empty() {
                println!(
                    "    Unmatched target fields: {}",
                    unmatched
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                println!("    (You can edit the field mapping later via the API)");
            }

            if matched_keys.is_empty() {
                println!("    No auto-matches found. Creating pass-through mapping.");
                let mut pass = serde_json::Map::new();
                for sf in src_fields {
                    pass.insert(sf.clone(), serde_json::Value::String(format!("$.{}", sf)));
                }
                (serde_json::Value::Object(pass), Some(result))
            } else {
                let mapping = result.mapping.clone();
                (mapping, Some(result))
            }
        } else {
            // Manual mode or no fields discovered
            println!("\n  No field auto-matching available. Creating identity mapping.");
            (serde_json::json!({}), None)
        };

        // Step 6: Ask for pipe name
        let default_name = format!("{}-to-{}", self.source, self.target);
        let pipe_name: String = dialoguer::Input::new()
            .with_prompt("Pipe name")
            .default(default_name)
            .interact_text()?;

        // Step 7: Create template via API — include matching metadata in config
        let mut config = serde_json::json!({"retry_count": 3});
        if let Some(ref result) = match_result {
            config["matching_mode"] = serde_json::Value::String(result.mode.to_string());
            if !result.confidence.is_empty() {
                let conf_map: serde_json::Map<String, serde_json::Value> = result
                    .confidence
                    .iter()
                    .map(|(k, v)| (k.clone(), serde_json::json!(v)))
                    .collect();
                config["field_confidence"] = serde_json::Value::Object(conf_map);
            }
            if !result.suggestions.is_empty() {
                config["transformations"] = serde_json::json!(result
                    .suggestions
                    .iter()
                    .map(|s| {
                        serde_json::json!({
                            "target": s.target_field,
                            "expr": s.expression,
                            "description": s.description,
                        })
                    })
                    .collect::<Vec<_>>());
            }
        }

        let template_request = CreatePipeTemplateApiRequest {
            name: pipe_name.clone(),
            description: Some(format!(
                "{} {} → {} {}",
                src_method, src_path, tgt_method, tgt_path
            )),
            source_app_type: self.source.clone(),
            source_endpoint: template_endpoint_for_operation(src_op),
            target_app_type: self.target.clone(),
            target_endpoint: template_endpoint_for_operation(tgt_op),
            target_external_url: None,
            field_mapping: field_mapping.clone(),
            config: Some(config),
            is_public: Some(false),
        };

        let source_container_name = if let Some(adapter) = &src_op.adapter {
            adapter.code.clone()
        } else if local_mode {
            local_container_for_operation(src_op, &self.source)
        } else {
            self.source.clone()
        };
        let local_target_container_name = if tgt_op.adapter.is_some() {
            None
        } else if local_mode {
            Some(local_container_for_operation(tgt_op, &self.target))
        } else {
            Some(self.target.clone())
        };
        let (source_adapter, _) = if let Some(metadata) = &src_op.adapter {
            prompt_adapter_reference(metadata)?
        } else {
            (PipeAdapterReference::new(""), None)
        };
        let source_adapter = src_op.adapter.as_ref().map(|_| source_adapter);
        let (target_adapter, adapter_target_url) = if let Some(metadata) = &tgt_op.adapter {
            prompt_adapter_reference(metadata)?
        } else {
            (PipeAdapterReference::new(""), None)
        };
        let target_adapter = tgt_op.adapter.as_ref().map(|_| target_adapter);
        let target_url = if target_adapter.is_some() {
            adapter_target_url
        } else {
            None
        };

        if local_mode {
            let store = LocalPipeStore::new(&project_dir);
            let mut notes = Vec::new();
            if let Some(run) = &source_run {
                notes.push(format!("source discovery: {}", describe_discovery_run(run)));
            }
            if let Some(run) = &target_run {
                notes.push(format!("target discovery: {}", describe_discovery_run(run)));
            }

            let local_pipe = LocalPipeDocument::draft(NewLocalPipeDocument {
                name: pipe_name.clone(),
                source: LocalPipeBinding {
                    selector: self.source.clone(),
                    container: src_op.container.clone(),
                    adapter: source_adapter.clone(),
                    method: src_method.clone(),
                    path: src_path.clone(),
                    fields: src_fields.clone(),
                },
                target: LocalPipeBinding {
                    selector: self.target.clone(),
                    container: tgt_op.container.clone(),
                    adapter: target_adapter.clone(),
                    method: tgt_method.clone(),
                    path: tgt_path.clone(),
                    fields: tgt_fields.clone(),
                },
                template: LocalPipeTemplate {
                    description: template_request.description.clone(),
                    source_app_type: template_request.source_app_type.clone(),
                    source_endpoint: template_request.source_endpoint.clone(),
                    target_app_type: template_request.target_app_type.clone(),
                    target_endpoint: template_request.target_endpoint.clone(),
                    target_external_url: template_request.target_external_url.clone(),
                    field_mapping: template_request.field_mapping.clone(),
                    config: template_request.config.clone(),
                    is_public: template_request.is_public.unwrap_or(false),
                },
                instance: LocalPipeInstance {
                    source_adapter: source_adapter.clone(),
                    source_container: source_container_name.clone(),
                    target_adapter: target_adapter.clone(),
                    target_container: local_target_container_name.clone(),
                    target_url: target_url.clone(),
                    field_mapping_override: None,
                    config_override: None,
                    trigger_count: 0,
                    error_count: 0,
                    last_triggered_at: None,
                },
                diagnostics: LocalPipeDiagnostics { notes },
            })?;
            let path = store.save_new(&local_pipe)?;

            if self.json {
                let mut output = serde_json::json!({
                    "local": true,
                    "path": path.display().to_string(),
                    "pipe": local_pipe,
                });
                redact_sensitive_json(&mut output);
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!(
                    "\n  {}✓ Local pipe '{}' created successfully",
                    prefix, pipe_name
                );
                println!("  Local ID:     {}", local_pipe.id);
                println!("  File:         {}", path.display());
                println!(
                    "  Source:       {} ({})",
                    local_pipe.source_display(),
                    src_path
                );
                println!(
                    "  Target:       {} ({})",
                    local_pipe.target_display(),
                    tgt_path
                );
                println!("  Status:       {}", local_pipe.status);
                println!("  Mapping:      {}", serde_json::to_string(&field_mapping)?);
                println!(
                    "  Promote:      stacker pipe deploy {} <deployment_hash>",
                    local_pipe.id
                );
            }

            return Ok(());
        }

        let ctx = ctx.as_ref().expect("remote runtime");
        let pb = progress::spinner("Creating pipe template...");
        let template = ctx
            .block_on(ctx.client.create_pipe_template(&template_request))
            .map_err(|e| {
                progress::finish_error(&pb, "Template creation failed");
                e
            })?;
        progress::finish_success(&pb, "Template created");

        let instance_request = CreatePipeInstanceApiRequest {
            deployment_hash: hash.clone(),
            source_adapter,
            source_container: source_container_name.clone(),
            target_adapter,
            target_container: local_target_container_name.clone(),
            target_url: target_url.clone(),
            template_id: Some(template.id.clone()),
            field_mapping_override: None,
            config_override: None,
        };

        let pb = progress::spinner("Creating pipe instance...");
        let instance = ctx
            .block_on(ctx.client.create_pipe_instance(&instance_request))
            .map_err(|e| {
                progress::finish_error(&pb, "Instance creation failed");
                e
            })?;
        progress::finish_success(&pb, "Pipe instance created");

        if self.json {
            let mut output = serde_json::json!({
                "template": template,
                "instance": instance,
                "local": false,
            });
            redact_sensitive_json(&mut output);
            println!("{}", serde_json::to_string_pretty(&output)?);
        } else {
            println!("\n  ✓ Pipe '{}' created successfully", pipe_name);
            println!("  Template ID:  {}", template.id);
            println!("  Instance ID:  {}", instance.id);
            let source_display = src_op
                .adapter
                .as_ref()
                .map(|metadata| format!("{} adapter", metadata.code))
                .unwrap_or_else(|| source_container_name.clone());
            let target_display = tgt_op
                .adapter
                .as_ref()
                .map(|metadata| format!("{} adapter", metadata.code))
                .or_else(|| local_target_container_name.clone())
                .or(target_url.clone())
                .unwrap_or_else(|| self.target.clone());
            println!("  Source:       {} ({})", source_display, src_path);
            println!("  Target:       {} ({})", target_display, tgt_path);
            println!(
                "  Status:       {} (use 'stacker pipe activate {}' to start)",
                instance.status, instance.id
            );
            println!("  Mapping:      {}", serde_json::to_string(&field_mapping)?);
        }

        Ok(())
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// stacker pipe list — list active pipes for a deployment
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

pub struct PipeListCommand {
    pub json: bool,
    pub deployment: Option<String>,
}

impl PipeListCommand {
    pub fn new(json: bool, deployment: Option<String>) -> Self {
        Self { json, deployment }
    }
}

impl CallableTrait for PipeListCommand {
    fn call(&self) -> Result<(), Box<dyn std::error::Error>> {
        let project_dir = std::env::current_dir().map_err(CliError::Io)?;
        if let Some(deploy_ctx) = resolve_local_deployment_context(&self.deployment, &project_dir)?
        {
            let prefix = mode_prefix(&deploy_ctx);
            let pb = progress::spinner(&format!("{}Fetching pipes...", prefix));
            let store = LocalPipeStore::new(&project_dir);
            let pipes = store.list().map_err(|e| {
                progress::finish_error(&pb, "Failed to fetch local pipes");
                e
            })?;
            progress::finish_success(&pb, &format!("{}{} pipe(s) found", prefix, pipes.len()));

            if pipes.is_empty() {
                println!("No pipes configured for this deployment.");
                println!("Use 'stacker pipe create <source> <target>' to create a pipe.");
                return Ok(());
            }

            if self.json {
                let mut output = serde_json::to_value(&pipes)?;
                redact_sensitive_json(&mut output);
                println!("{}", serde_json::to_string_pretty(&output)?);
                return Ok(());
            }

            println!(
                "\n{:<38} {:<15} {:<15} {:<10} {:>8} {:>8} {}",
                "ID", "SOURCE", "TARGET", "STATUS", "TRIGGERS", "ERRORS", "LAST TRIGGERED"
            );
            println!("{}", "─".repeat(120));

            for pipe in &pipes {
                let last = pipe
                    .instance
                    .last_triggered_at
                    .as_deref()
                    .unwrap_or("never");
                let status_icon = match pipe.status.as_str() {
                    "active" => "● active",
                    "paused" => "◉ paused",
                    "error" => "✗ error",
                    _ => "○ draft",
                };

                println!(
                    "{:<38} {:<15} {:<15} {:<10} {:>8} {:>8} {}",
                    &pipe.id,
                    truncate_str(pipe.source_display(), 14),
                    truncate_str(pipe.target_display(), 14),
                    status_icon,
                    pipe.instance.trigger_count,
                    pipe.instance.error_count,
                    last,
                );
            }

            println!("\n{} pipe(s) total.", pipes.len());
            return Ok(());
        }

        let ctx = CliRuntime::new("pipe list")?;
        let deploy_ctx = resolve_deployment_context(&self.deployment, &ctx)?;
        let prefix = mode_prefix(&deploy_ctx);
        let hash = match &deploy_ctx {
            DeploymentContext::Remote(hash) => hash,
            DeploymentContext::Local => unreachable!("local mode handled above"),
        };

        let pb = progress::spinner(&format!("{}Fetching pipes...", prefix));
        let pipes = ctx
            .block_on(ctx.client.list_pipe_instances(hash))
            .map_err(|e| {
                progress::finish_error(&pb, "Failed to fetch pipes");
                e
            })?;
        progress::finish_success(&pb, &format!("{}{} pipe(s) found", prefix, pipes.len()));

        if pipes.is_empty() {
            println!("No pipes configured for this deployment.");
            println!("Use 'stacker pipe create <source> <target>' to create a pipe.");
            return Ok(());
        }

        if self.json {
            let mut output = serde_json::to_value(&pipes)?;
            redact_sensitive_json(&mut output);
            println!("{}", serde_json::to_string_pretty(&output)?);
            return Ok(());
        }

        println!(
            "\n{:<38} {:<15} {:<15} {:<10} {:>8} {:>8} {}",
            "ID", "SOURCE", "TARGET", "STATUS", "TRIGGERS", "ERRORS", "LAST TRIGGERED"
        );
        println!("{}", "─".repeat(120));

        for pipe in &pipes {
            let source = pipe
                .source_adapter
                .as_ref()
                .map(|adapter| adapter.code.as_str())
                .unwrap_or(&pipe.source_container);
            let target = pipe
                .target_adapter
                .as_ref()
                .map(|adapter| adapter.code.as_str())
                .or(pipe.target_container.as_deref())
                .or(pipe.target_url.as_deref())
                .unwrap_or("-");
            let last = pipe.last_triggered_at.as_deref().unwrap_or("never");
            let status_icon = match pipe.status.as_str() {
                "active" => "● active",
                "paused" => "◉ paused",
                "error" => "✗ error",
                _ => "○ draft",
            };

            println!(
                "{:<38} {:<15} {:<15} {:<10} {:>8} {:>8} {}",
                &pipe.id,
                truncate_str(source, 14),
                truncate_str(target, 14),
                status_icon,
                pipe.trigger_count,
                pipe.error_count,
                last,
            );
        }

        println!("\n{} pipe(s) total.", pipes.len());
        Ok(())
    }
}

fn truncate_str(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max - 1])
    }
}

fn pipe_template_matches_request(
    existing: &CreatePipeTemplateApiRequest,
    candidate: &PipeTemplateInfo,
) -> bool {
    candidate.description == existing.description
        && candidate.source_app_type == existing.source_app_type
        && candidate.source_endpoint == existing.source_endpoint
        && candidate.target_app_type == existing.target_app_type
        && candidate.target_endpoint == existing.target_endpoint
        && candidate.target_external_url == existing.target_external_url
        && candidate.field_mapping == existing.field_mapping
        && candidate.config == existing.config
        && candidate.is_public.unwrap_or(false) == existing.is_public.unwrap_or(false)
}

fn find_reusable_pipe_template(
    templates: &[PipeTemplateInfo],
    request: &CreatePipeTemplateApiRequest,
) -> Result<Option<PipeTemplateInfo>, CliError> {
    let Some(existing) = templates
        .iter()
        .find(|template| template.name == request.name)
    else {
        return Ok(None);
    };

    if pipe_template_matches_request(request, existing) {
        Ok(Some(existing.clone()))
    } else {
        Err(CliError::ConfigValidation(format!(
            "Remote pipe template '{}' already exists with a different definition. Rename the local pipe or update the remote template before deploying.",
            request.name
        )))
    }
}

/// Select the appropriate field matcher based on CLI flags and stacker.yml config.
///
/// Priority:
/// 1. `--ai` flag → AI matcher (error if AI not configured)
/// 2. `--no-ai` flag → deterministic matcher
/// 3. Neither flag → check `stacker.yml` ai.enabled; if true → AI, else → deterministic
fn select_field_matcher(
    force_ai: bool,
    force_no_ai: bool,
    force_ml: bool,
) -> Box<dyn FieldMatcher> {
    if force_ml {
        return Box::new(crate::cli::ml_field_matcher::MlFieldMatcher::new());
    }

    if force_no_ai {
        return Box::new(DeterministicFieldMatcher);
    }

    let use_ai = if force_ai {
        true
    } else {
        // Try to read stacker.yml to check ai.enabled
        let project_dir = std::env::current_dir().unwrap_or_default();
        let config_path = project_dir.join("stacker.yml");
        if config_path.exists() {
            crate::cli::config_parser::StackerConfig::from_file(&config_path)
                .map(|c| c.ai.enabled)
                .unwrap_or(false)
        } else {
            false
        }
    };

    if use_ai {
        // Try to create AI matcher; fall back to deterministic on failure
        let project_dir = std::env::current_dir().unwrap_or_default();
        let config_path = project_dir.join("stacker.yml");
        let ai_config = config_path
            .exists()
            .then(|| {
                crate::cli::config_parser::StackerConfig::from_file(&config_path)
                    .ok()
                    .map(|c| c.ai)
            })
            .flatten();

        if let Some(config) = ai_config {
            match crate::cli::ai_field_matcher::AiFieldMatcher::new(&config) {
                Ok(matcher) => return Box::new(matcher),
                Err(e) => {
                    eprintln!(
                        "  ⚠ AI matcher unavailable ({}), falling back to deterministic",
                        e
                    );
                }
            }
        } else if force_ai {
            eprintln!(
                "  ⚠ --ai flag set but no ai: config in stacker.yml, falling back to deterministic"
            );
        }
    }

    Box::new(DeterministicFieldMatcher)
}

fn example_local_trigger_command(pipe_id: &str) -> String {
    format!(
        "stacker pipe trigger {} --data '{}'",
        pipe_id,
        r#"{"email":"person@example.com","subject":"Local pipe test","message":"Hello from the local contact form"}"#
    )
}

fn source_field_names(source_data: &serde_json::Value) -> Vec<String> {
    source_data
        .as_object()
        .map(|object| object.keys().cloned().collect())
        .unwrap_or_default()
}

fn lookup_json_path<'a>(
    source_data: &'a serde_json::Value,
    expression: &str,
) -> Option<&'a serde_json::Value> {
    if expression == "$" {
        return Some(source_data);
    }

    let mut current = source_data;
    for segment in expression.strip_prefix("$.")?.split('.') {
        if segment.is_empty() {
            return None;
        }
        current = current.get(segment)?;
    }

    Some(current)
}

fn apply_field_mapping(
    source_data: &serde_json::Value,
    mapping: &serde_json::Value,
) -> serde_json::Value {
    let mut output = serde_json::Map::new();

    if let Some(mapping_object) = mapping.as_object() {
        for (target_field, expression) in mapping_object {
            if let Some(path) = expression.as_str() {
                if let Some(value) = lookup_json_path(source_data, path) {
                    output.insert(target_field.clone(), value.clone());
                }
            }
        }
    }

    serde_json::Value::Object(output)
}

fn infer_local_mapping(
    pipe: &LocalPipeDocument,
    source_data: &serde_json::Value,
) -> Option<serde_json::Value> {
    let source_fields = source_field_names(source_data);
    if source_fields.is_empty() || pipe.target.fields.is_empty() {
        return None;
    }

    let matcher = select_field_matcher(false, false, false);
    let result = matcher.match_fields(&source_fields, &pipe.target.fields, Some(source_data));
    let mapping = result.mapping.as_object()?;
    if mapping.is_empty() {
        return None;
    }

    Some(apply_field_mapping(source_data, &result.mapping))
}

fn apply_smtp_defaults(source_data: &serde_json::Value, payload: &mut serde_json::Value) {
    let Some(source_object) = source_data.as_object() else {
        return;
    };
    let Some(payload_object) = payload.as_object_mut() else {
        return;
    };

    if !payload_object.contains_key("subject") {
        if let Some(subject) = source_object.get("subject") {
            payload_object.insert("subject".to_string(), subject.clone());
        }
    }

    if !payload_object.contains_key("from_email") {
        if let Some(email) = source_object.get("email") {
            payload_object.insert("from_email".to_string(), email.clone());
        }
    }

    if !payload_object.contains_key("reply_to_email") {
        if let Some(email) = source_object.get("email") {
            payload_object.insert("reply_to_email".to_string(), email.clone());
        }
    }

    if !payload_object.contains_key("body_text") {
        if let Some(message) = source_object.get("message") {
            payload_object.insert("body_text".to_string(), message.clone());
        }
    }
}

fn build_local_trigger_payload(
    pipe: &LocalPipeDocument,
    source_data: &serde_json::Value,
) -> serde_json::Value {
    let mut payload = if pipe
        .effective_field_mapping()
        .as_object()
        .map(|mapping| !mapping.is_empty())
        .unwrap_or(false)
    {
        apply_field_mapping(source_data, pipe.effective_field_mapping())
    } else {
        infer_local_mapping(pipe, source_data).unwrap_or_else(|| source_data.clone())
    };

    if pipe
        .instance
        .target_adapter
        .as_ref()
        .map(|adapter| adapter.code == "smtp")
        .unwrap_or(false)
    {
        apply_smtp_defaults(source_data, &mut payload);
    }

    payload
}

fn is_loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]")
}

fn local_target_aliases(container: &LocalContainerInfo) -> Vec<&str> {
    let mut aliases = vec![container.name.as_str()];
    if let Some(service) = container.labels.get("com.docker.compose.service") {
        aliases.push(service.as_str());
    }
    aliases
}

fn matches_local_target_alias(container: &LocalContainerInfo, candidate: &str) -> bool {
    let candidate = candidate.trim();
    if candidate.is_empty() {
        return false;
    }
    local_target_aliases(container).into_iter().any(|alias| {
        alias.eq_ignore_ascii_case(candidate)
            || alias
                .to_ascii_lowercase()
                .contains(&candidate.to_ascii_lowercase())
    })
}

fn find_local_target_container(
    pipe: &LocalPipeDocument,
    configured_host: Option<&str>,
) -> Result<Option<LocalContainerInfo>, CliError> {
    let explicit_container = pipe
        .instance
        .target_container
        .as_deref()
        .or(pipe.target.container.as_deref());
    let selector = pipe.target.selector.as_str();
    let containers = discover_local_containers(None).map_err(|error| {
        CliError::ConfigValidation(format!(
            "Failed to inspect local Docker containers for pipe '{}': {}",
            pipe.id, error
        ))
    })?;

    Ok(containers.into_iter().find(|container| {
        explicit_container
            .map(|name| matches_local_target_alias(container, name))
            .unwrap_or(false)
            || matches_local_target_alias(container, selector)
            || configured_host
                .filter(|host| !is_loopback_host(host))
                .map(|host| matches_local_target_alias(container, host))
                .unwrap_or(false)
    }))
}

fn remap_smtp_target_reference_for_container(
    mut target_adapter: PipeAdapterReference,
    target_selector: &str,
    container: &LocalContainerInfo,
) -> Result<PipeAdapterReference, CliError> {
    let Some(config) = target_adapter
        .config
        .as_mut()
        .and_then(|value| value.as_object_mut())
    else {
        return Ok(target_adapter);
    };

    let configured_host = config
        .get("host")
        .and_then(|value| value.as_str())
        .map(str::to_string);
    let configured_port = config
        .get("port")
        .and_then(|value| value.as_u64())
        .and_then(|value| u16::try_from(value).ok())
        .unwrap_or(587);

    if let Some(binding) = container.ports.iter().find(|port| {
        port.protocol == "tcp"
            && (port.container_port == configured_port || port.host_port == Some(configured_port))
    }) {
        if let Some(host_port) = binding.host_port {
            config.insert(
                "host".to_string(),
                serde_json::json!(docker_host_target(binding.host_ip.as_deref())),
            );
            config.insert("port".to_string(), serde_json::json!(host_port));
            return Ok(target_adapter);
        }
    }

    if configured_host
        .as_deref()
        .map(is_loopback_host)
        .unwrap_or(false)
    {
        return Err(CliError::ConfigValidation(format!(
            "Local SMTP target '{}' is configured for {}:{}, but the matching container '{}' does not publish that port to the host.\n\
             Publish the SMTP port in Docker Compose / stacker.yml or recreate the pipe with a host-reachable endpoint.",
            target_selector,
            configured_host.unwrap_or_else(|| "localhost".to_string()),
            configured_port,
            container.name
        )));
    }

    if let Some(address) = container.addresses.first() {
        config.insert("host".to_string(), serde_json::json!(address));
        return Ok(target_adapter);
    }

    Ok(target_adapter)
}

fn normalize_local_smtp_target_reference(
    pipe: &LocalPipeDocument,
    target_adapter: PipeAdapterReference,
) -> Result<PipeAdapterReference, CliError> {
    let configured_host = target_adapter
        .config
        .as_ref()
        .and_then(|value| value.get("host"))
        .and_then(|value| value.as_str())
        .map(str::to_string);

    let Some(container) = find_local_target_container(pipe, configured_host.as_deref())? else {
        return Ok(target_adapter);
    };

    remap_smtp_target_reference_for_container(target_adapter, &pipe.target.selector, &container)
}

async fn run_local_target_adapter(
    pipe: &LocalPipeDocument,
    payload: serde_json::Value,
) -> Result<serde_json::Value, CliError> {
    let target_adapter = pipe.instance.target_adapter.clone().ok_or_else(|| {
        CliError::ConfigValidation(format!(
            "Local trigger requires a target adapter. Pipe '{}' does not have one.",
            pipe.id
        ))
    })?;

    match target_adapter.code.as_str() {
        "smtp" => {
            let resolved_adapter = normalize_local_smtp_target_reference(pipe, target_adapter)?;
            let adapter = SmtpTargetAdapter::from_reference(resolved_adapter).map_err(|error| {
                CliError::ConfigValidation(format!(
                    "Invalid SMTP adapter configuration for local pipe '{}': {}",
                    pipe.id, error
                ))
            })?;

            adapter
                .deliver(PipeAdapterPayload::Json(payload))
                .await
                .map_err(|error| {
                    CliError::ConfigValidation(format!(
                        "Local SMTP delivery failed for pipe '{}': {}",
                        pipe.id, error
                    ))
                })
        }
        other => Err(CliError::ConfigValidation(format!(
            "Local trigger currently supports only the smtp target adapter. Pipe '{}' targets '{}'.",
            pipe.id, other
        ))),
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// stacker pipe activate — activate a pipe instance
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

pub struct PipeActivateCommand {
    pub pipe_id: String,
    pub trigger: String,
    pub poll_interval: u32,
    pub json: bool,
    pub deployment: Option<String>,
}

impl PipeActivateCommand {
    pub fn new(
        pipe_id: String,
        trigger: String,
        poll_interval: u32,
        json: bool,
        deployment: Option<String>,
    ) -> Self {
        Self {
            pipe_id,
            trigger,
            poll_interval,
            json,
            deployment,
        }
    }
}

impl CallableTrait for PipeActivateCommand {
    fn call(&self) -> Result<(), Box<dyn std::error::Error>> {
        let project_dir = std::env::current_dir().map_err(CliError::Io)?;
        if let Some(deploy_ctx) = resolve_local_deployment_context(&self.deployment, &project_dir)?
        {
            let prefix = mode_prefix(&deploy_ctx);
            let store = LocalPipeStore::new(&project_dir);
            let mut pipe = store.resolve(&self.pipe_id)?;
            pipe.set_status("active");
            let local_path = store.save(&pipe)?;

            if self.json {
                let mut output = serde_json::json!({
                    "local": true,
                    "pipe": pipe,
                    "file": local_path,
                    "note": "Local activate marks the pipe active in .stacker/pipes. Use pipe trigger for one-shot execution."
                });
                redact_sensitive_json(&mut output);
                println!("{}", serde_json::to_string_pretty(&output)?);
                return Ok(());
            }

            println!("\n  {}✓ Local pipe '{}' marked active", prefix, pipe.id);
            println!("  File: {}", local_path.display());
            println!(
                "  Note: local background listeners are not implemented yet for file-backed pipes."
            );
            println!("  Test now: {}", example_local_trigger_command(&pipe.id));
            return Ok(());
        }

        let ctx = CliRuntime::new("pipe activate")?;
        let hash = resolve_deployment_hash(&self.deployment, &ctx)?;
        ensure_remote_pipe_command_capability(&ctx, &hash)?;

        // Fetch pipe instance details to get source/target info
        let pb = progress::spinner("Fetching pipe details...");
        let pipe = ctx
            .block_on(ctx.client.get_pipe_instance(&self.pipe_id))
            .map_err(|e| {
                progress::finish_error(&pb, "Failed");
                e
            })?
            .ok_or_else(|| {
                CliError::ConfigValidation(format!("Pipe instance '{}' not found", self.pipe_id))
            })?;
        progress::finish_success(&pb, "Pipe found");

        // Get template info for endpoint details (if linked)
        let (source_endpoint, source_method, target_endpoint, target_method, field_mapping) =
            if let Some(ref tid) = pipe.template_id {
                let templates = ctx.block_on(ctx.client.list_pipe_templates(None, None))?;
                if let Some(tmpl) = templates.iter().find(|t| &t.id == tid) {
                    (
                        tmpl.source_endpoint["path"]
                            .as_str()
                            .unwrap_or("/")
                            .to_string(),
                        tmpl.source_endpoint["method"]
                            .as_str()
                            .unwrap_or("GET")
                            .to_string(),
                        tmpl.target_endpoint["path"]
                            .as_str()
                            .unwrap_or("/")
                            .to_string(),
                        tmpl.target_endpoint["method"]
                            .as_str()
                            .unwrap_or("POST")
                            .to_string(),
                        pipe.field_mapping_override
                            .clone()
                            .unwrap_or(tmpl.field_mapping.clone()),
                    )
                } else {
                    (
                        "/".to_string(),
                        "GET".to_string(),
                        "/".to_string(),
                        "POST".to_string(),
                        serde_json::json!({}),
                    )
                }
            } else {
                (
                    "/".to_string(),
                    "GET".to_string(),
                    "/".to_string(),
                    "POST".to_string(),
                    pipe.field_mapping_override
                        .clone()
                        .unwrap_or(serde_json::json!({})),
                )
            };

        // 1. Update status to "active" via API
        let pb = progress::spinner("Setting pipe status to active...");
        ctx.block_on(ctx.client.update_pipe_status(&self.pipe_id, "active"))
            .map_err(|e| {
                progress::finish_error(&pb, "Status update failed");
                e
            })?;
        progress::finish_success(&pb, "Status: active");

        // 2. Send activate_pipe command to agent
        let params = serde_json::json!({
            "pipe_instance_id": self.pipe_id,
            "source_adapter": pipe.source_adapter.clone(),
            "source_container": pipe.source_container.clone(),
            "source_endpoint": source_endpoint,
            "source_method": source_method,
            "target_adapter": pipe.target_adapter.clone(),
            "target_container": pipe.target_container.clone(),
            "target_url": pipe.target_url.clone(),
            "target_endpoint": target_endpoint,
            "target_method": target_method,
            "field_mapping": field_mapping,
            "trigger_type": self.trigger,
            "poll_interval_secs": self.poll_interval,
        });

        let request = AgentEnqueueRequest::new(&hash, "activate_pipe").with_raw_parameters(params);

        let info = run_agent_command(
            &ctx,
            &request,
            "Activating pipe on agent",
            PROBE_TIMEOUT_SECS,
        )?;

        print_command_result(&info, self.json);

        if !self.json && info.status == "completed" {
            println!("\n  ✓ Pipe '{}' is now active", self.pipe_id);
            println!("  Trigger type: {}", self.trigger);
            if self.trigger == "poll" {
                println!("  Poll interval: {}s", self.poll_interval);
            }
        }

        Ok(())
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// stacker pipe deactivate — stop a pipe
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

pub struct PipeDeactivateCommand {
    pub pipe_id: String,
    pub json: bool,
    pub deployment: Option<String>,
}

impl PipeDeactivateCommand {
    pub fn new(pipe_id: String, json: bool, deployment: Option<String>) -> Self {
        Self {
            pipe_id,
            json,
            deployment,
        }
    }
}

impl CallableTrait for PipeDeactivateCommand {
    fn call(&self) -> Result<(), Box<dyn std::error::Error>> {
        let project_dir = std::env::current_dir().map_err(CliError::Io)?;
        if let Some(deploy_ctx) = resolve_local_deployment_context(&self.deployment, &project_dir)?
        {
            let prefix = mode_prefix(&deploy_ctx);
            let store = LocalPipeStore::new(&project_dir);
            let mut pipe = store.resolve(&self.pipe_id)?;
            pipe.set_status("paused");
            let local_path = store.save(&pipe)?;

            if self.json {
                let mut output = serde_json::json!({
                    "local": true,
                    "pipe": pipe,
                    "file": local_path
                });
                redact_sensitive_json(&mut output);
                println!("{}", serde_json::to_string_pretty(&output)?);
                return Ok(());
            }

            println!("\n  {}✓ Local pipe '{}' paused", prefix, pipe.id);
            println!("  File: {}", local_path.display());
            return Ok(());
        }

        let ctx = CliRuntime::new("pipe deactivate")?;
        let hash = resolve_deployment_hash(&self.deployment, &ctx)?;
        ensure_remote_pipe_command_capability(&ctx, &hash)?;

        // 1. Update status to "paused" via API
        let pb = progress::spinner("Setting pipe status to paused...");
        ctx.block_on(ctx.client.update_pipe_status(&self.pipe_id, "paused"))
            .map_err(|e| {
                progress::finish_error(&pb, "Status update failed");
                e
            })?;
        progress::finish_success(&pb, "Status: paused");

        // 2. Send deactivate_pipe command to agent
        let params = serde_json::json!({
            "pipe_instance_id": self.pipe_id,
        });

        let request =
            AgentEnqueueRequest::new(&hash, "deactivate_pipe").with_raw_parameters(params);

        let info = run_agent_command(
            &ctx,
            &request,
            "Deactivating pipe on agent",
            PROBE_TIMEOUT_SECS,
        )?;

        print_command_result(&info, self.json);

        if !self.json && info.status == "completed" {
            println!("\n  ✓ Pipe '{}' deactivated", self.pipe_id);
        }

        Ok(())
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// stacker pipe trigger — one-shot pipe execution
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

pub struct PipeTriggerCommand {
    pub pipe_id: String,
    pub data: Option<String>,
    pub json: bool,
    pub deployment: Option<String>,
}

impl PipeTriggerCommand {
    pub fn new(
        pipe_id: String,
        data: Option<String>,
        json: bool,
        deployment: Option<String>,
    ) -> Self {
        Self {
            pipe_id,
            data,
            json,
            deployment,
        }
    }
}

impl CallableTrait for PipeTriggerCommand {
    fn call(&self) -> Result<(), Box<dyn std::error::Error>> {
        let project_dir = std::env::current_dir().map_err(CliError::Io)?;
        let deploy_ctx = if let Some(local_ctx) =
            resolve_local_deployment_context(&self.deployment, &project_dir)?
        {
            local_ctx
        } else {
            let ctx = CliRuntime::new("pipe trigger")?;
            resolve_deployment_context(&self.deployment, &ctx)?
        };
        let prefix = mode_prefix(&deploy_ctx);

        let input_data = match &self.data {
            Some(raw) => {
                let parsed: serde_json::Value = serde_json::from_str(raw)
                    .map_err(|e| CliError::ConfigValidation(format!("Invalid JSON data: {}", e)))?;
                Some(parsed)
            }
            None => None,
        };

        if deploy_ctx.is_local() {
            let store = LocalPipeStore::new(&project_dir);
            let mut pipe = store.resolve(&self.pipe_id)?;
            let source_data = input_data.ok_or_else(|| {
                CliError::ConfigValidation(format!(
                    "Local trigger requires --data '<json>' for now.\nExample: {}",
                    example_local_trigger_command(&pipe.id)
                ))
            })?;
            let effective_payload = build_local_trigger_payload(&pipe, &source_data);
            let pb = progress::spinner(&format!(
                "{}Triggering pipe '{}' locally...",
                prefix, self.pipe_id
            ));
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| {
                    progress::finish_error(&pb, "Local runtime initialization failed");
                    CliError::ConfigValidation(format!(
                        "Cannot start local pipe runtime: {}",
                        error
                    ))
                })?;

            match runtime.block_on(run_local_target_adapter(&pipe, effective_payload.clone())) {
                Ok(result) => {
                    pipe.record_trigger_success();
                    let local_path = store.save(&pipe)?;
                    progress::finish_success(&pb, &format!("{}Pipe triggered locally", prefix));
                    if self.json {
                        let mut output = serde_json::json!({
                            "status": "completed",
                            "local": true,
                            "pipe_id": pipe.id,
                            "file": local_path,
                            "input_data": source_data,
                            "effective_payload": effective_payload,
                            "result": result,
                        });
                        redact_sensitive_json(&mut output);
                        println!("{}", serde_json::to_string_pretty(&output)?);
                    } else {
                        println!("\n  {}✓ Pipe '{}' triggered locally", prefix, pipe.id);
                        println!("  File: {}", local_path.display());
                        println!(
                            "  Trigger count: {}  Errors: {}",
                            pipe.instance.trigger_count, pipe.instance.error_count
                        );
                    }
                }
                Err(error) => {
                    pipe.record_trigger_failure();
                    let _ = store.save(&pipe);
                    progress::finish_error(&pb, "Local trigger failed");
                    return Err(Box::new(error));
                }
            }

            return Ok(());
        }

        let ctx = CliRuntime::new("pipe trigger")?;
        let hash = match &deploy_ctx {
            DeploymentContext::Remote(h) => h.clone(),
            _ => unreachable!(),
        };
        ensure_remote_pipe_command_capability(&ctx, &hash)?;

        let params = serde_json::json!({
            "pipe_instance_id": self.pipe_id,
            "input_data": input_data,
        });

        let request = AgentEnqueueRequest::new(&hash, "trigger_pipe").with_raw_parameters(params);

        let info = run_agent_command(&ctx, &request, "Triggering pipe", PROBE_TIMEOUT_SECS)?;

        print_command_result(&info, self.json);

        if !self.json {
            if info.status == "completed" {
                if let Some(ref result) = info.result {
                    let success = result["success"].as_bool().unwrap_or(false);
                    if success {
                        println!("\n  ✓ Pipe '{}' triggered successfully", self.pipe_id);
                    } else {
                        let error = result["error"].as_str().unwrap_or("unknown error");
                        eprintln!("\n  ✗ Pipe trigger failed: {}", error);
                    }
                }
            }
        }

        Ok(())
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// stacker pipe history — show execution history
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

pub struct PipeHistoryCommand {
    pub instance_id: String,
    pub limit: i64,
    pub json: bool,
    pub deployment: Option<String>,
}

impl PipeHistoryCommand {
    pub fn new(instance_id: String, limit: i64, json: bool, deployment: Option<String>) -> Self {
        Self {
            instance_id,
            limit,
            json,
            deployment,
        }
    }
}

impl CallableTrait for PipeHistoryCommand {
    fn call(&self) -> Result<(), Box<dyn std::error::Error>> {
        let ctx = CliRuntime::new("pipe history")?;
        let deploy_ctx = resolve_deployment_context(&self.deployment, &ctx)?;
        let _prefix = mode_prefix(&deploy_ctx);

        let pb = progress::spinner("Fetching execution history...");
        let executions = ctx
            .block_on(
                ctx.client
                    .list_pipe_executions(&self.instance_id, self.limit, 0),
            )
            .map_err(|e| {
                progress::finish_error(&pb, "Failed to fetch history");
                e
            })?;
        progress::finish_success(&pb, &format!("{} execution(s) found", executions.len()));

        if executions.is_empty() {
            println!(
                "No executions recorded for pipe instance '{}'.",
                self.instance_id
            );
            println!(
                "Use 'stacker pipe trigger {}' to execute the pipe.",
                self.instance_id
            );
            return Ok(());
        }

        if self.json {
            println!("{}", serde_json::to_string_pretty(&executions)?);
            return Ok(());
        }

        println!(
            "\n{:<38} {:<10} {:<10} {:>10} {:<22} {}",
            "EXECUTION ID", "TRIGGER", "STATUS", "DURATION", "STARTED", "ERROR"
        );
        println!("{}", "─".repeat(110));

        for exec in &executions {
            let status_icon = match exec.status.as_str() {
                "success" => "✓ success",
                "failed" => "✗ failed",
                "running" => "⟳ running",
                _ => &exec.status,
            };
            let duration = exec
                .duration_ms
                .map(|ms| format!("{}ms", ms))
                .unwrap_or_else(|| "-".to_string());
            let error = exec.error.as_deref().unwrap_or("");

            println!(
                "{:<38} {:<10} {:<10} {:>10} {:<22} {}",
                &exec.id,
                truncate_str(&exec.trigger_type, 9),
                status_icon,
                duration,
                truncate_str(&exec.started_at, 21),
                truncate_str(error, 30),
            );
        }

        println!("\n{} execution(s) shown.", executions.len());
        Ok(())
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// stacker pipe replay — replay a previous execution
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

pub struct PipeReplayCommand {
    pub execution_id: String,
    pub json: bool,
    pub deployment: Option<String>,
}

impl PipeReplayCommand {
    pub fn new(execution_id: String, json: bool, deployment: Option<String>) -> Self {
        Self {
            execution_id,
            json,
            deployment,
        }
    }
}

impl CallableTrait for PipeReplayCommand {
    fn call(&self) -> Result<(), Box<dyn std::error::Error>> {
        let ctx = CliRuntime::new("pipe replay")?;
        let _hash = resolve_deployment_hash(&self.deployment, &ctx)?;

        let pb = progress::spinner(&format!("Replaying execution {}...", &self.execution_id));
        let replay = ctx
            .block_on(ctx.client.replay_pipe_execution(&self.execution_id))
            .map_err(|e| {
                progress::finish_error(&pb, "Replay failed");
                e
            })?;
        progress::finish_success(&pb, "Replay initiated");

        if self.json {
            println!("{}", serde_json::to_string_pretty(&replay)?);
            return Ok(());
        }

        println!("\n  Replay execution: {}", replay.execution_id);
        println!("  Replaying from:   {}", replay.replay_of);
        if let Some(ref cmd_id) = replay.command_id {
            println!("  Command ID:       {}", cmd_id);
            println!("\n  Replay enqueued. Use 'stacker pipe history' to check results.");
        } else {
            println!("  Status:           {}", replay.status);
            println!("  (command not enqueued — check server logs)");
        }

        Ok(())
    }
}

pub struct PipeDeployCommand {
    pub instance_id: String,
    pub deployment_hash: String,
    pub json: bool,
}

impl PipeDeployCommand {
    pub fn new(instance_id: String, deployment_hash: String, json: bool) -> Self {
        Self {
            instance_id,
            deployment_hash,
            json,
        }
    }
}

impl CallableTrait for PipeDeployCommand {
    fn call(&self) -> Result<(), Box<dyn std::error::Error>> {
        let ctx = CliRuntime::new("pipe deploy")?;
        let project_dir = std::env::current_dir().map_err(CliError::Io)?;
        let store = LocalPipeStore::new(&project_dir);
        let local_pipe = store.resolve(&self.instance_id)?;
        let template_request = local_pipe.to_template_request();

        let template_pb = progress::spinner(&format!(
            "Resolving remote template for {} → {}...",
            &local_pipe.id, &self.deployment_hash
        ));
        let templates = ctx
            .block_on(ctx.client.list_pipe_templates(
                Some(&template_request.source_app_type),
                Some(&template_request.target_app_type),
            ))
            .map_err(|e| {
                progress::finish_error(&template_pb, "Template lookup failed");
                e
            })?;
        let template =
            match find_reusable_pipe_template(&templates, &template_request).map_err(|e| {
                progress::finish_error(&template_pb, "Template promotion failed");
                e
            })? {
                Some(existing) => {
                    progress::finish_success(&template_pb, "Using existing template");
                    existing
                }
                None => {
                    let created = ctx
                        .block_on(ctx.client.create_pipe_template(&template_request))
                        .map_err(|e| {
                            progress::finish_error(&template_pb, "Template promotion failed");
                            e
                        })?;
                    progress::finish_success(&template_pb, "Template promoted");
                    created
                }
            };

        let instance_request =
            local_pipe.to_instance_request(self.deployment_hash.clone(), template.id.clone());

        let instance_pb = progress::spinner("Creating remote pipe instance...");
        let remote = ctx
            .block_on(ctx.client.create_pipe_instance(&instance_request))
            .map_err(|e| {
                progress::finish_error(&instance_pb, "Remote instance creation failed");
                e
            })?;
        progress::finish_success(&instance_pb, "Pipe deployed to remote");

        let mut updated_pipe = local_pipe.clone();
        updated_pipe.record_promotion(&self.deployment_hash, &template.id, &remote.id);
        let local_path = store.save(&updated_pipe)?;

        if self.json {
            let mut output = serde_json::json!({
                "local_pipe": updated_pipe,
                "remote_template_id": template.id,
                "remote_instance": remote,
            });
            redact_sensitive_json(&mut output);
            println!("{}", serde_json::to_string_pretty(&output)?);
            return Ok(());
        }

        println!("\n  ✓ Local pipe promoted to remote deployment");
        println!("  Local pipe ID:       {}", updated_pipe.id);
        println!("  Local file:          {}", local_path.display());
        println!("  Remote template ID:  {}", template.id);
        println!("  Remote instance ID:  {}", remote.id);
        println!("  Deployment:          {}", &remote.deployment_hash);
        println!("  Source:              {}", remote.source_container);
        if let Some(ref t) = remote.target_container {
            println!("  Target:              {}", t);
        } else if let Some(ref adapter) = remote.target_adapter {
            println!("  Target:              {} adapter", adapter.code);
        }
        println!("  Status:              {}", remote.status);
        println!(
            "\n  Use 'stacker pipe activate {}' to start the remote pipe.",
            remote.id
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::field_matcher::{DeterministicFieldMatcher, FieldMatcher};
    use serde_json::json;

    fn sample_local_smtp_pipe(mapping: serde_json::Value) -> LocalPipeDocument {
        LocalPipeDocument::draft(NewLocalPipeDocument {
            name: "status-panel-web-to-smtp".to_string(),
            source: LocalPipeBinding {
                selector: "status-panel-web".to_string(),
                container: Some("status-panel-web".to_string()),
                adapter: None,
                method: "POST".to_string(),
                path: "/contact".to_string(),
                fields: vec![
                    "name".to_string(),
                    "email".to_string(),
                    "subject".to_string(),
                    "message".to_string(),
                ],
            },
            target: LocalPipeBinding {
                selector: "smtp".to_string(),
                container: None,
                adapter: Some(
                    PipeAdapterReference::new("smtp")
                        .with_role(PipeAdapterRole::Target)
                        .with_config(json!({
                            "host": "smtp",
                            "port": 1025,
                            "from": "info@example.com",
                            "to": ["ops@example.com"],
                            "tls": false
                        })),
                ),
                method: "SEND".to_string(),
                path: "adapter:smtp".to_string(),
                fields: vec![
                    "from_email".to_string(),
                    "reply_to_email".to_string(),
                    "subject".to_string(),
                    "body_text".to_string(),
                    "body_html".to_string(),
                ],
            },
            template: LocalPipeTemplate {
                description: Some("POST /contact -> SEND adapter:smtp".to_string()),
                source_app_type: "status-panel-web".to_string(),
                source_endpoint: json!({"method":"POST","path":"/contact"}),
                target_app_type: "smtp".to_string(),
                target_endpoint: json!({"adapter":"smtp","mode":"adapter"}),
                target_external_url: None,
                field_mapping: mapping,
                config: Some(json!({"retry_count": 3})),
                is_public: false,
            },
            instance: LocalPipeInstance {
                source_adapter: None,
                source_container: "status-panel-web".to_string(),
                target_adapter: Some(
                    PipeAdapterReference::new("smtp")
                        .with_role(PipeAdapterRole::Target)
                        .with_config(json!({
                            "host": "smtp",
                            "port": 1025,
                            "from": "info@example.com",
                            "to": ["ops@example.com"],
                            "tls": false
                        })),
                ),
                target_container: None,
                target_url: None,
                field_mapping_override: None,
                config_override: None,
                trigger_count: 0,
                error_count: 0,
                last_triggered_at: None,
            },
            diagnostics: LocalPipeDiagnostics::default(),
        })
        .expect("sample local pipe should be valid")
    }

    fn sample_smtp_container(host_port: Option<u16>) -> LocalContainerInfo {
        LocalContainerInfo {
            id: "abc123".to_string(),
            name: "status-smtp-1".to_string(),
            image: "mailpit/mailpit:latest".to_string(),
            network: "status_default".to_string(),
            addresses: vec!["172.18.0.30".to_string()],
            ports: vec![LocalPortBinding {
                container_port: 1025,
                host_port,
                host_ip: Some("0.0.0.0".to_string()),
                protocol: "tcp".to_string(),
            }],
            status: "running".to_string(),
            env: BTreeMap::new(),
            labels: BTreeMap::from([(
                "com.docker.compose.service".to_string(),
                "smtp".to_string(),
            )]),
        }
    }

    fn sample_exim_container(host_port: Option<u16>) -> LocalContainerInfo {
        LocalContainerInfo {
            id: "def456".to_string(),
            name: "status-smtp-1".to_string(),
            image: "exim:latest".to_string(),
            network: "status_default".to_string(),
            addresses: vec!["172.18.0.31".to_string()],
            ports: vec![LocalPortBinding {
                container_port: 25,
                host_port,
                host_ip: Some("0.0.0.0".to_string()),
                protocol: "tcp".to_string(),
            }],
            status: "running".to_string(),
            env: BTreeMap::new(),
            labels: BTreeMap::from([(
                "com.docker.compose.service".to_string(),
                "smtp".to_string(),
            )]),
        }
    }

    fn sample_template_request() -> CreatePipeTemplateApiRequest {
        sample_local_smtp_pipe(json!({"subject": "$.subject"})).to_template_request()
    }

    fn sample_template_info() -> PipeTemplateInfo {
        let request = sample_template_request();
        PipeTemplateInfo {
            id: "tmpl-1".to_string(),
            name: request.name,
            description: request.description,
            source_app_type: request.source_app_type,
            source_endpoint: request.source_endpoint,
            target_app_type: request.target_app_type,
            target_endpoint: request.target_endpoint,
            target_external_url: request.target_external_url,
            field_mapping: request.field_mapping,
            config: request.config,
            is_public: request.is_public,
            created_by: "user-1".to_string(),
            created_at: "2026-05-23T00:00:00Z".to_string(),
            updated_at: "2026-05-23T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn test_find_reusable_pipe_template_reuses_identical_template() {
        let request = sample_template_request();
        let existing = sample_template_info();

        let resolved = find_reusable_pipe_template(&[existing.clone()], &request)
            .expect("lookup should succeed");

        let resolved = resolved.expect("template should be reused");
        assert_eq!(resolved.id, existing.id);
        assert_eq!(resolved.name, existing.name);
    }

    #[test]
    fn test_find_reusable_pipe_template_rejects_conflicting_template() {
        let request = sample_template_request();
        let mut existing = sample_template_info();
        existing.target_endpoint = json!({"adapter":"smtp","mode":"adapter","variant":"other"});

        let error = find_reusable_pipe_template(&[existing], &request)
            .expect_err("conflicting template should be rejected");

        assert!(
            error
                .to_string()
                .contains("already exists with a different definition"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn test_smart_field_match_exact() {
        let matcher = DeterministicFieldMatcher;
        let src = vec!["email".to_string(), "name".to_string(), "id".to_string()];
        let tgt = vec!["email".to_string(), "name".to_string()];
        let result = matcher.match_fields(&src, &tgt, None);
        let map = result.mapping.as_object().unwrap();
        assert_eq!(map["email"], "$.email");
        assert_eq!(map["name"], "$.name");
    }

    #[test]
    fn test_smart_field_match_case_insensitive() {
        let matcher = DeterministicFieldMatcher;
        let src = vec!["Email".to_string(), "UserName".to_string()];
        let tgt = vec!["email".to_string(), "username".to_string()];
        let result = matcher.match_fields(&src, &tgt, None);
        let map = result.mapping.as_object().unwrap();
        assert_eq!(map["email"], "$.Email");
        assert_eq!(map["username"], "$.UserName");
    }

    #[test]
    fn test_smart_field_match_semantic_aliases() {
        let matcher = DeterministicFieldMatcher;
        let src = vec!["user_email".to_string(), "display_name".to_string()];
        let tgt = vec!["email".to_string(), "name".to_string()];
        let result = matcher.match_fields(&src, &tgt, None);
        let map = result.mapping.as_object().unwrap();
        assert_eq!(map["email"], "$.user_email");
        assert_eq!(map["name"], "$.display_name");
    }

    #[test]
    fn test_smart_field_match_type_aware_suffix() {
        let matcher = DeterministicFieldMatcher;
        let src = vec!["author_id".to_string(), "post_id".to_string()];
        let tgt = vec!["user_id".to_string()];
        let sample = json!({"author_id": 42, "post_id": 1});
        let result = matcher.match_fields(&src, &tgt, Some(&sample));
        let map = result.mapping.as_object().unwrap();
        assert_eq!(map["user_id"], "$.author_id");
    }

    #[test]
    fn test_smart_field_match_no_matches() {
        let matcher = DeterministicFieldMatcher;
        let src = vec!["foo".to_string()];
        let tgt = vec!["bar".to_string()];
        let result = matcher.match_fields(&src, &tgt, None);
        let map = result.mapping.as_object().unwrap();
        assert!(map.is_empty());
    }

    #[test]
    fn test_smart_field_match_mixed_strategies() {
        let matcher = DeterministicFieldMatcher;
        let src = vec![
            "email".to_string(),
            "display_name".to_string(),
            "Phone".to_string(),
        ];
        let tgt = vec![
            "email".to_string(),
            "name".to_string(),
            "phone".to_string(),
            "unknown".to_string(),
        ];
        let result = matcher.match_fields(&src, &tgt, None);
        let map = result.mapping.as_object().unwrap();
        assert_eq!(map.len(), 3);
        assert_eq!(map["email"], "$.email");
        assert_eq!(map["name"], "$.display_name");
        assert_eq!(map["phone"], "$.Phone");
        assert!(!map.contains_key("unknown"));
    }

    #[test]
    fn test_deployment_context_local_is_local() {
        let ctx = DeploymentContext::Local;
        assert!(ctx.is_local());
        assert!(ctx.hash().is_none());
    }

    #[test]
    fn test_deployment_context_remote_has_hash() {
        let ctx = DeploymentContext::Remote("abc123".to_string());
        assert!(!ctx.is_local());
        assert_eq!(ctx.hash(), Some("abc123"));
    }

    #[test]
    fn test_mode_prefix_local() {
        let ctx = DeploymentContext::Local;
        let prefix = mode_prefix(&ctx);
        assert!(prefix.contains("[local]"));
        assert!(!prefix.is_empty());
    }

    #[test]
    fn test_mode_prefix_remote_empty() {
        let ctx = DeploymentContext::Remote("hash".to_string());
        let prefix = mode_prefix(&ctx);
        assert!(prefix.is_empty());
    }

    #[test]
    fn test_apply_field_mapping_supports_nested_paths() {
        let mapped = apply_field_mapping(
            &json!({
                "contact": {
                    "email": "person@example.com"
                },
                "message": "hello"
            }),
            &json!({
                "reply_to_email": "$.contact.email",
                "body_text": "$.message"
            }),
        );

        assert_eq!(
            mapped,
            json!({
                "reply_to_email": "person@example.com",
                "body_text": "hello"
            })
        );
    }

    #[test]
    fn test_build_local_trigger_payload_applies_smtp_defaults() {
        let pipe = sample_local_smtp_pipe(json!({
            "subject": "$.subject"
        }));

        let payload = build_local_trigger_payload(
            &pipe,
            &json!({
                "name": "Alice",
                "email": "alice@example.com",
                "subject": "Status question",
                "message": "Hello from the contact form"
            }),
        );

        assert_eq!(
            payload,
            json!({
                "subject": "Status question",
                "from_email": "alice@example.com",
                "reply_to_email": "alice@example.com",
                "body_text": "Hello from the contact form"
            })
        );
    }

    #[test]
    fn test_example_local_trigger_command_uses_expected_shape() {
        let command = example_local_trigger_command("pipe-123");
        assert!(command.contains("stacker pipe trigger pipe-123 --data"));
        assert!(command.contains("\"email\":\"person@example.com\""));
    }

    #[test]
    fn test_remap_smtp_target_reference_prefers_published_host_port() {
        let pipe = sample_local_smtp_pipe(json!({}));
        let adapter = pipe.instance.target_adapter.clone().expect("smtp adapter");
        let remapped = remap_smtp_target_reference_for_container(
            adapter,
            "smtp",
            &sample_smtp_container(Some(11025)),
        )
        .expect("smtp target should be remapped");
        let config = remapped.config.expect("smtp config");

        assert_eq!(config["host"], serde_json::json!("127.0.0.1"));
        assert_eq!(config["port"], serde_json::json!(11025));
    }

    #[test]
    fn test_remap_smtp_target_reference_accepts_host_published_port_mapping() {
        let pipe = sample_local_smtp_pipe(json!({}));
        let adapter = pipe.instance.target_adapter.clone().expect("smtp adapter");
        let remapped = remap_smtp_target_reference_for_container(
            adapter,
            "smtp",
            &sample_exim_container(Some(1025)),
        )
        .expect("smtp target should use the published host port");
        let config = remapped.config.expect("smtp config");

        assert_eq!(config["host"], serde_json::json!("127.0.0.1"));
        assert_eq!(config["port"], serde_json::json!(1025));
    }

    #[test]
    fn test_remap_smtp_target_reference_rejects_unpublished_localhost_target() {
        let mut pipe = sample_local_smtp_pipe(json!({}));
        if let Some(adapter) = pipe.instance.target_adapter.as_mut() {
            if let Some(config) = adapter
                .config
                .as_mut()
                .and_then(|value| value.as_object_mut())
            {
                config.insert("host".to_string(), serde_json::json!("localhost"));
            }
        }

        let adapter = pipe.instance.target_adapter.clone().expect("smtp adapter");
        let error = remap_smtp_target_reference_for_container(
            adapter,
            "smtp",
            &sample_smtp_container(None),
        )
        .expect_err("localhost target should require a published port");

        let message = error.to_string();
        assert!(message.contains("does not publish that port to the host"));
    }

    #[test]
    fn test_deployment_context_equality() {
        assert_eq!(DeploymentContext::Local, DeploymentContext::Local);
        assert_eq!(
            DeploymentContext::Remote("a".to_string()),
            DeploymentContext::Remote("a".to_string())
        );
        assert_ne!(
            DeploymentContext::Local,
            DeploymentContext::Remote("a".to_string())
        );
    }

    #[test]
    fn test_pipe_deploy_command_new() {
        let cmd = PipeDeployCommand::new("inst-123".to_string(), "deploy-hash".to_string(), true);
        assert_eq!(cmd.instance_id, "inst-123");
        assert_eq!(cmd.deployment_hash, "deploy-hash");
        assert!(cmd.json);
    }

    #[test]
    fn test_pipe_scan_request_local_filter_from_legacy() {
        let request = PipeScanRequest::Legacy {
            selector: Some("upload".to_string()),
        };
        assert_eq!(request.local_filter().unwrap(), Some("upload"));
    }

    #[test]
    fn test_pipe_scan_request_local_filter_accepts_legacy_without_selector() {
        let request = PipeScanRequest::Legacy { selector: None };
        assert_eq!(request.local_filter().unwrap(), None);
    }

    #[test]
    fn test_pipe_scan_request_local_filter_from_containers() {
        let request = PipeScanRequest::Containers {
            filter: Some("upload".to_string()),
        };
        assert_eq!(request.local_filter().unwrap(), Some("upload"));
    }

    #[test]
    fn test_pipe_scan_request_local_filter_rejects_app_mode() {
        let request = PipeScanRequest::App {
            app: "website".to_string(),
            container: None,
        };
        assert!(request.local_filter().is_err());
    }

    #[test]
    fn test_pipe_scan_request_remote_selector_from_app_mode() {
        let request = PipeScanRequest::App {
            app: "website".to_string(),
            container: Some("website-web-1".to_string()),
        };
        assert_eq!(
            request.remote_selector().unwrap(),
            ("website", Some("website-web-1"))
        );
    }

    #[test]
    fn test_pipe_scan_request_remote_selector_from_legacy() {
        let request = PipeScanRequest::Legacy {
            selector: Some("website".to_string()),
        };
        assert_eq!(request.remote_selector().unwrap(), ("website", None));
    }

    #[test]
    fn test_pipe_scan_request_remote_selector_rejects_legacy_without_selector() {
        let request = PipeScanRequest::Legacy { selector: None };
        assert!(request.remote_selector().is_err());
    }

    #[test]
    fn test_pipe_scan_request_remote_selector_rejects_containers_mode() {
        let request = PipeScanRequest::Containers { filter: None };
        assert!(request.remote_selector().is_err());
    }

    #[test]
    fn test_local_http_candidate_urls_include_internal_and_host_ports() {
        let container = LocalContainerInfo {
            id: "abc".to_string(),
            name: "local-device-api-1".to_string(),
            image: "example/device-api:local".to_string(),
            network: "app-network".to_string(),
            addresses: vec!["172.18.0.20".to_string()],
            ports: vec![
                LocalPortBinding {
                    container_port: 5050,
                    host_port: None,
                    host_ip: None,
                    protocol: "tcp".to_string(),
                },
                LocalPortBinding {
                    container_port: 8080,
                    host_port: Some(18080),
                    host_ip: Some("::".to_string()),
                    protocol: "tcp".to_string(),
                },
            ],
            status: "running".to_string(),
            env: std::collections::BTreeMap::new(),
            labels: std::collections::BTreeMap::new(),
        };

        let urls = local_http_candidate_urls(&container);
        assert!(urls.contains(&"http://172.18.0.20:5050".to_string()));
        assert!(urls.contains(&"http://[::1]:18080".to_string()));
    }

    #[test]
    fn test_parse_local_container_inspect_extracts_ports_and_env() {
        let inspect = json!({
            "Id": "abc123",
            "Name": "/local-postgres-1",
            "Config": {
                "Image": "postgres:17-alpine",
                "Env": ["POSTGRES_USER=postgres", "POSTGRES_DB=app"],
                "Labels": {"com.docker.compose.service": "database"},
                "ExposedPorts": {"5432/tcp": {}}
            },
            "State": {"Status": "running"},
            "NetworkSettings": {
                "Networks": {
                    "app-network": {
                        "IPAddress": "172.18.0.10"
                    }
                },
                "Ports": {
                    "5432/tcp": null
                }
            }
        });

        let container = parse_local_container_inspect(&inspect).unwrap();
        assert_eq!(container.name, "local-postgres-1");
        assert_eq!(container.network, "app-network");
        assert_eq!(container.addresses, vec!["172.18.0.10".to_string()]);
        assert_eq!(
            container.env.get("POSTGRES_USER").map(String::as_str),
            Some("postgres")
        );
        assert_eq!(container.ports[0].container_port, 5432);
        assert_eq!(container.ports[0].host_port, None);
    }

    #[test]
    fn test_local_resource_probe_plan_detects_common_services() {
        let postgres = LocalContainerInfo {
            id: "pg".to_string(),
            name: "local-postgres-1".to_string(),
            image: "postgres:17-alpine".to_string(),
            network: "app-network".to_string(),
            addresses: vec!["172.18.0.10".to_string()],
            ports: vec![LocalPortBinding {
                container_port: 5432,
                host_port: None,
                host_ip: None,
                protocol: "tcp".to_string(),
            }],
            status: "running".to_string(),
            env: std::collections::BTreeMap::new(),
            labels: std::collections::BTreeMap::new(),
        };
        let rabbit = LocalContainerInfo {
            id: "rmq".to_string(),
            name: "local-rabbitmq-1".to_string(),
            image: "rabbitmq:3-management".to_string(),
            network: "app-network".to_string(),
            addresses: vec!["172.18.0.11".to_string()],
            ports: vec![LocalPortBinding {
                container_port: 5672,
                host_port: None,
                host_ip: None,
                protocol: "tcp".to_string(),
            }],
            status: "running".to_string(),
            env: std::collections::BTreeMap::new(),
            labels: std::collections::BTreeMap::new(),
        };

        let pg_plan = local_resource_probe_plan(&postgres);
        let rabbit_plan = local_resource_probe_plan(&rabbit);

        assert!(pg_plan.iter().any(|item| item == "postgres"));
        assert!(rabbit_plan.iter().any(|item| item == "rabbitmq"));
    }

    #[test]
    fn test_build_local_probe_report_emits_progress_for_each_container() {
        let containers = vec![
            LocalContainerInfo {
                id: "one".to_string(),
                name: "local-api-1".to_string(),
                image: "example/api:latest".to_string(),
                network: "app-network".to_string(),
                addresses: vec![],
                ports: vec![],
                status: "running".to_string(),
                env: std::collections::BTreeMap::new(),
                labels: std::collections::BTreeMap::new(),
            },
            LocalContainerInfo {
                id: "two".to_string(),
                name: "local-web-1".to_string(),
                image: "example/web:latest".to_string(),
                network: "app-network".to_string(),
                addresses: vec![],
                ports: vec![],
                status: "running".to_string(),
                env: std::collections::BTreeMap::new(),
                labels: std::collections::BTreeMap::new(),
            },
        ];

        let mut seen = Vec::new();
        let _ = build_local_probe_report_with_progress(
            "local",
            &containers,
            &[],
            false,
            |current, total, container| {
                seen.push((current, total, container.to_string()));
            },
        );

        assert_eq!(
            seen,
            vec![
                (1, 2, "local-api-1".to_string()),
                (2, 2, "local-web-1".to_string())
            ]
        );
    }

    #[test]
    fn test_validate_pipe_command_capabilities_accepts_pipes_feature() {
        let capabilities = DeploymentCapabilitiesInfo {
            deployment_hash: "dep-123".to_string(),
            status: "online".to_string(),
            capabilities: vec!["docker".to_string(), "pipes".to_string()],
            features: crate::cli::stacker_client::DeploymentCapabilityFeatures {
                pipes: true,
                ..Default::default()
            },
        };

        assert!(validate_pipe_command_capabilities(&capabilities).is_ok());
    }

    #[test]
    fn test_validate_pipe_command_capabilities_rejects_missing_pipes_feature() {
        let capabilities = DeploymentCapabilitiesInfo {
            deployment_hash: "dep-456".to_string(),
            status: "online".to_string(),
            capabilities: vec![
                "docker".to_string(),
                "compose".to_string(),
                "logs".to_string(),
            ],
            features: crate::cli::stacker_client::DeploymentCapabilityFeatures::default(),
        };

        let error = validate_pipe_command_capabilities(&capabilities)
            .expect_err("missing pipes capability should be rejected");

        let message = error.to_string();
        assert!(message.contains("does not support pipe commands"));
        assert!(message.contains("dep-456"));
        assert!(message.contains("docker, compose, logs"));
    }
}
