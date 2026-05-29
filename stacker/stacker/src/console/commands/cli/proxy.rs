use crate::cli::config_parser::{
    CloudOrchestrator, DeployTarget, DomainConfig, ProxyType, SslMode, StackerConfig,
};
use crate::cli::deployment_lock::DeploymentLock;
use crate::cli::error::CliError;
use crate::cli::proxy_manager::{
    detect_proxy, detect_proxy_from_snapshot, generate_nginx_server_block, ContainerRuntime,
    DockerCliRuntime, ProxyDetection,
};
use crate::cli::runtime::CliRuntime;
use crate::console::commands::cli::agent::AgentConfigureProxyCommand;
use crate::console::commands::CallableTrait;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyProviderKind {
    NginxProxyManager,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyProviderMetadata {
    pub kind: ProxyProviderKind,
    pub canonical_name: &'static str,
    pub service_catalog_name: &'static str,
    pub internal_api_url: &'static str,
}

impl ProxyProviderKind {
    pub fn from_alias(alias: &str) -> Option<Self> {
        match normalize_proxy_provider_alias(alias).as_str() {
            "npm" | "nginxproxymanager" => Some(Self::NginxProxyManager),
            _ => None,
        }
    }

    pub fn metadata(self) -> ProxyProviderMetadata {
        match self {
            Self::NginxProxyManager => ProxyProviderMetadata {
                kind: self,
                canonical_name: "nginx-proxy-manager",
                service_catalog_name: "nginx_proxy_manager",
                internal_api_url: "http://nginx-proxy-manager:81",
            },
        }
    }
}

fn normalize_proxy_provider_alias(alias: &str) -> String {
    alias
        .trim()
        .to_ascii_lowercase()
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect()
}

/// Parse SSL mode string to `SslMode` enum.
pub fn parse_ssl_mode(s: Option<&str>) -> SslMode {
    match s.map(|v| v.to_lowercase()).as_deref() {
        Some("auto") | Some("true") | Some("yes") | Some("on") | Some("1") => SslMode::Auto,
        Some("manual") => SslMode::Manual,
        Some("off") | Some("false") | Some("no") | Some("0") => SslMode::Off,
        _ => SslMode::Off,
    }
}

/// Build a `DomainConfig` from CLI arguments.
pub fn build_domain_config(
    domain: &str,
    upstream: Option<&str>,
    ssl: Option<&str>,
) -> DomainConfig {
    DomainConfig {
        domain: domain.to_string(),
        ssl: parse_ssl_mode(ssl),
        upstream: upstream.unwrap_or("http://app:8080").to_string(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProxyConfigPersistence {
    config_path: PathBuf,
    backup_path: PathBuf,
    changed: bool,
}

fn upsert_proxy_domain_config(
    config: &mut StackerConfig,
    proxy_type: ProxyType,
    domain_config: DomainConfig,
) -> bool {
    let mut changed = false;

    if config.proxy.proxy_type != proxy_type {
        config.proxy.proxy_type = proxy_type;
        changed = true;
    }

    if let Some(existing) = config
        .proxy
        .domains
        .iter_mut()
        .find(|entry| entry.domain.eq_ignore_ascii_case(&domain_config.domain))
    {
        if existing.ssl != domain_config.ssl || existing.upstream != domain_config.upstream {
            existing.ssl = domain_config.ssl;
            existing.upstream = domain_config.upstream;
            changed = true;
        }
        return changed;
    }

    config.proxy.domains.push(domain_config);
    true
}

fn persist_proxy_config_to_stacker_yml(
    project_dir: &Path,
    proxy_type: ProxyType,
    domain_config: DomainConfig,
) -> Result<Option<ProxyConfigPersistence>, CliError> {
    let config_path = project_dir.join("stacker.yml");
    if !config_path.exists() {
        return Ok(None);
    }

    let mut config = StackerConfig::from_file_raw(&config_path)?;
    let changed = upsert_proxy_domain_config(&mut config, proxy_type, domain_config);
    let backup_path = PathBuf::from(format!("{}.bak", config_path.display()));

    if !changed {
        return Ok(Some(ProxyConfigPersistence {
            config_path,
            backup_path,
            changed,
        }));
    }

    let yaml = serde_yaml::to_string(&config)
        .map_err(|e| CliError::ConfigValidation(format!("Failed to serialize config: {}", e)))?;
    std::fs::copy(&config_path, &backup_path)?;
    std::fs::write(&config_path, yaml)?;

    Ok(Some(ProxyConfigPersistence {
        config_path,
        backup_path,
        changed,
    }))
}

fn print_proxy_config_persistence(result: Option<&ProxyConfigPersistence>) {
    let Some(result) = result else {
        eprintln!("⚠ No stacker.yml found; proxy config was not persisted locally.");
        return;
    };

    if result.changed {
        eprintln!("✓ Updated proxy config in {}", result.config_path.display());
        eprintln!("  Backup written to {}", result.backup_path.display());
    } else {
        eprintln!(
            "✓ Proxy config already up to date in {}",
            result.config_path.display()
        );
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyUpstreamTarget {
    pub app_code: String,
    pub port: u16,
}

pub fn parse_proxy_upstream(upstream: &str) -> Result<ProxyUpstreamTarget, CliError> {
    let upstream = upstream
        .strip_prefix("http://")
        .or_else(|| upstream.strip_prefix("https://"))
        .unwrap_or(upstream);

    if upstream.contains('/') {
        return Err(CliError::ConfigValidation(format!(
            "Invalid upstream '{}': paths are not supported; use host:port",
            upstream
        )));
    }

    let (host, port) = upstream.rsplit_once(':').ok_or_else(|| {
        CliError::ConfigValidation(format!(
            "Invalid upstream '{}': must match [http://]host:port format",
            upstream
        ))
    })?;

    if host.trim().is_empty() {
        return Err(CliError::ConfigValidation(format!(
            "Invalid upstream '{}': host is required",
            upstream
        )));
    }

    let port = port.parse::<u16>().map_err(|_| {
        CliError::ConfigValidation(format!(
            "Invalid upstream '{}': port must be between 1 and 65535",
            upstream
        ))
    })?;

    if port == 0 {
        return Err(CliError::ConfigValidation(format!(
            "Invalid upstream '{}': port must be between 1 and 65535",
            upstream
        )));
    }

    Ok(ProxyUpstreamTarget {
        app_code: host.to_string(),
        port,
    })
}

/// Run proxy detection using a `ContainerRuntime` (DIP).
pub fn run_detect(runtime: &dyn ContainerRuntime) -> Result<ProxyDetection, CliError> {
    detect_proxy(runtime)
}

/// `stacker proxy add <domain> [--upstream <host:port>] [--ssl[=auto|manual|off]]`
///
/// Adds a reverse-proxy entry for the given domain.
pub struct ProxyAddCommand {
    pub domain: String,
    pub upstream: Option<String>,
    pub ssl: Option<String>,
    pub force: bool,
    pub json: bool,
    pub deployment: Option<String>,
}

impl ProxyAddCommand {
    pub fn new(
        domain: String,
        upstream: Option<String>,
        ssl: Option<String>,
        force: bool,
        json: bool,
        deployment: Option<String>,
    ) -> Self {
        Self {
            domain,
            upstream,
            ssl,
            force,
            json,
            deployment,
        }
    }
}

impl CallableTrait for ProxyAddCommand {
    fn call(&self) -> Result<(), Box<dyn std::error::Error>> {
        let project_dir = std::env::current_dir()?;
        let domain_config =
            build_domain_config(&self.domain, self.upstream.as_deref(), self.ssl.as_deref());
        let use_agent = self.deployment.is_some() || is_cloud_or_remote(&project_dir);
        if use_agent {
            let upstream = self.upstream.as_deref().unwrap_or("app:8080");
            let target = parse_proxy_upstream(upstream)?;
            let ssl_enabled = parse_ssl_mode(self.ssl.as_deref()) != SslMode::Off;
            let command = AgentConfigureProxyCommand::new(
                target.app_code,
                self.domain.clone(),
                target.port,
                ssl_enabled,
                !ssl_enabled,
                "create".to_string(),
                self.force,
                self.json,
                self.deployment.clone(),
            );
            command.call()?;
            let persistence = persist_proxy_config_to_stacker_yml(
                &project_dir,
                ProxyType::NginxProxyManager,
                domain_config,
            )?;
            if !self.json {
                print_proxy_config_persistence(persistence.as_ref());
            }
            return Ok(());
        }

        let block = generate_nginx_server_block(&domain_config)?;
        let persistence =
            persist_proxy_config_to_stacker_yml(&project_dir, ProxyType::Nginx, domain_config)?;
        println!("{}", block);
        if !self.json {
            print_proxy_config_persistence(persistence.as_ref());
        }
        eprintln!(
            "✓ Proxy config generated for {}; apply this nginx snippet to configure a local proxy",
            self.domain
        );
        Ok(())
    }
}

/// `stacker proxy detect [--json] [--deployment <hash>]`
///
/// Scans running containers for an existing reverse-proxy (nginx, traefik, etc.)
/// and reports what was found.
///
/// - **Local deployments**: runs `docker ps` locally.
/// - **Cloud/remote deployments**: queries the Status Panel agent snapshot.
pub struct ProxyDetectCommand {
    pub json: bool,
    pub deployment: Option<String>,
}

impl ProxyDetectCommand {
    pub fn new(json: bool, deployment: Option<String>) -> Self {
        Self { json, deployment }
    }
}

/// Check whether the current project is configured for cloud/remote deployment.
fn is_cloud_or_remote(project_dir: &std::path::Path) -> bool {
    // 1. Check deployment lock
    if let Ok(Some(lock)) = DeploymentLock::load(project_dir) {
        if lock.target == "cloud" || lock.target == "server" {
            return true;
        }
    }

    // 2. Check stacker.yml
    let config_path = project_dir.join("stacker.yml");
    if let Ok(config) = StackerConfig::from_file(&config_path)
        .and_then(|config| config.with_resolved_deploy_target(None))
    {
        if config.deploy.target == DeployTarget::Cloud {
            return true;
        }
        if config.deploy.target == DeployTarget::Server {
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

/// Resolve deployment hash for proxy detection (minimal version).
fn resolve_deployment_hash_for_proxy(
    explicit: &Option<String>,
    ctx: &CliRuntime,
) -> Result<String, CliError> {
    if let Some(hash) = explicit {
        if !hash.is_empty() {
            return Ok(hash.clone());
        }
    }

    let project_dir = std::env::current_dir().map_err(CliError::Io)?;

    if let Some(lock) = DeploymentLock::load(&project_dir)? {
        if let Some(dep_id) = lock.deployment_id {
            let info = ctx.block_on(ctx.client.get_deployment_status(dep_id as i32))?;
            if let Some(info) = info {
                return Ok(info.deployment_hash);
            }
        }
    }

    let config_path = project_dir.join("stacker.yml");
    if config_path.exists() {
        if let Ok(config) = StackerConfig::from_file(&config_path)
            .and_then(|config| config.with_resolved_deploy_target(None))
        {
            if let Some(ref project_name) = config.project.identity {
                let project = ctx.block_on(ctx.client.find_project_by_name(project_name))?;
                if let Some(proj) = project {
                    let dep = ctx.block_on(ctx.client.get_deployment_status_by_project(proj.id))?;
                    if let Some(dep) = dep {
                        return Ok(dep.deployment_hash);
                    }
                }
            }
        }
    }

    Err(CliError::ConfigValidation(
        "Cannot determine deployment hash for remote proxy detection.\n\
         Use --deployment <HASH>, or run from a directory with a deployment lock or stacker.yml."
            .to_string(),
    ))
}

/// Pretty-print a proxy detection result.
fn print_detection(detection: &ProxyDetection, json: bool) {
    if json {
        let val = serde_json::json!({
            "proxy_type": format!("{:?}", detection.proxy_type),
            "container_name": detection.container_name,
            "ports": detection.ports,
        });
        println!("{}", serde_json::to_string_pretty(&val).unwrap_or_default());
        return;
    }

    eprintln!("Detected proxy: {:?}", detection.proxy_type);
    if let Some(name) = &detection.container_name {
        eprintln!("  Container: {}", name);
    }
    if !detection.ports.is_empty() {
        eprintln!("  Ports: {:?}", detection.ports);
    }
}

impl CallableTrait for ProxyDetectCommand {
    fn call(&self) -> Result<(), Box<dyn std::error::Error>> {
        let project_dir = std::env::current_dir()?;

        // If an explicit --deployment flag was given, or the project is
        // deployed to cloud/server, use the agent snapshot for detection.
        let use_remote = self.deployment.is_some() || is_cloud_or_remote(&project_dir);

        if use_remote {
            let ctx = CliRuntime::new("proxy detect")?;
            let hash = resolve_deployment_hash_for_proxy(&self.deployment, &ctx)?;

            let snapshot = ctx.block_on(ctx.client.agent_snapshot(&hash))?;
            let detection = detect_proxy_from_snapshot(&snapshot);
            print_detection(&detection, self.json);
        } else {
            let runtime = DockerCliRuntime;
            let detection = run_detect(&runtime)?;
            print_detection(&detection, self.json);
        }

        Ok(())
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::config_parser::{ConfigBuilder, ProxyConfig};
    use crate::cli::proxy_manager::ContainerInfo;

    struct MockRuntime {
        containers: Vec<ContainerInfo>,
    }

    impl ContainerRuntime for MockRuntime {
        fn list_containers(&self) -> Result<Vec<ContainerInfo>, CliError> {
            Ok(self.containers.clone())
        }
        fn is_available(&self) -> bool {
            true
        }
    }

    #[test]
    fn proxy_provider_aliases_resolve_to_nginx_proxy_manager() {
        for alias in [
            "npm",
            "nginx-proxy-manager",
            "nginx_proxy_manager",
            "Nginx Proxy Manager",
        ] {
            assert_eq!(
                ProxyProviderKind::from_alias(alias),
                Some(ProxyProviderKind::NginxProxyManager)
            );
        }
        assert_eq!(ProxyProviderKind::from_alias("traefik"), None);
    }

    #[test]
    fn nginx_proxy_manager_metadata_uses_stack_service_defaults() {
        let metadata = ProxyProviderKind::NginxProxyManager.metadata();

        assert_eq!(metadata.service_catalog_name, "nginx_proxy_manager");
        assert_eq!(metadata.internal_api_url, "http://nginx-proxy-manager:81");
        assert_eq!(metadata.canonical_name, "nginx-proxy-manager");
    }

    #[test]
    fn test_parse_ssl_mode_auto() {
        assert_eq!(parse_ssl_mode(Some("auto")), SslMode::Auto);
        assert_eq!(parse_ssl_mode(Some("AUTO")), SslMode::Auto);
        assert_eq!(parse_ssl_mode(Some("true")), SslMode::Auto);
    }

    #[test]
    fn test_parse_ssl_mode_defaults_to_off() {
        assert_eq!(parse_ssl_mode(None), SslMode::Off);
        assert_eq!(parse_ssl_mode(Some("unknown")), SslMode::Off);
        assert_eq!(parse_ssl_mode(Some("false")), SslMode::Off);
    }

    #[test]
    fn test_build_domain_config_with_defaults() {
        let cfg = build_domain_config("example.com", None, None);
        assert_eq!(cfg.domain, "example.com");
        assert_eq!(cfg.upstream, "http://app:8080");
        assert_eq!(cfg.ssl, SslMode::Off);
    }

    #[test]
    fn test_build_domain_config_with_overrides() {
        let cfg = build_domain_config("app.io", Some("http://web:3000"), Some("auto"));
        assert_eq!(cfg.upstream, "http://web:3000");
        assert_eq!(cfg.ssl, SslMode::Auto);
    }

    #[test]
    fn upsert_proxy_domain_config_sets_type_and_adds_domain() {
        let mut config = ConfigBuilder::new().name("demo").build().unwrap();
        let changed = upsert_proxy_domain_config(
            &mut config,
            ProxyType::NginxProxyManager,
            build_domain_config("example.com", Some("app:3000"), Some("auto")),
        );

        assert!(changed);
        assert_eq!(config.proxy.proxy_type, ProxyType::NginxProxyManager);
        assert_eq!(config.proxy.domains.len(), 1);
        assert_eq!(config.proxy.domains[0].domain, "example.com");
        assert_eq!(config.proxy.domains[0].ssl, SslMode::Auto);
        assert_eq!(config.proxy.domains[0].upstream, "app:3000");
    }

    #[test]
    fn upsert_proxy_domain_config_updates_existing_domain_without_duplicate() {
        let mut config = ConfigBuilder::new()
            .name("demo")
            .proxy(ProxyConfig {
                proxy_type: ProxyType::None,
                auto_detect: false,
                domains: vec![build_domain_config(
                    "Example.com",
                    Some("app:3000"),
                    Some("off"),
                )],
                config: None,
            })
            .build()
            .unwrap();

        let changed = upsert_proxy_domain_config(
            &mut config,
            ProxyType::NginxProxyManager,
            build_domain_config("example.com", Some("web:8080"), Some("auto")),
        );

        assert!(changed);
        assert_eq!(config.proxy.proxy_type, ProxyType::NginxProxyManager);
        assert_eq!(config.proxy.domains.len(), 1);
        assert_eq!(config.proxy.domains[0].domain, "Example.com");
        assert_eq!(config.proxy.domains[0].ssl, SslMode::Auto);
        assert_eq!(config.proxy.domains[0].upstream, "web:8080");
    }

    #[test]
    fn persist_proxy_config_to_stacker_yml_writes_backup_and_preserves_env_placeholders() {
        let dir = tempfile::TempDir::new().unwrap();
        let config_path = dir.path().join("stacker.yml");
        std::fs::write(
            &config_path,
            "name: demo\napp:\n  type: node\n  image: ${APP_IMAGE}\nproxy:\n  type: none\n  domains: []\n",
        )
        .unwrap();

        let result = persist_proxy_config_to_stacker_yml(
            dir.path(),
            ProxyType::NginxProxyManager,
            build_domain_config(
                "status.example.com",
                Some("status-panel-web:3000"),
                Some("auto"),
            ),
        )
        .unwrap()
        .expect("stacker.yml exists");

        assert!(result.changed);
        assert!(result.backup_path.exists());

        let written = std::fs::read_to_string(&config_path).unwrap();
        assert!(written.contains("${APP_IMAGE}"));

        let config = StackerConfig::from_file_raw(&config_path).unwrap();
        assert_eq!(config.proxy.proxy_type, ProxyType::NginxProxyManager);
        assert_eq!(config.proxy.domains.len(), 1);
        assert_eq!(config.proxy.domains[0].domain, "status.example.com");
        assert_eq!(config.proxy.domains[0].upstream, "status-panel-web:3000");
        assert_eq!(config.proxy.domains[0].ssl, SslMode::Auto);
    }

    #[test]
    fn given_stacker_proxy_add_when_config_is_persisted_then_stacker_yml_reflects_proxy_state() {
        let dir = tempfile::TempDir::new().unwrap();
        let config_path = dir.path().join("stacker.yml");
        std::fs::write(
            &config_path,
            r#"
name: web
services:
  - name: status-panel-web
    image: trydirect/status-panel-web:0.1.0
proxy:
  type: none
  auto_detect: false
  domains: []
"#,
        )
        .unwrap();

        let result = persist_proxy_config_to_stacker_yml(
            dir.path(),
            ProxyType::NginxProxyManager,
            build_domain_config(
                "status.stacker.my",
                Some("status-panel-web:3000"),
                Some("auto"),
            ),
        )
        .unwrap()
        .expect("stacker.yml exists");

        assert!(result.changed);
        assert!(result.backup_path.exists());

        let config = StackerConfig::from_file_raw(&config_path).unwrap();
        assert_eq!(config.proxy.proxy_type, ProxyType::NginxProxyManager);
        assert_eq!(config.proxy.domains.len(), 1);
        assert_eq!(config.proxy.domains[0].domain, "status.stacker.my");
        assert_eq!(config.proxy.domains[0].ssl, SslMode::Auto);
        assert_eq!(config.proxy.domains[0].upstream, "status-panel-web:3000");
        assert!(config
            .services
            .iter()
            .all(|service| service.name != "nginx_proxy_manager"));
    }

    #[test]
    fn test_parse_proxy_upstream_strips_scheme() {
        let target = parse_proxy_upstream("http://coolify:80").unwrap();
        assert_eq!(target.app_code, "coolify");
        assert_eq!(target.port, 80);
    }

    #[test]
    fn test_parse_proxy_upstream_rejects_paths() {
        let err = parse_proxy_upstream("http://coolify:80/admin").unwrap_err();
        assert!(err.to_string().contains("paths are not supported"));
    }

    #[test]
    fn test_detect_returns_none_for_empty_containers() {
        let runtime = MockRuntime { containers: vec![] };
        let result = run_detect(&runtime).unwrap();
        assert_eq!(result.proxy_type, ProxyType::None);
    }

    #[test]
    fn test_detect_finds_nginx_proxy() {
        let runtime = MockRuntime {
            containers: vec![ContainerInfo {
                id: "abc123".to_string(),
                name: "nginx-1".to_string(),
                image: "nginx:latest".to_string(),
                ports: vec![80, 443],
                status: "running".to_string(),
            }],
        };
        let result = run_detect(&runtime).unwrap();
        assert_eq!(result.proxy_type, ProxyType::Nginx);
    }
}
