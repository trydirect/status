use std::collections::HashMap;
use std::convert::TryFrom;
use std::fmt;
use std::path::Path;

use crate::cli::config_parser::{AppType, ProxyType, ServiceDefinition, StackerConfig};
use crate::cli::error::CliError;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// ComposeService — represents one service in docker-compose
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone)]
pub struct ComposeService {
    pub name: String,
    pub image: Option<String>,
    pub build_context: Option<String>,
    pub dockerfile: Option<String>,
    pub ports: Vec<String>,
    pub environment: HashMap<String, String>,
    pub volumes: Vec<String>,
    pub depends_on: Vec<String>,
    pub restart: String,
    pub networks: Vec<String>,
    pub labels: HashMap<String, String>,
    /// Container runtime (e.g., "kata"). None or "runc" means default.
    pub runtime: Option<String>,
}

impl Default for ComposeService {
    fn default() -> Self {
        Self {
            name: String::new(),
            image: None,
            build_context: None,
            dockerfile: None,
            ports: Vec::new(),
            environment: HashMap::new(),
            volumes: Vec::new(),
            depends_on: Vec::new(),
            restart: "unless-stopped".to_string(),
            networks: vec!["app-network".to_string()],
            labels: HashMap::new(),
            runtime: None,
        }
    }
}

/// Convert a `ServiceDefinition` (from stacker.yml) into a `ComposeService`.
impl From<&ServiceDefinition> for ComposeService {
    fn from(svc: &ServiceDefinition) -> Self {
        let mut compose_service = Self {
            name: svc.name.clone(),
            image: Some(svc.image.clone()),
            ports: svc.ports.clone(),
            environment: svc.environment.clone(),
            volumes: svc.volumes.clone(),
            depends_on: svc.depends_on.clone(),
            ..Default::default()
        };
        crate::helpers::stacker_labels::insert_runtime_labels(
            &mut compose_service.labels,
            None::<String>,
            None,
            crate::helpers::stacker_labels::SCOPE_PROJECT,
            &svc.name,
            &svc.name,
        );
        compose_service
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// ComposeDefinition — full docker-compose document
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone)]
pub struct ComposeDefinition {
    pub services: Vec<ComposeService>,
    pub networks: Vec<String>,
    pub volumes: Vec<String>,
}

impl Default for ComposeDefinition {
    fn default() -> Self {
        Self {
            services: Vec::new(),
            networks: vec!["app-network".to_string()],
            volumes: Vec::new(),
        }
    }
}

/// Build a complete `ComposeDefinition` from a `StackerConfig`.
///
/// This converts the config's app + services into docker-compose services,
/// sets up networking, and optionally adds a proxy service.
impl TryFrom<&StackerConfig> for ComposeDefinition {
    type Error = CliError;

    fn try_from(config: &StackerConfig) -> Result<Self, Self::Error> {
        let mut compose = ComposeDefinition::default();
        let mut named_volumes: Vec<String> = Vec::new();

        // --- Main app service ---
        let app_service = build_app_service(config);
        compose.services.push(app_service);

        // --- Additional services (databases, caches, etc.) ---
        for svc_def in &config.services {
            let svc = ComposeService::from(svc_def);

            // Collect named volumes
            for vol in &svc.volumes {
                if let Some(named) = extract_named_volume(vol) {
                    if !named_volumes.contains(&named) {
                        named_volumes.push(named);
                    }
                }
            }

            compose.services.push(svc);
        }

        // --- Proxy service ---
        if let Some(proxy_svc) = build_proxy_service(config) {
            compose.services.push(proxy_svc);
        }

        // --- Set top-level volumes ---
        compose.volumes = named_volumes;

        Ok(compose)
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Internal construction helpers (SRP: each builds one aspect)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

fn build_app_service(config: &StackerConfig) -> ComposeService {
    let mut svc = ComposeService {
        name: "app".to_string(),
        ..Default::default()
    };
    crate::helpers::stacker_labels::insert_runtime_labels(
        &mut svc.labels,
        None::<String>,
        None,
        crate::helpers::stacker_labels::SCOPE_PROJECT,
        "app",
        "app",
    );

    // If user specifies an image directly, use it.
    if let Some(ref img) = config.app.image {
        svc.image = Some(img.clone());
    } else {
        // Build from context
        svc.build_context = Some(config.app.path.to_string_lossy().to_string());
        if let Some(ref df) = config.app.dockerfile {
            svc.dockerfile = Some(df.to_string_lossy().to_string());
        }
    }

    // Ports: use explicit ports if provided, otherwise default from app type
    if config.app.ports.is_empty() {
        let default_port = default_port_for_app_type(config.app.app_type);
        svc.ports.push(format!("{}:{}", default_port, default_port));
    } else {
        svc.ports.extend(config.app.ports.clone());
    }

    // Volumes from app section
    svc.volumes.extend(config.app.volumes.clone());

    // Merge environment: top-level env first, then app-level (app wins)
    for (k, v) in &config.env {
        svc.environment.insert(k.clone(), v.clone());
    }
    for (k, v) in &config.app.environment {
        svc.environment.insert(k.clone(), v.clone());
    }

    svc
}

fn default_port_for_app_type(app_type: AppType) -> u16 {
    match app_type {
        AppType::Static => 80,
        AppType::Node => 3000,
        AppType::Python => 8000,
        AppType::Rust => 8080,
        AppType::Go => 8080,
        AppType::Php => 9000,
        AppType::Custom => 8080,
    }
}

fn build_proxy_service(config: &StackerConfig) -> Option<ComposeService> {
    match config.proxy.proxy_type {
        ProxyType::Nginx => {
            let mut svc = ComposeService {
                name: "nginx".to_string(),
                image: Some("nginx:alpine".to_string()),
                ports: vec!["80:80".to_string(), "443:443".to_string()],
                depends_on: vec!["app".to_string()],
                ..Default::default()
            };
            svc.volumes
                .push("./nginx/conf.d:/etc/nginx/conf.d:ro".to_string());
            Some(svc)
        }
        ProxyType::NginxProxyManager => {
            let mut svc = ComposeService {
                name: "proxy-manager".to_string(),
                image: Some("jc21/nginx-proxy-manager:latest".to_string()),
                ports: vec![
                    "80:80".to_string(),
                    "443:443".to_string(),
                    "81:81".to_string(),
                ],
                depends_on: vec!["app".to_string()],
                ..Default::default()
            };
            crate::helpers::stacker_labels::insert_runtime_labels(
                &mut svc.labels,
                None::<String>,
                None,
                crate::helpers::stacker_labels::SCOPE_PLATFORM,
                "nginx_proxy_manager",
                "nginx-proxy-manager",
            );
            Some(svc)
        }
        ProxyType::Traefik => {
            let mut svc = ComposeService {
                name: "traefik".to_string(),
                image: Some("traefik:v2.10".to_string()),
                ports: vec!["80:80".to_string(), "443:443".to_string()],
                depends_on: vec!["app".to_string()],
                ..Default::default()
            };
            svc.volumes
                .push("/var/run/docker.sock:/var/run/docker.sock:ro".to_string());
            Some(svc)
        }
        ProxyType::None => None,
    }
}

/// Extract a named volume from a volume string like "my-data:/var/lib/data".
/// Returns `None` for bind mounts (starting with `.` or `/`).
fn extract_named_volume(vol_str: &str) -> Option<String> {
    let parts: Vec<&str> = vol_str.split(':').collect();
    if parts.len() >= 2 {
        let source = parts[0];
        if !source.starts_with('.') && !source.starts_with('/') {
            return Some(source.to_string());
        }
    }
    None
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Rendering — produce docker-compose YAML string
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

impl ComposeDefinition {
    /// Render as a docker-compose YAML string (hand-built for readability).
    pub fn render(&self) -> String {
        let mut out = String::new();

        out.push_str("services:\n");

        for svc in &self.services {
            out.push_str(&format!("  {}:\n", svc.name));

            if let Some(ref img) = svc.image {
                out.push_str(&format!("    image: {}\n", img));
            }

            if let Some(ref ctx) = svc.build_context {
                out.push_str("    build:\n");
                out.push_str(&format!("      context: {}\n", ctx));
                if let Some(ref df) = svc.dockerfile {
                    out.push_str(&format!("      dockerfile: {}\n", df));
                }
            }

            if let Some(ref rt) = svc.runtime {
                if rt != "runc" {
                    out.push_str(&format!("    runtime: {}\n", rt));
                }
            }

            if !svc.ports.is_empty() {
                out.push_str("    ports:\n");
                for p in &svc.ports {
                    out.push_str(&format!("      - \"{}\"\n", p));
                }
            }

            if !svc.environment.is_empty() {
                out.push_str("    environment:\n");
                let mut keys: Vec<&String> = svc.environment.keys().collect();
                keys.sort();
                for k in keys {
                    out.push_str(&format!("      {}: \"{}\"\n", k, svc.environment[k]));
                }
            }

            if !svc.volumes.is_empty() {
                out.push_str("    volumes:\n");
                for v in &svc.volumes {
                    out.push_str(&format!("      - \"{}\"\n", v));
                }
            }

            if !svc.depends_on.is_empty() {
                out.push_str("    depends_on:\n");
                for d in &svc.depends_on {
                    out.push_str(&format!("      - {}\n", d));
                }
            }

            out.push_str(&format!("    restart: {}\n", svc.restart));

            if !svc.networks.is_empty() {
                out.push_str("    networks:\n");
                for n in &svc.networks {
                    out.push_str(&format!("      - {}\n", n));
                }
            }

            if !svc.labels.is_empty() {
                out.push_str("    labels:\n");
                let mut keys: Vec<&String> = svc.labels.keys().collect();
                keys.sort();
                for k in keys {
                    out.push_str(&format!("      {}: \"{}\"\n", k, svc.labels[k]));
                }
            }

            out.push('\n');
        }

        // Top-level networks
        if !self.networks.is_empty() {
            out.push_str("networks:\n");
            for n in &self.networks {
                out.push_str(&format!("  {}:\n    driver: bridge\n", n));
            }
            out.push('\n');
        }

        // Top-level volumes
        if !self.volumes.is_empty() {
            out.push_str("volumes:\n");
            for v in &self.volumes {
                out.push_str(&format!("  {}:\n", v));
            }
            out.push('\n');
        }

        out
    }

    /// Write docker-compose YAML to a file path.
    pub fn write_to(&self, path: &Path, overwrite: bool) -> Result<(), CliError> {
        if !overwrite && path.exists() {
            return Err(CliError::GeneratorError(format!(
                "Compose file already exists: {}",
                path.display()
            )));
        }
        let content = self.render();
        std::fs::write(path, content)?;
        Ok(())
    }
}

impl fmt::Display for ComposeDefinition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.render())
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Tests
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::config_parser::{AppSource, ConfigBuilder, DeployConfig, ProxyConfig, SslMode};
    use std::collections::HashMap;

    fn minimal_config(app_type: AppType) -> StackerConfig {
        ConfigBuilder::new()
            .name("test-app")
            .app_type(app_type)
            .build()
            .unwrap()
    }

    #[test]
    fn test_compose_from_minimal_static_config() {
        let config = minimal_config(AppType::Static);
        let compose = ComposeDefinition::try_from(&config).unwrap();
        assert_eq!(compose.services.len(), 1);
        assert_eq!(compose.services[0].name, "app");
        assert!(compose.services[0].ports.contains(&"80:80".to_string()));
    }

    #[test]
    fn test_compose_from_node_config() {
        let config = minimal_config(AppType::Node);
        let compose = ComposeDefinition::try_from(&config).unwrap();
        assert!(compose.services[0].ports.contains(&"3000:3000".to_string()));
    }

    #[test]
    fn test_compose_from_python_config_port() {
        let config = minimal_config(AppType::Python);
        let compose = ComposeDefinition::try_from(&config).unwrap();
        assert!(compose.services[0].ports.contains(&"8000:8000".to_string()));
    }

    #[test]
    fn test_compose_app_service_uses_build_context() {
        let config = minimal_config(AppType::Static);
        let compose = ComposeDefinition::try_from(&config).unwrap();
        let app = &compose.services[0];
        assert!(app.build_context.is_some());
        assert!(app.image.is_none());
    }

    #[test]
    fn test_compose_app_service_with_explicit_image() {
        let config = ConfigBuilder::new()
            .name("img-app")
            .app_type(AppType::Custom)
            .app_image("myregistry/myapp:latest")
            .build()
            .unwrap();
        let compose = ComposeDefinition::try_from(&config).unwrap();
        let app = &compose.services[0];
        assert_eq!(app.image.as_deref(), Some("myregistry/myapp:latest"));
        assert!(app.build_context.is_none());
    }

    #[test]
    fn test_compose_includes_additional_services() {
        let svc = ServiceDefinition {
            name: "postgres".into(),
            image: "postgres:16".into(),
            ports: vec!["5432:5432".into()],
            environment: HashMap::from([("POSTGRES_PASSWORD".into(), "secret".into())]),
            volumes: vec!["pg-data:/var/lib/postgresql/data".into()],
            depends_on: Vec::new(),
        };
        let config = ConfigBuilder::new()
            .name("with-db")
            .app_type(AppType::Node)
            .add_service(svc)
            .build()
            .unwrap();

        let compose = ComposeDefinition::try_from(&config).unwrap();
        assert_eq!(compose.services.len(), 2);
        assert_eq!(compose.services[1].name, "postgres");
        assert!(compose.volumes.contains(&"pg-data".to_string()));
    }

    #[test]
    fn test_compose_nginx_proxy_added() {
        let config = ConfigBuilder::new()
            .name("proxied-app")
            .app_type(AppType::Node)
            .proxy(ProxyConfig {
                proxy_type: ProxyType::Nginx,
                auto_detect: true,
                domains: Vec::new(),
                config: None,
            })
            .build()
            .unwrap();

        let compose = ComposeDefinition::try_from(&config).unwrap();
        let proxy_svc = compose.services.iter().find(|s| s.name == "nginx");
        assert!(proxy_svc.is_some());
        let proxy = proxy_svc.unwrap();
        assert_eq!(proxy.image.as_deref(), Some("nginx:alpine"));
        assert!(proxy.ports.contains(&"80:80".to_string()));
        assert!(proxy.ports.contains(&"443:443".to_string()));
        assert!(proxy.depends_on.contains(&"app".to_string()));
    }

    #[test]
    fn test_compose_no_proxy_when_none() {
        let config = minimal_config(AppType::Static);
        let compose = ComposeDefinition::try_from(&config).unwrap();
        // Only app service, no proxy
        assert_eq!(compose.services.len(), 1);
    }

    #[test]
    fn test_compose_traefik_proxy() {
        let config = ConfigBuilder::new()
            .name("traefik-app")
            .app_type(AppType::Python)
            .proxy(ProxyConfig {
                proxy_type: ProxyType::Traefik,
                auto_detect: true,
                domains: Vec::new(),
                config: None,
            })
            .build()
            .unwrap();

        let compose = ComposeDefinition::try_from(&config).unwrap();
        let traefik = compose.services.iter().find(|s| s.name == "traefik");
        assert!(traefik.is_some());
        assert_eq!(traefik.unwrap().image.as_deref(), Some("traefik:v2.10"));
    }

    #[test]
    fn test_compose_render_omits_obsolete_version() {
        let config = minimal_config(AppType::Static);
        let compose = ComposeDefinition::try_from(&config).unwrap();
        let yaml = compose.render();
        assert!(!yaml.contains("version:"));
    }

    #[test]
    fn test_compose_render_contains_services_block() {
        let config = minimal_config(AppType::Node);
        let compose = ComposeDefinition::try_from(&config).unwrap();
        let yaml = compose.render();
        assert!(yaml.contains("services:"));
        assert!(yaml.contains("  app:"));
    }

    #[test]
    fn test_compose_render_contains_networks() {
        let config = minimal_config(AppType::Static);
        let compose = ComposeDefinition::try_from(&config).unwrap();
        let yaml = compose.render();
        assert!(yaml.contains("networks:"));
        assert!(yaml.contains("app-network"));
    }

    #[test]
    fn test_compose_render_contains_volumes_section() {
        let svc = ServiceDefinition {
            name: "redis".into(),
            image: "redis:7".into(),
            ports: Vec::new(),
            environment: HashMap::new(),
            volumes: vec!["redis-data:/data".into()],
            depends_on: Vec::new(),
        };
        let config = ConfigBuilder::new()
            .name("with-vol")
            .app_type(AppType::Static)
            .add_service(svc)
            .build()
            .unwrap();

        let compose = ComposeDefinition::try_from(&config).unwrap();
        let yaml = compose.render();
        assert!(yaml.contains("volumes:"));
        assert!(yaml.contains("  redis-data:"));
    }

    #[test]
    fn test_compose_env_vars_propagated_to_app() {
        let config = ConfigBuilder::new()
            .name("env-app")
            .app_type(AppType::Node)
            .env("NODE_ENV", "production")
            .env("LOG_LEVEL", "debug")
            .build()
            .unwrap();

        let compose = ComposeDefinition::try_from(&config).unwrap();
        let app = &compose.services[0];
        assert_eq!(
            app.environment.get("NODE_ENV").map(|s| s.as_str()),
            Some("production")
        );
        assert_eq!(
            app.environment.get("LOG_LEVEL").map(|s| s.as_str()),
            Some("debug")
        );
    }

    #[test]
    fn test_compose_display_matches_render() {
        let config = minimal_config(AppType::Static);
        let compose = ComposeDefinition::try_from(&config).unwrap();
        assert_eq!(format!("{}", compose), compose.render());
    }

    #[test]
    fn test_compose_write_refuses_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("docker-compose.yml");
        std::fs::write(&path, "existing").unwrap();

        let config = minimal_config(AppType::Static);
        let compose = ComposeDefinition::try_from(&config).unwrap();
        let result = compose.write_to(&path, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_compose_write_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("docker-compose.yml");

        let config = minimal_config(AppType::Node);
        let compose = ComposeDefinition::try_from(&config).unwrap();
        compose.write_to(&path, false).unwrap();

        let written = std::fs::read_to_string(&path).unwrap();
        assert!(written.contains("app:"));
        assert!(written.contains("3000:3000"));
    }

    #[test]
    fn test_service_definition_to_compose_service() {
        let svc_def = ServiceDefinition {
            name: "mysql".into(),
            image: "mysql:8".into(),
            ports: vec!["3306:3306".into()],
            environment: HashMap::from([("MYSQL_ROOT_PASSWORD".into(), "pass".into())]),
            volumes: vec!["mysql-data:/var/lib/mysql".into()],
            depends_on: Vec::new(),
        };

        let compose_svc = ComposeService::from(&svc_def);
        assert_eq!(compose_svc.name, "mysql");
        assert_eq!(compose_svc.image.as_deref(), Some("mysql:8"));
        assert!(compose_svc.ports.contains(&"3306:3306".to_string()));
        assert_eq!(
            compose_svc
                .environment
                .get("MYSQL_ROOT_PASSWORD")
                .map(|s| s.as_str()),
            Some("pass")
        );
    }

    #[test]
    fn service_definition_adds_project_scope_labels() {
        let svc_def = ServiceDefinition {
            name: "smtp".into(),
            image: "trydirect/smtp:latest".into(),
            ports: Vec::new(),
            environment: HashMap::new(),
            volumes: Vec::new(),
            depends_on: Vec::new(),
        };

        let compose_svc = ComposeService::from(&svc_def);

        assert_eq!(
            compose_svc
                .labels
                .get(crate::helpers::stacker_labels::SCOPE)
                .map(String::as_str),
            Some("project")
        );
        assert_eq!(
            compose_svc
                .labels
                .get(crate::helpers::stacker_labels::SERVICE)
                .map(String::as_str),
            Some("smtp")
        );
        assert_eq!(
            compose_svc
                .labels
                .get(crate::helpers::stacker_labels::DNS)
                .map(String::as_str),
            Some("smtp")
        );
    }

    #[test]
    fn test_extract_named_volume_returns_name() {
        assert_eq!(
            extract_named_volume("pg-data:/var/lib/postgresql/data"),
            Some("pg-data".to_string())
        );
    }

    #[test]
    fn test_extract_named_volume_ignores_bind_mount() {
        assert_eq!(extract_named_volume("./data:/app/data"), None);
        assert_eq!(extract_named_volume("/host/path:/container"), None);
    }

    #[test]
    fn test_compose_nginx_proxy_manager() {
        let config = ConfigBuilder::new()
            .name("npm-app")
            .app_type(AppType::Static)
            .proxy(ProxyConfig {
                proxy_type: ProxyType::NginxProxyManager,
                auto_detect: true,
                domains: Vec::new(),
                config: None,
            })
            .build()
            .unwrap();

        let compose = ComposeDefinition::try_from(&config).unwrap();
        let npm = compose.services.iter().find(|s| s.name == "proxy-manager");
        assert!(npm.is_some());
        let npm = npm.unwrap();
        assert!(npm.ports.contains(&"81:81".to_string())); // NPM admin port
        assert_eq!(
            npm.labels
                .get(crate::helpers::stacker_labels::SCOPE)
                .map(String::as_str),
            Some("platform")
        );
        assert_eq!(
            npm.labels
                .get(crate::helpers::stacker_labels::SERVICE)
                .map(String::as_str),
            Some("nginx_proxy_manager")
        );
        assert_eq!(
            npm.labels
                .get(crate::helpers::stacker_labels::DNS)
                .map(String::as_str),
            Some("nginx-proxy-manager")
        );
    }

    #[test]
    fn render_includes_kata_runtime() {
        let svc = ComposeService {
            name: "web".to_string(),
            image: Some("nginx:latest".to_string()),
            runtime: Some("kata".to_string()),
            ..Default::default()
        };
        let def = ComposeDefinition {
            services: vec![svc],
            networks: vec!["app-network".to_string()],
            volumes: vec![],
        };
        let output = def.render();
        assert!(
            output.contains("runtime: kata"),
            "Expected 'runtime: kata' in:\n{}",
            output
        );
    }

    #[test]
    fn render_excludes_runc_runtime() {
        let svc = ComposeService {
            name: "web".to_string(),
            image: Some("nginx:latest".to_string()),
            runtime: Some("runc".to_string()),
            ..Default::default()
        };
        let def = ComposeDefinition {
            services: vec![svc],
            networks: vec!["app-network".to_string()],
            volumes: vec![],
        };
        let output = def.render();
        assert!(
            !output.contains("runtime:"),
            "runc runtime should not appear in:\n{}",
            output
        );
    }

    #[test]
    fn render_excludes_runtime_when_none() {
        let svc = ComposeService {
            name: "web".to_string(),
            image: Some("nginx:latest".to_string()),
            runtime: None,
            ..Default::default()
        };
        let def = ComposeDefinition {
            services: vec![svc],
            networks: vec!["app-network".to_string()],
            volumes: vec![],
        };
        let output = def.render();
        assert!(
            !output.contains("runtime:"),
            "No runtime should appear in:\n{}",
            output
        );
    }
}
