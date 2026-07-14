use std::collections::HashMap;

use crate::cli::config_parser::{DomainConfig, ProxyType, SslMode};
use crate::cli::error::CliError;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// ContainerInfo — minimal container metadata
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Lightweight representation of a running Docker container.
/// Populated by `ContainerRuntime::list_containers()`.
#[derive(Debug, Clone)]
pub struct ContainerInfo {
    pub id: String,
    pub name: String,
    pub image: String,
    pub ports: Vec<u16>,
    pub status: String,
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// ContainerRuntime trait — abstraction over Docker CLI (DIP)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Abstraction for interacting with the local container runtime.
///
/// Production: `DockerCliRuntime` shells out to `docker` / `docker compose`.
/// Tests: `MockContainerRuntime` returns canned data.
///
/// This is the **first** direct Docker CLI interaction in stacker —
/// the server-side code uses agent-mediated command queuing instead.
pub trait ContainerRuntime: Send + Sync {
    fn is_available(&self) -> bool;
    fn list_containers(&self) -> Result<Vec<ContainerInfo>, CliError>;
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// DockerCliRuntime — production implementation
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

pub struct DockerCliRuntime;

impl ContainerRuntime for DockerCliRuntime {
    fn is_available(&self) -> bool {
        std::process::Command::new("docker")
            .arg("info")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    fn list_containers(&self) -> Result<Vec<ContainerInfo>, CliError> {
        let output = std::process::Command::new("docker")
            .args([
                "ps",
                "--format",
                "{{.ID}}|{{.Names}}|{{.Image}}|{{.Ports}}|{{.Status}}",
            ])
            .output()
            .map_err(|_| CliError::ContainerRuntimeUnavailable)?;

        if !output.status.success() {
            return Err(CliError::ContainerRuntimeUnavailable);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let containers = stdout
            .lines()
            .filter(|line| !line.is_empty())
            .map(parse_docker_ps_line)
            .collect();

        Ok(containers)
    }
}

/// Parse a single line from `docker ps --format "{{.ID}}|{{.Names}}|{{.Image}}|{{.Ports}}|{{.Status}}"`.
fn parse_docker_ps_line(line: &str) -> ContainerInfo {
    let parts: Vec<&str> = line.splitn(5, '|').collect();

    let id = parts.first().unwrap_or(&"").to_string();
    let name = parts.get(1).unwrap_or(&"").to_string();
    let image = parts.get(2).unwrap_or(&"").to_string();
    let ports_str = parts.get(3).unwrap_or(&"");
    let status = parts.get(4).unwrap_or(&"").to_string();

    let ports = extract_host_ports(ports_str);

    ContainerInfo {
        id,
        name,
        image,
        ports,
        status,
    }
}

/// Extract host-side port numbers from Docker port mapping strings like
/// `0.0.0.0:80->80/tcp, 0.0.0.0:443->443/tcp`.
fn extract_host_ports(ports_str: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    for part in ports_str.split(',') {
        let part = part.trim();
        // Format: "0.0.0.0:HOST_PORT->CONTAINER_PORT/proto" or "HOST_PORT->CONTAINER_PORT/proto"
        if let Some(arrow_idx) = part.find("->") {
            let before_arrow = &part[..arrow_idx];
            // Get the port number after the last ':'
            if let Some(port_str) = before_arrow.rsplit(':').next() {
                if let Ok(port) = port_str.parse::<u16>() {
                    if !ports.contains(&port) {
                        ports.push(port);
                    }
                }
            }
        }
    }
    ports
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// ProxyDetection — result of scanning running containers
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Result of scanning local containers for a running reverse proxy.
#[derive(Debug, Clone, PartialEq)]
pub struct ProxyDetection {
    pub proxy_type: ProxyType,
    pub container_name: Option<String>,
    pub ports: Vec<u16>,
}

impl Default for ProxyDetection {
    fn default() -> Self {
        Self {
            proxy_type: ProxyType::None,
            container_name: None,
            ports: Vec::new(),
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// detect_proxy — scan running containers for a reverse proxy
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Known proxy image prefixes and their corresponding type.
const PROXY_SIGNATURES: &[(&str, ProxyType)] = &[
    ("jc21/nginx-proxy-manager", ProxyType::NginxProxyManager),
    ("nginx-proxy-manager", ProxyType::NginxProxyManager),
    ("traefik", ProxyType::Traefik),
    ("nginx", ProxyType::Nginx),
];

/// Scan running containers to find a reverse proxy.
///
/// Uses `ContainerRuntime` (DIP) so tests inject `MockContainerRuntime`.
/// NPM detection takes priority over plain nginx because NPM containers
/// also contain "nginx" in their image name.
pub fn detect_proxy(runtime: &dyn ContainerRuntime) -> Result<ProxyDetection, CliError> {
    if !runtime.is_available() {
        return Err(CliError::ContainerRuntimeUnavailable);
    }

    let containers = runtime.list_containers()?;

    for (signature, proxy_type) in PROXY_SIGNATURES {
        for container in &containers {
            if container.image.contains(signature) || container.name.contains(signature) {
                return Ok(ProxyDetection {
                    proxy_type: *proxy_type,
                    container_name: Some(container.name.clone()),
                    ports: container.ports.clone(),
                });
            }
        }
    }

    Ok(ProxyDetection::default())
}

/// Detect a reverse proxy from an agent snapshot JSON value.
///
/// The snapshot contains a `"containers"` array with objects like:
/// `{ "name": "...", "image": "...", "state": "running", ... }`
///
/// Uses the same `PROXY_SIGNATURES` as local detection.
pub fn detect_proxy_from_snapshot(snapshot: &serde_json::Value) -> ProxyDetection {
    let containers = match snapshot.get("containers").and_then(|v| v.as_array()) {
        Some(arr) => arr,
        None => return ProxyDetection::default(),
    };

    for (signature, proxy_type) in PROXY_SIGNATURES {
        for c in containers {
            let image = c.get("image").and_then(|v| v.as_str()).unwrap_or("");
            let name = c.get("name").and_then(|v| v.as_str()).unwrap_or("");

            if image.contains(signature) || name.contains(signature) {
                // Try to extract ports from the snapshot container object.
                // The agent may report ports as an array of numbers, an array of
                // strings like "80/tcp", or a "ports" string. Be lenient.
                let ports = extract_snapshot_ports(c);

                return ProxyDetection {
                    proxy_type: *proxy_type,
                    container_name: Some(name.to_string()),
                    ports,
                };
            }
        }
    }

    ProxyDetection::default()
}

/// Best-effort port extraction from an agent snapshot container object.
fn extract_snapshot_ports(container: &serde_json::Value) -> Vec<u16> {
    let mut ports = Vec::new();

    if let Some(arr) = container.get("ports").and_then(|v| v.as_array()) {
        for p in arr {
            if let Some(n) = p.as_u64() {
                if n <= u16::MAX as u64 {
                    ports.push(n as u16);
                }
            } else if let Some(s) = p.as_str() {
                // e.g. "80/tcp" or "0.0.0.0:81->81/tcp"
                if let Some(arrow_idx) = s.find("->") {
                    let before = &s[..arrow_idx];
                    if let Some(port_str) = before.rsplit(':').next() {
                        if let Ok(port) = port_str.parse::<u16>() {
                            if !ports.contains(&port) {
                                ports.push(port);
                            }
                        }
                    }
                } else if let Ok(port) = s.split('/').next().unwrap_or("").parse::<u16>() {
                    if !ports.contains(&port) {
                        ports.push(port);
                    }
                }
            }
        }
    }

    ports
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// generate_nginx_server_block — produce nginx config snippet
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

fn validate_domain(domain: &str) -> Result<(), CliError> {
    let re = regex::Regex::new(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$").unwrap();
    if !re.is_match(domain) {
        return Err(CliError::ConfigValidation(format!(
            "Invalid domain '{}': must contain only alphanumeric, dots, hyphens, underscores",
            domain
        )));
    }
    Ok(())
}

fn validate_upstream(upstream: &str) -> Result<(), CliError> {
    // Allow optional http:// or https:// prefix
    let re = regex::Regex::new(r"^(https?://)?[a-zA-Z0-9._-]+:[0-9]+$").unwrap();
    if !re.is_match(upstream) {
        return Err(CliError::ConfigValidation(format!(
            "Invalid upstream '{}': must match [http://]host:port format",
            upstream
        )));
    }
    Ok(())
}

/// Generate an nginx `server { }` block for a single domain configuration.
///
/// Produces a config suitable for inclusion in `/etc/nginx/conf.d/`.
/// SSL directives are included when `ssl` is `Auto` or `Manual`.
pub fn generate_nginx_server_block(domain: &DomainConfig) -> Result<String, CliError> {
    validate_domain(&domain.domain)?;
    validate_upstream(&domain.upstream)?;
    let mut block = String::new();
    let proxy_pass = proxy_pass_target(&domain.upstream);

    block.push_str("server {\n");

    match domain.ssl {
        SslMode::Auto | SslMode::Manual => {
            block.push_str("    listen 80;\n");
            block.push_str(&format!("    server_name {};\n", domain.domain));
            block.push_str("\n");
            block.push_str("    location / {\n");
            block.push_str(&format!(
                "        return 301 https://{}$request_uri;\n",
                domain.domain
            ));
            block.push_str("    }\n");
            block.push_str("}\n\n");

            block.push_str("server {\n");
            block.push_str("    listen 443 ssl http2;\n");
            block.push_str(&format!("    server_name {};\n", domain.domain));
            block.push_str("\n");

            if domain.ssl == SslMode::Auto {
                block.push_str(&format!(
                    "    ssl_certificate /etc/letsencrypt/live/{}/fullchain.pem;\n",
                    domain.domain
                ));
                block.push_str(&format!(
                    "    ssl_certificate_key /etc/letsencrypt/live/{}/privkey.pem;\n",
                    domain.domain
                ));
            } else {
                block.push_str("    ssl_certificate /etc/nginx/ssl/cert.pem;\n");
                block.push_str("    ssl_certificate_key /etc/nginx/ssl/key.pem;\n");
            }

            block.push_str("\n");
            block.push_str("    location / {\n");
            block.push_str(&format!("        proxy_pass {};\n", proxy_pass));
            block.push_str("        proxy_set_header Host $host;\n");
            block.push_str("        proxy_set_header X-Real-IP $remote_addr;\n");
            block
                .push_str("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n");
            block.push_str("        proxy_set_header X-Forwarded-Proto $scheme;\n");
            block.push_str("    }\n");
            block.push_str("}\n");
        }
        SslMode::Off => {
            block.push_str("    listen 80;\n");
            block.push_str(&format!("    server_name {};\n", domain.domain));
            block.push_str("\n");
            block.push_str("    location / {\n");
            block.push_str(&format!("        proxy_pass {};\n", proxy_pass));
            block.push_str("        proxy_set_header Host $host;\n");
            block.push_str("        proxy_set_header X-Real-IP $remote_addr;\n");
            block
                .push_str("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n");
            block.push_str("        proxy_set_header X-Forwarded-Proto $scheme;\n");
            block.push_str("    }\n");
            block.push_str("}\n");
        }
    }

    Ok(block)
}

fn proxy_pass_target(upstream: &str) -> String {
    if upstream.starts_with("http://") || upstream.starts_with("https://") {
        upstream.to_string()
    } else {
        format!("http://{}", upstream)
    }
}

/// Generate nginx configs for all domains in a proxy config.
/// Returns a map of `filename → config content` for writing to `./nginx/conf.d/`.
pub fn generate_nginx_configs(
    domains: &[DomainConfig],
) -> Result<HashMap<String, String>, CliError> {
    let mut configs = HashMap::new();

    for domain in domains {
        let filename = format!("{}.conf", domain.domain.replace('.', "_").replace('/', "_"));
        let content = generate_nginx_server_block(domain)?;
        configs.insert(filename, content);
    }

    Ok(configs)
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Tests
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[cfg(test)]
mod tests {
    use super::*;

    // ── Mock container runtime ──────────────────────

    struct MockContainerRuntime {
        available: bool,
        containers: Vec<ContainerInfo>,
    }

    impl MockContainerRuntime {
        fn available_with(containers: Vec<ContainerInfo>) -> Self {
            Self {
                available: true,
                containers,
            }
        }

        fn unavailable() -> Self {
            Self {
                available: false,
                containers: Vec::new(),
            }
        }
    }

    impl ContainerRuntime for MockContainerRuntime {
        fn is_available(&self) -> bool {
            self.available
        }

        fn list_containers(&self) -> Result<Vec<ContainerInfo>, CliError> {
            Ok(self.containers.clone())
        }
    }

    fn nginx_container() -> ContainerInfo {
        ContainerInfo {
            id: "abc123".to_string(),
            name: "nginx-proxy".to_string(),
            image: "nginx:alpine".to_string(),
            ports: vec![80, 443],
            status: "Up 2 hours".to_string(),
        }
    }

    fn npm_container() -> ContainerInfo {
        ContainerInfo {
            id: "def456".to_string(),
            name: "npm".to_string(),
            image: "jc21/nginx-proxy-manager:latest".to_string(),
            ports: vec![80, 443, 81],
            status: "Up 5 hours".to_string(),
        }
    }

    fn traefik_container() -> ContainerInfo {
        ContainerInfo {
            id: "ghi789".to_string(),
            name: "traefik".to_string(),
            image: "traefik:v2.10".to_string(),
            ports: vec![80, 443, 8080],
            status: "Up 1 hour".to_string(),
        }
    }

    fn app_container() -> ContainerInfo {
        ContainerInfo {
            id: "xyz999".to_string(),
            name: "my-app".to_string(),
            image: "myapp:latest".to_string(),
            ports: vec![3000],
            status: "Up 30 minutes".to_string(),
        }
    }

    // ── Proxy detection tests ───────────────────────

    #[test]
    fn test_detect_proxy_nginx_from_containers() {
        let runtime =
            MockContainerRuntime::available_with(vec![app_container(), nginx_container()]);
        let detection = detect_proxy(&runtime).unwrap();
        assert_eq!(detection.proxy_type, ProxyType::Nginx);
        assert_eq!(detection.container_name.as_deref(), Some("nginx-proxy"));
        assert!(detection.ports.contains(&80));
        assert!(detection.ports.contains(&443));
    }

    #[test]
    fn test_detect_proxy_npm_from_containers() {
        let runtime = MockContainerRuntime::available_with(vec![app_container(), npm_container()]);
        let detection = detect_proxy(&runtime).unwrap();
        assert_eq!(detection.proxy_type, ProxyType::NginxProxyManager);
        assert!(detection.ports.contains(&81));
    }

    #[test]
    fn test_detect_proxy_traefik_from_containers() {
        let runtime = MockContainerRuntime::available_with(vec![traefik_container()]);
        let detection = detect_proxy(&runtime).unwrap();
        assert_eq!(detection.proxy_type, ProxyType::Traefik);
        assert_eq!(detection.container_name.as_deref(), Some("traefik"));
    }

    #[test]
    fn test_detect_no_proxy() {
        let runtime = MockContainerRuntime::available_with(vec![app_container()]);
        let detection = detect_proxy(&runtime).unwrap();
        assert_eq!(detection.proxy_type, ProxyType::None);
        assert!(detection.container_name.is_none());
    }

    #[test]
    fn test_detect_npm_takes_priority_over_nginx() {
        // NPM containers contain "nginx" in their image. NPM must be detected
        // first because its signature is checked before plain "nginx".
        let runtime =
            MockContainerRuntime::available_with(vec![npm_container(), nginx_container()]);
        let detection = detect_proxy(&runtime).unwrap();
        assert_eq!(detection.proxy_type, ProxyType::NginxProxyManager);
    }

    #[test]
    fn test_detect_proxy_docker_unavailable() {
        let runtime = MockContainerRuntime::unavailable();
        let result = detect_proxy(&runtime);
        assert!(result.is_err());
    }

    // ── nginx config generation tests ───────────────

    #[test]
    fn test_generate_nginx_server_block_ssl_auto() {
        let domain = DomainConfig {
            domain: "app.example.com".to_string(),
            ssl: SslMode::Auto,
            upstream: "app:3000".to_string(),
        };
        let block = generate_nginx_server_block(&domain).unwrap();
        assert!(block.contains("server_name app.example.com;"));
        assert!(block.contains("listen 443 ssl http2;"));
        assert!(block.contains("proxy_pass http://app:3000;"));
        assert!(block.contains("letsencrypt"));
        assert!(block.contains("return 301 https://"));
    }

    #[test]
    fn test_generate_nginx_server_block_ssl_manual() {
        let domain = DomainConfig {
            domain: "app.example.com".to_string(),
            ssl: SslMode::Manual,
            upstream: "app:3000".to_string(),
        };
        let block = generate_nginx_server_block(&domain).unwrap();
        assert!(block.contains("listen 443 ssl http2;"));
        assert!(block.contains("/etc/nginx/ssl/cert.pem"));
        assert!(!block.contains("letsencrypt"));
    }

    #[test]
    fn test_generate_nginx_server_block_no_ssl() {
        let domain = DomainConfig {
            domain: "app.local".to_string(),
            ssl: SslMode::Off,
            upstream: "app:8080".to_string(),
        };
        let block = generate_nginx_server_block(&domain).unwrap();
        assert!(block.contains("listen 80;"));
        assert!(block.contains("server_name app.local;"));
        assert!(block.contains("proxy_pass http://app:8080;"));
        assert!(!block.contains("ssl"));
        assert!(!block.contains("443"));
    }

    #[test]
    fn test_generate_nginx_server_block_keeps_upstream_scheme() {
        let domain = DomainConfig {
            domain: "app.local".to_string(),
            ssl: SslMode::Off,
            upstream: "http://app:8080".to_string(),
        };
        let block = generate_nginx_server_block(&domain).unwrap();
        assert!(block.contains("proxy_pass http://app:8080;"));
        assert!(!block.contains("proxy_pass http://http://app:8080;"));
    }

    #[test]
    fn test_generate_nginx_configs_multiple_domains() {
        let domains = vec![
            DomainConfig {
                domain: "api.example.com".to_string(),
                ssl: SslMode::Auto,
                upstream: "api:4000".to_string(),
            },
            DomainConfig {
                domain: "web.example.com".to_string(),
                ssl: SslMode::Off,
                upstream: "web:3000".to_string(),
            },
        ];
        let configs = generate_nginx_configs(&domains).unwrap();
        assert_eq!(configs.len(), 2);
        assert!(configs.contains_key("api_example_com.conf"));
        assert!(configs.contains_key("web_example_com.conf"));
    }

    // ── Port parsing tests ──────────────────────────

    #[test]
    fn test_extract_host_ports_standard() {
        let ports = extract_host_ports("0.0.0.0:80->80/tcp, 0.0.0.0:443->443/tcp");
        assert_eq!(ports, vec![80, 443]);
    }

    #[test]
    fn test_extract_host_ports_different_host_container() {
        let ports = extract_host_ports("0.0.0.0:8080->80/tcp");
        assert_eq!(ports, vec![8080]);
    }

    #[test]
    fn test_extract_host_ports_empty() {
        let ports = extract_host_ports("");
        assert!(ports.is_empty());
    }

    #[test]
    fn test_extract_host_ports_no_arrow() {
        let ports = extract_host_ports("80/tcp");
        assert!(ports.is_empty());
    }

    // ── Docker ps line parsing tests ────────────────

    #[test]
    fn test_parse_docker_ps_line() {
        let line =
            "abc123|my-nginx|nginx:alpine|0.0.0.0:80->80/tcp, 0.0.0.0:443->443/tcp|Up 2 hours";
        let info = parse_docker_ps_line(line);
        assert_eq!(info.id, "abc123");
        assert_eq!(info.name, "my-nginx");
        assert_eq!(info.image, "nginx:alpine");
        assert_eq!(info.ports, vec![80, 443]);
        assert_eq!(info.status, "Up 2 hours");
    }

    #[test]
    fn test_parse_docker_ps_line_no_ports() {
        let line = "def456|app||Running|Up 5 min";
        let info = parse_docker_ps_line(line);
        assert_eq!(info.name, "app");
        assert!(info.ports.is_empty());
    }

    // ── Snapshot-based proxy detection tests ────────

    #[test]
    fn test_detect_from_snapshot_npm() {
        let snap = serde_json::json!({
            "containers": [
                {
                    "name": "npm-app",
                    "image": "jc21/nginx-proxy-manager:2.11",
                    "state": "running",
                    "ports": [80, 443, 81]
                },
                {
                    "name": "my-app",
                    "image": "myapp:latest",
                    "state": "running"
                }
            ]
        });
        let detection = detect_proxy_from_snapshot(&snap);
        assert_eq!(detection.proxy_type, ProxyType::NginxProxyManager);
        assert_eq!(detection.container_name.as_deref(), Some("npm-app"));
        assert!(detection.ports.contains(&81));
    }

    #[test]
    fn test_detect_from_snapshot_traefik() {
        let snap = serde_json::json!({
            "containers": [
                {
                    "name": "traefik-proxy",
                    "image": "traefik:v3.0",
                    "state": "running",
                    "ports": [80, 443, 8080]
                }
            ]
        });
        let detection = detect_proxy_from_snapshot(&snap);
        assert_eq!(detection.proxy_type, ProxyType::Traefik);
    }

    #[test]
    fn test_detect_from_snapshot_none() {
        let snap = serde_json::json!({
            "containers": [
                {
                    "name": "my-app",
                    "image": "myapp:latest",
                    "state": "running"
                }
            ]
        });
        let detection = detect_proxy_from_snapshot(&snap);
        assert_eq!(detection.proxy_type, ProxyType::None);
    }

    #[test]
    fn test_detect_from_snapshot_empty() {
        let snap = serde_json::json!({});
        let detection = detect_proxy_from_snapshot(&snap);
        assert_eq!(detection.proxy_type, ProxyType::None);
    }

    #[test]
    fn test_detect_from_snapshot_string_ports() {
        let snap = serde_json::json!({
            "containers": [
                {
                    "name": "npm",
                    "image": "jc21/nginx-proxy-manager:latest",
                    "state": "running",
                    "ports": ["80/tcp", "443/tcp", "81/tcp"]
                }
            ]
        });
        let detection = detect_proxy_from_snapshot(&snap);
        assert_eq!(detection.proxy_type, ProxyType::NginxProxyManager);
        assert_eq!(detection.ports, vec![80, 443, 81]);
    }

    #[test]
    fn test_detect_from_snapshot_name_match() {
        // Container name contains the signature, even if image doesn't
        let snap = serde_json::json!({
            "containers": [
                {
                    "name": "nginx-proxy-manager-app-1",
                    "image": "custom-npm:v1",
                    "state": "running",
                    "ports": [80, 81]
                }
            ]
        });
        let detection = detect_proxy_from_snapshot(&snap);
        assert_eq!(detection.proxy_type, ProxyType::NginxProxyManager);
    }

    // ── SECURITY: nginx config injection ──────────────
    // CWE-74: Improper Neutralization of Special Elements in Output
    //
    // The domain name and upstream are interpolated directly into nginx
    // config without sanitization. A malicious domain or upstream value
    // can inject arbitrary nginx directives.

    #[test]
    fn test_nginx_config_rejects_injection_via_domain_name() {
        let domain = DomainConfig {
            domain: "evil.com; location /admin { return 200 'pwned'; }".to_string(),
            ssl: SslMode::Off,
            upstream: "app:3000".to_string(),
        };
        let result = generate_nginx_server_block(&domain);
        assert!(
            result.is_err(),
            "Domain with special chars must be rejected"
        );
    }

    #[test]
    fn test_nginx_config_rejects_injection_via_upstream() {
        let domain = DomainConfig {
            domain: "safe.example.com".to_string(),
            ssl: SslMode::Off,
            upstream: "app:3000;\n        add_header X-Injected true".to_string(),
        };
        let result = generate_nginx_server_block(&domain);
        assert!(
            result.is_err(),
            "Upstream with special chars must be rejected"
        );
    }

    #[test]
    fn test_nginx_configs_rejects_domain_with_slashes() {
        let domains = vec![DomainConfig {
            domain: "../../../etc/nginx/evil".to_string(),
            ssl: SslMode::Off,
            upstream: "app:3000".to_string(),
        }];
        let result = generate_nginx_configs(&domains);
        assert!(result.is_err(), "Domain with slashes must be rejected");
    }
}
