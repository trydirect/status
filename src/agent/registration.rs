use serde::{Deserialize, Serialize};
use std::path::Path;
use tracing::{debug, info};

const STATUS_PANEL_CAPABILITY: &str = "status_panel";
const NPM_CREDENTIAL_SOURCE_VAULT: &str = "npm_credential_source=vault";

#[derive(Debug, Serialize)]
pub struct RegistrationRequest {
    pub purchase_token: String,
    pub server_fingerprint: ServerFingerprint,
    pub stack_id: String,
}

// ---- Login-based linking types (Entry Point C) ----

#[derive(Debug, Serialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoginResponse {
    pub session_token: String,
    pub user_id: String,
    pub deployments: Vec<DeploymentInfo>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DeploymentInfo {
    pub deployment_id: String,
    pub stack_name: String,
    pub status: String,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub server_ip: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct LinkAgentRequest {
    pub session_token: String,
    pub deployment_id: String,
    pub server_fingerprint: ServerFingerprint,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ServerFingerprint {
    pub hostname: String,
    pub os: String,
    pub cpu_count: u32,
    pub ram_mb: u64,
    pub disk_gb: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RegistrationResponse {
    pub agent_id: String,
    pub agent_token: String,
    pub deployment_hash: String,
    pub dashboard_url: Option<String>,
}

/// Collect server fingerprint from the local system.
pub fn collect_fingerprint() -> ServerFingerprint {
    let hostname = std::env::var("HOSTNAME")
        .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()))
        .unwrap_or_else(|_| "unknown".to_string());

    let os = std::process::Command::new("uname")
        .arg("-sr")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let cpu_count = std::fs::read_to_string("/proc/cpuinfo")
        .map(|content| {
            content
                .lines()
                .filter(|line| line.starts_with("processor"))
                .count() as u32
        })
        .unwrap_or(1);

    let ram_mb = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|content| {
            content.lines().find_map(|line| {
                if line.starts_with("MemTotal:") {
                    // Format: "MemTotal:       16384000 kB"
                    line.split_whitespace()
                        .nth(1)
                        .and_then(|v| v.parse::<u64>().ok())
                        .map(|kb| kb / 1024)
                } else {
                    None
                }
            })
        })
        .unwrap_or(0);

    let disk_gb = std::process::Command::new("df")
        .args(["--output=size", "-BG", "/"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| {
            s.lines()
                .nth(1) // skip header
                .and_then(|line| line.trim().trim_end_matches('G').parse::<u64>().ok())
        })
        .unwrap_or(0);

    ServerFingerprint {
        hostname,
        os,
        cpu_count,
        ram_mb,
        disk_gb,
    }
}

pub async fn collect_capabilities(default_compose_agent_enabled: bool) -> Vec<String> {
    let compose_agent = std::env::var("COMPOSE_AGENT_ENABLED")
        .ok()
        .and_then(|value| value.parse::<bool>().ok())
        .unwrap_or(default_compose_agent_enabled);

    let mut features = vec![
        STATUS_PANEL_CAPABILITY.to_string(),
        "monitoring".to_string(),
        NPM_CREDENTIAL_SOURCE_VAULT.to_string(),
    ];

    if cfg!(feature = "docker") {
        features.push("docker".to_string());
        features.push("compose".to_string());
        features.push("logs".to_string());
        features.push("restart".to_string());
    }

    if compose_agent {
        features.push("compose_agent".to_string());
    }

    #[cfg(feature = "docker")]
    {
        if crate::commands::stacker::detect_kata_runtime().await {
            features.push("kata".to_string());
        }
    }

    features
}

fn marketplace_registration_url(dashboard_url: &str) -> String {
    format!(
        "{}/api/v1/marketplace/agents/register",
        dashboard_url.trim_end_matches('/')
    )
}

fn agent_link_url(stacker_url: &str) -> String {
    format!("{}/api/v1/agent/link", stacker_url.trim_end_matches('/'))
}

fn agent_login_url(stacker_url: &str) -> String {
    format!("{}/api/v1/agent/login", stacker_url.trim_end_matches('/'))
}

/// Register this agent with the Stacker Server using a purchase token.
pub async fn register_with_stacker(
    dashboard_url: &str,
    purchase_token: &str,
    stack_id: &str,
) -> Result<RegistrationResponse, Box<dyn std::error::Error>> {
    let fingerprint = collect_fingerprint();
    debug!(
        hostname = %fingerprint.hostname,
        os = %fingerprint.os,
        cpu_count = %fingerprint.cpu_count,
        ram_mb = %fingerprint.ram_mb,
        disk_gb = %fingerprint.disk_gb,
        "collected server fingerprint"
    );

    let body = RegistrationRequest {
        purchase_token: purchase_token.to_string(),
        server_fingerprint: fingerprint,
        stack_id: stack_id.to_string(),
    };

    let url = marketplace_registration_url(dashboard_url);
    info!(url = %url, stack_id = %stack_id, "sending registration request to Stacker");

    let client = reqwest::Client::new();
    let resp = client.post(&url).json(&body).send().await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let err_body = resp.text().await.unwrap_or_default();
        return Err(format!("Registration failed ({}): {}", status, err_body).into());
    }

    let reg: RegistrationResponse = resp.json().await?;
    info!(
        agent_id = %reg.agent_id,
        deployment_hash = %reg.deployment_hash,
        "registration successful"
    );
    Ok(reg)
}

/// Save registration result to a local JSON file so the daemon can use it on next start.
pub fn save_registration(
    path: &Path,
    reg: &RegistrationResponse,
) -> Result<(), Box<dyn std::error::Error>> {
    let content = serde_json::json!({
        "agent_id": reg.agent_id,
        "agent_token": reg.agent_token,
        "deployment_hash": reg.deployment_hash,
        "dashboard_url": reg.dashboard_url,
    });
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(&content)?)?;
    info!(path = %path.display(), "registration saved to disk");
    Ok(())
}

/// Login to TryDirect via Stacker Server proxy. Returns session token and user's deployments.
pub async fn login_to_stacker(
    stacker_url: &str,
    email: &str,
    password: &str,
) -> Result<LoginResponse, Box<dyn std::error::Error>> {
    let body = LoginRequest {
        email: email.to_string(),
        password: password.to_string(),
    };

    let url = agent_login_url(stacker_url);
    info!(url = %url, email = %email, "sending login request to Stacker");

    let client = reqwest::Client::new();
    let resp = client.post(&url).json(&body).send().await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let err_body = resp.text().await.unwrap_or_default();
        return Err(format!("Login failed ({}): {}", status, err_body).into());
    }

    let login: LoginResponse = resp.json().await?;
    info!(
        user_id = %login.user_id,
        deployments = login.deployments.len(),
        "login successful, fetched deployments"
    );
    Ok(login)
}

/// Link this agent to a specific deployment using a session token (user already authenticated).
pub async fn link_agent_to_deployment(
    stacker_url: &str,
    session_token: &str,
    deployment_id: &str,
    default_compose_agent_enabled: bool,
) -> Result<RegistrationResponse, Box<dyn std::error::Error>> {
    let fingerprint = collect_fingerprint();
    let capabilities = collect_capabilities(default_compose_agent_enabled).await;
    debug!(
        hostname = %fingerprint.hostname,
        deployment_id = %deployment_id,
        "linking agent to deployment"
    );

    let body = LinkAgentRequest {
        session_token: session_token.to_string(),
        deployment_id: deployment_id.to_string(),
        server_fingerprint: fingerprint,
        capabilities,
    };

    let url = agent_link_url(stacker_url);
    info!(url = %url, deployment_id = %deployment_id, "sending link request to Stacker");

    let client = reqwest::Client::new();
    let resp = client.post(&url).json(&body).send().await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let err_body = resp.text().await.unwrap_or_default();
        return Err(format!("Agent linking failed ({}): {}", status, err_body).into());
    }

    let reg: RegistrationResponse = resp.json().await?;
    info!(
        agent_id = %reg.agent_id,
        deployment_hash = %reg.deployment_hash,
        "agent linked to deployment"
    );
    Ok(reg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collect_fingerprint_does_not_panic() {
        let fp = collect_fingerprint();
        // hostname should be non-empty on any system
        assert!(!fp.os.is_empty() || fp.os == "unknown");
    }

    #[test]
    fn test_save_registration_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("registration.json");

        let reg = RegistrationResponse {
            agent_id: "agent-123".to_string(),
            agent_token: "tok-secret".to_string(),
            deployment_hash: "hash-abc".to_string(),
            dashboard_url: Some("https://stacker.try.direct".to_string()),
        };

        save_registration(&path, &reg).unwrap();

        let raw = std::fs::read_to_string(&path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(parsed["agent_id"], "agent-123");
        assert_eq!(parsed["agent_token"], "tok-secret");
        assert_eq!(parsed["deployment_hash"], "hash-abc");
        assert_eq!(parsed["dashboard_url"], "https://stacker.try.direct");
    }

    #[test]
    fn marketplace_registration_url_uses_marketplace_scope() {
        assert_eq!(
            marketplace_registration_url("https://stacker.try.direct/"),
            "https://stacker.try.direct/api/v1/marketplace/agents/register"
        );
    }

    #[test]
    fn agent_link_url_uses_singular_agent_scope() {
        assert_eq!(
            agent_link_url("https://stacker.try.direct/"),
            "https://stacker.try.direct/api/v1/agent/link"
        );
    }

    #[test]
    fn agent_login_url_uses_agent_scope() {
        assert_eq!(
            agent_login_url("https://stacker.try.direct/"),
            "https://stacker.try.direct/api/v1/agent/login"
        );
    }

    #[tokio::test]
    async fn collect_capabilities_includes_vault_proxy_marker() {
        let capabilities = collect_capabilities(false).await;
        assert!(capabilities
            .iter()
            .any(|cap| cap == STATUS_PANEL_CAPABILITY));
        assert!(capabilities
            .iter()
            .any(|cap| cap == NPM_CREDENTIAL_SOURCE_VAULT));
    }
}
