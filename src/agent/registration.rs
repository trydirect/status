use serde::{Deserialize, Serialize};
use std::path::Path;
use tracing::{debug, info};

#[derive(Debug, Serialize)]
pub struct RegistrationRequest {
    pub purchase_token: String,
    pub server_fingerprint: ServerFingerprint,
    pub stack_id: String,
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

    let url = format!("{}/api/v1/agents/register", dashboard_url);
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
}
