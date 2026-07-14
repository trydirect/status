//! SSH client for remote server validation
//!
//! Uses russh to connect to servers and execute system check commands.

use base64::{engine::general_purpose, Engine as _};
use russh::client::{Config, Handle};
use russh::keys::key::PrivateKeyWithHashAlg;
use russh::keys::PrivateKey;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

/// Result of a full system check via SSH
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemCheckResult {
    /// SSH connection was successful
    pub connected: bool,
    /// SSH authentication was successful
    pub authenticated: bool,
    /// Username from whoami
    pub username: Option<String>,
    /// Total disk space in GB
    pub disk_total_gb: Option<f64>,
    /// Available disk space in GB
    pub disk_available_gb: Option<f64>,
    /// Disk usage percentage
    pub disk_usage_percent: Option<f64>,
    /// Docker is installed
    pub docker_installed: bool,
    /// Docker version string
    pub docker_version: Option<String>,
    /// OS name (from /etc/os-release)
    pub os_name: Option<String>,
    /// OS version
    pub os_version: Option<String>,
    /// Total memory in MB
    pub memory_total_mb: Option<u64>,
    /// Available memory in MB
    pub memory_available_mb: Option<u64>,
    /// Error message if validation failed
    pub error: Option<String>,
}

impl Default for SystemCheckResult {
    fn default() -> Self {
        Self {
            connected: false,
            authenticated: false,
            username: None,
            disk_total_gb: None,
            disk_available_gb: None,
            disk_usage_percent: None,
            docker_installed: false,
            docker_version: None,
            os_name: None,
            os_version: None,
            memory_total_mb: None,
            memory_available_mb: None,
            error: None,
        }
    }
}

impl SystemCheckResult {
    /// Check if the system meets minimum requirements
    pub fn meets_requirements(&self) -> bool {
        self.connected
            && self.authenticated
            && self.docker_installed
            && self.disk_available_gb.map_or(false, |gb| gb >= 5.0)
    }

    /// Generate a human-readable summary
    pub fn summary(&self) -> String {
        if !self.connected {
            return "Connection failed".to_string();
        }
        if !self.authenticated {
            return "Authentication failed".to_string();
        }

        let mut parts = vec![];

        if let Some(os) = &self.os_name {
            if let Some(ver) = &self.os_version {
                parts.push(format!("{} {}", os, ver));
            } else {
                parts.push(os.clone());
            }
        }

        if let Some(disk) = self.disk_available_gb {
            parts.push(format!("{:.1}GB available", disk));
        }

        if self.docker_installed {
            if let Some(ver) = &self.docker_version {
                parts.push(format!("Docker {}", ver));
            } else {
                parts.push("Docker installed".to_string());
            }
        } else {
            parts.push("Docker NOT installed".to_string());
        }

        if parts.is_empty() {
            "Connected".to_string()
        } else {
            parts.join(", ")
        }
    }
}

/// SSH client handler for russh
struct ClientHandler;

impl russh::client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        // Accept all host keys for server validation
        // In production, consider implementing host key verification
        Ok(true)
    }
}

/// Perform a full system check via SSH
///
/// Connects to the server, authenticates with the provided private key,
/// and runs diagnostic commands to gather system information.
pub async fn check_server(
    host: &str,
    port: u16,
    username: &str,
    private_key_pem: &str,
    connection_timeout: Duration,
) -> SystemCheckResult {
    let mut result = SystemCheckResult::default();

    // Parse the private key
    let key = match parse_private_key(private_key_pem) {
        Ok(k) => k,
        Err(e) => {
            tracing::error!("Failed to parse SSH private key: {}", e);
            result.error = Some(format!("Invalid SSH key: {}", e));
            return result;
        }
    };

    // Build SSH config
    let config = Arc::new(Config {
        ..Default::default()
    });

    // Connect with timeout
    let addr = format!("{}:{}", host, port);
    tracing::info!("Connecting to {} as {}", addr, username);

    let connection_result = timeout(
        connection_timeout,
        connect_and_auth(config, &addr, username, key),
    )
    .await;

    match connection_result {
        Ok(Ok(handle)) => {
            result.connected = true;
            result.authenticated = true;
            tracing::info!("SSH connection established successfully");

            // Run system checks
            run_system_checks(&mut result, handle).await;
        }
        Ok(Err(e)) => {
            tracing::warn!("SSH connection/auth failed: {}", e);
            let error_str = e.to_string().to_lowercase();
            if error_str.contains("auth")
                || error_str.contains("key")
                || error_str.contains("permission")
            {
                result.connected = true;
                result.error = Some(format!("Authentication failed: {}", e));
            } else {
                result.error = Some(format!("Connection failed: {}", e));
            }
        }
        Err(_) => {
            tracing::warn!("SSH connection timed out after {:?}", connection_timeout);
            result.error = Some(format!(
                "Connection timed out after {} seconds",
                connection_timeout.as_secs()
            ));
        }
    }

    result
}

/// Authorize an OpenSSH public key on the remote server using an accepted private key.
pub async fn authorize_public_key(
    host: &str,
    port: u16,
    username: &str,
    private_key_pem: &str,
    public_key: &str,
    connection_timeout: Duration,
) -> Result<(), anyhow::Error> {
    let public_key = public_key.trim();
    if public_key.is_empty() {
        return Err(anyhow::anyhow!("Public key cannot be empty"));
    }

    let key = parse_private_key(private_key_pem)?;
    let config = Arc::new(Config {
        ..Default::default()
    });
    let addr = format!("{}:{}", host, port);

    let handle = timeout(
        connection_timeout,
        connect_and_auth(config, &addr, username, key),
    )
    .await
    .map_err(|_| {
        anyhow::anyhow!(
            "Connection timed out after {} seconds",
            connection_timeout.as_secs()
        )
    })??;

    let encoded_key = general_purpose::STANDARD.encode(public_key.as_bytes());
    let command = format!(
        "set -eu; key=$(printf '%s' '{}' | base64 -d); \
         mkdir -p ~/.ssh; chmod 700 ~/.ssh; \
         touch ~/.ssh/authorized_keys; chmod 600 ~/.ssh/authorized_keys; \
         grep -qxF \"$key\" ~/.ssh/authorized_keys || printf '%s\\n' \"$key\" >> ~/.ssh/authorized_keys",
        encoded_key
    );

    let result = exec_command_checked(&handle, &command).await;
    let _ = handle
        .disconnect(russh::Disconnect::ByApplication, "", "English")
        .await;

    result
}

/// Parse a PEM-encoded private key (OpenSSH or traditional formats)
fn parse_private_key(pem: &str) -> Result<PrivateKey, anyhow::Error> {
    // russh-keys supports various formats including OpenSSH and traditional PEM
    let key = russh::keys::decode_secret_key(pem, None)?;
    Ok(key)
}

async fn exec_command_checked(
    handle: &Handle<ClientHandler>,
    command: &str,
) -> Result<(), anyhow::Error> {
    let mut channel = handle.channel_open_session().await?;
    channel.exec(true, command).await?;

    let mut stderr = Vec::new();
    let mut exit_status = None;
    let timeout_duration = Duration::from_secs(10);

    let read_result = timeout(timeout_duration, async {
        loop {
            match channel.wait().await {
                Some(russh::ChannelMsg::ExtendedData { data, ext: _ }) => {
                    stderr.extend_from_slice(&data);
                }
                Some(russh::ChannelMsg::ExitStatus {
                    exit_status: status,
                }) => {
                    exit_status = Some(status);
                }
                Some(russh::ChannelMsg::Eof) | Some(russh::ChannelMsg::Close) | None => break,
                _ => {}
            }
        }
    })
    .await;

    let _ = channel.eof().await;
    let _ = channel.close().await;

    if read_result.is_err() {
        return Err(anyhow::anyhow!("Remote authorization command timed out"));
    }

    if exit_status.unwrap_or(0) != 0 {
        let stderr = String::from_utf8_lossy(&stderr).trim().to_string();
        let message = if stderr.is_empty() {
            "Remote authorization command failed".to_string()
        } else {
            format!("Remote authorization command failed: {}", stderr)
        };
        return Err(anyhow::anyhow!(message));
    }

    Ok(())
}

/// Connect and authenticate to the SSH server
async fn connect_and_auth(
    config: Arc<Config>,
    addr: &str,
    username: &str,
    key: PrivateKey,
) -> Result<Handle<ClientHandler>, anyhow::Error> {
    let handler = ClientHandler;
    let mut handle = russh::client::connect(config, addr, handler).await?;

    // Authenticate with public key
    let auth_res = handle
        .authenticate_publickey(
            username,
            PrivateKeyWithHashAlg::new(
                Arc::new(key),
                handle.best_supported_rsa_hash().await?.flatten(),
            ),
        )
        .await?;

    if !auth_res.success() {
        return Err(anyhow::anyhow!("Public key authentication failed"));
    }

    Ok(handle)
}

/// Run system check commands and populate the result
async fn run_system_checks(result: &mut SystemCheckResult, handle: Handle<ClientHandler>) {
    // Check username
    if let Ok(output) = exec_command(&handle, "whoami").await {
        result.username = Some(output.trim().to_string());
    }

    // Check disk space (df -BG /)
    if let Ok(output) = exec_command(&handle, "df -BG / 2>/dev/null | tail -1").await {
        parse_disk_info(result, &output);
    }

    // Check Docker
    match exec_command(&handle, "docker --version 2>/dev/null").await {
        Ok(output) if !output.is_empty() && !output.contains("not found") => {
            result.docker_installed = true;
            // Extract version number (e.g., "Docker version 24.0.5, build ced0996")
            if let Some(version) = output
                .strip_prefix("Docker version ")
                .and_then(|s| s.split(',').next())
            {
                result.docker_version = Some(version.trim().to_string());
            }
        }
        _ => {
            result.docker_installed = false;
        }
    }

    // Check OS info
    if let Ok(output) = exec_command(&handle, "cat /etc/os-release 2>/dev/null").await {
        parse_os_info(result, &output);
    }

    // Check memory (free -m)
    if let Ok(output) = exec_command(&handle, "free -m 2>/dev/null | grep -i mem").await {
        parse_memory_info(result, &output);
    }
}

/// Execute a command on the remote server and return stdout
async fn exec_command(
    handle: &Handle<ClientHandler>,
    command: &str,
) -> Result<String, anyhow::Error> {
    let mut channel = handle.channel_open_session().await?;
    channel.exec(true, command).await?;

    let mut output = Vec::new();
    let timeout_duration = Duration::from_secs(10);

    let read_result = timeout(timeout_duration, async {
        loop {
            match channel.wait().await {
                Some(russh::ChannelMsg::Data { data }) => {
                    output.extend_from_slice(&data);
                }
                Some(russh::ChannelMsg::ExtendedData { data, ext: _ }) => {
                    // stderr - ignore for now
                    let _ = data;
                }
                Some(russh::ChannelMsg::Eof) => break,
                Some(russh::ChannelMsg::ExitStatus { exit_status: _ }) => {}
                Some(russh::ChannelMsg::Close) => break,
                None => break,
                _ => {}
            }
        }
    })
    .await;

    if read_result.is_err() {
        tracing::warn!("Command '{}' timed out", command);
    }

    // Close the channel
    let _ = channel.eof().await;
    let _ = channel.close().await;

    Ok(String::from_utf8_lossy(&output).to_string())
}

/// Parse disk info from df output
fn parse_disk_info(result: &mut SystemCheckResult, output: &str) {
    // df -BG output: "Filesystem     1G-blocks  Used Available Use% Mounted on"
    // Example line: "/dev/sda1         50G    20G       28G  42% /"
    let parts: Vec<&str> = output.split_whitespace().collect();
    if parts.len() >= 4 {
        // Parse total (index 1)
        if let Some(total) = parts
            .get(1)
            .and_then(|s| s.trim_end_matches('G').parse::<f64>().ok())
        {
            result.disk_total_gb = Some(total);
        }

        // Parse available (index 3)
        if let Some(avail) = parts
            .get(3)
            .and_then(|s| s.trim_end_matches('G').parse::<f64>().ok())
        {
            result.disk_available_gb = Some(avail);
        }

        // Parse usage percentage (index 4)
        if let Some(usage) = parts
            .get(4)
            .and_then(|s| s.trim_end_matches('%').parse::<f64>().ok())
        {
            result.disk_usage_percent = Some(usage);
        }
    }
}

/// Parse OS info from /etc/os-release
fn parse_os_info(result: &mut SystemCheckResult, output: &str) {
    for line in output.lines() {
        if line.starts_with("NAME=") {
            result.os_name = Some(
                line.trim_start_matches("NAME=")
                    .trim_matches('"')
                    .to_string(),
            );
        } else if line.starts_with("VERSION=") {
            result.os_version = Some(
                line.trim_start_matches("VERSION=")
                    .trim_matches('"')
                    .to_string(),
            );
        } else if line.starts_with("VERSION_ID=") && result.os_version.is_none() {
            result.os_version = Some(
                line.trim_start_matches("VERSION_ID=")
                    .trim_matches('"')
                    .to_string(),
            );
        }
    }
}

/// Parse memory info from free -m output
fn parse_memory_info(result: &mut SystemCheckResult, output: &str) {
    // free -m | grep Mem output: "Mem:          15883        5234        8234         123        2414       10315"
    let parts: Vec<&str> = output.split_whitespace().collect();
    if parts.len() >= 4 {
        // Total memory (index 1)
        if let Some(total) = parts.get(1).and_then(|s| s.parse::<u64>().ok()) {
            result.memory_total_mb = Some(total);
        }

        // Available memory (index 6 in newer free, or calculate from free + buffers/cache)
        // For simplicity, use the "free" column (index 3) + buffers/cache (index 5) if available
        if let Some(avail) = parts.get(6).and_then(|s| s.parse::<u64>().ok()) {
            result.memory_available_mb = Some(avail);
        } else if let Some(free) = parts.get(3).and_then(|s| s.parse::<u64>().ok()) {
            // Fallback to free column
            result.memory_available_mb = Some(free);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_disk_info() {
        let mut result = SystemCheckResult::default();
        parse_disk_info(&mut result, "/dev/sda1         50G    20G       28G  42% /");

        assert_eq!(result.disk_total_gb, Some(50.0));
        assert_eq!(result.disk_available_gb, Some(28.0));
        assert_eq!(result.disk_usage_percent, Some(42.0));
    }

    #[test]
    fn test_parse_os_info() {
        let mut result = SystemCheckResult::default();
        let os_release = r#"NAME="Ubuntu"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
ID=ubuntu
VERSION_ID="22.04"
"#;
        parse_os_info(&mut result, os_release);

        assert_eq!(result.os_name, Some("Ubuntu".to_string()));
        assert_eq!(
            result.os_version,
            Some("22.04.3 LTS (Jammy Jellyfish)".to_string())
        );
    }

    #[test]
    fn test_parse_memory_info() {
        let mut result = SystemCheckResult::default();
        parse_memory_info(
            &mut result,
            "Mem:          15883        5234        8234         123        2414       10315",
        );

        assert_eq!(result.memory_total_mb, Some(15883));
        assert_eq!(result.memory_available_mb, Some(10315));
    }

    #[test]
    fn test_summary() {
        let mut result = SystemCheckResult::default();
        assert_eq!(result.summary(), "Connection failed");

        result.connected = true;
        assert_eq!(result.summary(), "Authentication failed");

        result.authenticated = true;
        result.os_name = Some("Ubuntu".to_string());
        result.os_version = Some("22.04".to_string());
        result.disk_available_gb = Some(50.0);
        result.docker_installed = true;
        result.docker_version = Some("24.0.5".to_string());

        assert_eq!(
            result.summary(),
            "Ubuntu 22.04, 50.0GB available, Docker 24.0.5"
        );
    }
}
