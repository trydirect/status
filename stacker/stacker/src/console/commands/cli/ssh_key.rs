//! SSH key management commands — generate, show (read), upload, and inject keys.
//!
//! All operations call the Stacker server REST API (`/server/{id}/ssh-key/*`)
//! which stores keys in HashiCorp Vault. Requires `stacker login` first.

use std::path::{Path, PathBuf};

use crate::cli::credentials::FileCredentialStore;
use crate::cli::error::CliError;
use crate::cli::runtime::CliRuntime;
use crate::cli::stacker_client::{AuthorizePublicKeyResponse, ServerInfo, StackerClient};
use crate::console::commands::CallableTrait;
use crate::helpers::VaultClient;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// ssh-key generate
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// `stacker ssh-key generate --server-id <ID> [--save-to <PATH>]`
///
/// Generates a new Ed25519 SSH key pair on the server and stores it in Vault.
/// Prints the public key and fingerprint. If Vault storage fails, the server
/// returns the private key inline — use `--save-to` to save it to a local file.
pub struct SshKeyGenerateCommand {
    pub server_id: i32,
    pub save_to: Option<PathBuf>,
}

impl SshKeyGenerateCommand {
    pub fn new(server_id: i32, save_to: Option<PathBuf>) -> Self {
        Self { server_id, save_to }
    }
}

impl CallableTrait for SshKeyGenerateCommand {
    fn call(&self) -> Result<(), Box<dyn std::error::Error>> {
        let server_id = self.server_id;
        let save_to = self.save_to.clone();

        let ctx = CliRuntime::new("ssh-key generate")?;

        ctx.block_on(async {
            let result = ctx.client.generate_ssh_key(server_id).await?;

            println!("✓ SSH key generated for server {}", server_id);
            println!();
            println!("  Public key:");
            println!("    {}", result.public_key);
            if let Some(fp) = &result.fingerprint {
                println!("  Fingerprint: {}", fp);
            }
            println!("  Message: {}", result.message);

            // If the private key was returned (Vault storage failed), offer to save it
            if let Some(private_key) = &result.private_key {
                eprintln!();
                eprintln!("  ⚠ Vault storage failed — private key returned inline.");
                if let Some(path) = save_to {
                    std::fs::write(&path, private_key)?;
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
                    }
                    eprintln!("  ✓ Private key saved to {} (mode 600)", path.display());
                } else {
                    eprintln!("  Use --save-to <path> to save the private key to a file.");
                }
            }

            Ok(())
        })
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// ssh-key show
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// `stacker ssh-key show --server-id <ID> [--json]`
///
/// Retrieves the public SSH key for a server from Vault.
pub struct SshKeyShowCommand {
    pub server_id: i32,
    pub json: bool,
}

impl SshKeyShowCommand {
    pub fn new(server_id: i32, json: bool) -> Self {
        Self { server_id, json }
    }
}

impl CallableTrait for SshKeyShowCommand {
    fn call(&self) -> Result<(), Box<dyn std::error::Error>> {
        let server_id = self.server_id;
        let json = self.json;

        let ctx = CliRuntime::new("ssh-key show")?;

        ctx.block_on(async {
            let result = ctx.client.get_ssh_public_key(server_id).await?;

            if json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("SSH public key for server {}:", server_id);
                println!();
                println!("{}", result.public_key);
                if let Some(fp) = &result.fingerprint {
                    println!();
                    println!("Fingerprint: {}", fp);
                }
            }

            Ok(())
        })
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// ssh-key upload
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// `stacker ssh-key upload --server-id <ID> --public-key <FILE> --private-key <FILE>`
///
/// Uploads an existing SSH key pair to Vault for a server.
pub struct SshKeyUploadCommand {
    pub server_id: i32,
    pub public_key: PathBuf,
    pub private_key: PathBuf,
}

impl SshKeyUploadCommand {
    pub fn new(server_id: i32, public_key: PathBuf, private_key: PathBuf) -> Self {
        Self {
            server_id,
            public_key,
            private_key,
        }
    }
}

impl CallableTrait for SshKeyUploadCommand {
    fn call(&self) -> Result<(), Box<dyn std::error::Error>> {
        let server_id = self.server_id;
        let pub_path = self.public_key.clone();
        let priv_path = self.private_key.clone();

        // Read key files
        let public_key = std::fs::read_to_string(&pub_path).map_err(|e| {
            CliError::Io(std::io::Error::new(
                e.kind(),
                format!("Failed to read public key {}: {}", pub_path.display(), e),
            ))
        })?;
        let private_key = std::fs::read_to_string(&priv_path).map_err(|e| {
            CliError::Io(std::io::Error::new(
                e.kind(),
                format!("Failed to read private key {}: {}", priv_path.display(), e),
            ))
        })?;

        let ctx = CliRuntime::new("ssh-key upload")?;

        ctx.block_on(async {
            let server = ctx
                .client
                .upload_ssh_key(server_id, public_key.trim(), private_key.trim())
                .await?;

            println!("✓ SSH key uploaded for server {}", server_id);
            println!("  Key status: {}", server.key_status);
            if let Some(name) = &server.name {
                println!("  Server: {}", name);
            }
            if let Some(ip) = &server.srv_ip {
                println!("  IP: {}", ip);
            }

            Ok(())
        })
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Local backup key helpers
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone)]
pub struct LocalBackupKeyAuthorization {
    pub private_key_path: PathBuf,
    pub public_key_path: PathBuf,
    pub ssh_command: String,
    pub response: AuthorizePublicKeyResponse,
}

#[derive(Debug, Clone)]
struct LocalBackupKeypair {
    private_key_path: PathBuf,
    public_key_path: PathBuf,
    public_key: String,
}

pub async fn ensure_local_backup_key_authorized(
    client: &StackerClient,
    server: &ServerInfo,
) -> Result<LocalBackupKeyAuthorization, CliError> {
    let keypair = ensure_local_backup_keypair(server.id)?;
    let response = client
        .authorize_ssh_public_key(server.id, keypair.public_key.trim(), None, None)
        .await?;
    let ssh_command = format_ssh_command(
        &keypair.private_key_path,
        &response.ssh_user,
        &response.srv_ip,
        response.ssh_port,
    );

    Ok(LocalBackupKeyAuthorization {
        private_key_path: keypair.private_key_path,
        public_key_path: keypair.public_key_path,
        ssh_command,
        response,
    })
}

fn default_backup_ssh_dir() -> PathBuf {
    FileCredentialStore::default_path()
        .parent()
        .map(|path| path.join("ssh"))
        .unwrap_or_else(|| PathBuf::from("stacker").join("ssh"))
}

fn backup_key_paths_for_server(server_id: i32, ssh_dir: &Path) -> (PathBuf, PathBuf) {
    let private_key_path = ssh_dir.join(format!("server-{}_ed25519", server_id));
    let public_key_path = PathBuf::from(format!("{}.pub", private_key_path.display()));
    (private_key_path, public_key_path)
}

fn ensure_local_backup_keypair(server_id: i32) -> Result<LocalBackupKeypair, CliError> {
    ensure_local_backup_keypair_in_dir(server_id, &default_backup_ssh_dir())
}

fn ensure_local_backup_keypair_in_dir(
    server_id: i32,
    ssh_dir: &Path,
) -> Result<LocalBackupKeypair, CliError> {
    std::fs::create_dir_all(ssh_dir)?;
    set_private_dir_permissions(ssh_dir)?;

    let (private_key_path, public_key_path) = backup_key_paths_for_server(server_id, ssh_dir);

    let public_key = if private_key_path.exists() {
        let private_key = std::fs::read_to_string(&private_key_path).map_err(|e| {
            CliError::Io(std::io::Error::new(
                e.kind(),
                format!(
                    "Failed to read backup SSH key {}: {}",
                    private_key_path.display(),
                    e
                ),
            ))
        })?;
        let public_key = derive_public_key_from_private(&private_key)?;
        write_public_key_file(&public_key_path, &public_key)?;
        public_key
    } else {
        let (public_key, private_key) = VaultClient::generate_ssh_keypair().map_err(|e| {
            CliError::ConfigValidation(format!("Failed to generate local backup SSH key: {}", e))
        })?;
        write_private_key_file(&private_key_path, &private_key)?;
        write_public_key_file(&public_key_path, &public_key)?;
        public_key
    };

    Ok(LocalBackupKeypair {
        private_key_path,
        public_key_path,
        public_key,
    })
}

fn derive_public_key_from_private(private_key: &str) -> Result<String, CliError> {
    let private = ssh_key::PrivateKey::from_openssh(private_key).map_err(|e| {
        CliError::ConfigValidation(format!("Invalid local backup SSH private key: {}", e))
    })?;
    private.public_key().to_openssh().map_err(|e| {
        CliError::ConfigValidation(format!("Failed to derive local backup public key: {}", e))
    })
}

fn write_private_key_file(path: &Path, private_key: &str) -> Result<(), CliError> {
    use std::io::Write;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| {
            CliError::Io(std::io::Error::new(
                e.kind(),
                format!(
                    "Failed to create backup SSH private key {}: {}",
                    path.display(),
                    e
                ),
            ))
        })?;
    file.write_all(private_key.as_bytes())?;
    set_private_file_permissions(path)?;
    Ok(())
}

fn write_public_key_file(path: &Path, public_key: &str) -> Result<(), CliError> {
    std::fs::write(path, format!("{}\n", public_key.trim()))?;
    Ok(())
}

#[cfg(unix)]
fn set_private_dir_permissions(path: &Path) -> Result<(), CliError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_dir_permissions(_path: &Path) -> Result<(), CliError> {
    Ok(())
}

#[cfg(unix)]
fn set_private_file_permissions(path: &Path) -> Result<(), CliError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_file_permissions(_path: &Path) -> Result<(), CliError> {
    Ok(())
}

fn format_ssh_command(private_key_path: &Path, user: &str, host: &str, port: u16) -> String {
    format!(
        "ssh -i {} -p {} {}@{}",
        private_key_path.display(),
        port,
        user,
        host
    )
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// ssh-key inject
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// `stacker ssh-key inject --server-id <ID> --with-key <PATH> [--user <USER>] [--port <PORT>]`
///
/// Fetches the Vault-stored public key for a server and bootstraps it into the
/// server's `~/.ssh/authorized_keys` using a locally-available private key that
/// already works for SSH login.
///
/// Use this to repair a server whose `authorized_keys` doesn't contain the
/// Stacker-managed Vault key (for example after a fresh key generation that
/// failed to inject automatically). If you want Stacker to use your local key
/// pair instead, use `ssh-key upload`.
pub struct SshKeyInjectCommand {
    pub server_id: i32,
    /// Path to a local private key that already grants SSH access to the server.
    pub with_key: PathBuf,
    /// SSH user (default: root)
    pub user: Option<String>,
    /// SSH port override (default: server's stored ssh_port or 22)
    pub port: Option<u16>,
}

impl SshKeyInjectCommand {
    pub fn new(server_id: i32, with_key: PathBuf, user: Option<String>, port: Option<u16>) -> Self {
        Self {
            server_id,
            with_key,
            user,
            port,
        }
    }
}

fn validate_bootstrap_private_key_path(key_path: &Path) -> Result<(), CliError> {
    if key_path.extension().and_then(|ext| ext.to_str()) == Some("pub") {
        return Err(CliError::ConfigValidation(format!(
            "`--with-key` expects a private key file, not a public key: {}. Pass a private key that already grants SSH access to the server.",
            key_path.display()
        )));
    }

    Ok(())
}

impl CallableTrait for SshKeyInjectCommand {
    fn call(&self) -> Result<(), Box<dyn std::error::Error>> {
        let server_id = self.server_id;
        let key_path = self.with_key.clone();
        let override_user = self.user.clone();
        let override_port = self.port;

        validate_bootstrap_private_key_path(&key_path)?;

        // Read the local working private key
        let local_private_key = std::fs::read_to_string(&key_path).map_err(|e| {
            CliError::Io(std::io::Error::new(
                e.kind(),
                format!("Failed to read key file {}: {}", key_path.display(), e),
            ))
        })?;

        let ctx = CliRuntime::new("ssh-key inject")?;

        ctx.block_on(async {
            // Fetch server info to get IP, port, and user
            let servers = ctx.client.list_servers().await?;
            let server_info = servers
                .into_iter()
                .find(|s| s.id == server_id)
                .ok_or_else(|| {
                    CliError::ConfigValidation(format!("Server {} not found", server_id))
                })?;

            let host = server_info
                .srv_ip
                .as_deref()
                .filter(|ip| !ip.is_empty())
                .ok_or_else(|| {
                    CliError::ConfigValidation(format!(
                        "Server {} has no IP address — deploy it first",
                        server_id
                    ))
                })?
                .to_string();

            let port = override_port.unwrap_or_else(|| server_info.ssh_port.unwrap_or(22) as u16);
            let user = override_user
                .or_else(|| server_info.ssh_user.clone())
                .unwrap_or_else(|| "root".to_string());

            // Fetch the vault public key
            let key_resp = ctx.client.get_ssh_public_key(server_id).await?;
            let vault_public_key = key_resp.public_key.trim().to_string();

            println!("Server:     {} (ID {})", host, server_id);
            println!("SSH user:   {}  port: {}", user, port);
            println!(
                "Vault key:  {}",
                &vault_public_key[..vault_public_key.len().min(60)]
            );
            println!();
            println!(
                "Connecting with the bootstrap key to add the Vault key into authorized_keys..."
            );

            inject_key_via_ssh(
                &host,
                port,
                &user,
                local_private_key.trim(),
                &vault_public_key,
            )
            .await
        })
    }
}

/// SSH into the server using `local_private_key` and append `vault_public_key`
/// to `~/.ssh/authorized_keys` if it is not already present.
async fn inject_key_via_ssh(
    host: &str,
    port: u16,
    username: &str,
    local_private_key: &str,
    vault_public_key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use russh::client::{Config, Handle};
    use std::sync::Arc;
    use std::time::Duration;

    struct AcceptAllKeys;

    impl russh::client::Handler for AcceptAllKeys {
        type Error = russh::Error;
        async fn check_server_key(
            &mut self,
            _server_public_key: &russh::keys::PublicKey,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }
    }

    let key = russh::keys::decode_secret_key(local_private_key, None)
        .map_err(|e| CliError::ConfigValidation(format!("Invalid private key: {}", e)))?;

    let config = Arc::new(Config {
        ..Default::default()
    });

    let addr = format!("{}:{}", host, port);
    let mut handle: Handle<AcceptAllKeys> = tokio::time::timeout(
        Duration::from_secs(4),
        russh::client::connect(config, addr, AcceptAllKeys),
    )
    .await
    .map_err(|_| CliError::ConfigValidation(format!("Connection to {}:{} timed out", host, port)))?
    .map_err(|e| CliError::ConfigValidation(format!("Connection failed: {}", e)))?;

    let auth_res = handle
        .authenticate_publickey(
            username,
            russh::keys::key::PrivateKeyWithHashAlg::new(
                Arc::new(key),
                handle
                    .best_supported_rsa_hash()
                    .await
                    .map_err(|e| {
                        CliError::ConfigValidation(format!("RSA hash negotiation failed: {}", e))
                    })?
                    .flatten(),
            ),
        )
        .await
        .map_err(|e| CliError::ConfigValidation(format!("Authentication error: {}", e)))?;

    if !auth_res.success() {
        return Err(Box::new(CliError::ConfigValidation(
            "Authentication failed — the provided private key is not accepted by the server. `ssh-key inject` requires a bootstrap private key that already grants SSH access."
                .to_string(),
        )));
    }

    // Idempotent inject: add key only if not already present
    let safe_key = vault_public_key.replace('\'', r"'\''");
    let cmd = format!(
        "mkdir -p ~/.ssh && chmod 700 ~/.ssh && touch ~/.ssh/authorized_keys && \
         grep -qxF '{}' ~/.ssh/authorized_keys || echo '{}' >> ~/.ssh/authorized_keys",
        safe_key, safe_key
    );

    let mut channel = handle
        .channel_open_session()
        .await
        .map_err(|e| CliError::ConfigValidation(format!("Failed to open SSH channel: {}", e)))?;
    channel
        .exec(true, cmd)
        .await
        .map_err(|e| CliError::ConfigValidation(format!("Failed to exec command: {}", e)))?;

    // Drain channel output
    loop {
        match channel.wait().await {
            Some(russh::ChannelMsg::Eof) | Some(russh::ChannelMsg::Close) | None => break,
            Some(russh::ChannelMsg::ExitStatus { exit_status }) => {
                if exit_status != 0 {
                    return Err(Box::new(CliError::ConfigValidation(format!(
                        "Remote command exited with status {}",
                        exit_status
                    ))));
                }
                break;
            }
            _ => {}
        }
    }

    let _ = channel.eof().await;
    let _ = handle
        .disconnect(russh::Disconnect::ByApplication, "", "English")
        .await;

    println!(
        "✓ Vault public key injected into {}@{}:{} authorized_keys",
        username, host, port
    );
    println!();
    println!("You can now run:  stacker deploy");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        backup_key_paths_for_server, ensure_local_backup_keypair_in_dir, format_ssh_command,
        validate_bootstrap_private_key_path,
    };
    use crate::cli::error::CliError;
    use crate::helpers::VaultClient;
    use std::path::Path;
    use tempfile::TempDir;

    #[test]
    fn rejects_public_key_file_for_ssh_key_inject() {
        let err = validate_bootstrap_private_key_path(Path::new("/tmp/id_ed25519.pub"))
            .expect_err("public key paths must be rejected");

        match err {
            CliError::ConfigValidation(message) => {
                assert!(message.contains("expects a private key file"));
                assert!(message.contains("id_ed25519.pub"));
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn accepts_private_key_file_for_ssh_key_inject() {
        validate_bootstrap_private_key_path(Path::new("/tmp/id_ed25519"))
            .expect("private key paths should be accepted");
    }

    #[test]
    fn backup_key_paths_use_config_scoped_ssh_directory() {
        let ssh_dir = Path::new("/home/user/.config/stacker/ssh");
        let (private_key_path, public_key_path) = backup_key_paths_for_server(42, ssh_dir);

        assert_eq!(
            private_key_path,
            Path::new("/home/user/.config/stacker/ssh/server-42_ed25519")
        );
        assert_eq!(
            public_key_path,
            Path::new("/home/user/.config/stacker/ssh/server-42_ed25519.pub")
        );
    }

    #[test]
    fn local_backup_keypair_uses_existing_generate_keypair_helper_and_reuses_private_key() {
        let dir = TempDir::new().expect("tempdir");
        let keypair = ensure_local_backup_keypair_in_dir(7, dir.path()).expect("generate keypair");
        let private_before =
            std::fs::read_to_string(&keypair.private_key_path).expect("private key");
        let public_before = std::fs::read_to_string(&keypair.public_key_path).expect("public key");

        let regenerated =
            ensure_local_backup_keypair_in_dir(7, dir.path()).expect("reuse existing keypair");
        let private_after =
            std::fs::read_to_string(&regenerated.private_key_path).expect("private key");
        let public_after =
            std::fs::read_to_string(&regenerated.public_key_path).expect("public key");

        assert_eq!(private_before, private_after);
        assert_eq!(public_before, public_after);
        assert!(private_before.contains("OPENSSH PRIVATE KEY"));
        assert!(public_before.starts_with("ssh-ed25519 "));
    }

    #[test]
    fn local_backup_keypair_derives_public_key_when_pub_file_is_missing() {
        let dir = TempDir::new().expect("tempdir");
        let (public_key, private_key) = VaultClient::generate_ssh_keypair().expect("keypair");
        let (private_key_path, public_key_path) = backup_key_paths_for_server(8, dir.path());
        std::fs::write(&private_key_path, private_key).expect("write private key");

        let keypair = ensure_local_backup_keypair_in_dir(8, dir.path()).expect("reuse keypair");

        assert_eq!(keypair.public_key, public_key);
        assert_eq!(
            std::fs::read_to_string(public_key_path).expect("public key file"),
            format!("{}\n", public_key)
        );
    }

    #[test]
    fn formats_copy_paste_ssh_command() {
        let command = format_ssh_command(
            Path::new("/home/user/.config/stacker/ssh/server-42_ed25519"),
            "root",
            "203.0.113.10",
            2222,
        );

        assert_eq!(
            command,
            "ssh -i /home/user/.config/stacker/ssh/server-42_ed25519 -p 2222 root@203.0.113.10"
        );
    }
}
