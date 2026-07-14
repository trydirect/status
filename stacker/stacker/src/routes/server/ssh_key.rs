use crate::db;
use crate::helpers::{JsonResponse, VaultClient};
use crate::models;
use actix_web::{delete, get, post, web, Responder, Result};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;

/// Request body for uploading an existing SSH key pair
#[derive(Debug, Deserialize)]
pub struct UploadKeyRequest {
    pub public_key: String,
    pub private_key: String,
}

/// Response containing the public key for copying
#[derive(Debug, Clone, Default, Serialize)]
pub struct PublicKeyResponse {
    pub public_key: String,
    pub fingerprint: Option<String>,
}

/// Response for SSH key generation
#[derive(Debug, Clone, Default, Serialize)]
pub struct GenerateKeyResponse {
    pub public_key: String,
    pub fingerprint: Option<String>,
    pub message: String,
}

/// Response for SSH key generation (with optional private key if Vault fails)
#[derive(Debug, Clone, Default, Serialize)]
pub struct GenerateKeyResponseWithPrivate {
    pub public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
    pub fingerprint: Option<String>,
    pub message: String,
}

/// Request body for authorizing a caller-provided public key on the server
#[derive(Debug, Deserialize)]
pub struct AuthorizePublicKeyRequest {
    pub public_key: String,
    pub user: Option<String>,
    pub port: Option<u16>,
}

/// Response for public key authorization
#[derive(Debug, Clone, Default, Serialize)]
pub struct AuthorizePublicKeyResponse {
    pub server_id: i32,
    pub srv_ip: String,
    pub ssh_user: String,
    pub ssh_port: u16,
    pub authorized: bool,
    pub message: String,
}

/// Helper to verify server ownership
async fn verify_server_ownership(
    pg_pool: &PgPool,
    server_id: i32,
    user_id: &str,
) -> Result<models::Server, actix_web::Error> {
    db::server::fetch(pg_pool, server_id)
        .await
        .map_err(|_err| JsonResponse::<models::Server>::build().internal_server_error(""))
        .and_then(|server| match server {
            Some(s) if s.user_id != user_id => {
                Err(JsonResponse::<models::Server>::build().not_found("Server not found"))
            }
            Some(s) => Ok(s),
            None => Err(JsonResponse::<models::Server>::build().not_found("Server not found")),
        })
}

/// Generate a new SSH key pair for a server
/// POST /server/{id}/ssh-key/generate
#[tracing::instrument(name = "Generate SSH key for server.", skip_all)]
#[post("/{id}/ssh-key/generate")]
pub async fn generate_key(
    path: web::Path<(i32,)>,
    user: web::ReqData<Arc<models::User>>,
    pg_pool: web::Data<PgPool>,
    vault_client: web::Data<VaultClient>,
) -> Result<impl Responder> {
    let server_id = path.0;
    let server = verify_server_ownership(pg_pool.get_ref(), server_id, &user.id).await?;

    // Check if server already has an active key
    if server.key_status == "active" {
        return Err(JsonResponse::<GenerateKeyResponse>::build().bad_request(
            "Server already has an active SSH key. Delete it first to generate a new one.",
        ));
    }

    // Update status to pending
    db::server::update_ssh_key_status(pg_pool.get_ref(), server_id, None, "pending")
        .await
        .map_err(|e| JsonResponse::<GenerateKeyResponse>::build().internal_server_error(&e))?;

    // Generate SSH key pair
    let (public_key, private_key) = VaultClient::generate_ssh_keypair().map_err(|e| {
        tracing::error!("Failed to generate SSH keypair: {}", e);
        // Reset status on failure
        let _ = futures::executor::block_on(db::server::update_ssh_key_status(
            pg_pool.get_ref(),
            server_id,
            None,
            "failed",
        ));
        JsonResponse::<GenerateKeyResponse>::build()
            .internal_server_error("Failed to generate SSH key")
    })?;

    // Try to store in Vault, but don't fail if it doesn't work
    let vault_result = vault_client
        .get_ref()
        .store_ssh_key(&user.id, server_id, &public_key, &private_key)
        .await;

    let (vault_path, status, message, include_private_key) = match vault_result {
        Ok(path) => {
            tracing::info!("SSH key stored in Vault successfully");
            (Some(path), "active", "SSH key generated and stored in Vault successfully. Copy the public key to your server's authorized_keys.".to_string(), false)
        }
        Err(e) => {
            tracing::warn!(
                "Failed to store SSH key in Vault (continuing without Vault): {}",
                e
            );
            (None, "active", format!("SSH key generated successfully, but could not be stored in Vault ({}). Please save the private key shown below - it will not be shown again!", e), true)
        }
    };

    // Update server with vault path and active status
    db::server::update_ssh_key_status(pg_pool.get_ref(), server_id, vault_path, status)
        .await
        .map_err(|e| JsonResponse::<GenerateKeyResponse>::build().internal_server_error(&e))?;

    let response = GenerateKeyResponseWithPrivate {
        public_key: public_key.clone(),
        private_key: if include_private_key {
            Some(private_key)
        } else {
            None
        },
        fingerprint: None, // TODO: Calculate fingerprint
        message,
    };

    Ok(JsonResponse::build()
        .set_item(Some(response))
        .ok("SSH key generated"))
}

/// Upload an existing SSH key pair for a server
/// POST /server/{id}/ssh-key/upload
#[tracing::instrument(name = "Upload SSH key for server.", skip_all)]
#[post("/{id}/ssh-key/upload")]
pub async fn upload_key(
    path: web::Path<(i32,)>,
    form: web::Json<UploadKeyRequest>,
    user: web::ReqData<Arc<models::User>>,
    pg_pool: web::Data<PgPool>,
    vault_client: web::Data<VaultClient>,
) -> Result<impl Responder> {
    let server_id = path.0;
    let server = verify_server_ownership(pg_pool.get_ref(), server_id, &user.id).await?;

    // Check if server already has an active key
    if server.key_status == "active" {
        return Err(JsonResponse::<models::Server>::build().bad_request(
            "Server already has an active SSH key. Delete it first to upload a new one.",
        ));
    }

    // Validate keys (basic check)
    if !form.public_key.starts_with("ssh-") && !form.public_key.starts_with("ecdsa-") {
        return Err(JsonResponse::<models::Server>::build()
            .bad_request("Invalid public key format. Expected OpenSSH format."));
    }

    if !form.private_key.contains("PRIVATE KEY") {
        return Err(JsonResponse::<models::Server>::build()
            .bad_request("Invalid private key format. Expected PEM format."));
    }

    // Update status to pending
    db::server::update_ssh_key_status(pg_pool.get_ref(), server_id, None, "pending")
        .await
        .map_err(|e| JsonResponse::<models::Server>::build().internal_server_error(&e))?;

    // Store in Vault
    let vault_path = vault_client
        .get_ref()
        .store_ssh_key(&user.id, server_id, &form.public_key, &form.private_key)
        .await
        .map_err(|e| {
            tracing::error!("Failed to store SSH key in Vault: {}", e);
            let _ = futures::executor::block_on(db::server::update_ssh_key_status(
                pg_pool.get_ref(),
                server_id,
                None,
                "failed",
            ));
            JsonResponse::<models::Server>::build().internal_server_error("Failed to store SSH key")
        })?;

    // Update server with vault path and active status
    let updated_server =
        db::server::update_ssh_key_status(pg_pool.get_ref(), server_id, Some(vault_path), "active")
            .await
            .map_err(|e| JsonResponse::<models::Server>::build().internal_server_error(&e))?;

    Ok(JsonResponse::build()
        .set_item(Some(updated_server))
        .ok("SSH key uploaded successfully"))
}

/// Get the public key for a server (for copying to authorized_keys)
/// GET /server/{id}/ssh-key/public
#[tracing::instrument(name = "Get public SSH key for server.", skip_all)]
#[get("/{id}/ssh-key/public")]
pub async fn get_public_key(
    path: web::Path<(i32,)>,
    user: web::ReqData<Arc<models::User>>,
    pg_pool: web::Data<PgPool>,
    vault_client: web::Data<VaultClient>,
) -> Result<impl Responder> {
    let server_id = path.0;
    let server = verify_server_ownership(pg_pool.get_ref(), server_id, &user.id).await?;

    if server.key_status != "active" {
        return Err(JsonResponse::<PublicKeyResponse>::build()
            .not_found("No active SSH key found for this server"));
    }

    if server.vault_key_path.is_none() {
        return Err(JsonResponse::<PublicKeyResponse>::build()
            .bad_request("SSH key is not stored in Vault (Vault was unavailable when the key was generated). Please delete this key and generate a new one."));
    }

    let public_key = vault_client
        .get_ref()
        .fetch_ssh_public_key(&user.id, server_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to fetch public key from Vault: {}", e);
            if e.to_lowercase().contains("not found") {
                JsonResponse::<PublicKeyResponse>::build()
                    .not_found("SSH key not found in Vault. The key may have been lost or Vault was restored without its data. Please delete this key and generate a new one.")
            } else {
                JsonResponse::<PublicKeyResponse>::build()
                    .bad_request("Failed to retrieve SSH key from Vault. Please try again or regenerate the key.")
            }
        })?;

    let response = PublicKeyResponse {
        public_key,
        fingerprint: None, // TODO: Calculate fingerprint
    };

    Ok(JsonResponse::build().set_item(Some(response)).ok("OK"))
}

/// Authorize a caller-provided public key on the remote server.
///
/// POST /server/{id}/ssh-key/authorize-public-key
///
/// The caller sends only public key material. Stacker retrieves the server's
/// Vault-managed private key and uses it server-side to append the provided
/// public key to `authorized_keys` idempotently.
#[tracing::instrument(name = "Authorize public SSH key for server.", skip_all)]
#[post("/{id}/ssh-key/authorize-public-key")]
pub async fn authorize_public_key(
    path: web::Path<(i32,)>,
    form: web::Json<AuthorizePublicKeyRequest>,
    user: web::ReqData<Arc<models::User>>,
    pg_pool: web::Data<PgPool>,
    vault_client: web::Data<VaultClient>,
) -> Result<impl Responder> {
    use crate::helpers::ssh_client;

    let server_id = path.0;
    let server = verify_server_ownership(pg_pool.get_ref(), server_id, &user.id).await?;

    if server.key_status != "active" {
        return Err(
            JsonResponse::<AuthorizePublicKeyResponse>::build().bad_request(format!(
                "SSH key status is '{}', not active",
                server.key_status
            )),
        );
    }

    if server.vault_key_path.is_none() {
        return Err(JsonResponse::<AuthorizePublicKeyResponse>::build().bad_request(
            "SSH key is not stored in Vault. Regenerate the server SSH key before authorizing a backup key.",
        ));
    }

    let public_key = form.public_key.trim();
    ssh_key::PublicKey::from_openssh(public_key).map_err(|e| {
        JsonResponse::<AuthorizePublicKeyResponse>::build()
            .bad_request(format!("Invalid public key format: {}", e))
    })?;

    let srv_ip = server
        .srv_ip
        .as_deref()
        .filter(|ip| !ip.trim().is_empty())
        .ok_or_else(|| {
            JsonResponse::<AuthorizePublicKeyResponse>::build()
                .bad_request("Server IP address not configured")
        })?
        .to_string();

    let private_key = vault_client
        .get_ref()
        .fetch_ssh_key(&user.id, server_id)
        .await
        .map_err(|e| {
            tracing::warn!(
                "Failed to fetch SSH key from Vault while authorizing backup key: {}",
                e
            );
            JsonResponse::<AuthorizePublicKeyResponse>::build()
                .bad_request("SSH key could not be retrieved from secure storage")
        })?;

    let ssh_user = form
        .user
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| server.ssh_user.clone())
        .unwrap_or_else(|| "root".to_string());
    let ssh_port = form
        .port
        .unwrap_or_else(|| server.ssh_port.unwrap_or(22) as u16);

    ssh_client::authorize_public_key(
        &srv_ip,
        ssh_port,
        &ssh_user,
        &private_key,
        public_key,
        Duration::from_secs(4),
    )
    .await
    .map_err(|e| {
        tracing::warn!(
            "Failed to authorize backup public key for server {}: {}",
            server_id,
            e
        );
        JsonResponse::<AuthorizePublicKeyResponse>::build()
            .bad_request(format!("Failed to authorize public key on server: {}", e))
    })?;

    let response = AuthorizePublicKeyResponse {
        server_id,
        srv_ip,
        ssh_user,
        ssh_port,
        authorized: true,
        message: "Public key authorized successfully".to_string(),
    };

    Ok(JsonResponse::build()
        .set_item(Some(response))
        .ok("Public key authorized"))
}

/// Response for SSH validation with full system check
#[derive(Debug, Clone, Default, Serialize)]
pub struct ValidateResponse {
    pub valid: bool,
    pub server_id: i32,
    pub srv_ip: Option<String>,
    pub message: String,
    /// SSH connection was successful
    pub connected: bool,
    /// SSH authentication was successful
    pub authenticated: bool,
    /// Username from whoami
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Total disk space in GB
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_total_gb: Option<f64>,
    /// Available disk space in GB
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_available_gb: Option<f64>,
    /// Disk usage percentage
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_usage_percent: Option<f64>,
    /// Docker is installed
    pub docker_installed: bool,
    /// Docker version string
    #[serde(skip_serializing_if = "Option::is_none")]
    pub docker_version: Option<String>,
    /// OS name (from /etc/os-release)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_name: Option<String>,
    /// OS version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_version: Option<String>,
    /// Total memory in MB
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_total_mb: Option<u64>,
    /// Available memory in MB
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_available_mb: Option<u64>,
    /// Public key stored in Vault (shown only on auth failure for debugging)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vault_public_key: Option<String>,
}

/// Validate SSH connection for a server
/// POST /server/{id}/ssh-key/validate
///
/// This endpoint:
/// 1. Verifies the server exists and belongs to the user
/// 2. Checks the SSH key is active and retrieves it from Vault
/// 3. Connects to the server via SSH and authenticates
/// 4. Runs system diagnostic commands (whoami, df, docker, os-release, free)
/// 5. Returns comprehensive system information
#[tracing::instrument(name = "Validate SSH key for server.", skip_all)]
#[post("/{id}/ssh-key/validate")]
pub async fn validate_key(
    path: web::Path<(i32,)>,
    user: web::ReqData<Arc<models::User>>,
    pg_pool: web::Data<PgPool>,
    vault_client: web::Data<VaultClient>,
) -> Result<impl Responder> {
    use crate::helpers::ssh_client;
    use std::time::Duration;

    let server_id = path.0;
    let server = verify_server_ownership(pg_pool.get_ref(), server_id, &user.id).await?;

    // Check if server has an active key
    if server.key_status != "active" {
        let response = ValidateResponse {
            valid: false,
            server_id,
            srv_ip: server.srv_ip.clone(),
            message: format!("SSH key status is '{}', not active", server.key_status),
            ..Default::default()
        };
        return Ok(JsonResponse::build()
            .set_item(Some(response))
            .ok("Validation failed"));
    }

    if server.vault_key_path.is_none() {
        let response = ValidateResponse {
            valid: false,
            server_id,
            srv_ip: server.srv_ip.clone(),
            message: "SSH key is not stored in Vault (Vault was unavailable when the key was generated). Please delete this key and generate a new one.".to_string(),
            ..Default::default()
        };
        return Ok(JsonResponse::build()
            .set_item(Some(response))
            .ok("Validation failed"));
    }

    // Verify we have the server IP
    let srv_ip = match &server.srv_ip {
        Some(ip) if !ip.is_empty() => ip.clone(),
        _ => {
            let response = ValidateResponse {
                valid: false,
                server_id,
                srv_ip: server.srv_ip.clone(),
                message: "Server IP address not configured".to_string(),
                ..Default::default()
            };
            return Ok(JsonResponse::build()
                .set_item(Some(response))
                .ok("Validation failed"));
        }
    };

    // Fetch private key from Vault
    let private_key = match vault_client
        .get_ref()
        .fetch_ssh_key(&user.id, server_id)
        .await
    {
        Ok(key) => key,
        Err(e) => {
            tracing::warn!(
                "Failed to fetch SSH key from Vault during validation: {}",
                e
            );
            let response = ValidateResponse {
                valid: false,
                server_id,
                srv_ip: server.srv_ip.clone(),
                message: "SSH key could not be retrieved from secure storage".to_string(),
                ..Default::default()
            };
            return Ok(JsonResponse::build()
                .set_item(Some(response))
                .ok("Validation failed"));
        }
    };

    // Also fetch public key so we can include it in failed auth responses for debugging
    let vault_public_key = vault_client
        .get_ref()
        .fetch_ssh_public_key(&user.id, server_id)
        .await
        .ok();

    // Get SSH connection parameters
    let ssh_port = server.ssh_port.unwrap_or(22) as u16;
    let ssh_user = server
        .ssh_user
        .clone()
        .unwrap_or_else(|| "root".to_string());

    // Perform SSH connection and system check
    let check_result = ssh_client::check_server(
        &srv_ip,
        ssh_port,
        &ssh_user,
        &private_key,
        Duration::from_secs(4),
    )
    .await;

    // Build response from check result
    let valid = check_result.connected && check_result.authenticated;
    let message = if valid {
        check_result.summary()
    } else {
        check_result
            .error
            .unwrap_or_else(|| "SSH validation failed".to_string())
    };

    let response = ValidateResponse {
        valid,
        server_id,
        srv_ip: Some(srv_ip),
        message,
        connected: check_result.connected,
        authenticated: check_result.authenticated,
        // Include vault public key in response when auth fails (helps debug key mismatch)
        vault_public_key: if !check_result.authenticated {
            vault_public_key
        } else {
            None
        },
        username: check_result.username,
        disk_total_gb: check_result.disk_total_gb,
        disk_available_gb: check_result.disk_available_gb,
        disk_usage_percent: check_result.disk_usage_percent,
        docker_installed: check_result.docker_installed,
        docker_version: check_result.docker_version,
        os_name: check_result.os_name,
        os_version: check_result.os_version,
        memory_total_mb: check_result.memory_total_mb,
        memory_available_mb: check_result.memory_available_mb,
    };

    let ok_message = if valid {
        "SSH connection validated successfully"
    } else {
        "SSH validation failed"
    };

    Ok(JsonResponse::build()
        .set_item(Some(response))
        .ok(ok_message))
}

/// Delete SSH key for a server (disconnect)
/// DELETE /server/{id}/ssh-key
#[tracing::instrument(name = "Delete SSH key for server.", skip_all)]
#[delete("/{id}/ssh-key")]
pub async fn delete_key(
    path: web::Path<(i32,)>,
    user: web::ReqData<Arc<models::User>>,
    pg_pool: web::Data<PgPool>,
    vault_client: web::Data<VaultClient>,
) -> Result<impl Responder> {
    let server_id = path.0;
    let server = verify_server_ownership(pg_pool.get_ref(), server_id, &user.id).await?;

    if server.key_status == "none" {
        return Err(JsonResponse::<models::Server>::build()
            .bad_request("No SSH key to delete for this server"));
    }

    // Delete from Vault
    if let Err(e) = vault_client
        .get_ref()
        .delete_ssh_key(&user.id, server_id)
        .await
    {
        tracing::warn!("Failed to delete SSH key from Vault (may not exist): {}", e);
        // Continue anyway - the key might not exist in Vault
    }

    // Update server status
    let updated_server =
        db::server::update_ssh_key_status(pg_pool.get_ref(), server_id, None, "none")
            .await
            .map_err(|e| JsonResponse::<models::Server>::build().internal_server_error(&e))?;

    Ok(JsonResponse::build()
        .set_item(Some(updated_server))
        .ok("SSH key deleted successfully"))
}
