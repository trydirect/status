use crate::configuration::VaultSettings;
use reqwest::Client;
use serde_json::json;

pub struct VaultClient {
    client: Client,
    address: String,
    token: String,
    agent_path_prefix: String,
    api_prefix: String,
    ssh_key_path_prefix: String,
}

impl std::fmt::Debug for VaultClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultClient")
            .field("address", &self.address)
            .field("token", &"[REDACTED]")
            .field("agent_path_prefix", &self.agent_path_prefix)
            .field("api_prefix", &self.api_prefix)
            .field("ssh_key_path_prefix", &self.ssh_key_path_prefix)
            .finish()
    }
}

impl VaultClient {
    pub fn new(settings: &VaultSettings) -> Self {
        Self {
            client: Client::new(),
            address: settings.address.clone(),
            token: settings.token.clone(),
            agent_path_prefix: settings.agent_path_prefix.clone(),
            api_prefix: settings.api_prefix.clone(),
            ssh_key_path_prefix: settings
                .ssh_key_path_prefix
                .clone()
                .unwrap_or_else(|| "users".to_string()),
        }
    }

    /// Store agent token in Vault at agent/{deployment_hash}/token
    #[tracing::instrument(name = "Store agent token in Vault", skip_all)]
    pub async fn store_agent_token(
        &self,
        deployment_hash: &str,
        token: &str,
    ) -> Result<(), String> {
        let base = self.address.trim_end_matches('/');
        let prefix = self.agent_path_prefix.trim_matches('/');
        let api_prefix = self.api_prefix.trim_matches('/');
        let path = if api_prefix.is_empty() {
            format!("{}/{}/{}/token", base, prefix, deployment_hash)
        } else {
            format!(
                "{}/{}/{}/{}/token",
                base, api_prefix, prefix, deployment_hash
            )
        };

        let payload = json!({
            "data": {
                "token": token,
                "deployment_hash": deployment_hash
            }
        });

        self.client
            .post(&path)
            .header("X-Vault-Token", &self.token)
            .json(&payload)
            .send()
            .await
            .map_err(|e| {
                tracing::error!("Failed to store token in Vault: {:?}", e);
                format!("Vault store error: {}", e)
            })?
            .error_for_status()
            .map_err(|e| {
                tracing::error!("Vault returned error status: {:?}", e);
                format!("Vault error: {}", e)
            })?;

        tracing::info!(
            "Stored agent token in Vault for deployment_hash: {}",
            deployment_hash
        );
        Ok(())
    }

    /// Fetch agent token from Vault
    #[tracing::instrument(name = "Fetch agent token from Vault", skip_all)]
    pub async fn fetch_agent_token(&self, deployment_hash: &str) -> Result<String, String> {
        let base = self.address.trim_end_matches('/');
        let prefix = self.agent_path_prefix.trim_matches('/');
        let api_prefix = self.api_prefix.trim_matches('/');
        let path = if api_prefix.is_empty() {
            format!("{}/{}/{}/token", base, prefix, deployment_hash)
        } else {
            format!(
                "{}/{}/{}/{}/token",
                base, api_prefix, prefix, deployment_hash
            )
        };

        let response = self
            .client
            .get(&path)
            .header("X-Vault-Token", &self.token)
            .send()
            .await
            .map_err(|e| {
                tracing::error!("Failed to fetch token from Vault: {:?}", e);
                format!("Vault fetch error: {}", e)
            })?;

        if response.status() == 404 {
            return Err("Token not found in Vault".to_string());
        }

        let vault_response: serde_json::Value = response
            .error_for_status()
            .map_err(|e| {
                tracing::error!("Vault returned error status: {:?}", e);
                format!("Vault error: {}", e)
            })?
            .json()
            .await
            .map_err(|e| {
                tracing::error!("Failed to parse Vault response: {:?}", e);
                format!("Vault parse error: {}", e)
            })?;

        vault_response["data"]["data"]["token"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| {
                tracing::error!("Token not found in Vault response");
                "Token not in Vault response".to_string()
            })
    }

    /// Delete agent token from Vault
    #[tracing::instrument(name = "Delete agent token from Vault", skip_all)]
    pub async fn delete_agent_token(&self, deployment_hash: &str) -> Result<(), String> {
        let base = self.address.trim_end_matches('/');
        let prefix = self.agent_path_prefix.trim_matches('/');
        let api_prefix = self.api_prefix.trim_matches('/');
        let path = if api_prefix.is_empty() {
            format!("{}/{}/{}/token", base, prefix, deployment_hash)
        } else {
            format!(
                "{}/{}/{}/{}/token",
                base, api_prefix, prefix, deployment_hash
            )
        };

        self.client
            .delete(&path)
            .header("X-Vault-Token", &self.token)
            .send()
            .await
            .map_err(|e| {
                tracing::error!("Failed to delete token from Vault: {:?}", e);
                format!("Vault delete error: {}", e)
            })?
            .error_for_status()
            .map_err(|e| {
                tracing::error!("Vault returned error status: {:?}", e);
                format!("Vault error: {}", e)
            })?;

        tracing::info!(
            "Deleted agent token from Vault for deployment_hash: {}",
            deployment_hash
        );
        Ok(())
    }

    // ============ Runtime Preference Methods ============

    /// Store runtime preference for a deployment
    /// Path: {api_prefix}/{agent_prefix}/{deployment_hash}/runtime
    #[tracing::instrument(name = "Store runtime preference in Vault", skip_all)]
    pub async fn store_runtime_preference(
        &self,
        deployment_hash: &str,
        runtime: &str,
    ) -> Result<(), String> {
        let base = self.address.trim_end_matches('/');
        let prefix = self.agent_path_prefix.trim_matches('/');
        let api_prefix = self.api_prefix.trim_matches('/');
        let path = if api_prefix.is_empty() {
            format!("{}/{}/{}/runtime", base, prefix, deployment_hash)
        } else {
            format!(
                "{}/{}/{}/{}/runtime",
                base, api_prefix, prefix, deployment_hash
            )
        };

        let payload = json!({
            "data": {
                "runtime": runtime,
                "deployment_hash": deployment_hash
            }
        });

        self.client
            .post(&path)
            .header("X-Vault-Token", &self.token)
            .json(&payload)
            .send()
            .await
            .map_err(|e| {
                tracing::error!("Failed to store runtime preference in Vault: {:?}", e);
                format!("Vault store error: {}", e)
            })?
            .error_for_status()
            .map_err(|e| {
                tracing::error!("Vault returned error status: {:?}", e);
                format!("Vault error: {}", e)
            })?;

        tracing::info!(
            deployment_hash = %deployment_hash,
            runtime = %runtime,
            "Runtime preference stored in Vault"
        );
        Ok(())
    }

    /// Fetch runtime preference from Vault
    /// Returns None if not set
    #[tracing::instrument(name = "Fetch runtime preference from Vault", skip_all)]
    pub async fn fetch_runtime_preference(
        &self,
        deployment_hash: &str,
    ) -> Result<Option<String>, String> {
        let base = self.address.trim_end_matches('/');
        let prefix = self.agent_path_prefix.trim_matches('/');
        let api_prefix = self.api_prefix.trim_matches('/');
        let path = if api_prefix.is_empty() {
            format!("{}/{}/{}/runtime", base, prefix, deployment_hash)
        } else {
            format!(
                "{}/{}/{}/{}/runtime",
                base, api_prefix, prefix, deployment_hash
            )
        };

        let response = self
            .client
            .get(&path)
            .header("X-Vault-Token", &self.token)
            .send()
            .await
            .map_err(|e| {
                tracing::error!("Failed to fetch runtime preference from Vault: {:?}", e);
                format!("Vault fetch error: {}", e)
            })?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }

        let body: serde_json::Value = response
            .error_for_status()
            .map_err(|e| {
                tracing::error!("Vault returned error status: {:?}", e);
                format!("Vault error: {}", e)
            })?
            .json()
            .await
            .map_err(|e| {
                tracing::error!("Failed to parse runtime preference response: {:?}", e);
                format!("Vault parse error: {}", e)
            })?;

        let runtime = body
            .pointer("/data/data/runtime")
            .or_else(|| body.pointer("/data/runtime"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        Ok(runtime)
    }

    /// Delete runtime preference from Vault
    #[tracing::instrument(name = "Delete runtime preference from Vault", skip_all)]
    pub async fn delete_runtime_preference(&self, deployment_hash: &str) -> Result<(), String> {
        let base = self.address.trim_end_matches('/');
        let prefix = self.agent_path_prefix.trim_matches('/');
        let api_prefix = self.api_prefix.trim_matches('/');
        let path = if api_prefix.is_empty() {
            format!("{}/{}/{}/runtime", base, prefix, deployment_hash)
        } else {
            format!(
                "{}/{}/{}/{}/runtime",
                base, api_prefix, prefix, deployment_hash
            )
        };

        self.client
            .delete(&path)
            .header("X-Vault-Token", &self.token)
            .send()
            .await
            .map_err(|e| {
                tracing::error!("Failed to delete runtime preference from Vault: {:?}", e);
                format!("Vault delete error: {}", e)
            })?
            .error_for_status()
            .map_err(|e| {
                tracing::error!("Vault returned error status: {:?}", e);
                format!("Vault error: {}", e)
            })?;

        tracing::info!(
            deployment_hash = %deployment_hash,
            "Runtime preference deleted from Vault"
        );
        Ok(())
    }

    // ============ Org Runtime Policy Methods ============

    /// Fetch org-level runtime policy from Vault
    /// Path: {api_prefix}/{agent_prefix}/org/{org_id}/runtime_policy
    /// Returns the required runtime if an org policy exists, None otherwise
    #[tracing::instrument(name = "Fetch org runtime policy from Vault", skip_all)]
    pub async fn fetch_org_runtime_policy(&self, org_id: &str) -> Result<Option<String>, String> {
        let base = self.address.trim_end_matches('/');
        let prefix = self.agent_path_prefix.trim_matches('/');
        let api_prefix = self.api_prefix.trim_matches('/');
        let path = if api_prefix.is_empty() {
            format!("{}/{}/org/{}/runtime_policy", base, prefix, org_id)
        } else {
            format!(
                "{}/{}/{}/org/{}/runtime_policy",
                base, api_prefix, prefix, org_id
            )
        };

        let response = self
            .client
            .get(&path)
            .header("X-Vault-Token", &self.token)
            .send()
            .await
            .map_err(|e| {
                tracing::error!("Failed to fetch org runtime policy from Vault: {:?}", e);
                format!("Vault fetch error: {}", e)
            })?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }

        let body: serde_json::Value = response
            .error_for_status()
            .map_err(|e| {
                tracing::error!("Vault returned error status: {:?}", e);
                format!("Vault error: {}", e)
            })?
            .json()
            .await
            .map_err(|e| {
                tracing::error!("Failed to parse org runtime policy response: {:?}", e);
                format!("Vault parse error: {}", e)
            })?;

        let require_kata = body
            .pointer("/data/data/require_kata")
            .or_else(|| body.pointer("/data/require_kata"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if require_kata {
            Ok(Some("kata".to_string()))
        } else {
            Ok(None)
        }
    }

    // ============ SSH Key Management Methods ============

    /// Build the Vault API URL for SSH keys (KV v1).
    /// Path: `{address}/{api_prefix}/secret/{prefix}/{user_id}/ssh_keys/{server_id}`
    fn ssh_key_path(&self, user_id: &str, server_id: i32) -> String {
        let base = self.address.trim_end_matches('/');
        let api_prefix = self.api_prefix.trim_matches('/');
        let prefix = self.ssh_key_path_prefix.trim_matches('/');

        if api_prefix.is_empty() {
            format!(
                "{}/secret/{}/{}/ssh_keys/{}",
                base, prefix, user_id, server_id
            )
        } else {
            format!(
                "{}/{}/secret/{}/{}/ssh_keys/{}",
                base, api_prefix, prefix, user_id, server_id
            )
        }
    }

    /// Generate an SSH keypair (ed25519) and return (public_key, private_key)
    pub fn generate_ssh_keypair() -> Result<(String, String), String> {
        use ssh_key::{Algorithm, LineEnding, PrivateKey};

        let private_key = PrivateKey::random(&mut rand::thread_rng(), Algorithm::Ed25519)
            .map_err(|e| format!("Failed to generate SSH key: {}", e))?;

        let private_key_pem = private_key
            .to_openssh(LineEnding::LF)
            .map_err(|e| format!("Failed to encode private key: {}", e))?
            .to_string();

        let public_key = private_key.public_key();
        let public_key_openssh = public_key
            .to_openssh()
            .map_err(|e| format!("Failed to encode public key: {}", e))?;

        Ok((public_key_openssh, private_key_pem))
    }

    /// Store SSH keypair in Vault at users/{user_id}/ssh_keys/{server_id}
    #[tracing::instrument(name = "Store SSH key in Vault", skip_all)]
    pub async fn store_ssh_key(
        &self,
        user_id: &str,
        server_id: i32,
        public_key: &str,
        private_key: &str,
    ) -> Result<String, String> {
        let path = self.ssh_key_path(user_id, server_id);

        let payload = json!({
            "public_key": public_key,
            "private_key": private_key,
            "user_id": user_id,
            "server_id": server_id,
            "created_at": chrono::Utc::now().to_rfc3339()
        });

        self.client
            .post(&path)
            .header("X-Vault-Token", &self.token)
            .json(&payload)
            .send()
            .await
            .map_err(|e| {
                tracing::error!("Failed to store SSH key in Vault: {:?}", e);
                format!("Vault store error: {}", e)
            })?
            .error_for_status()
            .map_err(|e| {
                tracing::error!("Vault returned error status: {:?}", e);
                format!("Vault error: {}", e)
            })?;

        // Return the logical vault path for storage in database
        let vault_key_path = format!(
            "secret/{}/{}/ssh_keys/{}",
            self.ssh_key_path_prefix.trim_matches('/'),
            user_id,
            server_id
        );

        tracing::info!(
            "Stored SSH key in Vault for user: {}, server: {}",
            user_id,
            server_id
        );
        Ok(vault_key_path)
    }

    /// Fetch SSH private key from Vault
    #[tracing::instrument(name = "Fetch SSH key from Vault", skip_all)]
    pub async fn fetch_ssh_key(&self, user_id: &str, server_id: i32) -> Result<String, String> {
        let path = self.ssh_key_path(user_id, server_id);

        let response = self
            .client
            .get(&path)
            .header("X-Vault-Token", &self.token)
            .send()
            .await
            .map_err(|e| {
                tracing::error!("Failed to fetch SSH key from Vault: {:?}", e);
                format!("Vault fetch error: {}", e)
            })?;

        if response.status() == 404 {
            return Err("SSH key not found in Vault".to_string());
        }

        let vault_response: serde_json::Value = response
            .error_for_status()
            .map_err(|e| {
                tracing::error!("Vault returned error status: {:?}", e);
                format!("Vault error: {}", e)
            })?
            .json()
            .await
            .map_err(|e| {
                tracing::error!("Failed to parse Vault response: {:?}", e);
                format!("Vault parse error: {}", e)
            })?;

        vault_response["data"]["private_key"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| {
                tracing::error!("SSH key not found in Vault response");
                "SSH key not in Vault response".to_string()
            })
    }

    /// Fetch SSH public key from Vault
    #[tracing::instrument(name = "Fetch SSH public key from Vault", skip_all)]
    pub async fn fetch_ssh_public_key(
        &self,
        user_id: &str,
        server_id: i32,
    ) -> Result<String, String> {
        let path = self.ssh_key_path(user_id, server_id);

        let response = self
            .client
            .get(&path)
            .header("X-Vault-Token", &self.token)
            .send()
            .await
            .map_err(|e| {
                tracing::error!("Failed to fetch SSH public key from Vault: {:?}", e);
                format!("Vault fetch error: {}", e)
            })?;

        if response.status() == 404 {
            return Err("SSH key not found in Vault".to_string());
        }

        let vault_response: serde_json::Value = response
            .error_for_status()
            .map_err(|e| {
                tracing::error!("Vault returned error status: {:?}", e);
                format!("Vault error: {}", e)
            })?
            .json()
            .await
            .map_err(|e| {
                tracing::error!("Failed to parse Vault response: {:?}", e);
                format!("Vault parse error: {}", e)
            })?;

        vault_response["data"]["public_key"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| {
                tracing::error!("SSH public key not found in Vault response");
                "SSH public key not in Vault response".to_string()
            })
    }

    /// Delete SSH key from Vault (disconnect)
    #[tracing::instrument(name = "Delete SSH key from Vault", skip_all)]
    pub async fn delete_ssh_key(&self, user_id: &str, server_id: i32) -> Result<(), String> {
        let path = self.ssh_key_path(user_id, server_id);

        self.client
            .delete(&path)
            .header("X-Vault-Token", &self.token)
            .send()
            .await
            .map_err(|e| {
                tracing::error!("Failed to delete SSH key from Vault: {:?}", e);
                format!("Vault delete error: {}", e)
            })?
            .error_for_status()
            .map_err(|e| {
                tracing::error!("Vault returned error status: {:?}", e);
                format!("Vault error: {}", e)
            })?;

        tracing::info!(
            "Deleted SSH key from Vault for user: {}, server: {}",
            user_id,
            server_id
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{web, App, HttpResponse, HttpServer};
    use serde_json::Value;
    use std::net::TcpListener;

    async fn mock_store(body: web::Json<Value>) -> HttpResponse {
        // Expect { data: { token, deployment_hash } }
        if body["data"]["token"].is_string() && body["data"]["deployment_hash"].is_string() {
            HttpResponse::NoContent().finish()
        } else {
            HttpResponse::BadRequest().finish()
        }
    }

    async fn mock_fetch(path: web::Path<(String, String)>) -> HttpResponse {
        let (_prefix, deployment_hash) = path.into_inner();
        let resp = json!({
            "data": {
                "data": {
                    "token": "test-token-123",
                    "deployment_hash": deployment_hash
                }
            }
        });
        HttpResponse::Ok().json(resp)
    }

    async fn mock_delete() -> HttpResponse {
        HttpResponse::NoContent().finish()
    }

    async fn mock_store_runtime(body: web::Json<Value>) -> HttpResponse {
        if body["data"]["runtime"].is_string() && body["data"]["deployment_hash"].is_string() {
            HttpResponse::NoContent().finish()
        } else {
            HttpResponse::BadRequest().finish()
        }
    }

    async fn mock_fetch_runtime(path: web::Path<(String, String)>) -> HttpResponse {
        let (_prefix, deployment_hash) = path.into_inner();
        let resp = json!({
            "data": {
                "data": {
                    "runtime": "kata",
                    "deployment_hash": deployment_hash
                }
            }
        });
        HttpResponse::Ok().json(resp)
    }

    async fn mock_fetch_org_policy() -> HttpResponse {
        let resp = json!({
            "data": {
                "data": {
                    "require_kata": true
                }
            }
        });
        HttpResponse::Ok().json(resp)
    }

    async fn mock_fetch_org_policy_none() -> HttpResponse {
        HttpResponse::NotFound().finish()
    }

    #[tokio::test]
    async fn test_vault_client_store_fetch_delete() {
        // Start mock Vault server
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind port");
        let port = listener.local_addr().unwrap().port();
        let address = format!("http://127.0.0.1:{}", port);
        let prefix = "agent".to_string();

        let server = HttpServer::new(|| {
            App::new()
                // POST /v1/{prefix}/{deployment_hash}/token
                .route(
                    "/v1/{prefix}/{deployment_hash}/token",
                    web::post().to(mock_store),
                )
                // GET /v1/{prefix}/{deployment_hash}/token
                .route(
                    "/v1/{prefix}/{deployment_hash}/token",
                    web::get().to(mock_fetch),
                )
                // DELETE /v1/{prefix}/{deployment_hash}/token
                .route(
                    "/v1/{prefix}/{deployment_hash}/token",
                    web::delete().to(mock_delete),
                )
        })
        .listen(listener)
        .unwrap()
        .run();

        let _ = tokio::spawn(server);

        // Configure client
        let settings = VaultSettings {
            address: address.clone(),
            token: "dev-token".to_string(),
            agent_path_prefix: prefix.clone(),
            api_prefix: "v1".to_string(),
            ssh_key_path_prefix: None,
        };
        let client = VaultClient::new(&settings);
        let dh = "dep_test_abc";

        // Store
        client
            .store_agent_token(dh, "test-token-123")
            .await
            .expect("store token");

        // Fetch
        let fetched = client.fetch_agent_token(dh).await.expect("fetch token");
        assert_eq!(fetched, "test-token-123");

        // Delete
        client.delete_agent_token(dh).await.expect("delete token");
    }

    #[tokio::test]
    async fn test_vault_runtime_preference_store_fetch_delete() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind port");
        let port = listener.local_addr().unwrap().port();
        let address = format!("http://127.0.0.1:{}", port);

        let server = HttpServer::new(|| {
            App::new()
                .route(
                    "/v1/{prefix}/{deployment_hash}/runtime",
                    web::post().to(mock_store_runtime),
                )
                .route(
                    "/v1/{prefix}/{deployment_hash}/runtime",
                    web::get().to(mock_fetch_runtime),
                )
                .route(
                    "/v1/{prefix}/{deployment_hash}/runtime",
                    web::delete().to(mock_delete),
                )
        })
        .listen(listener)
        .unwrap()
        .run();

        let _ = tokio::spawn(server);

        let settings = VaultSettings {
            address,
            token: "dev-token".to_string(),
            agent_path_prefix: "agent".to_string(),
            api_prefix: "v1".to_string(),
            ssh_key_path_prefix: None,
        };
        let client = VaultClient::new(&settings);
        let dh = "dep_runtime_test";

        // Store runtime preference
        client
            .store_runtime_preference(dh, "kata")
            .await
            .expect("store runtime preference");

        // Fetch runtime preference
        let fetched = client
            .fetch_runtime_preference(dh)
            .await
            .expect("fetch runtime preference");
        assert_eq!(fetched, Some("kata".to_string()));

        // Delete runtime preference
        client
            .delete_runtime_preference(dh)
            .await
            .expect("delete runtime preference");
    }

    #[tokio::test]
    async fn test_vault_org_runtime_policy_enforced() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind port");
        let port = listener.local_addr().unwrap().port();
        let address = format!("http://127.0.0.1:{}", port);

        let server = HttpServer::new(|| {
            App::new().route(
                "/v1/{prefix}/org/{org_id}/runtime_policy",
                web::get().to(mock_fetch_org_policy),
            )
        })
        .listen(listener)
        .unwrap()
        .run();

        let _ = tokio::spawn(server);

        let settings = VaultSettings {
            address,
            token: "dev-token".to_string(),
            agent_path_prefix: "agent".to_string(),
            api_prefix: "v1".to_string(),
            ssh_key_path_prefix: None,
        };
        let client = VaultClient::new(&settings);

        let policy = client
            .fetch_org_runtime_policy("org-123")
            .await
            .expect("fetch org policy");
        assert_eq!(policy, Some("kata".to_string()));
    }

    #[tokio::test]
    async fn test_vault_org_runtime_policy_not_found() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind port");
        let port = listener.local_addr().unwrap().port();
        let address = format!("http://127.0.0.1:{}", port);

        let server = HttpServer::new(|| {
            App::new().route(
                "/v1/{prefix}/org/{org_id}/runtime_policy",
                web::get().to(mock_fetch_org_policy_none),
            )
        })
        .listen(listener)
        .unwrap()
        .run();

        let _ = tokio::spawn(server);

        let settings = VaultSettings {
            address,
            token: "dev-token".to_string(),
            agent_path_prefix: "agent".to_string(),
            api_prefix: "v1".to_string(),
            ssh_key_path_prefix: None,
        };
        let client = VaultClient::new(&settings);

        let policy = client
            .fetch_org_runtime_policy("org-no-policy")
            .await
            .expect("fetch org policy");
        assert_eq!(policy, None);
    }
}
