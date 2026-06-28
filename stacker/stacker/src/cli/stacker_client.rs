//! Stacker Server API Client for CLI
//!
//! Communicates with the Stacker server (not User Service directly) for:
//! - Project CRUD (list, create, lookup by name)
//! - Cloud credential management (list, lookup by provider)
//! - Server management (list, lookup by name)
//! - Deployment (POST /project/{id}/deploy or /project/{id}/deploy/{cloud_id})
//!
//! All endpoints require `Authorization: Bearer <token>` from `stacker login`.

use crate::cli::config_parser::DeployTarget;
use crate::cli::debug::cli_debug_enabled;
use crate::cli::error::CliError;
use crate::handoff::{DeploymentHandoffPayload, DeploymentHandoffResolveRequest};
use crate::services::{
    DeployPlan, DeployPlanOperation, DeploymentEventFeed, DeploymentState, TypedErrorEnvelope,
};
use pipe_adapter_sdk::PipeAdapterReference;
use serde::{Deserialize, Serialize};

/// Default Stacker server base URL (distinct from the User Service auth URL).
pub const DEFAULT_STACKER_URL: &str = "https://stacker.try.direct";

/// Default Vault URL used by status panel roles.
/// The Install Service Ansible role uses this to configure the agent's VAULT_ADDRESS
/// environment variable on the remote server. Must be a publicly reachable address
/// (not a Docker-internal IP) so deployed agents can connect to Vault.
pub const DEFAULT_VAULT_URL: &str = "https://vault.try.direct:8443";

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Response types (matching Stacker server JSON envelope)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Stacker server wraps responses in `{ "item": ..., "list": [...], "msg": "...", "_status": "OK" }`
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ApiResponse<T> {
    #[serde(rename = "_status")]
    pub status: Option<String>,
    pub msg: Option<String>,
    pub item: Option<T>,
    pub list: Option<Vec<T>>,
    pub id: Option<i32>,
    pub meta: Option<serde_json::Value>,
}

fn parse_typed_error_response(body: &str) -> Option<TypedErrorEnvelope> {
    serde_json::from_str(body).ok()
}

fn stacker_api_failure(action: &str, status: u16, body: &str) -> String {
    stacker_api_failure_with_message(
        "Stacker server request failed",
        action,
        status,
        body,
        cli_debug_enabled(),
    )
}

fn stacker_api_failure_with_debug(action: &str, status: u16, body: &str, debug: bool) -> String {
    stacker_api_failure_with_message("Stacker server request failed", action, status, body, debug)
}

fn stacker_api_failure_with_message(
    summary: &str,
    action: &str,
    status: u16,
    body: &str,
    debug: bool,
) -> String {
    if debug {
        format!("Stacker server {action} failed ({status}): {body}")
    } else {
        format!(
            "{summary} ({status}). Rerun with DEBUG=true or RUST_LOG=debug for endpoint details."
        )
    }
}

/// Project as returned by `/project` endpoints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectInfo {
    pub id: i32,
    pub name: String,
    pub user_id: String,
    pub metadata: serde_json::Value,
    pub created_at: String,
    pub updated_at: String,
}

/// Project app as returned by `/project/{id}/apps` endpoints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectAppInfo {
    pub id: i32,
    pub project_id: i32,
    pub code: String,
    pub name: String,
    pub image: String,
    pub enabled: bool,
    pub deploy_order: Option<i32>,
    pub parent_app_code: Option<String>,
}

/// Project app registration payload for `POST /project/{id}/apps`.
#[derive(Debug, Clone, Serialize)]
pub struct ProjectAppRegistrationRequest {
    pub code: String,
    pub name: Option<String>,
    pub image: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ports: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub volumes: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub depends_on: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deploy_order: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deployment_hash: Option<String>,
}

/// Cloud credentials as returned by `/cloud` endpoints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudInfo {
    pub id: i32,
    pub user_id: String,
    #[serde(default)]
    pub name: String,
    pub provider: String,
    pub cloud_token: Option<String>,
    pub cloud_key: Option<String>,
    pub cloud_secret: Option<String>,
    pub save_token: Option<bool>,
}

/// Server as returned by `/server` endpoints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    pub id: i32,
    pub user_id: String,
    pub project_id: i32,
    pub cloud_id: Option<i32>,
    #[serde(default)]
    pub cloud: Option<String>,
    pub region: Option<String>,
    pub zone: Option<String>,
    pub server: Option<String>,
    pub os: Option<String>,
    pub disk_type: Option<String>,
    pub srv_ip: Option<String>,
    pub ssh_port: Option<i32>,
    pub ssh_user: Option<String>,
    pub name: Option<String>,
    pub vault_key_path: Option<String>,
    #[serde(default = "default_connection_mode")]
    pub connection_mode: String,
    #[serde(default = "default_key_status")]
    pub key_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteSecretMetadataInfo {
    pub id: i32,
    pub scope: String,
    pub name: String,
    pub project_id: Option<i32>,
    pub app_code: Option<String>,
    pub server_id: Option<i32>,
    pub updated_at: String,
    pub updated_by: String,
    pub source: String,
}

fn default_connection_mode() -> String {
    "ssh".to_string()
}
fn default_key_status() -> String {
    "none".to_string()
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// SSH key response types
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Response from `POST /server/{id}/ssh-key/generate`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateKeyResponse {
    pub public_key: String,
    pub private_key: Option<String>,
    pub fingerprint: Option<String>,
    pub message: String,
}

/// Response from `GET /server/{id}/ssh-key/public`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyResponse {
    pub public_key: String,
    pub fingerprint: Option<String>,
}

/// Response from `POST /server/{id}/ssh-key/authorize-public-key`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizePublicKeyResponse {
    pub server_id: i32,
    pub srv_ip: String,
    pub ssh_user: String,
    pub ssh_port: u16,
    pub authorized: bool,
    pub message: String,
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Marketplace response types
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Marketplace template summary as returned by `GET /marketplace`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketplaceTemplate {
    pub id: Option<serde_json::Value>,
    pub slug: String,
    pub name: String,
    pub description: Option<String>,
    pub category_code: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub status: Option<String>,
    pub stack_definition: Option<serde_json::Value>,
}

/// Marketplace template info as returned by `/api/templates/mine`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketplaceTemplateInfo {
    pub id: String,
    pub name: String,
    pub slug: String,
    #[serde(default)]
    pub status: String,
    pub short_description: Option<String>,
    pub price: Option<f64>,
    pub billing_cycle: Option<String>,
    pub version: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub approved_at: Option<String>,
    pub review_reason: Option<String>,
}

/// Review history entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketplaceReviewInfo {
    pub id: String,
    pub template_id: String,
    pub reviewer_user_id: Option<String>,
    pub decision: String,
    pub review_reason: Option<String>,
    pub submitted_at: Option<String>,
    pub reviewed_at: Option<String>,
    pub security_checklist: Option<serde_json::Value>,
}

/// Deploy response from `/project/{id}/deploy`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployResponse {
    pub id: Option<i32>,
    #[serde(rename = "_status")]
    pub status: Option<String>,
    pub msg: Option<String>,
    pub meta: Option<serde_json::Value>,
}

/// Deployment status info from `/api/v1/deployments/{id}`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentStatusInfo {
    pub id: i32,
    pub project_id: i32,
    pub deployment_hash: String,
    pub status: String,
    /// Human-readable status/error message from the deployment pipeline.
    pub status_message: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Pipe template info from `/api/v1/pipes/templates`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipeTemplateInfo {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub source_app_type: String,
    pub source_endpoint: serde_json::Value,
    pub target_app_type: String,
    pub target_endpoint: serde_json::Value,
    #[serde(default)]
    pub target_external_url: Option<String>,
    pub field_mapping: serde_json::Value,
    #[serde(default)]
    pub config: Option<serde_json::Value>,
    #[serde(default)]
    pub is_public: Option<bool>,
    pub created_by: String,
    pub created_at: String,
    pub updated_at: String,
}

/// Pipe instance info from `/api/v1/pipes/instances`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipeInstanceInfo {
    pub id: String,
    #[serde(default)]
    pub template_id: Option<String>,
    pub deployment_hash: String,
    #[serde(default)]
    pub source_adapter: Option<PipeAdapterReference>,
    pub source_container: String,
    #[serde(default)]
    pub target_adapter: Option<PipeAdapterReference>,
    #[serde(default)]
    pub target_container: Option<String>,
    #[serde(default)]
    pub target_url: Option<String>,
    #[serde(default)]
    pub field_mapping_override: Option<serde_json::Value>,
    #[serde(default)]
    pub config_override: Option<serde_json::Value>,
    pub status: String,
    #[serde(default)]
    pub last_triggered_at: Option<String>,
    #[serde(default)]
    pub trigger_count: i64,
    #[serde(default)]
    pub error_count: i64,
    pub created_by: String,
    pub created_at: String,
    pub updated_at: String,
}

/// Pipe execution info from `/api/v1/pipes/executions`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipeExecutionInfo {
    pub id: String,
    pub pipe_instance_id: String,
    pub deployment_hash: String,
    pub trigger_type: String,
    pub status: String,
    #[serde(default)]
    pub source_data: Option<serde_json::Value>,
    #[serde(default)]
    pub mapped_data: Option<serde_json::Value>,
    #[serde(default)]
    pub target_response: Option<serde_json::Value>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub duration_ms: Option<i64>,
    #[serde(default)]
    pub replay_of: Option<String>,
    pub created_by: String,
    pub started_at: String,
    #[serde(default)]
    pub completed_at: Option<String>,
}

/// Replay response from `/api/v1/pipes/executions/{id}/replay`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipeReplayResponse {
    pub execution_id: String,
    pub replay_of: String,
    #[serde(default)]
    pub command_id: Option<String>,
    pub status: String,
}

/// Request body for creating a pipe template
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePipeTemplateApiRequest {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub source_app_type: String,
    pub source_endpoint: serde_json::Value,
    pub target_app_type: String,
    pub target_endpoint: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_external_url: Option<String>,
    pub field_mapping: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_public: Option<bool>,
}

/// Request body for creating a pipe instance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePipeInstanceApiRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deployment_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_adapter: Option<PipeAdapterReference>,
    pub source_container: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_adapter: Option<PipeAdapterReference>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_container: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field_mapping_override: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_override: Option<serde_json::Value>,
}

/// Request body for deploying (promoting) a local pipe to remote
#[derive(Debug, Serialize)]
pub struct DeployPipeApiRequest {
    pub deployment_hash: String,
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// StackerClient — HTTP client for the Stacker server
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

pub struct StackerClient {
    base_url: String,
    token: String,
    target: DeployTarget,
    http: reqwest::Client,
}

impl StackerClient {
    pub fn new(base_url: &str, token: &str) -> Self {
        Self::new_for_target(base_url, token, DeployTarget::Cloud)
    }

    pub fn new_for_target(base_url: &str, token: &str, target: DeployTarget) -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            token: token.to_string(),
            target,
            http,
        }
    }

    fn project_endpoint_candidates(&self, suffix: &str) -> [String; 2] {
        [
            format!("{}/api/v1/project{}", self.base_url, suffix),
            format!("{}/project{}", self.base_url, suffix),
        ]
    }

    async fn send_project_request(
        &self,
        method: reqwest::Method,
        suffix: &str,
        body: Option<&serde_json::Value>,
        action_label: &str,
    ) -> Result<reqwest::Response, CliError> {
        let mut last_response = None;

        for url in self.project_endpoint_candidates(suffix) {
            let mut request = self
                .http
                .request(method.clone(), &url)
                .bearer_auth(&self.token);
            if let Some(payload) = body {
                request = request.json(payload);
            }

            let resp = request.send().await.map_err(|e| CliError::DeployFailed {
                target: self.target.clone(),
                reason: format!("Stacker server unreachable: {}", e),
            })?;

            if resp.status().is_success() {
                return Ok(resp);
            }

            last_response = Some(resp);
        }

        last_response.ok_or_else(|| CliError::DeployFailed {
            target: self.target.clone(),
            reason: format!(
                "Stacker server {} failed: project endpoints were not reachable",
                action_label
            ),
        })
    }

    async fn send_server_request(
        &self,
        method: reqwest::Method,
        suffix: &str,
        body: Option<&serde_json::Value>,
        action_label: &str,
    ) -> Result<reqwest::Response, CliError> {
        let url = format!("{}/server{}", self.base_url, suffix);
        let mut request = self.http.request(method, &url).bearer_auth(&self.token);
        if let Some(payload) = body {
            request = request.json(payload);
        }

        request.send().await.map_err(|e| CliError::DeployFailed {
            target: self.target.clone(),
            reason: format!("Stacker server {} failed: {}", action_label, e),
        })
    }

    pub async fn resolve_handoff(
        base_url: &str,
        token: &str,
    ) -> Result<DeploymentHandoffPayload, CliError> {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");
        let url = format!("{}/api/v1/handoff/resolve", base_url.trim_end_matches('/'));
        let resp = http
            .post(&url)
            .json(&DeploymentHandoffResolveRequest {
                token: token.to_string(),
            })
            .send()
            .await
            .map_err(|e| CliError::DeployFailed {
                target: crate::cli::config_parser::DeployTarget::Cloud,
                reason: format!("Stacker server unreachable: {}", e),
            })?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::DeployFailed {
                target: crate::cli::config_parser::DeployTarget::Cloud,
                reason: stacker_api_failure_with_message(
                    "Stacker handoff resolve failed",
                    "POST /api/v1/handoff/resolve",
                    status,
                    &body,
                    cli_debug_enabled(),
                ),
            });
        }

        let api: ApiResponse<DeploymentHandoffPayload> =
            resp.json().await.map_err(|e| CliError::DeployFailed {
                target: crate::cli::config_parser::DeployTarget::Cloud,
                reason: format!("Invalid response from Stacker server: {}", e),
            })?;

        api.item.ok_or_else(|| CliError::DeployFailed {
            target: crate::cli::config_parser::DeployTarget::Cloud,
            reason: "Stacker handoff response did not include payload".to_string(),
        })
    }

    // ── Projects ─────────────────────────────────────

    /// List all projects for the authenticated user.
    pub async fn list_projects(&self) -> Result<Vec<ProjectInfo>, CliError> {
        let resp = self
            .send_project_request(reqwest::Method::GET, "", None, "GET /project")
            .await?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::DeployFailed {
                target: self.target.clone(),
                reason: stacker_api_failure("GET /project", status, &body),
            });
        }

        let api: ApiResponse<ProjectInfo> =
            resp.json().await.map_err(|e| CliError::DeployFailed {
                target: self.target.clone(),
                reason: format!("Invalid response from Stacker server: {}", e),
            })?;

        Ok(api.list.unwrap_or_default())
    }

    /// Find a project by name (case-insensitive).
    pub async fn find_project_by_name(&self, name: &str) -> Result<Option<ProjectInfo>, CliError> {
        let projects = self.list_projects().await?;
        let lower = name.to_lowercase();
        Ok(projects
            .into_iter()
            .find(|p| p.name.to_lowercase() == lower))
    }

    pub async fn find_project(&self, reference: &str) -> Result<Option<ProjectInfo>, CliError> {
        let projects = self.list_projects().await?;
        let lower = reference.to_lowercase();
        Ok(projects.into_iter().find(|project| {
            project.id.to_string() == reference || project.name.to_lowercase() == lower
        }))
    }

    /// List all apps for a project owned by the authenticated user.
    pub async fn list_project_apps(
        &self,
        project_id: i32,
    ) -> Result<Vec<ProjectAppInfo>, CliError> {
        let resp = self
            .send_project_request(
                reqwest::Method::GET,
                &format!("/{}/apps", project_id),
                None,
                "GET /project/{id}/apps",
            )
            .await?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            if let Some(error) = parse_typed_error_response(&body) {
                return Err(error.into());
            }
            return Err(CliError::DeployFailed {
                target: self.target.clone(),
                reason: stacker_api_failure(
                    &format!("GET /project/{project_id}/apps"),
                    status,
                    &body,
                ),
            });
        }

        let api: ApiResponse<ProjectAppInfo> =
            resp.json().await.map_err(|e| CliError::DeployFailed {
                target: self.target.clone(),
                reason: format!("Invalid response from Stacker server: {}", e),
            })?;

        Ok(api.list.unwrap_or_default())
    }

    /// Create or update one project app target.
    pub async fn upsert_project_app(
        &self,
        project_id: i32,
        request: &ProjectAppRegistrationRequest,
    ) -> Result<ProjectAppInfo, CliError> {
        let body =
            serde_json::to_value(request).map_err(|e| CliError::ConfigValidation(e.to_string()))?;
        let resp = self
            .send_project_request(
                reqwest::Method::POST,
                &format!("/{}/apps", project_id),
                Some(&body),
                "POST /project/{id}/apps",
            )
            .await?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::DeployFailed {
                target: self.target,
                reason: stacker_api_failure(
                    &format!("POST /project/{project_id}/apps"),
                    status,
                    &body,
                ),
            });
        }

        let api: ApiResponse<ProjectAppInfo> =
            resp.json().await.map_err(|e| CliError::DeployFailed {
                target: self.target,
                reason: format!("Invalid response from Stacker server: {}", e),
            })?;

        api.item.ok_or_else(|| CliError::DeployFailed {
            target: self.target,
            reason: "Stacker server did not return a project app".to_string(),
        })
    }

    /// Delete one project app target by exact code.
    pub async fn delete_project_app(
        &self,
        project_id: i32,
        app_code: &str,
        deployment_hash: Option<&str>,
    ) -> Result<(), CliError> {
        let suffix = if let Some(hash) = deployment_hash.filter(|value| !value.trim().is_empty()) {
            format!(
                "/{}/apps/{}?deployment_hash={}",
                project_id,
                app_code,
                urlencoding::encode(hash)
            )
        } else {
            format!("/{}/apps/{}", project_id, app_code)
        };

        let resp = self
            .send_project_request(
                reqwest::Method::DELETE,
                &suffix,
                None,
                "DELETE /project/{id}/apps/{code}",
            )
            .await?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            if let Some(error) = parse_typed_error_response(&body) {
                return Err(error.into());
            }
            return Err(CliError::DeployFailed {
                target: self.target.clone(),
                reason: stacker_api_failure(
                    &format!("DELETE /project/{project_id}/apps/{app_code}"),
                    status,
                    &body,
                ),
            });
        }

        Ok(())
    }

    // ── Deployments ───────────────────────────────────

    /// List deployments for the authenticated user.
    pub async fn list_deployments(
        &self,
        project_id: Option<i32>,
        limit: Option<i64>,
    ) -> Result<Vec<DeploymentStatusInfo>, CliError> {
        let url = format!("{}/api/v1/deployments", self.base_url);
        let mut req = self.http.get(&url).bearer_auth(&self.token);

        if let Some(pid) = project_id {
            req = req.query(&[("project_id", pid)]);
        }
        if let Some(limit) = limit {
            req = req.query(&[("limit", limit)]);
        }

        let resp = req.send().await.map_err(|e| CliError::DeployFailed {
            target: crate::cli::config_parser::DeployTarget::Cloud,
            reason: format!("Stacker server unreachable: {}", e),
        })?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::DeployFailed {
                target: crate::cli::config_parser::DeployTarget::Cloud,
                reason: stacker_api_failure("GET /api/v1/deployments", status, &body),
            });
        }

        let api: ApiResponse<DeploymentStatusInfo> =
            resp.json().await.map_err(|e| CliError::DeployFailed {
                target: crate::cli::config_parser::DeployTarget::Cloud,
                reason: format!("Invalid response from Stacker server: {}", e),
            })?;

        Ok(api.list.unwrap_or_default())
    }

    /// Create a project on the Stacker server.
    pub async fn create_project(
        &self,
        name: &str,
        metadata: serde_json::Value,
    ) -> Result<ProjectInfo, CliError> {
        // If metadata already has "custom" key (e.g. from build_project_body),
        // use it directly. Otherwise, wrap in a default structure.
        let body = if metadata.get("custom").is_some() {
            // Ensure custom_stack_code is set to the project name
            let mut body = metadata;
            if let Some(custom) = body.get_mut("custom").and_then(|c| c.as_object_mut()) {
                custom
                    .entry("custom_stack_code")
                    .or_insert_with(|| serde_json::json!(name));
            }
            body
        } else {
            let payload = serde_json::json!({
                "custom": {
                    "custom_stack_code": name,
                    "web": [],
                    "feature": [],
                    "service": [],
                }
            });

            // Merge metadata if provided
            if metadata.is_object() {
                let mut base = payload;
                if let Some(obj) = base.as_object_mut() {
                    if let Some(meta_obj) = metadata.as_object() {
                        for (k, v) in meta_obj {
                            obj.insert(k.clone(), v.clone());
                        }
                    }
                }
                base
            } else {
                payload
            }
        };

        let resp = self
            .send_project_request(reqwest::Method::POST, "", Some(&body), "POST /project")
            .await?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::DeployFailed {
                target: self.target.clone(),
                reason: stacker_api_failure("POST /project", status, &body),
            });
        }

        let api: ApiResponse<ProjectInfo> =
            resp.json().await.map_err(|e| CliError::DeployFailed {
                target: self.target.clone(),
                reason: format!("Invalid response from Stacker server: {}", e),
            })?;

        api.item.ok_or_else(|| CliError::DeployFailed {
            target: self.target.clone(),
            reason: "Stacker server created project but returned no item".to_string(),
        })
    }

    /// Update an existing project's metadata on the Stacker server.
    pub async fn update_project(
        &self,
        project_id: i32,
        body: serde_json::Value,
    ) -> Result<ProjectInfo, CliError> {
        let resp = self
            .send_project_request(
                reqwest::Method::PUT,
                &format!("/{}", project_id),
                Some(&body),
                "PUT /project/{id}",
            )
            .await?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::DeployFailed {
                target: self.target.clone(),
                reason: stacker_api_failure(&format!("PUT /project/{project_id}"), status, &body),
            });
        }

        let api: ApiResponse<ProjectInfo> =
            resp.json().await.map_err(|e| CliError::DeployFailed {
                target: self.target.clone(),
                reason: format!("Invalid response from Stacker server: {}", e),
            })?;

        api.item.ok_or_else(|| CliError::DeployFailed {
            target: self.target.clone(),
            reason: "Stacker server updated project but returned no item".to_string(),
        })
    }

    // ── Cloud credentials ────────────────────────────

    /// List all saved cloud credentials for the authenticated user.
    pub async fn list_clouds(&self) -> Result<Vec<CloudInfo>, CliError> {
        let url = format!("{}/cloud", self.base_url);
        let resp = self
            .http
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| CliError::DeployFailed {
                target: crate::cli::config_parser::DeployTarget::Cloud,
                reason: format!("Stacker server unreachable: {}", e),
            })?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::DeployFailed {
                target: crate::cli::config_parser::DeployTarget::Cloud,
                reason: stacker_api_failure("GET /cloud", status, &body),
            });
        }

        let api: ApiResponse<CloudInfo> =
            resp.json().await.map_err(|e| CliError::DeployFailed {
                target: crate::cli::config_parser::DeployTarget::Cloud,
                reason: format!("Invalid response from Stacker server: {}", e),
            })?;

        Ok(api.list.unwrap_or_default())
    }

    /// Find saved cloud credentials by provider name (e.g. "hetzner", "digital_ocean").
    pub async fn find_cloud_by_provider(
        &self,
        provider: &str,
    ) -> Result<Option<CloudInfo>, CliError> {
        let clouds = self.list_clouds().await?;
        let lower = provider.to_lowercase();
        Ok(clouds
            .into_iter()
            .find(|c| c.provider.to_lowercase() == lower))
    }

    /// Find saved cloud credentials by name (e.g. "my-hetzner", "htz-4").
    pub async fn find_cloud_by_name(&self, name: &str) -> Result<Option<CloudInfo>, CliError> {
        let clouds = self.list_clouds().await?;
        let lower = name.to_lowercase();
        Ok(clouds.into_iter().find(|c| c.name.to_lowercase() == lower))
    }

    /// Find saved cloud credentials by ID.
    pub async fn get_cloud(&self, cloud_id: i32) -> Result<Option<CloudInfo>, CliError> {
        let url = format!("{}/cloud/{}", self.base_url, cloud_id);
        let resp = self
            .http
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| CliError::DeployFailed {
                target: crate::cli::config_parser::DeployTarget::Cloud,
                reason: format!("Stacker server unreachable: {}", e),
            })?;

        if resp.status().as_u16() == 404 {
            return Ok(None);
        }

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::DeployFailed {
                target: crate::cli::config_parser::DeployTarget::Cloud,
                reason: stacker_api_failure(&format!("GET /cloud/{cloud_id}"), status, &body),
            });
        }

        let api: ApiResponse<CloudInfo> =
            resp.json().await.map_err(|e| CliError::DeployFailed {
                target: crate::cli::config_parser::DeployTarget::Cloud,
                reason: format!("Invalid response from Stacker server: {}", e),
            })?;

        Ok(api.item)
    }

    /// Save cloud credentials to the Stacker server.
    /// If credentials already exist for the provider, updates the existing record.
    pub async fn save_cloud(
        &self,
        provider: &str,
        cloud_token: Option<&str>,
        cloud_key: Option<&str>,
        cloud_secret: Option<&str>,
    ) -> Result<CloudInfo, CliError> {
        // Check if credentials already exist for this provider — update instead of insert
        if let Some(existing) = self.find_cloud_by_provider(provider).await? {
            return self
                .update_cloud(
                    existing.id,
                    provider,
                    &existing.name,
                    cloud_token,
                    cloud_key,
                    cloud_secret,
                )
                .await;
        }
        self.save_cloud_with_name(provider, None, cloud_token, cloud_key, cloud_secret)
            .await
    }

    /// Update existing cloud credentials by id.
    pub async fn update_cloud(
        &self,
        id: i32,
        provider: &str,
        name: &str,
        cloud_token: Option<&str>,
        cloud_key: Option<&str>,
        cloud_secret: Option<&str>,
    ) -> Result<CloudInfo, CliError> {
        let url = format!("{}/cloud/{}", self.base_url, id);

        let mut payload = serde_json::json!({
            "provider": provider,
            "name": name,
            "save_token": true,
        });

        if let Some(obj) = payload.as_object_mut() {
            if let Some(t) = cloud_token {
                obj.insert(
                    "cloud_token".to_string(),
                    serde_json::Value::String(t.to_string()),
                );
            }
            if let Some(k) = cloud_key {
                obj.insert(
                    "cloud_key".to_string(),
                    serde_json::Value::String(k.to_string()),
                );
            }
            if let Some(s) = cloud_secret {
                obj.insert(
                    "cloud_secret".to_string(),
                    serde_json::Value::String(s.to_string()),
                );
            }
        }

        let resp = self
            .http
            .put(&url)
            .bearer_auth(&self.token)
            .json(&payload)
            .send()
            .await
            .map_err(|e| CliError::DeployFailed {
                target: crate::cli::config_parser::DeployTarget::Cloud,
                reason: format!("Stacker server unreachable: {}", e),
            })?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::DeployFailed {
                target: crate::cli::config_parser::DeployTarget::Cloud,
                reason: stacker_api_failure(&format!("PUT /cloud/{id}"), status, &body),
            });
        }

        let api: ApiResponse<CloudInfo> =
            resp.json().await.map_err(|e| CliError::DeployFailed {
                target: crate::cli::config_parser::DeployTarget::Cloud,
                reason: format!("Invalid response from Stacker server: {}", e),
            })?;

        api.item.ok_or_else(|| CliError::DeployFailed {
            target: crate::cli::config_parser::DeployTarget::Cloud,
            reason: "Stacker server updated cloud but returned no item".to_string(),
        })
    }

    /// Save cloud credentials with an optional name.
    pub async fn save_cloud_with_name(
        &self,
        provider: &str,
        name: Option<&str>,
        cloud_token: Option<&str>,
        cloud_key: Option<&str>,
        cloud_secret: Option<&str>,
    ) -> Result<CloudInfo, CliError> {
        let url = format!("{}/cloud", self.base_url);

        let mut payload = serde_json::json!({
            "provider": provider,
            "save_token": true,
        });

        if let Some(obj) = payload.as_object_mut() {
            if let Some(n) = name {
                obj.insert("name".to_string(), serde_json::Value::String(n.to_string()));
            }
            if let Some(t) = cloud_token {
                obj.insert(
                    "cloud_token".to_string(),
                    serde_json::Value::String(t.to_string()),
                );
            }
            if let Some(k) = cloud_key {
                obj.insert(
                    "cloud_key".to_string(),
                    serde_json::Value::String(k.to_string()),
                );
            }
            if let Some(s) = cloud_secret {
                obj.insert(
                    "cloud_secret".to_string(),
                    serde_json::Value::String(s.to_string()),
                );
            }
        }

        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.token)
            .json(&payload)
            .send()
            .await
            .map_err(|e| CliError::DeployFailed {
                target: crate::cli::config_parser::DeployTarget::Cloud,
                reason: format!("Stacker server unreachable: {}", e),
            })?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::DeployFailed {
                target: crate::cli::config_parser::DeployTarget::Cloud,
                reason: stacker_api_failure("POST /cloud", status, &body),
            });
        }

        let api: ApiResponse<CloudInfo> =
            resp.json().await.map_err(|e| CliError::DeployFailed {
                target: crate::cli::config_parser::DeployTarget::Cloud,
                reason: format!("Invalid response from Stacker server: {}", e),
            })?;

        api.item.ok_or_else(|| CliError::DeployFailed {
            target: crate::cli::config_parser::DeployTarget::Cloud,
            reason: "Stacker server saved cloud but returned no item".to_string(),
        })
    }

    // ── Servers ──────────────────────────────────────

    /// List all servers for the authenticated user.
    pub async fn list_servers(&self) -> Result<Vec<ServerInfo>, CliError> {
        let url = format!("{}/server", self.base_url);
        let resp = self
            .http
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| CliError::DeployFailed {
                target: self.target.clone(),
                reason: format!("Stacker server unreachable: {}", e),
            })?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::DeployFailed {
                target: self.target.clone(),
                reason: stacker_api_failure("GET /server", status, &body),
            });
        }

        let api: ApiResponse<ServerInfo> =
            resp.json().await.map_err(|e| CliError::DeployFailed {
                target: self.target.clone(),
                reason: format!("Invalid response from Stacker server: {}", e),
            })?;

        Ok(api.list.unwrap_or_default())
    }

    /// Find a server by name (case-insensitive).
    pub async fn find_server_by_name(&self, name: &str) -> Result<Option<ServerInfo>, CliError> {
        let servers = self.list_servers().await?;
        let lower = name.to_lowercase();
        Ok(servers.into_iter().find(|s| {
            s.name
                .as_deref()
                .map(|n| n.to_lowercase() == lower)
                .unwrap_or(false)
        }))
    }

    pub async fn get_service_secret_metadata(
        &self,
        project_id: i32,
        app_code: &str,
        name: &str,
    ) -> Result<Option<RemoteSecretMetadataInfo>, CliError> {
        let resp = self
            .send_project_request(
                reqwest::Method::GET,
                &format!("/{}/apps/{}/secrets/{}", project_id, app_code, name),
                None,
                "GET /project/{id}/apps/{code}/secrets/{name}",
            )
            .await?;

        if resp.status().as_u16() == 404 {
            return Ok(None);
        }

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::DeployFailed {
                target: self.target.clone(),
                reason: stacker_api_failure(
                    &format!("GET /project/{project_id}/apps/{app_code}/secrets/{name}"),
                    status,
                    &body,
                ),
            });
        }

        let api: ApiResponse<RemoteSecretMetadataInfo> =
            resp.json().await.map_err(|e| CliError::DeployFailed {
                target: self.target.clone(),
                reason: format!("Invalid response from Stacker server: {}", e),
            })?;

        Ok(api.item)
    }

    pub async fn list_service_secrets(
        &self,
        project_id: i32,
        app_code: &str,
    ) -> Result<Vec<RemoteSecretMetadataInfo>, CliError> {
        let resp = self
            .send_project_request(
                reqwest::Method::GET,
                &format!("/{}/apps/{}/secrets", project_id, app_code),
                None,
                "GET /project/{id}/apps/{code}/secrets",
            )
            .await?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::DeployFailed {
                target: self.target.clone(),
                reason: stacker_api_failure(
                    &format!("GET /project/{project_id}/apps/{app_code}/secrets"),
                    status,
                    &body,
                ),
            });
        }

        let api: ApiResponse<RemoteSecretMetadataInfo> =
            resp.json().await.map_err(|e| CliError::DeployFailed {
                target: self.target.clone(),
                reason: format!("Invalid response from Stacker server: {}", e),
            })?;

        Ok(api.list.unwrap_or_default())
    }

    pub async fn set_service_secret(
        &self,
        project_id: i32,
        app_code: &str,
        name: &str,
        value: &str,
    ) -> Result<RemoteSecretMetadataInfo, CliError> {
        let body = serde_json::json!({ "value": value });
        let resp = self
            .send_project_request(
                reqwest::Method::PUT,
                &format!("/{}/apps/{}/secrets/{}", project_id, app_code, name),
                Some(&body),
                "PUT /project/{id}/apps/{code}/secrets/{name}",
            )
            .await?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::DeployFailed {
                target: self.target.clone(),
                reason: stacker_api_failure(
                    &format!("PUT /project/{project_id}/apps/{app_code}/secrets/{name}"),
                    status,
                    &body,
                ),
            });
        }

        let api: ApiResponse<RemoteSecretMetadataInfo> =
            resp.json().await.map_err(|e| CliError::DeployFailed {
                target: self.target.clone(),
                reason: format!("Invalid response from Stacker server: {}", e),
            })?;

        api.item.ok_or_else(|| CliError::DeployFailed {
            target: self.target.clone(),
            reason: "Stacker server saved secret but returned no item".to_string(),
        })
    }

    pub async fn delete_service_secret(
        &self,
        project_id: i32,
        app_code: &str,
        name: &str,
    ) -> Result<(), CliError> {
        let resp = self
            .send_project_request(
                reqwest::Method::DELETE,
                &format!("/{}/apps/{}/secrets/{}", project_id, app_code, name),
                None,
                "DELETE /project/{id}/apps/{code}/secrets/{name}",
            )
            .await?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::DeployFailed {
                target: self.target.clone(),
                reason: stacker_api_failure(
                    &format!("DELETE /project/{project_id}/apps/{app_code}/secrets/{name}"),
                    status,
                    &body,
                ),
            });
        }

        Ok(())
    }

    pub async fn get_server_secret_metadata(
        &self,
        server_id: i32,
        name: &str,
    ) -> Result<Option<RemoteSecretMetadataInfo>, CliError> {
        let resp = self
            .send_server_request(
                reqwest::Method::GET,
                &format!("/{}/secrets/{}", server_id, name),
                None,
                "GET /server/{id}/secrets/{name}",
            )
            .await?;

        if resp.status().as_u16() == 404 {
            return Ok(None);
        }

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::DeployFailed {
                target: self.target.clone(),
                reason: stacker_api_failure(
                    &format!("GET /server/{server_id}/secrets/{name}"),
                    status,
                    &body,
                ),
            });
        }

        let api: ApiResponse<RemoteSecretMetadataInfo> =
            resp.json().await.map_err(|e| CliError::DeployFailed {
                target: self.target.clone(),
                reason: format!("Invalid response from Stacker server: {}", e),
            })?;

        Ok(api.item)
    }

    pub async fn list_server_secrets(
        &self,
        server_id: i32,
    ) -> Result<Vec<RemoteSecretMetadataInfo>, CliError> {
        let resp = self
            .send_server_request(
                reqwest::Method::GET,
                &format!("/{}/secrets", server_id),
                None,
                "GET /server/{id}/secrets",
            )
            .await?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::DeployFailed {
                target: self.target.clone(),
                reason: stacker_api_failure(
                    &format!("GET /server/{server_id}/secrets"),
                    status,
                    &body,
                ),
            });
        }

        let api: ApiResponse<RemoteSecretMetadataInfo> =
            resp.json().await.map_err(|e| CliError::DeployFailed {
                target: self.target.clone(),
                reason: format!("Invalid response from Stacker server: {}", e),
            })?;

        Ok(api.list.unwrap_or_default())
    }

    pub async fn set_server_secret(
        &self,
        server_id: i32,
        name: &str,
        value: &str,
    ) -> Result<RemoteSecretMetadataInfo, CliError> {
        let body = serde_json::json!({ "value": value });
        let resp = self
            .send_server_request(
                reqwest::Method::PUT,
                &format!("/{}/secrets/{}", server_id, name),
                Some(&body),
                "PUT /server/{id}/secrets/{name}",
            )
            .await?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::DeployFailed {
                target: self.target.clone(),
                reason: stacker_api_failure(
                    &format!("PUT /server/{server_id}/secrets/{name}"),
                    status,
                    &body,
                ),
            });
        }

        let api: ApiResponse<RemoteSecretMetadataInfo> =
            resp.json().await.map_err(|e| CliError::DeployFailed {
                target: self.target.clone(),
                reason: format!("Invalid response from Stacker server: {}", e),
            })?;

        api.item.ok_or_else(|| CliError::DeployFailed {
            target: self.target.clone(),
            reason: "Stacker server saved secret but returned no item".to_string(),
        })
    }

    pub async fn delete_server_secret(&self, server_id: i32, name: &str) -> Result<(), CliError> {
        let resp = self
            .send_server_request(
                reqwest::Method::DELETE,
                &format!("/{}/secrets/{}", server_id, name),
                None,
                "DELETE /server/{id}/secrets/{name}",
            )
            .await?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::DeployFailed {
                target: self.target.clone(),
                reason: stacker_api_failure(
                    &format!("DELETE /server/{server_id}/secrets/{name}"),
                    status,
                    &body,
                ),
            });
        }

        Ok(())
    }

    // ── SSH Keys ─────────────────────────────────────

    /// Generate a new SSH key pair for a server (stored in Vault).
    pub async fn generate_ssh_key(&self, server_id: i32) -> Result<GenerateKeyResponse, CliError> {
        let url = format!("{}/server/{}/ssh-key/generate", self.base_url, server_id);
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| CliError::DeployFailed {
                target: crate::cli::config_parser::DeployTarget::Cloud,
                reason: format!("Stacker server unreachable: {}", e),
            })?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::DeployFailed {
                target: crate::cli::config_parser::DeployTarget::Cloud,
                reason: stacker_api_failure_with_message(
                    &format!("SSH key generation failed for server {server_id}"),
                    &format!("POST /server/{server_id}/ssh-key/generate"),
                    status,
                    &body,
                    cli_debug_enabled(),
                ),
            });
        }

        let api: ApiResponse<GenerateKeyResponse> =
            resp.json().await.map_err(|e| CliError::DeployFailed {
                target: crate::cli::config_parser::DeployTarget::Cloud,
                reason: format!("Invalid response from Stacker server: {}", e),
            })?;

        api.item.ok_or_else(|| CliError::DeployFailed {
            target: crate::cli::config_parser::DeployTarget::Cloud,
            reason: "Server generated key but returned no item".to_string(),
        })
    }

    /// Get the public SSH key for a server from Vault.
    pub async fn get_ssh_public_key(&self, server_id: i32) -> Result<PublicKeyResponse, CliError> {
        let url = format!("{}/server/{}/ssh-key/public", self.base_url, server_id);
        let resp = self
            .http
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| CliError::DeployFailed {
                target: self.target.clone(),
                reason: format!("Stacker server unreachable: {}", e),
            })?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::DeployFailed {
                target: crate::cli::config_parser::DeployTarget::Cloud,
                reason: stacker_api_failure_with_message(
                    &format!("Failed to fetch SSH public key for server {server_id}"),
                    &format!("GET /server/{server_id}/ssh-key/public"),
                    status,
                    &body,
                    cli_debug_enabled(),
                ),
            });
        }

        let api: ApiResponse<PublicKeyResponse> =
            resp.json().await.map_err(|e| CliError::DeployFailed {
                target: crate::cli::config_parser::DeployTarget::Cloud,
                reason: format!("Invalid response from Stacker server: {}", e),
            })?;

        api.item.ok_or_else(|| CliError::DeployFailed {
            target: crate::cli::config_parser::DeployTarget::Cloud,
            reason: "No SSH key found for this server".to_string(),
        })
    }

    /// Authorize a local public SSH key on a server using the server-side Vault key.
    pub async fn authorize_ssh_public_key(
        &self,
        server_id: i32,
        public_key: &str,
        user: Option<&str>,
        port: Option<u16>,
    ) -> Result<AuthorizePublicKeyResponse, CliError> {
        let url = format!(
            "{}/server/{}/ssh-key/authorize-public-key",
            self.base_url, server_id
        );
        let body = serde_json::json!({
            "public_key": public_key,
            "user": user,
            "port": port,
        });

        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await
            .map_err(|e| CliError::DeployFailed {
                target: self.target,
                reason: format!("Stacker server unreachable: {}", e),
            })?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::DeployFailed {
                target: self.target,
                reason: stacker_api_failure_with_message(
                    &format!("Failed to authorize SSH public key for server {server_id}"),
                    &format!("POST /server/{server_id}/ssh-key/authorize-public-key"),
                    status,
                    &body,
                    cli_debug_enabled(),
                ),
            });
        }

        let api: ApiResponse<AuthorizePublicKeyResponse> =
            resp.json().await.map_err(|e| CliError::DeployFailed {
                target: self.target,
                reason: format!("Invalid response from Stacker server: {}", e),
            })?;

        api.item.ok_or_else(|| CliError::DeployFailed {
            target: self.target,
            reason: "Server authorized SSH public key but returned no item".to_string(),
        })
    }

    pub async fn configure_cloud_firewall(
        &self,
        server_id: i32,
        request: &crate::forms::ConfigureCloudFirewallRequest,
    ) -> Result<crate::forms::ConfigureCloudFirewallResponse, CliError> {
        let url = format!("{}/server/{}/cloud-firewall", self.base_url, server_id);
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.token)
            .json(request)
            .send()
            .await
            .map_err(|e| CliError::DeployFailed {
                target: self.target,
                reason: format!("Stacker server unreachable: {}", e),
            })?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::DeployFailed {
                target: self.target,
                reason: stacker_api_failure_with_message(
                    &format!("Failed to configure cloud firewall for server {server_id}"),
                    &format!("POST /server/{server_id}/cloud-firewall"),
                    status,
                    &body,
                    cli_debug_enabled(),
                ),
            });
        }

        let api: ApiResponse<crate::forms::ConfigureCloudFirewallResponse> =
            resp.json().await.map_err(|e| CliError::DeployFailed {
                target: self.target,
                reason: format!("Invalid response from Stacker server: {}", e),
            })?;

        api.item.ok_or_else(|| CliError::DeployFailed {
            target: self.target,
            reason: "Cloud firewall operation returned no item".to_string(),
        })
    }

    /// Upload an existing SSH key pair to Vault for a server.
    pub async fn upload_ssh_key(
        &self,
        server_id: i32,
        public_key: &str,
        private_key: &str,
    ) -> Result<ServerInfo, CliError> {
        let url = format!("{}/server/{}/ssh-key/upload", self.base_url, server_id);
        let body = serde_json::json!({
            "public_key": public_key,
            "private_key": private_key,
        });

        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await
            .map_err(|e| CliError::DeployFailed {
                target: crate::cli::config_parser::DeployTarget::Cloud,
                reason: format!("Stacker server unreachable: {}", e),
            })?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::DeployFailed {
                target: crate::cli::config_parser::DeployTarget::Cloud,
                reason: stacker_api_failure_with_message(
                    &format!("SSH key upload failed for server {server_id}"),
                    &format!("POST /server/{server_id}/ssh-key/upload"),
                    status,
                    &body,
                    cli_debug_enabled(),
                ),
            });
        }

        let api: ApiResponse<ServerInfo> =
            resp.json().await.map_err(|e| CliError::DeployFailed {
                target: crate::cli::config_parser::DeployTarget::Cloud,
                reason: format!("Invalid response from Stacker server: {}", e),
            })?;

        api.item.ok_or_else(|| CliError::DeployFailed {
            target: crate::cli::config_parser::DeployTarget::Cloud,
            reason: "Server accepted key upload but returned no item".to_string(),
        })
    }

    // ── Marketplace ──────────────────────────────────

    /// List approved marketplace templates.
    pub async fn list_marketplace_templates(
        &self,
        category: Option<&str>,
        tag: Option<&str>,
    ) -> Result<Vec<MarketplaceTemplate>, CliError> {
        let mut url = format!("{}/marketplace", self.base_url);
        let mut params: Vec<String> = Vec::new();
        if let Some(c) = category {
            params.push(format!("category={}", c));
        }
        if let Some(t) = tag {
            params.push(format!("tag={}", t));
        }
        if !params.is_empty() {
            url = format!("{}?{}", url, params.join("&"));
        }

        let resp = self
            .http
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| CliError::DeployFailed {
                target: crate::cli::config_parser::DeployTarget::Cloud,
                reason: format!("Stacker server unreachable: {}", e),
            })?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::DeployFailed {
                target: crate::cli::config_parser::DeployTarget::Cloud,
                reason: stacker_api_failure_with_message(
                    "Marketplace listing failed",
                    "GET /marketplace",
                    status,
                    &body,
                    cli_debug_enabled(),
                ),
            });
        }

        let api: ApiResponse<MarketplaceTemplate> =
            resp.json().await.map_err(|e| CliError::DeployFailed {
                target: crate::cli::config_parser::DeployTarget::Cloud,
                reason: format!("Invalid response from Stacker server: {}", e),
            })?;

        Ok(api.list.unwrap_or_default())
    }

    /// Get a single marketplace template by slug.
    pub async fn get_marketplace_template(
        &self,
        slug: &str,
    ) -> Result<Option<MarketplaceTemplate>, CliError> {
        let url = format!("{}/marketplace/{}", self.base_url, slug);
        let resp = self
            .http
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| CliError::DeployFailed {
                target: crate::cli::config_parser::DeployTarget::Cloud,
                reason: format!("Stacker server unreachable: {}", e),
            })?;

        if resp.status().as_u16() == 404 {
            return Ok(None);
        }

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::DeployFailed {
                target: crate::cli::config_parser::DeployTarget::Cloud,
                reason: stacker_api_failure_with_message(
                    "Marketplace template fetch failed",
                    &format!("GET /marketplace/{slug}"),
                    status,
                    &body,
                    cli_debug_enabled(),
                ),
            });
        }

        let api: ApiResponse<MarketplaceTemplate> =
            resp.json().await.map_err(|e| CliError::DeployFailed {
                target: crate::cli::config_parser::DeployTarget::Cloud,
                reason: format!("Invalid response from Stacker server: {}", e),
            })?;

        Ok(api.item)
    }

    // ── Deploy ───────────────────────────────────────

    /// Deploy a project. If `cloud_id` is provided, uses saved cloud credentials.
    pub async fn deploy(
        &self,
        project_id: i32,
        cloud_id: Option<i32>,
        deploy_form: serde_json::Value,
    ) -> Result<DeployResponse, CliError> {
        let suffix = match cloud_id {
            Some(cid) => format!("/{}/deploy/{}", project_id, cid),
            None => format!("/{}/deploy", project_id),
        };
        let resp = self
            .send_project_request(
                reqwest::Method::POST,
                &suffix,
                Some(&deploy_form),
                "POST /project/{id}/deploy",
            )
            .await?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::DeployFailed {
                target: self.target.clone(),
                reason: stacker_api_failure_with_message(
                    "Stacker server deploy failed",
                    &format!("POST /project{suffix}"),
                    status,
                    &body,
                    cli_debug_enabled(),
                ),
            });
        }

        resp.json::<DeployResponse>()
            .await
            .map_err(|e| CliError::DeployFailed {
                target: self.target.clone(),
                reason: format!("Invalid deploy response from Stacker server: {}", e),
            })
    }

    /// Request rollback of a project to a known marketplace version.
    pub async fn rollback_project(
        &self,
        project_id: i32,
        version: &str,
    ) -> Result<DeployResponse, CliError> {
        let rollback_body = serde_json::json!({ "version": version });
        let resp = self
            .send_project_request(
                reqwest::Method::POST,
                &format!("/{}/rollback", project_id),
                Some(&rollback_body),
                "POST /project/{id}/rollback",
            )
            .await?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            if let Some(error) = parse_typed_error_response(&body) {
                return Err(error.into());
            }
            return Err(CliError::DeployFailed {
                target: self.target.clone(),
                reason: stacker_api_failure_with_message(
                    "Stacker server rollback failed",
                    &format!("POST /project/{project_id}/rollback"),
                    status,
                    &body,
                    cli_debug_enabled(),
                ),
            });
        }

        resp.json::<DeployResponse>()
            .await
            .map_err(|e| CliError::DeployFailed {
                target: self.target.clone(),
                reason: format!("Invalid rollback response from Stacker server: {}", e),
            })
    }

    // ── Deployment status ────────────────────────────

    /// Fetch deployment status by deployment ID.
    /// Returns `GET /api/v1/deployments/{id}`.
    pub async fn get_deployment_status(
        &self,
        deployment_id: i32,
    ) -> Result<Option<DeploymentStatusInfo>, CliError> {
        let url = format!("{}/api/v1/deployments/{}", self.base_url, deployment_id);
        let resp = self
            .http
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| CliError::DeployFailed {
                target: crate::cli::config_parser::DeployTarget::Cloud,
                reason: format!("Stacker server unreachable: {}", e),
            })?;

        if resp.status().as_u16() == 404 {
            return Ok(None);
        }

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::DeployFailed {
                target: self.target.clone(),
                reason: stacker_api_failure(
                    &format!("GET /api/v1/deployments/{deployment_id}"),
                    status,
                    &body,
                ),
            });
        }

        let api: ApiResponse<DeploymentStatusInfo> =
            resp.json().await.map_err(|e| CliError::DeployFailed {
                target: self.target.clone(),
                reason: format!("Invalid response from Stacker server: {}", e),
            })?;

        Ok(api.item)
    }

    /// Fetch canonical deployment state by deployment hash.
    /// Returns `GET /api/v1/deployments/{deployment_hash}/state`.
    pub async fn get_deployment_state_by_hash(
        &self,
        deployment_hash: &str,
    ) -> Result<Option<DeploymentState>, CliError> {
        let url = format!(
            "{}/api/v1/deployments/{}/state",
            self.base_url, deployment_hash
        );
        let resp = self
            .http
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| CliError::DeployFailed {
                target: self.target.clone(),
                reason: format!("Stacker server unreachable: {}", e),
            })?;

        if resp.status().as_u16() == 404 {
            return Ok(None);
        }

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::DeployFailed {
                target: self.target.clone(),
                reason: stacker_api_failure(
                    &format!("GET /api/v1/deployments/{deployment_hash}/state"),
                    status,
                    &body,
                ),
            });
        }

        let api: ApiResponse<DeploymentState> =
            resp.json().await.map_err(|e| CliError::DeployFailed {
                target: self.target.clone(),
                reason: format!("Invalid response from Stacker server: {}", e),
            })?;

        Ok(api.item)
    }

    /// Fetch structured deployment events by deployment hash.
    pub async fn get_deployment_events_by_hash(
        &self,
        deployment_hash: &str,
    ) -> Result<Option<DeploymentEventFeed>, CliError> {
        let url = format!(
            "{}/api/v1/deployments/{}/events",
            self.base_url, deployment_hash
        );
        let resp = self
            .http
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| CliError::DeployFailed {
                target: self.target.clone(),
                reason: format!("Stacker server unreachable: {}", e),
            })?;

        if resp.status().as_u16() == 404 {
            return Ok(None);
        }

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::DeployFailed {
                target: self.target.clone(),
                reason: stacker_api_failure(
                    &format!("GET /api/v1/deployments/{deployment_hash}/events"),
                    status,
                    &body,
                ),
            });
        }

        let api: ApiResponse<DeploymentEventFeed> =
            resp.json().await.map_err(|e| CliError::DeployFailed {
                target: self.target.clone(),
                reason: format!("Invalid response from Stacker server: {}", e),
            })?;

        Ok(api.item)
    }

    /// Fetch a read-only deployment plan by deployment hash.
    pub async fn get_deployment_plan_by_hash(
        &self,
        deployment_hash: &str,
        operation: DeployPlanOperation,
        target: &str,
        app_code: Option<&str>,
        rollback_target: Option<&str>,
        expected_fingerprint: Option<&str>,
    ) -> Result<Option<DeployPlan>, CliError> {
        let url = format!(
            "{}/api/v1/deployments/{}/plan",
            self.base_url, deployment_hash
        );
        let mut query = vec![
            (
                "operation".to_string(),
                serde_json::to_string(&operation)
                    .unwrap()
                    .trim_matches('"')
                    .to_string(),
            ),
            ("target".to_string(), target.to_string()),
        ];
        if let Some(app_code) = app_code.filter(|value| !value.trim().is_empty()) {
            query.push(("appCode".to_string(), app_code.to_string()));
        }
        if let Some(rollback_target) = rollback_target.filter(|value| !value.trim().is_empty()) {
            query.push(("rollbackTarget".to_string(), rollback_target.to_string()));
        }
        if let Some(fingerprint) = expected_fingerprint.filter(|value| !value.trim().is_empty()) {
            query.push(("expectedFingerprint".to_string(), fingerprint.to_string()));
        }

        let resp = self
            .http
            .get(&url)
            .query(&query)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| CliError::DeployFailed {
                target: self.target.clone(),
                reason: format!("Stacker server unreachable: {}", e),
            })?;

        if resp.status().as_u16() == 404 {
            return Ok(None);
        }

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            if let Some(error) = parse_typed_error_response(&body) {
                return Err(error.into());
            }
            return Err(CliError::DeployFailed {
                target: self.target.clone(),
                reason: stacker_api_failure(
                    &format!("GET /api/v1/deployments/{deployment_hash}/plan"),
                    status,
                    &body,
                ),
            });
        }

        let api: ApiResponse<DeployPlan> =
            resp.json().await.map_err(|e| CliError::DeployFailed {
                target: self.target.clone(),
                reason: format!("Invalid response from Stacker server: {}", e),
            })?;

        Ok(api.item)
    }

    /// Fetch the latest deployment status for a project.
    /// Returns `GET /api/v1/deployments/project/{project_id}`.
    pub async fn get_deployment_status_by_project(
        &self,
        project_id: i32,
    ) -> Result<Option<DeploymentStatusInfo>, CliError> {
        let url = format!(
            "{}/api/v1/deployments/project/{}",
            self.base_url, project_id
        );
        let resp = self
            .http
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| CliError::DeployFailed {
                target: self.target.clone(),
                reason: format!("Stacker server unreachable: {}", e),
            })?;

        if resp.status().as_u16() == 404 {
            return Ok(None);
        }

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::DeployFailed {
                target: self.target.clone(),
                reason: stacker_api_failure(
                    &format!("GET /api/v1/deployments/project/{project_id}"),
                    status,
                    &body,
                ),
            });
        }

        let api: ApiResponse<DeploymentStatusInfo> =
            resp.json().await.map_err(|e| CliError::DeployFailed {
                target: self.target.clone(),
                reason: format!("Invalid response from Stacker server: {}", e),
            })?;

        Ok(api.item)
    }

    /// Force-complete a stuck deployment (paused or error → completed).
    /// `POST /api/v1/deployments/{id}/force-complete`
    /// Fetch a deployment by its hash string.
    /// `GET /api/v1/deployments/hash/{hash}`
    pub async fn get_deployment_by_hash(
        &self,
        hash: &str,
    ) -> Result<Option<DeploymentStatusInfo>, CliError> {
        let url = format!("{}/api/v1/deployments/hash/{}", self.base_url, hash);
        let resp = self
            .http
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| CliError::DeployFailed {
                target: crate::cli::config_parser::DeployTarget::Cloud,
                reason: format!("Stacker server unreachable: {}", e),
            })?;

        if resp.status().as_u16() == 404 {
            return Ok(None);
        }

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::DeployFailed {
                target: crate::cli::config_parser::DeployTarget::Cloud,
                reason: stacker_api_failure(
                    &format!("GET /api/v1/deployments/hash/{hash}"),
                    status,
                    &body,
                ),
            });
        }

        let api: ApiResponse<DeploymentStatusInfo> =
            resp.json().await.map_err(|e| CliError::DeployFailed {
                target: crate::cli::config_parser::DeployTarget::Cloud,
                reason: format!("Invalid response from Stacker server: {}", e),
            })?;

        Ok(api.item)
    }

    pub async fn force_complete_deployment(
        &self,
        deployment_id: i32,
        force: bool,
    ) -> Result<DeploymentStatusInfo, CliError> {
        let url = if force {
            format!(
                "{}/api/v1/deployments/{}/force-complete?force=true",
                self.base_url, deployment_id
            )
        } else {
            format!(
                "{}/api/v1/deployments/{}/force-complete",
                self.base_url, deployment_id
            )
        };
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| CliError::DeployFailed {
                target: crate::cli::config_parser::DeployTarget::Cloud,
                reason: format!("Stacker server unreachable: {}", e),
            })?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::DeployFailed {
                target: crate::cli::config_parser::DeployTarget::Cloud,
                reason: stacker_api_failure_with_message(
                    "Force-complete failed",
                    &format!("POST /api/v1/deployments/{deployment_id}/force-complete"),
                    status,
                    &body,
                    cli_debug_enabled(),
                ),
            });
        }

        let api: ApiResponse<DeploymentStatusInfo> =
            resp.json().await.map_err(|e| CliError::DeployFailed {
                target: crate::cli::config_parser::DeployTarget::Cloud,
                reason: format!("Invalid response from Stacker server: {}", e),
            })?;

        api.item.ok_or_else(|| CliError::DeployFailed {
            target: crate::cli::config_parser::DeployTarget::Cloud,
            reason: "No deployment returned in force-complete response".to_string(),
        })
    }

    // ── Agent commands ───────────────────────────────

    /// Enqueue a command for the Status Panel agent on a deployment.
    ///
    /// `POST /api/v1/agent/commands/enqueue`
    pub async fn agent_enqueue(
        &self,
        request: &AgentEnqueueRequest,
    ) -> Result<AgentCommandInfo, CliError> {
        let url = format!("{}/api/v1/agent/commands/enqueue", self.base_url);
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.token)
            .json(request)
            .send()
            .await
            .map_err(|e| CliError::DeployFailed {
                target: crate::cli::config_parser::DeployTarget::Cloud,
                reason: format!("Stacker server unreachable: {}", e),
            })?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::AgentCommandFailed {
                command_id: String::new(),
                error: stacker_api_failure_with_message(
                    "Enqueue failed",
                    "POST /api/v1/agent/commands/enqueue",
                    status,
                    &body,
                    cli_debug_enabled(),
                ),
            });
        }

        let api: ApiResponse<AgentCommandInfo> =
            resp.json()
                .await
                .map_err(|e| CliError::AgentCommandFailed {
                    command_id: String::new(),
                    error: format!("Invalid enqueue response: {}", e),
                })?;

        api.item.ok_or_else(|| CliError::AgentCommandFailed {
            command_id: String::new(),
            error: "Empty enqueue response from server".to_string(),
        })
    }

    /// Get the status/result of a previously enqueued agent command.
    ///
    /// `GET /api/v1/commands/{deployment_hash}/{command_id}`
    pub async fn agent_command_status(
        &self,
        deployment_hash: &str,
        command_id: &str,
    ) -> Result<AgentCommandInfo, CliError> {
        let url = format!(
            "{}/api/v1/commands/{}/{}",
            self.base_url, deployment_hash, command_id
        );
        let resp = self
            .http
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| CliError::DeployFailed {
                target: crate::cli::config_parser::DeployTarget::Cloud,
                reason: format!("Stacker server unreachable: {}", e),
            })?;

        if resp.status().as_u16() == 404 {
            return Err(CliError::AgentCommandFailed {
                command_id: command_id.to_string(),
                error: "Command not found".to_string(),
            });
        }

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::AgentCommandFailed {
                command_id: command_id.to_string(),
                error: stacker_api_failure_with_message(
                    "Status check failed",
                    &format!("GET /api/v1/commands/{deployment_hash}/{command_id}"),
                    status,
                    &body,
                    cli_debug_enabled(),
                ),
            });
        }

        let api: ApiResponse<AgentCommandInfo> =
            resp.json()
                .await
                .map_err(|e| CliError::AgentCommandFailed {
                    command_id: command_id.to_string(),
                    error: format!("Invalid status response: {}", e),
                })?;

        api.item.ok_or_else(|| CliError::AgentCommandFailed {
            command_id: command_id.to_string(),
            error: "Empty status response".to_string(),
        })
    }

    /// Enqueue a command and poll until it completes or times out.
    ///
    /// This is the primary helper for CLI commands that need to wait for
    /// the agent to process a command and return a result.
    pub async fn agent_poll_result(
        &self,
        request: &AgentEnqueueRequest,
        timeout_secs: u64,
        poll_interval_secs: u64,
    ) -> Result<AgentCommandInfo, CliError> {
        let info = self.agent_enqueue(request).await?;
        let command_id = info.command_id.clone();
        let deployment_hash = request.deployment_hash.clone();

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
        let interval = std::time::Duration::from_secs(poll_interval_secs);

        let mut last_status = "pending".to_string();

        loop {
            tokio::time::sleep(interval).await;

            if tokio::time::Instant::now() >= deadline {
                return Err(CliError::AgentCommandTimeout {
                    command_id: command_id.clone(),
                    command_type: request.command_type.clone(),
                    last_status,
                    deployment_hash,
                });
            }

            let status = self
                .agent_command_status(&deployment_hash, &command_id)
                .await?;

            last_status = status.status.clone();
            match status.status.as_str() {
                "completed" | "failed" => return Ok(status),
                _ => continue,
            }
        }
    }

    /// Fetch a full deployment snapshot (agent info, commands, containers).
    ///
    /// `GET /api/v1/agent/deployments/{deployment_hash}`
    pub async fn agent_snapshot(
        &self,
        deployment_hash: &str,
    ) -> Result<serde_json::Value, CliError> {
        let url = format!(
            "{}/api/v1/agent/deployments/{}",
            self.base_url, deployment_hash
        );
        let resp = self
            .http
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| CliError::DeployFailed {
                target: crate::cli::config_parser::DeployTarget::Cloud,
                reason: format!("Stacker server unreachable: {}", e),
            })?;

        if resp.status().as_u16() == 404 {
            return Err(CliError::AgentNotFound {
                deployment_hash: deployment_hash.to_string(),
            });
        }

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::AgentCommandFailed {
                command_id: String::new(),
                error: stacker_api_failure_with_message(
                    "Snapshot failed",
                    &format!("GET /api/v1/agent/deployments/{deployment_hash}"),
                    status,
                    &body,
                    cli_debug_enabled(),
                ),
            });
        }

        resp.json::<serde_json::Value>()
            .await
            .map_err(|e| CliError::AgentCommandFailed {
                command_id: String::new(),
                error: format!("Invalid snapshot response: {}", e),
            })
    }

    /// Fetch the snapshot for the most recently active agent in a project.
    /// Returns `(snapshot_json, deployment_hash)` so the caller can use the hash
    /// for subsequent agent commands.
    pub async fn agent_snapshot_by_project(
        &self,
        project_id: i32,
    ) -> Result<(serde_json::Value, String), CliError> {
        let url = format!("{}/api/v1/agent/project/{}", self.base_url, project_id);
        let resp = self
            .http
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| CliError::DeployFailed {
                target: crate::cli::config_parser::DeployTarget::Cloud,
                reason: format!("Stacker server unreachable: {}", e),
            })?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::DeployFailed {
                target: crate::cli::config_parser::DeployTarget::Cloud,
                reason: stacker_api_failure(
                    &format!("GET /api/v1/agent/project/{project_id}"),
                    status,
                    &body,
                ),
            });
        }

        let json: serde_json::Value =
            resp.json()
                .await
                .map_err(|e| CliError::AgentCommandFailed {
                    command_id: String::new(),
                    error: format!("Invalid project snapshot response: {}", e),
                })?;

        // Extract deployment_hash from the nested agent object
        let hash = json
            .get("item")
            .unwrap_or(&json)
            .get("agent")
            .and_then(|a| a.get("deployment_hash"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| {
                CliError::ConfigValidation(
                    "No active agent found for this project. \
                 The agent may be offline or not yet deployed."
                        .to_string(),
                )
            })?;

        Ok((json, hash))
    }

    /// Fetch deployment agent capabilities.
    ///
    /// `GET /api/v1/deployments/{deployment_hash}/capabilities`
    pub async fn deployment_capabilities(
        &self,
        deployment_hash: &str,
    ) -> Result<DeploymentCapabilitiesInfo, CliError> {
        let url = format!(
            "{}/api/v1/deployments/{}/capabilities",
            self.base_url, deployment_hash
        );
        let resp = self
            .http
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| {
                CliError::ConfigValidation(format!(
                    "Failed to fetch deployment capabilities: {}",
                    e
                ))
            })?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::ConfigValidation(
                stacker_api_failure_with_message(
                    "Capabilities lookup failed",
                    &format!("GET /api/v1/deployments/{deployment_hash}/capabilities"),
                    status,
                    &body,
                    cli_debug_enabled(),
                ),
            ));
        }

        let api: ApiResponse<DeploymentCapabilitiesInfo> = resp.json().await.map_err(|e| {
            CliError::ConfigValidation(format!("Invalid deployment capabilities response: {}", e))
        })?;

        api.item.ok_or_else(|| {
            CliError::ConfigValidation("Empty deployment capabilities response".to_string())
        })
    }

    // ── Pipe management ─────────────────────────────

    /// List pipe instances for a deployment.
    ///
    /// `GET /api/v1/pipes/instances/{deployment_hash}`
    pub async fn list_pipe_instances(
        &self,
        deployment_hash: &str,
    ) -> Result<Vec<PipeInstanceInfo>, CliError> {
        let url = format!(
            "{}/api/v1/pipes/instances/{}",
            self.base_url, deployment_hash
        );
        let resp = self
            .http
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| CliError::ConfigValidation(format!("Failed to list pipes: {}", e)))?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::ConfigValidation(
                stacker_api_failure_with_message(
                    "List pipes failed",
                    &format!("GET /api/v1/pipes/instances/{deployment_hash}"),
                    status,
                    &body,
                    cli_debug_enabled(),
                ),
            ));
        }

        let api: ApiResponse<PipeInstanceInfo> = resp.json().await.map_err(|e| {
            CliError::ConfigValidation(format!("Invalid pipe list response: {}", e))
        })?;

        Ok(api.list.unwrap_or_default())
    }

    /// List local pipe instances for the current user.
    ///
    /// `GET /api/v1/pipes/instances/local`
    pub async fn list_local_pipe_instances(&self) -> Result<Vec<PipeInstanceInfo>, CliError> {
        let url = format!("{}/api/v1/pipes/instances/local", self.base_url);
        let resp = self
            .http
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| {
                CliError::ConfigValidation(format!("Failed to list local pipes: {}", e))
            })?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::ConfigValidation(
                stacker_api_failure_with_message(
                    "List local pipes failed",
                    "GET /api/v1/pipes/instances/local",
                    status,
                    &body,
                    cli_debug_enabled(),
                ),
            ));
        }

        let api: ApiResponse<PipeInstanceInfo> = resp.json().await.map_err(|e| {
            CliError::ConfigValidation(format!("Invalid local pipe list response: {}", e))
        })?;

        Ok(api.list.unwrap_or_default())
    }

    /// Get a pipe instance by ID.
    ///
    /// `GET /api/v1/pipes/instances/detail/{instance_id}`
    pub async fn get_pipe_instance(
        &self,
        instance_id: &str,
    ) -> Result<Option<PipeInstanceInfo>, CliError> {
        let url = format!(
            "{}/api/v1/pipes/instances/detail/{}",
            self.base_url, instance_id
        );
        let resp = self
            .http
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| CliError::ConfigValidation(format!("Failed to get pipe: {}", e)))?;

        if resp.status().as_u16() == 404 {
            return Ok(None);
        }
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::ConfigValidation(
                stacker_api_failure_with_message(
                    "Get pipe failed",
                    &format!("GET /api/v1/pipes/instances/detail/{instance_id}"),
                    status,
                    &body,
                    cli_debug_enabled(),
                ),
            ));
        }

        let api: ApiResponse<PipeInstanceInfo> = resp
            .json()
            .await
            .map_err(|e| CliError::ConfigValidation(format!("Invalid pipe response: {}", e)))?;

        Ok(api.item)
    }

    /// Create a pipe template.
    ///
    /// `POST /api/v1/pipes/templates`
    pub async fn create_pipe_template(
        &self,
        request: &CreatePipeTemplateApiRequest,
    ) -> Result<PipeTemplateInfo, CliError> {
        let url = format!("{}/api/v1/pipes/templates", self.base_url);
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.token)
            .json(request)
            .send()
            .await
            .map_err(|e| {
                CliError::ConfigValidation(format!("Failed to create pipe template: {}", e))
            })?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::ConfigValidation(
                stacker_api_failure_with_message(
                    "Create pipe template failed",
                    "POST /api/v1/pipes/templates",
                    status,
                    &body,
                    cli_debug_enabled(),
                ),
            ));
        }

        let api: ApiResponse<PipeTemplateInfo> = resp
            .json()
            .await
            .map_err(|e| CliError::ConfigValidation(format!("Invalid template response: {}", e)))?;

        api.item
            .ok_or_else(|| CliError::ConfigValidation("Empty template response".to_string()))
    }

    /// Create a pipe instance.
    ///
    /// `POST /api/v1/pipes/instances`
    pub async fn create_pipe_instance(
        &self,
        request: &CreatePipeInstanceApiRequest,
    ) -> Result<PipeInstanceInfo, CliError> {
        let url = format!("{}/api/v1/pipes/instances", self.base_url);
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.token)
            .json(request)
            .send()
            .await
            .map_err(|e| {
                CliError::ConfigValidation(format!("Failed to create pipe instance: {}", e))
            })?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::ConfigValidation(
                stacker_api_failure_with_message(
                    "Create pipe instance failed",
                    "POST /api/v1/pipes/instances",
                    status,
                    &body,
                    cli_debug_enabled(),
                ),
            ));
        }

        let api: ApiResponse<PipeInstanceInfo> = resp
            .json()
            .await
            .map_err(|e| CliError::ConfigValidation(format!("Invalid instance response: {}", e)))?;

        api.item
            .ok_or_else(|| CliError::ConfigValidation("Empty instance response".to_string()))
    }

    /// Update pipe instance status.
    ///
    /// `PUT /api/v1/pipes/instances/{instance_id}/status`
    pub async fn update_pipe_status(
        &self,
        instance_id: &str,
        status: &str,
    ) -> Result<PipeInstanceInfo, CliError> {
        let url = format!(
            "{}/api/v1/pipes/instances/{}/status",
            self.base_url, instance_id
        );
        let body = serde_json::json!({ "status": status });
        let resp = self
            .http
            .put(&url)
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                CliError::ConfigValidation(format!("Failed to update pipe status: {}", e))
            })?;

        if !resp.status().is_success() {
            let status_code = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::ConfigValidation(
                stacker_api_failure_with_message(
                    "Update pipe status failed",
                    &format!("PUT /api/v1/pipes/instances/{instance_id}/status"),
                    status_code,
                    &body,
                    cli_debug_enabled(),
                ),
            ));
        }

        let api: ApiResponse<PipeInstanceInfo> = resp
            .json()
            .await
            .map_err(|e| CliError::ConfigValidation(format!("Invalid status response: {}", e)))?;

        api.item
            .ok_or_else(|| CliError::ConfigValidation("Empty status response".to_string()))
    }

    /// List pipe templates visible to the current user.
    ///
    /// `GET /api/v1/pipes/templates`
    pub async fn list_pipe_templates(
        &self,
        source_app_type: Option<&str>,
        target_app_type: Option<&str>,
    ) -> Result<Vec<PipeTemplateInfo>, CliError> {
        let mut url = format!("{}/api/v1/pipes/templates", self.base_url);
        let mut params = Vec::new();
        if let Some(source) = source_app_type {
            params.push(format!("source_app_type={}", source));
        }
        if let Some(target) = target_app_type {
            params.push(format!("target_app_type={}", target));
        }
        if !params.is_empty() {
            url.push('?');
            url.push_str(&params.join("&"));
        }

        let resp = self
            .http
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| CliError::ConfigValidation(format!("Failed to list templates: {}", e)))?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::ConfigValidation(
                stacker_api_failure_with_message(
                    "List templates failed",
                    "GET /api/v1/pipes/templates",
                    status,
                    &body,
                    cli_debug_enabled(),
                ),
            ));
        }

        let api: ApiResponse<PipeTemplateInfo> = resp.json().await.map_err(|e| {
            CliError::ConfigValidation(format!("Invalid templates response: {}", e))
        })?;

        Ok(api.list.unwrap_or_default())
    }

    // ── Pipe Executions ──────────────────────────────

    /// List executions for a pipe instance (paginated).
    ///
    /// `GET /api/v1/pipes/instances/{instance_id}/executions?limit=N&offset=M`
    pub async fn list_pipe_executions(
        &self,
        instance_id: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<PipeExecutionInfo>, CliError> {
        let url = format!(
            "{}/api/v1/pipes/instances/{}/executions?limit={}&offset={}",
            self.base_url, instance_id, limit, offset
        );
        let resp = self
            .http
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| CliError::ConfigValidation(format!("Failed to list executions: {}", e)))?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::ConfigValidation(
                stacker_api_failure_with_message(
                    "List executions failed",
                    &format!("GET /api/v1/pipes/instances/{instance_id}/executions"),
                    status,
                    &body,
                    cli_debug_enabled(),
                ),
            ));
        }

        let api: ApiResponse<PipeExecutionInfo> = resp.json().await.map_err(|e| {
            CliError::ConfigValidation(format!("Invalid executions response: {}", e))
        })?;

        Ok(api.list.unwrap_or_default())
    }

    /// Get a single pipe execution by ID.
    ///
    /// `GET /api/v1/pipes/executions/{execution_id}`
    pub async fn get_pipe_execution(
        &self,
        execution_id: &str,
    ) -> Result<Option<PipeExecutionInfo>, CliError> {
        let url = format!("{}/api/v1/pipes/executions/{}", self.base_url, execution_id);
        let resp = self
            .http
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| CliError::ConfigValidation(format!("Failed to get execution: {}", e)))?;

        if resp.status().as_u16() == 404 {
            return Ok(None);
        }

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::ConfigValidation(
                stacker_api_failure_with_message(
                    "Get execution failed",
                    &format!("GET /api/v1/pipes/executions/{execution_id}"),
                    status,
                    &body,
                    cli_debug_enabled(),
                ),
            ));
        }

        let api: ApiResponse<PipeExecutionInfo> = resp.json().await.map_err(|e| {
            CliError::ConfigValidation(format!("Invalid execution response: {}", e))
        })?;

        Ok(api.item)
    }

    /// Replay a previous pipe execution.
    ///
    /// `POST /api/v1/pipes/executions/{execution_id}/replay`
    pub async fn replay_pipe_execution(
        &self,
        execution_id: &str,
    ) -> Result<PipeReplayResponse, CliError> {
        let url = format!(
            "{}/api/v1/pipes/executions/{}/replay",
            self.base_url, execution_id
        );
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| {
                CliError::ConfigValidation(format!("Failed to replay execution: {}", e))
            })?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::ConfigValidation(
                stacker_api_failure_with_message(
                    "Replay failed",
                    &format!("POST /api/v1/pipes/executions/{execution_id}/replay"),
                    status,
                    &body,
                    cli_debug_enabled(),
                ),
            ));
        }

        let api: ApiResponse<PipeReplayResponse> = resp
            .json()
            .await
            .map_err(|e| CliError::ConfigValidation(format!("Invalid replay response: {}", e)))?;

        api.item
            .ok_or_else(|| CliError::ConfigValidation("No replay response returned".to_string()))
    }

    /// Deploy (promote) a local pipe instance to a remote deployment.
    ///
    /// `POST /api/v1/pipes/instances/{instance_id}/deploy`
    pub async fn deploy_pipe(
        &self,
        instance_id: &str,
        deployment_hash: &str,
    ) -> Result<PipeInstanceInfo, CliError> {
        let url = format!(
            "{}/api/v1/pipes/instances/{}/deploy",
            self.base_url, instance_id
        );
        let body = DeployPipeApiRequest {
            deployment_hash: deployment_hash.to_string(),
        };
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await
            .map_err(|e| CliError::ConfigValidation(format!("Failed to deploy pipe: {}", e)))?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::ConfigValidation(
                stacker_api_failure_with_message(
                    "Deploy failed",
                    &format!("POST /api/v1/pipes/instances/{instance_id}/deploy"),
                    status,
                    &body,
                    cli_debug_enabled(),
                ),
            ));
        }

        let api: ApiResponse<PipeInstanceInfo> = resp
            .json()
            .await
            .map_err(|e| CliError::ConfigValidation(format!("Invalid deploy response: {}", e)))?;

        api.item
            .ok_or_else(|| CliError::ConfigValidation("No deploy response returned".to_string()))
    }

    // ── Marketplace (creator) ────────────────────────

    /// List the current user's marketplace template submissions.
    pub async fn marketplace_list_mine(&self) -> Result<Vec<MarketplaceTemplateInfo>, CliError> {
        let url = format!("{}/api/templates/mine", self.base_url);
        let resp = self
            .http
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| {
                CliError::MarketplaceFailed(format!("Stacker server unreachable: {}", e))
            })?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::MarketplaceFailed(
                stacker_api_failure_with_message(
                    "Marketplace submissions fetch failed",
                    "GET /api/templates/mine",
                    status,
                    &body,
                    cli_debug_enabled(),
                ),
            ));
        }

        let api: ApiResponse<MarketplaceTemplateInfo> = resp.json().await.map_err(|e| {
            CliError::MarketplaceFailed(format!("Invalid response from Stacker server: {}", e))
        })?;

        Ok(api.list.unwrap_or_default())
    }

    /// Get review history for a template by ID.
    pub async fn marketplace_reviews(
        &self,
        template_id: &str,
    ) -> Result<Vec<MarketplaceReviewInfo>, CliError> {
        let url = format!("{}/api/templates/{}/reviews", self.base_url, template_id);
        let resp = self
            .http
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| {
                CliError::MarketplaceFailed(format!("Stacker server unreachable: {}", e))
            })?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::MarketplaceFailed(
                stacker_api_failure_with_message(
                    "Marketplace reviews fetch failed",
                    &format!("GET /api/templates/{template_id}/reviews"),
                    status,
                    &body,
                    cli_debug_enabled(),
                ),
            ));
        }

        let api: ApiResponse<MarketplaceReviewInfo> = resp.json().await.map_err(|e| {
            CliError::MarketplaceFailed(format!("Invalid response from Stacker server: {}", e))
        })?;

        Ok(api.list.unwrap_or_default())
    }

    /// Create or update a marketplace template (POST /api/templates).
    pub async fn marketplace_create_or_update(
        &self,
        body: serde_json::Value,
    ) -> Result<MarketplaceTemplateInfo, CliError> {
        let url = format!("{}/api/templates", self.base_url);
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await
            .map_err(|e| CliError::MarketplaceFailed(format!("create template: {}", e)))?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::MarketplaceFailed(
                stacker_api_failure_with_message(
                    "Create template failed",
                    "POST /api/templates",
                    status,
                    &body,
                    cli_debug_enabled(),
                ),
            ));
        }

        let api: ApiResponse<MarketplaceTemplateInfo> = resp
            .json()
            .await
            .map_err(|e| CliError::MarketplaceFailed(format!("create template response: {}", e)))?;

        api.item
            .ok_or_else(|| CliError::MarketplaceFailed("No template in response".to_string()))
    }

    /// Submit a template for marketplace review.
    pub async fn marketplace_submit(&self, template_id: &str) -> Result<(), CliError> {
        let url = format!("{}/api/templates/{}/submit", self.base_url, template_id);
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| {
                CliError::MarketplaceFailed(format!("Stacker server unreachable: {}", e))
            })?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(CliError::MarketplaceFailed(
                stacker_api_failure_with_message(
                    "Submit failed",
                    &format!("POST /api/templates/{template_id}/submit"),
                    status,
                    &body,
                    cli_debug_enabled(),
                ),
            ));
        }

        Ok(())
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Agent request/response types
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Request body for `POST /api/v1/agent/commands/enqueue`.
///
/// Mirrors the server's `EnqueueRequest` — kept in sync so CLI payloads
/// are validated identically to direct API calls.
#[derive(Debug, Clone, Serialize)]
pub struct AgentEnqueueRequest {
    pub deployment_hash: String,
    pub command_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_seconds: Option<i32>,
}

impl AgentEnqueueRequest {
    /// Create a request with only the required fields.
    pub fn new(deployment_hash: impl Into<String>, command_type: impl Into<String>) -> Self {
        Self {
            deployment_hash: deployment_hash.into(),
            command_type: command_type.into(),
            priority: None,
            parameters: None,
            timeout_seconds: None,
        }
    }

    /// Builder: set typed parameters (serialized to JSON).
    pub fn with_parameters<T: Serialize>(mut self, params: &T) -> Result<Self, serde_json::Error> {
        self.parameters = Some(serde_json::to_value(params)?);
        Ok(self)
    }

    /// Builder: set raw JSON parameters.
    pub fn with_raw_parameters(mut self, params: serde_json::Value) -> Self {
        self.parameters = Some(params);
        self
    }

    /// Builder: set priority (low / normal / high / critical).
    pub fn with_priority(mut self, priority: impl Into<String>) -> Self {
        self.priority = Some(priority.into());
        self
    }

    /// Builder: set timeout in seconds.
    pub fn with_timeout(mut self, seconds: i32) -> Self {
        self.timeout_seconds = Some(seconds);
        self
    }
}

/// Agent command info as returned by the commands API.
///
/// Contains both status and (optionally) the result payload set by
/// the Status Panel agent after execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCommandInfo {
    pub command_id: String,
    pub deployment_hash: String,
    #[serde(rename = "type", default)]
    pub command_type: String,
    pub status: String,
    #[serde(default)]
    pub priority: String,
    #[serde(default)]
    pub parameters: Option<serde_json::Value>,
    #[serde(default)]
    pub result: Option<serde_json::Value>,
    #[serde(default)]
    pub error: Option<serde_json::Value>,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DeploymentCapabilityFeatures {
    #[serde(default)]
    pub kata_runtime: bool,
    #[serde(default)]
    pub compose: bool,
    #[serde(default)]
    pub backup: bool,
    #[serde(default)]
    pub pipes: bool,
    #[serde(default)]
    pub proxy_credentials_vault: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DeploymentCapabilitiesInfo {
    #[serde(default)]
    pub deployment_hash: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub features: DeploymentCapabilityFeatures,
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Helper: build deploy form from stacker.yml config
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

use crate::cli::config_parser::{ServiceDefinition, StackerConfig};

/// Generate a short unique ID for app entries (similar to Stacker UI IDs).
fn generate_app_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    format!("cli_{:x}", ts)
}

/// Parse a Docker image string like `user/repo:tag`, `repo:tag`, or `repo`
/// into (dockerhub_user, dockerhub_name, dockerhub_tag) tuple.
///
/// The tag is separated from the name so the server / Python side doesn't
/// accidentally append `:latest` again.
fn parse_docker_image(image: &str) -> (Option<String>, String, Option<String>) {
    // Split off tag first ("repo:tag" → "repo", Some("tag"))
    let (image_no_tag, tag) = if let Some(pos) = image.rfind(':') {
        // Avoid splitting on registry port like "registry.io:5000/repo"
        let after_colon = &image[pos + 1..];
        if after_colon.contains('/') {
            // The colon is part of a registry address, not a tag
            (image, None)
        } else {
            (&image[..pos], Some(after_colon.to_string()))
        }
    } else {
        (image, None)
    };

    // Now split user/name
    if let Some((user_part, repo_part)) = image_no_tag.split_once('/') {
        if user_part.contains('.') {
            // Registry address (e.g. "ghcr.io/owner/repo") — keep as-is
            (None, image_no_tag.to_string(), tag)
        } else {
            (Some(user_part.to_string()), repo_part.to_string(), tag)
        }
    } else {
        (None, image_no_tag.to_string(), tag)
    }
}

/// Parse a port mapping string like "8080:80", "127.0.0.1:8080:80", or "3000"
/// into (host_port, container_port) tuple.
fn parse_port_mapping(port_str: &str) -> (String, String) {
    // Remove protocol suffix like "/tcp", "/udp"
    let port_no_proto = port_str.split('/').next().unwrap_or(port_str);
    if let Some((host_part, container)) = port_no_proto.rsplit_once(':') {
        let host_port = host_part.rsplit(':').next().unwrap_or(host_part);
        (host_port.to_string(), container.to_string())
    } else {
        (port_no_proto.to_string(), port_no_proto.to_string())
    }
}

/// Parse a volume mapping string like "./dist:/usr/share/nginx/html" or "data:/var/lib/db"
/// into (host_path, container_path, read_only) tuple.
/// Handles optional `:ro` / `:rw` suffix (e.g. "/var/run/docker.sock:/var/run/docker.sock:ro").
fn parse_volume_mapping(vol_str: &str) -> (String, String, bool) {
    let parts: Vec<&str> = vol_str.split(':').collect();
    match parts.len() {
        // "source:target:mode" (e.g. "/host:/container:ro")
        3 => (parts[0].to_string(), parts[1].to_string(), parts[2] == "ro"),
        // "source:target"
        2 => (parts[0].to_string(), parts[1].to_string(), false),
        // bare path
        _ => (vol_str.to_string(), vol_str.to_string(), false),
    }
}

/// Convert a `ServiceDefinition` from stacker.yml into the Stacker server's
/// app JSON format (matching `forms::project::App` / `forms::project::Web`).
fn service_to_app_json(svc: &ServiceDefinition, network_ids: &[String]) -> serde_json::Value {
    let (dockerhub_user, dockerhub_name, dockerhub_tag) = parse_docker_image(&svc.image);
    let id = generate_app_id();

    let shared_ports: Vec<serde_json::Value> = svc
        .ports
        .iter()
        .map(|p| {
            let (host, container) = parse_port_mapping(p);
            serde_json::json!({
                "host_port": host,
                "container_port": container,
            })
        })
        .collect();

    let volumes: Vec<serde_json::Value> = svc
        .volumes
        .iter()
        .map(|v| {
            let (host, container, read_only) = parse_volume_mapping(v);
            serde_json::json!({
                "host_path": host,
                "container_path": container,
                "read_only": read_only,
            })
        })
        .collect();

    let environment: Vec<serde_json::Value> = svc
        .environment
        .iter()
        .map(|(k, v)| {
            serde_json::json!({
                "key": k,
                "value": v,
            })
        })
        .collect();

    let mut app = serde_json::json!({
        "_id": id,
        "name": svc.name.clone(),
        "code": svc.name.to_lowercase(),
        "type": "web",
        "dockerhub_name": dockerhub_name,
        "restart": "always",
        "custom": true,
        "shared_ports": shared_ports,
        "volumes": volumes,
        "environment": environment,
        "network": network_ids,
    });

    let obj = app.as_object_mut().unwrap();
    if let Some(user) = dockerhub_user {
        obj.insert("dockerhub_user".to_string(), serde_json::json!(user));
    }
    if let Some(tag) = dockerhub_tag {
        obj.insert("dockerhub_tag".to_string(), serde_json::json!(tag));
    }

    app
}

fn is_platform_managed_service(svc: &ServiceDefinition) -> bool {
    crate::project_app::is_platform_managed_app_identity(&svc.name, Some(&svc.image))
}

/// Convert the `app` section of stacker.yml into the Stacker server's app JSON
/// format. Returns `None` if the app has no image (build-only local apps).
fn app_source_to_app_json(
    config: &StackerConfig,
    network_ids: &[String],
) -> Option<serde_json::Value> {
    let image = config.app.image.as_deref()?;
    let (dockerhub_user, dockerhub_name, dockerhub_tag) = parse_docker_image(image);
    let id = generate_app_id();

    let app_name = config
        .project
        .identity
        .clone()
        .unwrap_or_else(|| config.name.clone());

    // Ports: use explicit ports if provided, otherwise default from app type
    let shared_ports: Vec<serde_json::Value> = if config.app.ports.is_empty() {
        let default_port = default_port_for_app_type(config.app.app_type);
        vec![serde_json::json!({
            "host_port": default_port.to_string(),
            "container_port": default_port.to_string(),
        })]
    } else {
        config
            .app
            .ports
            .iter()
            .map(|p| {
                let (host, container) = parse_port_mapping(p);
                serde_json::json!({
                    "host_port": host,
                    "container_port": container,
                })
            })
            .collect()
    };

    // Volumes
    let volumes: Vec<serde_json::Value> = config
        .app
        .volumes
        .iter()
        .map(|v| {
            let (host, container, read_only) = parse_volume_mapping(v);
            serde_json::json!({
                "host_path": host,
                "container_path": container,
                "read_only": read_only,
            })
        })
        .collect();

    // Environment: merge top-level env + app-level (app wins)
    let mut merged_env: std::collections::HashMap<String, String> = config.env.clone();
    for (k, v) in &config.app.environment {
        merged_env.insert(k.clone(), v.clone());
    }
    let environment: Vec<serde_json::Value> = merged_env
        .iter()
        .map(|(k, v)| serde_json::json!({ "key": k, "value": v }))
        .collect();

    let mut app = serde_json::json!({
        "_id": id,
        "name": app_name,
        "code": app_name.to_lowercase(),
        "type": "web",
        "dockerhub_name": dockerhub_name,
        "restart": "always",
        "custom": true,
        "shared_ports": shared_ports,
        "volumes": volumes,
        "environment": environment,
        "network": network_ids,
    });

    let obj = app.as_object_mut().unwrap();
    if let Some(user) = dockerhub_user {
        obj.insert("dockerhub_user".to_string(), serde_json::json!(user));
    }
    if let Some(tag) = dockerhub_tag {
        obj.insert("dockerhub_tag".to_string(), serde_json::json!(tag));
    }

    Some(app)
}

/// Map CLI AppType to default port (same as compose generator).
fn default_port_for_app_type(app_type: crate::cli::config_parser::AppType) -> u16 {
    use crate::cli::config_parser::AppType;
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

/// Build the project creation body (matching `forms::project::ProjectForm`)
/// from the CLI's `StackerConfig`, including services from stacker.yml.
pub fn build_project_body(config: &StackerConfig) -> serde_json::Value {
    let stack_code = config
        .project
        .identity
        .clone()
        .unwrap_or_else(|| config.name.clone());

    // Create a default network
    let network_id = format!("cli_net_{:x}", {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    });

    let network_ids = vec![network_id.clone()];

    // Convert the main app + services from stacker.yml to Stacker server
    // app format.  The main `app` section is the primary web application;
    // additional `services` are supporting containers.
    let mut web_apps: Vec<serde_json::Value> = Vec::new();
    let mut service_apps: Vec<serde_json::Value> = Vec::new();

    // Include the main app (if it has an image)
    if let Some(main_app) = app_source_to_app_json(config, &network_ids) {
        web_apps.push(main_app);
    }

    // Include additional services as service targets. Platform-managed apps
    // are installed by their own roles and directories, not by the project
    // compose, to avoid duplicate containers and host-port conflicts.
    for svc in &config.services {
        if is_platform_managed_service(svc) {
            continue;
        }
        service_apps.push(service_to_app_json(svc, &network_ids));
    }

    serde_json::json!({
        "custom": {
            "custom_stack_code": stack_code,
            "project_name": config.name.clone(),
            "web": web_apps,
            "feature": [],
            "service": service_apps,
            "networks": [{
                "id": network_id,
                "name": "default_network",
                "driver": "bridge",
            }],
        }
    })
}

pub fn attach_config_bundle_to_project_body(
    project_body: &mut serde_json::Value,
    artifacts: &crate::cli::config_bundle::ConfigBundleArtifacts,
) {
    if let Some(custom) = project_body
        .get_mut("custom")
        .and_then(|custom| custom.as_object_mut())
    {
        custom.insert(
            "deployment_artifacts".to_string(),
            serde_json::json!({
                "config_bundle": artifacts.artifact_metadata(),
            }),
        );
    }
}

pub fn attach_config_bundle_to_deploy_form(
    deploy_form: &mut serde_json::Value,
    artifacts: &crate::cli::config_bundle::ConfigBundleArtifacts,
) {
    if let Some(obj) = deploy_form.as_object_mut() {
        obj.insert(
            "environment".to_string(),
            serde_json::Value::String(artifacts.environment.clone()),
        );
        obj.insert(
            "config_files".to_string(),
            serde_json::Value::Array(artifacts.config_files.clone()),
        );
        obj.insert(
            "config_bundle".to_string(),
            serde_json::json!({
                "manifest": artifacts.artifact_metadata(),
            }),
        );
    }
}

/// Build the deploy form payload that matches the Stacker server's
/// `forms::project::Deploy` structure.
/// Generate a deterministic but unique server name from the project name.
///
/// Format: `{project}-{4hex}` where the hex suffix is derived from the current
/// timestamp so each deploy gets a distinct name, e.g. `website-a3f1`.
///
/// The name is sanitised to satisfy the strictest provider rules (Hetzner):
///   - only lowercase `a-z`, `0-9`, `-`
///   - must start with a letter
///   - must not end with `-`
///   - max 63 characters total
pub fn generate_server_name(project_name: &str) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    // Sanitise project name: lowercase, replace non-alnum with hyphen, collapse runs
    let sanitised: String = project_name
        .to_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect::<String>()
        .split('-')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-");

    // Ensure it starts with a letter (Hetzner requirement)
    let base = if sanitised.is_empty() {
        "srv".to_string()
    } else if !sanitised.starts_with(|c: char| c.is_ascii_lowercase()) {
        format!("srv-{}", sanitised)
    } else {
        sanitised
    };

    // 4-char hex suffix from current timestamp (unique per ~65k deploys within any second)
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let suffix = format!("{:04x}", (ts & 0xFFFF) as u16);

    // Truncate base so total stays within 63 chars: base + '-' + 4-char suffix = base ≤ 58
    let max_base = 63 - 1 - suffix.len(); // 58
    let truncated = if base.len() > max_base {
        base[..max_base].trim_end_matches('-').to_string()
    } else {
        base
    };

    format!("{}-{}", truncated, suffix)
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DeployFormOptions {
    pub include_managed_proxy: bool,
}

pub fn build_deploy_form_with_options(
    config: &StackerConfig,
    options: DeployFormOptions,
) -> serde_json::Value {
    let mut form = build_deploy_form(config);
    if !options.include_managed_proxy {
        remove_extended_feature(&mut form, "nginx_proxy_manager");
    }
    form
}

pub fn build_deploy_form(config: &StackerConfig) -> serde_json::Value {
    let cloud = config.deploy.cloud.as_ref();
    let provider = cloud
        .map(|c| {
            super::install_runner::provider_code_for_remote(&c.provider.to_string()).to_string()
        })
        .unwrap_or_else(|| "htz".to_string());
    let region = cloud
        .and_then(|c| c.region.clone())
        .unwrap_or_else(|| "nbg1".to_string());
    let server_size = cloud
        .and_then(|c| c.size.clone())
        .unwrap_or_else(|| "cpx11".to_string());
    let os = match provider.as_str() {
        "do" => "docker-20-04", // DigitalOcean marketplace image with Docker pre-installed
        "htz" => "docker-ce",   // Hetzner snapshot with Docker CE pre-installed (Ubuntu 24.04)
        "cnt" => "ubuntu-22.04", // Contabo: standard Ubuntu image
        _ => "ubuntu-22.04",
    };

    // Auto-generate a server name from the project name so every
    // provisioned server gets a recognisable label in `stacker list servers`.
    let project_name = config
        .project
        .identity
        .clone()
        .unwrap_or_else(|| config.name.clone());
    let server_name = generate_server_name(&project_name);

    let mut form = serde_json::json!({
        "cloud": {
            "provider": provider,
            "save_token": true,
        },
        "server": {
            "region": region,
            "server": server_size,
            "os": os,
            "name": server_name,
        },
        "stack": {
            "stack_code": config.project.identity.clone().unwrap_or_else(|| config.name.clone()),
            "vars": [],
            "integrated_features": [],
            "extended_features": [],
            "subscriptions": [],
        }
    });

    // Inject Docker registry credentials if provided (env vars or stacker.yml).
    // These flow through the Stacker server to the Install Service, which passes
    // them as Ansible extra vars (docker_registry, docker_username, docker_password).
    let registry_creds = super::install_runner::resolve_docker_registry_credentials(config);
    if !registry_creds.is_empty() {
        if let Some(obj) = form.as_object_mut() {
            obj.insert(
                "registry".to_string(),
                serde_json::Value::Object(registry_creds),
            );
        }
    }

    // When proxy type is Nginx or NginxProxyManager, inject "nginx_proxy_manager"
    // into extended_features so the install service's Ansible playbook runs the
    // nginx_proxy_manager role (collect_roles checks selected_features).
    match config.proxy.proxy_type {
        crate::cli::config_parser::ProxyType::Nginx
        | crate::cli::config_parser::ProxyType::NginxProxyManager => {
            if let Some(stack_obj) = form.get_mut("stack").and_then(|v| v.as_object_mut()) {
                let features = stack_obj
                    .entry("extended_features")
                    .or_insert_with(|| serde_json::json!([]));
                if let Some(arr) = features.as_array_mut() {
                    let npm = serde_json::Value::String("nginx_proxy_manager".to_string());
                    if !arr.contains(&npm) {
                        arr.push(npm);
                    }
                }
            }
        }
        _ => {}
    }

    // When monitoring.status_panel is enabled, inject the "statuspanel" role into
    // integrated_features, set connection_mode so the installer recognizes the
    // status panel flow, and pass vault_url in stack.vars so the Ansible role
    // configures the remote status panel agent with the public Vault address.
    if config.monitoring.status_panel {
        // Resolve public Vault URL: env override → default constant.
        let vault_url =
            std::env::var("STACKER_VAULT_URL").unwrap_or_else(|_| DEFAULT_VAULT_URL.to_string());

        if let Some(stack_obj) = form.get_mut("stack").and_then(|v| v.as_object_mut()) {
            let features = stack_obj
                .entry("integrated_features")
                .or_insert_with(|| serde_json::json!([]));
            if let Some(arr) = features.as_array_mut() {
                let sp = serde_json::Value::String("statuspanel".to_string());
                if !arr.contains(&sp) {
                    arr.push(sp);
                }
            }

            // Inject vault_url into stack.vars so the Install Service Ansible
            // statuspanel role configures the agent with the public Vault address.
            let vars = stack_obj
                .entry("vars")
                .or_insert_with(|| serde_json::json!([]));
            if let Some(arr) = vars.as_array_mut() {
                arr.push(serde_json::json!({
                    "key": "vault_url",
                    "value": vault_url
                }));
                arr.push(serde_json::json!({
                    "key": "status_panel_port",
                    "value": "5000"
                }));
            }
        }
        if let Some(server_obj) = form.get_mut("server").and_then(|v| v.as_object_mut()) {
            server_obj.insert(
                "connection_mode".to_string(),
                serde_json::Value::String("status_panel".to_string()),
            );
        }
    }

    form
}

pub fn build_server_deploy_form(
    config: &StackerConfig,
    server_cfg: &crate::cli::config_parser::ServerConfig,
    server_name: &str,
    force_status_panel: bool,
) -> serde_json::Value {
    build_server_deploy_form_with_options(
        config,
        server_cfg,
        server_name,
        force_status_panel,
        DeployFormOptions {
            include_managed_proxy: true,
        },
    )
}

pub fn build_server_deploy_form_with_options(
    config: &StackerConfig,
    server_cfg: &crate::cli::config_parser::ServerConfig,
    server_name: &str,
    force_status_panel: bool,
    options: DeployFormOptions,
) -> serde_json::Value {
    let project_name = config
        .project
        .identity
        .clone()
        .unwrap_or_else(|| config.name.clone());

    let mut form = serde_json::json!({
        "cloud": {
            "provider": "own",
            "save_token": false,
        },
        "server": {
            "name": server_name,
            "srv_ip": server_cfg.host,
            "ssh_user": server_cfg.user,
            "ssh_port": server_cfg.port,
        },
        "stack": {
            "stack_code": project_name,
            "vars": [],
            "integrated_features": [],
            "extended_features": [],
            "subscriptions": [],
        }
    });

    let registry_creds = super::install_runner::resolve_docker_registry_credentials(config);
    if !registry_creds.is_empty() {
        if let Some(obj) = form.as_object_mut() {
            obj.insert(
                "registry".to_string(),
                serde_json::Value::Object(registry_creds),
            );
        }
    }

    if options.include_managed_proxy {
        match config.proxy.proxy_type {
            crate::cli::config_parser::ProxyType::Nginx
            | crate::cli::config_parser::ProxyType::NginxProxyManager => {
                if let Some(stack_obj) = form.get_mut("stack").and_then(|v| v.as_object_mut()) {
                    let features = stack_obj
                        .entry("extended_features")
                        .or_insert_with(|| serde_json::json!([]));
                    if let Some(arr) = features.as_array_mut() {
                        let npm = serde_json::Value::String("nginx_proxy_manager".to_string());
                        if !arr.contains(&npm) {
                            arr.push(npm);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    if config.monitoring.status_panel || force_status_panel {
        let vault_url =
            std::env::var("STACKER_VAULT_URL").unwrap_or_else(|_| DEFAULT_VAULT_URL.to_string());

        if let Some(stack_obj) = form.get_mut("stack").and_then(|v| v.as_object_mut()) {
            let features = stack_obj
                .entry("integrated_features")
                .or_insert_with(|| serde_json::json!([]));
            if let Some(arr) = features.as_array_mut() {
                let sp = serde_json::Value::String("statuspanel".to_string());
                if !arr.contains(&sp) {
                    arr.push(sp);
                }
            }

            let vars = stack_obj
                .entry("vars")
                .or_insert_with(|| serde_json::json!([]));
            if let Some(arr) = vars.as_array_mut() {
                arr.push(serde_json::json!({
                    "key": "vault_url",
                    "value": vault_url
                }));
                arr.push(serde_json::json!({
                    "key": "status_panel_port",
                    "value": "5000"
                }));
            }
        }
        if let Some(server_obj) = form.get_mut("server").and_then(|v| v.as_object_mut()) {
            server_obj.insert(
                "connection_mode".to_string(),
                serde_json::Value::String("status_panel".to_string()),
            );
        }
    }

    form
}

fn remove_extended_feature(form: &mut serde_json::Value, code: &str) {
    let Some(features) = form
        .get_mut("stack")
        .and_then(|stack| stack.get_mut("extended_features"))
        .and_then(|features| features.as_array_mut())
    else {
        return;
    };

    features.retain(|feature| feature.as_str() != Some(code));
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn stacker_api_failure_hides_endpoint_and_body_without_debug() {
        let message = stacker_api_failure_with_debug(
            "GET /cloud",
            400,
            r#"{"message":"401 Unauthorized"}"#,
            false,
        );

        assert!(message.contains("Stacker server request failed (400)"));
        assert!(!message.contains("GET /cloud"));
        assert!(!message.contains("401 Unauthorized"));
        assert!(!message.contains(r#"{"message""#));
        assert!(message.contains("DEBUG=true"));
        assert!(message.contains("RUST_LOG=debug"));
    }

    #[test]
    fn stacker_api_failure_includes_endpoint_and_body_with_debug() {
        let message = stacker_api_failure_with_debug(
            "GET /cloud",
            400,
            r#"{"message":"401 Unauthorized"}"#,
            true,
        );

        assert_eq!(
            message,
            r#"Stacker server GET /cloud failed (400): {"message":"401 Unauthorized"}"#
        );
    }

    #[test]
    fn test_build_deploy_form_defaults() {
        let config = crate::cli::config_parser::ConfigBuilder::new()
            .name("myproject")
            .deploy_target(crate::cli::config_parser::DeployTarget::Cloud)
            .cloud(crate::cli::config_parser::CloudConfig {
                provider: crate::cli::config_parser::CloudProvider::Hetzner,
                orchestrator: crate::cli::config_parser::CloudOrchestrator::Remote,
                region: Some("fsn1".to_string()),
                size: Some("cpx11".to_string()),
                install_image: None,
                remote_payload_file: None,
                ssh_key: None,
                key: None,
                server: None,
            })
            .build()
            .unwrap();

        let form = build_deploy_form(&config);
        assert_eq!(form["cloud"]["provider"], "htz");
        assert_eq!(form["server"]["region"], "fsn1");
        assert_eq!(form["server"]["server"], "cpx11");
        assert_eq!(form["stack"]["stack_code"], "myproject");
        // Auto-generated server name should start with the project name
        let name = form["server"]["name"].as_str().unwrap();
        assert!(
            name.starts_with("myproject-"),
            "server name should start with project name, got: {}",
            name
        );
        assert_eq!(
            name.len(),
            "myproject-".len() + 4,
            "suffix should be 4 hex chars"
        );
    }

    #[test]
    fn test_attach_config_bundle_adds_deploy_files_and_stack_builder_metadata() {
        let artifacts = crate::cli::config_bundle::ConfigBundleArtifacts {
            environment: "production".to_string(),
            manifest_path: std::path::PathBuf::from(
                ".stacker/deploy/production/config-bundle.manifest.json",
            ),
            archive_path: std::path::PathBuf::from(
                ".stacker/deploy/production/config-bundle.tar.zst",
            ),
            remote_compose_path: std::path::PathBuf::from(
                ".stacker/deploy/production/docker-compose.remote.yml",
            ),
            manifest: crate::cli::config_bundle::ConfigBundleManifest {
                version: 1,
                environment: "production".to_string(),
                files: vec![crate::cli::config_bundle::ConfigBundleFile {
                    source_path: "docker/production/.env".to_string(),
                    destination_path:
                        "/opt/stacker/deployments/production/files/docker/production/.env"
                            .to_string(),
                    mode: "0644".to_string(),
                    size: 17,
                    sha256: "abc123".to_string(),
                }],
            },
            config_files: vec![serde_json::json!({
                "name": ".env",
                "content": "RUST_LOG=warning\n",
                "destination_path": "/opt/stacker/deployments/production/files/docker/production/.env",
            })],
        };

        let config = crate::cli::config_parser::ConfigBuilder::new()
            .name("device-api")
            .deploy_target(crate::cli::config_parser::DeployTarget::Cloud)
            .build()
            .unwrap();
        let mut project_body = build_project_body(&config);
        let mut deploy_form = build_deploy_form(&config);

        attach_config_bundle_to_project_body(&mut project_body, &artifacts);
        attach_config_bundle_to_deploy_form(&mut deploy_form, &artifacts);

        assert_eq!(deploy_form["environment"], "production");
        assert_eq!(deploy_form["config_files"][0]["name"], ".env");
        assert_eq!(
            project_body["custom"]["deployment_artifacts"]["config_bundle"]["config_files"][0]
                ["source_path"],
            "docker/production/.env"
        );
        assert_eq!(
            project_body["custom"]["deployment_artifacts"]["config_bundle"]["config_files"][0]
                ["content_hidden"],
            true
        );
        assert!(
            project_body["custom"]["deployment_artifacts"]["config_bundle"]["config_files"][0]
                .get("content")
                .is_none()
        );
    }

    #[test]
    fn test_build_server_deploy_form_uses_existing_server_settings() {
        let config = crate::cli::config_parser::ConfigBuilder::new()
            .name("myproject")
            .deploy_target(crate::cli::config_parser::DeployTarget::Server)
            .server(crate::cli::config_parser::ServerConfig {
                host: "203.0.113.10".to_string(),
                user: "deploy".to_string(),
                ssh_key: Some(std::path::PathBuf::from("/tmp/id_ed25519")),
                port: 2222,
            })
            .build()
            .unwrap();
        let server_cfg = config.deploy.server.as_ref().unwrap();

        let form = build_server_deploy_form(&config, server_cfg, "edge-box", true);

        assert_eq!(form["cloud"]["provider"], "own");
        assert_eq!(form["cloud"]["save_token"], false);
        assert_eq!(form["server"]["name"], "edge-box");
        assert_eq!(form["server"]["srv_ip"], "203.0.113.10");
        assert_eq!(form["server"]["ssh_user"], "deploy");
        assert_eq!(form["server"]["ssh_port"], 2222);
        assert_eq!(form["server"]["connection_mode"], "status_panel");
        assert_eq!(form["stack"]["stack_code"], "myproject");
        assert!(form["stack"]["integrated_features"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == "statuspanel"));
    }

    #[test]
    fn test_build_server_deploy_form_with_status_panel_monitoring_uses_connection_mode() {
        let config = crate::cli::config_parser::ConfigBuilder::new()
            .name("myproject")
            .deploy_target(crate::cli::config_parser::DeployTarget::Server)
            .server(crate::cli::config_parser::ServerConfig {
                host: "203.0.113.10".to_string(),
                user: "deploy".to_string(),
                ssh_key: Some(std::path::PathBuf::from("/tmp/id_ed25519")),
                port: 2222,
            })
            .monitoring(crate::cli::config_parser::MonitoringConfig {
                status_panel: true,
                healthcheck: None,
                metrics: None,
            })
            .build()
            .unwrap();
        let server_cfg = config.deploy.server.as_ref().unwrap();

        let form = build_server_deploy_form(&config, server_cfg, "edge-box", false);
        let vars = form["stack"]["vars"].as_array().unwrap();

        assert_eq!(form["server"]["connection_mode"], "status_panel");
        assert!(form["stack"]["integrated_features"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == "statuspanel"));
        assert!(vars.iter().any(|value| value["key"] == "vault_url"));
    }

    #[test]
    fn test_build_deploy_form_with_identity() {
        let config = crate::cli::config_parser::ConfigBuilder::new()
            .name("myproject")
            .deploy_target(crate::cli::config_parser::DeployTarget::Cloud)
            .cloud(crate::cli::config_parser::CloudConfig {
                provider: crate::cli::config_parser::CloudProvider::Hetzner,
                orchestrator: crate::cli::config_parser::CloudOrchestrator::Remote,
                region: None,
                size: None,
                install_image: None,
                remote_payload_file: None,
                ssh_key: None,
                key: None,
                server: None,
            })
            .project_identity("optimumcode")
            .build()
            .unwrap();

        let form = build_deploy_form(&config);
        assert_eq!(form["stack"]["stack_code"], "optimumcode");
    }

    #[test]
    fn test_build_deploy_form_with_status_panel() {
        let config = crate::cli::config_parser::ConfigBuilder::new()
            .name("myproject")
            .deploy_target(crate::cli::config_parser::DeployTarget::Cloud)
            .cloud(crate::cli::config_parser::CloudConfig {
                provider: crate::cli::config_parser::CloudProvider::Hetzner,
                orchestrator: crate::cli::config_parser::CloudOrchestrator::Remote,
                region: Some("nbg1".to_string()),
                size: Some("cx22".to_string()),
                install_image: None,
                remote_payload_file: None,
                ssh_key: None,
                key: None,
                server: None,
            })
            .monitoring(crate::cli::config_parser::MonitoringConfig {
                status_panel: true,
                healthcheck: None,
                metrics: None,
            })
            .build()
            .unwrap();

        let form = build_deploy_form(&config);
        // status_panel should inject "statuspanel" into integrated_features
        let features = form["stack"]["integrated_features"].as_array().unwrap();
        assert!(
            features.contains(&serde_json::json!("statuspanel")),
            "integrated_features should contain 'statuspanel': {:?}",
            features
        );
        assert_eq!(form["server"]["connection_mode"], "status_panel");

        // vault_url should be passed in stack.vars for the Ansible statuspanel role
        let vars = form["stack"]["vars"].as_array().unwrap();
        let vault_var = vars.iter().find(|v| v["key"] == "vault_url");
        assert!(
            vault_var.is_some(),
            "stack.vars should contain vault_url: {:?}",
            vars
        );
        assert_eq!(
            vault_var.unwrap()["value"],
            DEFAULT_VAULT_URL,
            "vault_url should be the public Vault address"
        );

        // status_panel_port should be passed in stack.vars for the cloud firewall
        let port_var = vars.iter().find(|v| v["key"] == "status_panel_port");
        assert!(
            port_var.is_some(),
            "stack.vars should contain status_panel_port: {:?}",
            vars
        );
        assert_eq!(
            port_var.unwrap()["value"],
            "5000",
            "status_panel_port should be 5000"
        );
    }

    #[test]
    fn test_build_deploy_form_with_nginx_proxy() {
        let config = crate::cli::config_parser::ConfigBuilder::new()
            .name("myproject")
            .deploy_target(crate::cli::config_parser::DeployTarget::Cloud)
            .cloud(crate::cli::config_parser::CloudConfig {
                provider: crate::cli::config_parser::CloudProvider::Hetzner,
                orchestrator: crate::cli::config_parser::CloudOrchestrator::Remote,
                region: Some("nbg1".to_string()),
                size: Some("cx22".to_string()),
                install_image: None,
                remote_payload_file: None,
                ssh_key: None,
                key: None,
                server: None,
            })
            .proxy(crate::cli::config_parser::ProxyConfig {
                proxy_type: crate::cli::config_parser::ProxyType::Nginx,
                auto_detect: true,
                domains: vec![],
                config: None,
            })
            .build()
            .unwrap();

        let form = build_deploy_form(&config);
        // proxy type nginx should inject "nginx_proxy_manager" into extended_features
        let ext_features = form["stack"]["extended_features"].as_array().unwrap();
        assert!(
            ext_features.contains(&serde_json::json!("nginx_proxy_manager")),
            "extended_features should contain 'nginx_proxy_manager': {:?}",
            ext_features
        );
    }

    #[test]
    fn test_build_project_body_with_nginx_proxy_does_not_add_npm_project_feature() {
        let config = crate::cli::config_parser::ConfigBuilder::new()
            .name("myproject")
            .proxy(crate::cli::config_parser::ProxyConfig {
                proxy_type: crate::cli::config_parser::ProxyType::Nginx,
                auto_detect: true,
                domains: vec![],
                config: None,
            })
            .build()
            .unwrap();

        let body = build_project_body(&config);
        let features = body["custom"]["feature"].as_array().unwrap();
        assert!(
            features.iter().all(|f| f["code"] != "nginx_proxy_manager"),
            "feature array should not contain nginx_proxy_manager project app: {:?}",
            features
        );
    }

    #[test]
    fn pipe_instance_request_serializes_adapter_references() {
        let request = CreatePipeInstanceApiRequest {
            deployment_hash: Some("dep-123".into()),
            source_adapter: Some(
                PipeAdapterReference::new("imap")
                    .with_config(serde_json::json!({ "mailbox": "INBOX" })),
            ),
            source_container: "status-panel-web".into(),
            target_adapter: Some(
                PipeAdapterReference::new("smtp")
                    .with_config(serde_json::json!({ "host": "smtp.example.com" })),
            ),
            target_container: None,
            target_url: Some("smtp://mail.example.com:587".into()),
            template_id: Some("tpl-123".into()),
            field_mapping_override: Some(serde_json::json!({ "subject": "$.subject" })),
            config_override: Some(serde_json::json!({ "timeout_secs": 30 })),
        };

        let value = serde_json::to_value(&request).unwrap();
        assert_eq!(value["source_adapter"]["code"], "imap");
        assert_eq!(value["target_adapter"]["code"], "smtp");
        assert_eq!(value["source_adapter"]["config"]["mailbox"], "INBOX");
        assert_eq!(
            value["target_adapter"]["config"]["host"],
            "smtp.example.com"
        );
    }

    #[test]
    fn pipe_instance_info_deserializes_adapter_references() {
        let value = serde_json::json!({
            "id": "pipe-123",
            "template_id": "tpl-123",
            "deployment_hash": "dep-123",
            "source_adapter": {
                "code": "imap",
                "role": "source",
                "config": { "mailbox": "INBOX" }
            },
            "source_container": "status-panel-web",
            "target_adapter": {
                "code": "smtp",
                "role": "target",
                "config": { "host": "smtp.example.com" }
            },
            "target_container": "smtp",
            "target_url": null,
            "field_mapping_override": { "subject": "$.subject" },
            "config_override": { "timeout_secs": 30 },
            "status": "draft",
            "last_triggered_at": null,
            "trigger_count": 0,
            "error_count": 0,
            "created_by": "user-123",
            "created_at": "2026-05-21T00:00:00Z",
            "updated_at": "2026-05-21T00:00:00Z"
        });

        let info: PipeInstanceInfo = serde_json::from_value(value).unwrap();
        assert_eq!(
            info.source_adapter
                .as_ref()
                .map(|adapter| adapter.code.as_str()),
            Some("imap")
        );
        assert_eq!(
            info.target_adapter
                .as_ref()
                .map(|adapter| adapter.code.as_str()),
            Some("smtp")
        );
        assert_eq!(info.source_container, "status-panel-web");
        assert_eq!(info.target_container.as_deref(), Some("smtp"));
    }

    #[test]
    fn test_build_project_body_skips_declared_npm_service_when_proxy_is_managed() {
        let npm_service = ServiceDefinition {
            name: "nginx_proxy_manager".to_string(),
            image: "jc21/nginx-proxy-manager:latest".to_string(),
            ports: vec![
                "80:80".to_string(),
                "443:443".to_string(),
                "81:81".to_string(),
            ],
            environment: std::collections::HashMap::new(),
            volumes: vec!["npm_data:/data".to_string()],
            depends_on: vec![],
        };
        let redis_service = ServiceDefinition {
            name: "redis".to_string(),
            image: "redis:7-alpine".to_string(),
            ports: vec![],
            environment: std::collections::HashMap::new(),
            volumes: vec![],
            depends_on: vec![],
        };
        let config = crate::cli::config_parser::ConfigBuilder::new()
            .name("myproject")
            .add_service(npm_service)
            .add_service(redis_service)
            .proxy(crate::cli::config_parser::ProxyConfig {
                proxy_type: crate::cli::config_parser::ProxyType::NginxProxyManager,
                auto_detect: true,
                domains: vec![],
                config: None,
            })
            .build()
            .unwrap();

        let body = build_project_body(&config);
        let service = body["custom"]["service"].as_array().unwrap();
        let codes = service
            .iter()
            .filter_map(|app| app["code"].as_str())
            .collect::<Vec<_>>();
        assert_eq!(codes, vec!["redis"]);
    }

    #[test]
    fn test_build_project_body_skips_platform_managed_services_even_without_proxy() {
        let npm_service = ServiceDefinition {
            name: "nginx_proxy_manager".to_string(),
            image: "jc21/nginx-proxy-manager:latest".to_string(),
            ports: vec![
                "80:80".to_string(),
                "443:443".to_string(),
                "81:81".to_string(),
            ],
            environment: std::collections::HashMap::new(),
            volumes: vec!["npm_data:/data".to_string()],
            depends_on: vec![],
        };
        let statuspanel_service = ServiceDefinition {
            name: "statuspanel".to_string(),
            image: "ghcr.io/trydirect/statuspanel:latest".to_string(),
            ports: vec!["5000:5000".to_string()],
            environment: std::collections::HashMap::new(),
            volumes: vec![],
            depends_on: vec![],
        };
        let smtp_service = ServiceDefinition {
            name: "smtp".to_string(),
            image: "trydirect/smtp:latest".to_string(),
            ports: vec!["127.0.0.1:1025:25".to_string()],
            environment: std::collections::HashMap::new(),
            volumes: vec![],
            depends_on: vec![],
        };
        let config = crate::cli::config_parser::ConfigBuilder::new()
            .name("myproject")
            .add_service(npm_service)
            .add_service(statuspanel_service)
            .add_service(smtp_service)
            .proxy(crate::cli::config_parser::ProxyConfig {
                proxy_type: crate::cli::config_parser::ProxyType::None,
                auto_detect: false,
                domains: vec![],
                config: None,
            })
            .build()
            .unwrap();

        let body = build_project_body(&config);
        let service = body["custom"]["service"].as_array().unwrap();
        let codes = service
            .iter()
            .filter_map(|app| app["code"].as_str())
            .collect::<Vec<_>>();
        assert_eq!(codes, vec!["smtp"]);
    }

    #[test]
    fn test_parse_port_mapping_accepts_host_ip_bindings() {
        assert_eq!(
            parse_port_mapping("127.0.0.1:1025:25"),
            ("1025".to_string(), "25".to_string())
        );
        assert_eq!(
            parse_port_mapping("127.0.0.1:1025:25/tcp"),
            ("1025".to_string(), "25".to_string())
        );
        assert_eq!(
            parse_port_mapping("3000:3000"),
            ("3000".to_string(), "3000".to_string())
        );
        assert_eq!(
            parse_port_mapping("8080"),
            ("8080".to_string(), "8080".to_string())
        );
    }

    #[test]
    fn test_scn_001_stacker_yml_service_serializes_as_service_target() {
        let upload_service = ServiceDefinition {
            name: "upload".to_string(),
            image: "ghcr.io/example/upload:1.0".to_string(),
            ports: vec!["8081:8080".to_string()],
            environment: std::collections::HashMap::new(),
            volumes: vec![],
            depends_on: vec![],
        };
        let config = crate::cli::config_parser::ConfigBuilder::new()
            .name("Device API")
            .project_identity("device-api")
            .app_image("ghcr.io/example/device-api:1.0")
            .add_service(upload_service)
            .build()
            .unwrap();

        let body = build_project_body(&config);
        let web_codes = body["custom"]["web"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|app| app["code"].as_str())
            .collect::<Vec<_>>();
        let service_codes = body["custom"]["service"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|app| app["code"].as_str())
            .collect::<Vec<_>>();

        assert_eq!(web_codes, vec!["device-api"]);
        assert_eq!(service_codes, vec!["upload"]);
    }

    #[test]
    fn test_build_project_body_with_status_panel_does_not_add_status_panel_feature() {
        let config = crate::cli::config_parser::ConfigBuilder::new()
            .name("myproject")
            .monitoring(crate::cli::config_parser::MonitoringConfig {
                status_panel: true,
                healthcheck: None,
                metrics: None,
            })
            .build()
            .unwrap();

        let body = build_project_body(&config);
        let features = body["custom"]["feature"].as_array().unwrap();
        assert!(
            features.iter().all(|f| f["code"] != "statuspanel"),
            "feature array should not contain statuspanel entry: {:?}",
            features
        );
    }

    #[test]
    fn test_build_project_body_without_proxy() {
        let config = crate::cli::config_parser::ConfigBuilder::new()
            .name("myproject")
            .build()
            .unwrap();

        let body = build_project_body(&config);
        let features = body["custom"]["feature"].as_array().unwrap();
        assert!(
            features.is_empty(),
            "feature array should be empty when no proxy configured"
        );
    }

    #[test]
    fn test_generate_server_name_basic() {
        let name = generate_server_name("website");
        assert!(name.starts_with("website-"), "got: {}", name);
        // 4 hex chars suffix
        let suffix = &name["website-".len()..];
        assert_eq!(suffix.len(), 4);
        assert!(
            suffix.chars().all(|c| c.is_ascii_hexdigit()),
            "suffix should be hex, got: {}",
            suffix
        );
    }

    #[test]
    fn test_generate_server_name_sanitises() {
        let name = generate_server_name("My Cool App!");
        assert!(name.starts_with("my-cool-app-"), "got: {}", name);
    }

    #[test]
    fn test_generate_server_name_empty() {
        let name = generate_server_name("");
        assert!(
            name.starts_with("srv-"),
            "empty input should fallback to 'srv', got: {}",
            name
        );
    }

    #[test]
    fn test_generate_server_name_special_chars() {
        let name = generate_server_name("app___v2..beta");
        assert!(
            name.starts_with("app-v2-beta-"),
            "consecutive separators collapsed, got: {}",
            name
        );
    }

    #[test]
    fn test_generate_server_name_numeric_start() {
        // Hetzner requires name to start with a letter
        let name = generate_server_name("123app");
        assert!(
            name.starts_with("srv-123app-"),
            "numeric start should get 'srv-' prefix, got: {}",
            name
        );
    }

    #[test]
    fn test_generate_server_name_max_length() {
        let long = "a".repeat(100);
        let name = generate_server_name(&long);
        assert!(
            name.len() <= 63,
            "name must be ≤63 chars (Hetzner), got {} chars: {}",
            name.len(),
            name
        );
        assert!(name.starts_with("aaa"), "got: {}", name);
        // Must not end with hyphen
        assert!(
            !name.ends_with('-'),
            "must not end with hyphen, got: {}",
            name
        );
    }

    #[tokio::test]
    async fn test_list_projects_falls_back_to_legacy_project_path() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/v1/project"))
            .respond_with(ResponseTemplate::new(404).set_body_string(
                r#"{"_status":"ERR","_error":{"code":404,"message":"not found"}}"#,
            ))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/project"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "_status": "OK",
                "list": [
                    {
                        "id": 7,
                        "name": "demo-project",
                        "user_id": "user-1",
                        "metadata": {},
                        "created_at": "2026-01-01T00:00:00Z",
                        "updated_at": "2026-01-01T00:00:00Z"
                    }
                ]
            })))
            .mount(&server)
            .await;

        let client = StackerClient::new_for_target(&server.uri(), "token", DeployTarget::Server);
        let projects = client
            .list_projects()
            .await
            .expect("fallback should succeed");

        assert_eq!(projects.len(), 1);
        assert_eq!(projects[0].id, 7);
        assert_eq!(projects[0].name, "demo-project");
    }

    #[tokio::test]
    async fn test_deploy_falls_back_to_legacy_project_path() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/api/v1/project/12/deploy"))
            .respond_with(ResponseTemplate::new(404).set_body_string(
                r#"{"_status":"ERR","_error":{"code":404,"message":"not found"}}"#,
            ))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/project/12/deploy"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 99,
                "_status": "OK",
                "meta": {
                    "deployment_hash": "hash-123"
                }
            })))
            .mount(&server)
            .await;

        let client = StackerClient::new_for_target(&server.uri(), "token", DeployTarget::Server);
        let response = client
            .deploy(
                12,
                None,
                serde_json::json!({ "stack": { "stack_code": "demo" } }),
            )
            .await
            .expect("deploy fallback should succeed");

        assert_eq!(response.id, Some(99));
        assert_eq!(response.status.as_deref(), Some("OK"));
        assert_eq!(
            response
                .meta
                .as_ref()
                .and_then(|meta| meta.get("deployment_hash")),
            Some(&serde_json::json!("hash-123"))
        );
    }

    #[tokio::test]
    async fn test_list_projects_retries_api_v1_after_forbidden_legacy_proxy_response() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/v1/project"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "_status": "OK",
                "list": [
                    {
                        "id": 7,
                        "name": "demo-project",
                        "user_id": "user-1",
                        "metadata": {},
                        "created_at": "2026-01-01T00:00:00Z",
                        "updated_at": "2026-01-01T00:00:00Z"
                    }
                ]
            })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/project"))
            .respond_with(ResponseTemplate::new(403).set_body_string("forbidden"))
            .mount(&server)
            .await;

        let client = StackerClient::new_for_target(&server.uri(), "token", DeployTarget::Server);
        let projects = client
            .list_projects()
            .await
            .expect("api v1 endpoint should be preferred before legacy 403");

        assert_eq!(projects.len(), 1);
        assert_eq!(projects[0].name, "demo-project");
    }
}
