use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentHandoffKind {
    #[default]
    Deployment,
    Account,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeploymentHandoffProject {
    pub id: i32,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeploymentHandoffDeployment {
    pub id: i32,
    pub hash: String,
    pub target: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeploymentHandoffServer {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeploymentHandoffCloud {
    pub id: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeploymentHandoffAgent {
    pub base_url: String,
    pub deployment_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeploymentHandoffCredentials {
    pub access_token: String,
    pub token_type: String,
    pub expires_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeploymentHandoffPayload {
    #[serde(default)]
    pub kind: DeploymentHandoffKind,
    pub version: u32,
    pub expires_at: DateTime<Utc>,
    pub project: DeploymentHandoffProject,
    pub deployment: DeploymentHandoffDeployment,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<DeploymentHandoffServer>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloud: Option<DeploymentHandoffCloud>,
    pub lockfile: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stacker_yml: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<DeploymentHandoffAgent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credentials: Option<DeploymentHandoffCredentials>,
}

impl DeploymentHandoffPayload {
    pub fn is_account_scoped(&self) -> bool {
        self.kind == DeploymentHandoffKind::Account
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeploymentHandoffLink {
    pub token: String,
    pub url: String,
    pub expires_at: DateTime<Utc>,
}

impl DeploymentHandoffLink {
    pub fn is_expired(&self) -> bool {
        self.is_expired_at(Utc::now())
    }

    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        now >= self.expires_at
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct DeploymentHandoffMintRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deployment_id: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deployment_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeploymentHandoffMintResponse {
    pub token: String,
    pub url: String,
    pub command: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeploymentHandoffResolveRequest {
    pub token: String,
}
