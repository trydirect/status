use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    db,
    helpers::{
        extract_capabilities, has_capability, has_capability_value, remote_runtime_compose_path,
        remote_runtime_env_path, NPM_CREDENTIAL_SOURCE_KEY,
    },
    models::{Agent, Command, Deployment, Project, ProjectApp},
};

pub const DEPLOYMENT_STATE_SCHEMA_VERSION: &str = "v1alpha1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentState {
    pub schema_version: String,
    pub project: DeploymentProjectState,
    pub deployment: DeploymentStateDeployment,
    pub agent: DeploymentAgentState,
    pub runtime: DeploymentRuntimeState,
    pub apps: Vec<DeploymentAppState>,
    pub drift: DeploymentDriftState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_command: Option<DeploymentLastCommandState>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentProjectState {
    pub id: i32,
    pub identity: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentStateDeployment {
    pub id: i32,
    pub deployment_hash: String,
    pub status: String,
    pub runtime: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentAgentState {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_heartbeat: Option<DateTime<Utc>>,
    pub capabilities: Vec<String>,
    pub features: DeploymentAgentFeatures,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentAgentFeatures {
    pub compose: bool,
    pub kata_runtime: bool,
    pub backup: bool,
    pub pipes: bool,
    pub proxy_credentials_vault: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentRuntimeState {
    pub compose_path: String,
    pub env_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentAppState {
    pub code: String,
    pub name: String,
    pub enabled: bool,
    pub config_version: i32,
    pub vault_sync_version: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentDriftState {
    pub has_drift: bool,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentLastCommandState {
    pub r#type: String,
    pub status: String,
    pub finished_at: DateTime<Utc>,
}

impl DeploymentState {
    pub fn from_parts(
        project: &Project,
        deployment: &Deployment,
        agent: Option<&Agent>,
        apps: &[ProjectApp],
        last_command: Option<&Command>,
    ) -> Self {
        let capabilities = agent
            .map(|item| extract_capabilities(item.capabilities.clone()))
            .unwrap_or_default();

        let features = DeploymentAgentFeatures {
            compose: has_capability(&capabilities, "compose"),
            kata_runtime: has_capability(&capabilities, "kata"),
            backup: has_capability(&capabilities, "backup"),
            pipes: has_capability(&capabilities, "pipes"),
            proxy_credentials_vault: has_capability_value(
                &capabilities,
                NPM_CREDENTIAL_SOURCE_KEY,
                "vault",
            ),
        };

        let apps = apps
            .iter()
            .map(|app| DeploymentAppState {
                code: app.code.clone(),
                name: app.name.clone(),
                enabled: app.enabled.unwrap_or(true),
                config_version: app.config_version.unwrap_or(0),
                vault_sync_version: app.vault_sync_version.unwrap_or(0),
                config_hash: app.config_hash.clone(),
            })
            .collect();

        Self {
            schema_version: DEPLOYMENT_STATE_SCHEMA_VERSION.to_string(),
            project: DeploymentProjectState {
                id: project.id,
                identity: project
                    .metadata
                    .get("identity")
                    .and_then(|value| value.as_str())
                    .unwrap_or(&project.name)
                    .to_string(),
                name: project.name.clone(),
            },
            deployment: DeploymentStateDeployment {
                id: deployment.id,
                deployment_hash: deployment.deployment_hash.clone(),
                status: deployment.status.clone(),
                runtime: deployment.runtime.clone(),
            },
            agent: DeploymentAgentState {
                id: agent.map(|item| item.id.to_string()),
                status: agent
                    .map(|item| item.status.clone())
                    .unwrap_or_else(|| "offline".to_string()),
                version: agent.and_then(|item| item.version.clone()),
                last_heartbeat: agent.and_then(|item| item.last_heartbeat),
                capabilities,
                features,
            },
            runtime: DeploymentRuntimeState {
                compose_path: remote_runtime_compose_path().to_string(),
                env_path: remote_runtime_env_path().to_string(),
            },
            apps,
            drift: DeploymentDriftState {
                has_drift: false,
                summary: "no drift detected".to_string(),
            },
            last_command: last_command.map(|command| DeploymentLastCommandState {
                r#type: command.r#type.clone(),
                status: command.status.clone(),
                finished_at: command.updated_at,
            }),
        }
    }

    pub async fn for_deployment_hash(
        pool: &sqlx::PgPool,
        deployment_hash: &str,
    ) -> Result<Option<Self>, String> {
        let deployment =
            match db::deployment::fetch_by_deployment_hash(pool, deployment_hash).await? {
                Some(item) => item,
                None => return Ok(None),
            };

        let project = db::project::fetch(pool, deployment.project_id)
            .await?
            .ok_or_else(|| "Project not found for deployment".to_string())?;
        let agent = db::agent::fetch_by_deployment_hash(pool, deployment_hash).await?;
        let apps = db::project_app::fetch_by_deployment(pool, project.id, deployment.id).await?;
        let last_command = db::command::fetch_recent_by_deployment(pool, deployment_hash, 1, true)
            .await?
            .into_iter()
            .next();

        Ok(Some(Self::from_parts(
            &project,
            &deployment,
            agent.as_ref(),
            &apps,
            last_command.as_ref(),
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Agent, Command, Deployment, Project, ProjectApp};
    use serde_json::json;

    fn sample_project() -> Project {
        let mut project = Project::new(
            "user-a".to_string(),
            "syncopia".to_string(),
            json!({ "identity": "syncopia" }),
            json!({}),
        );
        project.id = 17;
        project.metadata = json!({ "identity": "syncopia" });
        project
    }

    fn sample_deployment(hash: &str, status: &str) -> Deployment {
        let mut deployment = Deployment::new(
            17,
            Some("user-a".to_string()),
            hash.to_string(),
            status.to_string(),
            "runc".to_string(),
            json!({}),
        );
        deployment.id = 31;
        deployment
    }

    fn sample_app(code: &str, name: &str, config_version: i32, sync_version: i32) -> ProjectApp {
        let mut app = ProjectApp::new(
            17,
            code.to_string(),
            name.to_string(),
            format!("{code}:latest"),
        );
        app.config_version = Some(config_version);
        app.vault_sync_version = Some(sync_version);
        app.config_hash = Some(format!("cfg-{code}"));
        app
    }

    #[test]
    fn serializes_online_state() {
        let mut agent = Agent::new("deployment_state_online".to_string());
        agent.mark_online();
        agent.version = Some("0.1.9".to_string());
        agent.capabilities = Some(json!([
            "docker",
            "compose",
            "logs",
            "npm_credential_source=vault"
        ]));

        let state = DeploymentState::from_parts(
            &sample_project(),
            &sample_deployment("deployment_state_online", "healthy"),
            Some(&agent),
            &[
                sample_app("device-api", "Device API", 3, 3),
                sample_app("upload", "Upload", 2, 2),
            ],
            Some(
                &Command::new(
                    "cmd-1".to_string(),
                    "deployment_state_online".to_string(),
                    "deploy_app".to_string(),
                    "user-a".to_string(),
                )
                .mark_completed(),
            ),
        );

        let json = serde_json::to_value(&state).expect("state should serialize");
        assert_eq!(json["schemaVersion"], DEPLOYMENT_STATE_SCHEMA_VERSION);
        assert_eq!(
            json["deployment"]["deploymentHash"],
            "deployment_state_online"
        );
        assert_eq!(json["agent"]["status"], "online");
        assert_eq!(json["apps"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn offline_state_omits_optional_agent_fields() {
        let state = DeploymentState::from_parts(
            &sample_project(),
            &sample_deployment("deployment_state_offline", "pending"),
            None,
            &[],
            None,
        );

        let json = serde_json::to_value(&state).expect("state should serialize");
        assert_eq!(json["agent"]["status"], "offline");
        assert!(json["agent"].get("id").is_none());
        assert!(json.get("lastCommand").is_none());
    }
}
