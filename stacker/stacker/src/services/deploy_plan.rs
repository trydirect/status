use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;

use crate::{
    db,
    models::Deployment,
    services::{
        DeploymentAppState, DeploymentState, TypedErrorCode, TypedErrorEnvelope,
        TypedRemediationClass,
    },
};

pub const DEPLOY_PLAN_SCHEMA_VERSION: &str = "v1alpha1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeployPlanOperation {
    Deploy,
    DeployApp,
    RollbackDeploy,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeployPlanActionKind {
    ReconcileRuntimeEnv,
    RedeployApp,
    RollbackDeploy,
    SyncAppConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DeployPlanRollback {
    pub requested_target: String,
    pub current_version: String,
    pub resolved_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackPlanContext {
    pub requested_target: String,
    pub current_version: String,
    pub resolved_version: String,
}

pub async fn resolve_rollback_plan_context(
    pg_pool: &PgPool,
    deployment: &Deployment,
    requested_target: &str,
) -> Result<RollbackPlanContext, TypedErrorEnvelope> {
    let project = db::project::fetch(pg_pool, deployment.project_id)
        .await
        .map_err(|_| TypedErrorEnvelope::internal_error("Failed to load rollback project"))?
        .ok_or_else(|| {
            TypedErrorEnvelope::deployment_not_found("Project not found for deployment")
        })?;

    let template_id = project.source_template_id.ok_or_else(|| {
        TypedErrorEnvelope::new(
            TypedErrorCode::RollbackTargetUnavailable,
            "Rollback is only available for marketplace deployments with an older template version",
            false,
            TypedRemediationClass::State,
        )
        .with_context("rollbackTarget", requested_target)
    })?;

    let versions = db::marketplace::list_versions_by_template(pg_pool, template_id)
        .await
        .map_err(|_| TypedErrorEnvelope::internal_error("Failed to load rollback versions"))?;

    let current = if let Some(current_version) = project.template_version.as_deref() {
        versions
            .iter()
            .find(|version| version.version == current_version)
    } else {
        versions
            .iter()
            .find(|version| version.is_latest.unwrap_or(false))
    }
    .ok_or_else(|| {
        TypedErrorEnvelope::new(
            TypedErrorCode::RollbackTargetUnavailable,
            "Rollback target could not be resolved from the current deployment state",
            false,
            TypedRemediationClass::State,
        )
        .with_context("rollbackTarget", requested_target)
    })?;

    let resolved_version = if requested_target == "previous" {
        let current_index = versions
            .iter()
            .position(|version| version.version == current.version)
            .ok_or_else(|| {
                TypedErrorEnvelope::new(
                    TypedErrorCode::RollbackTargetUnavailable,
                    "Current template version is not present in the rollback history",
                    false,
                    TypedRemediationClass::State,
                )
                .with_context("rollbackTarget", requested_target)
                .with_context("currentVersion", current.version.clone())
            })?;

        versions
            .get(current_index + 1)
            .map(|version| version.version.clone())
            .ok_or_else(|| {
                TypedErrorEnvelope::new(
                    TypedErrorCode::RollbackTargetUnavailable,
                    "No older marketplace template version is available for rollback",
                    false,
                    TypedRemediationClass::State,
                )
                .with_context("rollbackTarget", requested_target)
                .with_context("currentVersion", current.version.clone())
            })?
    } else {
        versions
            .iter()
            .find(|version| version.version == requested_target)
            .map(|version| version.version.clone())
            .ok_or_else(|| {
                TypedErrorEnvelope::new(
                    TypedErrorCode::RollbackTargetUnavailable,
                    format!(
                        "Marketplace template version '{}' is not available for rollback",
                        requested_target
                    ),
                    false,
                    TypedRemediationClass::State,
                )
                .with_context("rollbackTarget", requested_target)
            })?
    };

    Ok(RollbackPlanContext {
        requested_target: requested_target.to_string(),
        current_version: current.version.clone(),
        resolved_version,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DeployPlanScope {
    pub mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_code: Option<String>,
    pub selected_apps: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DeployPlanAction {
    pub kind: DeployPlanActionKind,
    pub target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_code: Option<String>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DeployPlan {
    pub schema_version: String,
    pub deployment_hash: String,
    pub operation: DeployPlanOperation,
    pub target: String,
    pub fingerprint: String,
    pub scope: DeployPlanScope,
    pub has_changes: bool,
    pub actions: Vec<DeployPlanAction>,
    pub reasoning: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rollback: Option<DeployPlanRollback>,
}

pub fn build_deploy_plan(
    state: &DeploymentState,
    operation: DeployPlanOperation,
    target: &str,
    requested_app: Option<&str>,
    expected_fingerprint: Option<&str>,
) -> Result<DeployPlan, TypedErrorEnvelope> {
    let selected_apps = select_apps(state, requested_app)?;
    let fingerprint = plan_fingerprint(state, target, &operation, &selected_apps);

    if let Some(expected) = expected_fingerprint.filter(|value| !value.is_empty()) {
        if expected != fingerprint {
            return Err(TypedErrorEnvelope::new(
                TypedErrorCode::PlanStale,
                "Plan input is stale; regenerate the plan before apply",
                false,
                TypedRemediationClass::State,
            )
            .with_context("expectedFingerprint", expected)
            .with_context("actualFingerprint", fingerprint.clone())
            .with_context("deploymentHash", state.deployment.deployment_hash.clone()));
        }
    }

    let mut actions = Vec::new();
    let mut reasoning = Vec::new();

    if state.drift.has_drift {
        actions.push(DeployPlanAction {
            kind: DeployPlanActionKind::ReconcileRuntimeEnv,
            target: "deployment".to_string(),
            app_code: None,
            reason: "runtime env drift detected".to_string(),
        });
        reasoning
            .push("deployment drift requires runtime env reconciliation before apply".to_string());
    }

    for app in &selected_apps {
        if app.config_version > app.vault_sync_version {
            actions.push(DeployPlanAction {
                kind: DeployPlanActionKind::SyncAppConfig,
                target: "app".to_string(),
                app_code: Some(app.code.clone()),
                reason: "app config version is ahead of the synced Vault/runtime version"
                    .to_string(),
            });
        }
    }

    if matches!(operation, DeployPlanOperation::DeployApp) {
        let app = selected_apps.first().ok_or_else(|| {
            TypedErrorEnvelope::invalid_request("deploy-app plan requires a selected app")
        })?;
        actions.insert(
            0,
            DeployPlanAction {
                kind: DeployPlanActionKind::RedeployApp,
                target: "app".to_string(),
                app_code: Some(app.code.clone()),
                reason: "explicit deploy-app plan targets a single app".to_string(),
            },
        );
        reasoning.push("deploy-app scope is restricted to the requested app".to_string());
    } else if actions.is_empty() {
        reasoning.push("no drift detected for the selected scope".to_string());
        reasoning.push(
            "all selected apps are already synced with their current config versions".to_string(),
        );
    } else if selected_apps
        .iter()
        .any(|app| app.config_version > app.vault_sync_version)
    {
        reasoning.push("at least one selected app has unsynced config changes".to_string());
    }

    Ok(DeployPlan {
        schema_version: DEPLOY_PLAN_SCHEMA_VERSION.to_string(),
        deployment_hash: state.deployment.deployment_hash.clone(),
        operation,
        target: target.to_string(),
        fingerprint,
        scope: DeployPlanScope {
            mode: if requested_app.is_some() {
                "app".to_string()
            } else {
                "deployment".to_string()
            },
            app_code: requested_app.map(ToOwned::to_owned),
            selected_apps: selected_apps.iter().map(|app| app.code.clone()).collect(),
        },
        has_changes: !actions.is_empty(),
        actions,
        reasoning,
        rollback: None,
    })
}

pub fn build_rollback_plan(
    state: &DeploymentState,
    target: &str,
    rollback: RollbackPlanContext,
    expected_fingerprint: Option<&str>,
) -> Result<DeployPlan, TypedErrorEnvelope> {
    let selected_apps = select_apps(state, None)?;
    let fingerprint = rollback_fingerprint(state, target, &rollback);

    if let Some(expected) = expected_fingerprint.filter(|value| !value.is_empty()) {
        if expected != fingerprint {
            return Err(TypedErrorEnvelope::new(
                TypedErrorCode::PlanStale,
                "Plan input is stale; regenerate the plan before apply",
                false,
                TypedRemediationClass::State,
            )
            .with_context("expectedFingerprint", expected)
            .with_context("actualFingerprint", fingerprint.clone())
            .with_context("deploymentHash", state.deployment.deployment_hash.clone()));
        }
    }

    let has_changes = rollback.current_version != rollback.resolved_version;
    let mut reasoning = vec![
        format!(
            "rollback preview resolved requested target '{}' to template version {}",
            rollback.requested_target, rollback.resolved_version
        ),
        format!(
            "current deployment template version is {}",
            rollback.current_version
        ),
    ];

    let actions = if has_changes {
        vec![DeployPlanAction {
            kind: DeployPlanActionKind::RollbackDeploy,
            target: "deployment".to_string(),
            app_code: None,
            reason: format!(
                "rollback preview targets marketplace template version {}",
                rollback.resolved_version
            ),
        }]
    } else {
        reasoning.push("deployment is already on the requested rollback target".to_string());
        Vec::new()
    };

    Ok(DeployPlan {
        schema_version: DEPLOY_PLAN_SCHEMA_VERSION.to_string(),
        deployment_hash: state.deployment.deployment_hash.clone(),
        operation: DeployPlanOperation::RollbackDeploy,
        target: target.to_string(),
        fingerprint,
        scope: DeployPlanScope {
            mode: "deployment".to_string(),
            app_code: None,
            selected_apps: selected_apps.iter().map(|app| app.code.clone()).collect(),
        },
        has_changes,
        actions,
        reasoning,
        rollback: Some(DeployPlanRollback {
            requested_target: rollback.requested_target,
            current_version: rollback.current_version,
            resolved_version: rollback.resolved_version,
        }),
    })
}

fn select_apps<'a>(
    state: &'a DeploymentState,
    requested_app: Option<&str>,
) -> Result<Vec<&'a DeploymentAppState>, TypedErrorEnvelope> {
    match requested_app {
        Some(app_code) => state
            .apps
            .iter()
            .find(|app| app.code == app_code)
            .map(|app| vec![app])
            .ok_or_else(|| {
                TypedErrorEnvelope::invalid_request(format!(
                    "Requested app '{app_code}' was not found in deployment state"
                ))
                .with_context("appCode", app_code)
            }),
        None => Ok(state.apps.iter().collect()),
    }
}

fn plan_fingerprint(
    state: &DeploymentState,
    target: &str,
    operation: &DeployPlanOperation,
    selected_apps: &[&DeploymentAppState],
) -> String {
    let payload = serde_json::json!({
        "deploymentHash": state.deployment.deployment_hash,
        "status": state.deployment.status,
        "runtime": state.deployment.runtime,
        "target": target,
        "operation": operation,
        "drift": {
            "hasDrift": state.drift.has_drift,
            "summary": state.drift.summary,
        },
        "apps": selected_apps.iter().map(|app| serde_json::json!({
            "code": app.code,
            "configVersion": app.config_version,
            "vaultSyncVersion": app.vault_sync_version,
            "configHash": app.config_hash,
            "enabled": app.enabled,
        })).collect::<Vec<_>>(),
    });

    format!("{:x}", Sha256::digest(payload.to_string().as_bytes()))
}

fn rollback_fingerprint(
    state: &DeploymentState,
    target: &str,
    rollback: &RollbackPlanContext,
) -> String {
    let payload = serde_json::json!({
        "deploymentHash": state.deployment.deployment_hash,
        "status": state.deployment.status,
        "runtime": state.deployment.runtime,
        "target": target,
        "operation": DeployPlanOperation::RollbackDeploy,
        "rollback": {
            "requestedTarget": rollback.requested_target,
            "currentVersion": rollback.current_version,
            "resolvedVersion": rollback.resolved_version,
        },
        "apps": state.apps.iter().map(|app| serde_json::json!({
            "code": app.code,
            "configVersion": app.config_version,
            "vaultSyncVersion": app.vault_sync_version,
            "configHash": app.config_hash,
            "enabled": app.enabled,
        })).collect::<Vec<_>>(),
    });

    format!("{:x}", Sha256::digest(payload.to_string().as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::{
        DeploymentAgentFeatures, DeploymentAgentState, DeploymentDriftState,
        DeploymentProjectState, DeploymentRuntimeState, DeploymentState, DeploymentStateDeployment,
    };

    fn sample_state() -> DeploymentState {
        DeploymentState {
            schema_version: "v1alpha1".to_string(),
            project: DeploymentProjectState {
                id: 17,
                identity: "syncopia".to_string(),
                name: "syncopia".to_string(),
            },
            deployment: DeploymentStateDeployment {
                id: 31,
                deployment_hash: "deployment_state_online".to_string(),
                status: "healthy".to_string(),
                runtime: "runc".to_string(),
            },
            agent: DeploymentAgentState {
                id: Some("agent-1".to_string()),
                status: "online".to_string(),
                version: Some("0.2.8".to_string()),
                last_heartbeat: None,
                capabilities: vec!["compose".to_string()],
                features: DeploymentAgentFeatures {
                    compose: true,
                    kata_runtime: false,
                    backup: false,
                    pipes: false,
                    proxy_credentials_vault: false,
                },
            },
            runtime: DeploymentRuntimeState {
                compose_path: "/home/trydirect/project/docker-compose.yml".to_string(),
                env_path: "/home/trydirect/project/.env".to_string(),
            },
            apps: vec![
                DeploymentAppState {
                    code: "device-api".to_string(),
                    name: "Device API".to_string(),
                    enabled: true,
                    config_version: 2,
                    vault_sync_version: 2,
                    config_hash: Some("cfg-device-api".to_string()),
                },
                DeploymentAppState {
                    code: "upload".to_string(),
                    name: "Upload".to_string(),
                    enabled: true,
                    config_version: 3,
                    vault_sync_version: 3,
                    config_hash: Some("cfg-upload".to_string()),
                },
            ],
            drift: DeploymentDriftState {
                has_drift: false,
                summary: "no drift detected".to_string(),
            },
            last_command: None,
        }
    }

    #[test]
    fn deploy_plan_snapshot_with_no_changes() {
        let plan = build_deploy_plan(
            &sample_state(),
            DeployPlanOperation::Deploy,
            "cloud",
            None,
            None,
        )
        .expect("plan should build");

        assert_eq!(plan.schema_version, DEPLOY_PLAN_SCHEMA_VERSION);
        assert!(!plan.has_changes);
        assert!(plan.actions.is_empty());
        assert_eq!(plan.scope.mode, "deployment");
    }

    #[test]
    fn deploy_plan_snapshot_with_env_and_config_drift() {
        let mut state = sample_state();
        state.drift.has_drift = true;
        state.drift.summary = "runtime env drift detected".to_string();
        state.apps[1].config_version = 4;
        state.apps[1].vault_sync_version = 3;

        let plan = build_deploy_plan(&state, DeployPlanOperation::Deploy, "cloud", None, None)
            .expect("plan should build");

        assert!(plan.has_changes);
        assert!(plan
            .actions
            .iter()
            .any(|action| { matches!(action.kind, DeployPlanActionKind::ReconcileRuntimeEnv) }));
        assert!(plan.actions.iter().any(|action| {
            matches!(action.kind, DeployPlanActionKind::SyncAppConfig)
                && action.app_code.as_deref() == Some("upload")
        }));
    }

    #[test]
    fn deploy_app_plan_targets_single_service() {
        let plan = build_deploy_plan(
            &sample_state(),
            DeployPlanOperation::DeployApp,
            "cloud",
            Some("upload"),
            None,
        )
        .expect("plan should build");

        assert!(plan.has_changes);
        assert_eq!(plan.scope.mode, "app");
        assert_eq!(plan.scope.app_code.as_deref(), Some("upload"));
        assert_eq!(plan.scope.selected_apps, vec!["upload".to_string()]);
        assert!(plan.actions.iter().any(|action| {
            matches!(action.kind, DeployPlanActionKind::RedeployApp)
                && action.app_code.as_deref() == Some("upload")
        }));
    }

    #[test]
    fn stale_input_detection_returns_plan_stale_error() {
        let state = sample_state();
        let error = build_deploy_plan(
            &state,
            DeployPlanOperation::Deploy,
            "cloud",
            None,
            Some("stale-fingerprint"),
        )
        .expect_err("stale plan should be rejected");

        assert_eq!(error.code, TypedErrorCode::PlanStale);
        assert_eq!(
            error.context.get("expectedFingerprint").map(String::as_str),
            Some("stale-fingerprint")
        );
    }

    #[test]
    fn rollback_plan_snapshot_targets_resolved_version() {
        let plan = build_rollback_plan(
            &sample_state(),
            "cloud",
            RollbackPlanContext {
                requested_target: "previous".to_string(),
                current_version: "1.2.0".to_string(),
                resolved_version: "1.1.0".to_string(),
            },
            None,
        )
        .expect("rollback plan should build");

        assert_eq!(plan.operation, DeployPlanOperation::RollbackDeploy);
        assert!(plan.has_changes);
        assert!(plan
            .actions
            .iter()
            .any(|action| matches!(action.kind, DeployPlanActionKind::RollbackDeploy)));
        assert_eq!(
            plan.rollback
                .as_ref()
                .map(|item| item.resolved_version.as_str()),
            Some("1.1.0")
        );
    }
}
