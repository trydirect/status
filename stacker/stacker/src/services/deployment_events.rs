use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::types::JsonValue;

use crate::{
    db,
    models::{Command, Deployment},
    services::{TypedErrorEnvelope, TypedRemediationClass},
};

pub const DEPLOYMENT_EVENTS_SCHEMA_VERSION: &str = "v1alpha1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentEventKind {
    DeploymentStatus,
    CommandQueued,
    CommandSent,
    CommandExecuting,
    CommandCompleted,
    CommandFailed,
    CommandCancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentEventClassification {
    Info,
    Progress,
    Success,
    Failure,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentEvent {
    pub sequence: usize,
    pub kind: DeploymentEventKind,
    pub classification: DeploymentEventClassification,
    pub occurred_at: DateTime<Utc>,
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retryable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation_class: Option<TypedRemediationClass>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentEventFeed {
    pub schema_version: String,
    pub deployment_hash: String,
    pub events: Vec<DeploymentEvent>,
}

#[derive(Debug, Clone)]
struct DeploymentEventDraft {
    kind: DeploymentEventKind,
    classification: DeploymentEventClassification,
    occurred_at: DateTime<Utc>,
    summary: String,
    command_id: Option<String>,
    command_type: Option<String>,
    status: Option<String>,
    retryable: Option<bool>,
    remediation_class: Option<TypedRemediationClass>,
    order_key: u8,
}

impl DeploymentEventFeed {
    pub fn from_parts(deployment: &Deployment, commands: &[Command]) -> Self {
        let mut drafts = Vec::new();

        if let Some(status_message) = deployment
            .metadata
            .get("status_message")
            .and_then(|value| value.as_str())
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            drafts.push(DeploymentEventDraft {
                kind: DeploymentEventKind::DeploymentStatus,
                classification: classify_deployment_status(&deployment.status),
                occurred_at: deployment.updated_at,
                summary: status_message.to_string(),
                command_id: None,
                command_type: None,
                status: Some(deployment.status.clone()),
                retryable: None,
                remediation_class: None,
                order_key: 2,
            });
        }

        for command in commands {
            drafts.push(DeploymentEventDraft {
                kind: DeploymentEventKind::CommandQueued,
                classification: DeploymentEventClassification::Info,
                occurred_at: command.created_at,
                summary: format!("{} queued", command.r#type),
                command_id: Some(command.command_id.clone()),
                command_type: Some(command.r#type.clone()),
                status: Some("queued".to_string()),
                retryable: None,
                remediation_class: None,
                order_key: 0,
            });

            if command.status != "queued" {
                let (kind, classification, order_key) = classify_command_status(&command.status);
                let (summary, retryable, remediation_class) =
                    summarize_command_outcome(command, &kind, &classification);

                drafts.push(DeploymentEventDraft {
                    kind,
                    classification,
                    occurred_at: command.updated_at,
                    summary,
                    command_id: Some(command.command_id.clone()),
                    command_type: Some(command.r#type.clone()),
                    status: Some(command.status.clone()),
                    retryable,
                    remediation_class,
                    order_key,
                });
            }
        }

        drafts.sort_by(|left, right| {
            left.occurred_at
                .cmp(&right.occurred_at)
                .then_with(|| left.order_key.cmp(&right.order_key))
                .then_with(|| left.command_id.cmp(&right.command_id))
                .then_with(|| left.summary.cmp(&right.summary))
        });

        let events = drafts
            .into_iter()
            .enumerate()
            .map(|(index, draft)| DeploymentEvent {
                sequence: index + 1,
                kind: draft.kind,
                classification: draft.classification,
                occurred_at: draft.occurred_at,
                summary: draft.summary,
                command_id: draft.command_id,
                command_type: draft.command_type,
                status: draft.status,
                retryable: draft.retryable,
                remediation_class: draft.remediation_class,
            })
            .collect();

        Self {
            schema_version: DEPLOYMENT_EVENTS_SCHEMA_VERSION.to_string(),
            deployment_hash: deployment.deployment_hash.clone(),
            events,
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
        let commands = db::command::fetch_by_deployment(pool, deployment_hash).await?;
        Ok(Some(Self::from_parts(&deployment, &commands)))
    }
}

fn classify_deployment_status(status: &str) -> DeploymentEventClassification {
    match status {
        "healthy" | "completed" | "active" => DeploymentEventClassification::Success,
        "failed" | "error" | "deploy_failed" => DeploymentEventClassification::Failure,
        _ => DeploymentEventClassification::Progress,
    }
}

fn classify_command_status(
    status: &str,
) -> (DeploymentEventKind, DeploymentEventClassification, u8) {
    match status {
        "sent" => (
            DeploymentEventKind::CommandSent,
            DeploymentEventClassification::Progress,
            1,
        ),
        "executing" => (
            DeploymentEventKind::CommandExecuting,
            DeploymentEventClassification::Progress,
            2,
        ),
        "completed" => (
            DeploymentEventKind::CommandCompleted,
            DeploymentEventClassification::Success,
            3,
        ),
        "failed" => (
            DeploymentEventKind::CommandFailed,
            DeploymentEventClassification::Failure,
            3,
        ),
        "cancelled" => (
            DeploymentEventKind::CommandCancelled,
            DeploymentEventClassification::Failure,
            3,
        ),
        _ => (
            DeploymentEventKind::CommandQueued,
            DeploymentEventClassification::Info,
            0,
        ),
    }
}

fn summarize_command_outcome(
    command: &Command,
    kind: &DeploymentEventKind,
    classification: &DeploymentEventClassification,
) -> (String, Option<bool>, Option<TypedRemediationClass>) {
    match kind {
        DeploymentEventKind::CommandSent => {
            (format!("{} sent to agent", command.r#type), None, None)
        }
        DeploymentEventKind::CommandExecuting => {
            (format!("{} executing", command.r#type), None, None)
        }
        DeploymentEventKind::CommandCompleted => (
            extract_message(command.result.as_ref())
                .unwrap_or_else(|| format!("{} completed", command.r#type)),
            None,
            None,
        ),
        DeploymentEventKind::CommandFailed | DeploymentEventKind::CommandCancelled => {
            if let Some(error) = parse_typed_error(command.error.as_ref()) {
                return (
                    error.message,
                    Some(error.retryable),
                    Some(error.remediation_class),
                );
            }

            (
                extract_message(command.error.as_ref()).unwrap_or_else(|| {
                    format!(
                        "{} {}",
                        command.r#type,
                        match classification {
                            DeploymentEventClassification::Failure => "failed",
                            _ => "ended",
                        }
                    )
                }),
                Some(false),
                Some(TypedRemediationClass::State),
            )
        }
        _ => (format!("{} queued", command.r#type), None, None),
    }
}

fn extract_message(value: Option<&JsonValue>) -> Option<String> {
    let value = value?;
    if let Some(message) = value.get("message").and_then(|item| item.as_str()) {
        return Some(message.to_string());
    }
    if let Some(status) = value.get("status").and_then(|item| item.as_str()) {
        return Some(status.to_string());
    }
    if let Some(errors) = value.get("errors").and_then(|item| item.as_array()) {
        if let Some(message) = errors
            .iter()
            .find_map(|entry| entry.get("message").and_then(|item| item.as_str()))
        {
            return Some(message.to_string());
        }
    }
    value.as_str().map(ToOwned::to_owned)
}

fn parse_typed_error(value: Option<&JsonValue>) -> Option<TypedErrorEnvelope> {
    serde_json::from_value(value?.clone()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Command, Deployment};
    use serde_json::json;

    fn sample_deployment() -> Deployment {
        let mut deployment = Deployment::new(
            17,
            Some("user-a".to_string()),
            "deployment_events_online".to_string(),
            "in_progress".to_string(),
            "runc".to_string(),
            json!({
                "status_message": "Provisioning server"
            }),
        );
        deployment.updated_at = DateTime::parse_from_rfc3339("2026-05-17T08:02:00Z")
            .unwrap()
            .with_timezone(&Utc);
        deployment
    }

    fn sample_command(
        command_id: &str,
        status: &str,
        created_at: &str,
        updated_at: &str,
    ) -> Command {
        let mut command = Command::new(
            command_id.to_string(),
            "deployment_events_online".to_string(),
            "deploy_app".to_string(),
            "user-a".to_string(),
        );
        command.status = status.to_string();
        command.created_at = DateTime::parse_from_rfc3339(created_at)
            .unwrap()
            .with_timezone(&Utc);
        command.updated_at = DateTime::parse_from_rfc3339(updated_at)
            .unwrap()
            .with_timezone(&Utc);
        command
    }

    #[test]
    fn serializes_event_feed() {
        let feed = DeploymentEventFeed::from_parts(
            &sample_deployment(),
            &[sample_command(
                "cmd-1",
                "completed",
                "2026-05-17T08:00:00Z",
                "2026-05-17T08:05:00Z",
            )],
        );

        let json = serde_json::to_value(&feed).expect("event feed should serialize");
        assert_eq!(
            json["schemaVersion"].as_str().unwrap(),
            DEPLOYMENT_EVENTS_SCHEMA_VERSION
        );
        assert!(json["events"].as_array().unwrap().len() >= 2);
    }

    #[test]
    fn orders_events_by_time_then_phase() {
        let feed = DeploymentEventFeed::from_parts(
            &sample_deployment(),
            &[sample_command(
                "cmd-1",
                "executing",
                "2026-05-17T08:00:00Z",
                "2026-05-17T08:01:00Z",
            )],
        );

        assert_eq!(feed.events[0].kind, DeploymentEventKind::CommandQueued);
        assert_eq!(feed.events[1].kind, DeploymentEventKind::CommandExecuting);
        assert_eq!(feed.events[2].kind, DeploymentEventKind::DeploymentStatus);
    }

    #[test]
    fn classifies_failure_events_from_typed_errors() {
        let mut command = sample_command(
            "cmd-1",
            "failed",
            "2026-05-17T08:00:00Z",
            "2026-05-17T08:03:00Z",
        );
        command.error = Some(
            serde_json::to_value(TypedErrorEnvelope::deployment_capability_missing(
                "Agent cannot run rollback",
            ))
            .unwrap(),
        );

        let feed = DeploymentEventFeed::from_parts(&sample_deployment(), &[command]);
        let failure = feed
            .events
            .iter()
            .find(|event| event.kind == DeploymentEventKind::CommandFailed)
            .expect("failed event should exist");

        assert_eq!(
            failure.classification,
            DeploymentEventClassification::Failure
        );
        assert_eq!(failure.retryable, Some(false));
        assert_eq!(
            failure.remediation_class,
            Some(TypedRemediationClass::Capability)
        );
    }
}
