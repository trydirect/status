use std::sync::Arc;
use std::time::Duration;

use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use crate::transport::http_polling::build_signed_headers;

// ---- Types ----

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NotificationKind {
    StackUpdateAvailable,
    StackPublished,
    SystemNotice,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notification {
    pub id: String,
    pub kind: NotificationKind,
    pub title: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stack_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stack_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_version: Option<String>,
    pub created_at: String,
    #[serde(default)]
    pub read: bool,
}

#[derive(Debug, Serialize)]
pub struct NotificationSummary {
    pub unread_count: usize,
    pub notifications: Vec<Notification>,
}

#[derive(Debug, Deserialize)]
pub struct MarkReadRequest {
    #[serde(default)]
    pub ids: Vec<String>,
    #[serde(default)]
    pub all: bool,
}

#[derive(Debug, Serialize)]
pub struct UnreadCountResponse {
    pub unread_count: usize,
}

pub type NotificationStore = Arc<RwLock<Vec<Notification>>>;

pub fn new_notification_store() -> NotificationStore {
    Arc::new(RwLock::new(Vec::new()))
}

// ---- Store operations ----

pub async fn get_unread_count(store: &NotificationStore) -> usize {
    let notifications = store.read().await;
    notifications.iter().filter(|n| !n.read).count()
}

pub async fn get_summary(store: &NotificationStore) -> NotificationSummary {
    let notifications = store.read().await;
    let unread_count = notifications.iter().filter(|n| !n.read).count();
    NotificationSummary {
        unread_count,
        notifications: notifications.clone(),
    }
}

pub async fn mark_read(store: &NotificationStore, ids: &[String], all: bool) {
    let mut notifications = store.write().await;
    for n in notifications.iter_mut() {
        if all || ids.contains(&n.id) {
            n.read = true;
        }
    }
}

/// Merge incoming notifications into the store, deduplicating by id.
/// New notifications are prepended (most recent first).
pub async fn merge_notifications(store: &NotificationStore, incoming: Vec<Notification>) {
    let mut notifications = store.write().await;
    for n in incoming {
        if !notifications.iter().any(|existing| existing.id == n.id) {
            notifications.insert(0, n);
        }
    }
    // Cap at 100 notifications to prevent unbounded growth
    notifications.truncate(100);
}

// ---- Poller ----

#[derive(Debug, Deserialize)]
struct StackerNotificationsResponse {
    notifications: Vec<Notification>,
}

pub fn spawn_notification_poller(
    dashboard_url: String,
    agent_id: String,
    agent_token: String,
    deployment_hash: String,
    store: NotificationStore,
    interval: Duration,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let client = Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .expect("failed to build HTTP client for notification poller");

        let mut suppressed_404 = false;
        let mut backoff_secs = 0u64;

        info!(
            interval_secs = interval.as_secs(),
            "notification poller started"
        );

        loop {
            tokio::time::sleep(if backoff_secs > 0 {
                Duration::from_secs(backoff_secs)
            } else {
                interval
            })
            .await;

            let url = format!(
                "{}/api/v1/agent/notifications?deployment_hash={}",
                dashboard_url, deployment_hash
            );

            let headers = match build_signed_headers(&agent_id, &agent_token, &[]) {
                Ok(h) => h,
                Err(e) => {
                    error!(error = %e, "failed to build HMAC headers for notification poll");
                    backoff_secs = (backoff_secs * 2).clamp(5, 300);
                    continue;
                }
            };

            match client.get(&url).headers(headers).send().await {
                Ok(resp) => {
                    backoff_secs = 0;
                    match resp.status().as_u16() {
                        200 => {
                            suppressed_404 = false;
                            match resp.json::<StackerNotificationsResponse>().await {
                                Ok(body) => {
                                    let count = body.notifications.len();
                                    if count > 0 {
                                        debug!(count, "received notifications from Stacker");
                                        merge_notifications(&store, body.notifications).await;
                                    }
                                }
                                Err(e) => {
                                    warn!(error = %e, "failed to parse notifications response");
                                }
                            }
                        }
                        204 => {
                            // No new notifications
                        }
                        404 => {
                            if !suppressed_404 {
                                info!("Stacker notifications endpoint not available (404), will retry silently");
                                suppressed_404 = true;
                            }
                        }
                        status => {
                            warn!(status, "unexpected status from notifications endpoint");
                        }
                    }
                }
                Err(e) => {
                    debug!(error = %e, "notification poll failed (network)");
                    backoff_secs = (backoff_secs * 2).clamp(5, 300);
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_notification(id: &str, kind: NotificationKind) -> Notification {
        Notification {
            id: id.to_string(),
            kind,
            title: format!("Test {}", id),
            message: "Test message".to_string(),
            stack_id: Some("stack-1".to_string()),
            stack_name: Some("MyStack".to_string()),
            new_version: Some("2.0".to_string()),
            created_at: "2026-04-12T00:00:00Z".to_string(),
            read: false,
        }
    }

    #[test]
    fn notification_kind_serialization() {
        let json = serde_json::to_string(&NotificationKind::StackUpdateAvailable).unwrap();
        assert_eq!(json, r#""stack_update_available""#);

        let json = serde_json::to_string(&NotificationKind::StackPublished).unwrap();
        assert_eq!(json, r#""stack_published""#);

        let json = serde_json::to_string(&NotificationKind::SystemNotice).unwrap();
        assert_eq!(json, r#""system_notice""#);
    }

    #[test]
    fn notification_kind_deserialization() {
        let kind: NotificationKind = serde_json::from_str(r#""stack_update_available""#).unwrap();
        assert_eq!(kind, NotificationKind::StackUpdateAvailable);
    }

    #[test]
    fn notification_roundtrip() {
        let n = sample_notification("n1", NotificationKind::StackPublished);
        let json = serde_json::to_string(&n).unwrap();
        let deserialized: Notification = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, "n1");
        assert_eq!(deserialized.kind, NotificationKind::StackPublished);
        assert!(!deserialized.read);
    }

    #[test]
    fn notification_read_defaults_false() {
        let json =
            r#"{"id":"x","kind":"system_notice","title":"t","message":"m","created_at":"now"}"#;
        let n: Notification = serde_json::from_str(json).unwrap();
        assert!(!n.read);
    }

    #[tokio::test]
    async fn store_merge_deduplicates() {
        let store = new_notification_store();
        let n1 = sample_notification("n1", NotificationKind::StackUpdateAvailable);
        let n2 = sample_notification("n2", NotificationKind::StackPublished);

        merge_notifications(&store, vec![n1.clone(), n2]).await;
        assert_eq!(store.read().await.len(), 2);

        // Merge again with duplicate id
        let n1_dup = sample_notification("n1", NotificationKind::SystemNotice);
        let n3 = sample_notification("n3", NotificationKind::SystemNotice);
        merge_notifications(&store, vec![n1_dup, n3]).await;
        assert_eq!(store.read().await.len(), 3);

        // Original n1 should still be StackUpdateAvailable (not replaced)
        let locked = store.read().await;
        let found = locked.iter().find(|n| n.id == "n1").unwrap();
        assert_eq!(found.kind, NotificationKind::StackUpdateAvailable);
    }

    #[tokio::test]
    async fn store_unread_count() {
        let store = new_notification_store();
        let n1 = sample_notification("n1", NotificationKind::StackUpdateAvailable);
        let mut n2 = sample_notification("n2", NotificationKind::StackPublished);
        n2.read = true;

        merge_notifications(&store, vec![n1, n2]).await;
        assert_eq!(get_unread_count(&store).await, 1);
    }

    #[tokio::test]
    async fn mark_read_by_ids() {
        let store = new_notification_store();
        merge_notifications(
            &store,
            vec![
                sample_notification("n1", NotificationKind::StackUpdateAvailable),
                sample_notification("n2", NotificationKind::StackPublished),
                sample_notification("n3", NotificationKind::SystemNotice),
            ],
        )
        .await;

        mark_read(&store, &["n1".to_string(), "n3".to_string()], false).await;

        let locked = store.read().await;
        assert!(locked.iter().find(|n| n.id == "n1").unwrap().read);
        assert!(!locked.iter().find(|n| n.id == "n2").unwrap().read);
        assert!(locked.iter().find(|n| n.id == "n3").unwrap().read);
    }

    #[tokio::test]
    async fn mark_read_all() {
        let store = new_notification_store();
        merge_notifications(
            &store,
            vec![
                sample_notification("n1", NotificationKind::StackUpdateAvailable),
                sample_notification("n2", NotificationKind::StackPublished),
            ],
        )
        .await;

        mark_read(&store, &[], true).await;
        assert_eq!(get_unread_count(&store).await, 0);
    }

    #[tokio::test]
    async fn store_caps_at_100() {
        let store = new_notification_store();
        let batch: Vec<Notification> = (0..120)
            .map(|i| sample_notification(&format!("n{}", i), NotificationKind::SystemNotice))
            .collect();
        merge_notifications(&store, batch).await;
        assert_eq!(store.read().await.len(), 100);
    }

    #[tokio::test]
    async fn get_summary_returns_correct_data() {
        let store = new_notification_store();
        let mut n1 = sample_notification("n1", NotificationKind::StackUpdateAvailable);
        n1.read = true;
        let n2 = sample_notification("n2", NotificationKind::StackPublished);

        merge_notifications(&store, vec![n1, n2]).await;

        let summary = get_summary(&store).await;
        assert_eq!(summary.unread_count, 1);
        assert_eq!(summary.notifications.len(), 2);
    }
}
