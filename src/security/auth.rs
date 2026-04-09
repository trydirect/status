use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::warn;
use uuid::Uuid;

/// Session-based user info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionUser {
    pub id: u64,
    pub username: String,
    pub created_at: DateTime<Utc>,
}

impl SessionUser {
    pub fn new(username: String) -> Self {
        Self {
            id: 1,
            username,
            created_at: Utc::now(),
        }
    }
}

/// Default session TTL: 24 hours.
const DEFAULT_SESSION_TTL: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);

/// In-memory session store with TTL support.
#[derive(Debug, Clone)]
pub struct SessionStore {
    sessions: Arc<
        tokio::sync::RwLock<std::collections::HashMap<String, (SessionUser, std::time::Instant)>>,
    >,
    ttl: std::time::Duration,
}

impl SessionStore {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
            ttl: DEFAULT_SESSION_TTL,
        }
    }

    pub fn with_ttl(ttl: std::time::Duration) -> Self {
        Self {
            sessions: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
            ttl,
        }
    }

    pub async fn create_session(&self, user: SessionUser) -> String {
        let session_id = Uuid::new_v4().to_string();
        let mut sessions = self.sessions.write().await;
        sessions.insert(session_id.clone(), (user, std::time::Instant::now()));
        session_id
    }

    pub fn ttl(&self) -> std::time::Duration {
        self.ttl
    }

    pub async fn get_session(&self, session_id: &str) -> Option<SessionUser> {
        let sessions = self.sessions.read().await;
        sessions.get(session_id).and_then(|(user, created)| {
            if created.elapsed() < self.ttl {
                Some(user.clone())
            } else {
                None
            }
        })
    }

    pub async fn delete_session(&self, session_id: &str) {
        let mut sessions = self.sessions.write().await;
        sessions.remove(session_id);
    }

    /// Remove all sessions older than `max_age`.
    pub async fn cleanup_expired(&self, max_age: std::time::Duration) {
        let mut sessions = self.sessions.write().await;
        let now = std::time::Instant::now();
        sessions.retain(|_, (_, created)| now.duration_since(*created) < max_age);
    }
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Credentials from environment.
pub struct Credentials {
    pub username: String,
    pub password: String,
}

/// Error returned when credentials are not configured.
#[derive(Debug)]
pub struct CredentialsNotConfigured;

impl std::fmt::Display for CredentialsNotConfigured {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "STATUS_PANEL_USERNAME and STATUS_PANEL_PASSWORD must be set. \
             Run `status init` to generate a .env template."
        )
    }
}

impl std::error::Error for CredentialsNotConfigured {}

impl Credentials {
    /// Load credentials from environment variables.
    /// Returns an error if either variable is missing — there are no defaults.
    pub fn from_env() -> Result<Self, CredentialsNotConfigured> {
        let username = std::env::var("STATUS_PANEL_USERNAME").ok();
        let password = std::env::var("STATUS_PANEL_PASSWORD").ok();

        match (username, password) {
            (Some(u), Some(p)) if !u.is_empty() && p.len() >= 8 => Ok(Self {
                username: u,
                password: p,
            }),
            _ => {
                warn!(
                    "STATUS_PANEL_USERNAME and/or STATUS_PANEL_PASSWORD not set or password \
                     too short (min 8 chars) — authentication is disabled until credentials \
                     are configured."
                );
                Err(CredentialsNotConfigured)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_session_store_create_and_get() {
        let store = SessionStore::new();
        let user = SessionUser::new("testuser".to_string());

        let session_id = store.create_session(user.clone()).await;
        assert!(!session_id.is_empty());

        let retrieved = store.get_session(&session_id).await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().username, "testuser");
    }

    #[tokio::test]
    async fn test_session_store_delete() {
        let store = SessionStore::new();
        let user = SessionUser::new("testuser".to_string());

        let session_id = store.create_session(user).await;
        let retrieved = store.get_session(&session_id).await;
        assert!(retrieved.is_some());

        store.delete_session(&session_id).await;
        let after_delete = store.get_session(&session_id).await;
        assert!(after_delete.is_none());
    }

    #[tokio::test]
    async fn test_session_store_multiple_sessions() {
        let store = SessionStore::new();
        let user1 = SessionUser::new("user1".to_string());
        let user2 = SessionUser::new("user2".to_string());

        let session1 = store.create_session(user1).await;
        let session2 = store.create_session(user2).await;

        assert_ne!(session1, session2);

        let retrieved1 = store.get_session(&session1).await.unwrap();
        let retrieved2 = store.get_session(&session2).await.unwrap();

        assert_eq!(retrieved1.username, "user1");
        assert_eq!(retrieved2.username, "user2");
    }

    #[test]
    fn test_session_user_creation() {
        let user = SessionUser::new("testuser".to_string());
        assert_eq!(user.id, 1);
        assert_eq!(user.username, "testuser");
    }

    #[test]
    fn test_credentials_from_env() {
        std::env::set_var("STATUS_PANEL_USERNAME", "envuser");
        std::env::set_var("STATUS_PANEL_PASSWORD", "envpass12");

        let creds = Credentials::from_env().expect("should succeed with env vars set");
        assert_eq!(creds.username, "envuser");
        assert_eq!(creds.password, "envpass12");

        std::env::remove_var("STATUS_PANEL_USERNAME");
        std::env::remove_var("STATUS_PANEL_PASSWORD");
    }

    #[test]
    fn test_credentials_error_when_unset() {
        std::env::remove_var("STATUS_PANEL_USERNAME");
        std::env::remove_var("STATUS_PANEL_PASSWORD");
        std::thread::sleep(std::time::Duration::from_millis(10));

        let result = Credentials::from_env();
        assert!(
            result.is_err(),
            "must return error when credentials are not configured"
        );
    }

    #[test]
    fn test_credentials_error_when_empty() {
        std::env::set_var("STATUS_PANEL_USERNAME", "");
        std::env::set_var("STATUS_PANEL_PASSWORD", "testpass1");

        let result = Credentials::from_env();
        assert!(result.is_err(), "must return error when username is empty");

        std::env::remove_var("STATUS_PANEL_USERNAME");
        std::env::remove_var("STATUS_PANEL_PASSWORD");
    }

    #[test]
    fn test_credentials_error_when_password_too_short() {
        std::env::set_var("STATUS_PANEL_USERNAME", "admin");
        std::env::set_var("STATUS_PANEL_PASSWORD", "short");

        let result = Credentials::from_env();
        assert!(
            result.is_err(),
            "must return error when password is shorter than 8 characters"
        );

        std::env::remove_var("STATUS_PANEL_USERNAME");
        std::env::remove_var("STATUS_PANEL_PASSWORD");
    }

    #[tokio::test]
    async fn test_session_cleanup_expired() {
        let store = SessionStore::new();
        let user = SessionUser::new("testuser".to_string());
        let session_id = store.create_session(user).await;

        assert!(store.get_session(&session_id).await.is_some());

        // Cleanup with 0 TTL should remove all sessions
        store
            .cleanup_expired(std::time::Duration::from_secs(0))
            .await;
        assert!(store.get_session(&session_id).await.is_none());
    }

    #[tokio::test]
    async fn test_get_session_enforces_ttl() {
        // Create a store with a very short TTL
        let store = SessionStore::with_ttl(std::time::Duration::from_millis(50));
        let user = SessionUser::new("testuser".to_string());
        let session_id = store.create_session(user).await;

        // Session should be valid immediately
        assert!(store.get_session(&session_id).await.is_some());

        // Wait for TTL to expire
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Session should now be rejected by get_session
        assert!(
            store.get_session(&session_id).await.is_none(),
            "expired session must not be returned by get_session"
        );
    }
}
