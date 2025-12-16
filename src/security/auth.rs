use serde::{Deserialize, Serialize};
use std::sync::Arc;
use chrono::{DateTime, Utc};
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

/// In-memory session store (replace with persistent store in production).
#[derive(Debug, Clone)]
pub struct SessionStore {
    sessions: Arc<tokio::sync::RwLock<std::collections::HashMap<String, SessionUser>>>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
        }
    }

    pub async fn create_session(&self, user: SessionUser) -> String {
        let session_id = Uuid::new_v4().to_string();
        let mut sessions = self.sessions.write().await;
        sessions.insert(session_id.clone(), user);
        session_id
    }

    pub async fn get_session(&self, session_id: &str) -> Option<SessionUser> {
        let sessions = self.sessions.read().await;
        sessions.get(session_id).cloned()
    }

    pub async fn delete_session(&self, session_id: &str) {
        let mut sessions = self.sessions.write().await;
        sessions.remove(session_id);
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

impl Credentials {
    pub fn from_env() -> Self {
        let username = std::env::var("STATUS_PANEL_USERNAME")
            .unwrap_or_else(|_| "admin".to_string());
        let password = std::env::var("STATUS_PANEL_PASSWORD")
            .unwrap_or_else(|_| "admin".to_string());
        Self { username, password }
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
        std::env::set_var("STATUS_PANEL_PASSWORD", "envpass");
        
        let creds = Credentials::from_env();
        assert_eq!(creds.username, "envuser");
        assert_eq!(creds.password, "envpass");
        
        std::env::remove_var("STATUS_PANEL_USERNAME");
        std::env::remove_var("STATUS_PANEL_PASSWORD");
    }

    #[test]
    fn test_credentials_defaults() {
        // Clear any environment variables first
        std::env::remove_var("STATUS_PANEL_USERNAME");
        std::env::remove_var("STATUS_PANEL_PASSWORD");
        
        // Small delay to avoid race with other tests
        std::thread::sleep(std::time::Duration::from_millis(10));
        
        let creds = Credentials::from_env();
        assert_eq!(creds.username, "admin");
        assert_eq!(creds.password, "admin");
    }
}
